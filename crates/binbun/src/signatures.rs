//! Library signatures over images: packs made from static libraries,
//! objects and linked ELF files with symbols ([`make`]), and a binary's
//! functions matched against packs ([`match_image`]).
//!
//! Each function's canonical form is computed from its L1 as
//! decompilation prepares it, but a tail jump through a slot holding a
//! fixed code pointer is a tail call of that code ([`analyse`]); a call's
//! arguments are the
//! argument registers the callee reads before writing, from the callee's
//! own L1 ([`binbun_sigpack::reads`], resolved through functions that pass
//! them on). A pack's function is then recorded: its behaviour on chosen
//! states ([`binbun_sigpack::check::record`]); look-alikes in one bucket
//! (the same argument and result registers) that agree with each other's
//! recordings are run on the separator search's states, and one that
//! tells them apart is added to both recordings, else they form an
//! equivalence group.
//!
//! Matching takes the binary's own build of each library (of several
//! packs of one, [`elect`]) and, per function, the pack entries of the same identity
//! and the fingerprint index's candidates, and (with behaviour checking)
//! runs the function on each candidate's recorded states. A name is given
//! only when it is the one answer: a unique, non-trivial identity no
//! other candidate's behaviour also fits, or the one candidate whose
//! behaviour fits (with at least half the function's blocks run) when
//! every other candidate's does not.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;
use std::thread;

use crate::cfg::{Destination, Exit, FunctionId};
use binbun_loader::relocatable::{self, Linked};
use binbun_loader::{Format, Image, SymbolKind};
use binbun_semantics::core::Memory as _;
use binbun_semantics::ir::RegisterId;
use binbun_sigpack::check::{
    self, Param, Platform, Recorded, Recording, Ret, Shape, StateId, Subject, World,
};
use binbun_sigpack::index::Index;
use binbun_sigpack::pack::{Build, BuildInfo, Built, Check, Code, Entry, Header, Pack, Separator};
use binbun_sigpack::{Abi, Canonical, Fingerprint, Identity, Input, Referent, Surroundings};
use binbun_ssa::Function;
use binbun_typedb::types::{FloatFormat, Signature};
use binbun_typedb::{Type, TypeId, TypeLibrary};

use crate::Database;
use crate::analysis::Seeds;
use crate::corrections::{Bounds, instruction_length};
use crate::decompile::{decompile_l1, threads};
use crate::funclets;
use crate::lift::ImageEnvironment;
use crate::manglings::msvc;
use crate::memory::ImageMemory;
use crate::target::convention;

/// The thread pointer of checking runs.
const THREAD: u64 = 0x7ff0_0000_0000;

/// Where checking runs find imported functions: the `n`th import of an
/// image at `IMPORTS + 16 * n`, which its slot holds.
const IMPORTS: u64 = 0x7fe0_0000_0000;

/// The checking platform of `image`'s code: its convention, the program
/// counter, the direction flag clear and the thread pointer fixed (`fs`'s
/// base on Linux, `gs`'s, the TEB, on Windows), its block readable.
///
/// # Errors
///
/// The image's code is not lifted, or is not x86-64.
pub fn platform(image: &Image<'_>) -> Result<Platform<'static>, String> {
    if image.machine != binbun_loader::Machine::X86_64 {
        return Err(format!(
            "signatures are made and matched for x86-64 code only (this is {:?})",
            image.machine
        ));
    }
    let environment = ImageEnvironment::new(image, &[]).map_err(|e| e.0)?;
    let declarations = environment.declarations();
    let convention = convention(image, declarations);
    // The thread's self pointers; on Windows (the TEB, in `gs`) also its
    // array of thread-local blocks, 64 slots, each a block of zeros.
    let (thread, thread_words) = if image.format == Format::Pe {
        let array = THREAD + 0x800;
        let mut words = vec![(0x30, THREAD), (0x58, array)];
        words.extend((0..64).map(|slot| (0x800 + 8 * slot, THREAD - 0x1000)));
        ("gs_base", words)
    } else {
        ("fs_base", vec![(0, THREAD), (16, THREAD)])
    };
    let fixed = ["df", thread]
        .into_iter()
        .zip([0, THREAD])
        .filter_map(|(name, value)| Some((declarations.find(name)?, value)))
        .collect();
    Ok(Platform {
        abi: Abi {
            declarations,
            stack_pointer: environment.stack_pointer(),
            arguments: convention.arguments.clone(),
            float_arguments: convention.float_arguments.clone(),
            results: convention.results.clone(),
            float_results: convention.float_results.clone(),
            system_call: convention.system_call,
        },
        program_counter: declarations.find("rip"),
        fixed,
        thread: Some(THREAD),
        thread_words,
        link_bytes: 8,
        fuel: 10_000,
    })
}

/// A function's analysis for signatures.
#[derive(Clone, Debug)]
pub struct Analysed {
    /// Its entry.
    pub entry: u64,
    /// Its L1, as decompilation prepares it but for tail jumps through
    /// slots ([`analyse`]).
    pub l1: Function,
    /// Its canonical form.
    pub canonical: Canonical,
    /// How many of its blocks can run.
    pub reachable: usize,
}

/// What the image around a function looks like to the canonical form:
/// read-only strings by content, other mapped addresses as slots, and
/// the argument registers each function reads; its fixed imports' slots,
/// whether it is position-independent, and what the loader relocates.
/// In an image rustc built ([`rustc_commit`]) strings are slots too: a
/// Rust string is no C string, its length is not in its bytes, and what
/// follows it up to a NUL is where the linker put it (the library's
/// object and a program linking it differ).
struct ImageSurroundings<'a> {
    image: &'a Image<'a>,
    memory: ImageMemory<'a>,
    /// The slots of the fixed imports ([`binbun_loader::Import::fixed`]).
    imports: HashSet<u64>,
    /// Whether a NUL-terminated string is its text (not built by rustc).
    texts: bool,
    reads: &'a BTreeMap<u64, u32>,
}

impl<'a> ImageSurroundings<'a> {
    fn new(image: &'a Image<'a>, reads: &'a BTreeMap<u64, u32>) -> Self {
        Self {
            image,
            memory: ImageMemory::new(image),
            imports: image
                .imports
                .iter()
                .filter(|import| import.fixed && import.size == 8)
                .map(|import| import.slot)
                .collect(),
            texts: rustc_commit(image).is_none(),
            reads,
        }
    }
}

impl Surroundings for ImageSurroundings<'_> {
    fn referent(&self, address: u64) -> Option<Referent> {
        // A PE image's base (`__ImageBase`, which jump tables count from)
        // is an address of the image, mapped or not.
        if self.image.format == Format::Pe && address == self.image.base {
            return Some(Referent::Other);
        }
        self.image.segment(address)?;
        let text = self.texts.then(|| text(self.image, address)).flatten();
        Some(text.map_or(Referent::Other, Referent::Text))
    }

    fn reads(&self, callee: u64) -> Option<u32> {
        self.reads.get(&callee).copied()
    }

    fn import(&self, slot: u64) -> bool {
        self.imports.contains(&slot)
    }

    /// A PLT entry: `jmp [rip+slot]`, after `endbr64` and with `bnd` or
    /// not.
    fn stub(&self, address: u64) -> Option<u64> {
        let mut bytes = [0u8; 11];
        let read = self.image.read(address, &mut bytes).ok()?;
        let all = bytes.get(..read)?;
        let bytes = all.strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfa]).unwrap_or(all);
        let bytes = bytes.strip_prefix(&[0xf2]).unwrap_or(bytes);
        let displacement = bytes.strip_prefix(&[0xff, 0x25])?.get(..4)?;
        // The prefixes, the opcode and the displacement.
        let length = all.len() - bytes.len() + 6;
        let displacement = i32::from_le_bytes(displacement.try_into().ok()?);
        let slot = address
            .wrapping_add(length as u64)
            .wrapping_add_signed(i64::from(displacement));
        self.import(slot).then_some(slot)
    }

    fn position_independent(&self) -> bool {
        self.image.position_independent
    }

    fn relocated(&self, address: u64, bytes: u16) -> bool {
        self.memory
            .written(address, address.saturating_add(u64::from(bytes)))
    }
}

/// The hash of the NUL-terminated text at `address` of `image`, if it is
/// in read-only data (not code) and is text: printable or whitespace
/// bytes (or above 0x7f), at least one, at most 4096.
fn text(image: &Image<'_>, address: u64) -> Option<u128> {
    let segment = image.segment(address)?;
    if segment.permissions.write || image.is_code(address) {
        return None;
    }
    // An aligned word holding one of the image's addresses is a pointer
    // (a table's entry), whatever its bytes look like.
    let mut word = [0u8; 8];
    if address.is_multiple_of(8)
        && image.read(address, &mut word) == Ok(8)
        && image.is_mapped(u64::from_le_bytes(word))
    {
        return None;
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 64];
    let mut at = address;
    while bytes.len() < 4096 {
        let count = image.read(at, &mut buffer).unwrap_or(0);
        let read = buffer.get(..count).filter(|b| !b.is_empty())?;
        if let Some(end) = read.iter().position(|&b| b == 0) {
            bytes.extend(read.iter().take(end));
            // Text: UTF-8 without control characters but whitespace, and
            // some letter or digit (a table of 0xff bytes is no string).
            let text = core::str::from_utf8(&bytes).is_ok_and(|text| {
                text.chars().any(char::is_alphanumeric)
                    && text.chars().all(|c| !c.is_control() || c.is_whitespace())
            });
            if !text {
                return None;
            }
            let hash = blake3::hash(&bytes);
            let mut out = [0u8; 16];
            out.copy_from_slice(hash.as_bytes().get(..16)?);
            return Some(u128::from_le_bytes(out));
        }
        bytes.extend_from_slice(read);
        at += count as u64;
    }
    None
}

/// The world a function runs in for checking: its image's bytes, the
/// symbols of its image (when recording a library's function) and the
/// argument registers each function reads. An import's slot holds an
/// address of its own ([`IMPORTS`]), named as the import
/// (`__imp_GetLastError`), as the loader fills it: so a call through the
/// slot is a call to that import, in a library's objects (COFF's `__imp_`
/// slots) as in a program.
struct ImageWorld<'a> {
    image: &'a Image<'a>,
    /// Symbols by start: end and name.
    symbols: BTreeMap<u64, (u64, String)>,
    /// Sections by start: end and a name (`.rodata#3`, numbered as the
    /// image lists them), for addresses no symbol covers.
    sections: BTreeMap<u64, (u64, String)>,
    /// The imports' slots by start: their size and the address they hold.
    slots: BTreeMap<u64, (u8, u64)>,
    /// The imports' names, by their index ([`IMPORTS`]).
    imports: Vec<&'a str>,
    reads: &'a BTreeMap<u64, u32>,
}

impl<'a> ImageWorld<'a> {
    /// `image`'s world, its symbols `symbols` (start, size, name: the
    /// first of a start is kept).
    fn new(
        image: &'a Image<'a>,
        symbols: impl IntoIterator<Item = (u64, u64, String)>,
        reads: &'a BTreeMap<u64, u32>,
    ) -> Self {
        let mut map: BTreeMap<u64, (u64, String)> = BTreeMap::new();
        for (start, size, name) in symbols {
            map.entry(start)
                .or_insert((start.saturating_add(size.max(1)), name));
        }
        let sections = if map.is_empty() {
            BTreeMap::new()
        } else {
            image
                .sections
                .iter()
                .enumerate()
                .map(|(index, section)| {
                    (
                        section.start,
                        (
                            section.start.saturating_add(section.size),
                            format!("{}#{index}", section.name),
                        ),
                    )
                })
                .collect()
        };
        let imports: Vec<&str> = image.imports.iter().map(|i| i.name.as_str()).collect();
        let slots = image
            .imports
            .iter()
            .zip(0u64..)
            .map(|(import, index)| (import.slot, (import.size, IMPORTS + 16 * index)))
            .collect();
        Self {
            image,
            symbols: map,
            sections,
            slots,
            imports,
            reads,
        }
    }

    /// The index of the import whose address [`IMPORTS`] `address` is in.
    fn import(&self, address: u64) -> Option<usize> {
        let index = usize::try_from(address.checked_sub(IMPORTS)? / 16).ok()?;
        (index < self.imports.len()).then_some(index)
    }
}

impl World for ImageWorld<'_> {
    fn byte(&self, address: u64) -> Option<u8> {
        if let Some((&slot, &(size, held))) = self.slots.range(..=address).next_back()
            && address < slot + u64::from(size)
        {
            return held
                .to_le_bytes()
                .get(usize::try_from(address - slot).ok()?)
                .copied();
        }
        if self.import(address).is_some() {
            return Some(0);
        }
        let mut byte = [0u8];
        if self.image.read(address, &mut byte) == Ok(1) {
            return Some(byte[0]);
        }
        // A PE image's headers, which the loader maps at its base
        // (`__ImageBase`), as zeros where not mapped here.
        (self.image.format == Format::Pe && address.wrapping_sub(self.image.base) < 0x1000)
            .then_some(0)
    }

    fn symbol(&self, address: u64) -> Option<(String, i64)> {
        if let Some(index) = self.import(address) {
            let name = self.imports.get(index)?;
            return Some((
                format!("__imp_{name}"),
                i64::try_from(address % 16).unwrap_or(0),
            ));
        }
        let covering = |map: &BTreeMap<u64, (u64, String)>| {
            let (&start, (end, name)) = map.range(..=address).next_back()?;
            (address < *end).then(|| (name.clone(), i64::try_from(address - start).unwrap_or(0)))
        };
        covering(&self.symbols).or_else(|| covering(&self.sections))
    }

    fn reads(&self, callee: u64) -> Option<u32> {
        self.reads.get(&callee).copied()
    }

    fn text(&self, address: u64) -> Option<u128> {
        text(self.image, address)
    }
}

/// The stack of [`parallel`]'s threads.
const STACK: usize = 256 << 20;

/// Runs `work` on each of `items` on [`threads`] threads, the results in
/// order (none for an item if no thread could be started).
fn parallel<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = Mutex::new(0usize);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    thread::scope(|scope| {
        for _ in 0..threads().max(1) {
            // The canonical form follows values' operands recursively, as
            // deep as a function's longest chain of operations.
            let spawned = thread::Builder::new()
                .stack_size(STACK)
                .spawn_scoped(scope, || {
                    loop {
                        let index = {
                            let Ok(mut next) = next.lock() else { return };
                            let index = *next;
                            *next += 1;
                            index
                        };
                        let Some(item) = items.get(index) else { return };
                        let result = work(item);
                        if let Ok(mut results) = results.lock()
                            && let Some(slot) = results.get_mut(index)
                        {
                            *slot = Some(result);
                        }
                    }
                });
            if spawned.is_err() {
                break;
            }
        }
    });
    results
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect()
}

/// The canonical forms of the functions `ids` of `db`, each with its L1
/// (in the order of `ids`; `None` where one does not lift), and the
/// argument registers each reads, by entry.
pub fn analyse(
    db: &Database<'_>,
    platform: &Platform<'_>,
    ids: &[FunctionId],
) -> (Vec<Option<Analysed>>, BTreeMap<u64, u32>) {
    let image = db.image();
    let summaries = db.summaries();
    let lift = |id: FunctionId| decompile_l1(image, db.program(), id, summaries, &[]).ok();
    // The argument registers each function reads itself, and those it
    // passes on to its callees.
    let reads: Vec<Option<(u64, binbun_sigpack::Reads)>> = parallel(ids, |&id| {
        let prepared = lift(id)?;
        let input = Input {
            function: &prepared.l1,
            constants: &prepared.facts.constants,
            stack: &prepared.facts.stack,
            abi: &platform.abi,
        };
        Some((prepared.l1.entry, binbun_sigpack::reads(input)))
    });
    let reads: Vec<(u64, binbun_sigpack::Reads)> = reads.into_iter().flatten().collect();
    let reads = resolve_reads(&reads);
    let surroundings = ImageSurroundings::new(image, &reads);
    let analysed = parallel(ids, |&id| {
        let prepared = lift(id)?;
        let input = Input {
            function: &prepared.l1,
            constants: &prepared.facts.constants,
            stack: &prepared.facts.stack,
            abi: &platform.abi,
        };
        let mut canonical = binbun_sigpack::canonical(input, &surroundings);
        canonical.fingerprint.arguments = reads.get(&prepared.l1.entry).copied().unwrap_or(0);
        let reachable = (0..prepared.l1.blocks.len())
            .filter(|&b| {
                prepared
                    .facts
                    .constants
                    .reachable(binbun_ssa::BlockId(u32::try_from(b).unwrap_or(u32::MAX)))
            })
            .count();
        Some(Analysed {
            entry: prepared.l1.entry,
            l1: prepared.l1,
            canonical,
            reachable,
        })
    });
    (analysed, reads)
}

/// The argument registers each function reads: its own, and those it
/// passes on that its callee reads (none for a callee not known), to a
/// fixed point.
fn resolve_reads(reads: &[(u64, binbun_sigpack::Reads)]) -> BTreeMap<u64, u32> {
    let mut masks: BTreeMap<u64, u32> = reads.iter().map(|(entry, r)| (*entry, r.direct)).collect();
    for _ in 0..64 {
        let mut changed = false;
        for (entry, read) in reads {
            let mut mask = masks.get(entry).copied().unwrap_or(0);
            for &(callee, forwarded) in &read.forwards {
                // Passed on to a callee not known: what it reads is not
                // known either, and is not counted.
                let callee_reads = callee.and_then(|c| masks.get(&c).copied()).unwrap_or(0);
                mask |= forwarded & callee_reads;
            }
            if masks.get(entry) != Some(&mask) {
                masks.insert(*entry, mask);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    masks
}

/// Function `id` of `db` run on `recording`'s states and compared with
/// it ([`check::replay`]).
///
/// # Errors
///
/// The image's code is not x86-64, or the function does not lift.
pub fn replay(
    db: &Database<'_>,
    id: FunctionId,
    recording: &Recording,
) -> Result<check::Verdict, String> {
    let platform = platform(db.image())?;
    let (analysed, reads) = analyse(db, &platform, &[id]);
    let function = analysed
        .into_iter()
        .flatten()
        .next()
        .ok_or("the function does not lift")?;
    let world = ImageWorld::new(db.image(), Vec::new(), &reads);
    Ok(check::replay(
        &function.l1,
        function.entry,
        &platform,
        &world,
        recording,
    ))
}

/// What `binbun sig make` is told about the pack.
#[derive(Clone, Debug, Default)]
pub struct MakeOptions {
    /// The library's name.
    pub library: String,
    /// Its version.
    pub version: String,
    /// Its licence (SPDX).
    pub licence: String,
    /// Its copyright notice.
    pub notice: Option<String>,
    /// The source package.
    pub source: Option<binbun_sigpack::pack::Source>,
    /// The build's name in the pack.
    pub build: String,
    /// The toolchain.
    pub toolchain: Option<String>,
    /// The flags.
    pub flags: Option<String>,
    /// Whether to carry the functions' code instead of recordings (a pack
    /// for the user's own use).
    pub code: bool,
    /// Whether to look for separators and equivalence groups.
    pub separators: bool,
}

/// A function symbol group of an image: its address, names, object and
/// size.
#[derive(Clone, Debug)]
struct Named {
    address: u64,
    names: Vec<String>,
    object: String,
    size: Option<u64>,
}

/// One input image of a pack and what is known about its parts.
struct Source<'a> {
    image: Image<'a>,
    /// For objects: the link (members, relocations).
    linked: Option<&'a Linked>,
}

/// A pack made from `inputs` (each a path and its bytes: archives `.a`,
/// `.rlib` and Microsoft's `.lib`, ELF and COFF relocatable objects,
/// linked ELF files with symbols) under `options`. A pack of COFF objects
/// is for Windows (`x86_64`, `windows`, `msvc`), its prototypes from the
/// Universal CRT's declarations.
///
/// # Errors
///
/// An input is not one of those (an import library has no code), the
/// image's code is not x86-64, or no function was found.
pub fn make(inputs: &[(String, Vec<u8>)], options: &MakeOptions) -> Result<Pack, String> {
    let mut objects: Vec<(String, &[u8])> = Vec::new();
    let mut linked_files: Vec<(&str, &[u8])> = Vec::new();
    for (path, data) in inputs {
        let base = path.rsplit('/').next().unwrap_or(path);
        if relocatable::is_archive(data) {
            // An archive member by its own name (`strcpy.o`), as every
            // build of the library names it.
            let kinds = relocatable::archive_members(data).map_err(|e| format!("{path}: {e}"))?;
            if kinds.objects.is_empty() && kinds.imports != 0 {
                return Err(format!(
                    "{path}: an import library ({} imports): its functions are in a DLL",
                    kinds.imports
                ));
            }
            objects.extend(kinds.objects);
        } else if relocatable::is_relocatable(data) {
            objects.push((base.to_owned(), data));
        } else {
            linked_files.push((path, data));
        }
    }
    let link = if objects.is_empty() {
        None
    } else {
        Some(Linked::link(&objects).map_err(|e| e.to_string())?)
    };
    let mut images: Vec<Source<'_>> = Vec::new();
    if let Some(link) = &link {
        images.push(Source {
            image: link.image(),
            linked: Some(link),
        });
    }
    for (path, data) in linked_files {
        let image = Image::parse(data).map_err(|e| format!("{path}: {e}"))?;
        images.push(Source {
            image,
            linked: None,
        });
    }
    let mut entries: BTreeMap<(String, String), Entry> = BTreeMap::new();
    for input in &images {
        for entry in make_image(input, options)? {
            entries.insert((entry.name.clone(), entry.object.clone()), entry);
        }
    }
    if entries.is_empty() {
        return Err("no function found in the inputs".into());
    }
    let sha256 = inputs.iter().map(|(_, data)| sha256_hex(data)).collect();
    let windows = images.iter().any(|input| input.image.format == Format::Pe);
    let (os, env, typedb) = if windows {
        ("windows", "msvc", "windows-x86_64-ucrt")
    } else {
        ("linux", "", "linux-x86_64-libc")
    };
    Ok(Pack {
        header: Header {
            binbun_sigpack: binbun_sigpack::pack::FORMAT,
            identity: binbun_sigpack::canon::VERSION,
            revision: 1,
            library: options.library.clone(),
            version: options.version.clone(),
            target: binbun_sigpack::pack::Target {
                arch: "x86_64".into(),
                os: os.into(),
                env: env.into(),
                pointer_size: 8,
            },
            licence: options.licence.clone(),
            notice: options.notice.clone(),
            source: options.source.clone(),
            builds: vec![BuildInfo {
                id: options.build.clone(),
                toolchain: options.toolchain.clone(),
                flags: options.flags.clone(),
                inputs: inputs
                    .iter()
                    .map(|(path, _)| path.rsplit('/').next().unwrap_or(path).to_owned())
                    .collect(),
                sha256,
            }],
            typedb: Some(typedb.into()),
            made_by: format!("binbun {} sig make", env!("CARGO_PKG_VERSION")),
        },
        functions: entries.into_values().collect(),
    })
}

/// `bytes` in hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The SHA-256 of `data` in hexadecimal.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    hex(&sha2::Sha256::digest(data))
}

/// The functions of one input image, by symbol, with their aliases (one
/// address) and objects.
fn named_functions(input: &Source<'_>) -> Vec<Named> {
    let image = &input.image;
    let mut by_address: BTreeMap<u64, Named> = BTreeMap::new();
    for (index, symbol) in image.symbols.iter().enumerate() {
        if symbol.kind != SymbolKind::Function
            || !image.is_code(symbol.address)
            || funclet(&symbol.name)
        {
            continue;
        }
        let object = match input.linked {
            Some(linked) => linked
                .symbol_members
                .get(index)
                .and_then(|&m| linked.members.get(m))
                .map_or_else(String::new, |m| m.name.clone()),
            None => String::new(),
        };
        let named = by_address.entry(symbol.address).or_insert_with(|| Named {
            address: symbol.address,
            names: Vec::new(),
            object,
            size: symbol.size,
        });
        if !named.names.contains(&symbol.name) {
            named.names.push(symbol.name.clone());
        }
        named.size = named.size.or(symbol.size);
    }
    by_address.into_values().collect()
}

/// Every symbol of an input image (start, size, name), for recording and
/// callee names: the image's and, for objects, the link's externals; by
/// start, section symbols (`.text`) after names.
fn symbols(input: &Source<'_>) -> Vec<(u64, u64, String)> {
    let mut symbols: Vec<(u64, u64, String)> = input
        .image
        .symbols
        .iter()
        .map(|s| (s.address, s.size.unwrap_or(1), s.name.clone()))
        .collect();
    if let Some(linked) = input.linked {
        symbols.extend(
            linked
                .externals
                .iter()
                .map(|(name, &address)| (address, 16, name.clone())),
        );
    }
    symbols
        .sort_by(|a, b| (a.0, a.2.starts_with('.'), &a.2).cmp(&(b.0, b.2.starts_with('.'), &b.2)));
    symbols
}

/// Whether `name` is an MSVC funclet's: code split out of a function for
/// its exception handling, part of that function (a program's PDB names
/// it after it, `` `f'::`1'::dtor$3 ``), and as short and alike from one
/// function to another as unwinding a local is. A C++ function's are
/// mangled (`?dtor$3@?0??f@@YAXXZ@4HA`, `?catch$`, `?fin$`, `?filt$`),
/// a C function's are its name, the kind and a number (`_putw$fin$0`,
/// `f$filt$1`, `f$catch$6`, `f$dtor$0`).
fn funclet(name: &str) -> bool {
    const KINDS: [&str; 4] = ["dtor", "catch", "fin", "filt"];
    if let Some(rest) = name.strip_prefix('?') {
        return KINDS
            .iter()
            .any(|kind| rest.strip_prefix(kind).is_some_and(|r| r.starts_with('$')));
    }
    let mut parts = name.rsplitn(3, '$');
    let (Some(number), Some(kind), Some(function)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    !function.is_empty()
        && KINDS.contains(&kind)
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
}

/// The primary name of `names` (one address): the one the type library
/// declares, else the first without a leading underscore, else the first
/// in order.
fn primary(names: &[String], library: &TypeLibrary) -> usize {
    names
        .iter()
        .position(|name| {
            library
                .function(None, name)
                .is_some_and(|d| d.prototype.is_some())
        })
        .or_else(|| names.iter().position(|name| !name.starts_with('_')))
        .unwrap_or(0)
}

/// A function of a pack being made, before separators and groups.
struct Made {
    named: Named,
    primary: usize,
    /// The identical definitions it stands for ([`merge_identical`]).
    copies: u32,
    shape: Shape,
    prototype: Option<String>,
    build: Build,
}

/// The entries of one input image.
#[expect(clippy::too_many_lines, reason = "one pass over the image's functions")]
fn make_image(input: &Source<'_>, options: &MakeOptions) -> Result<Vec<Entry>, String> {
    let image = &input.image;
    let platform = platform(image)?;
    let db = Database::new(image, Seeds::ALL).map_err(|e| e.to_string())?;
    let named = named_functions(input);
    let ids: Vec<FunctionId> = named
        .iter()
        .map(|n| {
            db.function_at(n.address)
                .filter(|&id| db.function(id).is_some_and(|f| f.entry == n.address))
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_else(|| {
            named
                .iter()
                .filter_map(|n| db.function_at(n.address))
                .collect()
        });
    let (analysed, reads) = analyse(&db, &platform, &ids);
    let by_entry: HashMap<u64, &Analysed> =
        analysed.iter().flatten().map(|a| (a.entry, a)).collect();
    let world = ImageWorld::new(image, symbols(input), &reads);
    let library = db.library();
    let made: Vec<Option<Made>> = parallel(&named, |named| {
        let analysed = by_entry.get(&named.address)?;
        let primary = primary(&named.names, library);
        let name = named.names.get(primary)?;
        let declared = named.names.iter().find_map(|n| {
            library
                .function(None, n)?
                .prototype
                .as_ref()
                .map(|f| (n, &f.value))
        });
        let shape = match declared {
            Some((_, signature)) => shape(library, signature),
            None => unknown_shape(&analysed.canonical.fingerprint, &platform),
        };
        let prototype = declared.map(|(_, signature)| spell_prototype(library, signature, name));
        let mut fingerprint = analysed.canonical.fingerprint.clone();
        let callees: Vec<String> = analysed
            .canonical
            .code
            .iter()
            .map(|&address| {
                world
                    .symbol(address)
                    .filter(|(_, o)| *o == 0)
                    .map(|(n, _)| n)
                    .unwrap_or_default()
            })
            .collect();
        fingerprint.callees = callees.iter().filter(|c| !c.is_empty()).cloned().collect();
        let bytes = masked_bytes(input, named, &analysed.l1);
        let subject = Subject {
            function: &analysed.l1,
            entry: analysed.entry,
            masks: &analysed.canonical.masks,
        };
        let check = if options.code {
            Some(Check::Code(code(input, named, &analysed.l1)))
        } else {
            check::record(subject, &platform, &world, &shape).map(Check::Recorded)
        };
        Some(Made {
            named: named.clone(),
            primary,
            copies: 1,
            shape,
            prototype,
            build: Build {
                identity: analysed.canonical.identity,
                bytes: binbun_sigpack::bytes_hash(&bytes),
                trivial: analysed.canonical.trivial,
                fingerprint,
                callees,
                check,
            },
        })
    });
    let mut made: Vec<Made> = made.into_iter().flatten().collect();
    merge_identical(&mut made, &by_entry, library);
    let primaries: Vec<String> = made
        .iter()
        .map(|m| m.named.names.get(m.primary).cloned().unwrap_or_default())
        .collect();
    let mut groups: Vec<usize> = (0..made.len()).collect();
    let mut look_alikes: Vec<BTreeSet<String>> = vec![BTreeSet::new(); made.len()];
    let mut separators: Vec<Vec<Separator>> = vec![Vec::new(); made.len()];
    if options.separators && !options.code {
        let functions: Vec<Option<&Analysed>> = made
            .iter()
            .map(|m| by_entry.get(&m.named.address).copied())
            .collect();
        // Functions whose code is the same but for which functions it
        // calls run alike (one class of `runs`), and record alike if of
        // one shape (one class of `records`): the search runs once per
        // pair of classes, from their first members.
        let runs = number(made.iter().zip(&functions).map(|(m, f)| {
            let canonical = f.map(|f| &f.canonical);
            let code = canonical.map(|c| c.code.as_slice()).unwrap_or_default();
            let pattern = number(code.iter());
            (
                m.build.identity,
                m.build.bytes.clone(),
                canonical.map(|c| c.data.clone()).unwrap_or_default(),
                pattern,
            )
        }));
        let records = number(
            made.iter()
                .zip(&runs)
                .map(|(m, &run)| (run, m.shape.to_string())),
        );
        let firsts = |classes: &[usize]| -> Vec<usize> {
            let mut seen = BTreeSet::new();
            (0..classes.len())
                .filter(|&i| classes.get(i).is_some_and(|&c| seen.insert(c)))
                .collect()
        };
        let runners = firsts(&runs);
        let recorders = firsts(&records);
        let recordings: Vec<(usize, &Recording)> = recorders
            .iter()
            .filter_map(|&a| match made.get(a)?.build.check.as_ref()? {
                Check::Recorded(recording) => Some((a, recording)),
                Check::Code(_) => None,
            })
            .collect();
        let fits = could_fit(&recordings, &functions, &runners, &platform, &world);
        let searches = parallel(&recorders, |&a| {
            let rivals = fits.get(&a).map(Vec::as_slice).unwrap_or_default();
            search_look_alikes(a, &made, &functions, &runs, rivals, &platform, &world)
        });
        let searches: BTreeMap<usize, Search> = searches
            .into_iter()
            .filter_map(|search| Some((*records.get(search.of)?, search)))
            .collect();
        let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (index, &run) in runs.iter().enumerate() {
            members.entry(run).or_default().push(index);
        }
        // Who still fits whose recording once the separators are in.
        let mut fitting: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); made.len()];
        for a in 0..made.len() {
            let Some(search) = records.get(a).and_then(|class| searches.get(class)) else {
                continue;
            };
            if let Some(slot) = fitting.get_mut(a) {
                *slot = search
                    .fitting
                    .iter()
                    .filter_map(|run| members.get(run))
                    .flatten()
                    .copied()
                    .filter(|&b| b != a)
                    .collect();
            }
            // The separators: this function's own runs on the states
            // found for the first of its class.
            let own: Vec<(usize, Recorded)> = search
                .separators
                .iter()
                .filter_map(|(rival, recorded)| {
                    if a == search.of {
                        return Some((*rival, recorded.clone()));
                    }
                    let m = made.get(a)?;
                    let function = functions.get(a).copied().flatten()?;
                    let (run, _) = check::record_one(
                        subject(function),
                        &platform,
                        &world,
                        &m.shape,
                        &recorded.state,
                    );
                    Some((*rival, run.ok()?))
                })
                .collect();
            if let Some(Made {
                build:
                    Build {
                        check: Some(Check::Recorded(recording)),
                        ..
                    },
                ..
            }) = made.get_mut(a)
                && let Some(list) = separators.get_mut(a)
            {
                for (rival, recorded) in own {
                    list.push(Separator {
                        from: primaries.get(rival).cloned().unwrap_or_default(),
                        state: u32::try_from(recording.states.len()).unwrap_or(u32::MAX),
                    });
                    recording.states.push(recorded);
                }
            }
        }
        for (a, fits) in fitting.iter().enumerate() {
            for &b in fits {
                if fitting.get(b).is_some_and(|other| other.contains(&a)) {
                    // Each fits the other's recording: one group.
                    let (ra, rb) = (find(&mut groups, a), find(&mut groups, b));
                    if let (Some(slot), true) = (groups.get_mut(ra.max(rb)), ra != rb) {
                        *slot = ra.min(rb);
                    }
                } else if let (Some(list), Some(name)) = (look_alikes.get_mut(a), primaries.get(b))
                {
                    list.insert(name.clone());
                }
            }
        }
    }
    // Each group named by its least member's name.
    let roots: Vec<usize> = (0..made.len()).map(|i| find(&mut groups, i)).collect();
    let mut group_names: BTreeMap<usize, (usize, &str)> = BTreeMap::new();
    for (&root, name) in roots.iter().zip(&primaries) {
        let slot = group_names.entry(root).or_insert((0, name.as_str()));
        slot.0 += 1;
        slot.1 = slot.1.min(name.as_str());
    }
    let group_of = |index: usize| {
        let root = roots.get(index)?;
        let &(members, name) = group_names.get(root)?;
        (members > 1).then(|| name.to_owned())
    };
    let groups: Vec<Option<String>> = (0..made.len()).map(group_of).collect();
    Ok(made
        .into_iter()
        .zip(groups)
        .zip(look_alikes.into_iter().zip(separators))
        .map(|((m, group), (look_alikes, separators))| {
            let name = m.named.names.get(m.primary).cloned().unwrap_or_default();
            let mut aliases: Vec<String> = m
                .named
                .names
                .iter()
                .filter(|n| **n != name)
                .cloned()
                .collect();
            aliases.sort();
            aliases.dedup();
            Entry {
                name,
                aliases,
                copies: m.copies,
                group,
                look_alikes: look_alikes.into_iter().collect(),
                object: m.named.object,
                prototype: m.prototype,
                builds: [(options.build.clone(), Built::Record(Box::new(m.build)))]
                    .into_iter()
                    .collect(),
                separators,
            }
        })
        .collect())
}

/// How many of the separator search's states of each kind (of the
/// function's shape, of the other's) [`search_look_alikes`] tries on a
/// pair whose code fits: past them the pair stays unseparated, so it is
/// grouped or a look-alike, listed and never named. A bound costs only
/// look-alikes told apart (recall), never a wrong name. Most pairs no
/// state separates; most separators are among the first states of the
/// other's shape. Eight tries each of the search's eight variations
/// (`binbun_sigpack::check::spec`) once: on musl's 3-build pack it keeps 764
/// of 1,125 separators and every row's recall.
const SEPARATOR_BUDGET: u32 = 8;

/// What [`search_look_alikes`] found for one function.
struct Search {
    /// The function (its index in the functions made).
    of: usize,
    /// States telling it from a function whose code fit its recording,
    /// with that function's index and its own recorded run on the state.
    separators: Vec<(usize, Recorded)>,
    /// The classes of functions running alike whose code fits its
    /// recording, separators included.
    fitting: BTreeSet<usize>,
}

/// How many of a recording's first states [`could_fit`] tries.
const OPENINGS: usize = 8;

/// For each of `recorders` (indices of `made`) with a recording, the
/// `runners` whose code could fit it, in order: those whose run on each
/// of its first [`OPENINGS`] states agrees with it up to the first call
/// ([`check::Opening::may_agree`]). The others' replay would differ on
/// one of those states, so they do not fit. Each runner runs once per
/// state (a shape and a state number) the recordings have, not once per
/// recording, and from the second state on only if a recording of the
/// state is still to be told from it.
fn could_fit(
    recordings: &[(usize, &Recording)],
    functions: &[Option<&Analysed>],
    runners: &[usize],
    platform: &Platform<'_>,
    world: &ImageWorld<'_>,
) -> HashMap<usize, Vec<(usize, u32)>> {
    // The runners each recording could still fit (`None`: all), each with
    // the positions of the states its run skips (a bit each); none if no
    // replay agrees with it (states of another generator, or fewer than
    // the minimum).
    let all: Vec<(usize, u32)> = runners.iter().map(|&b| (b, 0)).collect();
    let mut fits: Vec<Option<Vec<(usize, u32)>>> = recordings
        .iter()
        .map(|(_, r)| {
            (r.generator != check::STATES || r.states.len() < check::MINIMUM).then(Vec::new)
        })
        .collect();
    for position in 0..OPENINGS {
        // The recordings still to be told apart, by their state there.
        type Key<'k> = (&'k Shape, u32, Option<&'k Shape>);
        let mut by_state: BTreeMap<usize, (Key<'_>, Vec<usize>)> = BTreeMap::new();
        let mut keys: HashMap<Key<'_>, usize> = HashMap::new();
        for (i, (_, recording)) in recordings.iter().enumerate() {
            let Some(recorded) = recording.states.get(position) else {
                continue;
            };
            if fits
                .get(i)
                .is_some_and(|f| f.as_ref().is_some_and(Vec::is_empty))
            {
                continue;
            }
            let shaped = match &recorded.state {
                StateId::Own(_) => None,
                StateId::Shaped(_, shape) => Some(shape),
            };
            let key = (&recording.shape, recorded.state.number(), shaped);
            let next = keys.len();
            let group = *keys.entry(key).or_insert(next);
            by_state.entry(group).or_insert((key, Vec::new())).1.push(i);
        }
        for ((shape, _, _), members) in by_state.into_values() {
            let Some(state) = members
                .first()
                .and_then(|&i| recordings.get(i))
                .and_then(|(_, r)| r.states.get(position))
                .map(|recorded| &recorded.state)
            else {
                continue;
            };
            let any = members
                .iter()
                .any(|&i| fits.get(i).is_some_and(Option::is_none));
            let needed: Vec<usize> = if any {
                runners.to_vec()
            } else {
                let union: BTreeSet<usize> = members
                    .iter()
                    .filter_map(|&i| fits.get(i)?.as_ref())
                    .flatten()
                    .map(|&(b, _)| b)
                    .collect();
                union.into_iter().collect()
            };
            // Each runner's opening; `None` if it has no code to run.
            let openings: BTreeMap<usize, Option<check::Opening>> = parallel(&needed, |&b| {
                let opening = functions
                    .get(b)
                    .copied()
                    .flatten()
                    .map(|f| check::opening(&f.l1, f.entry, platform, world, shape, state));
                (b, opening)
            })
            .into_iter()
            .collect();
            let kept = parallel(&members, |&i| {
                let (_, recording) = recordings.get(i)?;
                let recorded = recording.states.get(position)?;
                // A runner not opened (no thread ran it) is kept.
                let keep = |&(b, skipped): &(usize, u32)| match openings.get(&b) {
                    Some(Some(opening)) => opening
                        .may_agree(&recording.shape, recorded, platform, world)
                        .then(|| (b, skipped | u32::from(opening.skipped()) << position)),
                    Some(None) => None,
                    None => Some((b, skipped)),
                };
                let list = fits.get(i)?.as_deref().unwrap_or(&all);
                Some((i, list.iter().filter_map(keep).collect::<Vec<_>>()))
            });
            for (i, list) in kept.into_iter().flatten() {
                if let Some(slot) = fits.get_mut(i) {
                    *slot = Some(list);
                }
            }
        }
    }
    recordings
        .iter()
        .zip(fits)
        .map(|(&(a, _), list)| (a, list.unwrap_or_else(|| all.clone())))
        .collect()
}

/// Every class of functions running alike among `rivals` (the first
/// member of each, in order, with the states its opening skips as
/// [`could_fit`] gives them; `runs`: each function's class) whose code
/// fits the recording of function `of` (run as a binary's function would
/// be, its callees bound at first use), each told apart by a state of the
/// separator search (of its shape, else of the other's) if one does,
/// else fitting. Its own class fits without running.
fn search_look_alikes(
    of: usize,
    made: &[Made],
    functions: &[Option<&Analysed>],
    runs: &[usize],
    rivals: &[(usize, u32)],
    platform: &Platform<'_>,
    world: &ImageWorld<'_>,
) -> Search {
    let mut search = Search {
        of,
        separators: Vec::new(),
        fitting: BTreeSet::new(),
    };
    let (Some(m), Some(Some(own))) = (made.get(of), functions.get(of)) else {
        return search;
    };
    let Some(Check::Recorded(recording)) = &m.build.check else {
        return search;
    };
    let mut recording = recording.clone();
    let own_class = runs.get(of);
    if let Some(&class) = own_class {
        search.fitting.insert(class);
    }
    // Its runs on the search's states (by number and the other shape a
    // state is of; `None`: skipped), each run once whatever rivals it is
    // tried on.
    let mut own_runs: HashMap<(u32, Option<Shape>), Option<Recorded>> = HashMap::new();
    for &(other, skipped) in rivals {
        let Some(&class) = runs.get(other) else {
            continue;
        };
        if Some(&class) == own_class {
            continue;
        }
        let Some(function) = functions.get(other).copied().flatten() else {
            continue;
        };
        let verdict = check::replay_knowing(
            &function.l1,
            function.entry,
            platform,
            world,
            &recording,
            |index| index < 32 && skipped & (1 << index) != 0,
        );
        if !verdict.agrees() {
            continue;
        }
        let numbers = check::SEARCH..check::SEARCH + SEPARATOR_BUDGET.min(check::SEARCH_STATES);
        let theirs = made
            .get(other)
            .map(|o| &o.shape)
            .filter(|shape| **shape != m.shape);
        let states = numbers.clone().map(StateId::Own).chain(
            theirs
                .into_iter()
                .flat_map(move |shape| numbers.clone().map(|n| StateId::Shaped(n, shape.clone()))),
        );
        // The first state on which it does what the other does not.
        let found = states.into_iter().find_map(|state| {
            let shaped = match &state {
                StateId::Own(_) => None,
                StateId::Shaped(_, shape) => Some(shape.clone()),
            };
            let recorded = own_runs
                .entry((state.number(), shaped))
                .or_insert_with(|| {
                    check::record_one(subject(own), platform, world, &m.shape, &state)
                        .0
                        .ok()
                })
                .as_ref()?;
            check::separates(subject(function), &m.shape, platform, world, recorded)
                .then(|| recorded.clone())
        });
        match found {
            Some(recorded) => {
                recording.states.push(recorded.clone());
                search.separators.push((other, recorded));
            }
            None => {
                search.fitting.insert(class);
            }
        }
    }
    search
}

/// Identical definitions of `made` merged into one function with their
/// names as aliases: functions of one identity and the same masked bytes
/// and data references, whose callees are the same functions or are
/// themselves identical (to a fixed point), and which are not trivial or
/// call something (a forwarder: `malloc` and `__libc_malloc` both jump
/// to one allocator; trivial stubs without calls, `return 0` in many
/// objects, stay apart). The member holding the primary name of them all
/// ([`primary`]) stays.
fn merge_identical(
    made: &mut Vec<Made>,
    by_entry: &HashMap<u64, &Analysed>,
    library: &TypeLibrary,
) {
    let index_of: HashMap<u64, usize> = made
        .iter()
        .enumerate()
        .map(|(i, m)| (m.named.address, i))
        .collect();
    let canonical = |m: &Made| by_entry.get(&m.named.address).map(|a| &a.canonical);
    let mut class = number(made.iter().map(|m| {
        (
            m.build.identity,
            m.build.bytes.clone(),
            canonical(m).map(|c| c.data.clone()).unwrap_or_default(),
        )
    }));
    for _ in 0..made.len() {
        let refined = number(made.iter().enumerate().map(|(i, m)| {
            let callees: Vec<(bool, u64)> = canonical(m)
                .map(|c| c.code.as_slice())
                .unwrap_or_default()
                .iter()
                .map(|&address| {
                    index_of
                        .get(&address)
                        .and_then(|&j| class.get(j))
                        .map_or((false, address), |&k| (true, k as u64))
                })
                .collect();
            (class.get(i).copied().unwrap_or(usize::MAX), callees)
        }));
        // Refining only splits classes: as many as before, none split.
        let stable = refined.iter().max() == class.iter().max();
        class = refined;
        if stable {
            break;
        }
    }
    let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, &k) in class.iter().enumerate() {
        members.entry(k).or_default().push(index);
    }
    let mut absorbed = vec![false; made.len()];
    let mut merged: Vec<(usize, Vec<String>, usize, usize)> = Vec::new();
    for list in members.values().filter(|list| list.len() > 1) {
        if list
            .first()
            .and_then(|&i| made.get(i))
            .is_none_or(|m| m.build.trivial && canonical(m).is_none_or(|c| c.code.is_empty()))
        {
            continue;
        }
        let holders: Vec<(usize, &String)> = list
            .iter()
            .filter_map(|&i| made.get(i).map(|m| (i, m)))
            .flat_map(|(i, m)| m.named.names.iter().map(move |n| (i, n)))
            .collect();
        let mut all: Vec<String> = Vec::new();
        for (_, name) in &holders {
            if !all.contains(name) {
                all.push((*name).clone());
            }
        }
        let chosen = primary(&all, library);
        let Some(owner) = all
            .get(chosen)
            .and_then(|name| holders.iter().find(|(_, n)| *n == name))
            .map(|&(i, _)| i)
        else {
            continue;
        };
        for &i in list {
            if let (Some(slot), true) = (absorbed.get_mut(i), i != owner) {
                *slot = true;
            }
        }
        merged.push((owner, all, chosen, list.len()));
    }
    for (owner, names, chosen, copies) in merged {
        if let Some(m) = made.get_mut(owner) {
            m.named.names = names;
            m.primary = chosen;
            m.copies = u32::try_from(copies).unwrap_or(u32::MAX);
        }
    }
    let mut index = 0;
    made.retain(|_| {
        let keep = !absorbed.get(index).copied().unwrap_or(false);
        index += 1;
        keep
    });
}

/// Class numbers for `keys`: equal keys one number, by first occurrence.
fn number<K: Ord>(keys: impl Iterator<Item = K>) -> Vec<usize> {
    let mut numbers: BTreeMap<K, usize> = BTreeMap::new();
    keys.map(|key| {
        let next = numbers.len();
        *numbers.entry(key).or_insert(next)
    })
    .collect()
}

/// `f` as a subject of recording.
fn subject(f: &Analysed) -> Subject<'_> {
    Subject {
        function: &f.l1,
        entry: f.entry,
        masks: &f.canonical.masks,
    }
}

/// The root of `index` in the union-find `groups`.
fn find(groups: &mut [usize], index: usize) -> usize {
    let mut root = index;
    for _ in 0..groups.len() {
        match groups.get(root) {
            Some(&parent) if parent != root => root = parent,
            Some(_) | None => break,
        }
    }
    if let Some(slot) = groups.get_mut(index) {
        *slot = root;
    }
    root
}

/// The range of `named`'s code: its symbol's size, else up to the end of
/// the last block its L1 has.
fn extent(named: &Named, l1: &Function) -> core::ops::Range<u64> {
    let end = named.size.map_or_else(
        || {
            l1.blocks
                .iter()
                .map(|b| b.end + 1)
                .max()
                .unwrap_or(named.address)
        },
        |size| named.address + size,
    );
    named.address..end.max(named.address)
}

/// `named`'s bytes with relocated fields zeroed.
fn masked_bytes(input: &Source<'_>, named: &Named, l1: &Function) -> Vec<u8> {
    let range = extent(named, l1);
    let mut bytes = vec![0u8; usize::try_from(range.end - range.start).unwrap_or(0)];
    let count = input.image.read(range.start, &mut bytes).unwrap_or(0);
    bytes.truncate(count);
    if let Some(linked) = input.linked {
        for relocation in linked.relocations_in(range.clone()) {
            let at = usize::try_from(relocation.at - range.start).unwrap_or(usize::MAX);
            for byte in bytes.iter_mut().skip(at).take(usize::from(relocation.size)) {
                *byte = 0;
            }
        }
    }
    bytes
}

/// `named`'s code for a pack that carries it.
fn code(input: &Source<'_>, named: &Named, l1: &Function) -> Code {
    let range = extent(named, l1);
    let bytes = masked_bytes(input, named, l1);
    let relocs = input
        .linked
        .map(|linked| {
            linked
                .relocations_in(range.clone())
                .iter()
                .map(|r| {
                    (
                        u32::try_from(r.at - range.start).unwrap_or(u32::MAX),
                        r.kind_name(),
                        r.symbol.clone(),
                        r.addend,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Code {
        code: hex(&bytes),
        relocs,
    }
}

/// Type `id` of `library` through its typedefs.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "every type but a typedef is itself"
)]
fn resolve(library: &TypeLibrary, id: TypeId) -> Option<&Type> {
    let mut id = id;
    for _ in 0..64 {
        match library.ty(id)? {
            Type::Typedef(typedef) => id = typedef.target,
            other => return Some(other),
        }
    }
    None
}

/// The shape of a function declared as `signature` in `library`.
fn shape(library: &TypeLibrary, signature: &Signature<TypeId>) -> Shape {
    let mut params = Vec::new();
    let mut pointer_before = false;
    for param in &signature.params {
        let shape = match resolve(library, param.ty) {
            Some(Type::Pointer(target)) => {
                pointer_before = true;
                match resolve(library, *target) {
                    Some(Type::Char { .. } | Type::Int { size: 1, .. }) => Param::Str,
                    _ => Param::Buf,
                }
            }
            Some(Type::Int { signed, size }) => {
                let name = library.ty(param.ty).and_then(Type::key).unwrap_or_default();
                if pointer_before && !*signed && *size == 8 && name.contains("size_t") {
                    Param::Count
                } else {
                    Param::Int {
                        bytes: *size,
                        signed: *signed,
                    }
                }
            }
            Some(Type::Char { signed }) => Param::Int {
                bytes: 1,
                signed: *signed,
            },
            Some(Type::Bool) => Param::Int {
                bytes: 1,
                signed: false,
            },
            Some(Type::Enum(_)) => Param::Int {
                bytes: 4,
                signed: true,
            },
            Some(Type::Float(FloatFormat::Single)) => Param::Float(4),
            Some(Type::Float(FloatFormat::Double)) => Param::Float(8),
            _ => Param::Unknown,
        };
        params.push(shape);
    }
    let ret = match resolve(library, signature.ret) {
        Some(Type::Void) => Ret::Void,
        Some(Type::Pointer(_)) => Ret::Ptr,
        Some(Type::Int { size, .. }) => Ret::Int(*size),
        Some(Type::Char { .. } | Type::Bool) => Ret::Int(1),
        Some(Type::Enum(_)) => Ret::Int(4),
        Some(Type::Float(FloatFormat::Single)) => Ret::Float(4),
        Some(Type::Float(FloatFormat::Double)) => Ret::Float(8),
        _ => Ret::Unknown,
    };
    Shape { params, ret }
}

/// The shape of a function without a prototype: an unknown parameter for
/// each integer argument register up to the last it reads, a double for
/// each vector argument register up to the last it reads; a result if it
/// writes the first result register, else a double if it writes the
/// first vector result register.
fn unknown_shape(fingerprint: &Fingerprint, platform: &Platform<'_>) -> Shape {
    let integers = platform.abi.arguments.len();
    let vectors = platform.abi.float_arguments.len();
    let mask = fingerprint.arguments & ((1 << integers) - 1);
    let count = 32 - mask.leading_zeros();
    let vector_mask = (fingerprint.arguments >> integers) & ((1 << vectors) - 1);
    let vector_count = 32 - vector_mask.leading_zeros();
    let writes =
        |first: Option<&RegisterId>| first.is_some_and(|r| fingerprint.results.contains(&r.0));
    let mut params = vec![Param::Unknown; count as usize];
    params.extend(core::iter::repeat_n(Param::Float(8), vector_count as usize));
    Shape {
        params,
        ret: if writes(platform.abi.results.first()) {
            Ret::Unknown
        } else if writes(platform.abi.float_results.first()) {
            Ret::Float(8)
        } else {
            Ret::Void
        },
    }
}

/// `id` of `library` declared as `name` in C.
fn spell(library: &TypeLibrary, id: TypeId, name: &str) -> String {
    let mut declarator = name.to_owned();
    let mut id = id;
    for _ in 0..64 {
        let base = match library.ty(id) {
            Some(&Type::Pointer(target)) => {
                declarator.insert(0, '*');
                id = target;
                continue;
            }
            Some(&Type::Array { element, count }) => {
                if declarator.starts_with('*') {
                    declarator = format!("({declarator})");
                }
                declarator = format!(
                    "{declarator}[{}]",
                    count.map(|n| n.to_string()).unwrap_or_default()
                );
                id = element;
                continue;
            }
            Some(Type::Function(signature)) => {
                if declarator.starts_with('*') {
                    declarator = format!("({declarator})");
                }
                declarator = format!("{declarator}({})", parameters(library, signature));
                id = signature.ret;
                continue;
            }
            Some(Type::Void) | None => "void".to_owned(),
            Some(Type::Bool) => "_Bool".to_owned(),
            Some(Type::Char { .. }) => "char".to_owned(),
            Some(&Type::Int { signed, size }) => {
                let base = match size {
                    1 => "char",
                    2 => "short",
                    4 => "int",
                    8 => "long",
                    _ => "__int128",
                };
                match (signed, size) {
                    (true, 1) => "signed char".to_owned(),
                    (true, _) => base.to_owned(),
                    (false, _) => format!("unsigned {base}"),
                }
            }
            Some(Type::Float(format)) => match format {
                FloatFormat::Half => "_Float16",
                FloatFormat::Single => "float",
                FloatFormat::Double => "double",
                FloatFormat::X87 => "long double",
                FloatFormat::Quad => "_Float128",
            }
            .to_owned(),
            Some(Type::Record(record)) => record.key.clone(),
            Some(Type::Enum(definition)) => definition.key.clone(),
            Some(Type::Typedef(typedef)) => typedef.name.clone(),
            Some(Type::Opaque(opaque)) => opaque.name.clone(),
        };
        return if declarator.is_empty() {
            base
        } else {
            format!("{base} {declarator}")
        };
    }
    "void".to_owned()
}

/// The parameter list of `signature` in C.
fn parameters(library: &TypeLibrary, signature: &Signature<TypeId>) -> String {
    let mut parameters: Vec<String> = signature
        .params
        .iter()
        .map(|param| spell(library, param.ty, param.name.as_deref().unwrap_or("")))
        .collect();
    if signature.variadic {
        parameters.push("...".to_owned());
    } else if parameters.is_empty() {
        parameters.push("void".to_owned());
    }
    parameters.join(", ")
}

/// `name` declared with `signature` in C.
fn spell_prototype(library: &TypeLibrary, signature: &Signature<TypeId>, name: &str) -> String {
    let declarator = format!("{name}({})", parameters(library, signature));
    spell(library, signature.ret, &declarator)
}

/// How a function was named, or why not.
#[derive(Clone, Debug, PartialEq)]
pub enum How {
    /// Its identity is a unique, non-trivial one of the pack, and no
    /// other candidate's behaviour fits.
    Exact,
    /// Its behaviour fits this candidate's recording on this many states,
    /// every other candidate's not (its own does not fit, or it calls a
    /// function named otherwise than the candidate's callee).
    Behaviour {
        /// The states that agreed.
        states: usize,
        /// The candidates ruled out, each with the state and what
        /// differed (state 0 and the callee for a contradicted call).
        rivals: Vec<(String, u32, String)>,
    },
}

/// The result for one function of a binary.
#[derive(Clone, Debug, PartialEq)]
pub struct Match {
    /// Its entry.
    pub entry: u64,
    /// Its identity.
    pub identity: Identity,
    /// The name given, if one: the pack entry (its index in the packs:
    /// pack, entry) and how.
    pub named: Option<((usize, usize), How)>,
    /// The candidates it could be, when none is given: the identities'
    /// entries (trivial or shared), and those whose behaviour fits.
    pub candidates: Vec<(usize, usize)>,
    /// Whether it could not be checked by running (exact only).
    pub uncheckable: bool,
    /// The index's candidates for its fingerprint, best first (at most
    /// [`binbun_sigpack::index::CANDIDATES`]).
    pub proposed: Vec<(usize, usize)>,
    /// Whether recovery found it only by looking where the packs said
    /// ([`MatchOptions::sweep`]) or where a forwarder jumps: such a
    /// function is reported only when named.
    pub found: bool,
    /// Why it is not named though it has candidates, if it is not.
    pub why: Option<String>,
}

/// What matching does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MatchOptions {
    /// Check candidates by running the functions on their recordings
    /// ([`binbun_sigpack::check`]); else exact identities only.
    pub behaviour: bool,
    /// Look for functions recovery did not find: at the first instruction
    /// after padding in each stretch of code no block covers, over rounds
    /// (each found function's end opens the next), keeping those a pack
    /// names.
    pub sweep: bool,
}

/// A pack entry: its pack's index and its index there.
type Key = (usize, usize);

/// The packs matched against, indexed.
struct Packs<'p> {
    all: &'p [Pack],
    /// Every entry by identity.
    by_identity: HashMap<Identity, BTreeSet<Key>>,
    /// The fingerprints.
    index: Index<Key>,
    /// Entries by name and alias, per pack.
    by_name: HashMap<(usize, &'p str), Vec<Key>>,
    /// The members of each group, per pack.
    groups: HashMap<(usize, &'p str), Vec<Key>>,
    /// The entries forwarding to each entry ([`forwarded`]): a
    /// compiler inlining the callee makes a forwarder behave as it.
    forwarders: HashMap<Key, Vec<Key>>,
    /// The entries calling each entry of their own object (a compiler may
    /// inline a function into its object's callers, which then run as it
    /// on its recording: `__acrt_getptd_noexit` with
    /// `internal_get_ptd_head_slow` inlined).
    inliners: HashMap<Key, Vec<Key>>,
    /// The entries that are instances of generic code, each with the
    /// callees (symbols) that are functions of its types
    /// ([`instance`]).
    instances: HashMap<Key, (String, BTreeSet<String>)>,
    /// Per pack, why it names by identity only, if it does: a Rust pack
    /// of another toolchain than the binary's ([`elect`]).
    foreign: Vec<Option<String>>,
}

impl<'p> Packs<'p> {
    /// `packs` indexed, those `usable` holds false for left out (their
    /// indices kept); `foreign` as [`Packs::foreign`].
    fn new(packs: &'p [Pack], usable: &[bool], foreign: Vec<Option<String>>) -> Self {
        let used = || {
            packs
                .iter()
                .enumerate()
                .filter(|&(p, _)| usable.get(p).copied().unwrap_or(true))
        };
        let mut by_identity: HashMap<Identity, BTreeSet<Key>> = HashMap::new();
        let mut by_name: HashMap<(usize, &str), Vec<Key>> = HashMap::new();
        let mut groups: HashMap<(usize, &str), Vec<Key>> = HashMap::new();
        let mut fingerprints = Vec::new();
        for (p, pack) in used() {
            for (e, entry) in pack.functions.iter().enumerate() {
                // A funclet is named with its function, never alone.
                if funclet(&entry.name) {
                    continue;
                }
                for id in entry.builds.keys() {
                    if let Some(build) = pack.build(entry, id) {
                        by_identity
                            .entry(build.identity)
                            .or_default()
                            .insert((p, e));
                        fingerprints.push(((p, e), build.fingerprint.clone()));
                    }
                }
                for name in core::iter::once(&entry.name).chain(&entry.aliases) {
                    by_name.entry((p, name)).or_default().push((p, e));
                }
                if let Some(group) = &entry.group {
                    groups.entry((p, group)).or_default().push((p, e));
                }
            }
        }
        let mut forwarders: HashMap<Key, Vec<Key>> = HashMap::new();
        let mut inliners: HashMap<Key, Vec<Key>> = HashMap::new();
        let mut instances = HashMap::new();
        for (p, pack) in used() {
            for (e, entry) in pack.functions.iter().enumerate() {
                let records = || entry.builds.keys().filter_map(|id| pack.build(entry, id));
                let callees: BTreeSet<&str> = records()
                    .flat_map(|b| &b.callees)
                    .map(String::as_str)
                    .collect();
                for callee in callees {
                    for &to in by_name.get(&(p, callee)).into_iter().flatten() {
                        let own = !entry.object.is_empty()
                            && pack
                                .functions
                                .get(to.1)
                                .is_some_and(|callee| callee.object == entry.object);
                        if to != (p, e) && own {
                            inliners.entry(to).or_default().push((p, e));
                        }
                    }
                }
                let targets: BTreeSet<(&str, u32)> = records()
                    .filter_map(|b| Some((forwarded(b)?, b.fingerprint.arguments)))
                    .collect();
                for (target, arguments) in targets {
                    for &to in by_name.get(&(p, target)).into_iter().flatten() {
                        // Its arguments passed on as they are: with the
                        // callee inlined it is the callee.
                        let passed = packs.get(to.0).is_some_and(|pack| {
                            pack.functions.get(to.1).is_some_and(|callee| {
                                callee.builds.keys().any(|id| {
                                    pack.build(callee, id)
                                        .is_some_and(|b| b.fingerprint.arguments == arguments)
                                })
                            })
                        });
                        let together = entry.group.is_some()
                            && packs
                                .get(to.0)
                                .and_then(|pack| pack.functions.get(to.1))
                                .is_some_and(|other| other.group == entry.group);
                        if to != (p, e) && passed && !together {
                            forwarders.entry(to).or_default().push((p, e));
                        }
                    }
                }
                if let Some(found) = instance(&entry.name, records().flat_map(|b| &b.callees)) {
                    instances.insert((p, e), found);
                }
            }
        }
        Self {
            all: packs,
            by_identity,
            index: Index::new(fingerprints),
            by_name,
            groups,
            forwarders,
            inliners,
            instances,
            foreign,
        }
    }

    fn entry(&self, (p, e): Key) -> Option<&'p Entry> {
        self.all.get(p)?.functions.get(e)
    }

    /// Whether `name` is a function's name in `key`'s entry.
    fn names(&self, key: Key, name: &str) -> bool {
        self.entry(key)
            .is_some_and(|e| e.name == name || e.aliases.iter().any(|a| a == name))
    }

    /// Whether `name` is the name of a function of pack `p`.
    fn is_function(&self, p: usize, name: &str) -> bool {
        self.by_name.contains_key(&(p, name))
    }

    /// The entries a function fitting `key`'s recording could also be:
    /// its group's other members and its look-alikes.
    fn related(&self, key: Key) -> Vec<Key> {
        let Some(entry) = self.entry(key) else {
            return Vec::new();
        };
        let group = entry
            .group
            .as_deref()
            .and_then(|g| self.groups.get(&(key.0, g)));
        let alike = entry
            .look_alikes
            .iter()
            .filter_map(|name| self.by_name.get(&(key.0, name.as_str())));
        group
            .into_iter()
            .chain(alike)
            .flatten()
            .copied()
            .filter(|&k| k != key)
            .collect()
    }
}

/// The generic code a function named `name` is an instance of (a Rust
/// generic function or impl for some types, a trait's default method for
/// one, a C++ template for some arguments), if it is one, and those of
/// its `callees` (symbols) that are functions of the types it is for: a
/// Rust callee whose path mentions one, a C++ one whose name, scopes or
/// their template arguments are one.
fn instance<'c>(
    name: &str,
    callees: impl Iterator<Item = &'c String>,
) -> Option<(String, BTreeSet<String>)> {
    let (generic, own): (String, BTreeSet<String>) =
        if let Some(found) = binbun_sigpack::rust::instance(name) {
            let own = callees
                .filter(|callee| {
                    binbun_sigpack::rust::path(callee)
                        .is_some_and(|path| found.types.iter().any(|ty| path.contains(ty.as_str())))
                })
                .cloned()
                .collect();
            (found.generic, own)
        } else {
            let found = msvc::instance(name)?;
            let own = callees
                .filter(|callee| {
                    callee.starts_with('?')
                        && msvc::names(callee).iter().any(|n| found.types.contains(n))
                })
                .cloned()
                .collect();
            (found.generic, own)
        };
    Some((generic, own))
}

/// The function `build` forwards to, if it is a forwarder: one small block
/// whose one call, a tail call (it writes no result of its own: `strcpy`
/// returning its argument after calling `stpcpy` is none), goes to a
/// named function, with nothing else it calls or loops over
/// (`__iswcntrl_l(c, l)` returning `iswcntrl(c)`). [`Packs::new`] keeps
/// those passing on the arguments the callee reads as they are.
fn forwarded(build: &Build) -> Option<&str> {
    let f = &build.fingerprint;
    let [callee] = build.callees.as_slice() else {
        return None;
    };
    (f.blocks == 1
        && f.calls == 1
        && f.loops == 0
        && f.system_calls == 0
        && f.results.is_empty()
        && f.size <= FORWARDER_SIZE
        && !callee.is_empty())
    .then_some(callee.as_str())
}

/// The most operations a forwarder has: its arguments passed on, the
/// call, its result returned.
const FORWARDER_SIZE: u32 = 16;

/// How one candidate compared with a function.
#[derive(Clone, Debug)]
enum Outcome {
    /// Its recording fits: the states that agreed, why that is too little
    /// to name the function by (the runs entered under half its blocks,
    /// the recording does one thing whatever the input, or every state
    /// that agreed faults before the function does anything), if it is,
    /// and the pack's functions bound to the binary's addresses (calls),
    /// by name.
    Agrees {
        states: usize,
        weak: Option<&'static str>,
        bound: Vec<(String, u64)>,
    },
    /// A state differs: which and how.
    Differs(u32, String),
    /// Neither: too few states ran.
    Unresolved,
    /// It has no recording.
    Unrecorded,
}

/// A function's candidates, checked.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent traits of the function's code and how it was found"
)]
struct Checked {
    entry: u64,
    identity: Identity,
    trivial: bool,
    /// Whether its identity would be trivial but for its constants: a
    /// few operations on a value such as a thread-local variable's
    /// offset, which static linking chooses (each constant one linking
    /// could choose: [`linkable`]).
    small: bool,
    /// Whether it is [`tiny`].
    tiny: bool,
    /// The entries of its identity.
    exact: BTreeSet<Key>,
    /// The index's candidates.
    proposed: Vec<Key>,
    /// Each candidate run (with behaviour checking): the identity's, the
    /// index's, and the group members and look-alikes of each that fits.
    outcomes: BTreeMap<Key, Outcome>,
    found: bool,
    /// The functions it calls or jumps to (other functions' entries).
    calls: Vec<u64>,
}

/// `function`'s candidates in `packs`, each checked if `behaviour`.
fn check_candidates(
    function: &Analysed,
    packs: &Packs<'_>,
    platform: &Platform<'_>,
    world: &ImageWorld<'_>,
    behaviour: bool,
) -> (BTreeSet<Key>, Vec<Key>, BTreeMap<Key, Outcome>) {
    let canonical = &function.canonical;
    let exact = packs
        .by_identity
        .get(&canonical.identity)
        .cloned()
        .unwrap_or_default();
    let proposed: Vec<Key> = packs
        .index
        .query(&canonical.fingerprint, false)
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let mut outcomes = BTreeMap::new();
    if !behaviour {
        return (exact, proposed, outcomes);
    }
    let mut queue: Vec<Key> = exact.iter().chain(&proposed).copied().collect();
    while let Some(key) = queue.pop() {
        if outcomes.contains_key(&key) {
            continue;
        }
        let (Some(pack), Some(entry)) = (packs.all.get(key.0), packs.entry(key)) else {
            continue;
        };
        let mut outcome = Outcome::Unrecorded;
        for id in entry.builds.keys() {
            let Some(Check::Recorded(recording)) =
                pack.build(entry, id).and_then(|b| b.check.as_ref())
            else {
                continue;
            };
            let verdict = check::replay(&function.l1, function.entry, platform, world, recording);
            if verdict.agrees() {
                outcome = Outcome::Agrees {
                    states: verdict.agreed,
                    weak: if verdict.covered.len() * 2 < function.reachable {
                        Some("the runs entered under half its blocks")
                    } else if !verdict.varied {
                        Some(ONE_THING)
                    } else if verdict.faulted == verdict.agreed {
                        Some("the states that agreed all fault before it does anything")
                    } else {
                        None
                    },
                    bound: verdict
                        .bindings
                        .bound()
                        .filter(|(name, _)| packs.is_function(key.0, name))
                        .map(|(name, address)| (name.to_owned(), address))
                        .collect(),
                };
                break;
            }
            outcome = match (verdict.differs, outcome) {
                (Some((state, what)), _) | (None, Outcome::Differs(state, what)) => {
                    Outcome::Differs(state, what)
                }
                (None, _) => Outcome::Unresolved,
            };
        }
        if matches!(outcome, Outcome::Agrees { .. }) {
            queue.extend(packs.related(key));
        }
        outcomes.insert(key, outcome);
    }
    (exact, proposed, outcomes)
}

/// What one function is named, or listed as, given the names of the
/// others (`names`, by entry).
struct Decision {
    named: Option<(Key, How)>,
    candidates: Vec<Key>,
    uncheckable: bool,
    /// Why it is not named, if it has candidates.
    why: Option<String>,
}

/// The decision for `checked`: a unique non-trivial identity is
/// named unless its own recording does not fit or another candidate's
/// also does, strongly (its group's other members are candidates when
/// it fits; without behaviour checking, it must be alone in its group);
/// nor when the identity is a few operations on constants and its
/// recording does one thing on every state: glibc's
/// `__h_errno_location`, `return &h_errno`, has the identity of the
/// binary's `__ctype_tolower_loc` when the pack's linking gave `h_errno`
/// the offset the binary's gives `__libc_tsd_CTYPE_TOLOWER`;
/// otherwise a name is given by behaviour only when exactly one candidate fits, every
/// other candidate within reach (the index's, the identity's, and the
/// group members and look-alikes of each that fits) was ruled out, the
/// runs covered at least half the function's blocks, and the recording
/// does not do one thing on every state (fault at one address, return
/// one value), which any function failing or ending alike would fit.
/// A name by behaviour is further withheld for a trivial function the
/// library does not declare (no prototype: a static function, which a
/// program's own code cannot call), unless library code fitting its
/// callers calls it so (`called`): the program's `zcfree(opaque, p)`
/// calling `free(p)` is glibc's static `deallocate` to every check; and
/// for a candidate of a pack that names by identity only
/// ([`Packs::foreign`]).
///
/// A candidate is ruled out by a call its runs made to a function of
/// its pack (bound to the binary's function there) that is named
/// otherwise, and, for a variadic function whose one call passes its
/// arguments on (`fscanf` calling `vfscanf`: any `f(a, b, ...)` doing
/// `return g(a, b, ap)` is that code), by one to a function not named
/// so: Lua's `luaO_pushfstring(L, fmt, ...)` is musl's `fscanf` to the
/// instruction, but calls `luaO_pushvfstring`. It is ruled out too when
/// the function calls one named as no build of the candidate calls:
/// `tan`, calling `__tan`, fits `sin`'s recording, whose states all
/// return before `sin` would call `__sin`.
#[expect(
    clippy::too_many_lines,
    reason = "the exact rule, then the behaviour rule, each with why not"
)]
fn decide(
    checked: &Checked,
    names: &HashMap<u64, Key>,
    called: &HashMap<u64, HashSet<&str>>,
    packs: &Packs<'_>,
    behaviour: bool,
) -> Decision {
    let name_of = |key: Key| {
        packs
            .entry(key)
            .map_or_else(String::new, |e| e.name.clone())
    };
    let unique_exact = (checked.exact.len() == 1 && !checked.trivial)
        .then(|| checked.exact.first().copied())
        .flatten();
    if !behaviour {
        let alone = |key: &Key| packs.entry(*key).is_some_and(|e| e.group.is_none());
        return match unique_exact.filter(alone) {
            Some(key) => Decision {
                named: Some((key, How::Exact)),
                candidates: Vec::new(),
                uncheckable: false,
                why: None,
            },
            None => Decision {
                named: None,
                candidates: checked.exact.iter().copied().collect(),
                uncheckable: false,
                why: (!checked.exact.is_empty())
                    .then(|| "its identity is not unique, trivial or in a group".to_owned()),
            },
        };
    }
    // A call bound to a function named otherwise contradicts; for a
    // variadic function passing its arguments on, one bound to a
    // function not named as its callee too.
    let contradiction = |key: Key, bound: &[(String, u64)]| {
        let forwards = packs
            .all
            .get(key.0)
            .zip(packs.entry(key))
            .and_then(|(pack, entry)| {
                if !entry.prototype.as_deref()?.contains("...") {
                    return None;
                }
                let callees: BTreeSet<&str> = entry
                    .builds
                    .keys()
                    .filter_map(|id| pack.build(entry, id))
                    .flat_map(|b| &b.callees)
                    .map(String::as_str)
                    .filter(|&name| name != "__stack_chk_fail")
                    .collect();
                match callees.into_iter().collect::<Vec<_>>()[..] {
                    [only] => Some(only),
                    _ => None,
                }
            });
        bound.iter().find_map(|(name, address)| {
            if *address == checked.entry {
                return None;
            }
            match names.get(address) {
                Some(&holder) => (!packs.names(holder, name))
                    .then(|| format!("its call to {name} goes to a function named otherwise")),
                None => (forwards == Some(name.as_str())).then(|| {
                    format!("it passes its arguments on to {name}, and the function it calls is not named so")
                }),
            }
        })
    };
    // A call to a function named as no build of the candidate calls (if
    // the candidate calls only functions of its pack: a symbol that names
    // none, such as musl's `__memcpy_fwd` label inside `memcpy`, could be
    // any of them).
    let foreign_call = |key: Key| {
        let (pack, entry) = (packs.all.get(key.0)?, packs.entry(key)?);
        let callees: Vec<&String> = entry
            .builds
            .keys()
            .filter_map(|id| pack.build(entry, id))
            .flat_map(|b| &b.callees)
            .collect();
        if callees.iter().any(|name| !packs.is_function(key.0, name)) {
            return None;
        }
        checked.calls.iter().find_map(|address| {
            let &holder = names.get(address)?;
            let holder_name = &packs.entry(holder)?.name;
            (!callees.iter().any(|name| packs.names(holder, name)))
                .then(|| format!("it calls {holder_name}, which {} never calls", entry.name))
        })
    };
    let mut agreeing: Vec<(Key, usize, Option<&'static str>)> = Vec::new();
    let mut rivals: Vec<(String, u32, String)> = Vec::new();
    let mut unresolved: Option<String> = None;
    for (&key, outcome) in &checked.outcomes {
        match outcome {
            Outcome::Agrees {
                states,
                weak,
                bound,
            } => match contradiction(key, bound).or_else(|| foreign_call(key)) {
                Some(why) => rivals.push((name_of(key), 0, why)),
                None => agreeing.push((key, *states, *weak)),
            },
            Outcome::Differs(state, what) => rivals.push((name_of(key), *state, what.clone())),
            Outcome::Unresolved | Outcome::Unrecorded => {
                if Some(key) != unique_exact && unresolved.is_none() {
                    unresolved = Some(name_of(key));
                }
            }
        }
    }
    // Entries of one name are one answer (a static function defined alike
    // in several objects).
    let mut seen = BTreeSet::new();
    agreeing.retain(|&(key, ..)| seen.insert(name_of(key)));
    let listed = || {
        let mut candidates: Vec<Key> = agreeing
            .iter()
            .map(|&(key, ..)| key)
            .chain(checked.exact.iter().copied())
            .collect();
        candidates.sort_unstable();
        candidates.dedup();
        candidates
    };
    if let Some(key) = unique_exact {
        let own = checked.outcomes.get(&key);
        let own_name = name_of(key);
        let fits = agreeing.iter().any(|&(k, ..)| name_of(k) == own_name);
        // Another candidate fitting only weakly (a recording doing one
        // thing whatever the input) says nothing against the identity.
        let strong_rivals = || {
            agreeing
                .iter()
                .filter(|&&(k, _, weak)| weak.is_none() && name_of(k) != own_name)
        };
        let others = strong_rivals().next().is_some();
        let uncheckable = matches!(own, None | Some(Outcome::Unrecorded | Outcome::Unresolved));
        // An identity that is its constants, confirmed by a recording
        // doing one thing on every state, is confirmed by nothing.
        let unconfirmed = checked.small
            && agreeing
                .iter()
                .any(|&(k, _, weak)| weak == Some(ONE_THING) && name_of(k) == own_name);
        let why = if others {
            let names: Vec<String> = strong_rivals().map(|&(k, ..)| name_of(k)).collect();
            Some(format!(
                "its identity's, and {} more fit: {}",
                names.len(),
                names.join(", ")
            ))
        } else if unconfirmed {
            Some(format!(
                "its identity is a few operations on constants (a thread-local variable's offset is one), and {ONE_THING}"
            ))
        } else if !(fits || uncheckable) {
            Some(
                rivals
                    .iter()
                    .find(|(name, ..)| *name == name_of(key))
                    .map_or_else(
                        || "its identity's recording does not fit".to_owned(),
                        |(_, state, what)| {
                            format!("its identity's recording does not fit (state {state}: {what})")
                        },
                    ),
            )
        } else {
            None
        };
        return if why.is_none() {
            Decision {
                named: Some((key, How::Exact)),
                candidates: Vec::new(),
                uncheckable,
                why,
            }
        } else {
            Decision {
                named: None,
                candidates: listed(),
                uncheckable,
                why,
            }
        };
    }
    let why = match (agreeing.as_slice(), &unresolved) {
        // A compiler's clone (`.constprop.0`, `.isra.0`, `.part.0`) does
        // what the function it was cloned from does for some arguments:
        // that function, in a binary built otherwise, fits it too.
        (&[(key, _, None)], None) if name_of(key).contains('.') => {
            Some("a compiler's clone is named by its identity only".to_owned())
        }
        (&[(key, _, None)], None)
            if checked.trivial
                && packs.entry(key).is_some_and(|e| e.prototype.is_none())
                && !called
                    .get(&checked.entry)
                    .is_some_and(|ns| ns.iter().any(|n| packs.names(key, n))) =>
        {
            Some(format!(
                "{}: a trivial function the library does not declare is named by behaviour only where library code calls it so",
                name_of(key)
            ))
        }
        (&[(key, _, None)], None) if packs.foreign.get(key.0).is_some_and(Option::is_some) => {
            packs.foreign.get(key.0).cloned().flatten()
        }
        ([], _) | (&[(_, _, None)], None) => None,
        (&[(_, _, Some(weak))], None) => Some(weak.to_owned()),
        ([_], Some(name)) => Some(format!("{name} could not be checked")),
        (many, _) => Some(format!(
            "{} candidates fit: {}",
            many.len(),
            many.iter()
                .map(|&(k, ..)| name_of(k))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    };
    match agreeing.as_slice() {
        &[(key, states, None)] if why.is_none() => Decision {
            named: Some((key, How::Behaviour { states, rivals })),
            candidates: Vec::new(),
            uncheckable: false,
            why: None,
        },
        _ => Decision {
            named: None,
            candidates: listed(),
            uncheckable: false,
            why,
        },
    }
}

/// How many rounds the sweep and the naming fixed point take at most.
const ROUNDS: usize = 64;

/// Why a recording fitting says little: whatever the input, it does one
/// thing (faults at one address, returns one value).
const ONE_THING: &str = "its recording does one thing on every state";

/// Names given at more addresses than the library has the function
/// ([`Entry::copies`]) withdrawn, the functions listed with it: one of
/// them at least is another function that behaves the same (another
/// compiler made `__isalnum_l` the code of `isalnum`, where the pack's
/// build has it call `isalnum`).
fn unname_repeated(decisions: &mut [Decision], packs: &Packs<'_>) {
    let mut count: HashMap<Key, u32> = HashMap::new();
    for decision in decisions.iter() {
        if let Some((key, _)) = &decision.named {
            *count.entry(*key).or_default() += 1;
        }
    }
    for decision in decisions.iter_mut() {
        let Some((key, _)) = &decision.named else {
            continue;
        };
        let key = *key;
        let times = count.get(&key).copied().unwrap_or(0);
        let Some(entry) = packs.entry(key).filter(|e| times > e.copies) else {
            continue;
        };
        decision.why = Some(format!(
            "{} would be named at {times} addresses; the library has it {}",
            entry.name,
            if entry.copies == 1 {
                "once".to_owned()
            } else {
                format!("{} times", entry.copies)
            }
        ));
        decision.named = None;
        if !decision.candidates.contains(&key) {
            decision.candidates.push(key);
        }
    }
}

/// Names withdrawn where what fits could as well be a function the packs
/// do not hold apart from it, given the names of the previous round
/// (`names`, by entry):
///
/// - an instance of generic code (a Rust default method or generic
///   function for some type, a C++ template for some arguments: an STL
///   tree's `_Rrotate` for the runtime's own map and a program's
///   `map<int, int>`): another type's instance runs alike, so it
///   is named only when the functions of its types it calls were bound to
///   functions named so (`<Adapter<StderrLock> as Write>::write_char`
///   fits rustc-demangle's `<SizeLimitedFmtAdapter as Write>::write_char`,
///   whose `write_str` is no `Adapter`'s);
/// - a function others forward to with their arguments as they are
///   (`__iswcntrl_l(c, l)` returns `iswcntrl(c)`): another compiler
///   inlines the callee into the forwarder, which then behaves as the
///   callee, so the callee's name is given only when each forwarder is
///   named elsewhere, or callers whose library code fits call the
///   function as the callee and none as a forwarder.
/// - a function its object's other functions call, named by behaviour: a
///   compiler may inline it into them (`__acrt_getptd_noexit` with
///   `internal_get_ptd_head_slow` inlined fits the latter's recording),
///   so it is named only when each of them is named elsewhere, or a
///   function named calls it by its name.
/// - a function whose recording other functions of its library fit too
///   (its group's members, its look-alikes: code that differs from it in
///   what it calls, `fscanf` passing its arguments to `vfscanf` as
///   Lua's `luaO_pushfstring` passes them to `luaO_pushvfstring`): its
///   calls are all that tells it apart, so it is named only when each
///   function of the packs its calls were bound to is named so there.
/// - a tiny function ([`tiny`]: a getter, `return -1`): its code says too
///   little to tell it from a program's own of the same few operations
///   (`basic_ios::tie` is any class's getter of a field at that offset),
///   so it is named only when a function named in the binary calls it
///   by its name (that function's library code binds it so).
#[expect(
    clippy::too_many_lines,
    reason = "one rule after another, each with why"
)]
fn unname_unsettled(
    decisions: &mut [Decision],
    checked: &[Checked],
    packs: &Packs<'_>,
    names: &HashMap<u64, Key>,
    called: &HashMap<u64, HashSet<&str>>,
) {
    fn bound(c: &Checked, key: Key) -> &[(String, u64)] {
        match c.outcomes.get(&key) {
            Some(Outcome::Agrees { bound, .. }) => bound.as_slice(),
            _ => &[],
        }
    }
    // Where each name is given.
    let mut named_at: HashMap<Key, Vec<u64>> = HashMap::new();
    // What each address is called as by functions named.
    let mut called_by_named: HashMap<u64, HashSet<&str>> = HashMap::new();
    for c in checked {
        if let Some(&key) = names.get(&c.entry) {
            named_at.entry(key).or_default().push(c.entry);
            for (name, address) in bound(c, key) {
                if *address != c.entry {
                    called_by_named.entry(*address).or_default().insert(name);
                }
            }
        }
    }
    let name_of = |key: Key| packs.entry(key).map_or("", |e| e.name.as_str());
    for (decision, c) in decisions.iter_mut().zip(checked) {
        let Some((key, how)) = &decision.named else {
            continue;
        };
        let key = *key;
        let by_behaviour = matches!(how, How::Behaviour { .. });
        let mut why = None;
        if let Some((generic, own)) = packs.instances.get(&key) {
            // A recursive call confirms nothing.
            let calls: Vec<&(String, u64)> = bound(c, key)
                .iter()
                .filter(|(name, address)| *address != c.entry && own.contains(name))
                .collect();
            let confirmed = !calls.is_empty()
                && calls.iter().all(|(name, address)| {
                    names
                        .get(address)
                        .is_some_and(|&holder| packs.names(holder, name))
                });
            if !confirmed {
                why = Some(format!(
                    "an instance of {generic}: another type's runs alike, and the functions of its types it calls are not named so"
                ));
            }
        }
        let unsettled = packs.forwarders.get(&key).and_then(|forwarders| {
            // Called as the callee, and never as a forwarder of it.
            let as_names = called.get(&c.entry);
            let called_as =
                |k: Key| as_names.is_some_and(|ns| ns.iter().any(|n| packs.names(k, n)));
            if called_as(key) && !forwarders.iter().any(|&f| called_as(f)) {
                return None;
            }
            forwarders.iter().copied().find(|forwarder| {
                !named_at
                    .get(forwarder)
                    .is_some_and(|at| at.iter().any(|&a| a != c.entry))
            })
        });
        if let (None, Some(forwarder)) = (&why, unsettled) {
            why = Some(format!(
                "{} forwards to {}: with it inlined it runs alike, and is named nowhere else",
                name_of(forwarder),
                name_of(key)
            ));
            if !decision.candidates.contains(&forwarder) {
                decision.candidates.push(forwarder);
            }
        }
        let alike = packs
            .entry(key)
            .is_some_and(|e| e.group.is_some() || !e.look_alikes.is_empty());
        let called_so = called_by_named
            .get(&c.entry)
            .is_some_and(|ns| ns.iter().any(|n| packs.names(key, n)));
        if why.is_none() && by_behaviour {
            let mut otherwise: Vec<&str> = called_by_named
                .get(&c.entry)
                .into_iter()
                .flatten()
                .copied()
                .filter(|n| packs.is_function(key.0, n) && !packs.names(key, n))
                .collect();
            otherwise.sort_unstable();
            if let Some(other) = otherwise.first() {
                why = Some(format!(
                    "a function named calls it as {other}, whose recording {} fits",
                    name_of(key)
                ));
            }
        }
        if why.is_none() && by_behaviour && !called_so {
            let inliner = packs.inliners.get(&key).and_then(|inliners| {
                inliners.iter().copied().find(|inliner| {
                    !named_at
                        .get(inliner)
                        .is_some_and(|at| at.iter().any(|&a| a != c.entry))
                })
            });
            if let Some(inliner) = inliner {
                why = Some(format!(
                    "{} calls {} in its object: with it inlined it runs alike, and is named nowhere else",
                    name_of(inliner),
                    name_of(key)
                ));
                if !decision.candidates.contains(&inliner) {
                    decision.candidates.push(inliner);
                }
            }
        }
        if why.is_none() && alike {
            let unconfirmed = bound(c, key).iter().find(|(name, address)| {
                *address != c.entry
                    && !names
                        .get(address)
                        .is_some_and(|&holder| packs.names(holder, name))
            });
            if let Some((callee, _)) = unconfirmed {
                why = Some(format!(
                    "other functions fit {}'s recording, and its call to {callee} goes to a function not named so",
                    name_of(key)
                ));
            }
        }
        if why.is_none() && c.tiny && !called_so {
            why = Some(format!(
                "{} is a few operations, which a program's own function may be, and no function named calls it so",
                name_of(key)
            ));
        }
        if why.is_some() {
            decision.why = why;
            decision.named = None;
            if !decision.candidates.contains(&key) {
                decision.candidates.push(key);
            }
            decision.candidates.sort_unstable();
        }
    }
}

/// Whether a function of canonical form `c` is tiny: fewer operations
/// than a trivial one has (`binbun_sigpack::canon::TRIVIAL_OPERATIONS`), no
/// call, system call, string or data of the image, and no operation but
/// loads and what addresses them (`add`, `extend`, the `cmp` of an
/// address's check): a getter of a field its argument points to, or a
/// constant returned. Its constants (a field's offset, `-1`) say little
/// of which function it is; a computation (`tolower`) is not tiny.
fn tiny(c: &Canonical) -> bool {
    let f = &c.fingerprint;
    f.size < binbun_sigpack::canon::TRIVIAL_OPERATIONS
        && f.calls == 0
        && f.system_calls == 0
        && f.strings.is_empty()
        && c.data.is_empty()
        && f.ops
            .keys()
            .all(|op| op.starts_with("load") || ["add", "extend", "cmp"].contains(&op.as_str()))
}

/// The first address from `from` (before `to`) that is not padding:
/// `nop` in any of its forms, `int3`, zero bytes.
fn after_padding(image: &Image<'_>, from: u64, to: u64) -> u64 {
    let mut at = from;
    while at < to {
        let mut bytes = [0u8; 16];
        let read = image.read(at, &mut bytes).unwrap_or(0);
        let bytes = bytes.get(..read).unwrap_or_default();
        match bytes.first() {
            None => return to,
            Some(0x90 | 0xcc | 0x00) => {
                at += 1;
                continue;
            }
            Some(_) => {}
        }
        let prefixes = bytes
            .iter()
            .take_while(|&&b| b == 0x66 || b == 0x2e)
            .count();
        let nop = matches!(
            (bytes.get(prefixes), bytes.get(prefixes + 1)),
            (Some(0x90), _) | (Some(0x0f), Some(0x1f))
        );
        match instruction_length(image, at) {
            Some(length) if nop && length != 0 => at += length,
            Some(_) | None => return at,
        }
    }
    to
}

/// Starts of functions recovery left out of `db`: where a function's
/// entry block jumps, if no function starts there and the function has
/// no code after that jump and its padding but the jump's target (a
/// forwarder, `xor esi, esi; jmp callee`, whose callee recovery took
/// into it, so the forwarder would have the callee's identity; a
/// function whose first block jumps into its loop has the loop after the
/// jump; a callee may be the next function); with `sweep`, the first
/// instruction after padding of each stretch of code no block covers.
/// Starts the user's corrections already state are left out.
fn missed_starts(db: &Database<'_>, sweep: bool) -> BTreeSet<u64> {
    let program = db.program();
    let image = db.image();
    let mut starts = BTreeSet::new();
    for (_, function) in db.functions() {
        if let Some(block) = program
            .block_at(function.entry)
            .and_then(|b| program.blocks.get(b))
            && let Exit::Jump(Destination::Address(target)) = block.exit
            && target != function.entry
            && program.function_at(target).is_none()
        {
            let after = after_padding(image, block.end, block.end.saturating_add(64));
            let continues = function
                .blocks
                .iter()
                .filter_map(|&b| program.blocks.get(b))
                .any(|b| b.start != target && (block.end..=after).contains(&b.start));
            if !continues {
                starts.insert(target);
            }
        }
    }
    if sweep {
        let mut covered: Vec<(u64, u64)> =
            program.blocks.values().map(|b| (b.start, b.end)).collect();
        covered.sort_unstable();
        for range in &image.code {
            let mut at = range.start;
            let first = covered.partition_point(|&(_, end)| end <= range.start);
            let blocks = covered.get(first..).unwrap_or_default();
            let mut blocks = blocks.iter().take_while(|&&(start, _)| start < range.end);
            while at < range.end {
                let (gap_end, next) = match blocks.next() {
                    Some(&(start, end)) => (start.max(at), end),
                    None => (range.end, range.end),
                };
                if gap_end > at {
                    let start = after_padding(image, at, gap_end);
                    if start < gap_end {
                        starts.insert(start);
                    }
                }
                at = at.max(next);
            }
        }
    }
    starts.retain(|&start| db.corrections().bounds(start).is_none());
    starts
}

/// `db` recovered again with functions at the starts it missed
/// ([`missed_starts`]), over rounds until none is left; `None` if none
/// was missed. Recovery starts from what `db`'s did (its seeds and the
/// user's corrections).
fn recovered_again<'a>(db: &Database<'a>, sweep: bool) -> Result<Option<Database<'a>>, String> {
    let mut corrections = db.corrections().clone();
    let mut current: Option<Database<'a>> = None;
    for _ in 0..ROUNDS {
        let starts = missed_starts(current.as_ref().unwrap_or(db), sweep);
        if starts.is_empty() {
            break;
        }
        for start in starts {
            corrections.set_bounds(start, Some(Bounds::Function { end: None }));
        }
        current = Some(
            Database::with_corrections(db.image(), db.seeds(), None, corrections.clone())
                .map_err(|e| e.to_string())?,
        );
    }
    Ok(current)
}

/// The functions of `db` for which `include` holds, analysed and their
/// candidates checked.
fn check_all(
    db: &Database<'_>,
    packs: &Packs<'_>,
    platform: &Platform<'_>,
    behaviour: bool,
    include: impl Fn(u64) -> Option<bool> + Sync,
) -> Vec<Checked> {
    let ids: Vec<FunctionId> = db.functions().map(|(id, _)| id).collect();
    let (analysed, reads) = analyse(db, platform, &ids);
    check_analysed(db, &analysed, &reads, packs, platform, behaviour, include)
}

/// The functions `analysed` of `db` (with the argument registers each
/// reads, `reads`) for which `include` holds, their candidates checked.
fn check_analysed(
    db: &Database<'_>,
    analysed: &[Option<Analysed>],
    reads: &BTreeMap<u64, u32>,
    packs: &Packs<'_>,
    platform: &Platform<'_>,
    behaviour: bool,
    include: impl Fn(u64) -> Option<bool> + Sync,
) -> Vec<Checked> {
    let world = ImageWorld::new(db.image(), Vec::new(), reads);
    let program = db.program();
    let calls: HashMap<u64, Vec<u64>> = db
        .functions()
        .map(|(_, f)| {
            let mut calls: Vec<u64> = f
                .blocks
                .iter()
                .filter_map(|&b| program.blocks.get(b))
                .filter_map(|b| match b.exit {
                    Exit::Call {
                        callee: Destination::Address(to),
                        ..
                    }
                    | Exit::Jump(Destination::Address(to)) => Some(to),
                    Exit::Next
                    | Exit::Jump(_)
                    | Exit::Branch(_)
                    | Exit::Call { .. }
                    | Exit::Return
                    | Exit::Stop
                    | Exit::Invalid
                    | Exit::Limit => None,
                })
                .filter(|&to| to != f.entry && program.function_at(to).is_some())
                .collect();
            calls.sort_unstable();
            calls.dedup();
            (f.entry, calls)
        })
        .collect();
    let analysed: Vec<(&Analysed, bool)> = analysed
        .iter()
        .flatten()
        .filter_map(|a| Some((a, include(a.entry)?)))
        .collect();
    parallel(&analysed, |&(function, found)| {
        let (exact, proposed, outcomes) =
            check_candidates(function, packs, platform, &world, behaviour);
        Checked {
            entry: function.entry,
            identity: function.canonical.identity,
            trivial: function.canonical.trivial,
            small: function.canonical.operations < binbun_sigpack::canon::TRIVIAL_OPERATIONS
                && function.canonical.fingerprint.strings.is_empty()
                && function.canonical.fingerprint.system_calls == 0
                && function
                    .canonical
                    .fingerprint
                    .constants
                    .iter()
                    .all(|&c| linkable(c)),
            tiny: tiny(&function.canonical),
            exact,
            proposed,
            outcomes,
            found,
            calls: calls.get(&function.entry).cloned().unwrap_or_default(),
        }
    })
}

/// Whether constant `value` (its bits, zero-extended from its width) could
/// be one linking chose, such as a thread-local variable's offset: a
/// 32-bit value, or a 64-bit one whose bits are a 32-bit value
/// sign-extended. A wider one (the GS cookie's default
/// `0x2b992ddfa232`) is the code's own.
fn linkable(value: u64) -> bool {
    u32::try_from(value).is_ok() || i32::try_from(value.cast_signed()).is_ok()
}

/// The rustc commit that built a Rust binary: the `COMMIT` of the
/// standard library's source paths (`/rustc/COMMIT/library/...`) its
/// panic locations carry, if it has them.
fn rustc_commit(image: &Image<'_>) -> Option<String> {
    const PREFIX: &[u8] = b"/rustc/";
    const LENGTH: usize = 40;
    image.segments.iter().find_map(|segment| {
        let bytes = segment.bytes;
        bytes
            .windows(PREFIX.len())
            .enumerate()
            .filter(|(_, window)| *window == PREFIX)
            .find_map(|(at, _)| {
                let start = at + PREFIX.len();
                let commit = bytes.get(start..start + LENGTH)?;
                (commit.iter().all(u8::is_ascii_hexdigit)
                    && bytes.get(start + LENGTH) == Some(&b'/'))
                .then(|| String::from_utf8_lossy(commit).into_owned())
            })
    })
}

/// The rustc commit (abbreviated) of a build's toolchain written as
/// rustc's version line (`rustc 1.99.0 (b940084d7 2026-09-28)`).
fn toolchain_commit(build: &BuildInfo) -> Option<&str> {
    let (_, rest) = build
        .toolchain
        .as_deref()?
        .strip_prefix("rustc ")?
        .split_once(" (")?;
    let commit = rest.split(' ').next()?;
    (commit.len() >= 7 && commit.bytes().all(|b| b.is_ascii_hexdigit())).then_some(commit)
}

/// The library a pack's library is one build of, for [`elect`]: a
/// program links one C library, glibc or musl.
fn kind(library: &str) -> &str {
    match library {
        "glibc" | "musl" => "the C library",
        other => other,
    }
}

/// Which of `packs` a binary (`image`, its functions' canonical forms
/// `functions`) is matched against, and why each that names by identity
/// only does ([`Packs::foreign`]). A binary holds one build of a library:
/// of several packs of one library ([`kind`]: glibc as four
/// distributions build it and musl, Rust std of three toolchains), a
/// Rust std pack of the toolchain that built the binary is the one, else
/// those whose unique non-trivial identities the binary has most of (all
/// of them if it has none): another build's functions only compete with
/// the right one's, and some are other functions' code in this build
/// (musl's or an older glibc's `__h_errno_location`, `return
/// &tls_variable` as static linking leaves it, is the code of glibc
/// 2.43's `__ctype_toupper_loc`).
/// A Rust pack of another toolchain than the binary's, or of any if the
/// binary names none, names by identity only: a function a version
/// moved (`std::sys::pal::unix::futex::futex_wake` in 1.98, in
/// `std::sys::sync::futex::unix` since) runs alike under its old name.
fn elect<'a>(
    packs: &[Pack],
    image: &Image<'_>,
    functions: impl Iterator<Item = &'a Analysed>,
) -> (Vec<bool>, Vec<Option<String>>) {
    fn commits(pack: &Pack) -> Vec<&str> {
        pack.header
            .builds
            .iter()
            .filter_map(toolchain_commit)
            .collect()
    }
    let binary = rustc_commit(image);
    let built_by_binary = |pack: &Pack| {
        binary.as_deref().is_some_and(|binary| {
            commits(pack)
                .iter()
                .any(|commit| binary.starts_with(commit))
        })
    };
    let foreign = packs
        .iter()
        .map(|pack| {
            let commits = commits(pack);
            let first = commits.first()?;
            (!built_by_binary(pack)).then(|| {
                format!(
                    "{} {} is rustc {first}'s, the binary {}: named by identity only",
                    pack.header.library,
                    pack.header.version,
                    binary.as_deref().map_or_else(
                        || "names no rustc".to_owned(),
                        |c| format!("rustc {}'s", c.get(..9).unwrap_or(c))
                    )
                )
            })
        })
        .collect();
    let mut by_library: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (p, pack) in packs.iter().enumerate() {
        by_library
            .entry(kind(&pack.header.library))
            .or_default()
            .push(p);
    }
    let mut usable = vec![true; packs.len()];
    let contested: Vec<&Vec<usize>> = by_library.values().filter(|ps| ps.len() > 1).collect();
    if contested.is_empty() {
        return (usable, foreign);
    }
    let identities: Vec<Identity> = functions
        .filter(|f| !f.canonical.trivial)
        .map(|f| f.canonical.identity)
        .collect();
    for members in contested {
        let own: Vec<usize> = members
            .iter()
            .copied()
            .filter(|&p| packs.get(p).is_some_and(built_by_binary))
            .collect();
        let elected = if own.is_empty() {
            let votes: Vec<usize> = members
                .iter()
                .map(|&p| {
                    packs
                        .get(p)
                        .map_or(0, |pack| unique_hits(pack, &identities))
                })
                .collect();
            let most = votes.iter().copied().max().unwrap_or(0);
            members
                .iter()
                .zip(&votes)
                .filter(|&(_, &v)| v == most)
                .map(|(&p, _)| p)
                .collect()
        } else {
            own
        };
        for &p in members {
            if let Some(slot) = usable.get_mut(p) {
                *slot = elected.contains(&p);
            }
        }
    }
    (usable, foreign)
}

/// How many of `identities` are each the identity of one entry of `pack`.
fn unique_hits(pack: &Pack, identities: &[Identity]) -> usize {
    let mut entries: HashMap<Identity, BTreeSet<usize>> = HashMap::new();
    for (e, entry) in pack.functions.iter().enumerate() {
        for id in entry.builds.keys() {
            if let Some(build) = pack.build(entry, id) {
                entries.entry(build.identity).or_default().insert(e);
            }
        }
    }
    identities
        .iter()
        .filter(|identity| entries.get(identity).is_some_and(|es| es.len() == 1))
        .count()
}

/// The functions of `db` matched against `packs`.
///
/// Recovery is first redone where a function's entry is a lone jump into
/// code no function starts at (a forwarder and its callee, recovered as
/// one), and with [`MatchOptions::sweep`] in code no function covers;
/// functions found so are kept only when named. Of several packs of one
/// library, those of the binary's build are elected ([`elect`]); a
/// match's pack index is still the pack's in `packs`. Then each
/// function's candidates are checked ([`check_candidates`]) and the
/// names decided ([`decide`]) until they no longer change: a name can
/// rule out a candidate of its callers.
///
/// # Errors
///
/// The image's code is not x86-64, or recovery fails.
pub fn match_image(
    db: &Database<'_>,
    packs: &[Pack],
    options: MatchOptions,
) -> Result<Vec<Match>, String> {
    let platform = platform(db.image())?;
    let original: BTreeSet<u64> = db.functions().map(|(_, f)| f.entry).collect();
    let split = recovered_again(db, false)?;
    let base = split.as_ref().unwrap_or(db);
    let ids: Vec<FunctionId> = base.functions().map(|(id, _)| id).collect();
    let (analysed, reads) = analyse(base, &platform, &ids);
    let (usable, foreign) = elect(packs, base.image(), analysed.iter().flatten());
    let packs = Packs::new(packs, &usable, foreign);
    // A function's funclets are parts of it, named with it: those its
    // exception handling data names, and any built in.
    let mut parts = funclets::named(base.image());
    parts.extend(funclets::built_in(base.image(), base.program()));
    let mut checked = check_analysed(
        base,
        &analysed,
        &reads,
        &packs,
        &platform,
        options.behaviour,
        |entry| (!parts.contains(&entry)).then(|| !original.contains(&entry)),
    );
    drop(analysed);
    if options.sweep
        && let Some(swept) = recovered_again(base, true)?
    {
        let known: BTreeSet<u64> = base.functions().map(|(_, f)| f.entry).collect();
        checked.extend(check_all(
            &swept,
            &packs,
            &platform,
            options.behaviour,
            |entry| (!known.contains(&entry)).then_some(true),
        ));
    }
    // What each address is called as by callers whose library code fits.
    let mut called: HashMap<u64, HashSet<&str>> = HashMap::new();
    for c in &checked {
        for outcome in c.outcomes.values() {
            if let Outcome::Agrees { bound, .. } = outcome {
                for (name, address) in bound {
                    if *address != c.entry {
                        called.entry(*address).or_default().insert(name);
                    }
                }
            }
        }
    }
    // Names until they no longer change.
    let mut names: HashMap<u64, Key> = HashMap::new();
    let mut decisions: Vec<Decision> = Vec::new();
    for _ in 0..ROUNDS {
        decisions = checked
            .iter()
            .map(|c| decide(c, &names, &called, &packs, options.behaviour))
            .collect();
        unname_repeated(&mut decisions, &packs);
        unname_unsettled(&mut decisions, &checked, &packs, &names, &called);
        let next: HashMap<u64, Key> = checked
            .iter()
            .zip(&decisions)
            .filter_map(|(c, d)| Some((c.entry, d.named.as_ref()?.0)))
            .collect();
        if next == names {
            break;
        }
        names = next;
    }
    let mut matches: Vec<Match> = checked
        .into_iter()
        .zip(decisions)
        .filter(|(c, d)| !c.found || d.named.is_some())
        .map(|(c, d)| Match {
            entry: c.entry,
            identity: c.identity,
            named: d.named,
            candidates: d.candidates,
            uncheckable: d.uncheckable,
            proposed: c.proposed,
            found: c.found,
            why: d.why,
        })
        .collect();
    keep_adoptable(db, &mut matches)?;
    Ok(matches)
}

/// Drops the functions the packs found (not recovery's: a forwarder's
/// callee split off, a swept one) that recovery would not make functions
/// when only those named are adopted, as the session adopts them (a
/// correction each, [`Bounds::Function`]): the split recovery saw
/// started more functions at once, and one of them may lie where only
/// another, unnamed, made a block start. A name is never proposed for
/// what is not a function. Repeated until every one kept is a function
/// (dropping one changes the others' recovery); all are dropped if that
/// does not settle in [`ROUNDS`].
///
/// # Errors
///
/// Recovery fails.
fn keep_adoptable(db: &Database<'_>, matches: &mut Vec<Match>) -> Result<(), String> {
    for _ in 0..ROUNDS {
        let mut corrections = db.corrections().clone();
        let mut adopted = false;
        for m in matches.iter().filter(|m| m.found) {
            corrections.set_bounds(m.entry, Some(Bounds::Function { end: None }));
            adopted = true;
        }
        if !adopted {
            return Ok(());
        }
        let again = Database::with_corrections(db.image(), db.seeds(), None, corrections)
            .map_err(|e| e.to_string())?;
        let before = matches.len();
        matches.retain(|m| !m.found || again.function_at(m.entry).is_some());
        if matches.len() == before {
            return Ok(());
        }
    }
    matches.retain(|m| !m.found);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        reason = "test helpers fail loudly"
    )]

    use super::*;

    #[test]
    fn funclets_by_name() {
        // C++ funclets, mangled, and C ones, the function's name, the
        // kind and a number.
        for name in [
            "?dtor$3@?0??f@@YAXXZ@4HA",
            "?catch$6@?0??g@@YAXXZ@4HA",
            "_putw$fin$0",
            "__scrt_is_nonwritable_in_current_image$filt$0",
            "__std_acquire_shared_mutex_for_instance$catch$6",
            "__std_stacktrace_to_string$dtor$0",
        ] {
            assert!(funclet(name), "{name}");
        }
        // Templates (`?$`), and names merely holding a `$`.
        for name in [
            "??$common_gmtime_s@_J@@YAHQEAUtm@@QEB_J@Z",
            "?finish@@YAXXZ",
            "$fin$0",
            "f$fin$",
            "f$final$0",
            "f$fin$x",
            "memcpy",
        ] {
            assert!(!funclet(name), "{name}");
        }
    }

    /// Every function of `sigs-gcc.a` recorded and replayed on every
    /// other's recording: [`could_fit`] keeps each function whose replay
    /// agrees, and a replay not running the states it found skipped
    /// ([`check::replay_knowing`]) counts and differs as the replay does.
    /// It rules out some pairs and keeps some that fit.
    #[test]
    fn could_fit_keeps_every_function_that_fits() {
        let path = format!(
            "{}/../../tests/fixtures/sigs-gcc.a",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = std::fs::read(&path).unwrap();
        let objects = relocatable::archive_members(&data).unwrap().objects;
        let link = Linked::link(&objects).unwrap();
        let input = Source {
            image: link.image(),
            linked: Some(&link),
        };
        let platform = platform(&input.image).unwrap();
        let db = Database::new(&input.image, Seeds::ALL).unwrap();
        let ids: Vec<FunctionId> = named_functions(&input)
            .iter()
            .filter_map(|n| db.function_at(n.address))
            .collect();
        let (analysed, reads) = analyse(&db, &platform, &ids);
        let world = ImageWorld::new(&input.image, symbols(&input), &reads);
        let functions: Vec<Option<&Analysed>> = analysed.iter().map(Option::as_ref).collect();
        let recorded: Vec<(usize, Recording)> = functions
            .iter()
            .enumerate()
            .filter_map(|(a, f)| {
                let f = (*f)?;
                let shape = unknown_shape(&f.canonical.fingerprint, &platform);
                Some((a, check::record(subject(f), &platform, &world, &shape)?))
            })
            .collect();
        let recordings: Vec<(usize, &Recording)> = recorded.iter().map(|(a, r)| (*a, r)).collect();
        let runners: Vec<usize> = (0..functions.len()).collect();
        let fits = could_fit(&recordings, &functions, &runners, &platform, &world);
        let (mut pruned, mut fitting) = (0, 0);
        for &(a, recording) in &recordings {
            let kept: HashMap<usize, u32> = fits[&a].iter().copied().collect();
            for (b, function) in functions.iter().enumerate() {
                let Some(function) = function else {
                    continue;
                };
                let replayed =
                    check::replay(&function.l1, function.entry, &platform, &world, recording);
                let Some(&skipped) = kept.get(&b) else {
                    assert!(!replayed.agrees(), "{b} fits {a}'s recording: kept");
                    pruned += 1;
                    continue;
                };
                let knowing = check::replay_knowing(
                    &function.l1,
                    function.entry,
                    &platform,
                    &world,
                    recording,
                    |index| index < 32 && skipped & (1 << index) != 0,
                );
                assert_eq!(
                    (knowing.agreed, knowing.skipped, &knowing.differs),
                    (replayed.agreed, replayed.skipped, &replayed.differs),
                    "{b} on {a}'s recording"
                );
                fitting += usize::from(a != b && replayed.agrees());
            }
        }
        assert!(pruned > 0, "no pair ruled out");
        assert!(fitting > 0, "no other function fits a recording");
    }
}
