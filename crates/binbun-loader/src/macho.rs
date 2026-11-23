//! Mach-O specifics: the slices of a universal file ([`slices`],
//! [`select`]), the entry point (`LC_MAIN`), the exports trie, the function
//! starts (`LC_FUNCTION_STARTS`), what the dynamic loader writes (chained
//! fixups, `LC_DYLD_CHAINED_FIXUPS`, or `LC_DYLD_INFO`'s rebase and bind
//! opcodes) and makes read-only (`SG_READ_ONLY` segments), the imports
//! (binds, by library), init functions, and function ranges and exception
//! tables from the compact unwind table (`__unwind_info`). `__eh_frame` is
//! read as ELF's `.eh_frame` is.
//!
//! Names lose the leading `_` that C compilers for Apple's platforms
//! prefix to every C name ([`crate::Symbol::name`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;

use gimli::RunTimeEndian;
use object::macho::{
    self, BindDylib, CpuSubtype, CpuType, DyldInfoCommand, LinkeditDataCommand, SegmentCommand64,
};
use object::read::macho::{
    DyldChainedImport, ExportData, ExportsTrieIterator, FatArch, Fixup as Chained, MachHeader,
    MachOFatFile32, MachOFatFile64, MachOFile64,
};
use object::{Endianness, FileKind, Object, ObjectSection, SectionFlags};

use crate::{
    EntryFrame, Fixup, Image, Import, LoadError, Machine, Part, Pointer, PointerSource, Referent,
    Relocation, Symbol, SymbolKind, SymbolSource, UnwindEntry, UnwindSource, compact, elf, lsda,
};

/// One architecture's image in a universal ("fat") Mach-O file.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Slice {
    /// Its architecture, as Apple's tools name it (`x86_64`, `x86_64h`,
    /// `arm64`, `arm64e`, `i386`; `cputype N` for one without a name).
    pub arch: String,
    /// Its instruction set.
    pub machine: Machine,
    /// Where its bytes start in the file.
    pub offset: u64,
    /// How many there are.
    pub size: u64,
}

impl Slice {
    /// Its bytes in the universal file `data`, if they are in it.
    pub fn bytes<'data>(&self, data: &'data [u8]) -> Option<&'data [u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let end = start.checked_add(usize::try_from(self.size).ok()?)?;
        data.get(start..end)
    }
}

/// The slices of the universal Mach-O file `data`, in the file's order;
/// none for any other file.
///
/// # Errors
///
/// A universal file's header is damaged.
pub fn slices(data: &[u8]) -> Result<Vec<Slice>, LoadError> {
    let damaged = |error: object::Error| LoadError::Parse(error.to_string());
    match FileKind::parse(data) {
        Ok(FileKind::MachOFat32) => Ok(fat(MachOFatFile32::parse(data).map_err(damaged)?.arches())),
        Ok(FileKind::MachOFat64) => Ok(fat(MachOFatFile64::parse(data).map_err(damaged)?.arches())),
        Ok(_) | Err(_) => Ok(Vec::new()),
    }
}

/// The slices that `arches` (a universal file's) describe.
fn fat<A: FatArch>(arches: &[A]) -> Vec<Slice> {
    arches
        .iter()
        .map(|arch| {
            let (offset, size) = arch.file_range();
            let (name, machine) = arch_name(arch.cputype(), arch.cpusubtype());
            Slice {
                arch: name,
                machine,
                offset,
                size,
            }
        })
        .collect()
}

/// The name Apple's tools give the architecture of `cputype` and
/// `cpusubtype`, and its instruction set.
fn arch_name(cputype: CpuType, cpusubtype: CpuSubtype) -> (String, Machine) {
    let subtype = cpusubtype.0 & !macho::CPU_SUBTYPE_MASK;
    let (name, machine) = match cputype {
        macho::CPU_TYPE_X86_64 if subtype == macho::CPU_SUBTYPE_X86_64_H.0 => {
            ("x86_64h", Machine::X86_64)
        }
        macho::CPU_TYPE_X86_64 => ("x86_64", Machine::X86_64),
        macho::CPU_TYPE_ARM64 if subtype == macho::CPU_SUBTYPE_ARM64E.0 => {
            ("arm64e", Machine::Aarch64)
        }
        macho::CPU_TYPE_ARM64 => ("arm64", Machine::Aarch64),
        macho::CPU_TYPE_ARM64_32 => ("arm64_32", Machine::Other),
        macho::CPU_TYPE_X86 => ("i386", Machine::X86),
        macho::CPU_TYPE_ARM => ("arm", Machine::Arm),
        macho::CPU_TYPE_POWERPC => ("ppc", Machine::Other),
        macho::CPU_TYPE_POWERPC64 => ("ppc64", Machine::Other),
        other => return (format!("cputype {}", other.0), Machine::Other),
    };
    (name.to_owned(), machine)
}

/// The instruction set binbun runs on.
const fn host() -> Machine {
    if cfg!(target_arch = "x86_64") {
        Machine::X86_64
    } else if cfg!(target_arch = "aarch64") {
        Machine::Aarch64
    } else {
        Machine::Other
    }
}

/// The slice of `slices` (a universal file's) opened when none is asked
/// for: the first for the host's instruction set, else the first.
pub fn preferred(slices: &[Slice]) -> Option<&Slice> {
    slices
        .iter()
        .find(|slice| slice.machine == host())
        .or_else(|| slices.first())
}

/// The bytes of the image `data` holds and which slice they are: of a
/// universal Mach-O file, the slice of architecture `arch` ([`Slice::arch`]),
/// or without one the first for the host's instruction set, else the
/// first; any other file whole, whatever `arch` says.
///
/// # Errors
///
/// A universal file's header is damaged, it has no slices, its slice lies
/// past its end, or it has none of `arch`.
pub fn select<'data>(
    data: &'data [u8],
    arch: Option<&str>,
) -> Result<(&'data [u8], Option<Slice>), LoadError> {
    let slices = slices(data)?;
    if slices.is_empty() {
        return Ok((data, None));
    }
    let chosen = match arch {
        Some(arch) => slices
            .iter()
            .find(|slice| slice.arch == arch)
            .ok_or_else(|| LoadError::NoSlice {
                arch: arch.to_owned(),
                available: slices.iter().map(|slice| slice.arch.clone()).collect(),
            })?,
        None => preferred(&slices)
            .ok_or_else(|| LoadError::Parse("a universal file without slices".to_owned()))?,
    };
    let bytes = chosen.bytes(data).ok_or_else(|| {
        LoadError::Parse(format!(
            "the {} slice lies past the file's end",
            chosen.arch
        ))
    })?;
    Ok((bytes, Some(chosen.clone())))
}

/// Whether `file` is an object file (`MH_OBJECT`), not a loaded image.
pub fn is_object(file: &MachOFile64<'_>) -> bool {
    file.macho_header().filetype(file.endian()) == macho::MH_OBJECT
}

/// A segment's load command.
#[derive(Clone, Copy, Debug)]
struct SegmentInfo {
    address: u64,
    size: u64,
    file_offset: u64,
    file_size: u64,
    read_only_after_fixups: bool,
}

impl SegmentInfo {
    fn new(command: &SegmentCommand64<Endianness>, endian: Endianness) -> Self {
        Self {
            address: command.vmaddr.get(endian),
            size: command.vmsize.get(endian),
            file_offset: command.fileoff.get(endian),
            file_size: command.filesize.get(endian),
            read_only_after_fixups: command.flags.get(endian).contains(macho::SG_READ_ONLY),
        }
    }

    /// Its bytes in the file `data`.
    fn bytes<'data>(&self, data: &'data [u8]) -> &'data [u8] {
        let start = usize::try_from(self.file_offset).unwrap_or(usize::MAX);
        let size = usize::try_from(self.file_size).unwrap_or(usize::MAX);
        data.get(start..start.saturating_add(size))
            .unwrap_or_default()
    }

    /// The address `offset` bytes into it.
    const fn at(&self, offset: u64) -> u64 {
        self.address.saturating_add(offset)
    }
}

/// What the load commands say.
#[derive(Default)]
struct Commands<'data> {
    /// The segments, in load command order (as binds and fixups number
    /// them).
    segments: Vec<SegmentInfo>,
    /// The install names of the libraries it loads, by ordinal from 1.
    libraries: Vec<String>,
    /// `LC_MAIN`'s entry point: a file offset.
    main: Option<u64>,
    function_starts: Option<&'data LinkeditDataCommand<Endianness>>,
    dyld_info: Option<&'data DyldInfoCommand<Endianness>>,
    chained_fixups: Option<&'data LinkeditDataCommand<Endianness>>,
    exports_trie: Option<&'data LinkeditDataCommand<Endianness>>,
}

impl<'data> Commands<'data> {
    fn read(file: &MachOFile64<'data>) -> Result<Self, object::Error> {
        let endian = file.endian();
        let mut commands = Self::default();
        let mut iter = file.macho_load_commands()?;
        while let Some(command) = iter.next()? {
            if let Some((segment, _)) = command.segment_64()? {
                commands.segments.push(SegmentInfo::new(segment, endian));
            } else if let Some(dylib) = command.dylib()? {
                let name = command.string(endian, dylib.dylib.name)?;
                commands
                    .libraries
                    .push(String::from_utf8_lossy(name).into_owned());
            } else if let Some(main) = command.entry_point()? {
                commands.main = Some(main.entryoff.get(endian));
            } else if let Some(info) = command.dyld_info()? {
                commands.dyld_info = Some(info);
            } else if let Some(fixups) = command.dyld_chained_fixups()? {
                commands.chained_fixups = Some(fixups);
            } else if let Some(trie) = command.dyld_exports_trie()? {
                commands.exports_trie = Some(trie);
            } else if command.cmd() == macho::LC_FUNCTION_STARTS {
                commands.function_starts = Some(command.data()?);
            }
        }
        Ok(commands)
    }

    /// The library of bind ordinal `dylib`, if one the image loads.
    fn library(&self, dylib: BindDylib) -> Option<String> {
        let index = usize::try_from(dylib.index()?.checked_sub(1)?).ok()?;
        self.libraries.get(index).cloned()
    }

    /// The address of file offset `offset`.
    fn address(&self, offset: u64) -> Option<u64> {
        self.segments
            .iter()
            .find(|s| (s.file_offset..s.file_offset.saturating_add(s.file_size)).contains(&offset))
            .map(|s| s.at(offset - s.file_offset))
    }
}

/// `name` as C knows it: without the leading `_` of the Mach-O symbol.
fn c_name(name: &[u8]) -> String {
    let name = String::from_utf8_lossy(name);
    name.strip_prefix('_').unwrap_or(&name).to_owned()
}

/// What is damaged in the fixups.
#[derive(Debug)]
enum Damage {
    /// What the parser says.
    Parse(object::Error),
    /// A fixup names what is not there.
    Missing(&'static str),
}

impl From<object::Error> for Damage {
    fn from(error: object::Error) -> Self {
        Self::Parse(error)
    }
}

impl fmt::Display for Damage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => error.fmt(f),
            Self::Missing(what) => f.write_str(what),
        }
    }
}

/// Loads the Mach-O specifics of `file` into `image`, whose segments,
/// sections, code and symbol table's symbols are read.
pub fn load<'data>(file: &MachOFile64<'data>, image: &mut Image<'data>) {
    let commands = match Commands::read(file) {
        Ok(commands) => commands,
        Err(error) => return image.warn(Part::Imports, error),
    };
    let header = file.macho_header();
    image.position_independent = header.filetype(file.endian()) != macho::MH_EXECUTE
        || header.flags(file.endian()).contains(macho::MH_PIE);
    for symbol in &mut image.symbols {
        if let Some(name) = symbol.name.strip_prefix('_') {
            symbol.name = name.to_owned();
        }
    }
    if let Some(entry) = commands.main.and_then(|offset| commands.address(offset)) {
        image.entry = Some(entry).filter(|&entry| image.is_mapped(entry));
    }
    image.relro = commands
        .segments
        .iter()
        .filter(|s| s.read_only_after_fixups)
        .map(|s| s.address..s.address.saturating_add(s.size))
        .collect();
    exports(file, &commands, image);
    function_starts(file, &commands, image);
    let rebases = fixups(file, &commands, image);
    initializers(file, image, &rebases);
    unwind_info(file, image);
}

/// The symbols of the exports trie (`LC_DYLD_EXPORTS_TRIE`, or
/// `LC_DYLD_INFO`'s): functions and data at an address in the image; not
/// re-exports (another library's), absolute values or thread-local
/// variables (an offset in the thread's storage).
fn exports(file: &MachOFile64<'_>, commands: &Commands<'_>, image: &mut Image<'_>) {
    let (endian, data) = (file.endian(), file.data());
    let trie = match (commands.exports_trie, commands.dyld_info) {
        (Some(trie), _) => trie.exports_trie(endian, data),
        (None, Some(info)) => info.exports_trie(endian, data),
        (None, None) => return,
    };
    let mut trie: ExportsTrieIterator<'_> = match trie {
        Ok(trie) => trie,
        Err(error) => return image.warn(Part::Exports, error),
    };
    loop {
        let export = match trie.next() {
            Ok(Some(export)) => export,
            Ok(None) => break,
            Err(error) => return image.warn(Part::Exports, error),
        };
        if export.flags().kind() != macho::EXPORT_SYMBOL_FLAGS_KIND_REGULAR {
            continue;
        }
        let offset = match *export.data() {
            ExportData::Regular { address } => address,
            ExportData::StubAndResolver { stub_address, .. } => stub_address,
            ExportData::Reexport { .. } => continue,
        };
        let address = image.base.saturating_add(offset);
        image.symbols.push(Symbol {
            name: c_name(export.name()),
            address,
            size: None,
            kind: if image.is_code(address) {
                SymbolKind::Function
            } else {
                SymbolKind::Data
            },
            source: SymbolSource::Export,
            interposes: false,
        });
    }
}

/// The function starts of `LC_FUNCTION_STARTS` that are code.
fn function_starts(file: &MachOFile64<'_>, commands: &Commands<'_>, image: &mut Image<'_>) {
    let Some(command) = commands.function_starts else {
        return;
    };
    let mut starts = match command.function_starts(file.endian(), file.data(), image.base) {
        Ok(starts) => starts,
        Err(error) => return image.warn(Part::FunctionStarts, error),
    };
    loop {
        match starts.next() {
            Ok(Some(start)) if image.is_code(start) => image.function_starts.push(start),
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) => return image.warn(Part::FunctionStarts, error),
        }
    }
}

/// What the dynamic loader writes: chained fixups if the image has them,
/// else `LC_DYLD_INFO`'s binds and rebases. The rebased slots and their
/// targets.
fn fixups(
    file: &MachOFile64<'_>,
    commands: &Commands<'_>,
    image: &mut Image<'_>,
) -> BTreeMap<u64, u64> {
    let mut rebases = BTreeMap::new();
    let result = match (commands.chained_fixups, commands.dyld_info) {
        (Some(command), _) => chained_fixups(file, commands, command, image, &mut rebases),
        (None, Some(info)) => dyld_info(file, commands, info, image, &mut rebases),
        (None, None) => Ok(()),
    };
    if let Err(error) = result {
        image.warn(Part::Imports, error);
    }
    for (&at, &target) in &rebases {
        image.fixups.push(Fixup {
            start: at,
            size: 8,
            value: Some(target),
        });
        image.pointers.push(Pointer {
            at,
            target,
            relocation: Relocation::Rebase,
        });
        image.code_pointer(at, target, PointerSource::Relocation);
    }
    rebases
}

/// A bind of the slot at `slot` (`size` bytes) to `name` of library
/// ordinal `dylib`, plus `addend`: an import, unless the image binds to
/// itself or to an offset from the symbol; `at_load`: bound before the
/// program runs.
struct Bind<'a> {
    slot: u64,
    size: u8,
    name: &'a [u8],
    dylib: BindDylib,
    weak: bool,
    addend: i64,
    at_load: bool,
}

/// Records `bind`.
fn bind(image: &mut Image<'_>, commands: &Commands<'_>, bind: &Bind<'_>) {
    image.fixups.push(Fixup {
        start: bind.slot,
        size: u64::from(bind.size),
        value: None,
    });
    if bind.dylib == macho::BIND_SPECIAL_DYLIB_SELF || bind.addend != 0 {
        return;
    }
    let fixed = bind.at_load
        && !bind.weak
        && image
            .relro
            .iter()
            .any(|range: &Range<u64>| range.contains(&bind.slot));
    image.imports.push(Import {
        name: c_name(bind.name),
        library: commands.library(bind.dylib),
        slot: bind.slot,
        size: bind.size,
        fixed,
    });
}

/// The chained fixups of `command` (`LC_DYLD_CHAINED_FIXUPS`): binds
/// (every one made at load), rebases into `rebases`.
fn chained_fixups(
    file: &MachOFile64<'_>,
    commands: &Commands<'_>,
    command: &LinkeditDataCommand<Endianness>,
    image: &mut Image<'_>,
    rebases: &mut BTreeMap<u64, u64>,
) -> Result<(), Damage> {
    let (endian, data) = (file.endian(), file.data());
    let fixups = command.chained_fixups(endian, data)?;
    let imports: Vec<DyldChainedImport<'_>> = fixups.imports(endian)?.collect::<Result<_, _>>()?;
    let mut segments = fixups.segments(endian)?;
    while let Some(segment) = segments.next()? {
        let Some(info) = commands.segments.get(segment.index() as usize) else {
            return Err(Damage::Missing("chained fixups of a segment that is none"));
        };
        let mut chain = segment.fixups(endian, image.base, info.bytes(data));
        while let Some((offset, fixup)) = chain.next()? {
            let slot = info.at(offset);
            match fixup {
                Chained::Rebase(rebase) => {
                    rebases.insert(slot, image.base.saturating_add(rebase.target_offset));
                }
                Chained::Bind(fixup) => {
                    let import = imports
                        .get(fixup.ordinal as usize)
                        .ok_or(Damage::Missing("a chained bind of an import that is none"))?;
                    let bound = Bind {
                        slot,
                        size: 8,
                        name: import.name,
                        dylib: import.dylib,
                        weak: import.weak_import,
                        addend: import.addend.saturating_add(i64::from(fixup.addend)),
                        at_load: true,
                    };
                    bind(image, commands, &bound);
                }
                // Kernel collections' and firmware's: written, value unknown.
                Chained::KernelCacheRebase(_) | Chained::SegmentedRebase(_) => {
                    image.fixups.push(Fixup {
                        start: slot,
                        size: 8,
                        value: None,
                    });
                }
            }
        }
    }
    Ok(())
}

/// The binds and rebases of `LC_DYLD_INFO`: non-lazy binds (made at load)
/// and lazy binds (`__la_symbol_ptr`, made at the first call); weak binds
/// only override slots the other streams bind or rebase. Rebases into
/// `rebases`, but of a slot a lazy bind fills (which holds the address of
/// its stub helper until then).
fn dyld_info(
    file: &MachOFile64<'_>,
    commands: &Commands<'_>,
    info: &DyldInfoCommand<Endianness>,
    image: &mut Image<'_>,
    rebases: &mut BTreeMap<u64, u64>,
) -> Result<(), Damage> {
    let (endian, data) = (file.endian(), file.data());
    let mut bound = BTreeSet::new();
    for (mut binds, at_load) in [
        (info.binds(endian, data, 8)?, true),
        (info.lazy_binds(endian, data, 8)?, false),
    ] {
        while let Some(found) = binds.next()? {
            let segment = commands
                .segments
                .get(usize::from(found.segment_index))
                .ok_or(Damage::Missing("a bind in a segment that is none"))?;
            let slot = segment.at(found.segment_offset);
            bound.insert(slot);
            let size = if found.kind == macho::BIND_TYPE_POINTER {
                8
            } else {
                4
            };
            let found = Bind {
                slot,
                size,
                name: found.symbol,
                dylib: found.dylib,
                weak: found.flags.contains(macho::BIND_SYMBOL_FLAGS_WEAK_IMPORT),
                addend: found.addend,
                at_load,
            };
            bind(image, commands, &found);
        }
    }
    let mut found = info.rebases(endian, data, 8)?;
    while let Some(rebase) = found.next()? {
        let segment = commands
            .segments
            .get(usize::from(rebase.segment_index))
            .ok_or(Damage::Missing("a rebase in a segment that is none"))?;
        let slot = segment.at(rebase.segment_offset);
        if bound.contains(&slot) {
            continue;
        }
        if rebase.kind == macho::REBASE_TYPE_POINTER {
            if let Some(target) = image.read_word(slot, 8, true) {
                rebases.insert(slot, target);
            }
        } else {
            image.fixups.push(Fixup {
                start: slot,
                size: 4,
                value: image.read_word(slot, 4, true),
            });
        }
    }
    Ok(())
}

/// The functions the dynamic loader calls before `main`: those of
/// `__init_offsets` (offsets from the image's start) and `__mod_init_func`
/// (pointers, rebased: `rebases`).
fn initializers(file: &MachOFile64<'_>, image: &mut Image<'_>, rebases: &BTreeMap<u64, u64>) {
    for section in file.sections() {
        let SectionFlags::MachO { flags, .. } = section.flags() else {
            continue;
        };
        let (start, size) = (section.address(), section.size());
        if flags.typ() == macho::S_INIT_FUNC_OFFSETS {
            for at in (start..start.saturating_add(size)).step_by(4) {
                if let Some(offset) = image.read_word(at, 4, true) {
                    let target = image.base.saturating_add(offset);
                    image.code_pointer(at, target, PointerSource::InitArray);
                }
            }
        } else if flags.typ() == macho::S_MOD_INIT_FUNC_POINTERS {
            for (&at, &target) in rebases.range(start..start.saturating_add(size)) {
                image.code_pointer(at, target, PointerSource::InitArray);
            }
        }
    }
}

/// Whether compact unwind `encoding` of `machine` says the function's
/// `__eh_frame` entry tells how to unwind it (`UNWIND_X86_64_MODE_DWARF`,
/// `UNWIND_ARM64_MODE_DWARF`).
const fn is_dwarf(machine: Machine, encoding: u32) -> bool {
    let mode = encoding & 0x0f00_0000;
    match machine {
        Machine::X86_64 => mode == 0x0400_0000,
        Machine::Aarch64 => mode == 0x0300_0000,
        Machine::X86 | Machine::Arm | Machine::Other => false,
    }
}

/// The function ranges of `__unwind_info` and the exception tables its
/// functions have. An entry (but one whose `__eh_frame` entry is read
/// instead, or one without unwind information) is split at the function
/// starts in it; without function starts the entries are not taken, as
/// their ranges may hold several functions.
fn unwind_info(file: &MachOFile64<'_>, image: &mut Image<'_>) {
    let Some(section) = file.section_by_name("__unwind_info") else {
        return;
    };
    let table = match section
        .data()
        .map_err(|error| error.to_string())
        .and_then(|bytes| compact::parse(bytes, image.base))
    {
        Ok(table) => table,
        Err(error) => return image.warn(Part::UnwindInfo, error),
    };
    let mut entries = Vec::new();
    for (i, entry) in table.entries.iter().enumerate() {
        let end = table
            .entries
            .get(i + 1)
            .map_or(table.end, |next| next.start);
        if entry.encoding == 0 || is_dwarf(image.machine, entry.encoding) {
            continue;
        }
        let starts = &image.function_starts;
        let first = starts.partition_point(|&s| s < entry.start);
        let last = starts.partition_point(|&s| s < end);
        let within = starts.get(first..last).unwrap_or_default();
        let mut cuts: Vec<u64> = within.to_vec();
        if within.first() != Some(&entry.start) && !within.is_empty() {
            cuts.insert(0, entry.start);
        }
        for (j, &start) in cuts.iter().enumerate() {
            let fragment =
                start == entry.start && entry.encoding & compact::NOT_FUNCTION_START != 0;
            entries.push(UnwindEntry {
                start,
                end: cuts.get(j + 1).copied().unwrap_or(end),
                source: UnwindSource::UnwindInfo,
                fragment,
                split_from: None,
                frame: if fragment {
                    EntryFrame::Inside
                } else {
                    EntryFrame::Call
                },
            });
        }
    }
    image.unwind.extend(entries);
    let section = |name| file.section_by_name(name).map(|s| s.address());
    let layout = lsda::Layout {
        endian: RunTimeEndian::Little,
        address_size: 8,
        text: section("__text"),
        data: section("__got"),
    };
    for &(function, lsda) in &table.lsdas {
        let covering = table.entries.partition_point(|e| e.start <= function);
        let personality = covering
            .checked_sub(1)
            .and_then(|i| table.entries.get(i))
            .and_then(|entry| entry.personality())
            .and_then(|index| table.personalities.get(index as usize - 1))
            .map(|&slot| Referent {
                slot: Some(slot),
                ..Referent::default()
            });
        elf::exception_table(image, layout, lsda, function, personality);
    }
}
