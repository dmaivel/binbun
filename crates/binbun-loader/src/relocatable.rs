//! Relocatable objects (ELF `.o` files, and the members of `.a` archives
//! and Rust `.rlib`s; COFF `.obj` files and the members of Microsoft's
//! `.lib` archives) laid out as one image ([`Linked`]): what a signature
//! pack is made from (`binbun sig make`).
//!
//! An object file maps nothing: its sections are placed here at
//! synthetic addresses, one segment per kind (code, read-only data,
//! writable data and zeroed data, thread-local data), from
//! [`Linked::BASE`], below 2 GiB so that 32-bit absolute relocations of
//! code built without `-fPIC` fit. Each object's relocations are applied
//! as a static link would, against the symbols the objects define (the
//! first strong definition of a global name wins, as the archive
//! member a linker picks first); what no object defines gets an address
//! of its own in a writable segment of external symbols, 16 bytes each,
//! and a GOT entry a slot in a read-only segment holding its symbol's
//! address. So every call and data reference in the code is a constant
//! address in the image, as in a statically linked program.
//!
//! The relocations are also kept as stated ([`Relocation`]: offset, ELF
//! or COFF type, symbol, addend), so a function's bytes can be given with
//! every relocated field zeroed.
//!
//! Each ELF object's `.eh_frame` is placed too (in a read-only segment
//! of its own, after the others) and read once relocated: its exception
//! tables and landing pads are the image's, as a linked program's are,
//! so a function's cleanup code is part of it on both sides.
//!
//! COFF objects are linked as Microsoft's linker links them into a PE
//! image ([`Linked::format`] is [`Format::Pe`], so the code is read with
//! the Windows x64 convention): sections with a `$` in their name are
//! grouped and ordered by name (`.CRT$XCA` before `.CRT$XCZ`, `.tls`
//! before `.tls$ZZZ`); of COMDAT sections of one symbol only the first
//! object's is kept, with its associated sections (`.pdata`, `.xdata`),
//! and each copy of code compiled otherwise, under its name but
//! referenced by none;
//! the code starts a page after [`Linked::BASE`], which is
//! `__ImageBase` (`ADDR32NB` relocations count from it); a weak external
//! or a `/alternatename` directive no object defines resolves to its
//! default, and a function's weak name is an alias of it there (MSVC's
//! alias objects, `_strcmpi` for `_stricmp`); `__imp_NAME` no object
//! defines is the import `NAME`: a slot of a read-only import address
//! table the loader fills, as in a PE image ([`Image::imports`],
//! [`Image::fixups`]). Symbols carry no
//! size in COFF: a function's ends at the next function of its section
//! or at the section's end. `.pdata` gives the unwind entries and
//! exception handlers ([`Image::unwind`], [`Image::frame_handlers`]).
//! Import libraries' members (short import objects) and link-time code
//! generation objects (`/GL`) are not objects to lay out: archives skip
//! them ([`archive_members`], [`ArchiveKinds`]).
//!
//! x86-64 only (`R_X86_64_*`, `IMAGE_REL_AMD64_*`); a relocation of
//! another type is skipped with a warning ([`Part::Relocations`]).

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use binbun_semantics::core::memory::{Memory as _, Permissions};
use object::read::coff::{CoffFile, CoffHeader, Symbol as _};
use object::{
    LittleEndian as LE, Object, ObjectComdat as _, ObjectSection, ObjectSymbol, RelocationFlags,
    RelocationTarget, SectionFlags, SectionKind, SymbolIndex, SymbolKind as ObjectSymbolKind,
    SymbolSection, elf, pe,
};

use crate::pe::x64_pdata;
use crate::{
    ExceptionTable, Fixup, Format, Image, Import, LandingPad, LoadError, Machine, Part, Section,
    Segment, Symbol, SymbolKind, SymbolSource, Warning, elf as elf_image, lsda,
};

/// A relocation's type, as its object's format numbers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationType {
    /// An ELF type (`R_X86_64_PLT32`).
    Elf(u32),
    /// A COFF type (`IMAGE_REL_AMD64_REL32`).
    Coff(u16),
}

/// One relocation of an object as stated: where it applies, its type, the
/// symbol it refers to (a section's name for a section-relative one) and
/// its addend (a COFF relocation's is the field's value in the object).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// The address of the field it writes, in the [`Linked`] image.
    pub at: u64,
    /// The field's size in bytes.
    pub size: u8,
    /// The relocation type.
    pub kind: RelocationType,
    /// The symbol.
    pub symbol: String,
    /// The addend.
    pub addend: i64,
}

impl Relocation {
    /// The name of its type, lower case and without the `R_X86_64_` or
    /// `IMAGE_REL_AMD64_` prefix (`plt32`, `rel32`), or its number.
    pub fn kind_name(&self) -> String {
        let r_type = match self.kind {
            RelocationType::Elf(r_type) => r_type,
            RelocationType::Coff(typ) => return coff_kind_name(typ),
        };
        match elf::RelocationType(r_type) {
            elf::R_X86_64_64 => "64".into(),
            elf::R_X86_64_PC32 => "pc32".into(),
            elf::R_X86_64_PLT32 => "plt32".into(),
            elf::R_X86_64_GOTPCREL => "gotpcrel".into(),
            elf::R_X86_64_GOTPCRELX => "gotpcrelx".into(),
            elf::R_X86_64_REX_GOTPCRELX => "rex_gotpcrelx".into(),
            elf::R_X86_64_32 => "32".into(),
            elf::R_X86_64_32S => "32s".into(),
            elf::R_X86_64_PC64 => "pc64".into(),
            elf::R_X86_64_TPOFF32 => "tpoff32".into(),
            elf::R_X86_64_GOTTPOFF => "gottpoff".into(),
            other => other.0.to_string(),
        }
    }
}

/// The name of COFF x86-64 relocation type `typ`, as
/// [`Relocation::kind_name`] gives it.
fn coff_kind_name(typ: u16) -> String {
    let rel32 = pe::IMAGE_REL_AMD64_REL32.0;
    match pe::RelocationType(typ) {
        pe::IMAGE_REL_AMD64_ABSOLUTE => "absolute".into(),
        pe::IMAGE_REL_AMD64_ADDR64 => "addr64".into(),
        pe::IMAGE_REL_AMD64_ADDR32 => "addr32".into(),
        pe::IMAGE_REL_AMD64_ADDR32NB => "addr32nb".into(),
        pe::IMAGE_REL_AMD64_REL32 => "rel32".into(),
        _ if (rel32 + 1..=rel32 + 5).contains(&typ) => format!("rel32_{}", typ - rel32),
        pe::IMAGE_REL_AMD64_SECTION => "section".into(),
        pe::IMAGE_REL_AMD64_SECREL => "secrel".into(),
        pe::IMAGE_REL_AMD64_SECREL7 => "secrel7".into(),
        _ => typ.to_string(),
    }
}

/// An object file of a [`Linked`] image: its name and the range of
/// addresses its sections were given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Its name (the archive member's, or the path given).
    pub name: String,
    /// Its sections' ranges (one per segment kind it has bytes in).
    pub ranges: Vec<core::ops::Range<u64>>,
}

/// Relocatable objects laid out and relocated as one image ([the
/// module](self)); [`Linked::image`] is that image.
#[derive(Clone, Debug)]
pub struct Linked {
    /// The instruction set.
    pub machine: Machine,
    /// The format of the programs the objects link into: [`Format::Elf`]
    /// for ELF objects, [`Format::Pe`] for COFF objects.
    pub format: Format,
    segments: Vec<Owned>,
    /// The sections placed, named `member(section)`.
    pub sections: Vec<Section>,
    /// The code: the executable sections' ranges, sorted.
    pub code: Vec<core::ops::Range<u64>>,
    /// The symbols defined (functions and data objects; not sections or
    /// files), at their addresses.
    pub symbols: Vec<Symbol>,
    /// Which object each symbol of [`Linked::symbols`] comes from (an
    /// index into [`Linked::members`]).
    pub symbol_members: Vec<usize>,
    /// The symbols no object defines, at the addresses given them.
    pub externals: BTreeMap<String, u64>,
    /// The imports (COFF's `__imp_NAME` no object defines), by name
    /// (`NAME`), at their slots in the import address table.
    pub imports: BTreeMap<String, u64>,
    /// The objects, in the order given.
    pub members: Vec<Member>,
    /// Every relocation applied (or skipped), sorted by address.
    pub relocations: Vec<Relocation>,
    /// The landing pads of the objects' exception tables.
    landing_pads: Vec<LandingPad>,
    /// The objects' exception tables (from their `.eh_frame`).
    exception_tables: Vec<ExceptionTable>,
    /// What was skipped.
    pub warnings: Vec<Warning>,
}

/// A segment and its bytes.
#[derive(Clone, Debug)]
struct Owned {
    start: u64,
    size: u64,
    permissions: Permissions,
    bytes: Vec<u8>,
}

/// The kinds of segment sections go to, in address order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Place {
    Code,
    ReadOnly,
    Data,
    Zero,
    Thread,
    /// `.eh_frame`, read only for the exception tables.
    Unwind,
}

const PLACES: [Place; 6] = [
    Place::Code,
    Place::ReadOnly,
    Place::Data,
    Place::Zero,
    Place::Thread,
    Place::Unwind,
];

/// Where each kind of segment starts, by [`Place`].
type Starts = [u64; PLACES.len()];

impl Place {
    const fn permissions(self) -> Permissions {
        Permissions {
            read: true,
            write: matches!(self, Self::Data | Self::Zero | Self::Thread),
            execute: matches!(self, Self::Code),
        }
    }
}

/// A section placed: its object, index there, kind of segment and offset
/// in it.
struct Placed {
    member: usize,
    index: object::SectionIndex,
    place: Place,
    offset: u64,
    size: u64,
    name: String,
}

/// Where a symbol of an object resolves.
#[derive(Clone, Copy)]
enum Resolved {
    Address(u64),
    /// A thread-local symbol: its offset in the thread-local block.
    Thread(u64),
}

/// A relocation's write, its symbol resolved.
struct Write {
    at: u64,
    kind: RelocationType,
    target: Target,
    addend: i64,
}
/// What a relocation refers to.
enum Target {
    Resolved(Resolved),
    External(String),
}

/// The start of the segment of `place`.
fn start(starts: &Starts, place: Place) -> u64 {
    starts.get(place as usize).copied().unwrap_or_default()
}

/// The bytes one GOT slot or external symbol takes.
const SLOT: u64 = 16;

impl Linked {
    /// The first address of the image: no power of two nor one less, so
    /// that the edge values checking states put in registers (`1 << k`,
    /// `(1 << k) - 1`) do not land in the image and get recorded as its
    /// symbols.
    pub const BASE: u64 = 0x1234_0000;

    /// The relocatable objects `objects` (each a name and its bytes), all
    /// ELF or all COFF, laid out and relocated as one image.
    ///
    /// # Errors
    ///
    /// An object is not an x86-64 ELF or COFF relocatable object (or an
    /// MSVC alias object), is damaged, or the objects mix the formats.
    #[expect(clippy::too_many_lines, reason = "one pass over the objects' symbols")]
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "object's symbol kinds and sections are non-exhaustive"
    )]
    pub fn link(objects: &[(String, &[u8])]) -> Result<Self, LoadError> {
        let files = objects
            .iter()
            .map(|(name, data)| parse_object(name, data))
            .collect::<Result<Vec<_>, _>>()?;
        let coff = files
            .iter()
            .any(|f| f.format() == object::BinaryFormat::Coff);
        if coff
            && files
                .iter()
                .any(|f| f.format() != object::BinaryFormat::Coff)
        {
            return Err(LoadError::Parse(
                "ELF and COFF objects are not linked together".into(),
            ));
        }
        let mut linked = Self {
            machine: Machine::X86_64,
            format: if coff { Format::Pe } else { Format::Elf },
            segments: Vec::new(),
            sections: Vec::new(),
            code: Vec::new(),
            symbols: Vec::new(),
            symbol_members: Vec::new(),
            externals: BTreeMap::new(),
            imports: BTreeMap::new(),
            members: objects
                .iter()
                .map(|(name, _)| Member {
                    name: name.clone(),
                    ranges: Vec::new(),
                })
                .collect(),
            relocations: Vec::new(),
            landing_pads: Vec::new(),
            exception_tables: Vec::new(),
            warnings: Vec::new(),
        };
        let placed = layout(&files, coff);
        let starts = linked.place_segments(&files, &placed);
        let address = |p: &Placed| start(&starts, p.place) + p.offset;
        let sections: BTreeMap<(usize, usize), &Placed> =
            placed.iter().map(|p| ((p.member, p.index.0), p)).collect();
        for p in &placed {
            linked.sections.push(Section {
                name: p.name.clone(),
                start: address(p),
                size: p.size,
            });
            let range = address(p)..address(p) + p.size;
            if p.place == Place::Code && p.size != 0 {
                linked.code.push(range.clone());
            }
            let Some(member) = linked.members.get_mut(p.member) else {
                continue;
            };
            let ranges = &mut member.ranges;
            match ranges.last_mut() {
                Some(last) if last.end == range.start || range.is_empty() => {
                    last.end = last.end.max(range.end);
                }
                Some(_) | None => ranges.push(range),
            }
        }
        linked.code.sort_unstable_by_key(|r| r.start);
        // Symbols: each object's defined ones, and the global names.
        let mut globals: BTreeMap<String, (Resolved, bool)> = BTreeMap::new();
        let mut commons = Vec::new();
        for (member, file) in files.iter().enumerate() {
            for symbol in file.symbols() {
                let Ok(name) = symbol.name() else { continue };
                let (resolved, in_code) = match symbol.section() {
                    SymbolSection::Section(index) => {
                        let Some(p) = sections.get(&(member, index.0)) else {
                            continue;
                        };
                        let resolved = if p.place == Place::Thread {
                            Resolved::Thread(p.offset + symbol.address())
                        } else {
                            Resolved::Address(address(p) + symbol.address())
                        };
                        (resolved, p.place == Place::Code)
                    }
                    SymbolSection::Common => {
                        let size = symbol.size().max(1);
                        // COFF states no alignment: as a linker aligns.
                        let align = if coff {
                            size.next_power_of_two().min(16)
                        } else {
                            symbol.address()
                        };
                        commons.push((name.to_owned(), size, align));
                        continue;
                    }
                    SymbolSection::Unknown
                    | SymbolSection::None
                    | SymbolSection::Undefined
                    | SymbolSection::Absolute
                    | _ => continue,
                };
                let kind = match symbol.kind() {
                    ObjectSymbolKind::Text => SymbolKind::Function,
                    // A COFF object's assembly routines are global labels
                    // in code (MASM's `PROC`s without a function type).
                    ObjectSymbolKind::Data if coff && in_code && symbol.is_global() => {
                        SymbolKind::Function
                    }
                    ObjectSymbolKind::Data | ObjectSymbolKind::Tls => SymbolKind::Data,
                    ObjectSymbolKind::Section | ObjectSymbolKind::File => continue,
                    ObjectSymbolKind::Label if coff => continue,
                    _ => SymbolKind::Other,
                };
                // COFF's compiler-made names (`$LN5`, `$pdata$f`,
                // `@comp.id`) name no function or object.
                if name.is_empty() || (coff && name.starts_with(['$', '.', '@'])) {
                    continue;
                }
                if let Resolved::Address(address) = resolved {
                    linked.symbols.push(Symbol {
                        name: name.to_owned(),
                        address,
                        size: Some(symbol.size()).filter(|&size| size != 0),
                        kind,
                        source: SymbolSource::Static,
                        interposes: false,
                    });
                    linked.symbol_members.push(member);
                }
                if symbol.is_global() {
                    let strong = !symbol.is_weak();
                    match globals.entry(name.to_owned()) {
                        Entry::Vacant(entry) => {
                            entry.insert((resolved, strong));
                        }
                        Entry::Occupied(mut entry) => {
                            if strong && !entry.get().1 {
                                entry.insert((resolved, strong));
                            }
                        }
                    }
                }
            }
        }
        if coff {
            linked.size_functions(&placed, &starts);
            linked.resolve_weak(&files, &mut globals, |member, index, offset| {
                let p = sections.get(&(member, index))?;
                Some(if p.place == Place::Thread {
                    Resolved::Thread(p.offset + offset)
                } else {
                    Resolved::Address(address(p) + offset)
                })
            });
            // The linker's symbol for the image's base, which `ADDR32NB`
            // relocations count from.
            if let Entry::Vacant(entry) = globals.entry("__ImageBase".into()) {
                entry.insert((Resolved::Address(Self::BASE), true));
                linked.symbols.push(Symbol {
                    name: "__ImageBase".into(),
                    address: Self::BASE,
                    size: None,
                    kind: SymbolKind::Data,
                    source: SymbolSource::Static,
                    interposes: false,
                });
                linked.symbol_members.push(usize::MAX);
            }
        }
        linked.place_commons(&commons, &mut globals);
        linked.relocate(&files, &sections, &starts, &globals);
        linked.relocations.sort_by_key(|r| r.at);
        linked.read_exception_tables(&placed, &starts);
        Ok(linked)
    }

    /// Reads the exception tables of the objects' `.eh_frame` sections
    /// (`placed` at `starts`, relocated) into [`Linked::image`]'s.
    fn read_exception_tables(&mut self, placed: &[Placed], starts: &Starts) {
        let layout = lsda::Layout {
            endian: gimli::RunTimeEndian::Little,
            address_size: 8,
            text: None,
            data: None,
        };
        let segment = self.segments.iter().find(|s| {
            s.start == start(starts, Place::Unwind) && s.permissions == Place::Unwind.permissions()
        });
        let sections: Vec<(u64, &[u8])> = placed
            .iter()
            .filter(|p| p.place == Place::Unwind)
            .filter_map(|p| {
                let at = usize::try_from(p.offset).ok()?;
                let size = usize::try_from(p.size).ok()?;
                let bytes = segment?.bytes.get(at..at.checked_add(size)?)?;
                Some((start(starts, p.place) + p.offset, bytes))
            })
            .collect();
        if sections.is_empty() {
            // No `.eh_frame` (a COFF object's are in its `.pdata`, read by
            // [`Linked::image`]).
            return;
        }
        let mut image = self.image();
        for (address, data) in sections {
            elf_image::eh_frame_at(&mut image, data, address, layout);
        }
        let landing_pads = core::mem::take(&mut image.landing_pads);
        let exception_tables = core::mem::take(&mut image.exception_tables);
        let warnings = core::mem::take(&mut image.warnings);
        self.landing_pads = landing_pads;
        self.exception_tables = exception_tables;
        self.warnings = warnings;
    }

    /// Makes the segments of the sections `placed` (of `files`), filled
    /// with their bytes; the start of each kind's segment, by [`Place`].
    fn place_segments(&mut self, files: &[object::File<'_>], placed: &[Placed]) -> Starts {
        let mut starts = [0; PLACES.len()];
        // A PE image's sections start after its headers' page, at
        // `__ImageBase`.
        let mut next = if self.format == Format::Pe {
            Self::BASE + 0x1000
        } else {
            Self::BASE
        };
        for place in PLACES {
            let size = placed
                .iter()
                .filter(|p| p.place == place)
                .map(|p| p.offset + p.size)
                .max()
                .unwrap_or(0);
            if let Some(slot) = starts.get_mut(place as usize) {
                *slot = next;
            }
            let mut bytes = Vec::new();
            if place != Place::Zero {
                bytes.resize(usize::try_from(size).unwrap_or(0), 0);
                for p in placed.iter().filter(|p| p.place == place) {
                    let Some(file) = files.get(p.member) else {
                        continue;
                    };
                    let Ok(section) = file.section_by_index(p.index) else {
                        continue;
                    };
                    let data = section.data().unwrap_or_default();
                    let at = usize::try_from(p.offset).unwrap_or(usize::MAX);
                    if let Some(dest) = bytes.get_mut(at..at.saturating_add(data.len())) {
                        dest.copy_from_slice(data);
                    }
                }
            }
            if size != 0 {
                self.segments.push(Owned {
                    start: next,
                    size,
                    permissions: place.permissions(),
                    bytes,
                });
            }
            next = (next + size + 0xffff) & !0xfff;
        }
        starts
    }

    /// Places common symbols `commons` (name, size, alignment) in a zeroed
    /// segment of their own and enters those no object defines in
    /// `globals`.
    fn place_commons(
        &mut self,
        commons: &[(String, u64, u64)],
        globals: &mut BTreeMap<String, (Resolved, bool)>,
    ) {
        let start = self.next_free();
        let mut offset = 0u64;
        for (name, size, align) in commons {
            if globals.contains_key(name) {
                continue;
            }
            let align = (*align).clamp(1, 4096);
            offset = offset.next_multiple_of(align);
            let address = start + offset;
            globals.insert(name.clone(), (Resolved::Address(address), true));
            self.symbols.push(Symbol {
                name: name.clone(),
                address,
                size: Some(*size),
                kind: SymbolKind::Data,
                source: SymbolSource::Static,
                interposes: false,
            });
            self.symbol_members.push(usize::MAX);
            offset += size;
        }
        if offset != 0 {
            self.segments.push(Owned {
                start,
                size: offset,
                permissions: Place::Zero.permissions(),
                bytes: Vec::new(),
            });
        }
    }

    /// The first page-aligned address past every segment, with a gap.
    fn next_free(&self) -> u64 {
        self.segments
            .iter()
            .map(|s| s.start + s.size)
            .max()
            .map_or(Self::BASE, |end| (end + 0xffff) & !0xfff)
    }

    /// Gives each function symbol without a size (COFF states none) the
    /// bytes up to the next function of its section, or to the section's
    /// end, of the sections `placed` (segments from `starts`).
    fn size_functions(&mut self, placed: &[Placed], starts: &Starts) {
        let mut ranges: Vec<core::ops::Range<u64>> = placed
            .iter()
            .filter(|p| p.place == Place::Code)
            .map(|p| {
                let at = start(starts, p.place) + p.offset;
                at..at + p.size
            })
            .collect();
        ranges.sort_unstable_by_key(|r| r.start);
        let mut entries: Vec<u64> = self
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .map(|s| s.address)
            .collect();
        entries.sort_unstable();
        entries.dedup();
        for symbol in &mut self.symbols {
            if symbol.kind != SymbolKind::Function || symbol.size.is_some() {
                continue;
            }
            let at = symbol.address;
            let Some(range) = ranges
                .partition_point(|r| r.start <= at)
                .checked_sub(1)
                .and_then(|i| ranges.get(i))
                .filter(|r| r.contains(&at))
            else {
                continue;
            };
            let next = entries
                .get(entries.partition_point(|&e| e <= at))
                .copied()
                .unwrap_or(u64::MAX);
            symbol.size = Some(next.min(range.end) - at).filter(|&size| size != 0);
        }
    }

    /// Enters in `globals` the weak externals and `/alternatename`
    /// directives of the COFF `files` whose names no object defines,
    /// resolved as their defaults (a symbol of the object, by member,
    /// section index and offset, resolved by `defined`; else a global
    /// name); a function's weak name is a symbol of it, an alias.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "object's symbol sections are non-exhaustive"
    )]
    fn resolve_weak(
        &mut self,
        files: &[object::File<'_>],
        globals: &mut BTreeMap<String, (Resolved, bool)>,
        defined: impl Fn(usize, usize, u64) -> Option<Resolved>,
    ) {
        /// Where a weak name's default is.
        enum Default {
            Defined(Resolved),
            Named(String),
        }
        let mut weak: Vec<(String, Default)> = Vec::new();
        for (member, file) in files.iter().enumerate() {
            for (name, index) in weak_externals(file) {
                let Ok(symbol) = file.symbol_by_index(index) else {
                    continue;
                };
                let default = match symbol.section() {
                    SymbolSection::Section(section) => {
                        match defined(member, section.0, symbol.address()) {
                            Some(resolved) => Default::Defined(resolved),
                            None => continue,
                        }
                    }
                    _ => Default::Named(symbol.name().unwrap_or_default().to_owned()),
                };
                weak.push((name, default));
            }
            for (name, default) in alternate_names(file) {
                weak.push((name, Default::Named(default)));
            }
        }
        // Defaults may be weak names themselves: until nothing changes.
        for _ in 0..4 {
            let mut changed = false;
            for (name, default) in &weak {
                if globals.contains_key(name) {
                    continue;
                }
                let resolved = match default {
                    Default::Defined(resolved) => *resolved,
                    Default::Named(default) => match globals.get(default) {
                        Some(&(resolved, _)) => resolved,
                        None => continue,
                    },
                };
                globals.insert(name.clone(), (resolved, false));
                changed = true;
                let Resolved::Address(address) = resolved else {
                    continue;
                };
                let function = self
                    .symbols
                    .iter()
                    .zip(&self.symbol_members)
                    .find(|(s, _)| s.address == address && s.kind == SymbolKind::Function)
                    .map(|(s, &m)| (s.size, m));
                if let Some((size, owner)) = function {
                    self.symbols.push(Symbol {
                        name: name.clone(),
                        address,
                        size,
                        kind: SymbolKind::Function,
                        source: SymbolSource::Static,
                        interposes: false,
                    });
                    self.symbol_members.push(owner);
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Applies every relocation of `files` (whose sections are placed at
    /// `sections`, segments from `starts`), resolving global names by
    /// `globals`; external symbols and GOT slots get segments of their
    /// own.
    #[expect(
        clippy::too_many_lines,
        reason = "every x86-64 relocation type, in one place"
    )]
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "object's relocation targets and symbol sections are non-exhaustive"
    )]
    fn relocate(
        &mut self,
        files: &[object::File<'_>],
        sections: &BTreeMap<(usize, usize), &Placed>,
        starts: &Starts,
        globals: &BTreeMap<String, (Resolved, bool)>,
    ) {
        let thread_size = sections
            .values()
            .filter(|p| p.place == Place::Thread)
            .map(|p| p.offset + p.size)
            .max()
            .unwrap_or(0)
            .next_multiple_of(16);
        // First pass: every write, with symbols resolved; external names
        // and GOT slots collected.
        let mut writes = Vec::new();
        for (member, file) in files.iter().enumerate() {
            for section in file.sections() {
                let Some(p) = sections.get(&(member, section.index().0)) else {
                    continue;
                };
                let base = start(starts, p.place) + p.offset;
                let data = section.data().unwrap_or_default();
                for (offset, relocation) in section.relocations() {
                    let (kind, addend) = match relocation.flags() {
                        RelocationFlags::Elf { r_type } => {
                            (RelocationType::Elf(r_type.0), relocation.addend())
                        }
                        RelocationFlags::Coff { typ } => (
                            RelocationType::Coff(typ.0),
                            implicit_addend(data, offset, relocation.size()),
                        ),
                        _ => continue,
                    };
                    let (target, name) = match relocation.target() {
                        RelocationTarget::Symbol(index) => {
                            let Ok(symbol) = file.symbol_by_index(index) else {
                                continue;
                            };
                            let name = symbol.name().unwrap_or_default().to_owned();
                            let target = match symbol.section() {
                                SymbolSection::Section(index)
                                    if symbol.is_local() || !globals.contains_key(&name) =>
                                {
                                    match sections.get(&(member, index.0)) {
                                        Some(q) if q.place == Place::Thread => Target::Resolved(
                                            Resolved::Thread(q.offset + symbol.address()),
                                        ),
                                        Some(q) => Target::Resolved(Resolved::Address(
                                            start(starts, q.place) + q.offset + symbol.address(),
                                        )),
                                        None => Target::External(name.clone()),
                                    }
                                }
                                SymbolSection::Absolute => {
                                    Target::Resolved(Resolved::Address(symbol.address()))
                                }
                                _ => match globals.get(&name) {
                                    Some(&(resolved, _)) => Target::Resolved(resolved),
                                    None => Target::External(name.clone()),
                                },
                            };
                            let name = if name.is_empty() {
                                symbol
                                    .section_index()
                                    .and_then(|i| sections.get(&(member, i.0)))
                                    .map(|q| q.name.clone())
                                    .unwrap_or_default()
                            } else {
                                name
                            };
                            (target, name)
                        }
                        RelocationTarget::Section(index) => {
                            let Some(q) = sections.get(&(member, index.0)) else {
                                continue;
                            };
                            let resolved = if q.place == Place::Thread {
                                Resolved::Thread(q.offset)
                            } else {
                                Resolved::Address(start(starts, q.place) + q.offset)
                            };
                            (Target::Resolved(resolved), q.name.clone())
                        }
                        RelocationTarget::Absolute | _ => {
                            (Target::Resolved(Resolved::Address(0)), String::new())
                        }
                    };
                    let at = base + offset;
                    self.relocations.push(Relocation {
                        at,
                        size: relocation.size() / 8,
                        kind,
                        symbol: name,
                        addend,
                    });
                    writes.push(Write {
                        at,
                        kind,
                        target,
                        addend,
                    });
                }
            }
        }
        // External symbols, then GOT slots. A COFF object's `__imp_NAME`
        // no object defines is an import: a slot of an import address
        // table the loader fills ([`Linked::imports`]).
        let coff = self.format == Format::Pe;
        let mut externals: BTreeMap<String, u64> = BTreeMap::new();
        let mut imports: BTreeMap<String, u64> = BTreeMap::new();
        for write in &writes {
            if let Target::External(name) = &write.target {
                match name.strip_prefix("__imp_") {
                    Some(imported) if coff => imports.entry(imported.to_owned()).or_insert(0),
                    Some(_) | None => externals.entry(name.clone()).or_insert(0),
                };
            }
        }
        let start = self.next_free();
        for (index, address) in (0u64..).zip(externals.values_mut()) {
            *address = start + index * SLOT;
        }
        if !externals.is_empty() {
            self.segments.push(Owned {
                start,
                size: externals.len() as u64 * SLOT,
                permissions: Place::Data.permissions(),
                bytes: Vec::new(),
            });
        }
        // The import address table: read-only, as a PE image's is.
        let start = self.next_free();
        for (index, address) in (0u64..).zip(imports.values_mut()) {
            *address = start + index * 8;
        }
        if !imports.is_empty() {
            let size = imports.len() as u64 * 8;
            self.segments.push(Owned {
                start,
                size,
                permissions: Place::ReadOnly.permissions(),
                bytes: vec![0; usize::try_from(size).unwrap_or(0)],
            });
        }
        let value = |target: &Target| -> Resolved {
            match target {
                Target::Resolved(resolved) => *resolved,
                Target::External(name) => Resolved::Address(
                    externals
                        .get(name)
                        .or_else(|| imports.get(name.strip_prefix("__imp_")?))
                        .copied()
                        .unwrap_or(0),
                ),
            }
        };
        let thread = |resolved: Resolved| -> u64 {
            match resolved {
                Resolved::Thread(offset) => offset.wrapping_sub(thread_size),
                Resolved::Address(address) => address,
            }
        };
        let mut got: BTreeMap<u64, u64> = BTreeMap::new();
        let got_start = self.next_free();
        let mut got_bytes = Vec::new();
        let mut slot = |value: u64| -> u64 {
            let next = got.len() as u64;
            *got.entry(value).or_insert_with(|| {
                got_bytes.extend_from_slice(&value.to_le_bytes());
                got_start + next * 8
            })
        };
        for write in &writes {
            let s = value(&write.target);
            let a = write.addend;
            let p = write.at;
            let r_type = match write.kind {
                RelocationType::Elf(r_type) => r_type,
                RelocationType::Coff(typ) => {
                    let field = coff_field(typ, s, a, p, starts);
                    if field.is_none() {
                        self.warnings.push(Warning {
                            part: Part::Relocations,
                            message: format!("COFF relocation type {typ} at {p:#x} skipped"),
                        });
                    }
                    if let Some((value, size)) = field {
                        self.write(p, value.to_le_bytes().get(..size).unwrap_or_default());
                    }
                    continue;
                }
            };
            let field: Option<(u64, usize)> = match elf::RelocationType(r_type) {
                elf::R_X86_64_NONE => None,
                elf::R_X86_64_64 | elf::R_X86_64_TPOFF64 => {
                    Some((thread(s).wrapping_add_signed(a), 8))
                }
                elf::R_X86_64_PC32 | elf::R_X86_64_PLT32 => {
                    Some((thread(s).wrapping_add_signed(a).wrapping_sub(p), 4))
                }
                elf::R_X86_64_PC64 => Some((thread(s).wrapping_add_signed(a).wrapping_sub(p), 8)),
                elf::R_X86_64_32 | elf::R_X86_64_32S | elf::R_X86_64_TPOFF32 => {
                    Some((thread(s).wrapping_add_signed(a), 4))
                }
                elf::R_X86_64_16 => Some((thread(s).wrapping_add_signed(a), 2)),
                elf::R_X86_64_8 => Some((thread(s).wrapping_add_signed(a), 1)),
                elf::R_X86_64_PC16 => Some((thread(s).wrapping_add_signed(a).wrapping_sub(p), 2)),
                elf::R_X86_64_PC8 => Some((thread(s).wrapping_add_signed(a).wrapping_sub(p), 1)),
                elf::R_X86_64_GOTPCREL
                | elf::R_X86_64_GOTPCRELX
                | elf::R_X86_64_REX_GOTPCRELX
                | elf::R_X86_64_GOTTPOFF
                | elf::R_X86_64_TLSGD
                | elf::R_X86_64_TLSLD => {
                    let entry = slot(thread(s));
                    Some((entry.wrapping_add_signed(a).wrapping_sub(p), 4))
                }
                elf::R_X86_64_DTPOFF32 => match s {
                    Resolved::Thread(offset) => Some((offset.wrapping_add_signed(a), 4)),
                    Resolved::Address(_) => None,
                },
                elf::R_X86_64_DTPOFF64 => match s {
                    Resolved::Thread(offset) => Some((offset.wrapping_add_signed(a), 8)),
                    Resolved::Address(_) => None,
                },
                elf::R_X86_64_GOTPC32 => {
                    Some((got_start.wrapping_add_signed(a).wrapping_sub(p), 4))
                }
                elf::R_X86_64_GOTOFF64 => {
                    Some((thread(s).wrapping_add_signed(a).wrapping_sub(got_start), 8))
                }
                other => {
                    self.warnings.push(Warning {
                        part: Part::Relocations,
                        message: format!("relocation type {} at {p:#x} skipped", other.0),
                    });
                    None
                }
            };
            if let Some((value, size)) = field {
                self.write(p, value.to_le_bytes().get(..size).unwrap_or_default());
            }
        }
        if !got_bytes.is_empty() {
            self.segments.push(Owned {
                start: got_start,
                size: got_bytes.len() as u64,
                permissions: Place::ReadOnly.permissions(),
                bytes: got_bytes,
            });
        }
        self.externals = externals;
        self.imports = imports;
        self.segments.sort_by_key(|s| s.start);
    }

    /// Writes `bytes` at `address`, where a segment has bytes.
    fn write(&mut self, address: u64, bytes: &[u8]) {
        let Some(segment) = self
            .segments
            .iter_mut()
            .find(|s| s.start <= address && address < s.start + s.size)
        else {
            return;
        };
        let at = usize::try_from(address - segment.start).unwrap_or(usize::MAX);
        if let Some(dest) = segment.bytes.get_mut(at..at.saturating_add(bytes.len())) {
            dest.copy_from_slice(bytes);
        }
    }

    /// The image: the segments, sections, code and symbols, the exception
    /// tables and landing pads of ELF objects' `.eh_frame`, and for COFF
    /// objects the unwind entries and exception handlers of their
    /// `.pdata`; nothing to import, no entry, no fixups (the relocations
    /// are applied).
    pub fn image(&self) -> Image<'_> {
        let mut image = Image {
            format: self.format,
            machine: self.machine,
            slice: None,
            base: Self::BASE,
            position_independent: false,
            kernel: false,
            entry: None,
            segments: self
                .segments
                .iter()
                .map(|s| Segment {
                    start: s.start,
                    size: s.size,
                    permissions: s.permissions,
                    bytes: &s.bytes,
                })
                .collect(),
            sections: self.sections.clone(),
            code: self.code.clone(),
            symbols: self.symbols.clone(),
            imports: self
                .imports
                .iter()
                .map(|(name, &slot)| Import {
                    name: name.clone(),
                    library: None,
                    slot,
                    size: 8,
                    fixed: true,
                })
                .collect(),
            function_starts: Vec::new(),
            unwind: Vec::new(),
            code_pointers: Vec::new(),
            pointers: Vec::new(),
            resolved: Vec::new(),
            landing_pads: self.landing_pads.clone(),
            exception_tables: self.exception_tables.clone(),
            frame_handlers: Vec::new(),
            funclets: Vec::new(),
            fixups: self
                .imports
                .values()
                .map(|&slot| Fixup {
                    start: slot,
                    size: 8,
                    value: None,
                })
                .collect(),
            relro: Vec::new(),
            warnings: self.warnings.clone(),
        };
        if self.format == Format::Pe {
            let mut table = Vec::new();
            for section in self.sections.iter().filter(|s| s.name == ".pdata") {
                let mut bytes = vec![0u8; usize::try_from(section.size).unwrap_or(0)];
                let read = image.read(section.start, &mut bytes).unwrap_or(0);
                table.extend_from_slice(bytes.get(..read).unwrap_or_default());
            }
            x64_pdata(&table, Self::BASE, &mut image);
            image
                .unwind
                .sort_unstable_by_key(|entry| (entry.start, entry.end));
            image
                .code_pointers
                .sort_unstable_by_key(|p| (p.at, p.target));
            image.code_pointers.dedup_by_key(|p| (p.at, p.target));
            image
                .landing_pads
                .sort_unstable_by_key(|p| (p.address, p.function));
            image.landing_pads.dedup();
        }
        image
    }

    /// The object whose sections hold `address`.
    pub fn member(&self, address: u64) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| m.ranges.iter().any(|r| r.contains(&address)))
    }

    /// The relocations whose fields lie in `range`.
    pub fn relocations_in(&self, range: core::ops::Range<u64>) -> &[Relocation] {
        let start = self.relocations.partition_point(|r| r.at < range.start);
        let end = self.relocations.partition_point(|r| r.at < range.end);
        self.relocations.get(start..end).unwrap_or_default()
    }
}

/// The sections of `files` to place: allocated ones with a size, each at
/// an offset in its kind's segment (aligned as it asks). COFF objects'
/// sections ([`coff_place`]) are ordered by name in their segments, as a
/// PE linker groups them (keeping the objects' order within one name),
/// and a COMDAT section another object already defined is left out with
/// its associated sections.
fn layout(files: &[object::File<'_>], coff: bool) -> Vec<Placed> {
    let mut placed = Vec::new();
    if coff {
        let discarded = discarded_comdats(files);
        for (member, file) in files.iter().enumerate() {
            for section in file.sections() {
                if discarded.contains(&(member, section.index().0)) {
                    continue;
                }
                let name = section.name().unwrap_or_default();
                let Some(place) = coff_place(&section, name) else {
                    continue;
                };
                placed.push(Placed {
                    member,
                    index: section.index(),
                    place,
                    offset: section.align().clamp(1, 4096),
                    size: section.size(),
                    name: name.to_owned(),
                });
            }
        }
        // Grouped by the name before `$`, then ordered by the whole name.
        placed.sort_by(|a, b| {
            (a.place, a.name.split('$').next(), &a.name).cmp(&(
                b.place,
                b.name.split('$').next(),
                &b.name,
            ))
        });
        let mut ends = [0u64; PLACES.len()];
        for p in &mut placed {
            let Some(end) = ends.get_mut(p.place as usize) else {
                continue;
            };
            // The alignment, kept in `offset` until now.
            p.offset = end.next_multiple_of(p.offset);
            *end = p.offset + p.size;
        }
        return placed;
    }
    let mut ends = [0u64; PLACES.len()];
    for (member, file) in files.iter().enumerate() {
        for section in file.sections() {
            let SectionFlags::Elf { sh_flags, .. } = section.flags() else {
                continue;
            };
            if sh_flags.0 & elf::SHF_ALLOC.0 == 0 || section.size() == 0 {
                continue;
            }
            let name = section.name().unwrap_or_default();
            if name.starts_with(".note") {
                continue;
            }
            let thread = sh_flags.0 & elf::SHF_TLS.0 != 0;
            let place = if name == ".eh_frame" {
                Place::Unwind
            } else if name.starts_with(".eh_frame") {
                continue;
            } else if thread {
                Place::Thread
            } else if sh_flags.0 & elf::SHF_EXECINSTR.0 != 0 {
                Place::Code
            } else if section.kind() == SectionKind::UninitializedData {
                Place::Zero
            } else if sh_flags.0 & elf::SHF_WRITE.0 == 0 || name.starts_with(".data.rel.ro") {
                Place::ReadOnly
            } else {
                Place::Data
            };
            let Some(end) = ends.get_mut(place as usize) else {
                continue;
            };
            let offset = end.next_multiple_of(section.align().clamp(1, 4096));
            *end = offset + section.size();
            placed.push(Placed {
                member,
                index: section.index(),
                place,
                offset,
                size: section.size(),
                name: name.to_owned(),
            });
        }
    }
    placed
}

/// The objects of an archive ([`archive_members`]) and what was left out.
#[derive(Clone, Debug, Default)]
pub struct ArchiveKinds<'data> {
    /// The objects to link, by name (a COFF member's without its
    /// directory: `strcpy.obj`), in archive order.
    pub objects: Vec<(String, &'data [u8])>,
    /// How many members were an import library's: short import objects
    /// (one per function or variable, which is in a DLL) and the import
    /// descriptors' objects (`.idata$` sections only).
    pub imports: usize,
    /// The names of members of other kinds left out: link-time code
    /// generation objects (`/GL`), objects of another instruction set,
    /// damaged ones.
    pub skipped: Vec<String>,
}

/// The members of the archive `data` (`!<arch>`: a `.a`, `.rlib` or
/// Microsoft `.lib`) that are relocatable objects to link: ELF objects
/// with code; x86-64 COFF objects and MSVC alias objects (weak externals
/// only). The archive's symbol tables (its linker members), a Rust
/// library's metadata, an import library's short import objects and
/// link-time code generation objects are left out.
///
/// # Errors
///
/// `data` is no archive, or a damaged one.
pub fn archive_members(data: &[u8]) -> Result<ArchiveKinds<'_>, LoadError> {
    let archive = object::read::archive::ArchiveFile::parse(data)
        .map_err(|e| LoadError::Parse(e.to_string()))?;
    let mut kinds = ArchiveKinds::default();
    for member in archive.members() {
        let member = member.map_err(|e| LoadError::Parse(e.to_string()))?;
        let Ok(bytes) = member.data(data) else {
            continue;
        };
        let name = String::from_utf8_lossy(member.name()).into_owned();
        let coff = match object::FileKind::parse(bytes) {
            Ok(object::FileKind::CoffImport) => {
                kinds.imports += 1;
                continue;
            }
            Ok(object::FileKind::Coff | object::FileKind::CoffBig) => true,
            // Another anonymous object: link-time code generation's.
            Err(_) if bytes.starts_with(&[0, 0, 0xff, 0xff]) => {
                kinds.skipped.push(name);
                continue;
            }
            Err(_) => is_alias_object(bytes),
            Ok(_) => false,
        };
        if coff {
            match parse_object(&name, bytes) {
                // An import library's descriptors: its import directory
                // and thunk tables (`.idata$2` to `.idata$6`), no code.
                Ok(file)
                    if file
                        .sections()
                        .any(|s| s.name().is_ok_and(|n| n.starts_with(".idata$")))
                        && file.sections().all(|s| {
                            s.name()
                                .is_ok_and(|n| n.starts_with(".idata$") || n.starts_with(".debug$"))
                        }) =>
                {
                    kinds.imports += 1;
                }
                Ok(_) => {
                    let base = name.rsplit(['\\', '/']).next().unwrap_or(&name);
                    kinds.objects.push((base.to_owned(), bytes));
                }
                Err(_) => kinds.skipped.push(name),
            }
            continue;
        }
        let relocatable = object::File::parse(bytes).is_ok_and(|file| {
            file.format() == object::BinaryFormat::Elf
                && file.kind() == object::ObjectKind::Relocatable
                && file.sections().any(|s| {
                    matches!(s.flags(), SectionFlags::Elf { sh_flags, .. } if sh_flags.0 & elf::SHF_EXECINSTR.0 != 0)
                })
        });
        if relocatable {
            kinds.objects.push((name, bytes));
        }
    }
    Ok(kinds)
}

/// Whether `data` is an archive (`!<arch>`).
pub fn is_archive(data: &[u8]) -> bool {
    data.starts_with(b"!<arch>\n")
}

/// Whether `data` is a relocatable object: ELF, or COFF (`.obj`).
pub fn is_relocatable(data: &[u8]) -> bool {
    object::File::parse(data).is_ok_and(|file| {
        matches!(
            file.format(),
            object::BinaryFormat::Elf | object::BinaryFormat::Coff
        ) && file.kind() == object::ObjectKind::Relocatable
    })
}

/// Whether `data` may be an MSVC alias object (`ALIASOBJ`: no machine,
/// weak externals naming a function's other names), by its header: no
/// machine, and a section count where an anonymous object has `0xffff`.
fn is_alias_object(data: &[u8]) -> bool {
    matches!(data, [0, 0, low, high, ..] if [*low, *high] != [0xff, 0xff])
}

/// The object `data` (called `name`), parsed: an x86-64 ELF relocatable
/// object, an x86-64 COFF object, or an MSVC alias object.
///
/// # Errors
///
/// `data` is none of those.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "object's formats are non-exhaustive; every other one is unsupported"
)]
fn parse_object<'data>(name: &str, data: &'data [u8]) -> Result<object::File<'data>, LoadError> {
    let file = match object::File::parse(data) {
        Ok(file) => file,
        Err(_) if is_alias_object(data) => object::File::Coff(
            CoffFile::parse(data).map_err(|e| LoadError::Parse(format!("{name}: {e}")))?,
        ),
        Err(e) => return Err(LoadError::Parse(format!("{name}: {e}"))),
    };
    let architecture = file.architecture();
    match file.format() {
        object::BinaryFormat::Elf if file.kind() == object::ObjectKind::Relocatable => {}
        object::BinaryFormat::Coff
            if architecture == object::Architecture::Unknown
                && file
                    .sections()
                    .all(|s| s.relocations().next().is_none() && s.kind() != SectionKind::Text) =>
        {
            return Ok(file);
        }
        object::BinaryFormat::Coff => {}
        _ => return Err(LoadError::UnsupportedFormat),
    }
    if architecture != object::Architecture::X86_64 {
        return Err(LoadError::Parse(format!(
            "{name}: only x86-64 objects are read (this one is {architecture:?})"
        )));
    }
    Ok(file)
}

/// The value a COFF relocation's field holds in its section `data` at
/// `offset` (a field of `bits` bits, sign-extended): its addend.
fn implicit_addend(data: &[u8], offset: u64, bits: u8) -> i64 {
    let at = usize::try_from(offset).unwrap_or(usize::MAX);
    let field = |size: usize| data.get(at..at.saturating_add(size));
    match bits {
        64 => field(8)
            .and_then(|b| b.try_into().ok())
            .map_or(0, i64::from_le_bytes),
        32 => field(4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, |b| i64::from(i32::from_le_bytes(b))),
        16 => field(2)
            .and_then(|b| b.try_into().ok())
            .map_or(0, |b| i64::from(i16::from_le_bytes(b))),
        _ => 0,
    }
}

/// The value and size of the field a COFF x86-64 relocation of type
/// `typ` writes at `p`, its symbol resolved to `s` and its addend `a`, in
/// an image whose segments start at `starts`: a field of no bytes when it
/// writes nothing here (`ABSOLUTE`, `SECTION`: debug information's),
/// `None` for a type not handled. A thread-local symbol's address is in
/// the thread-local segment (the TLS template), and `SECREL` counts from
/// its segment's start (a thread-local variable's offset in the block).
fn coff_field(typ: u16, s: Resolved, a: i64, p: u64, starts: &Starts) -> Option<(u64, usize)> {
    let absolute = match s {
        Resolved::Address(address) => address,
        Resolved::Thread(offset) => start(starts, Place::Thread) + offset,
    };
    let section_offset = match s {
        Resolved::Thread(offset) => offset,
        Resolved::Address(address) => {
            address
                - starts
                    .iter()
                    .copied()
                    .filter(|&start| start <= address)
                    .max()
                    .unwrap_or(address)
        }
    };
    let value = absolute.wrapping_add_signed(a);
    let rel32 = pe::IMAGE_REL_AMD64_REL32.0;
    match pe::RelocationType(typ) {
        pe::IMAGE_REL_AMD64_ABSOLUTE | pe::IMAGE_REL_AMD64_SECTION => Some((0, 0)),
        pe::IMAGE_REL_AMD64_ADDR64 => Some((value, 8)),
        pe::IMAGE_REL_AMD64_ADDR32 => Some((value, 4)),
        pe::IMAGE_REL_AMD64_ADDR32NB => Some((value.wrapping_sub(Linked::BASE), 4)),
        _ if (rel32..=rel32 + 5).contains(&typ) => {
            let next = p + 4 + u64::from(typ - rel32);
            Some((value.wrapping_sub(next), 4))
        }
        pe::IMAGE_REL_AMD64_SECREL => Some((section_offset.wrapping_add_signed(a), 4)),
        _ => None,
    }
}

/// The COFF sections' COMDATs that an earlier object (in `files` order)
/// already defined, by member and section index, with their associated
/// sections: a linker keeps the first. A COMDAT of code whose bytes (its
/// relocated fields as the object holds them) differ from every copy kept
/// is kept too: one inline function compiled otherwise in another object
/// (`get_raw_ptd` with a callee inlined), which a program's linker may
/// choose. Its symbols are the image's but not global names: references
/// resolve to the first copy.
fn discarded_comdats(files: &[object::File<'_>]) -> BTreeSet<(usize, usize)> {
    let mut chosen: BTreeMap<String, Vec<Option<&[u8]>>> = BTreeMap::new();
    let mut discarded = BTreeSet::new();
    for (member, file) in files.iter().enumerate() {
        for comdat in file.comdats() {
            let Ok(name) = comdat.name() else { continue };
            let code = comdat.sections().find_map(|index| {
                let section = file.section_by_index(index).ok()?;
                (section.kind() == SectionKind::Text)
                    .then(|| section.data().ok())
                    .flatten()
            });
            match chosen.entry(name.to_owned()) {
                Entry::Vacant(entry) => {
                    entry.insert(vec![code]);
                }
                Entry::Occupied(mut entry) => {
                    if code.is_some() && !entry.get().contains(&code) {
                        entry.get_mut().push(code);
                    } else {
                        discarded.extend(comdat.sections().map(|index| (member, index.0)));
                    }
                }
            }
        }
    }
    discarded
}

/// Where a COFF object's section `section` (called `name`) goes, if it is
/// part of the image: not debug information (`.debug$S`), linker
/// directives (`.drectve`) or anything else the linker removes or
/// discards.
fn coff_place(section: &object::Section<'_, '_>, name: &str) -> Option<Place> {
    let SectionFlags::Coff { characteristics } = section.flags() else {
        return None;
    };
    let has = |flag: pe::SectionFlags| characteristics.0 & flag.0 != 0;
    let removed = has(pe::IMAGE_SCN_LNK_REMOVE)
        || has(pe::IMAGE_SCN_LNK_INFO)
        || has(pe::IMAGE_SCN_MEM_DISCARDABLE);
    if removed || section.size() == 0 || name.starts_with(".debug") {
        return None;
    }
    Some(if name == ".tls" || name.starts_with(".tls$") {
        Place::Thread
    } else if has(pe::IMAGE_SCN_MEM_EXECUTE) || has(pe::IMAGE_SCN_CNT_CODE) {
        Place::Code
    } else if has(pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
        Place::Zero
    } else if has(pe::IMAGE_SCN_MEM_WRITE) {
        Place::Data
    } else {
        Place::ReadOnly
    })
}

/// The weak externals of COFF object `file`: each name and the index of
/// its default symbol.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "object's files are non-exhaustive; only COFF has weak externals"
)]
fn weak_externals(file: &object::File<'_>) -> Vec<(String, SymbolIndex)> {
    match file {
        object::File::Coff(coff) => weak_externals_of(coff),
        object::File::CoffBig(coff) => weak_externals_of(coff),
        _ => Vec::new(),
    }
}

/// [`weak_externals`] of a COFF file of either header.
fn weak_externals_of<'data, H: CoffHeader>(
    coff: &CoffFile<'data, &'data [u8], H>,
) -> Vec<(String, SymbolIndex)> {
    let table = coff.coff_symbol_table();
    table
        .iter()
        .filter(|(_, symbol)| {
            symbol.storage_class() == pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
                && symbol.has_aux_weak_external()
        })
        .filter_map(|(index, symbol)| {
            let name = symbol.name(table.strings()).ok()?;
            let aux = table.aux_weak_external(index).ok()?;
            Some((
                String::from_utf8_lossy(name).into_owned(),
                SymbolIndex(usize::try_from(aux.weak_default_sym_index.get(LE)).ok()?),
            ))
        })
        .collect()
}

/// The `/alternatename:NAME=DEFAULT` directives of COFF object `file`'s
/// `.drectve` section.
fn alternate_names(file: &object::File<'_>) -> Vec<(String, String)> {
    let Some(section) = file.section_by_name(".drectve") else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(section.data().unwrap_or_default()).into_owned();
    text.split_ascii_whitespace()
        .filter_map(|directive| {
            let (option, value) = directive.split_once(':')?;
            let option = option.trim_start_matches(['/', '-']);
            if !option.eq_ignore_ascii_case("alternatename") {
                return None;
            }
            let (name, default) = value.trim_matches('"').split_once('=')?;
            Some((name.to_owned(), default.to_owned()))
        })
        .collect()
}
