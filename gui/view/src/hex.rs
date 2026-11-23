//! The structured hex view without the framework:
//! the image as a byte space partitioned by what its bytes are, its rows,
//! the typed overlays laid over it, the selection, and what is copied.
//!
//! - **Two spaces.** [`Mode::Address`]: the mapped segments, each
//!   from a 16-byte boundary, one after another; bytes the file does not
//!   supply (`.bss`) are uninitialised. [`Mode::File`]: the file's bytes
//!   by offset, headers and tables the loader never maps included. A
//!   position is an address or a file offset; [`HexImage::to_address`]
//!   and [`HexImage::to_file`] convert, through the load commands'
//!   regions (ELF `PT_LOAD`, PE sections and headers).
//! - **The partition** ([`HexImage::cells`]): of any range, painted in
//!   layers, each byte taking the strongest: the file's headers and their
//!   tables (read through the built-in C structures, [`crate::hex_types`]),
//!   then the listing's items (instructions, strings, pointers, import
//!   slots, typed values, padding; `binbun::listing`'s spans), then the
//!   sections by type (symbol tables, string tables, relocations), then
//!   relocation slots, unexplored bytes, the rest of a section, and what
//!   no section holds. Costs the range, not the image.
//! - **Rows**: 16 bytes a row, one line each, in one 64-bit line space as
//!   the listing's.
//! - **Overlays** ([`Overlay`]): a laid-out C type at a place: the file's
//!   headers and tables as one tree (ELF: the `Elf64_Ehdr`, the
//!   `Elf64_Phdr[e_phnum]` at `e_phoff`, the `Elf64_Shdr[e_shnum]` at
//!   `e_shoff`; PE: the DOS and NT headers and the section headers), the
//!   debug information's typed globals, and the user's, saved beside the
//!   project ([`save_overlays`]). Their leaves are placed over the bytes
//!   of either space ([`HexImage::placed`]), a leaf at a time, so a tree
//!   whose parts the loader maps apart (the section headers it never
//!   maps) is placed part by part.

use std::fmt::Write as _;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use binbun::listing::{Span, SpanKind};
use binbun_debuginfo::info::DebugModel;
use binbun_loader::{Format, Image, Machine};

use crate::crash_safe;
use crate::hex_tree::StructTree;
use crate::hex_types::{self, DataModel, Layout, TypeSet, read_uint};
use crate::hex_types::{Node, Shape};
use crate::scroll::{Scroller, Sideways};

/// Bytes a row.
pub const ROW: u64 = 16;

/// Which space positions are in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Virtual addresses: the mapped segments.
    #[default]
    Address,
    /// File offsets: the whole file.
    File,
}

/// What a byte is: its partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// A file header (ELF header; DOS, NT and optional headers).
    Header,
    /// A table of the file: program and section headers, PE's section
    /// table, symbol tables.
    Table,
    /// An instruction of a function.
    Code,
    /// An instruction no function holds.
    LooseCode,
    /// A string (a literal, a string table).
    String,
    /// A pointer a relocation stores.
    Pointer,
    /// An import's pointer slot.
    Import,
    /// A typed value: a scalar, an object, an array, a jump table.
    Value,
    /// A slot the loader writes, or a relocation table.
    Relocation,
    /// Padding: alignment, runs of one value, zeros between sections.
    Padding,
    /// A section's bytes nothing finer describes.
    Section,
    /// Mapped bytes no analysis typed.
    Unexplored,
    /// File bytes no section or header holds.
    Other,
    /// Mapped bytes the file does not supply (`.bss`).
    Uninitialised,
    /// No byte: an address no segment maps, past the file's end.
    Gap,
}

impl Kind {
    /// Every kind, in the legend's order.
    pub const ALL: [Self; 15] = [
        Self::Header,
        Self::Table,
        Self::Code,
        Self::LooseCode,
        Self::String,
        Self::Pointer,
        Self::Import,
        Self::Value,
        Self::Relocation,
        Self::Padding,
        Self::Section,
        Self::Unexplored,
        Self::Other,
        Self::Uninitialised,
        Self::Gap,
    ];

    /// Its name, for a tooltip.
    pub fn title(self) -> &'static str {
        match self {
            Self::Header => "Header",
            Self::Table => "Table",
            Self::Code => "Code",
            Self::LooseCode => "Code outside functions",
            Self::String => "String",
            Self::Pointer => "Pointer",
            Self::Import => "Import slot",
            Self::Value => "Typed data",
            Self::Relocation => "Relocation",
            Self::Padding => "Padding",
            Self::Section => "Section",
            Self::Unexplored => "Unexplored",
            Self::Other => "Outside sections",
            Self::Uninitialised => "Uninitialised",
            Self::Gap => "Unmapped",
        }
    }
}

/// One byte of the view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    /// Its value; `None` where there is no byte (uninitialised, a gap).
    pub value: Option<u8>,
    /// What it is.
    pub kind: Kind,
    /// An item (instruction, data item, header, section) starts here.
    pub start: bool,
}

/// File bytes mapped at an address.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Region {
    file: Range<u64>,
    address: u64,
}

/// A part of the file: a header, a table, a section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// Its file offsets.
    pub file: Range<u64>,
    /// What it is.
    pub kind: Kind,
    /// Its name (`ELF header`, `.text`).
    pub name: String,
}

/// A run of address-mode rows: a segment from a row boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Block {
    /// Its first row's address.
    start: u64,
    /// Past its last row.
    end: u64,
    /// Its first row in the address-mode row space.
    first_row: u64,
}

/// Where an overlay is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Anchor {
    /// At a file offset.
    File(u64),
    /// At an address.
    Address(u64),
}

impl Anchor {
    /// Its space and its position there.
    pub fn place(self) -> (Mode, u64) {
        match self {
            Self::File(at) => (Mode::File, at),
            Self::Address(at) => (Mode::Address, at),
        }
    }
}

/// Where an overlay comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// The file's headers.
    Header,
    /// The whole program's typed globals ([`crate::hex_globals`]).
    Program,
    /// The debug information's typed globals.
    Debug,
    /// The user.
    User,
}

/// A type laid over bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Overlay {
    /// Where it starts.
    pub anchor: Anchor,
    /// The type.
    pub layout: Arc<Layout>,
    /// Where it comes from.
    pub source: Source,
    /// The instance's name (`ELF`, `PE`, a global's name).
    pub name: String,
    /// What the user wrote, for a user overlay (a type's name or C).
    pub text: Option<String>,
    /// Names of its parts by their bytes from its start (a section
    /// header's: its section's name).
    pub labels: Vec<(Range<u64>, String)>,
}

impl Overlay {
    /// The label of its part at `range` (from its start), if it has one.
    pub fn label(&self, range: &Range<u64>) -> Option<&str> {
        let i = self.labels.partition_point(|(r, _)| r.start < range.start);
        self.labels
            .get(i)
            .filter(|(r, _)| r == range)
            .map(|(_, label)| label.as_str())
    }
}

/// A leaf of an overlay (a field the hex view tints) at positions of one
/// space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed {
    /// Its first position (in the range asked of).
    pub start: u64,
    /// Past its last (in the range asked of).
    pub end: u64,
    /// Its first byte from the overlay's start, wherever it is.
    pub offset: u64,
    /// Its size.
    pub size: u64,
    /// Its path (`ehdr.e_ident`, `phdr[2].p_flags`); empty for an overlay
    /// of a scalar.
    pub path: String,
    /// The overlay's index in the overlays asked of.
    pub overlay: usize,
    /// Its number among the overlay's leaves, in offset order (its tint).
    pub ordinal: u64,
}

/// The image's byte space: its regions, parts, rows and header overlays.
#[derive(Clone, Debug)]
pub struct HexImage {
    file_len: u64,
    little: bool,
    model: DataModel,
    regions: Vec<Region>,
    /// Indices of `regions` by address.
    by_address: Vec<usize>,
    parts: Vec<Part>,
    blocks: Vec<Block>,
    /// The mapped segments: their addresses and how many bytes the file
    /// supplies.
    segments: Vec<(Range<u64>, u64)>,
    /// The sections by address, for names.
    sections: Vec<(Range<u64>, String)>,
    /// The loader's small fixups (a word it writes), by start.
    fixups: Vec<Range<u64>>,
    headers: Vec<Overlay>,
}

impl HexImage {
    /// The byte space of `image`, parsed from `file` (its bytes).
    pub fn new(file: &[u8], image: &Image<'_>) -> Self {
        let arch = match image.machine {
            Machine::X86 => "x86",
            Machine::Arm => "arm",
            Machine::Aarch64 => "aarch64",
            Machine::X86_64 | Machine::Other => "x86_64",
        };
        let os = match image.format {
            Format::Pe => "windows",
            Format::Elf => "linux",
            Format::MachO => "macos",
        };
        let model = DataModel::of(arch, os);
        let little = !(image.format == Format::Elf && file.get(5) == Some(&2));
        let mut this = Self {
            file_len: file.len() as u64,
            little,
            model,
            regions: Vec::new(),
            by_address: Vec::new(),
            parts: Vec::new(),
            blocks: Vec::new(),
            segments: Vec::new(),
            sections: Vec::new(),
            fixups: Vec::new(),
            headers: Vec::new(),
        };
        let mut types = TypeSet::builtin(model);
        match image.format {
            Format::Elf => this.read_elf(file, &mut types),
            Format::Pe => this.read_pe(file, &mut types),
            Format::MachO => this.read_macho(file, image, &mut types),
        }
        this.parts
            .sort_by_key(|p| (p.file.start, std::cmp::Reverse(p.file.end)));
        this.regions.retain(|r| !r.file.is_empty());
        this.regions.sort_by_key(|r| r.file.start);
        this.by_address = (0..this.regions.len()).collect();
        this.by_address
            .sort_by_key(|&i| this.regions.get(i).map_or(0, |r| r.address));
        let mut row = 0;
        for segment in &image.segments {
            let start = segment.start / ROW * ROW;
            let end = segment.end().div_ceil(ROW) * ROW;
            // Segments sharing a row share a block.
            if let Some(last) = this.blocks.last_mut()
                && start < last.end
            {
                row += (end.max(last.end) - last.end) / ROW;
                last.end = end.max(last.end);
            } else {
                this.blocks.push(Block {
                    start,
                    end,
                    first_row: row,
                });
                row += (end - start) / ROW;
            }
            this.segments
                .push((segment.start..segment.end(), segment.bytes.len() as u64));
        }
        this.sections = image
            .sections
            .iter()
            .map(|s| (s.start..s.start.saturating_add(s.size), s.name.clone()))
            .collect();
        this.sections.sort_by_key(|(r, _)| r.start);
        this.fixups = image
            .fixups
            .iter()
            .filter(|f| f.size <= 8)
            .map(|f| f.start..f.start + f.size)
            .collect();
        this
    }

    /// The ELF headers, program headers, section headers and sections.
    fn read_elf(&mut self, file: &[u8], types: &mut TypeSet) {
        let wide = file.get(4) == Some(&2);
        let names = if wide {
            ["Elf64_Ehdr", "Elf64_Phdr", "Elf64_Shdr"]
        } else {
            ["Elf32_Ehdr", "Elf32_Phdr", "Elf32_Shdr"]
        };
        let [Ok(ehdr), Ok(phdr), Ok(shdr)] = names.map(|n| types.layout(n)) else {
            return;
        };
        let little = self.little;
        let at = |offset: u64| file.get(usize::try_from(offset).unwrap_or(usize::MAX)..);
        let read = |layout: &Layout, offset: u64, field: &str| {
            at(offset).and_then(|bytes| layout.read(bytes, field, little))
        };
        let field = |name: &str| read(&ehdr, 0, name).unwrap_or(0);
        self.parts.push(Part {
            file: 0..ehdr.size.min(self.file_len),
            kind: Kind::Header,
            name: "ELF header".to_owned(),
        });
        let mut members = vec![ehdr.root.member("ehdr", 0)];
        let mut labels = Vec::new();
        let table = |offset: u64, count: u64, size: u64| -> Vec<u64> {
            if offset == 0 || size == 0 || count > 0x10000 {
                return Vec::new();
            }
            (0..count).map(|i| offset + i * size).collect()
        };
        let (phoff, phnum, phsize) = (field("e_phoff"), field("e_phnum"), field("e_phentsize"));
        let programs = table(phoff, phnum, phsize);
        if !programs.is_empty() {
            self.parts.push(Part {
                file: phoff..phoff + phnum * phsize,
                kind: Kind::Table,
                name: "Program headers".to_owned(),
            });
            if phsize == phdr.size {
                members.push(phdr.root.array(phnum, "phdr", phoff));
            }
        }
        for &offset in &programs {
            // PT_LOAD.
            if read(&phdr, offset, "p_type") == Some(1) {
                let get = |name: &str| read(&phdr, offset, name).unwrap_or(0);
                let start = get("p_offset");
                let end = start.saturating_add(get("p_filesz")).min(self.file_len);
                self.regions.push(Region {
                    file: start..end.max(start),
                    address: get("p_vaddr"),
                });
            }
        }
        let (shoff, shnum, shsize) = (field("e_shoff"), field("e_shnum"), field("e_shentsize"));
        let sections = table(shoff, shnum, shsize);
        if !sections.is_empty() {
            self.parts.push(Part {
                file: shoff..shoff + shnum * shsize,
                kind: Kind::Table,
                name: "Section headers".to_owned(),
            });
            if shsize == shdr.size {
                members.push(shdr.root.array(shnum, "shdr", shoff));
            }
        }
        let strings = sections
            .get(usize::try_from(field("e_shstrndx")).unwrap_or(usize::MAX))
            .and_then(|&offset| read(&shdr, offset, "sh_offset"));
        for &offset in &sections {
            let get = |name: &str| read(&shdr, offset, name).unwrap_or(0);
            let name = strings
                .and_then(|base| at(base + get("sh_name")))
                .map(|bytes| {
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(0).min(64);
                    String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned()
                })
                .unwrap_or_default();
            if !name.is_empty() && shsize == shdr.size {
                labels.push((offset..offset + shsize, name.clone()));
            }
            let kind = match get("sh_type") {
                // SHT_NULL, SHT_NOBITS: no bytes in the file.
                0 | 8 => continue,
                // SHT_SYMTAB, SHT_DYNSYM, SHT_HASH, SHT_DYNAMIC, SHT_GNU_HASH,
                // the symbol versions.
                2 | 11 | 5 | 6 | 0x6fff_fff6 | 0x6fff_fffe | 0x6fff_ffff => Kind::Table,
                3 => Kind::String,
                // SHT_RELA, SHT_REL, SHT_RELR.
                4 | 9 | 19 => Kind::Relocation,
                _ => Kind::Section,
            };
            let start = get("sh_offset");
            let end = start.saturating_add(get("sh_size")).min(self.file_len);
            if start < end {
                self.parts.push(Part {
                    file: start..end,
                    kind,
                    name,
                });
            }
        }
        self.headers.push(file_overlay("ELF", members, labels));
    }

    /// The DOS, NT and optional headers, the section table and sections.
    fn read_pe(&mut self, file: &[u8], types: &mut TypeSet) {
        let (Ok(dos), Ok(section)) = (
            types.layout("IMAGE_DOS_HEADER"),
            types.layout("IMAGE_SECTION_HEADER"),
        ) else {
            return;
        };
        let at = |offset: u64| file.get(usize::try_from(offset).unwrap_or(usize::MAX)..);
        let read = |layout: &Layout, offset: u64, field: &str| {
            at(offset).and_then(|bytes| layout.read(bytes, field, true))
        };
        self.parts.push(Part {
            file: 0..dos.size.min(self.file_len),
            kind: Kind::Header,
            name: "DOS header".to_owned(),
        });
        let mut members = vec![dos.root.member("dos", 0)];
        let mut labels = Vec::new();
        let nt_at = read(&dos, 0, "e_lfanew").unwrap_or(0);
        if nt_at > dos.size {
            self.parts.push(Part {
                file: dos.size..nt_at.min(self.file_len),
                kind: Kind::Section,
                name: "DOS stub".to_owned(),
            });
        }
        // The optional header's magic: PE32+ or PE32.
        let magic = at(nt_at + 24).and_then(|b| read_uint(b.get(..2)?, true));
        let nt_name = if magic == Some(0x20b) {
            "IMAGE_NT_HEADERS64"
        } else {
            "IMAGE_NT_HEADERS32"
        };
        let Ok(nt) = types.layout(nt_name) else {
            self.headers.push(file_overlay("PE", members, labels));
            return;
        };
        let get = |name: &str| read(&nt, nt_at, name).unwrap_or(0);
        let optional = get("FileHeader.SizeOfOptionalHeader");
        let table_at = nt_at + 24 + optional;
        self.parts.push(Part {
            file: nt_at..table_at.min(self.file_len),
            kind: Kind::Header,
            name: "NT headers".to_owned(),
        });
        if nt_at >= dos.size {
            members.push(nt.root.member("nt", nt_at));
        }
        let base = get("OptionalHeader.ImageBase");
        self.regions.push(Region {
            file: 0..get("OptionalHeader.SizeOfHeaders").min(self.file_len),
            address: base,
        });
        let count = get("FileHeader.NumberOfSections").min(0x1000);
        self.parts.push(Part {
            file: table_at..(table_at + count * section.size).min(self.file_len),
            kind: Kind::Table,
            name: "Section table".to_owned(),
        });
        if count > 0 {
            members.push(section.root.array(count, "sections", table_at));
        }
        for i in 0..count {
            let offset = table_at + i * section.size;
            let get = |name: &str| read(&section, offset, name).unwrap_or(0);
            let name = at(offset)
                .and_then(|b| b.get(..8))
                .map(|b| {
                    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                    String::from_utf8_lossy(b.get(..end).unwrap_or_default()).into_owned()
                })
                .unwrap_or_default();
            if !name.is_empty() {
                labels.push((offset..offset + section.size, name.clone()));
            }
            let start = get("PointerToRawData");
            let raw = get("SizeOfRawData");
            let virtual_size = get("Misc.PhysicalAddress");
            let mapped = if virtual_size == 0 {
                raw
            } else {
                raw.min(virtual_size)
            };
            let end = start.saturating_add(raw).min(self.file_len);
            if start < end {
                self.parts.push(Part {
                    file: start..end,
                    kind: Kind::Section,
                    name,
                });
                self.regions.push(Region {
                    file: start..start.saturating_add(mapped).min(end),
                    address: base + get("VirtualAddress"),
                });
            }
        }
        self.headers.push(file_overlay("PE", members, labels));
    }

    /// Of a slice of a universal file, the universal header and the other
    /// slices; the slice's Mach-O header, load commands (segments with
    /// their sections' headers), sections and symbol table.
    fn read_macho(&mut self, file: &[u8], image: &Image<'_>, types: &mut TypeSet) {
        if let Some(own) = &image.slice {
            self.read_universal(file, own);
        }
        let (Ok(header), Ok(command), Ok(segment), Ok(section)) = (
            types.layout("struct mach_header_64"),
            types.layout("struct load_command"),
            types.layout("struct segment_command_64"),
            types.layout("struct section_64"),
        ) else {
            return;
        };
        // Offsets in the slice are from its start.
        let base = image.slice.as_ref().map_or(0, |slice| slice.offset);
        let at = |offset: u64| file.get(usize::try_from(offset).unwrap_or(usize::MAX)..);
        let read = |layout: &Layout, offset: u64, field: &str| {
            at(offset).and_then(|bytes| layout.read(bytes, field, true))
        };
        let word = |offset: u64| at(offset).and_then(|b| read_uint(b.get(..4)?, true));
        self.parts.push(Part {
            file: base..base.saturating_add(header.size).min(self.file_len),
            kind: Kind::Header,
            name: "Mach-O header".to_owned(),
        });
        let mut members = vec![header.root.member("header", base)];
        let mut labels = Vec::new();
        let get = |field: &str| read(&header, base, field).unwrap_or(0);
        let commands = base + header.size;
        let end = commands
            .saturating_add(get("sizeofcmds"))
            .min(self.file_len);
        self.parts.push(Part {
            file: commands..end,
            kind: Kind::Table,
            name: "Load commands".to_owned(),
        });
        let mut offset = commands;
        for index in 0..get("ncmds").min(0x10000) {
            let kind = read(&command, offset, "cmd").unwrap_or(0);
            let size = read(&command, offset, "cmdsize").unwrap_or(0);
            if size < command.size || offset.saturating_add(size) > end {
                break;
            }
            match kind {
                // LC_SEGMENT_64: the segment, its sections' headers after it.
                0x19 if size >= segment.size => {
                    let get = |field: &str| read(&segment, offset, field).unwrap_or(0);
                    members.push(segment.root.member(&format!("lc{index}"), offset));
                    labels.push((offset..offset + segment.size, macho_name(file, offset + 8)));
                    let start = base.saturating_add(get("fileoff"));
                    self.regions.push(Region {
                        file: start..start.saturating_add(get("filesize")).min(self.file_len),
                        address: get("vmaddr"),
                    });
                    let table = offset + segment.size;
                    let count = get("nsects").min((size - segment.size) / section.size);
                    if count > 0 {
                        members.push(section.root.array(
                            count,
                            &format!("lc{index}_sections"),
                            table,
                        ));
                    }
                    for at in (0..count).map(|i| table + i * section.size) {
                        let name = self.read_section(file, base, &section, at);
                        labels.push((at..at + section.size, name));
                    }
                }
                // LC_SYMTAB: symoff, nsyms (16-byte `nlist_64`s), stroff,
                // strsize.
                0x2 if size >= 24 => {
                    members.push(command.root.member(&format!("lc{index}"), offset));
                    let field = |at: u64| word(offset + at).unwrap_or(0);
                    let start = base.saturating_add(field(8));
                    self.file_part(start, field(12) * 16, Kind::Table, "Symbol table");
                    let start = base.saturating_add(field(16));
                    self.file_part(start, field(20), Kind::String, "String table");
                }
                _ => members.push(command.root.member(&format!("lc{index}"), offset)),
            }
            offset += size;
        }
        self.headers.push(file_overlay("Mach-O", members, labels));
    }

    /// The part of the section whose `section_64` (`section`) is at
    /// `header`, in a slice from `base`, if its bytes are in the file;
    /// its name (`__TEXT,__text`).
    fn read_section(&mut self, file: &[u8], base: u64, section: &Layout, header: u64) -> String {
        let get = |field: &str| {
            file.get(usize::try_from(header).unwrap_or(usize::MAX)..)
                .and_then(|bytes| section.read(bytes, field, true))
                .unwrap_or(0)
        };
        let name = format!(
            "{},{}",
            macho_name(file, header + 16),
            macho_name(file, header)
        );
        let kind = match get("flags") & 0xff {
            // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL: no bytes
            // in the file.
            0x1 | 0xc | 0x12 => return name,
            // S_CSTRING_LITERALS.
            0x2 => Kind::String,
            // S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS.
            0x6 | 0x7 => Kind::Relocation,
            _ => Kind::Section,
        };
        let start = get("offset");
        if start != 0 {
            self.file_part(base.saturating_add(start), get("size"), kind, &name);
        }
        name
    }

    /// A part of `size` bytes from `start`, as far as the file holds them
    /// (none if it holds none).
    fn file_part(&mut self, start: u64, size: u64, kind: Kind, name: &str) {
        let end = start.saturating_add(size).min(self.file_len);
        if start < end {
            self.parts.push(Part {
                file: start..end,
                kind,
                name: name.to_owned(),
            });
        }
    }

    /// The universal header of the file whose slice `own` the image is,
    /// and its other slices.
    fn read_universal(&mut self, file: &[u8], own: &binbun_loader::Slice) {
        let Ok(slices) = binbun_loader::slices(file) else {
            return;
        };
        // `fat_arch_64`s after FAT_MAGIC_64's header, else `fat_arch`s;
        // big-endian.
        let entry = if file.get(..4) == Some(&[0xca, 0xfe, 0xba, 0xbf][..]) {
            32
        } else {
            20
        };
        let count = u64::try_from(slices.len()).unwrap_or(u64::MAX);
        self.parts.push(Part {
            file: 0..count
                .saturating_mul(entry)
                .saturating_add(8)
                .min(self.file_len),
            kind: Kind::Header,
            name: "Universal header".to_owned(),
        });
        for slice in slices.iter().filter(|slice| *slice != own) {
            let start = slice.offset.min(self.file_len);
            let end = slice.offset.saturating_add(slice.size).min(self.file_len);
            if start < end {
                self.parts.push(Part {
                    file: start..end,
                    kind: Kind::Section,
                    name: format!("{} slice", slice.arch),
                });
            }
        }
    }

    /// Whether multi-byte values are little-endian.
    pub fn little(&self) -> bool {
        self.little
    }

    /// The image's data model (pointer and `long` widths).
    pub fn model(&self) -> DataModel {
        self.model
    }

    /// The file's length.
    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    /// The parts of the file: headers, tables, sections.
    pub fn parts(&self) -> &[Part] {
        &self.parts
    }

    /// The overlays of the file's headers.
    pub fn headers(&self) -> &[Overlay] {
        &self.headers
    }

    /// The address file offset `offset` is loaded at.
    pub fn to_address(&self, offset: u64) -> Option<u64> {
        let i = self
            .regions
            .partition_point(|r| r.file.start <= offset)
            .checked_sub(1)?;
        // Regions may nest (PE's headers): the latest start first.
        self.regions.get(..=i)?.iter().rev().find_map(|r| {
            r.file
                .contains(&offset)
                .then(|| r.address + (offset - r.file.start))
        })
    }

    /// The file offset of `address`'s byte, if the file supplies it.
    pub fn to_file(&self, address: u64) -> Option<u64> {
        let i = self
            .by_address
            .partition_point(|&i| self.regions.get(i).is_some_and(|r| r.address <= address))
            .checked_sub(1)?;
        self.by_address.get(..=i)?.iter().rev().find_map(|&i| {
            let r = self.regions.get(i)?;
            let offset = r.file.start + (address - r.address);
            (address >= r.address && offset < r.file.end).then_some(offset)
        })
    }

    /// Position `at` of `from` in `to` (`None`: it has none there).
    pub fn convert(&self, at: u64, from: Mode, to: Mode) -> Option<u64> {
        match (from, to) {
            (Mode::Address, Mode::Address) | (Mode::File, Mode::File) => Some(at),
            (Mode::Address, Mode::File) => self.to_file(at),
            (Mode::File, Mode::Address) => self.to_address(at),
        }
    }

    /// The address of position `at` in `mode`.
    pub fn address_of(&self, at: u64, mode: Mode) -> Option<u64> {
        self.convert(at, mode, Mode::Address)
            .filter(|&a| self.segment(a).is_some())
    }

    /// An anchor's position in `mode`.
    pub fn place(&self, anchor: Anchor, mode: Mode) -> Option<u64> {
        match anchor {
            Anchor::File(at) => self.convert(at, Mode::File, mode),
            Anchor::Address(at) => self.convert(at, Mode::Address, mode),
        }
    }

    /// The segment holding `address`: its range and the bytes the file
    /// supplies.
    fn segment(&self, address: u64) -> Option<&(Range<u64>, u64)> {
        let i = self
            .segments
            .partition_point(|(r, _)| r.start <= address)
            .checked_sub(1)?;
        self.segments.get(i).filter(|(r, _)| r.contains(&address))
    }

    /// The section holding `address`.
    pub fn section(&self, address: u64) -> Option<&str> {
        let i = self
            .sections
            .partition_point(|(r, _)| r.start <= address)
            .checked_sub(1)?;
        self.sections
            .get(i)
            .filter(|(r, _)| r.contains(&address))
            .map(|(_, name)| name.as_str())
    }

    /// The part of the file holding `offset` (the innermost).
    pub fn part(&self, offset: u64) -> Option<&Part> {
        self.parts
            .iter()
            .filter(|p| p.file.contains(&offset))
            .min_by_key(|p| p.file.end - p.file.start)
    }

    /// How many rows `mode` has.
    pub fn rows(&self, mode: Mode) -> u64 {
        match mode {
            Mode::File => self.file_len.div_ceil(ROW),
            Mode::Address => self
                .blocks
                .last()
                .map_or(0, |b| b.first_row + (b.end - b.start) / ROW),
        }
    }

    /// The address space's blocks in address order: the segments rounded
    /// out to whole rows, those sharing a row joined. Address mode's rows
    /// are these laid end to end (the gaps between them skipped).
    pub fn blocks(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.blocks.iter().map(|b| b.start..b.end)
    }

    /// The first position of row `row` of `mode`.
    pub fn row_start(&self, mode: Mode, row: u64) -> Option<u64> {
        match mode {
            Mode::File => (row < self.rows(mode)).then(|| row * ROW),
            Mode::Address => {
                let i = self
                    .blocks
                    .partition_point(|b| b.first_row <= row)
                    .checked_sub(1)?;
                let b = self.blocks.get(i)?;
                let at = b.start + (row - b.first_row) * ROW;
                (at < b.end).then_some(at)
            }
        }
    }

    /// The row of position `at` of `mode`, else the nearest row after it.
    pub fn row_of(&self, mode: Mode, at: u64) -> u64 {
        match mode {
            Mode::File => (at / ROW).min(self.rows(mode).saturating_sub(1)),
            Mode::Address => {
                let i = self.blocks.partition_point(|b| b.start <= at);
                match i.checked_sub(1).and_then(|i| self.blocks.get(i)) {
                    Some(b) if at < b.end => b.first_row + (at - b.start) / ROW,
                    _ => self
                        .blocks
                        .get(i)
                        .map_or(self.rows(mode).saturating_sub(1), |b| b.first_row),
                }
            }
        }
    }

    /// The first and past the last position of `mode` holding a byte.
    pub fn bounds(&self, mode: Mode) -> Range<u64> {
        match mode {
            Mode::File => 0..self.file_len,
            Mode::Address => {
                let start = self.segments.first().map_or(0, |(r, _)| r.start);
                let end = self.segments.last().map_or(0, |(r, _)| r.end);
                start..end
            }
        }
    }

    /// Whether position `at` of `mode` holds a byte (or an uninitialised
    /// one).
    pub fn holds(&self, mode: Mode, at: u64) -> bool {
        match mode {
            Mode::File => at < self.file_len,
            Mode::Address => self.segment(at).is_some(),
        }
    }

    /// Position `at` of `mode` moved `delta` bytes through its rows (a
    /// row's bytes, then the next row's: gaps between segments are
    /// skipped), clamped to the first and last row.
    pub fn step(&self, mode: Mode, at: u64, delta: i64) -> u64 {
        let total = self.rows(mode) * ROW;
        if total == 0 {
            return at;
        }
        let row = self.row_of(mode, at);
        let start = self.row_start(mode, row).unwrap_or(at);
        let index = row * ROW + at.saturating_sub(start).min(ROW - 1);
        let to = index.saturating_add_signed(delta).min(total - 1);
        self.row_start(mode, to / ROW).map_or(at, |s| s + to % ROW)
    }

    /// The first and last positions of `mode`'s rows.
    pub fn ends(&self, mode: Mode) -> (u64, u64) {
        let rows = self.rows(mode);
        let first = self.row_start(mode, 0).unwrap_or(0);
        let last = rows
            .checked_sub(1)
            .and_then(|r| self.row_start(mode, r))
            .map_or(first, |s| s + ROW - 1);
        (first, last)
    }

    /// A row's prefix: its address or file offset, zero-padded to the
    /// space's widest (the breadcrumb names the section).
    pub fn prefix(&self, mode: Mode, at: u64) -> String {
        let digits = self.digits(mode);
        format!("{at:0digits$X}")
    }

    /// The widest prefix of `mode`, in characters.
    pub fn prefix_width(&self, mode: Mode) -> usize {
        self.digits(mode)
    }

    /// Hex digits of `mode`'s positions (at least 4).
    fn digits(&self, mode: Mode) -> usize {
        let end = self.bounds(mode).end.saturating_sub(1).max(1);
        let bits = 64 - end.leading_zeros();
        usize::try_from(bits.div_ceil(4)).unwrap_or(16).max(4)
    }

    /// The value of the byte at position `at` of `mode`.
    pub fn byte(&self, file: &[u8], mode: Mode, at: u64) -> Option<u8> {
        let offset = match mode {
            Mode::File => at,
            Mode::Address => self.to_file(at)?,
        };
        file.get(usize::try_from(offset).ok()?).copied()
    }

    /// The bytes of `range` in `mode` that are there, from its start (up
    /// to the first missing one).
    pub fn read(&self, file: &[u8], mode: Mode, range: Range<u64>) -> Vec<u8> {
        range.map_while(|at| self.byte(file, mode, at)).collect()
    }

    /// The cells of `range` in `mode`: each byte's value and partition,
    /// from `file`'s bytes and `listing`'s items.
    #[expect(clippy::too_many_lines, reason = "the layers, in order")]
    pub fn cells(
        &self,
        file: &[u8],
        listing: Option<&binbun::listing::Listing>,
        mode: Mode,
        range: Range<u64>,
    ) -> Vec<Cell> {
        let len = usize::try_from(range.end.saturating_sub(range.start)).unwrap_or(0);
        // Each position's file offset, address, and the winning layer's
        // strength.
        let mut offsets: Vec<Option<u64>> = Vec::with_capacity(len);
        let mut addresses: Vec<Option<u64>> = Vec::with_capacity(len);
        let mut cells: Vec<Cell> = Vec::with_capacity(len);
        let mut strength: Vec<u8> = vec![0; len];
        for at in range {
            let (offset, address, cell) = match mode {
                Mode::File => {
                    let value = file.get(usize::try_from(at).unwrap_or(usize::MAX)).copied();
                    let kind = match value {
                        None => Kind::Gap,
                        Some(0) => Kind::Padding,
                        Some(_) => Kind::Other,
                    };
                    let address = self.to_address(at);
                    (
                        value.map(|_| at),
                        address,
                        Cell {
                            value,
                            kind,
                            start: false,
                        },
                    )
                }
                Mode::Address => {
                    let offset = self.to_file(at);
                    let value = offset
                        .and_then(|o| file.get(usize::try_from(o).ok()?))
                        .copied();
                    let kind = match (self.segment(at), value) {
                        (None, _) => Kind::Gap,
                        (Some(_), None) => Kind::Uninitialised,
                        (Some(_), Some(_)) => Kind::Unexplored,
                    };
                    let address = (kind != Kind::Gap).then_some(at);
                    (
                        offset,
                        address,
                        Cell {
                            value,
                            kind,
                            start: false,
                        },
                    )
                }
            };
            offsets.push(offset);
            addresses.push(address);
            cells.push(cell);
        }
        let mut paint = |i: usize, kind: Kind, power: u8, start: bool| {
            if let (Some(cell), Some(s)) = (cells.get_mut(i), strength.get_mut(i))
                && power >= *s
            {
                cell.start = start || (power == *s && cell.start);
                cell.kind = kind;
                *s = power;
            }
        };
        // The file's parts, by file offset.
        for part in &self.parts {
            let power = match part.kind {
                Kind::Header => 100,
                Kind::Table => 90,
                Kind::String | Kind::Relocation => 50,
                Kind::Code
                | Kind::LooseCode
                | Kind::Pointer
                | Kind::Import
                | Kind::Value
                | Kind::Padding
                | Kind::Section
                | Kind::Unexplored
                | Kind::Other
                | Kind::Uninitialised
                | Kind::Gap => 10,
            };
            for (i, offset) in offsets.iter().enumerate() {
                if let Some(o) = *offset
                    && part.file.contains(&o)
                {
                    let kind = if part.kind == Kind::Section && mode == Mode::Address {
                        Kind::Unexplored
                    } else {
                        part.kind
                    };
                    paint(i, kind, power, o == part.file.start);
                }
            }
        }
        // The listing's items, by address: over each run of consecutive
        // addresses.
        if let Some(listing) = listing {
            let mut i = 0;
            while i < len {
                let Some(first) = addresses.get(i).copied().flatten() else {
                    i += 1;
                    continue;
                };
                let mut n = 1;
                while addresses.get(i + n).copied().flatten() == Some(first + n as u64) {
                    n += 1;
                }
                for span in listing.spans(first..first + n as u64) {
                    let (kind, power) = span_kind(&span);
                    let from = span.start.max(first);
                    let to = span.end.min(first + n as u64);
                    for a in from..to {
                        paint(
                            i + usize::try_from(a - first).unwrap_or(0),
                            kind,
                            power,
                            a == span.start,
                        );
                    }
                }
                i += n;
            }
        }
        // The loader's slots.
        for (i, address) in addresses.iter().enumerate() {
            let Some(a) = *address else { continue };
            let k = self.fixups.partition_point(|f| f.end <= a);
            if let Some(fixup) = self.fixups.get(k).filter(|f| f.contains(&a)) {
                paint(i, Kind::Relocation, 45, a == fixup.start);
            }
        }
        cells
    }

    /// The runs of `range` of `mode` whose positions are consecutive in
    /// `space` too: each run's first position and length, and its first
    /// position in `space`.
    fn runs(&self, mode: Mode, range: Range<u64>, space: Mode) -> Vec<(u64, u64, u64)> {
        let mut runs: Vec<(u64, u64, u64)> = Vec::new();
        for at in range {
            let Some(there) = self.convert(at, mode, space) else {
                continue;
            };
            match runs.last_mut() {
                Some((start, len, from)) if *start + *len == at && *from + *len == there => {
                    *len += 1;
                }
                _ => runs.push((at, 1, there)),
            }
        }
        runs
    }

    /// The leaves of `overlays` over `range` of `mode`, each cut to the
    /// bytes it has there, by position.
    pub fn placed(&self, overlays: &[Overlay], mode: Mode, range: Range<u64>) -> Vec<Placed> {
        let [by_address, by_file] =
            [Mode::Address, Mode::File].map(|space| self.runs(mode, range.clone(), space));
        let mut out = Vec::new();
        for (index, overlay) in overlays.iter().enumerate() {
            let (space, base) = overlay.anchor.place();
            let runs = match space {
                Mode::Address => &by_address,
                Mode::File => &by_file,
            };
            let size = overlay.layout.size;
            for &(at, len, there) in runs {
                if there >= base + size || there + len <= base {
                    continue;
                }
                let from = there.saturating_sub(base);
                let to = (there + len - base).min(size);
                for leaf in overlay.layout.leaves_in(from..to) {
                    let start = leaf.start.max(from);
                    let end = leaf.end.min(to);
                    out.push(Placed {
                        start: at + (base + start - there),
                        end: at + (base + end - there),
                        offset: leaf.start,
                        size: leaf.end - leaf.start,
                        path: leaf.path,
                        overlay: index,
                        ordinal: leaf.ordinal,
                    });
                }
            }
        }
        out.sort_by_key(|p| (p.start, p.overlay));
        out
    }

    /// Where position `at` of `mode` is in `overlay`: its byte from the
    /// overlay's start, if the byte is the overlay's.
    pub fn locate(&self, overlay: &Overlay, mode: Mode, at: u64) -> Option<u64> {
        let (space, base) = overlay.anchor.place();
        let there = self.convert(at, mode, space)?;
        let offset = there.checked_sub(base)?;
        overlay.layout.holds(offset).then_some(offset)
    }

    /// The position in `mode` of byte `offset` of `overlay`.
    pub fn position(&self, overlay: &Overlay, mode: Mode, offset: u64) -> Option<u64> {
        let (space, base) = overlay.anchor.place();
        self.convert(base.checked_add(offset)?, space, mode)
    }

    /// The image summarised in `buckets` equal parts of `mode`'s rows:
    /// each part's most common kind (gaps aside) and its bytes' entropy
    /// (0–1).
    pub fn overview(
        &self,
        file: &[u8],
        listing: Option<&binbun::listing::Listing>,
        mode: Mode,
        buckets: usize,
    ) -> Vec<(Kind, f32)> {
        let rows = self.rows(mode);
        if rows == 0 || buckets == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(buckets);
        for part in 0..buckets {
            let mut counts = [0u64; Kind::ALL.len()];
            let mut histogram = [0u64; 256];
            let mut total = 0u64;
            for start in self.part_rows(mode, buckets, part) {
                for cell in self.cells(file, listing, mode, start..start + ROW) {
                    if let Some(slot) = Kind::ALL
                        .iter()
                        .position(|&k| k == cell.kind)
                        .and_then(|k| counts.get_mut(k))
                    {
                        *slot += 1;
                    }
                    if let Some(v) = cell.value
                        && let Some(h) = histogram.get_mut(usize::from(v))
                    {
                        *h += 1;
                        total += 1;
                    }
                }
            }
            let kind = Kind::ALL
                .iter()
                .zip(counts)
                .filter(|(k, _)| **k != Kind::Gap)
                .max_by_key(|(_, n)| *n)
                .filter(|(_, n)| *n > 0)
                .map_or(Kind::Gap, |(k, _)| *k);
            out.push((kind, entropy(&histogram, total)));
        }
        out
    }

    /// Where the rows of part `part` of `buckets` equal parts of `mode`'s
    /// rows start that [`Self::overview`] reads: every n-th from its
    /// first, n its rows over 64 (64 to 127 of a long part, enough for
    /// its kind; each of a short one).
    pub fn part_rows(
        &self,
        mode: Mode,
        buckets: usize,
        part: usize,
    ) -> impl Iterator<Item = u64> + '_ {
        let rows = self.rows(mode);
        let (part, buckets) = (part as u64, (buckets as u64).max(1));
        let first = part * rows / buckets;
        let last = ((part + 1) * rows / buckets).max(first + 1).min(rows);
        let step = usize::try_from((last.saturating_sub(first) / 64).max(1)).unwrap_or(usize::MAX);
        (first..last)
            .step_by(step)
            .filter_map(move |row| self.row_start(mode, row))
    }
}

/// The file's headers and tables (`members`, at their file offsets) as
/// one overlay named `name` at offset 0, its parts named by `labels`.
fn file_overlay(name: &str, members: Vec<Node>, labels: Vec<(Range<u64>, String)>) -> Overlay {
    let size = members.iter().map(|m| m.offset + m.size).max().unwrap_or(0);
    let root = Node::new(
        String::new(),
        String::new(),
        0,
        size,
        Shape::Record {
            union: false,
            members,
        },
    );
    Overlay {
        anchor: Anchor::File(0),
        layout: Arc::new(Layout {
            name: String::new(),
            size,
            sparse: true,
            root,
        }),
        source: Source::Header,
        name: name.to_owned(),
        text: None,
        labels,
    }
}

/// The 16-byte name (`segname`, `sectname`) at `offset` of `file`: up to
/// its first zero byte.
fn macho_name(file: &[u8], offset: u64) -> String {
    let Some(bytes) = usize::try_from(offset)
        .ok()
        .and_then(|start| file.get(start..start.checked_add(16)?))
    else {
        return String::new();
    };
    let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned()
}

/// The Shannon entropy of a byte histogram, 0–1 (8 bits a byte is 1).
#[expect(clippy::cast_precision_loss, reason = "a ratio")]
pub fn entropy(histogram: &[u64; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    let bits: f64 = histogram
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum();
    #[expect(clippy::cast_possible_truncation, reason = "0–1")]
    let e = (bits / 8.0) as f32;
    e
}

/// A listing span's kind and strength.
fn span_kind(span: &Span) -> (Kind, u8) {
    match span.kind {
        SpanKind::Instruction { function: true } => (Kind::Code, 60),
        SpanKind::Instruction { function: false } => (Kind::LooseCode, 60),
        SpanKind::String { .. } => (Kind::String, 60),
        SpanKind::Pointer { .. } => (Kind::Pointer, 60),
        SpanKind::Import => (Kind::Import, 60),
        SpanKind::Table => (Kind::Value, 60),
        SpanKind::Align | SpanKind::Fill { .. } => (Kind::Padding, 55),
        SpanKind::Uninitialised => (Kind::Uninitialised, 60),
        SpanKind::Scalar { .. } | SpanKind::Values { .. } => (Kind::Value, 40),
        SpanKind::Unexplored => (Kind::Unexplored, 20),
    }
}

/// Where a data row's parts are, in characters: the
/// prefix, two spaces, 16 bytes of two digits each a space apart with a
/// second space after the eighth, two spaces, the 16 characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Columns {
    /// The prefix's width.
    pub prefix: usize,
}

impl Columns {
    /// The first column of byte `i`'s digits.
    pub fn hex(self, i: u64) -> usize {
        let i = usize::try_from(i.min(ROW - 1)).unwrap_or(0);
        self.prefix + 2 + 3 * i + usize::from(i >= 8)
    }

    /// The column of byte `i`'s character.
    pub fn text(self, i: u64) -> usize {
        self.prefix + 52 + usize::try_from(i.min(ROW - 1)).unwrap_or(0)
    }

    /// The row's width.
    pub fn width(self) -> usize {
        self.prefix + 68
    }

    /// The byte at column `col` and whether in the characters; `None` in
    /// the prefix. A space between bytes belongs to the byte before it.
    pub fn byte_at(self, col: usize) -> Option<(u64, bool)> {
        let c = col.checked_sub(self.prefix + 2)?;
        if c + 1 >= 50 {
            return Some(((c.saturating_sub(50) as u64).min(ROW - 1), true));
        }
        let i = if c < 24 { c / 3 } else { (c - 1) / 3 };
        Some(((i as u64).min(ROW - 1), false))
    }
}

/// The hex view of a pane: on or off, its space, the cursor and the
/// selection, the scrolling, and its side area (the structure tree over
/// the data inspector, right of or under the bytes): shown or hidden, its
/// share under the bytes, the tree's state.
#[derive(Debug, Default)]
#[expect(clippy::struct_excessive_bools, reason = "independent toggles")]
pub struct HexPane {
    /// The pane shows the hex view (else its listing).
    pub on: bool,
    /// The space shown.
    pub mode: Mode,
    /// The cursor: the selection's moving end.
    pub cursor: u64,
    /// The selection's fixed end (none: the cursor's byte alone).
    pub anchor: Option<u64>,
    /// The scrolling over the rows.
    pub scroll: Scroller,
    /// The rows' sideways scrolling.
    pub side: Sideways,
    /// The listing line the cursor last followed or set.
    pub followed: Option<u64>,
    /// An address the cursor goes to when next drawn (another view moved
    /// the shared cursor), and whether as a jump.
    pub target: Option<(u64, bool)>,
    /// The pane showed the graph before the hex view.
    pub graph: bool,
    /// The cursor is in the text column.
    pub text: bool,
    /// A drag selects.
    pub dragging: bool,
    /// The overview shows entropy (else kinds).
    pub entropy: bool,
    /// The overview is being dragged.
    pub overview_drag: bool,
    /// The user hid the side area.
    pub side_hidden: bool,
    /// The side area's share of the pane's height while under the bytes.
    pub side_split: SideSplit,
    /// The structure tree: what is expanded and selected.
    pub tree: StructTree,
    /// The tree's first line shown.
    pub tree_top: usize,
}

/// Where a hex pane's side area goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidePlace {
    /// Right of the bytes: the pane is wide enough for both.
    Beside,
    /// Under the bytes, in a split whose divider drags.
    Under,
    /// Hidden by its toolbar toggle.
    Hidden,
}

/// The side area's share of a hex pane's height while it is under the
/// bytes: a half until its divider is dragged.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SideSplit(f32);

impl Default for SideSplit {
    fn default() -> Self {
        Self(0.5)
    }
}

impl SideSplit {
    /// A share as saved; the default unless strictly between 0 and 1.
    pub fn new(share: f32) -> Self {
        if share > 0.0 && share < 1.0 {
            Self(share)
        } else {
            Self::default()
        }
    }

    /// The side area's share of the pane's height.
    pub fn share(self) -> f32 {
        self.0
    }

    /// Follows the divider dragged to `at` from the top of a pane `height`
    /// high: the bytes above it and the side area under it each kept at
    /// least `min` high; nothing changes if they cannot both be. Returns
    /// whether the share changed.
    pub fn drag(&mut self, at: f32, height: f32, min: f32) -> bool {
        if height <= 0.0 || !at.is_finite() || height < 2.0 * min {
            return false;
        }
        let side = (height - at).clamp(min, height - min) / height;
        let changed = (side - self.0).abs() > f32::EPSILON;
        self.0 = side;
        changed
    }
}

impl HexPane {
    /// Where the side area goes in a pane `width` wide whose bytes need
    /// `bytes` beside a side area `side` wide: hidden only by its toggle;
    /// right of the bytes with room for both, else under them.
    pub fn side_place(&self, width: f32, bytes: f32, side: f32) -> SidePlace {
        if self.side_hidden {
            SidePlace::Hidden
        } else if width >= bytes + side {
            SidePlace::Beside
        } else {
            SidePlace::Under
        }
    }

    /// The selection: the bytes between the anchor and the cursor, both
    /// included.
    pub fn selection(&self) -> Range<u64> {
        let anchor = self.anchor.unwrap_or(self.cursor);
        anchor.min(self.cursor)..anchor.max(self.cursor) + 1
    }

    /// Moves the cursor to `at`, extending the selection if `extend`.
    pub fn select(&mut self, at: u64, extend: bool) {
        if extend {
            if self.anchor.is_none() {
                self.anchor = Some(self.cursor);
            }
        } else {
            self.anchor = None;
        }
        self.cursor = at;
    }

    /// Switches to `mode`, the cursor and selection converted (kept where
    /// they have no place there).
    pub fn switch(&mut self, image: &HexImage, mode: Mode) {
        if mode == self.mode {
            return;
        }
        let convert = |at: u64| image.convert(at, self.mode, mode);
        if let Some(cursor) = convert(self.cursor) {
            self.cursor = cursor;
            self.anchor = self.anchor.and_then(convert);
        } else {
            self.cursor = image.bounds(mode).start;
            self.anchor = None;
        }
        self.mode = mode;
        self.followed = None;
    }
}

/// How the selection is copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CopyFormat {
    /// `48 89 E5`.
    Hex,
    /// A C string literal of the bytes: `"\x48\x89\xE5"`.
    Bytes,
    /// A C array: `unsigned char data[3] = { 0x48, 0x89, 0xE5 };`.
    CArray,
}

/// `bytes` as `format`.
pub fn copy_text(bytes: &[u8], format: CopyFormat) -> String {
    let mut out = String::with_capacity(bytes.len() * 6 + 32);
    match format {
        CopyFormat::Hex => {
            for (i, b) in bytes.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                let _ = write!(out, "{b:02X}");
            }
        }
        CopyFormat::Bytes => {
            out.push('"');
            for b in bytes {
                let _ = write!(out, "\\x{b:02X}");
            }
            out.push('"');
        }
        CopyFormat::CArray => {
            let _ = write!(out, "unsigned char data[{}] = {{", bytes.len());
            for (i, b) in bytes.iter().enumerate() {
                out.push_str(if i % 12 == 0 { "\n    " } else { " " });
                let _ = write!(out, "0x{b:02X},");
            }
            out.push_str("\n};");
        }
    }
    out
}

/// The overlays of the debug information's typed globals.
pub fn debug_overlays(debug: &DebugModel) -> Vec<Overlay> {
    debug
        .globals
        .iter()
        .filter_map(|(&address, global)| {
            let layout = hex_types::from_debug(debug, global.ty)?;
            Some(Overlay {
                anchor: Anchor::Address(address),
                layout: Arc::new(layout),
                source: Source::Debug,
                name: global.name.clone(),
                text: None,
                labels: Vec::new(),
            })
        })
        .collect()
}

/// Saves `overlays` (the user's) to `path`, crash-safely.
///
/// # Errors
///
/// It cannot be written.
pub fn save_overlays(path: &Path, overlays: &[Overlay]) -> Result<(), String> {
    let mut doc = toml_edit::DocumentMut::new();
    let mut array = toml_edit::ArrayOfTables::new();
    for overlay in overlays.iter().filter(|o| o.source == Source::User) {
        let mut table = toml_edit::Table::new();
        let (key, at) = match overlay.anchor {
            Anchor::Address(a) => ("address", a),
            Anchor::File(o) => ("offset", o),
        };
        table.insert(key, toml_edit::value(format!("0x{at:X}")));
        table.insert(
            "type",
            toml_edit::value(
                overlay
                    .text
                    .clone()
                    .unwrap_or_else(|| overlay.layout.name.clone()),
            ),
        );
        array.push(table);
    }
    doc.insert("overlay", toml_edit::Item::ArrayOfTables(array));
    crash_safe::write(path, doc.to_string().as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The user's overlays saved at `path`, laid out with `types` (their C
/// defined there again); what does not parse is skipped. None if there is
/// no file.
///
/// # Errors
///
/// The file is there but cannot be read or is not TOML.
pub fn load_overlays(path: &Path, types: &mut TypeSet) -> Result<Vec<Overlay>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    let Some(tables) = doc
        .get("overlay")
        .and_then(toml_edit::Item::as_array_of_tables)
    else {
        return Ok(out);
    };
    for table in tables {
        let number = |key: &str| {
            let text = table.get(key)?.as_str()?;
            u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
        };
        let anchor = match (number("address"), number("offset")) {
            (Some(a), _) => Anchor::Address(a),
            (None, Some(o)) => Anchor::File(o),
            (None, None) => continue,
        };
        let Some(text) = table.get("type").and_then(toml_edit::Item::as_str) else {
            continue;
        };
        let Ok(layout) = types.apply(text) else {
            continue;
        };
        out.push(user_overlay(anchor, layout, text));
    }
    Ok(out)
}

/// A user's overlay of `layout` (from `text`) at `anchor`.
pub fn user_overlay(anchor: Anchor, layout: Arc<Layout>, text: &str) -> Overlay {
    Overlay {
        anchor,
        name: layout.name.clone(),
        layout,
        source: Source::User,
        text: Some(text.trim().to_owned()),
        labels: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests fail loudly"
    )]

    use binbun::Database;
    use binbun::analysis::Seeds;

    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read(&path).unwrap()
    }

    #[test]
    fn an_elf_file_is_partitioned_by_its_headers_and_the_listing() {
        let data = fixture("program-x86_64.elf");
        let image = Image::parse(&data).unwrap();
        let db = Database::new(&image, Seeds::ALL).unwrap();
        let listing = binbun::listing::Listing::build(&db, &binbun::listing::Options::default());
        let hex = HexImage::new(&data, &image);
        // The ELF header, then the program headers, in the file.
        let head = hex.cells(&data, Some(&listing), Mode::File, 0..0x48);
        assert!(head[..0x40].iter().all(|c| c.kind == Kind::Header));
        assert!(head[0].start && head[0].value == Some(0x7f));
        assert_eq!(head[0x40].kind, Kind::Table);
        assert!(head[0x40].start);
        // `checked` at 11D0: its instructions start where they do
        // (`sub rsp, 8` is 4 bytes, `test edi, edi` 2), in either space.
        let offset = hex.to_file(0x11d0).unwrap();
        assert_eq!(hex.to_address(offset), Some(0x11d0));
        for (mode, at) in [(Mode::Address, 0x11d0), (Mode::File, offset)] {
            let code = hex.cells(&data, Some(&listing), mode, at..at + 8);
            assert!(code.iter().all(|c| c.kind == Kind::Code), "{mode:?}");
            let starts: Vec<usize> = (0..8).filter(|&i| code[i].start).collect();
            assert_eq!(starts, [0, 4, 6], "{mode:?}");
            assert_eq!(code[0].value, Some(data[usize::try_from(offset).unwrap()]));
        }
        // The section headers at the end of the file are mapped nowhere.
        let shoff = hex
            .parts()
            .iter()
            .find(|p| p.name == "Section headers")
            .unwrap()
            .file
            .start;
        assert_eq!(hex.to_address(shoff), None);
        assert_eq!(
            hex.cells(&data, None, Mode::File, shoff..shoff + 1)[0].kind,
            Kind::Table
        );
        // A string's bytes, by the listing.
        let rodata = image.sections.iter().find(|s| s.name == ".rodata").unwrap();
        let strings: Vec<Cell> = hex.cells(
            &data,
            Some(&listing),
            Mode::Address,
            rodata.start..rodata.start + rodata.size,
        );
        assert!(strings.iter().any(|c| c.kind == Kind::String));
        // Every row of the address space starts at a mapped row.
        for row in 0..hex.rows(Mode::Address) {
            let start = hex.row_start(Mode::Address, row).unwrap();
            assert_eq!(hex.row_of(Mode::Address, start), row);
            assert_eq!(start % ROW, 0);
        }
        // Stepping crosses from one segment's last row to the next
        // segment's first, and stops at the ends.
        let (first, last) = hex.ends(Mode::Address);
        assert_eq!(hex.step(Mode::Address, first, -1), first);
        assert_eq!(hex.step(Mode::Address, last, 16), last);
        let second = image.segments[1].start / ROW * ROW;
        let end_of_first = image.segments[0].end().div_ceil(ROW) * ROW - 1;
        assert!(
            second > end_of_first + 1,
            "the fixture's segments leave a gap"
        );
        assert_eq!(hex.step(Mode::Address, end_of_first, 1), second);
        assert_eq!(hex.step(Mode::Address, second, -1), end_of_first);
        assert_eq!(hex.step(Mode::Address, second + 3, -16), end_of_first - 12);
        assert_eq!(hex.prefix(Mode::Address, 0x11d0), "11D0");
        assert_eq!(hex.prefix(Mode::Address, 0x40), "0040");
    }

    /// The rows an overview's part reads (the feature map judges a part
    /// library code on them): its own, evenly spread from its first, 64
    /// to 127 of a long part; with more parts than rows, each part one
    /// row and every row some part's.
    #[test]
    fn an_overview_part_reads_its_own_rows_evenly_spread() {
        let data = fixture("program-x86_64.elf");
        let image = Image::parse(&data).unwrap();
        let hex = HexImage::new(&data, &image);
        let rows = hex.rows(Mode::Address);
        assert!(rows >= 3 * 64, "the fixture has {rows} rows");
        let read = |buckets: usize, part: usize| -> Vec<u64> {
            hex.part_rows(Mode::Address, buckets, part)
                .map(|start| hex.row_of(Mode::Address, start))
                .collect()
        };
        let whole = read(1, 0);
        let step = rows / 64;
        assert_eq!(whole.len() as u64, rows.div_ceil(step));
        assert!((64..128).contains(&whole.len()));
        assert_eq!(whole.first(), Some(&0));
        assert!(whole.windows(2).all(|w| w[1] - w[0] == step));
        // Three parts: each reads inside its third, from its first row.
        let mut seen = 0;
        for part in 0..3 {
            let (first, last) = (part * rows / 3, (part + 1) * rows / 3);
            let rows_read = read(3, usize::try_from(part).unwrap());
            assert!((64..128).contains(&rows_read.len()));
            assert_eq!(rows_read.first(), Some(&first));
            assert!(rows_read.iter().all(|r| (first..last).contains(r)));
            assert!(rows_read.iter().all(|&r| r >= seen));
            seen = last;
        }
        // More parts than rows: one row each, every row read.
        let parts = usize::try_from(rows * 2).unwrap();
        let mut all: Vec<u64> = (0..parts)
            .flat_map(|part| {
                let one = read(parts, part);
                assert_eq!(one.len(), 1, "part {part}");
                one
            })
            .collect();
        all.dedup();
        assert_eq!(all, (0..rows).collect::<Vec<_>>());
    }

    #[test]
    fn the_headers_and_tables_are_one_tree_placed_leaf_by_leaf() {
        let data = fixture("program-x86_64.elf");
        let image = Image::parse(&data).unwrap();
        let hex = HexImage::new(&data, &image);
        let headers = hex.headers();
        assert_eq!(headers.len(), 1);
        let elf = &headers[0];
        assert_eq!(elf.name, "ELF");
        let read = |path: &str| elf.layout.read(&data, path, true).unwrap();
        // The program headers are `Elf64_Phdr[e_phnum]` at `e_phoff`.
        let (phoff, phdr) = elf.layout.field("phdr").unwrap();
        assert_eq!(phoff, read("ehdr.e_phoff"));
        assert_eq!(phdr.ty, format!("Elf64_Phdr[{}]", read("ehdr.e_phnum")));
        assert_eq!(read("phdr[0].p_type"), 6, "PT_PHDR first");
        let (shoff, _) = elf.layout.field("shdr").unwrap();
        assert_eq!(shoff, read("ehdr.e_shoff"));
        // Each section header is labelled with its section's name.
        let text = (0..read("ehdr.e_shnum"))
            .map(|i| shoff + i * 64)
            .find(|&at| elf.label(&(at..at + 64)) == Some(".text"))
            .unwrap();
        assert_eq!(
            hex.part(read(&format!("shdr[{}].sh_offset", (text - shoff) / 64)))
                .unwrap()
                .name,
            ".text"
        );
        // Only the headers' and tables' bytes are the overlay's.
        assert_eq!(hex.locate(elf, Mode::File, 0x3f), Some(0x3f));
        assert_eq!(hex.locate(elf, Mode::File, shoff - 1), None);
        let placed = hex.placed(headers, Mode::File, 0..0x20);
        let leaves: Vec<(&str, u64)> = placed
            .iter()
            .map(|p| (p.path.as_str(), p.ordinal))
            .collect();
        assert_eq!(
            leaves,
            [
                ("ehdr.e_ident", 0),
                ("ehdr.e_type", 1),
                ("ehdr.e_machine", 2),
                ("ehdr.e_version", 3),
                ("ehdr.e_entry", 4)
            ]
        );
        assert_eq!((placed[4].start, placed[4].end), (0x18, 0x20));
        // In addresses: the program headers where the loader maps them, a
        // leaf cut at the range's end; the section headers nowhere.
        let at = hex.to_address(phoff).unwrap();
        let placed = hex.placed(headers, Mode::Address, at..at + 6);
        let leaves: Vec<(&str, u64, u64, u64, u64)> = placed
            .iter()
            .map(|p| (p.path.as_str(), p.start, p.end, p.offset, p.size))
            .collect();
        assert_eq!(
            leaves,
            [
                ("phdr[0].p_type", at, at + 4, phoff, 4),
                ("phdr[0].p_flags", at + 4, at + 6, phoff + 4, 4)
            ]
        );
        assert_eq!(hex.position(elf, Mode::Address, phoff), Some(at));
        assert_eq!(hex.position(elf, Mode::Address, shoff), None);
    }

    #[test]
    fn a_pe_file_maps_its_sections_at_the_image_base() {
        let data = fixture("program-x86_64.exe");
        let image = Image::parse(&data).unwrap();
        let hex = HexImage::new(&data, &image);
        let pe = &hex.headers()[0];
        assert_eq!(pe.name, "PE");
        let nt = pe.layout.read(&data, "dos.e_lfanew", true).unwrap();
        assert_eq!(pe.layout.field("nt").map(|(at, _)| at), Some(nt));
        assert_eq!(pe.layout.read(&data, "nt.Signature", true), Some(0x4550));
        let (table, sections) = pe.layout.field("sections").unwrap();
        assert_eq!(sections.size, 40 * image.sections.len() as u64);
        assert!(pe.label(&(table..table + 40)).is_some());
        let text = image.sections.iter().find(|s| s.name == ".text").unwrap();
        let offset = hex.to_file(text.start).unwrap();
        assert_eq!(hex.to_address(offset), Some(text.start));
        assert_eq!(hex.part(offset).unwrap().name, ".text");
        assert_eq!(
            hex.byte(&data, Mode::Address, text.start),
            hex.byte(&data, Mode::File, offset)
        );
        // The headers are mapped at the image base.
        assert_eq!(hex.to_file(image.base), Some(0));
        assert_eq!(
            hex.cells(&data, None, Mode::Address, image.base..image.base + 2)[0].value,
            Some(b'M')
        );
    }

    /// Each slice of a universal file maps its segments from where the
    /// slice starts: its `__text` is where the address says, its header
    /// at its `__TEXT`'s address; the universal header and the other
    /// slices are parts of the file too.
    #[test]
    fn a_universal_slice_maps_its_segments_from_the_slices_start() {
        let data = fixture("program-universal.macho");
        for slice in binbun_loader::slices(&data).unwrap() {
            let image = Image::parse_arch(&data, Some(&slice.arch)).unwrap();
            let hex = HexImage::new(&data, &image);
            let macho = &hex.headers()[0];
            assert_eq!(macho.name, "Mach-O");
            assert_eq!(
                macho.layout.read(&data, "header.magic", true),
                Some(0xfeed_facf),
                "{}",
                slice.arch
            );
            assert_eq!(hex.part(0).unwrap().name, "Universal header");
            assert_eq!(hex.part(slice.offset).unwrap().name, "Mach-O header");
            let others: Vec<&str> = hex
                .parts()
                .iter()
                .filter_map(|p| p.name.strip_suffix(" slice"))
                .collect();
            assert_eq!(others.len(), 2, "{others:?}");
            assert!(!others.contains(&slice.arch.as_str()));
            let text = image
                .sections
                .iter()
                .find(|s| s.name == "__TEXT,__text")
                .unwrap();
            let offset = hex.to_file(text.start).unwrap();
            assert!(offset > slice.offset && offset < slice.offset + slice.size);
            assert_eq!(hex.to_address(offset), Some(text.start));
            assert_eq!(hex.part(offset).unwrap().name, "__TEXT,__text");
            assert_eq!(
                hex.byte(&data, Mode::Address, text.start),
                hex.byte(&data, Mode::File, offset)
            );
            assert_eq!(hex.to_file(image.base), Some(slice.offset));
        }
    }

    #[test]
    fn a_selection_spans_both_ends_and_switching_space_keeps_it() {
        let data = fixture("program-x86_64.elf");
        let image = Image::parse(&data).unwrap();
        let hex = HexImage::new(&data, &image);
        let mut pane = HexPane {
            cursor: 0x11d4,
            ..HexPane::default()
        };
        pane.select(0x11d0, true);
        assert_eq!(pane.selection(), 0x11d0..0x11d5);
        pane.switch(&hex, Mode::File);
        let offset = hex.to_file(0x11d0).unwrap();
        assert_eq!(pane.selection(), offset..offset + 5);
        pane.select(offset + 1, false);
        assert_eq!(pane.selection(), offset + 1..offset + 2);
    }

    #[test]
    fn the_side_area_goes_beside_or_under_and_hides_only_by_its_toggle() {
        let (bytes, side) = (700.0, 480.0);
        let mut pane = HexPane::default();
        // Room for both, exactly: beside; a pixel less: under the bytes,
        // at any narrower width; room again: beside.
        assert_eq!(pane.side_place(1180.0, bytes, side), SidePlace::Beside);
        assert_eq!(pane.side_place(1179.0, bytes, side), SidePlace::Under);
        assert_eq!(pane.side_place(300.0, bytes, side), SidePlace::Under);
        assert_eq!(pane.side_place(1600.0, bytes, side), SidePlace::Beside);
        // Hidden by the user: at any width, in this pane only.
        pane.side_hidden = true;
        assert_eq!(pane.side_place(4000.0, bytes, side), SidePlace::Hidden);
        assert_eq!(pane.side_place(300.0, bytes, side), SidePlace::Hidden);
        assert_eq!(
            HexPane::default().side_place(4000.0, bytes, side),
            SidePlace::Beside
        );
    }

    #[test]
    fn the_side_split_drags_within_its_minimum() {
        let mut split = SideSplit::default();
        assert!((split.share() - 0.5).abs() < 1e-6);
        // The divider 300 down a pane 1000 high: the side area takes 70%.
        assert!(split.drag(300.0, 1000.0, 100.0));
        assert!((split.share() - 0.7).abs() < 1e-6);
        // Each side kept 100 high.
        assert!(split.drag(20.0, 1000.0, 100.0));
        assert!((split.share() - 0.9).abs() < 1e-6);
        assert!(split.drag(990.0, 1000.0, 100.0));
        assert!((split.share() - 0.1).abs() < 1e-6);
        assert!(!split.drag(995.0, 1000.0, 100.0));
        // Too low a pane for both: unchanged.
        assert!(!split.drag(50.0, 150.0, 100.0));
        assert!((split.share() - 0.1).abs() < 1e-6);
        // A saved share outside (0, 1) is the default.
        assert!((SideSplit::new(0.25).share() - 0.25).abs() < 1e-6);
        assert_eq!(SideSplit::new(1.0), SideSplit::default());
        assert_eq!(SideSplit::new(f32::NAN), SideSplit::default());
    }

    #[test]
    fn bytes_copy_as_hex_a_string_or_a_c_array() {
        let bytes = [0x48, 0x89, 0xe5];
        assert_eq!(copy_text(&bytes, CopyFormat::Hex), "48 89 E5");
        assert_eq!(copy_text(&bytes, CopyFormat::Bytes), r#""\x48\x89\xE5""#);
        assert_eq!(
            copy_text(&bytes, CopyFormat::CArray),
            "unsigned char data[3] = {\n    0x48, 0x89, 0xE5,\n};"
        );
    }

    /// A row drawn as the columns say, read back by `byte_at`.
    #[test]
    fn columns_lay_out_a_row_and_find_the_byte_under_a_column() {
        let c = Columns { prefix: 10 };
        let mut row = " ".repeat(c.prefix + 2);
        for i in 0..16u8 {
            let _ = write!(row, "{i:02X}");
            row.push_str(match i {
                7 => "  ",
                15 => "",
                _ => " ",
            });
        }
        row.push_str("  ");
        row.push_str("abcdefghijklmnop");
        assert_eq!(row.len(), c.width());
        for i in 0..16u64 {
            assert_eq!(&row[c.hex(i)..c.hex(i) + 2], format!("{i:02X}"));
            assert_eq!(row.as_bytes()[c.text(i)], b'a' + u8::try_from(i).unwrap());
            assert_eq!(c.byte_at(c.hex(i)), Some((i, false)));
            assert_eq!(c.byte_at(c.hex(i) + 2), Some((i, false)), "the space after");
            assert_eq!(c.byte_at(c.text(i)), Some((i, true)));
        }
        assert_eq!(c.byte_at(c.hex(7) + 3), Some((7, false)), "the group's gap");
        assert_eq!(c.byte_at(c.prefix), None);
        assert_eq!(c.byte_at(c.width() + 9), Some((15, true)));
    }

    #[test]
    fn user_overlays_are_saved_and_read_back() {
        let dir = std::env::temp_dir().join(format!("binbun-hex-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = binbun_session::Project::new(&dir).overlays();
        let mut types = TypeSet::builtin(DataModel::LP64);
        let text = "struct pair { uint16_t tag; char *name; }";
        let overlays = vec![
            user_overlay(Anchor::Address(0x4010), types.apply(text).unwrap(), text),
            user_overlay(
                Anchor::File(0x40),
                types.apply("Elf64_Phdr").unwrap(),
                "Elf64_Phdr",
            ),
        ];
        save_overlays(&path, &overlays).unwrap();
        let mut fresh = TypeSet::builtin(DataModel::LP64);
        let back = load_overlays(&path, &mut fresh).unwrap();
        assert_eq!(back, overlays);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn entropy_is_zero_for_one_value_and_one_for_every_value_alike() {
        let mut one = [0u64; 256];
        one[7] = 100;
        assert!(entropy(&one, 100).abs() < 1e-6);
        let all = [4u64; 256];
        assert!((entropy(&all, 1024) - 1.0).abs() < 1e-6);
    }
}
