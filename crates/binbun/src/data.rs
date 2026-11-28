//! The image's data for lowering and printing (globals): the objects its
//! symbols and import slots name, the memory it maps as data and which of
//! it the program cannot change, and its strings ([`ImageData`]).
//!
//! - **Objects** are the data symbols with a size and the imports'
//!   pointer slots, each wholly inside the image's data sections; where
//!   two overlap (aliases, an object inside another), the first by
//!   address (the larger at one address) is the object.
//! - **Data** is what the image's mapped sections cover outside its code
//!   ([`Image::code`]: a Mach-O `__TEXT,__cstring`, the `.rodata` of an
//!   ELF file linked without `-z separate-code`, though their segment is
//!   executable): not the file's headers (which a position-independent
//!   image maps at address 0), nor addresses no section covers.
//! - **Read-only** is what [`ImageMemory`] calls unchanging: non-writable
//!   segments, and RELRO ranges once the dynamic loader has relocated
//!   them; the bytes known are those nothing relocates.
//! - **Names** are the symbols' (the first at an address), an import
//!   thunk's import, and an import slot's import with `_ptr` (the slot
//!   holds the import's address, it is not the import).
//! - **Position independence**: an image the dynamic loader may load
//!   anywhere ([`Image::position_independent`]) has no immediate in its
//!   code that is one of its addresses.
//!
//! The sections holding the program's own data, which strings and
//! pointers are looked for in, are [`program_data`].

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use binbun_decompile::data::{Data, Object};
use binbun_loader::{Image, Import, Section, SymbolKind};
use binbun_print::c::{Image as Printing, ThreadPointer, Unlifted};
use binbun_semantics::ir::RegisterId;
use binbun_ssa::constant::ReadOnly as _;

use crate::lift::{ImageEnvironment, disassemble, unlifted};
use crate::memory::ImageMemory;
use crate::target::{convention, thread_pointer};
use crate::user::data_model;

/// The longest string taken as one: its bytes before the NUL.
const MAX_STRING: u64 = 4096;

/// How many bytes [`ImageData`] reads at once ([`ImageMemory::plain`]).
const RUN: usize = 256;

/// The prefixes of the names of sections that hold what the dynamic
/// loader, the unwinder, the debugger or the operating system read about
/// the program, not the program's data: ELF symbol, version, relocation,
/// note, dynamic and unwind sections; PE unwind, relocation, import,
/// export and resource sections; Mach-O unwind sections; debugging
/// information. And `.tbss`, which takes no room in the image (its
/// address is the next section's).
const METADATA: [&str; 29] = [
    ".interp",
    ".note",
    ".hash",
    ".gnu.hash",
    ".dynsym",
    ".dynstr",
    ".gnu.version",
    ".rela.",
    ".rel.",
    ".relr.dyn",
    ".dynamic",
    ".eh_frame",
    ".gcc_except_table",
    ".sframe",
    ".stapsdt",
    ".symtab",
    ".strtab",
    ".debug",
    ".pdata",
    ".xdata",
    ".reloc",
    ".idata",
    ".didat",
    ".edata",
    ".rsrc",
    ".tbss",
    "__TEXT,__unwind_info",
    "__TEXT,__eh_frame",
    "__TEXT,__gcc_except_tab",
];

/// The sections of `image` holding the program's own data, sorted by
/// address: loaded (at an address other than 0, with a size), not code,
/// and not what the dynamic loader, the unwinder, the debugger or the
/// operating system read about the program (ELF symbol, version,
/// relocation, note, dynamic and unwind sections; PE unwind, relocation,
/// import, export and resource sections; Mach-O unwind sections;
/// debugging information), nor `.tbss`. Both read-only and writable ones.
pub fn program_data<'a>(image: &'a Image<'_>) -> Vec<&'a Section> {
    let mut sections: Vec<&Section> = image
        .sections
        .iter()
        .filter(|section| section.start != 0 && section.size != 0)
        .filter(|section| image.is_mapped(section.start) && !image.is_code(section.start))
        .filter(|section| {
            !METADATA
                .iter()
                .any(|prefix| section.name.starts_with(prefix))
        })
        .collect();
    sections.sort_by_key(|section| (section.start, section.size));
    sections
}

/// The image's data, for lowering ([`Data`]) and the printer
/// ([`binbun_print::c::Image`]).
#[derive(Debug)]
pub struct ImageData<'a> {
    /// The image (its instructions, for those without semantics).
    image: &'a Image<'a>,
    memory: ImageMemory<'a>,
    /// Whether the image is loaded at an address of the loader's choosing.
    relocatable: bool,
    /// The data sections (mapped, not code) and the data in code
    /// ([`crate::cfg::Program::data`]), sorted by start.
    sections: Vec<Range<u64>>,
    /// The data in code: start to end.
    code_data: BTreeMap<u64, u64>,
    /// The named objects, by first byte: size and whether read-only; not
    /// overlapping.
    objects: BTreeMap<u64, (u64, bool)>,
    /// The names of addresses.
    names: BTreeMap<u64, String>,
    /// The fixed imports' names, by slot ([`binbun_loader::Import::fixed`]);
    /// an import by ordinal (`#19`, no symbol to link to) is named by its
    /// module and ordinal (`WS2_32_ordinal_19`).
    fixed: BTreeMap<u64, String>,
    /// Every import's pointer slot.
    slots: BTreeSet<u64>,
    /// How C spells the platform's thread pointer.
    thread_pointer: ThreadPointer,
    /// The width of the platform's C `long`, in bits.
    long_width: u16,
    /// The register the convention keeps the thread pointer in.
    thread_register: Option<RegisterId>,
}

impl<'a> ImageData<'a> {
    /// The data of `image`, its addresses named by `names` (functions'
    /// and objects') and its import slots by their imports; its objects
    /// its data symbols with a size, its import slots and `objects` (start,
    /// size: debug information's globals), the first and largest at a
    /// start where they overlap; `code_data` (start to end) is data in its
    /// code ([`crate::cfg::Program::data`]: strings a compiler put there).
    pub fn new(
        image: &'a Image<'a>,
        mut names: BTreeMap<u64, String>,
        objects: &[(u64, u64)],
        code_data: &BTreeMap<u64, u64>,
    ) -> Self {
        let memory = ImageMemory::new(image);
        let mut sections: Vec<Range<u64>> = image
            .sections
            .iter()
            .filter(|section| section.start != 0 && section.size != 0)
            .filter(|section| image.is_mapped(section.start) && !image.is_code(section.start))
            .map(|section| section.start..section.start.saturating_add(section.size))
            .chain(code_data.iter().map(|(&start, &end)| start..end))
            .collect();
        sections.sort_by_key(|range| (range.start, range.end));
        for import in &image.imports {
            names
                .entry(import.slot)
                .or_insert_with(|| format!("{}_ptr", import.name));
        }
        let mut data = Self {
            image,
            memory,
            relocatable: image.position_independent,
            sections,
            code_data: code_data.clone(),
            objects: BTreeMap::new(),
            names,
            fixed: image
                .imports
                .iter()
                .filter(|import| import.fixed)
                .map(|import| (import.slot, import_name(import)))
                .collect(),
            slots: image.imports.iter().map(|import| import.slot).collect(),
            thread_pointer: thread_pointer(image),
            long_width: u16::from(data_model(image).long) * 8,
            thread_register: ImageEnvironment::new(image, &[])
                .ok()
                .and_then(|environment| {
                    convention(image, environment.declarations()).thread_pointer
                }),
        };
        let mut candidates: Vec<(u64, u64)> = image
            .symbols
            .iter()
            .filter(|symbol| matches!(symbol.kind, SymbolKind::Data | SymbolKind::Other))
            .filter_map(|symbol| Some((symbol.address, symbol.size?)))
            .chain(
                image
                    .imports
                    .iter()
                    .map(|import| (import.slot, u64::from(import.size))),
            )
            .chain(objects.iter().copied())
            .filter(|&(start, size)| size > 0 && data.in_data(start, size))
            .collect();
        candidates.sort_by_key(|&(start, size)| (start, std::cmp::Reverse(size)));
        let mut end = 0;
        for (start, size) in candidates {
            if start < end {
                continue;
            }
            end = start.saturating_add(size);
            let read_only = data.memory.unchanging(start, end);
            data.objects.insert(start, (size, read_only));
        }
        data
    }

    /// Whether all `bytes` bytes at `address` are in one data section.
    fn in_data(&self, address: u64, bytes: u64) -> bool {
        let Some(end) = address.checked_add(bytes) else {
            return false;
        };
        let after = self
            .sections
            .partition_point(|section| section.start <= address);
        self.sections
            .get(..after)
            .unwrap_or_default()
            .iter()
            .any(|section| section.contains(&address) && end <= section.end)
    }

    /// The data in the image's code ([`crate::cfg::Program::data`]):
    /// start to end.
    pub fn code_data(&self) -> &BTreeMap<u64, u64> {
        &self.code_data
    }

    /// The byte at `address`, if the program cannot change it and the
    /// image says what it is.
    fn byte(&self, address: u64) -> Option<u8> {
        let bits = self.memory.read(address, 1)?;
        u8::try_from(bits.low_u64()).ok()
    }

    /// How many bytes from `address` on are all in one data section
    /// ([`Self::in_data`]): 0 where it is in none.
    fn data_room(&self, address: u64) -> u64 {
        let after = self
            .sections
            .partition_point(|section| section.start <= address);
        self.sections
            .get(..after)
            .unwrap_or_default()
            .iter()
            .filter(|section| section.contains(&address))
            .map(|section| section.end - address)
            .max()
            .unwrap_or(0)
    }

    /// The bytes from `address` on that each [`Self::byte`] gives, at
    /// most `most` of them (at least one, read alone, where the first is
    /// one), into `buffer`: how many, or `None` where the first is none.
    fn bytes<'b>(&self, address: u64, most: u64, buffer: &'b mut [u8; RUN]) -> Option<&'b [u8]> {
        let most = usize::try_from(most).unwrap_or(RUN).min(RUN);
        let run = buffer.get_mut(..most)?;
        let read = self.memory.plain(address, run);
        if read > 0 {
            return run.get(..read);
        }
        let first = run.first_mut()?;
        *first = self.byte(address)?;
        run.get(..1)
    }
}

/// The C name of an import ([`ImageData`]'s fixed imports): its name, or
/// for one by ordinal (`#19`), its module's name without extension and
/// the ordinal (`WS2_32_ordinal_19`), as a C identifier.
fn import_name(import: &Import) -> String {
    let Some(ordinal) = import.name.strip_prefix('#') else {
        return import.name.clone();
    };
    let module = import.library.as_deref().map_or("import", |library| {
        library.split('.').next().unwrap_or(library)
    });
    format!("{module}_ordinal_{ordinal}")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

impl Data for ImageData<'_> {
    fn object(&self, address: u64) -> Option<Object> {
        let (&start, &(size, read_only)) = self.objects.range(..=address).next_back()?;
        let object = Object {
            start,
            size,
            read_only,
        };
        object.holds(address, 1).then_some(object)
    }

    fn data(&self, address: u64, bytes: u64) -> Option<bool> {
        self.in_data(address, bytes).then(|| {
            self.memory
                .unchanging(address, address.saturating_add(bytes))
        })
    }

    fn string(&self, address: u64) -> Option<u64> {
        let mut buffer = [0; RUN];
        let mut length = 0;
        while length <= MAX_STRING {
            let at = address.checked_add(length)?;
            let room = self.data_room(at).min(MAX_STRING + 1 - length);
            if room == 0 {
                return None;
            }
            let run = self.bytes(at, room, &mut buffer)?;
            if let Some(nul) = run.iter().position(|&byte| byte == 0) {
                return Some(length + nul as u64);
            }
            length += run.len() as u64;
        }
        None
    }

    fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>> {
        Printing::constant(self, address, bytes)
    }

    fn wide_string(&self, address: u64) -> Option<u64> {
        if !address.is_multiple_of(2) {
            return None;
        }
        for length in 0..=MAX_STRING / 2 {
            let at = address.checked_add(2 * length)?;
            if !self.in_data(at, 2) {
                return None;
            }
            match (self.byte(at)?, self.byte(at + 1)?) {
                (0, 0) => return Some(length),
                (_, 0) => {}
                _ => return None,
            }
        }
        None
    }

    fn relocatable(&self) -> bool {
        self.relocatable
    }

    fn fixed_import(&self, slot: u64, bytes: u16) -> bool {
        self.memory.fixed_slot(slot, bytes)
    }

    fn import_slot(&self, slot: u64) -> bool {
        self.slots.contains(&slot)
    }
}

impl Printing for ImageData<'_> {
    fn symbol(&self, address: u64) -> Option<String> {
        self.names.get(&address).cloned()
    }

    fn import(&self, slot: u64) -> Option<String> {
        self.fixed.get(&slot).cloned()
    }

    fn read_only(&self, address: u64, bytes: u64) -> bool {
        address
            .checked_add(bytes)
            .is_some_and(|end| bytes > 0 && self.memory.unchanging(address, end))
    }

    fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>> {
        let mut buffer = [0; RUN];
        let mut constant = Vec::new();
        let mut length = 0;
        while length < bytes {
            let run = self.bytes(address.checked_add(length)?, bytes - length, &mut buffer)?;
            constant.extend_from_slice(run);
            length += run.len() as u64;
        }
        Some(constant)
    }

    fn string(&self, address: u64) -> Option<Vec<u8>> {
        let length = Data::string(self, address)?;
        if !Printing::read_only(self, address, length.checked_add(1)?) {
            return None;
        }
        Printing::constant(self, address, length)
    }

    fn thread_pointer(&self) -> ThreadPointer {
        self.thread_pointer
    }

    fn long_width(&self) -> u16 {
        self.long_width
    }

    fn is_thread_pointer(&self, register: RegisterId) -> bool {
        self.thread_register == Some(register)
    }

    fn unlifted(&self, address: u64) -> Option<Unlifted> {
        unlifted(self.image, address).ok()
    }

    fn instruction(&self, address: u64) -> Option<String> {
        // XED leaves a space after a mnemonic without operands.
        let (text, _) = disassemble(self.image, address).ok()?;
        Some(text.trim_end().to_owned())
    }
}
