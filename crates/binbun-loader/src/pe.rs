//! PE specifics: imports by IAT slot, exports, code pointers from base
//! relocations, what the loader writes (relocated slots, IAT slots, slots
//! its data directories name), function ranges and exception handlers from
//! `.pdata`.

use core::mem::{offset_of, size_of};

use binbun_semantics::core::memory::Memory;
use object::LittleEndian as LE;
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_SUBSYSTEM_NATIVE,
    ImageLoadConfigDirectory32, ImageLoadConfigDirectory64, ImageTlsDirectory32,
    ImageTlsDirectory64,
};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader as _, Import as PeImport, PeFile};
use object::{ExportTarget, NameOrOrdinal, Object};

use crate::msvc::{self, Handled};
use crate::{
    EntryFrame, Fixup, Image, Import, Machine, Part, Pointer, PointerSource, Relocation, Symbol,
    SymbolKind, SymbolSource, UnwindEntry, UnwindSource,
};

pub fn load<'data, Pe: ImageNtHeaders>(pe: &PeFile<'data, Pe>, image: &mut Image<'data>) {
    let base = pe.relative_address_base();
    imports(pe, base, image);
    delay_imports(pe, base, image);
    image.kernel = pe.nt_headers().optional_header().subsystem() == IMAGE_SUBSYSTEM_NATIVE
        && image
            .imports
            .iter()
            .any(|import| import.library.as_deref().is_some_and(is_kernel_module));
    loader_slots(pe, base, image);
    exports(pe, image);
    base_relocations(pe, image);
    match image.machine {
        Machine::X86_64 => pdata(pe, base, image),
        Machine::Aarch64 => arm64_pdata(pe, base, image),
        Machine::X86 | Machine::Arm | Machine::Other => {}
    }
}

/// Whether module `name` is kernel-mode code: the kernel (`ntoskrnl.exe`),
/// the HAL (`hal.dll`), or a driver (`.sys`).
fn is_kernel_module(name: &str) -> bool {
    name.eq_ignore_ascii_case("ntoskrnl.exe")
        || name.eq_ignore_ascii_case("hal.dll")
        || name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("sys"))
}

/// The slots base relocations adjust, unchanged at the preferred base
/// (pointers, `DIR64` and `HIGHLOW` entries, with their value; the others
/// without); the pointers among them ([`Image::pointers`]), and those
/// that point to code.
fn base_relocations<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, image: &mut Image<'_>) {
    let base = pe.relative_address_base();
    let mut blocks = match pe
        .data_directories()
        .relocation_blocks(pe.data(), &pe.section_table())
    {
        Ok(Some(blocks)) => blocks,
        Ok(None) => return,
        Err(error) => return image.warn(Part::Relocations, error),
    };
    loop {
        let block = match blocks.next() {
            Ok(Some(block)) => block,
            Ok(None) => break,
            Err(error) => return image.warn(Part::Relocations, error),
        };
        for relocation in block {
            let (size, pointer) = match relocation.typ {
                object::pe::IMAGE_REL_BASED_ABSOLUTE => continue,
                object::pe::IMAGE_REL_BASED_DIR64 => (8, true),
                object::pe::IMAGE_REL_BASED_HIGHLOW => (4, true),
                object::pe::IMAGE_REL_BASED_HIGH
                | object::pe::IMAGE_REL_BASED_LOW
                | object::pe::IMAGE_REL_BASED_HIGHADJ => (2, false),
                _ => (8, false),
            };
            let at = base + u64::from(relocation.virtual_address);
            let target = image.read_word(at, size, true).filter(|_| pointer);
            image.fixups.push(Fixup {
                start: at,
                size: size as u64,
                value: target,
            });
            if let Some(target) = target {
                image.code_pointer(at, target, PointerSource::Relocation);
                image.pointers.push(Pointer {
                    at,
                    target,
                    relocation: Relocation::Base,
                });
            }
        }
    }
}

/// Each import's IAT slot: the loader writes the imported address there,
/// and calls go through it (`call [rip+slot]`).
/// A slot in a section without `IMAGE_SCN_MEM_WRITE` is
/// [`fixed`](Import::fixed).
fn imports<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, base: u64, image: &mut Image<'_>) {
    let table = match pe.import_table() {
        Ok(Some(table)) => table,
        Ok(None) => return,
        Err(error) => return image.warn(Part::Imports, error),
    };
    let mut descriptors = match table.descriptors() {
        Ok(descriptors) => descriptors,
        Err(error) => return image.warn(Part::Imports, error),
    };
    let size = size_of::<Pe::ImageThunkData>();
    loop {
        let descriptor = match descriptors.next() {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => break,
            Err(error) => return image.warn(Part::Imports, error),
        };
        let library = table
            .name(descriptor.name.get(LE))
            .ok()
            .map(|name| String::from_utf8_lossy(name).into_owned());
        let first_thunk = descriptor.first_thunk.get(LE);
        // Names come from the lookup table; without one, from the IAT as
        // stored in the file.
        let lookup = match descriptor.original_first_thunk.get(LE) {
            0 => first_thunk,
            rva => rva,
        };
        let mut thunks = match table.thunks(lookup) {
            Ok(thunks) => thunks,
            Err(error) => {
                image.warn(Part::Imports, error);
                continue;
            }
        };
        for index in 0u64.. {
            let thunk = match thunks.next::<Pe>() {
                Ok(Some(thunk)) => thunk,
                Ok(None) => break,
                Err(error) => {
                    image.warn(Part::Imports, error);
                    break;
                }
            };
            let slot = base + u64::from(first_thunk) + index * size as u64;
            image.fixups.push(Fixup {
                start: slot,
                size: size as u64,
                value: None,
            });
            let name = match table.import::<Pe>(thunk) {
                Ok(PeImport::Name(_, name)) => String::from_utf8_lossy(name).into_owned(),
                Ok(PeImport::Ordinal(ordinal)) => format!("#{ordinal}"),
                Err(error) => {
                    image.warn(Part::Imports, error);
                    continue;
                }
            };
            let fixed = image.segment(slot).is_some_and(|section| {
                !section.permissions.write && slot.saturating_add(size as u64) <= section.end()
            });
            image.imports.push(Import {
                name,
                library: library.clone(),
                slot,
                size: u8::try_from(size).unwrap_or(8),
                fixed,
            });
        }
    }
}

/// The slots delay-load imports write when first called (their IAT
/// entries, as many as their name table has) and the module handle each
/// keeps. Descriptors of the old kind (addresses instead of RVAs) are
/// skipped.
fn delay_imports<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, base: u64, image: &mut Image<'_>) {
    let table = match pe.delay_load_import_table() {
        Ok(Some(table)) => table,
        Ok(None) => return,
        Err(error) => return image.warn(Part::Imports, error),
    };
    let mut descriptors = match table.descriptors() {
        Ok(descriptors) => descriptors,
        Err(error) => return image.warn(Part::Imports, error),
    };
    let size = size_of::<Pe::ImageThunkData>();
    loop {
        let descriptor = match descriptors.next() {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => break,
            Err(error) => return image.warn(Part::Imports, error),
        };
        if descriptor.attributes.get(LE) & 1 == 0 {
            image.warn(Part::Imports, "a delay-load descriptor of the old kind");
            continue;
        }
        let handle = descriptor.module_handle_rva.get(LE);
        if handle != 0 {
            image.fixups.push(Fixup {
                start: base + u64::from(handle),
                size: size as u64,
                value: None,
            });
        }
        let iat = base + u64::from(descriptor.import_address_table_rva.get(LE));
        let mut thunks = match table.thunks(descriptor.import_name_table_rva.get(LE)) {
            Ok(thunks) => thunks,
            Err(error) => {
                image.warn(Part::Imports, error);
                continue;
            }
        };
        for index in 0u64.. {
            match thunks.next::<Pe>() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => {
                    image.warn(Part::Imports, error);
                    break;
                }
            }
            image.fixups.push(Fixup {
                start: iat + index * size as u64,
                size: size as u64,
                value: None,
            });
        }
    }
}

/// The slots the loader writes that the data directories name: the TLS
/// index (`AddressOfIndex`), and from the load configuration the security
/// cookie and the Control Flow Guard function pointers.
fn loader_slots<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, base: u64, image: &mut Image<'_>) {
    let word = size_of::<Pe::ImageThunkData>();
    let (tls, tls_size, load_config) = if word == 8 {
        (
            offset_of!(ImageTlsDirectory64, address_of_index),
            size_of::<ImageTlsDirectory64>(),
            [
                offset_of!(ImageLoadConfigDirectory64, security_cookie),
                offset_of!(ImageLoadConfigDirectory64, guard_cf_check_function_pointer),
                offset_of!(
                    ImageLoadConfigDirectory64,
                    guard_cf_dispatch_function_pointer
                ),
                offset_of!(
                    ImageLoadConfigDirectory64,
                    guard_rf_failure_routine_function_pointer
                ),
                offset_of!(
                    ImageLoadConfigDirectory64,
                    guard_rf_verify_stack_pointer_function_pointer
                ),
            ],
        )
    } else {
        (
            offset_of!(ImageTlsDirectory32, address_of_index),
            size_of::<ImageTlsDirectory32>(),
            [
                offset_of!(ImageLoadConfigDirectory32, security_cookie),
                offset_of!(ImageLoadConfigDirectory32, guard_cf_check_function_pointer),
                offset_of!(
                    ImageLoadConfigDirectory32,
                    guard_cf_dispatch_function_pointer
                ),
                offset_of!(
                    ImageLoadConfigDirectory32,
                    guard_rf_failure_routine_function_pointer
                ),
                offset_of!(
                    ImageLoadConfigDirectory32,
                    guard_rf_verify_stack_pointer_function_pointer
                ),
            ],
        )
    };
    let directory = |index: usize| {
        pe.data_directory(index)
            .map(|directory| directory.virtual_address.get(LE))
            .filter(|&address| address != 0)
            .map(|address| base + u64::from(address))
    };
    if let Some(start) = directory(IMAGE_DIRECTORY_ENTRY_TLS) {
        named_slots(image, start, tls_size as u64, &[tls], word);
    }
    if let Some(start) = directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
        // The structure starts with its size: later fields may be missing.
        if let Some(size) = image.read_word(start, 4, true) {
            named_slots(image, start, size, &load_config, word);
        }
    }
}

/// The `word`-byte slots that the address fields at `fields` (offsets) of
/// the `size`-byte structure at `start` point to.
fn named_slots(image: &mut Image<'_>, start: u64, size: u64, fields: &[usize], word: usize) {
    for &offset in fields {
        if (offset + word) as u64 > size {
            continue;
        }
        let slot = image
            .read_word(start + offset as u64, word, true)
            .filter(|&slot| slot != 0);
        if let Some(slot) = slot {
            image.fixups.push(Fixup {
                start: slot,
                size: word as u64,
                value: None,
            });
        }
    }
}

/// The export table's symbols (forwarders, which name other modules'
/// symbols, have no address here and are left out).
fn exports<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, image: &mut Image<'_>) {
    let exports = match pe.exports() {
        Ok(exports) => exports,
        Err(error) => return image.warn(Part::Exports, error),
    };
    for export in exports {
        let export = match export {
            Ok(export) => export,
            Err(error) => {
                image.warn(Part::Exports, error);
                break;
            }
        };
        let ExportTarget::Address { address } = export.target() else {
            continue;
        };
        let kind = if image.is_code(address) {
            SymbolKind::Function
        } else {
            SymbolKind::Data
        };
        let name = match export.name() {
            NameOrOrdinal::Name(name) => String::from_utf8_lossy(name).into_owned(),
            NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
        };
        image.symbols.push(Symbol {
            name,
            address,
            size: None,
            kind,
            source: SymbolSource::Export,
            interposes: false,
        });
    }
}

/// The bytes of the exception directory (`.pdata`), as far as mapped.
fn exception_table<Pe: ImageNtHeaders>(
    pe: &PeFile<'_, Pe>,
    base: u64,
    image: &mut Image<'_>,
) -> Vec<u8> {
    let Some(directory) = pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return Vec::new();
    };
    let (rva, size) = (directory.virtual_address.get(LE), directory.size.get(LE));
    let Ok(size) = usize::try_from(size) else {
        return Vec::new();
    };
    let mut table = vec![0u8; size];
    let read = image.read(base + u64::from(rva), &mut table).unwrap_or(0);
    if read < size {
        image.warn(
            Part::Pdata,
            format_args!("only {read} of {size} bytes are mapped"),
        );
    }
    table.truncate(read);
    table
}

/// x64 `.pdata`: `RUNTIME_FUNCTION` entries (begin, end, unwind data, as
/// RVAs). Entries whose unwind information chains to another entry's
/// cover split-off parts of functions. Unwind information with an
/// exception or termination handler names it (a function) after the
/// unwind codes, and the handler's data follows ([`crate::msvc`]).
fn pdata<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, base: u64, image: &mut Image<'_>) {
    let table = exception_table(pe, base, image);
    x64_pdata(&table, base, image);
}

/// The x64 `.pdata` entries `table` of `image` (whose RVAs count from
/// `base`), as [`pdata`] reads them: also a linked image's
/// ([`crate::relocatable`]).
pub(crate) fn x64_pdata(table: &[u8], base: u64, image: &mut Image<'_>) {
    /// `UNW_FLAG_EHANDLER`, `UNW_FLAG_UHANDLER` and `UNW_FLAG_CHAININFO`,
    /// in the flags of `UNWIND_INFO`'s first byte.
    const HANDLERS: u8 = 3;
    const CHAIN_INFO: u8 = 4;
    let mut handlers = Vec::new();
    let entries: Vec<UnwindEntry> = table
        .as_chunks::<12>()
        .0
        .iter()
        .filter_map(|entry| {
            let word = |at: usize| {
                entry
                    .get(at..at + 4)?
                    .try_into()
                    .ok()
                    .map(u32::from_le_bytes)
            };
            let (begin, end, unwind) = (word(0)?, word(4)?, word(8)?);
            if begin == 0 || end <= begin {
                return None;
            }
            // An odd unwind address points at another runtime function
            // entry; else the flags of the unwind information tell.
            let info = base + u64::from(unwind);
            let mut header = [0u8; 4];
            let flags = if unwind & 1 != 0 {
                CHAIN_INFO
            } else if image.read(info, &mut header) == Ok(4) {
                header.first().copied().unwrap_or(0) >> 3
            } else {
                0
            };
            if flags & HANDLERS != 0 && flags & CHAIN_INFO == 0 {
                // The handler's RVA follows the codes (two bytes each,
                // padded to an even count).
                let codes = u64::from(header.get(2).copied().unwrap_or(0));
                let at = info + 4 + 2 * (codes + (codes & 1));
                if let Some(rva) = image.read_word(at, 4, true) {
                    let count = usize::from(header.get(2).copied().unwrap_or(0));
                    let mut unwind_info = vec![0u8; 4 + 2 * count];
                    let establisher = (image.read(info, &mut unwind_info) == Ok(unwind_info.len()))
                        .then(|| msvc::establisher(&unwind_info))
                        .flatten();
                    handlers.push(Handled {
                        function: base + u64::from(begin),
                        at,
                        handler: base + rva,
                        establisher,
                    });
                }
            }
            let fragment = flags & CHAIN_INFO != 0;
            Some(UnwindEntry {
                start: base + u64::from(begin),
                end: base + u64::from(end),
                source: UnwindSource::Pdata,
                fragment,
                split_from: fragment.then(|| chain_root(image, base, unwind)).flatten(),
                frame: entry_frame(fragment),
            })
        })
        .collect();
    image.unwind.extend(entries);
    for entry in &handlers {
        image.code_pointer(entry.at, entry.handler, PointerSource::UnwindHandler);
    }
    msvc::read(image, base, &handlers);
}

/// The most links [`chain_root`] follows.
const CHAIN_DEPTH: usize = 32;

/// The start of the function chained x64 unwind information leads to:
/// from the information at RVA `unwind` (of `image`, RVAs from `base`), the
/// chained runtime function entry (after the unwind codes; at once where
/// the RVA is odd), then its own chain, to the first entry whose
/// information chains no further.
fn chain_root(image: &Image<'_>, base: u64, mut unwind: u32) -> Option<u64> {
    const CHAIN_INFO: u8 = 4;
    for _ in 0..CHAIN_DEPTH {
        let entry = if unwind & 1 != 0 {
            base + u64::from(unwind & !1)
        } else {
            let info = base + u64::from(unwind);
            let mut header = [0u8; 4];
            if image.read(info, &mut header) != Ok(4) {
                return None;
            }
            let codes = u64::from(header.get(2).copied().unwrap_or(0));
            info + 4 + 2 * (codes + (codes & 1))
        };
        let begin = image.read_word(entry, 4, true)?;
        let next = u32::try_from(image.read_word(entry + 8, 4, true)?).ok()?;
        let mut header = [0u8; 4];
        let chained = next & 1 != 0
            || (image.read(base + u64::from(next), &mut header) == Ok(4)
                && header.first().copied().unwrap_or(0) >> 3 & CHAIN_INFO != 0);
        if !chained {
            return Some(base + begin);
        }
        unwind = next;
    }
    None
}

/// How the code of a `.pdata` entry is entered: inside a frame if it is a
/// fragment (chained unwind information), else as a function.
const fn entry_frame(fragment: bool) -> EntryFrame {
    if fragment {
        EntryFrame::Inside
    } else {
        EntryFrame::Call
    }
}

/// ARM64 `.pdata`: entries of two words, the function's start (an RVA) and
/// its unwind data, either packed into the word (the low two bits, the
/// flag, 1 or 2; the function's length in instructions in bits 2-12; flag
/// 2 for a fragment without a prologue) or the RVA of an `.xdata` record
/// (flag 0), whose first word has the length (bits 0-17) and whose
/// exception handler, if bit 20 (X) is set, follows the epilogue scopes
/// and unwind codes.
fn arm64_pdata<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, base: u64, image: &mut Image<'_>) {
    let table = exception_table(pe, base, image);
    let mut handlers = Vec::new();
    let entries: Vec<UnwindEntry> = table
        .as_chunks::<8>()
        .0
        .iter()
        .filter_map(|entry| {
            let [b0, b1, b2, b3, u0, u1, u2, u3] = *entry;
            let begin = u32::from_le_bytes([b0, b1, b2, b3]);
            let unwind = u32::from_le_bytes([u0, u1, u2, u3]);
            if begin == 0 {
                return None;
            }
            let start = base + u64::from(begin);
            let (length, fragment) = match unwind & 3 {
                0 => {
                    let (length, handler) = arm64_xdata(image, base, base + u64::from(unwind))?;
                    handlers.extend(handler);
                    (length, false)
                }
                flag => (u64::from((unwind >> 2) & 0x7ff), flag == 2),
            };
            (length != 0).then(|| UnwindEntry {
                start,
                end: start + 4 * length,
                source: UnwindSource::Pdata,
                fragment,
                split_from: None,
                frame: entry_frame(fragment),
            })
        })
        .collect();
    image.unwind.extend(entries);
    for (at, handler) in handlers {
        image.code_pointer(at, handler, PointerSource::UnwindHandler);
    }
}

/// The function length (in instructions) of the ARM64 `.xdata` record at
/// `at`, and where its exception handler's RVA (relative to `base`) is
/// stored with the handler's address, if it has one.
fn arm64_xdata(image: &Image<'_>, base: u64, at: u64) -> Option<(u64, Option<(u64, u64)>)> {
    let header = image.read_word(at, 4, true)?;
    let length = header & 0x3_ffff;
    if header & (1 << 20) == 0 {
        return Some((length, None));
    }
    let packed_epilogue = header & (1 << 21) != 0;
    let (mut scopes, mut code_words) = ((header >> 22) & 0x1f, header >> 27);
    let mut after = at + 4;
    if scopes == 0 && code_words == 0 {
        // An extension word holds larger counts.
        let extension = image.read_word(after, 4, true)?;
        (scopes, code_words) = (extension & 0xffff, (extension >> 16) & 0xff);
        after += 4;
    }
    if !packed_epilogue {
        after += 4 * scopes;
    }
    after += 4 * code_words;
    let handler = image.read_word(after, 4, true)?;
    Some((length, Some((after, base + handler))))
}
