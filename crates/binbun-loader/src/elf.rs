//! ELF specifics: imports and code pointers from the dynamic relocations,
//! the libraries imports come from (their symbol versions' `vn_file`), what
//! the dynamic loader writes (relocated slots, the dynamic section) and
//! makes read-only (RELRO), which import slots it fills at load and never
//! changes after (`BIND_NOW` and RELRO), function ranges from `.eh_frame`,
//! landing pads from the exception tables (LSDAs) that `.eh_frame` points
//! to.

use std::collections::{BTreeMap, BTreeSet};

use binbun_semantics::core::Memory;
use gimli::{
    BaseAddresses, CallFrameInstruction, CieOrFde, EhFrame, FrameDescriptionEntry,
    Pointer as EncodedPointer, Reader, RunTimeEndian, UnwindSection,
};
use object::elf::{
    PT_DYNAMIC, PT_GNU_RELRO, ProgramType, R_386_32, R_386_COPY, R_386_GLOB_DAT, R_386_IRELATIVE,
    R_386_JMP_SLOT, R_386_RELATIVE, R_386_TLS_DESC, R_AARCH64_ABS64, R_AARCH64_COPY,
    R_AARCH64_GLOB_DAT, R_AARCH64_IRELATIVE, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE,
    R_AARCH64_TLSDESC, R_ARM_ABS32, R_ARM_COPY, R_ARM_GLOB_DAT, R_ARM_IRELATIVE, R_ARM_JUMP_SLOT,
    R_ARM_RELATIVE, R_ARM_TLS_DESC, R_X86_64_64, R_X86_64_COPY, R_X86_64_GLOB_DAT,
    R_X86_64_IRELATIVE, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE, R_X86_64_RELATIVE64,
    R_X86_64_TLSDESC, RelocationType, STB_GLOBAL, STB_GNU_UNIQUE, STB_WEAK, STT_FUNC,
    STT_GNU_IFUNC, STV_DEFAULT, STV_PROTECTED,
};
use object::read::elf::{ElfFile, FileHeader, ProgramHeader, Sym};
use object::{
    Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, ReadRef, RelocationFlags,
    RelocationTarget, SymbolFlags,
};

use crate::{
    EntryFrame, ExceptionTable, Fixup, Image, Import, LandingPad, Machine, Part, Pointer,
    PointerSource, Referent, Relocation, Resolved, UnwindEntry, UnwindSource, lsda,
};

/// A program header: its type, address and size in memory.
pub type ProgramRange = (ProgramType, u64, u64);

/// Loads the ELF specifics of `file`, whose program headers are `headers`
/// and whose undefined dynamic symbols come from `libraries` (by index:
/// [`libraries`]).
pub fn load(
    file: &object::File<'_>,
    headers: &[ProgramRange],
    libraries: &BTreeMap<usize, String>,
    image: &mut Image<'_>,
) {
    relro(headers, image);
    let now = binds_now(file, headers, image);
    // After `relro`: whether a slot is fixed depends on it.
    imports(file, libraries, image, now);
    pointers(file, image);
    // After `pointers`, which records the packed relative relocations.
    fixups(file, headers, image);
    eh_frame(file, image);
}

/// Every dynamic relocation against an undefined symbol is a slot the
/// dynamic loader fills with that symbol's address: `JUMP_SLOT` entries for
/// PLT calls, `GLOB_DAT` entries for `call [rip+got]` and data. A slot is a
/// pointer (the parser reports no size for these relocation types).
/// With `now` (the image binds every symbol at load time), a slot of a
/// symbol that is not weak inside a RELRO range is
/// [`fixed`](Import::fixed). Its library is the one `libraries` names for
/// its symbol.
fn imports(
    file: &object::File<'_>,
    libraries: &BTreeMap<usize, String>,
    image: &mut Image<'_>,
    now: bool,
) {
    let (Some(relocations), Some(symbols)) =
        (file.dynamic_relocations(), file.dynamic_symbol_table())
    else {
        return;
    };
    let size: u8 = if file.is_64() { 8 } else { 4 };
    for (slot, relocation) in relocations {
        let RelocationTarget::Symbol(index) = relocation.target() else {
            continue;
        };
        let symbol = match symbols.symbol_by_index(index) {
            Ok(symbol) => symbol,
            Err(error) => {
                image.warn(
                    Part::Imports,
                    format_args!("relocation at {slot:#x}: {error}"),
                );
                continue;
            }
        };
        if !symbol.is_undefined() {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let fixed = now
            && !symbol.is_weak()
            && image.relro.iter().any(|range| {
                range.start <= slot && slot.saturating_add(u64::from(size)) <= range.end
            });
        image.imports.push(Import {
            name: name.to_owned(),
            library: libraries.get(&index.0).cloned(),
            slot,
            size,
            fixed,
        });
    }
}

/// The library each undefined dynamic symbol of `elf` comes from, by
/// symbol index: the file (`vn_file`) of the version needed
/// (`.gnu.version_r`, which `DT_VERNEED` points to) that the symbol's
/// version (`.gnu.version`, `DT_VERSYM`) names. The dynamic loader binds
/// a versioned reference only to a definition of that version in that
/// library. An unversioned symbol comes from whichever module of the
/// global scope defines it first (the executable, its `DT_NEEDED`
/// libraries breadth first with theirs, preloaded ones): not stated, even
/// with one `DT_NEEDED` (its own dependencies, or a preloaded library,
/// may define it).
pub fn libraries<'data, Elf: FileHeader, R: ReadRef<'data>>(
    elf: &ElfFile<'data, Elf, R>,
) -> BTreeMap<usize, String> {
    let endian = elf.endian();
    let Some(versions) = elf
        .elf_section_table()
        .versions(endian, elf.data())
        .ok()
        .flatten()
    else {
        return BTreeMap::new();
    };
    elf.elf_dynamic_symbol_table()
        .enumerate()
        .filter(|(_, symbol)| symbol.is_undefined(endian))
        .filter_map(|(index, _)| {
            let version = versions
                .version(versions.version_index(endian, index).index())
                .ok()??;
            let file = version.file()?;
            Some((index.0, String::from_utf8_lossy(file).into_owned()))
        })
        .collect()
}

/// The RELRO ranges of `headers` ([`Image::relro`]): `PT_GNU_RELRO`, its
/// end rounded down to a page as loaders do (the page the machine's
/// loaders assume at most).
fn relro(headers: &[ProgramRange], image: &mut Image<'_>) {
    let page = match image.machine {
        Machine::X86 | Machine::X86_64 => 0x1000,
        Machine::Aarch64 | Machine::Arm | Machine::Other => 0x1_0000,
    };
    for &(kind, start, size) in headers {
        if kind == PT_GNU_RELRO {
            let end = start.saturating_add(size) & !(page - 1);
            if end > start {
                image.relro.push(start..end);
            }
        }
    }
}

/// Whether the dynamic table (`PT_DYNAMIC` of `headers`) asks the dynamic
/// loader to bind every symbol before the program runs, not at its first
/// use: `DF_BIND_NOW` in `DT_FLAGS`, `DF_1_NOW` in `DT_FLAGS_1`, or a
/// `DT_BIND_NOW` entry (the System V gABI's "Dynamic Section"; glibc's
/// `ld.so` honours all three, and `LD_BIND_NOW` only adds to them).
fn binds_now(file: &object::File<'_>, headers: &[ProgramRange], image: &Image<'_>) -> bool {
    const DT_BIND_NOW: u64 = 24;
    const DT_FLAGS: u64 = 30;
    const DT_FLAGS_1: u64 = 0x6fff_fffb;
    const DF_BIND_NOW: u64 = 0x8;
    const DF_1_NOW: u64 = 0x1;
    let word = if file.is_64() { 8 } else { 4 };
    let little = file.is_little_endian();
    let step = 2 * word as u64;
    headers
        .iter()
        .filter(|&&(kind, ..)| kind == PT_DYNAMIC)
        .any(|&(_, start, size)| {
            (0..size / step)
                .map_while(|index| {
                    let at = start.saturating_add(index * step);
                    let tag = image.read_word(at, word, little)?;
                    let value = image.read_word(at.saturating_add(word as u64), word, little)?;
                    Some((tag, value))
                })
                .take_while(|&(tag, _)| tag != 0)
                .any(|(tag, value)| match tag {
                    DT_BIND_NOW => true,
                    DT_FLAGS => value & DF_BIND_NOW != 0,
                    DT_FLAGS_1 => value & DF_1_NOW != 0,
                    _ => false,
                })
        })
}

/// Pointers to code the file stores: values the dynamic relocations make
/// addresses of (relative relocations, whose value is the addend or, for
/// `REL` relocations, what is stored; and relocations against defined
/// symbols), and the entries of the init and fini arrays (which a
/// non-position-independent executable stores without relocations). The
/// dynamic relocations that store one of the image's addresses, to code or
/// data, are its [`Image::pointers`] ([`pointer_relocation`]).
fn pointers(file: &object::File<'_>, image: &mut Image<'_>) {
    let size = if file.is_64() { 8 } else { 4 };
    let little = file.is_little_endian();
    let symbols = file.dynamic_symbol_table();
    for (at, relocation) in file.dynamic_relocations().into_iter().flatten() {
        let (base, ifunc) = match relocation.target() {
            RelocationTarget::Absolute => (0, None),
            RelocationTarget::Symbol(index) => {
                let Some(symbol) = symbols.as_ref().and_then(|s| s.symbol_by_index(index).ok())
                else {
                    continue;
                };
                if symbol.is_undefined() {
                    continue;
                }
                let ifunc = matches!(symbol.flags(), SymbolFlags::Elf { st_info, .. }
                    if st_info.st_type() == STT_GNU_IFUNC);
                (symbol.address(), Some(ifunc))
            }
            RelocationTarget::Section(_) | _ => continue,
        };
        let addend = if relocation.has_implicit_addend() {
            match image.read_word(at, size, little) {
                Some(value) => value,
                None => continue,
            }
        } else {
            relocation.addend().cast_unsigned()
        };
        let target = base.wrapping_add(addend);
        image.code_pointer(at, target, PointerSource::Relocation);
        if let RelocationFlags::Elf { r_type } = relocation.flags()
            && ifunc.is_none()
            && irelative(image.machine, r_type)
        {
            image.resolved.push(Resolved {
                at,
                resolver: target,
                names: Vec::new(),
            });
        }
        if let RelocationFlags::Elf { r_type } = relocation.flags()
            && let Some(relocation) = pointer_relocation(image.machine, r_type, ifunc)
        {
            image.pointers.push(Pointer {
                at,
                target,
                relocation,
            });
        }
    }
    relr(file, image, size, little);
    dynamic_tags(file, image, size, little);
    for name in [".init_array", ".fini_array", ".preinit_array"] {
        let Some(section) = file.section_by_name(name) else {
            continue;
        };
        let count = section.size() / size as u64;
        for index in 0..count {
            let at = section.address() + index * size as u64;
            if let Some(target) = image.read_word(at, size, little) {
                image.code_pointer(at, target, PointerSource::InitArray);
            }
        }
    }
}

/// The init and fini functions of the dynamic section (`DT_INIT`,
/// `DT_FINI`), which the dynamic loader calls.
fn dynamic_tags(file: &object::File<'_>, image: &mut Image<'_>, size: usize, little: bool) {
    const DT_INIT: u64 = 12;
    const DT_FINI: u64 = 13;
    let Some(section) = file.section_by_name(".dynamic") else {
        return;
    };
    let step = 2 * size as u64;
    for index in 0..section.size() / step {
        let at = section.address() + index * step;
        let (Some(tag), Some(value)) = (
            image.read_word(at, size, little),
            image.read_word(at + size as u64, size, little),
        ) else {
            break;
        };
        match tag {
            0 => break,
            DT_INIT | DT_FINI => {
                image.code_pointer(at + size as u64, value, PointerSource::DynamicTag);
            }
            _ => {}
        }
    }
}

/// Packed relative relocations (`.relr.dyn`, `DT_RELR`): a list of words,
/// each either an address to relocate (even) or a bitmap of which of the
/// next `word bits - 1` words to relocate (odd). Each relocated word holds
/// its target (an implicit addend over a base of 0).
fn relr(file: &object::File<'_>, image: &mut Image<'_>, size: usize, little: bool) {
    let Some(section) = file.section_by_name(".relr.dyn") else {
        return;
    };
    let data = match section.data() {
        Ok(data) => data,
        Err(error) => return image.warn(Part::Relocations, error),
    };
    let step = size as u64;
    let bits = 8 * step - 1;
    let mut next = 0;
    let mut relocated = Vec::new();
    for word in data.chunks_exact(size) {
        let mut bytes = [0u8; 8];
        let Some(low) = bytes.get_mut(..size) else {
            break;
        };
        low.copy_from_slice(word);
        if !little {
            low.reverse();
        }
        let entry = u64::from_le_bytes(bytes);
        if entry & 1 == 0 {
            relocated.push(entry);
            next = entry.wrapping_add(step);
        } else {
            let mut bitmap = entry >> 1;
            let mut at = next;
            while bitmap != 0 {
                if bitmap & 1 != 0 {
                    relocated.push(at);
                }
                bitmap >>= 1;
                at = at.wrapping_add(step);
            }
            next = next.wrapping_add(bits * step);
        }
    }
    for at in relocated {
        let target = image.read_word(at, size, little);
        image.fixups.push(Fixup {
            start: at,
            size: step,
            value: target,
        });
        if let Some(target) = target {
            image.code_pointer(at, target, PointerSource::Relocation);
            image.pointers.push(Pointer {
                at,
                target,
                relocation: Relocation::Relative,
            });
        }
    }
}

/// What dynamic relocation type `r_type` of `machine` makes of its slot,
/// against a symbol the image defines (`symbol`: whether it is an indirect
/// function; `None`: no symbol), if it stores one of the image's
/// addresses: a relative relocation without a symbol, an absolute word,
/// GOT or PLT slot against one that is not an indirect function (whose
/// slot holds what its resolver returns).
fn pointer_relocation(
    machine: Machine,
    r_type: RelocationType,
    symbol: Option<bool>,
) -> Option<Relocation> {
    let (relative, absolute, glob_dat, jump_slot) = match machine {
        Machine::X86_64 if r_type == R_X86_64_RELATIVE64 => {
            return symbol.is_none().then_some(Relocation::Relative);
        }
        Machine::X86_64 => (
            R_X86_64_RELATIVE,
            R_X86_64_64,
            R_X86_64_GLOB_DAT,
            R_X86_64_JUMP_SLOT,
        ),
        Machine::X86 => (R_386_RELATIVE, R_386_32, R_386_GLOB_DAT, R_386_JMP_SLOT),
        Machine::Aarch64 => (
            R_AARCH64_RELATIVE,
            R_AARCH64_ABS64,
            R_AARCH64_GLOB_DAT,
            R_AARCH64_JUMP_SLOT,
        ),
        Machine::Arm => (R_ARM_RELATIVE, R_ARM_ABS32, R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT),
        Machine::Other => return None,
    };
    let Some(ifunc) = symbol else {
        return (r_type == relative).then_some(Relocation::Relative);
    };
    if ifunc {
        None
    } else if r_type == absolute {
        Some(Relocation::Absolute)
    } else if r_type == glob_dat {
        Some(Relocation::GlobDat)
    } else if r_type == jump_slot {
        Some(Relocation::JumpSlot)
    } else {
        None
    }
}

/// What an ELF dynamic relocation type writes.
enum Write {
    /// A relative relocation of a slot of this many bytes: the load
    /// address plus an addend.
    Relative(usize),
    /// A copy relocation: as many bytes as its symbol has.
    Copy,
    /// A slot of this many bytes, which the dynamic loader fills with its
    /// symbol's address (plus the addend): GOT and PLT slots (`GLOB_DAT`,
    /// `JUMP_SLOT`) and absolute 64-bit words (`R_X86_64_64`,
    /// `R_AARCH64_ABS64`).
    Symbol(usize),
    /// Anything else, at most this many bytes.
    Other(usize),
}

/// What relocation type `r_type` of `machine` writes, in an image of
/// `word`-byte pointers. Types the parser gives no size for write a word,
/// but TLS descriptors two; on other machines, two words is the bound.
fn relocation_write(machine: Machine, r_type: RelocationType, word: usize) -> Write {
    let (relative, copy, descriptor, slots): (_, _, _, &[RelocationType]) = match machine {
        Machine::X86_64 if r_type == R_X86_64_RELATIVE64 => return Write::Relative(8),
        Machine::X86_64 => (
            R_X86_64_RELATIVE,
            R_X86_64_COPY,
            R_X86_64_TLSDESC,
            &[R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_64],
        ),
        Machine::X86 => (
            R_386_RELATIVE,
            R_386_COPY,
            R_386_TLS_DESC,
            &[R_386_GLOB_DAT, R_386_JMP_SLOT],
        ),
        Machine::Aarch64 => (
            R_AARCH64_RELATIVE,
            R_AARCH64_COPY,
            R_AARCH64_TLSDESC,
            &[R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64],
        ),
        Machine::Arm => (
            R_ARM_RELATIVE,
            R_ARM_COPY,
            R_ARM_TLS_DESC,
            &[R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT],
        ),
        Machine::Other => return Write::Other(2 * word),
    };
    if r_type == relative {
        Write::Relative(word)
    } else if r_type == copy {
        Write::Copy
    } else if r_type == descriptor {
        Write::Other(2 * word)
    } else if slots.contains(&r_type) {
        Write::Symbol(word)
    } else {
        match machine {
            Machine::X86_64 | Machine::X86 => Write::Other(word),
            Machine::Aarch64 | Machine::Arm | Machine::Other => Write::Other(2 * word),
        }
    }
}

/// What the dynamic loader writes ([`Image::fixups`]): the slots of the
/// dynamic relocations and the dynamic section; and the RELRO range it
/// makes read-only afterwards ([`Image::relro`]). When the dynamic section
/// names relocations but none are found (no section headers), the loader
/// may write anywhere: fixups cover every segment.
fn fixups(file: &object::File<'_>, headers: &[ProgramRange], image: &mut Image<'_>) {
    let word = if file.is_64() { 8 } else { 4 };
    let little = file.is_little_endian();
    relocation_fixups(file, image, word, little);
    let found = !image.fixups.is_empty();
    let mut relocating = false;
    for &(kind, start, size) in headers {
        if kind == PT_DYNAMIC {
            relocating |= has_relocation_tags(image, start, size, word, little);
            image.fixups.push(Fixup {
                start,
                size,
                value: None,
            });
        }
    }
    if relocating && !found {
        image.warn(
            Part::Relocations,
            "the dynamic relocations are not found: the dynamic loader may write anywhere",
        );
        let everywhere: Vec<Fixup> = image
            .segments
            .iter()
            .map(|segment| Fixup {
                start: segment.start,
                size: segment.size,
                value: None,
            })
            .collect();
        image.fixups.extend(everywhere);
    }
}

/// The slots of the dynamic relocations: relative ones with their target
/// at the linked addresses (the addend or, for `REL` relocations, what is
/// stored); GOT and PLT slots and absolute 64-bit words of a function the
/// image defines with that function's address (plus the addend of a
/// `RELA` relocation), the others (whose value depends on other modules or
/// on the run) with none.
///
/// A defined function's slot holds its address only as long as nothing
/// interposes the symbol: an executable or a preloaded library can, for
/// default-visibility symbols (protected and hidden ones cannot be, but
/// they are rarely reached through a slot). That is the binding binbun
/// assumes, as a disassembler shows `foo@plt` calling the library's own
/// `foo`. Data symbols are left unknown: an executable's copy relocation
/// moves the object routinely, and `STT_GNU_IFUNC` slots hold what the
/// resolver returns, not the symbol's address.
fn relocation_fixups(file: &object::File<'_>, image: &mut Image<'_>, word: usize, little: bool) {
    let symbols = file.dynamic_symbol_table();
    let symbol = |target: RelocationTarget| {
        if let RelocationTarget::Symbol(index) = target {
            symbols.as_ref().and_then(|s| s.symbol_by_index(index).ok())
        } else {
            None
        }
    };
    for (at, relocation) in file.dynamic_relocations().into_iter().flatten() {
        let reported = usize::from(relocation.size() / 8);
        let write = if let RelocationFlags::Elf { r_type } = relocation.flags() {
            relocation_write(image.machine, r_type, word)
        } else {
            Write::Other(2 * word)
        };
        let absolute = matches!(relocation.target(), RelocationTarget::Absolute);
        let (size, value) = match write {
            Write::Relative(size) if absolute => {
                let value = if relocation.has_implicit_addend() {
                    image.read_word(at, size, little)
                } else {
                    Some(relocation.addend().cast_unsigned())
                };
                (size as u64, value)
            }
            Write::Relative(size) | Write::Other(size) => (size.max(reported) as u64, None),
            Write::Symbol(size) => {
                let addend = if relocation.has_implicit_addend() {
                    0
                } else {
                    relocation.addend().cast_unsigned()
                };
                let value = symbol(relocation.target())
                    .filter(|symbol| {
                        !symbol.is_undefined()
                            && matches!(symbol.flags(), SymbolFlags::Elf { st_info, .. }
                                if st_info.st_type() == STT_FUNC)
                    })
                    .map(|symbol| symbol.address().wrapping_add(addend));
                (size.max(reported) as u64, value)
            }
            Write::Copy => {
                let size = symbol(relocation.target())
                    .as_ref()
                    .map_or(0, ObjectSymbol::size);
                (size.max(word as u64), None)
            }
        };
        image.fixups.push(Fixup {
            start: at,
            size,
            value,
        });
    }
}

/// Whether the dynamic table at `start` (`size` bytes) names relocations
/// (`DT_RELA`, `DT_REL`, `DT_JMPREL`, `DT_RELR`).
fn has_relocation_tags(
    image: &Image<'_>,
    start: u64,
    size: u64,
    word: usize,
    little: bool,
) -> bool {
    const DT_RELA: u64 = 7;
    const DT_REL: u64 = 17;
    const DT_JMPREL: u64 = 23;
    const DT_RELR: u64 = 36;
    let step = 2 * word as u64;
    (0..size / step)
        .map_while(|index| image.read_word(start.saturating_add(index * step), word, little))
        .take_while(|&tag| tag != 0)
        .any(|tag| matches!(tag, DT_RELA | DT_REL | DT_JMPREL | DT_RELR))
}

/// The program headers of `elf`.
pub fn program_headers<'data, Elf: FileHeader, R: ReadRef<'data>>(
    elf: &ElfFile<'data, Elf, R>,
) -> Vec<ProgramRange> {
    let endian = elf.endian();
    elf.elf_program_headers()
        .iter()
        .map(|header| {
            let start: u64 = header.p_vaddr(endian).into();
            let size: u64 = header.p_memsz(endian).into();
            (header.p_type(endian), start, size)
        })
        .collect()
}

/// Whether a relocation of type `r_type` on `machine` is `IRELATIVE`: its
/// slot takes what the resolver at its addend returns.
fn irelative(machine: Machine, r_type: RelocationType) -> bool {
    let irelative = match machine {
        Machine::X86_64 => R_X86_64_IRELATIVE,
        Machine::X86 => R_386_IRELATIVE,
        Machine::Aarch64 => R_AARCH64_IRELATIVE,
        Machine::Arm => R_ARM_IRELATIVE,
        Machine::Other => return false,
    };
    r_type == irelative
}

/// The names of `elf`'s dynamic `STT_GNU_IFUNC` symbols that other
/// modules' references bind to, by the resolver each is the value of
/// (the criteria of [`interposing`], for indirect functions), sorted:
/// what an `IRELATIVE` slot that calls the same resolver holds
/// ([`crate::Resolved`]).
pub fn resolver_names<'data, Elf: FileHeader, R: ReadRef<'data>>(
    elf: &ElfFile<'data, Elf, R>,
) -> BTreeMap<u64, Vec<String>> {
    let endian = elf.endian();
    let versions = elf
        .elf_section_table()
        .versions(endian, elf.data())
        .ok()
        .flatten();
    let table = elf.elf_dynamic_symbol_table();
    let mut names: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (index, symbol) in table.enumerate() {
        let bind = symbol.st_bind();
        let visibility = symbol.st_visibility();
        if symbol.st_type() != STT_GNU_IFUNC
            || !(bind == STB_GLOBAL || bind == STB_WEAK || bind == STB_GNU_UNIQUE)
            || !(visibility == STV_DEFAULT || visibility == STV_PROTECTED)
            || versions.as_ref().is_some_and(|versions| {
                let version = versions.version_index(endian, index);
                version.is_hidden() || version.is_local()
            })
        {
            continue;
        }
        let Ok(name) = table.symbol_name(endian, symbol) else {
            continue;
        };
        names
            .entry(symbol.st_value(endian).into())
            .or_default()
            .push(String::from_utf8_lossy(name).into_owned());
    }
    for list in names.values_mut() {
        list.sort();
        list.dedup();
    }
    names
}

/// The indices of `elf`'s dynamic symbols that other modules' references
/// to their names bind to (see [`crate::Symbol::interposes`]): functions
/// (`STT_FUNC`), global, weak or unique, of default or protected
/// visibility, whose version (`.gnu.version`) is their name's default
/// (not hidden: `name@@VERSION`) or none.
pub fn interposing<'data, Elf: FileHeader, R: ReadRef<'data>>(
    elf: &ElfFile<'data, Elf, R>,
) -> BTreeSet<usize> {
    let endian = elf.endian();
    let versions = elf
        .elf_section_table()
        .versions(endian, elf.data())
        .ok()
        .flatten();
    elf.elf_dynamic_symbol_table()
        .enumerate()
        .filter(|&(index, symbol)| {
            let bind = symbol.st_bind();
            let visibility = symbol.st_visibility();
            symbol.st_type() == STT_FUNC
                && (bind == STB_GLOBAL || bind == STB_WEAK || bind == STB_GNU_UNIQUE)
                && (visibility == STV_DEFAULT || visibility == STV_PROTECTED)
                && versions.as_ref().is_none_or(|versions| {
                    let version = versions.version_index(endian, index);
                    !version.is_hidden() && !version.is_local()
                })
        })
        .map(|(index, _)| index.0)
        .collect()
}

/// The frame description entries of `.eh_frame` (one per function, or cold
/// part of one, with unwind information), their exception tables and the
/// landing pads in them. Mach-O's `__eh_frame` too (`object` finds
/// `__eh_frame`, `__text` and `__got` by the ELF names).
pub fn eh_frame(file: &object::File<'_>, image: &mut Image<'_>) {
    let Some(section) = file.section_by_name(".eh_frame") else {
        return;
    };
    let data = match section.data() {
        Ok(data) => data,
        Err(error) => return image.warn(Part::EhFrame, error),
    };
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let layout = lsda::Layout {
        endian,
        address_size: if file.is_64() { 8 } else { 4 },
        text: file.section_by_name(".text").map(|text| text.address()),
        data: file.section_by_name(".got").map(|got| got.address()),
    };
    eh_frame_at(image, data, section.address(), layout);
}

/// The frame description entries of the `.eh_frame` section `data` at
/// `address` of `image` (laid out as `layout` says), their exception
/// tables and the landing pads in them ([`eh_frame`]).
pub fn eh_frame_at(image: &mut Image<'_>, data: &[u8], address: u64, layout: lsda::Layout) {
    let endian = layout.endian;
    let address_size = layout.address_size;
    let mut eh_frame = EhFrame::new(data, endian);
    eh_frame.set_address_size(address_size);
    let mut bases = BaseAddresses::default().set_eh_frame(address);
    if let Some(text) = layout.text {
        bases = bases.set_text(text);
    }
    if let Some(got) = layout.data {
        bases = bases.set_got(got);
    }
    let eh_frame_range = address..address.saturating_add(data.len() as u64);
    let little = endian == RunTimeEndian::Little;
    let mut entries = eh_frame.entries(&bases);
    loop {
        let entry = match entries.next() {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(error) => return image.warn(Part::EhFrame, error),
        };
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let fde = match partial.parse(EhFrame::cie_from_offset) {
            Ok(fde) => fde,
            Err(error) => {
                image.warn(Part::EhFrame, error);
                continue;
            }
        };
        if fde.len() == 0 {
            continue;
        }
        let start = fde.initial_address();
        image.unwind.push(UnwindEntry {
            start,
            end: start.saturating_add(fde.len()),
            source: UnwindSource::EhFrame,
            fragment: false,
            split_from: None,
            frame: entry_frame(&fde, &eh_frame, &bases),
        });
        // A null pointer is none, whatever its encoding: gimli adds the
        // base to it, which for a pc-relative one is in `.eh_frame`.
        let pointer = |pointer: Option<EncodedPointer>| match pointer {
            Some(EncodedPointer::Direct(address))
                if address != 0 && !eh_frame_range.contains(&address) =>
            {
                Some(Referent {
                    address: Some(address),
                    ..Referent::default()
                })
            }
            Some(EncodedPointer::Indirect(slot)) if !eh_frame_range.contains(&slot) => {
                Some(Referent {
                    slot: Some(slot),
                    ..Referent::default()
                })
            }
            Some(EncodedPointer::Direct(_) | EncodedPointer::Indirect(_)) | None => None,
        };
        let lsda = pointer(fde.lsda()).and_then(|lsda| {
            lsda.address.or_else(|| {
                let slot = lsda.slot?;
                image.read_word(slot, usize::from(address_size), little)
            })
        });
        if let Some(lsda) = lsda {
            exception_table(image, layout, lsda, start, pointer(fde.personality()));
        }
    }
}

/// How `fde`'s code is entered, by its own instructions before its first
/// row advances past its start: the return address made undefined, as the
/// outermost frame; another rule changed, inside a frame (not as a
/// function is, whose entry rules are its CIE's initial ones); else by a
/// call. Padding, `DW_CFA_GNU_args_size`, remembering or restoring the
/// rules and a register's "same value" change no rule; instructions that do
/// not parse count as no change.
fn entry_frame<R: Reader>(
    fde: &FrameDescriptionEntry<R>,
    eh_frame: &EhFrame<R>,
    bases: &BaseAddresses,
) -> EntryFrame {
    let return_address = fde.cie().return_address_register();
    let mut frame = EntryFrame::Call;
    let mut instructions = fde.instructions(eh_frame, bases);
    while let Ok(Some(instruction)) = instructions.next() {
        match instruction {
            CallFrameInstruction::Nop
            | CallFrameInstruction::ArgsSize { .. }
            | CallFrameInstruction::RememberState
            | CallFrameInstruction::RestoreState
            | CallFrameInstruction::Restore { .. }
            | CallFrameInstruction::SameValue { .. } => {}
            CallFrameInstruction::SetLoc { .. } | CallFrameInstruction::AdvanceLoc { .. } => {
                break;
            }
            CallFrameInstruction::Undefined { register } if register == return_address => {
                return EntryFrame::Outermost;
            }
            CallFrameInstruction::DefCfa { .. }
            | CallFrameInstruction::DefCfaSf { .. }
            | CallFrameInstruction::DefCfaRegister { .. }
            | CallFrameInstruction::DefCfaOffset { .. }
            | CallFrameInstruction::DefCfaOffsetSf { .. }
            | CallFrameInstruction::DefCfaExpression { .. }
            | CallFrameInstruction::Undefined { .. }
            | CallFrameInstruction::Offset { .. }
            | CallFrameInstruction::OffsetExtendedSf { .. }
            | CallFrameInstruction::ValOffset { .. }
            | CallFrameInstruction::ValOffsetSf { .. }
            | CallFrameInstruction::Register { .. }
            | CallFrameInstruction::Expression { .. }
            | CallFrameInstruction::ValExpression { .. }
            | CallFrameInstruction::NegateRaState => frame = EntryFrame::Inside,
        }
    }
    frame
}

/// Records the exception table (LSDA) at `lsda` of the function starting at
/// `function`, whose personality routine is `personality`, and its landing
/// pads; reports its damage.
pub fn exception_table(
    image: &mut Image<'_>,
    layout: lsda::Layout,
    lsda: u64,
    function: u64,
    personality: Option<Referent>,
) {
    let available = image
        .segment(lsda)
        .map_or(0, |s| usize::try_from(s.end() - lsda).unwrap_or(usize::MAX))
        .min(lsda::LIMIT);
    let mut bytes = vec![0u8; available];
    let read = image.read(lsda, &mut bytes).unwrap_or(0);
    bytes.truncate(read);
    let little = layout.endian == RunTimeEndian::Little;
    let deref = |slot| image.read_word(slot, usize::from(layout.address_size), little);
    let parsed = lsda::parse(&bytes, lsda, function, layout, &deref);
    for damage in parsed.damage {
        image.warn(
            Part::ExceptionTable,
            format_args!("LSDA at {lsda:#x}: {damage}"),
        );
    }
    image.landing_pads.extend(
        parsed
            .call_sites
            .iter()
            .filter_map(|call_site| call_site.landing_pad)
            .map(|address| LandingPad { function, address }),
    );
    image.exception_tables.push(ExceptionTable {
        function,
        lsda,
        personality,
        call_sites: parsed.call_sites,
    });
}
