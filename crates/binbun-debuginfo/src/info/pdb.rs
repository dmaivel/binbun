//! Debug information from a PDB (`pdb2`, MIT OR Apache-2.0: a maintained fork of
//! getsentry's `pdb`) for the x86-64 or ARM64 PE image it describes. Only
//! the registers and the frames depend on the architecture (the image's):
//! names, prototypes, types and their layouts (pointer sizes as the type
//! records state them), globals and units read alike for both.
//!
//! - **Functions**: every module's procedure symbols (`S_GPROC32`,
//!   `S_LPROC32`), by entry address (the image base plus the RVA); the
//!   return type from the procedure's type (`LF_PROCEDURE`,
//!   `LF_MFUNCTION`); the unit, the module's: the source file and current
//!   directory of its build information (`S_BUILDINFO`'s `LF_BUILDINFO`
//!   in the IPI stream), else the module's (object file's) name.
//! - **Variables** of the procedure's own body (blocks included, inlined
//!   callees' `S_INLINESITE` scopes not): `S_LOCAL` with its
//!   `S_DEFRANGE_*` ranges (registers, register-relative and
//!   frame-pointer-relative memory; sub-fields and programs are
//!   [`Place::Other`]), and the older whole-function `S_REGISTER`,
//!   `S_REGREL32` and `S_BPREL32`. Parameters are the `S_LOCAL`s flagged
//!   `param`; without any, the first of the older symbols, as many as the
//!   procedure's type has arguments. An older symbol naming a variable an
//!   `S_LOCAL` already states (MSVC's home slots of `/O2` parameters) is
//!   left out.
//! - **Globals**: the data symbols (`S_GDATA32`, `S_LDATA32`) of the
//!   global symbol stream and of the modules outside procedures, by
//!   address (the first stated at one).
//! - **Types** (TPI): primitives (and pointers to them), pointers and
//!   references, modifiers (looked through), arrays, classes, structs,
//!   unions (forward references resolved by unique name, else name), their
//!   members, base classes and bit-fields, enums, `LF_ALIAS` typedefs (PDB
//!   names no other typedefs: variables refer to the named type itself),
//!   procedure types. Pointers to members are [`Type::Unknown`].
//!
//! **Frame offsets.** PDB states memory places as a register after the
//! prologue plus an offset: `S_REGREL32`'s and `S_DEFRANGE_REGISTER_REL`'s
//! register (the stack pointer mostly), `S_DEFRANGE_FRAMEPOINTER_REL`'s
//! frame pointer (`S_FRAMEPROC`'s encoded base pointer: x86-64's `rsp`,
//! `rbp` or `r13`; ARM64's `sp` or `x29`). The image's unwind information
//! (`.pdata`) states how far that register is below the canonical frame
//! address (CFA) once the prologue ran ([`Frame`]):
//!
//! - **x86-64** (`UNWIND_INFO`; the CFA is the entry `rsp` + 8): for
//!   `rsp`, 8 (the return address) plus the pushes and allocations; for
//!   the frame register `UWOP_SET_FPREG` sets, 8 plus what was pushed and
//!   allocated before it minus 16 × the frame register offset. A function
//!   without unwind information is a leaf that leaves `rsp` alone: CFA −
//!   `rsp` = 8.
//! - **ARM64** (packed unwind data or an `.xdata` record; the CFA is the
//!   entry `sp`, the call leaves the return address in `lr`): for `sp`,
//!   what the prologue's allocations and pre-indexed saves moved it by;
//!   for `x29`, that less what moved `sp` after `set_fp`/`add_fp` set it
//!   (and `add_fp`'s offset). Packed data states the whole frame
//!   (`FrameSize` × 16), and with `CR` 2 or 3 sets `x29` to `sp` last. A
//!   function without unwind information leaves `sp` alone: CFA − `sp` =
//!   0.
//!
//! `register + offset` is then [`Place::Stack`]`(offset − (CFA −
//! register))`.
//!
//! Damaged records are reported in [`DebugModel::damage`]. `pdb2` panics on
//! pointer records with undefined kind or mode bits: those records are
//! found in the raw type stream first and never parsed. Nor are
//! `S_CALLEES` and `S_CALLERS` symbols (of profile-guided builds), whose
//! function lists `pdb2` misreads and then asserts on in debug builds;
//! they state no variable.

use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::ops::Range;

use object::Object;
use object::read::pe::PeFile64;
use pdb2::{
    AddressMap, ClassKind, DataSymbol, DefRangeRegisterRelativeSymbol, FallibleIterator, IdData,
    IdFinder, IdIndex, IdInformation, Indirection, PdbInternalSectionOffset, PrimitiveKind,
    PrimitiveType, StreamIndex, SymbolData, SymbolTable, TypeData, TypeFinder, TypeIndex,
    TypeInformation,
};

use crate::info::model::{
    Composite, CompositeKind, Damage, DebugModel, Encoding, Field, Function, Global, Language,
    Place, Span, Type, TypeId, Unit, UnitId, Variable,
};

/// How deep type references are followed before the rest is
/// [`Type::Unknown`].
const TYPE_DEPTH: u32 = 256;

/// The start of every PDB (an MSF 7.00 file).
const MSF_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

/// `LF_POINTER`.
const LF_POINTER: u16 = 0x1002;

/// `S_CALLEES` and `S_CALLERS`.
const S_CALLEES: u16 = 0x115a;
const S_CALLERS: u16 = 0x115b;

/// The arguments of an `LF_BUILDINFO` record, by index
/// (`CV_BuildInfo_e`): the current directory and the source file.
const BUILD_DIRECTORY: usize = 0;
const BUILD_SOURCE: usize = 2;

/// Whether `data` is a PDB.
pub fn is_pdb(data: &[u8]) -> bool {
    data.starts_with(MSF_MAGIC)
}

/// Reads the PDB `data` of the x86-64 or ARM64 PE image `image` (whose
/// image base, unwind information and `CodeView` record it needs).
///
/// # Errors
///
/// If `image` is no x86-64 or ARM64 PE image, `data` no PDB `pdb2` opens,
/// or the PDB is not the image's (`CodeView` GUID and age). Damage inside
/// the PDB is reported in [`DebugModel::damage`] instead.
pub fn read(data: &[u8], image: &[u8]) -> Result<DebugModel, String> {
    let pe = PeFile64::parse(image).map_err(|error| error.to_string())?;
    let architecture = pe.architecture();
    let machine = if architecture == object::Architecture::X86_64 {
        Machine::X86_64
    } else if architecture == object::Architecture::Aarch64 {
        Machine::Aarch64
    } else {
        return Err(format!("no PDB reader for {architecture:?}"));
    };
    let message = |error: pdb2::Error| error.to_string();
    let mut pdb = pdb2::PDB::open(Cursor::new(data)).map_err(message)?;
    let info = pdb.pdb_information().map_err(message)?;
    let dbi = pdb.debug_information().map_err(message)?;
    let codeview = pe
        .pdb_info()
        .map_err(|error| error.to_string())?
        .ok_or("the image names no PDB")?;
    if info.guid.to_bytes_le() != codeview.guid() || dbi.age() != Some(codeview.age()) {
        return Err(format!(
            "the PDB ({}, age {:?}) is not the image's (age {})",
            info.guid,
            dbi.age(),
            codeview.age()
        ));
    }
    let mut model = DebugModel::default();
    let bad = bad_pointers(&mut pdb, &mut model.damage);
    let tpi = pdb.type_information().map_err(message)?;
    let address_map = pdb.address_map().map_err(message)?;
    // Without an IPI stream (older PDBs) a module's unit is its name.
    let ipi = pdb.id_information().ok();
    let ids = ipi.as_ref().map(id_finder);
    let mut types = Types::new(&tpi, bad, model);
    let mut reader = Reader {
        machine,
        base: pe.relative_address_base(),
        address_map: &address_map,
        frames: match machine {
            Machine::X86_64 => x86_64_frames(&pe, image),
            Machine::Aarch64 => aarch64_frames(&pe, image),
        },
        ids: ids.as_ref(),
    };
    let mut modules = dbi.modules().map_err(message)?;
    loop {
        let module = match modules.next() {
            Ok(Some(module)) => module,
            Ok(None) => break,
            Err(error) => {
                types.damage("DBI modules".to_owned(), &error);
                break;
            }
        };
        let name = module.module_name().into_owned();
        match pdb.module_info(&module) {
            Ok(Some(info)) => reader.module(&name, &info, &mut types),
            Ok(None) => {}
            Err(error) => types.damage(format!("module {name}"), &error),
        }
    }
    match pdb.global_symbols() {
        Ok(globals) => reader.globals(&globals, &mut types),
        Err(error) => types.damage("global symbols".to_owned(), &error),
    }
    Ok(types.model)
}

/// A finder of every id of `ipi`.
fn id_finder<'t>(ipi: &'t IdInformation<'_>) -> IdFinder<'t> {
    let mut finder = ipi.finder();
    let mut items = ipi.iter();
    while let Ok(Some(_)) = items.next() {
        finder.update(&items);
    }
    finder
}

/// The types the PDB `data` defines under `names` (struct, class, union or
/// enum names, such as ntdll.pdb's `_TEB`), whatever image it describes:
/// the model holding them, with what they refer to, and each name's type
/// (`None` if the PDB defines none).
///
/// # Errors
///
/// If `data` is no PDB `pdb2` opens.
pub fn named(data: &[u8], names: &[&str]) -> Result<(DebugModel, Vec<Option<TypeId>>), String> {
    let message = |error: pdb2::Error| error.to_string();
    let mut pdb = pdb2::PDB::open(Cursor::new(data)).map_err(message)?;
    let mut model = DebugModel::default();
    let bad = bad_pointers(&mut pdb, &mut model.damage);
    let tpi = pdb.type_information().map_err(message)?;
    let mut types = Types::new(&tpi, bad, model);
    let ids = names
        .iter()
        .map(|name| {
            let index = types.definitions.get(name.as_bytes()).copied()?;
            Some(types.ty(index))
        })
        .collect();
    Ok((types.model, ids))
}

/// The type indices of `LF_POINTER` records `pdb2` would panic on (kind or
/// mode bits it has no value for), from the raw type stream.
fn bad_pointers<'s>(
    pdb: &mut pdb2::PDB<'s, Cursor<&'s [u8]>>,
    damage: &mut Vec<Damage>,
) -> HashSet<u32> {
    let mut bad = HashSet::new();
    let Ok(Some(stream)) = pdb.raw_stream(StreamIndex(2)) else {
        return bad;
    };
    let bytes = stream.as_slice();
    let half = |at: usize| -> Option<u16> {
        let slice = bytes.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes(slice.try_into().ok()?))
    };
    let word = |at: usize| -> Option<u32> {
        let slice = bytes.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    };
    let (Some(header), Some(mut index)) = (word(4), word(8)) else {
        return bad;
    };
    let Ok(mut at) = usize::try_from(header) else {
        return bad;
    };
    while let Some(length) = half(at) {
        let length = usize::from(length);
        let record = at + 2;
        if half(record) == Some(LF_POINTER) {
            let attributes = (length >= 10).then(|| word(record + 6)).flatten();
            let valid = attributes.is_some_and(|attributes| {
                let mode = (attributes >> 5) & 7;
                let kind = attributes & 0x1f;
                let size = (attributes >> 13) & 0x3f;
                mode <= 4 && (size != 0 || kind <= 0x0c)
            });
            if !valid {
                bad.insert(index);
                damage.push(Damage {
                    at: format!("TPI {index:#x}"),
                    message: "pointer record with undefined attributes".to_owned(),
                });
            }
        }
        at = record + length;
        index = index.saturating_add(1);
    }
    bad
}

/// Where the stack pointer and the frame register are once a function's
/// prologue ran, as their distance below the canonical frame address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The stack pointer (`rsp`, ARM64's `sp`) and CFA − its value.
    pub stack: (&'static str, i64),
    /// The frame register (x86-64's `UWOP_SET_FPREG` register, ARM64's
    /// `x29`) and CFA − its value.
    pub frame: Option<(&'static str, i64)>,
    /// The prologue's moves of the stack pointer, in the order they run:
    /// where the instruction making each ends (from the function's start)
    /// and how far it moves the stack pointer down. A place stated for
    /// addresses in the prologue is against the stack pointer there
    /// ([`Self::stack`]). x86-64's unwind codes state them; empty for
    /// ARM64's, whose places are taken as after the prologue.
    pub prologue: Vec<(u64, i64)>,
}

impl Frame {
    /// `register + offset`, `at` bytes into the function, as a
    /// canonical-frame-address-relative stack place, if the register is the
    /// stack pointer or the frame register: the stack pointer as the
    /// prologue's moves up to `at` left it ([`Self::prologue`]).
    pub fn stack(&self, register: &str, offset: i64, at: u64) -> Option<i64> {
        let below = if register == self.stack.0 {
            let later: i64 = self
                .prologue
                .iter()
                .filter(|&&(end, _)| end > at)
                .map(|&(_, depth)| depth)
                .sum();
            self.stack.1 - later
        } else {
            self.frame.filter(|&(name, _)| name == register)?.1
        };
        offset.checked_sub(below)
    }

    /// The frame of an x86-64 `UNWIND_INFO` record (`info`: its bytes and
    /// what follows). Codes are listed last-executed first; chained
    /// records are not followed (their codes are the parent's, in the same
    /// prologue).
    pub fn from_unwind_info(info: &[u8]) -> Option<Self> {
        let &[version_flags, _, count, frame] = info.get(..4)? else {
            return None;
        };
        let version = version_flags & 7;
        let codes = info.get(4..4 + 2 * usize::from(count))?;
        let slot = |index: usize| -> Option<u16> {
            let bytes = codes.get(2 * index..2 * index + 2)?;
            Some(u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]))
        };
        // (the depth each code adds, whether it sets the frame register),
        // in the array's order.
        let mut steps: Vec<(i64, bool)> = Vec::new();
        // Each move's end in the prologue and depth, in the array's order.
        let mut prologue = Vec::new();
        let mut index = 0;
        while index < usize::from(count) {
            let code = slot(index)?;
            let operation = (code >> 8) & 0xf;
            let operand = i64::from(code >> 12);
            let (depth, slots) = match operation {
                0 => (8, 1),
                1 if operand == 0 => (i64::from(slot(index + 1)?) * 8, 2),
                1 => {
                    let low = u32::from(slot(index + 1)?);
                    let high = u32::from(slot(index + 2)?);
                    (i64::from(low | (high << 16)), 3)
                }
                2 => (operand * 8 + 8, 1),
                3 => (0, 1),
                // Version 2's `UWOP_EPILOG`.
                6 if version >= 2 => (0, 1),
                4 | 6 | 8 => (0, 2),
                5 | 7 | 9 => (0, 3),
                10 => (if operand == 0 { 40 } else { 48 }, 1),
                _ => return None,
            };
            steps.push((depth, operation == 3));
            if depth != 0 {
                prologue.push((u64::from(code & 0xff), depth));
            }
            index += slots;
        }
        let total: i64 = steps.iter().map(|&(depth, _)| depth).sum();
        let frame = steps.iter().position(|&(_, sets)| sets).and_then(|at| {
            let before: i64 = steps.get(at + 1..)?.iter().map(|&(depth, _)| depth).sum();
            let register = gpr(frame & 0xf)?;
            Some((register, 8 + before - 16 * i64::from(frame >> 4)))
        });
        Some(Self {
            stack: ("rsp", 8 + total),
            frame,
            prologue: prologue.into_iter().rev().collect(),
        })
    }

    /// The frame of ARM64 packed unwind data (an exception directory
    /// entry's second word, flag 1 or 2): the prologue allocates
    /// `FrameSize` × 16 bytes in all (register saves, locals and outgoing
    /// arguments) and, with `CR` 2 or 3 (`x29` chained), sets `x29` to `sp`
    /// after the last allocation.
    pub fn from_arm64_packed(word: u32) -> Option<Self> {
        if !matches!(word & 3, 1 | 2) {
            return None;
        }
        let size = i64::from(word >> 23) * 16;
        Some(Self {
            stack: ("sp", size),
            frame: matches!((word >> 21) & 3, 2 | 3).then_some(("x29", size)),
            prologue: Vec::new(),
        })
    }

    /// The frame of an ARM64 `.xdata` record (`record`: its bytes and what
    /// follows): its prologue's unwind codes, which start the codes after
    /// the header (and its extension word, where both counts are 0) and
    /// the epilogue scopes (none where the `E` bit packs the one epilogue
    /// into the header).
    pub fn from_arm64_xdata(record: &[u8]) -> Option<Self> {
        let word = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(record.get(at..at + 4)?.try_into().ok()?))
        };
        let header = word(0)?;
        let (mut scopes, mut words, mut at) = ((header >> 22) & 0x1f, header >> 27, 4);
        if scopes == 0 && words == 0 {
            let extension = word(4)?;
            (scopes, words, at) = (extension & 0xffff, (extension >> 16) & 0xff, 8);
        }
        if header & (1 << 21) == 0 {
            at += 4 * usize::try_from(scopes).ok()?;
        }
        let length = 4 * usize::try_from(words).ok()?;
        Self::from_arm64_codes(record.get(at..at.checked_add(length)?)?)
    }

    /// The frame ARM64 prologue unwind codes `codes` describe, up to their
    /// `end`. Codes are listed last-executed first: each allocation and
    /// pre-indexed save moves `sp` further from the CFA, and `set_fp`
    /// (`mov x29, sp`) or `add_fp` (`add x29, sp, #x × 8`) sets `x29` from
    /// `sp` before the codes listed ahead of it ran. `None` for codes that
    /// end early, or that move `sp` by what is known only at run time (an
    /// SVE allocation) or describe a custom stack (trap, machine and context
    /// frames, written by hand in assembly).
    pub fn from_arm64_codes(codes: &[u8]) -> Option<Self> {
        // What the codes so far moved `sp` by, and how far above `sp` in
        // the body `x29` was set.
        let mut moved: i64 = 0;
        let mut frame = None;
        let mut at = 0;
        loop {
            let op = *codes.get(at)?;
            let byte = |index: usize| codes.get(at + index).copied().map(i64::from);
            let (by, length) = match op {
                // alloc_s.
                0x00..=0x1f => (16 * i64::from(op), 1),
                // save_r19r20_x: `stp x19, x20, [sp, #-z × 8]!`.
                0x20..=0x3f => (8 * i64::from(op & 0x1f), 1),
                // save_fplr_x: `stp x29, lr, [sp, #-(z + 1) × 8]!`.
                0x80..=0xbf => (8 * (i64::from(op & 0x3f) + 1), 1),
                // alloc_m.
                0xc0..=0xc7 => (16 * ((i64::from(op & 7) << 8) | byte(1)?), 2),
                // save_regp_x, save_fregp_x.
                0xcc..=0xcf | 0xda..=0xdb => (8 * ((byte(1)? & 0x3f) + 1), 2),
                // save_reg_x, save_freg_x.
                0xd4..=0xd5 | 0xde => (8 * ((byte(1)? & 0x1f) + 1), 2),
                // save_regp, save_reg, save_lrpair, save_fregp, save_freg:
                // at `sp` + an offset.
                0xc8..=0xcb | 0xd0..=0xd3 | 0xd6..=0xd9 | 0xdc..=0xdd => (0, 2),
                // alloc_l.
                0xe0 => (16 * ((byte(1)? << 16) | (byte(2)? << 8) | byte(3)?), 4),
                // set_fp.
                0xe1 => {
                    frame = Some(moved);
                    (0, 1)
                }
                // add_fp.
                0xe2 => {
                    frame = Some(moved + 8 * byte(1)?);
                    (0, 2)
                }
                // end.
                0xe4 => break,
                // save_fplr (at `sp` + an offset), nop, end_c (the
                // parent's codes follow), save_next,
                // MSFT_OP_CLEAR_UNWOUND_TO_CALL, pac_sign_lr.
                0x40..=0x7f | 0xe3 | 0xe5 | 0xe6 | 0xec | 0xfc => (0, 1),
                // save_any_reg: `x`/`d`/`q` registers (kinds 0 to 2) at
                // `[sp, #-(o + 1) × 16]!` with the write-back bit; SVE
                // registers (kind 3) at `sp` + an offset.
                0xe7 => {
                    let (registers, offset) = (byte(1)?, byte(2)?);
                    if registers & 0x80 != 0 {
                        return None;
                    }
                    let pre_indexed = offset >> 6 != 3 && registers & 0x20 != 0;
                    (
                        if pre_indexed {
                            16 * ((offset & 0x3f) + 1)
                        } else {
                            0
                        },
                        3,
                    )
                }
                _ => return None,
            };
            moved = moved.checked_add(by)?;
            at += length;
        }
        Some(Self {
            stack: ("sp", moved),
            frame: frame.map(|above| ("x29", moved - above)),
            prologue: Vec::new(),
        })
    }
}

/// x86-64's general-purpose registers by their encoding number.
fn gpr(number: u8) -> Option<&'static str> {
    const NAMES: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    NAMES.get(usize::from(number)).copied()
}

/// The rows of the image's exception directory (`.pdata`).
fn exception_table<'d>(pe: &PeFile64<'d>, image: &'d [u8]) -> &'d [u8] {
    pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        .and_then(|directory| directory.data(image, &pe.section_table()).ok())
        .unwrap_or_default()
}

/// Each function's [`Frame`] by its start RVA, from x86-64 `.pdata`
/// (begin, end, `UNWIND_INFO` RVA).
fn x86_64_frames(pe: &PeFile64<'_>, image: &[u8]) -> HashMap<u32, Frame> {
    let mut out = HashMap::new();
    let sections = pe.section_table();
    for entry in exception_table(pe, image).as_chunks::<12>().0 {
        let word = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(entry.get(at..at + 4)?.try_into().ok()?))
        };
        let (Some(begin), Some(unwind)) = (word(0), word(8)) else {
            continue;
        };
        // An odd unwind address points at another entry: a part of a
        // function, not its start.
        if unwind & 1 != 0 {
            continue;
        }
        if let Some(frame) = sections
            .pe_data_at(image, unwind)
            .and_then(Frame::from_unwind_info)
        {
            out.entry(begin).or_insert(frame);
        }
    }
    out
}

/// Each function's [`Frame`] by its start RVA, from ARM64 `.pdata`: the
/// begin RVA, then packed unwind data (flag 1 or 2 in the low bits) or
/// the RVA of an `.xdata` record (flag 0). A link record (flag 3, the RVA
/// of another `.pdata` record) starts a jump island inside that record's
/// function, no function.
fn aarch64_frames(pe: &PeFile64<'_>, image: &[u8]) -> HashMap<u32, Frame> {
    let mut out = HashMap::new();
    let sections = pe.section_table();
    for &[b0, b1, b2, b3, u0, u1, u2, u3] in exception_table(pe, image).as_chunks::<8>().0 {
        let begin = u32::from_le_bytes([b0, b1, b2, b3]);
        let unwind = u32::from_le_bytes([u0, u1, u2, u3]);
        let frame = match unwind & 3 {
            0 => sections
                .pe_data_at(image, unwind)
                .and_then(Frame::from_arm64_xdata),
            1 | 2 => Frame::from_arm64_packed(unwind),
            _ => None,
        };
        if let Some(frame) = frame {
            out.entry(begin).or_insert(frame);
        }
    }
    out
}

/// The architectures whose PDBs are read: their register numbers, the
/// registers `S_FRAMEPROC`'s base pointers encode, and their unwind
/// information differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Machine {
    X86_64,
    Aarch64,
}

impl Machine {
    /// The register `CodeView` register number `number` names, lower
    /// case.
    fn register(self, number: u16) -> Option<&'static str> {
        match self {
            Self::X86_64 => x86_64_register(number),
            Self::Aarch64 => aarch64_register(number),
        }
    }

    /// The register an `S_FRAMEPROC` encoded base pointer names: 1 the
    /// stack pointer, 2 the frame pointer, 3 x86-64's base pointer of a
    /// realigned frame (`r13`; ARM64 has none documented, nor has the
    /// encoding been seen in an ARM64 PDB).
    fn base_pointer(self, encoded: u8) -> Option<&'static str> {
        match (self, encoded) {
            (Self::X86_64, 1) => Some("rsp"),
            (Self::X86_64, 2) => Some("rbp"),
            (Self::X86_64, 3) => Some("r13"),
            (Self::Aarch64, 1) => Some("sp"),
            (Self::Aarch64, 2) => Some("x29"),
            (Self::X86_64 | Self::Aarch64, _) => None,
        }
    }

    /// The frame pointer `S_BPREL32` counts from.
    const fn frame_pointer(self) -> &'static str {
        match self {
            Self::X86_64 => "rbp",
            Self::Aarch64 => "x29",
        }
    }

    /// The frame of a function without unwind information: a leaf, which
    /// leaves the stack pointer where the call did (x86-64's below the
    /// return address it pushed).
    const fn leaf(self) -> Frame {
        let stack = match self {
            Self::X86_64 => ("rsp", 8),
            Self::Aarch64 => ("sp", 0),
        };
        Frame {
            stack,
            frame: None,
            prologue: Vec::new(),
        }
    }
}

/// The 64-bit register a `CodeView` x86-64 register number names (its
/// sub-registers included: `ecx` is `rcx`), lower case.
fn x86_64_register(number: u16) -> Option<&'static str> {
    const LEGACY: [&str; 8] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
    const XMM: [&str; 16] = [
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
        "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    ];
    let at = |table: &'static [&'static str], index: u16| table.get(usize::from(index)).copied();
    match number {
        // al cl dl bl, then ah ch dh bh.
        1..=4 => at(&LEGACY, number - 1),
        5..=8 => at(&LEGACY, number - 5),
        9..=16 => at(&LEGACY, number - 9),
        17..=24 => at(&LEGACY, number - 17),
        154..=161 => at(&XMM, number - 154),
        // xmm0_0..xmm7_3 (one float lane each).
        162..=193 => at(&XMM, (number - 162) / 4),
        // xmm0l..xmm7l (the low float).
        194..=201 => at(&XMM, number - 194),
        252..=259 => at(&XMM, number - 244),
        260..=291 => at(&XMM, 8 + (number - 260) / 4),
        292..=299 => at(&XMM, number - 284),
        // sil dil bpl spl.
        324 => Some("rsi"),
        325 => Some("rdi"),
        326 => Some("rbp"),
        327 => Some("rsp"),
        328..=335 => at(
            &["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"],
            number - 328,
        ),
        336..=367 => gpr(u8::try_from(8 + (number - 336) % 8).ok()?),
        // ymm0..ymm15 are xmm0..xmm15 for the scorer.
        368..=383 => at(&XMM, number - 368),
        _ => None,
    }
}

/// The register a `CodeView` ARM64 register number (`CV_ARM64_*`) names,
/// lower case: `x0`..`x30` (with their `w` halves; `fp` is `x29`, `lr`
/// `x30`), `sp`, and `v0`..`v31` (with their `b`, `h`, `s`, `d` and `q`
/// views). The zero registers hold nothing.
fn aarch64_register(number: u16) -> Option<&'static str> {
    const X: [&str; 31] = [
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
        "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
        "x27", "x28", "x29", "x30",
    ];
    const V: [&str; 32] = [
        "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13",
        "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26",
        "v27", "v28", "v29", "v30", "v31",
    ];
    let at = |table: &'static [&'static str], index: u16| table.get(usize::from(index)).copied();
    match number {
        // w0..w30.
        10..=40 => at(&X, number - 10),
        // x0..x28, fp, lr.
        50..=80 => at(&X, number - 50),
        81 => Some("sp"),
        // s0..s31, d0..d31, q0..q31, b0..b31, h0..h31.
        100..=131 => at(&V, number - 100),
        140..=171 => at(&V, number - 140),
        180..=211 => at(&V, number - 180),
        230..=261 => at(&V, number - 230),
        270..=301 => at(&V, number - 270),
        _ => None,
    }
}

/// The type table being built: `pdb2`'s finder and the converted types.
struct Types<'t> {
    finder: TypeFinder<'t>,
    /// Class, union and enum definitions by unique name and by name, for
    /// forward references.
    definitions: HashMap<Vec<u8>, TypeIndex>,
    bad: HashSet<u32>,
    converted: HashMap<u32, TypeId>,
    model: DebugModel,
}

impl<'t> Types<'t> {
    fn new(tpi: &'t TypeInformation<'_>, bad: HashSet<u32>, model: DebugModel) -> Self {
        let mut types = Self {
            finder: tpi.finder(),
            definitions: HashMap::new(),
            bad,
            converted: HashMap::new(),
            model,
        };
        let mut items = tpi.iter();
        loop {
            match items.next() {
                Ok(Some(item)) => {
                    types.finder.update(&items);
                    if types.bad.contains(&item.index().0) {
                        continue;
                    }
                    let names = match item.parse() {
                        Ok(TypeData::Class(class)) if !class.properties.forward_reference() => {
                            [class.unique_name, Some(class.name)]
                        }
                        Ok(TypeData::Union(union)) if !union.properties.forward_reference() => {
                            [union.unique_name, Some(union.name)]
                        }
                        Ok(TypeData::Enumeration(enumeration))
                            if !enumeration.properties.forward_reference() =>
                        {
                            [enumeration.unique_name, Some(enumeration.name)]
                        }
                        Ok(_) | Err(_) => continue,
                    };
                    for name in names.into_iter().flatten() {
                        types
                            .definitions
                            .entry(name.as_bytes().to_vec())
                            .or_insert(item.index());
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    types.damage("TPI".to_owned(), &error);
                    break;
                }
            }
        }
        types
    }

    fn damage(&mut self, at: String, error: &impl ToString) {
        self.model.damage.push(Damage {
            at,
            message: error.to_string(),
        });
    }

    fn push(&mut self, ty: Type) -> TypeId {
        let id = TypeId(u32::try_from(self.model.types.len()).unwrap_or(u32::MAX));
        self.model.types.push(ty);
        id
    }

    fn parse(&mut self, index: TypeIndex) -> Option<TypeData<'t>> {
        if self.bad.contains(&index.0) {
            return None;
        }
        match self.finder.find(index).and_then(|item| item.parse()) {
            Ok(data) => Some(data),
            Err(error) => {
                self.damage(format!("TPI {:#x}", index.0), &error);
                None
            }
        }
    }

    /// The definition a forward reference names, if the PDB has one.
    fn definition(
        &self,
        unique: Option<pdb2::RawString<'_>>,
        name: pdb2::RawString<'_>,
    ) -> Option<TypeIndex> {
        unique
            .and_then(|unique| self.definitions.get(unique.as_bytes()))
            .or_else(|| self.definitions.get(name.as_bytes()))
            .copied()
    }

    fn ty(&mut self, index: TypeIndex) -> TypeId {
        self.ty_within(index, TYPE_DEPTH)
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "pdb2's TypeData is non-exhaustive; only these kinds lead elsewhere"
    )]
    fn ty_within(&mut self, index: TypeIndex, depth: u32) -> TypeId {
        if let Some(&id) = self.converted.get(&index.0) {
            return id;
        }
        let Some(depth) = depth.checked_sub(1) else {
            return self.push(Type::Unknown);
        };
        let Some(data) = self.parse(index) else {
            return self.push(Type::Unknown);
        };
        // Looked through, or the definition of a forward reference: the
        // same id as what they lead to.
        let through = match &data {
            TypeData::Modifier(modifier) => Some(modifier.underlying_type),
            TypeData::Bitfield(bitfield) => Some(bitfield.underlying_type),
            TypeData::Class(class) if class.properties.forward_reference() => {
                self.definition(class.unique_name, class.name)
            }
            TypeData::Union(union) if union.properties.forward_reference() => {
                self.definition(union.unique_name, union.name)
            }
            TypeData::Enumeration(enumeration) if enumeration.properties.forward_reference() => {
                self.definition(enumeration.unique_name, enumeration.name)
            }
            _ => None,
        };
        if let Some(target) = through.filter(|target| target.0 != index.0) {
            let id = self.ty_within(target, depth);
            self.converted.insert(index.0, id);
            return id;
        }
        // Recorded before its parts are converted, so a type reaching
        // itself ends.
        let id = self.push(Type::Unknown);
        self.converted.insert(index.0, id);
        let ty = self.convert(&data, depth);
        if let Some(slot) = usize::try_from(id.0)
            .ok()
            .and_then(|index| self.model.types.get_mut(index))
        {
            *slot = ty;
        }
        id
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "pdb2's TypeData is non-exhaustive; the other kinds are no variable's type"
    )]
    fn convert(&mut self, data: &TypeData<'t>, depth: u32) -> Type {
        match data {
            TypeData::Primitive(primitive) => self.primitive(*primitive),
            TypeData::Pointer(pointer) => {
                if pointer.attributes.pointer_to_member() {
                    return Type::Unknown;
                }
                Type::Pointer {
                    target: self.ty_within(pointer.underlying_type, depth),
                    bytes: u64::from(pointer.attributes.size()),
                }
            }
            TypeData::Array(array) => self.array(array.element_type, &array.dimensions, depth),
            TypeData::Class(class) => {
                let kind = match class.kind {
                    ClassKind::Class => CompositeKind::Class,
                    ClassKind::Struct | ClassKind::Interface => CompositeKind::Struct,
                };
                let forward = class.properties.forward_reference();
                let fields = match class.fields {
                    Some(list) if !forward => self.fields(list, depth),
                    Some(_) | None => Vec::new(),
                };
                Type::Composite(Composite {
                    kind,
                    name: Some(class.name.to_string().into_owned()),
                    size: (!forward).then_some(class.size),
                    fields,
                })
            }
            TypeData::Union(union) => {
                let forward = union.properties.forward_reference();
                Type::Composite(Composite {
                    kind: CompositeKind::Union,
                    name: Some(union.name.to_string().into_owned()),
                    size: (!forward).then_some(union.size),
                    fields: if forward {
                        Vec::new()
                    } else {
                        self.fields(union.fields, depth)
                    },
                })
            }
            TypeData::Enumeration(enumeration) => {
                let underlying = self.ty_within(enumeration.underlying_type, depth);
                let (bytes, signed) = match self.model.ty(underlying) {
                    Type::Base {
                        bytes, encoding, ..
                    } => (
                        *bytes,
                        matches!(encoding, Encoding::Signed | Encoding::Char { signed: true }),
                    ),
                    Type::Void
                    | Type::Pointer { .. }
                    | Type::Array { .. }
                    | Type::Composite(_)
                    | Type::Enum { .. }
                    | Type::Typedef { .. }
                    | Type::Function { .. }
                    | Type::Unknown => (4, true),
                };
                Type::Enum {
                    name: Some(enumeration.name.to_string().into_owned()),
                    bytes,
                    signed,
                }
            }
            TypeData::Alias(alias) => Type::Typedef {
                name: alias.name.to_string().into_owned(),
                target: self.ty_within(alias.underlying_type, depth),
            },
            TypeData::Procedure(procedure) => {
                let returns = match procedure.return_type {
                    Some(ty) => self.ty_within(ty, depth),
                    None => self.push(Type::Void),
                };
                self.function(returns, procedure.argument_list, depth)
            }
            TypeData::MemberFunction(function) => {
                let returns = self.ty_within(function.return_type, depth);
                self.function(returns, function.argument_list, depth)
            }
            // Pointers to members are not modelled; modifiers, bit-fields
            // and forward references only reach here when they refer to
            // themselves.
            _ => Type::Unknown,
        }
    }

    fn primitive(&mut self, primitive: PrimitiveType) -> Type {
        let base = primitive_type(primitive.kind);
        let Some(indirection) = primitive.indirection else {
            return base;
        };
        let bytes = match indirection {
            Indirection::Near16 | Indirection::Far16 | Indirection::Huge16 => 2,
            Indirection::Near32 | Indirection::Far32 => 4,
            Indirection::Near64 => 8,
            Indirection::Near128 => 16,
        };
        Type::Pointer {
            target: self.push(base),
            bytes,
        }
    }

    /// An array: `dimensions` are byte sizes, each holding the ones before
    /// it (`float[4][4]` is `[16, 64]`).
    fn array(&mut self, element: TypeIndex, dimensions: &[u32], depth: u32) -> Type {
        let mut element = self.ty_within(element, depth);
        let mut ty = Type::Array {
            element,
            count: None,
        };
        for (position, &bytes) in dimensions.iter().enumerate() {
            let count = self
                .model
                .size(element)
                .filter(|&size| size != 0)
                .map(|size| u64::from(bytes) / size);
            ty = Type::Array { element, count };
            if position + 1 < dimensions.len() {
                element = self.push(ty.clone());
            }
        }
        ty
    }

    fn function(&mut self, returns: TypeId, arguments: TypeIndex, depth: u32) -> Type {
        let (parameters, variadic) = self.arguments(arguments, depth);
        Type::Function {
            returns,
            parameters,
            variadic,
        }
    }

    /// An argument list's types, and whether it ends in `...` (a
    /// `T_NOTYPE` argument).
    fn arguments(&mut self, list: TypeIndex, depth: u32) -> (Vec<TypeId>, bool) {
        let Some(TypeData::ArgumentList(list)) = self.parse(list) else {
            return (Vec::new(), false);
        };
        let mut arguments = list.arguments.as_slice();
        let variadic = arguments.last().is_some_and(|last| last.0 == 0);
        if variadic {
            arguments = arguments.split_last().map_or(&[], |(_, rest)| rest);
        }
        let types = arguments
            .iter()
            .map(|&argument| self.ty_within(argument, depth))
            .collect();
        (types, variadic)
    }

    /// The data members and base classes of a field list (and its
    /// continuations).
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "pdb2's TypeData is non-exhaustive; methods, nested and static members are no data"
    )]
    fn fields(&mut self, mut list: TypeIndex, depth: u32) -> Vec<Field> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        while seen.insert(list.0) {
            let Some(TypeData::FieldList(fields)) = self.parse(list) else {
                break;
            };
            for field in &fields.fields {
                match field {
                    TypeData::Member(member) => {
                        let bits = match self.parse(member.field_type) {
                            Some(TypeData::Bitfield(bitfield)) => {
                                Some((u64::from(bitfield.position), u64::from(bitfield.length)))
                            }
                            _ => None,
                        };
                        out.push(Field {
                            name: Some(member.name.to_string().into_owned()),
                            offset: member.offset,
                            ty: self.ty_within(member.field_type, depth),
                            bits,
                        });
                    }
                    TypeData::BaseClass(base) => out.push(Field {
                        name: None,
                        offset: u64::from(base.offset),
                        ty: self.ty_within(base.base_class, depth),
                        bits: None,
                    }),
                    _ => {}
                }
            }
            match fields.continuation {
                Some(next) => list = next,
                None => break,
            }
        }
        out
    }

    /// A procedure type's return type and argument count (with `this`).
    fn signature(&mut self, index: TypeIndex) -> (TypeId, Vec<TypeId>, bool) {
        match self.parse(index) {
            Some(TypeData::Procedure(procedure)) => {
                let returns = match procedure.return_type {
                    Some(ty) => self.ty(ty),
                    None => self.push(Type::Void),
                };
                let (arguments, variadic) = self.arguments(procedure.argument_list, TYPE_DEPTH);
                (returns, arguments, variadic)
            }
            Some(TypeData::MemberFunction(function)) => {
                let returns = self.ty(function.return_type);
                let mut arguments = Vec::new();
                if let Some(this) = function.this_pointer_type {
                    arguments.push(self.ty(this));
                }
                let (rest, variadic) = self.arguments(function.argument_list, TYPE_DEPTH);
                arguments.extend(rest);
                (returns, arguments, variadic)
            }
            _ => (self.push(Type::Unknown), Vec::new(), false),
        }
    }
}

/// A primitive type's name (as `llvm-pdbutil` prints it), width and
/// encoding.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "pdb2's PrimitiveKind is non-exhaustive"
)]
fn primitive_type(kind: PrimitiveKind) -> Type {
    use Encoding::{Bool, Char, Float, Other, Signed, Unsigned};
    let (name, bytes, encoding) = match kind {
        PrimitiveKind::Void => return Type::Void,
        PrimitiveKind::Char => ("signed char", 1, Char { signed: true }),
        PrimitiveKind::UChar => ("unsigned char", 1, Char { signed: false }),
        PrimitiveKind::RChar => ("char", 1, Char { signed: true }),
        PrimitiveKind::WChar => ("wchar_t", 2, Char { signed: false }),
        PrimitiveKind::RChar16 => ("char16_t", 2, Char { signed: false }),
        PrimitiveKind::RChar32 => ("char32_t", 4, Char { signed: false }),
        PrimitiveKind::Char8 => ("char8_t", 1, Char { signed: false }),
        PrimitiveKind::I8 => ("__int8", 1, Signed),
        PrimitiveKind::U8 => ("unsigned __int8", 1, Unsigned),
        PrimitiveKind::Short => ("short", 2, Signed),
        PrimitiveKind::UShort => ("unsigned short", 2, Unsigned),
        PrimitiveKind::I16 => ("__int16", 2, Signed),
        PrimitiveKind::U16 => ("unsigned __int16", 2, Unsigned),
        PrimitiveKind::Long => ("long", 4, Signed),
        PrimitiveKind::ULong => ("unsigned long", 4, Unsigned),
        PrimitiveKind::I32 => ("int", 4, Signed),
        PrimitiveKind::U32 => ("unsigned", 4, Unsigned),
        PrimitiveKind::HRESULT => ("HRESULT", 4, Signed),
        PrimitiveKind::Quad | PrimitiveKind::I64 => ("__int64", 8, Signed),
        PrimitiveKind::UQuad | PrimitiveKind::U64 => ("unsigned __int64", 8, Unsigned),
        PrimitiveKind::Octa | PrimitiveKind::I128 => ("__int128", 16, Signed),
        PrimitiveKind::UOcta | PrimitiveKind::U128 => ("unsigned __int128", 16, Unsigned),
        PrimitiveKind::F16 => ("__half", 2, Float),
        PrimitiveKind::F32 | PrimitiveKind::F32PP => ("float", 4, Float),
        PrimitiveKind::F48 => ("__float48", 6, Float),
        PrimitiveKind::F64 => ("double", 8, Float),
        PrimitiveKind::F80 => ("long double", 10, Float),
        PrimitiveKind::F128 => ("__float128", 16, Float),
        PrimitiveKind::Complex32 => ("_Complex float", 8, Other),
        PrimitiveKind::Complex64 => ("_Complex double", 16, Other),
        PrimitiveKind::Complex80 => ("_Complex long double", 20, Other),
        PrimitiveKind::Complex128 => ("_Complex __float128", 32, Other),
        PrimitiveKind::Bool8 => ("bool", 1, Bool),
        PrimitiveKind::Bool16 => ("__bool16", 2, Bool),
        PrimitiveKind::Bool32 => ("__bool32", 4, Bool),
        PrimitiveKind::Bool64 => ("__bool64", 8, Bool),
        _ => return Type::Unknown,
    };
    Type::Base {
        name: name.to_owned(),
        bytes,
        encoding,
    }
}

/// A place as a symbol states it, before the frame is known.
#[derive(Clone, Debug)]
enum Raw {
    Register(&'static str),
    /// A register (after the prologue) plus an offset.
    Relative(&'static str, i64),
    /// The frame pointer `S_FRAMEPROC` names plus an offset.
    Frame(i64),
    Other,
}

/// A variable symbol of the open procedure.
#[derive(Debug)]
struct Pending {
    name: String,
    ty: TypeIndex,
    /// `S_LOCAL`: whether it is a parameter; the older symbols: `None`.
    parameter: Option<bool>,
    spans: Vec<(Range<u64>, Raw)>,
}

/// The procedure whose symbols are being read.
#[derive(Debug)]
struct Open {
    entry: u64,
    range: Range<u64>,
    name: String,
    ty: TypeIndex,
    variables: Vec<Pending>,
    /// `S_FRAMEPROC`'s encoded local and parameter base pointers.
    base_pointers: (u8, u8),
}

/// What the scopes inside a procedure are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Procedure,
    Block,
    Inline,
}

struct Reader<'a, 's> {
    machine: Machine,
    base: u64,
    address_map: &'a AddressMap<'s>,
    frames: HashMap<u32, Frame>,
    /// The IPI stream's ids, if the PDB has one.
    ids: Option<&'a IdFinder<'a>>,
}

impl Reader<'_, '_> {
    fn address(&self, offset: PdbInternalSectionOffset) -> Option<u64> {
        let rva = offset.to_rva(self.address_map)?;
        self.base.checked_add(u64::from(rva.0))
    }

    /// The id `id` as a string (its substrings, then its own text).
    fn string(&self, id: IdIndex) -> Option<String> {
        let ids = self.ids?;
        let IdData::String(string) = ids.find(id).ok()?.parse().ok()? else {
            return None;
        };
        let mut text = String::new();
        if let Some(list) = string.substrings
            && let Ok(IdData::StringList(list)) = ids.find(list).and_then(|item| item.parse())
        {
            for part in list.substrings {
                if let Ok(IdData::String(part)) =
                    ids.find(IdIndex(part.0)).and_then(|item| item.parse())
                {
                    text.push_str(&part.name.to_string());
                }
            }
        }
        text.push_str(&string.name.to_string());
        Some(text)
    }

    /// The unit of module `module`, whose build information (`S_BUILDINFO`)
    /// is `build` and whose compile flags state `language`: its source
    /// file and current directory, else the module's name.
    fn unit(&self, module: &str, build: Option<IdIndex>, language: Language) -> Unit {
        let arguments = build.and_then(|id| {
            if let IdData::BuildInfo(info) = self.ids?.find(id).ok()?.parse().ok()? {
                Some(info.arguments)
            } else {
                None
            }
        });
        let argument = |index: usize| {
            let id = *arguments.as_ref()?.get(index)?;
            self.string(id).filter(|text| !text.is_empty())
        };
        match argument(BUILD_SOURCE) {
            Some(name) => Unit {
                name,
                directory: argument(BUILD_DIRECTORY),
                language,
            },
            None => Unit {
                name: module.to_owned(),
                directory: None,
                language,
            },
        }
    }

    /// `range` without its gaps, as addresses.
    fn spans(
        &self,
        range: &pdb2::AddressRange,
        gaps: &[pdb2::AddressGap],
        raw: &Raw,
    ) -> Vec<(Range<u64>, Raw)> {
        let Some(start) = self.address(range.offset) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut from = start;
        let end = start + u64::from(range.cb_range);
        let mut gaps: Vec<_> = gaps.iter().collect();
        gaps.sort_by_key(|gap| gap.gap_start_offset);
        for gap in gaps {
            let gap_start = start + u64::from(gap.gap_start_offset);
            if from < gap_start {
                out.push((from..gap_start.min(end), raw.clone()));
            }
            from = from.max(gap_start + u64::from(gap.cb_range));
        }
        if from < end {
            out.push((from..end, raw.clone()));
        }
        out
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "pdb2's SymbolData is non-exhaustive; the rest go to `variable`"
    )]
    fn module(&mut self, name: &str, info: &pdb2::ModuleInfo<'_>, types: &mut Types<'_>) {
        let mut symbols = match info.symbols() {
            Ok(symbols) => symbols,
            Err(error) => return types.damage(format!("module {name}"), &error),
        };
        let mut open: Option<Open> = None;
        let mut scopes: Vec<Scope> = Vec::new();
        let mut build = None;
        let mut language = Language::Other;
        // The module's unit, recorded with its first function.
        let mut unit: Option<UnitId> = None;
        loop {
            let symbol = match symbols.next() {
                Ok(Some(symbol)) => symbol,
                Ok(None) => break,
                Err(error) => {
                    types.damage(format!("module {name}"), &error);
                    break;
                }
            };
            if matches!(symbol.raw_kind(), S_CALLEES | S_CALLERS) {
                continue;
            }
            let data = match symbol.parse() {
                Ok(data) => data,
                // Kinds `pdb2` does not know are not variables.
                Err(pdb2::Error::UnimplementedSymbolKind(_)) => continue,
                Err(error) => {
                    types.damage(format!("module {name} symbol {}", symbol.index()), &error);
                    continue;
                }
            };
            let own = scopes.first() == Some(&Scope::Procedure) && !scopes.contains(&Scope::Inline);
            match data {
                SymbolData::Procedure(procedure) => {
                    if !scopes.is_empty() {
                        scopes.push(Scope::Block);
                        continue;
                    }
                    scopes.push(Scope::Procedure);
                    open = self.address(procedure.offset).map(|entry| Open {
                        entry,
                        range: entry..entry + u64::from(procedure.len),
                        name: procedure.name.to_string().into_owned(),
                        ty: procedure.type_index,
                        variables: Vec::new(),
                        base_pointers: (0, 0),
                    });
                }
                SymbolData::Block(_) | SymbolData::Thunk(_) | SymbolData::SeparatedCode(_) => {
                    scopes.push(Scope::Block);
                }
                SymbolData::InlineSite(_) => scopes.push(Scope::Inline),
                SymbolData::ScopeEnd | SymbolData::ProcedureEnd | SymbolData::InlineSiteEnd => {
                    if scopes.pop() == Some(Scope::Procedure)
                        && let Some(open) = open.take()
                    {
                        let mut function = self.finish(open, types);
                        if !types.model.functions.contains_key(&function.entry) {
                            let id = *unit.get_or_insert_with(|| {
                                types.model.push_unit(self.unit(name, build, language))
                            });
                            function.unit = Some(id);
                            types.model.functions.insert(function.entry, function);
                        }
                    }
                }
                SymbolData::BuildInfo(info) if scopes.is_empty() => build = Some(info.id),
                SymbolData::CompileFlags(flags) if scopes.is_empty() => {
                    if flags.language == pdb2::SourceLanguage::C {
                        language = Language::C;
                    }
                }
                data => {
                    if let SymbolData::Data(symbol) = &data
                        && scopes.is_empty()
                    {
                        self.global(symbol, types);
                    } else if own && let Some(open) = open.as_mut() {
                        self.variable(open, data);
                    }
                }
            }
        }
    }

    /// The global symbol stream's data symbols (`S_GDATA32`,
    /// `S_LDATA32`) as globals, its public symbols of code (`S_PUB32`) as
    /// names.
    fn globals(&self, table: &SymbolTable<'_>, types: &mut Types<'_>) {
        let mut symbols = table.iter();
        loop {
            match symbols.next() {
                Ok(Some(symbol)) => match symbol.parse() {
                    Ok(SymbolData::Data(data)) => self.global(&data, types),
                    Ok(SymbolData::Public(public)) if public.code || public.function => {
                        if let Some(address) = self.address(public.offset) {
                            types
                                .model
                                .publics
                                .entry(address)
                                .or_insert_with(|| public.name.to_string().into_owned());
                        }
                    }
                    Ok(_) | Err(_) => {}
                },
                Ok(None) => break,
                Err(error) => {
                    types.damage("global symbols".to_owned(), &error);
                    break;
                }
            }
        }
    }

    /// Records data symbol `data` as a global at its address (the first
    /// one stated there).
    fn global(&self, data: &DataSymbol<'_>, types: &mut Types<'_>) {
        let Some(address) = self.address(data.offset) else {
            return;
        };
        if types.model.globals.contains_key(&address) {
            return;
        }
        let ty = types.ty(data.type_index);
        types.model.globals.insert(
            address,
            Global {
                name: data.name.to_string().into_owned(),
                ty,
            },
        );
    }

    /// A variable symbol, or a range of the last `S_LOCAL`.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "pdb2's SymbolData is non-exhaustive; other symbols state no variable"
    )]
    fn variable(&self, open: &mut Open, data: SymbolData<'_>) {
        let whole = open.range.clone();
        let older = |name: pdb2::RawString<'_>, ty, raw| Pending {
            name: name.to_string().into_owned(),
            ty,
            parameter: None,
            spans: vec![(whole.clone(), raw)],
        };
        let ranges = |open: &mut Open, spans: Vec<(Range<u64>, Raw)>| {
            if let Some(last) = open.variables.last_mut()
                && last.parameter.is_some()
            {
                last.spans.extend(spans);
            }
        };
        match data {
            SymbolData::Local(local) => open.variables.push(Pending {
                name: local.name.to_string().into_owned(),
                ty: local.type_index,
                parameter: Some(local.flags.isparam),
                spans: Vec::new(),
            }),
            SymbolData::RegisterVariable(symbol) => {
                let raw = self
                    .machine
                    .register(symbol.register.0)
                    .map_or(Raw::Other, Raw::Register);
                open.variables
                    .push(older(symbol.name, symbol.type_index, raw));
            }
            SymbolData::RegisterRelative(symbol) => {
                let raw = self
                    .machine
                    .register(symbol.register.0)
                    .map_or(Raw::Other, |register| {
                        Raw::Relative(register, i64::from(symbol.offset))
                    });
                open.variables
                    .push(older(symbol.name, symbol.type_index, raw));
            }
            SymbolData::BasePointerRelative(symbol) => {
                let raw = Raw::Relative(self.machine.frame_pointer(), i64::from(symbol.offset));
                open.variables
                    .push(older(symbol.name, symbol.type_index, raw));
            }
            SymbolData::DefRangeRegister(symbol) => {
                let raw = self
                    .machine
                    .register(symbol.register.0)
                    .map_or(Raw::Other, Raw::Register);
                ranges(open, self.spans(&symbol.range, &symbol.gaps, &raw));
            }
            SymbolData::DefRangeRegisterRelative(DefRangeRegisterRelativeSymbol {
                base_register,
                offset_base_pointer,
                spilled_udt_member,
                range,
                gaps,
                ..
            }) => {
                let raw = match self.machine.register(base_register.0) {
                    Some(register) if spilled_udt_member == 0 => {
                        Raw::Relative(register, i64::from(offset_base_pointer))
                    }
                    Some(_) | None => Raw::Other,
                };
                ranges(open, self.spans(&range, &gaps, &raw));
            }
            SymbolData::DefRangeFramePointerRelative(symbol) => {
                let raw = Raw::Frame(i64::from(symbol.offset));
                ranges(open, self.spans(&symbol.range, &symbol.gaps, &raw));
            }
            SymbolData::DefRangeFramePointerRelativeFullScope(symbol) => {
                ranges(
                    open,
                    vec![(whole.clone(), Raw::Frame(i64::from(symbol.offset)))],
                );
            }
            SymbolData::DefRange(pdb2::DefRangeSymbol { range, gaps, .. })
            | SymbolData::DefRangeSubField(pdb2::DefRangeSubFieldSymbol { range, gaps, .. })
            | SymbolData::DefRangeSubFieldRegister(pdb2::DefRangeSubFieldRegisterSymbol {
                range,
                gaps,
                ..
            }) => ranges(open, self.spans(&range, &gaps, &Raw::Other)),
            SymbolData::FrameProcedure(frame) => {
                open.base_pointers = (
                    frame.flags.encoded_local_base_pointer,
                    frame.flags.encoded_param_base_pointer,
                );
            }
            _ => {}
        }
    }

    /// The function of a closed procedure: places resolved against its
    /// frame, parameters told from locals.
    fn finish(&self, open: Open, types: &mut Types<'_>) -> Function {
        let (returns, arguments, variadic) = types.signature(open.ty);
        let frame = open
            .entry
            .checked_sub(self.base)
            .and_then(|rva| u32::try_from(rva).ok())
            .and_then(|rva| self.frames.get(&rva))
            .cloned()
            .unwrap_or(self.machine.leaf());
        let flagged = open
            .variables
            .iter()
            .any(|variable| variable.parameter == Some(true));
        let stated: HashSet<String> = open
            .variables
            .iter()
            .filter(|variable| variable.parameter.is_some())
            .map(|variable| variable.name.clone())
            .collect();
        let mut parameters = Vec::new();
        let mut locals = Vec::new();
        for pending in open.variables {
            let is_parameter = match pending.parameter {
                Some(parameter) => parameter,
                // The home slots of the parameters (and the stack copies of
                // locals) an `S_LOCAL` states.
                None if stated.contains(&pending.name) => continue,
                None => !flagged && parameters.len() < arguments.len(),
            };
            let encoded = if is_parameter {
                open.base_pointers.1
            } else {
                open.base_pointers.0
            };
            let variable = Variable {
                name: Some(pending.name),
                ty: types.ty(pending.ty),
                location: pending
                    .spans
                    .into_iter()
                    .map(|(range, raw)| Span {
                        place: place(
                            &raw,
                            &frame,
                            self.machine.base_pointer(encoded),
                            // A whole-function symbol states its place
                            // after the prologue; a live range where it
                            // starts.
                            if range == open.range {
                                u64::MAX
                            } else {
                                range.start.saturating_sub(open.entry)
                            },
                        ),
                        range,
                    })
                    .collect(),
            };
            if is_parameter {
                parameters.push(variable);
            } else {
                locals.push(variable);
            }
        }
        Function {
            entry: open.entry,
            name: Some(open.name),
            parameters,
            returns,
            variadic,
            arity: Some(arguments.len()),
            locals,
            unit: None,
        }
    }
}

/// A symbol's place against the function's frame, `at` bytes into the
/// function (`base`: the register `S_FRAMEPROC`'s base pointer for the
/// variable's kind names).
fn place(raw: &Raw, frame: &Frame, base: Option<&'static str>, at: u64) -> Place {
    let relative = |register: &'static str, offset: i64| {
        frame
            .stack(register, offset, at)
            .map_or(Place::Relative { register, offset }, Place::Stack)
    };
    match *raw {
        Raw::Register(register) => Place::Register(register),
        Raw::Relative(register, offset) => relative(register, offset),
        Raw::Frame(offset) => base.map_or(Place::Other, |register| relative(register, offset)),
        Raw::Other => Place::Other,
    }
}
