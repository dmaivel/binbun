//! What an instruction without semantics may change must be what
//! `lift_opaque` makes unknown, or analyses built on it would keep stale
//! values: checked on words of every encoding the decoder knows.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::{BTreeMap, BTreeSet};

use binbun_aarch64::operand::{Register, RegisterClass, Writeback};
use binbun_aarch64::{FlagSet, Instruction, MemoryKind, Operand, decode};
use binbun_aarch64_lift::registers::{self, C, FPCR, FPSR, N, SP, V, Z};
use binbun_aarch64_lift::{AARCH64, lift_opaque, opaque_outputs};
use binbun_isa::Flow;
use binbun_semantics::Semantics;
use binbun_semantics::ir::{Binary, Expr, RegisterId, Stmt, View};
use binbun_semantics::text::{parse, print};
use binbun_semantics::verify::verify;
use xtask::aarchmrs::Package;

const PACKAGE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../third_party/aarchmrs/AARCHMRS_OPENSOURCE_A_profile_FAT-2026-09.tar.gz"
);

const ADDRESS: u64 = 0x40_1000;

/// What `semantics` writes anywhere: registers, stores, intrinsics.
#[derive(Default)]
struct Written {
    registers: BTreeSet<RegisterId>,
    stores: usize,
    intrinsics: usize,
}

fn written(statements: &[Stmt], out: &mut Written) {
    for statement in statements {
        match statement {
            Stmt::Write { view, .. } => {
                out.registers.insert(view.register);
            }
            Stmt::Store { .. } => out.stores += 1,
            Stmt::Intrinsic { .. } => out.intrinsics += 1,
            Stmt::If {
                then, otherwise, ..
            } => {
                written(then, out);
                written(otherwise, out);
            }
            Stmt::Loop(body) | Stmt::Atomic(body) => written(body, out),
            Stmt::Read { .. }
            | Stmt::Load { .. }
            | Stmt::Break
            | Stmt::Trap(_)
            | Stmt::Jump { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::SystemCall => {}
        }
    }
}

/// The L0 register an operand register lives in, if it is L0 state.
fn state(register: Register) -> Option<RegisterId> {
    match register.class {
        RegisterClass::W | RegisterClass::X | RegisterClass::Wsp | RegisterClass::Xsp => {
            registers::general(register).map(|view| view.register)
        }
        RegisterClass::B
        | RegisterClass::H
        | RegisterClass::S
        | RegisterClass::D
        | RegisterClass::Q
        | RegisterClass::V
        | RegisterClass::Z => Some(registers::v(register.number)),
        RegisterClass::P
        | RegisterClass::Pn
        | RegisterClass::Zt
        | RegisterClass::C
        | RegisterClass::Ffr => None,
    }
}

/// The registers L0 must see written by `instruction`, by its metadata.
fn expected(instruction: Instruction) -> BTreeSet<RegisterId> {
    let mut out = BTreeSet::new();
    for (operand, access) in instruction
        .operands()
        .as_slice()
        .iter()
        .zip(&instruction.access())
    {
        if let Operand::Memory(memory) = operand
            && memory.writeback != Writeback::None
        {
            out.extend(state(memory.base));
        }
        if !access.writes() {
            continue;
        }
        if let Operand::Register(register) | Operand::Writeback(register) = *operand {
            out.extend(state(register));
        }
        if let Operand::List(list) = *operand {
            for k in 0..list.count {
                let number = (list.first.number + k * list.stride) % list.registers();
                out.extend(state(Register {
                    number,
                    ..list.first
                }));
            }
        }
    }
    out.extend(
        instruction
            .implicit()
            .writes
            .iter()
            .copied()
            .filter_map(state),
    );
    let flags = instruction.flags().written;
    for (flag, id) in [
        (FlagSet::N, N),
        (FlagSet::Z, Z),
        (FlagSet::C, C),
        (FlagSet::V, V),
    ] {
        if flags.contains(flag) {
            out.insert(id);
        }
    }
    out
}

/// Words of an AARCHMRS encoding: the fixed bits, with the free bits all
/// clear, all set, and random.
fn words(instruction: &xtask::aarchmrs::Instruction, seed: &mut u64) -> Vec<u32> {
    let mut fixed_mask = 0u32;
    let mut fixed_value = 0u32;
    for field in &instruction.encoding.fields {
        let soft = field.should_be_mask.value();
        fixed_mask |= u32::try_from((field.value.mask() & !soft) << field.start).unwrap();
        fixed_value |= u32::try_from((field.value.value() & !soft) << field.start).unwrap();
    }
    let mut words = vec![fixed_value, fixed_value | !fixed_mask];
    for _ in 0..48 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        let random = u32::try_from(*seed >> 32).unwrap();
        words.push((random & !fixed_mask) | fixed_value);
    }
    words
}

/// Every register an operand, an implied register or the flags may write,
/// and every base written back, is written by the over-approximation;
/// stores write memory (a store of fixed size by stores, else through the
/// `unlifted` intrinsic); no output of its intrinsic is wider than C's
/// widest integer (128 bits: `stp q0, q1` stores two), and
/// `opaque_outputs` lists them all; the semantics verify and round-trip
/// through the text form. Words of every encoding the decoder knows that
/// continue with the next instruction.
#[test]
fn opaque_semantics_write_every_register_an_operand_may_write() {
    let package = Package::read(PACKAGE).unwrap();
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut failures = BTreeMap::new();
    let mut encodings = BTreeSet::new();
    let mut checked = 0;
    let mut stores = 0;
    for (_, encoding) in package.a64.encodings() {
        for word in words(encoding, &mut seed) {
            let Ok(instruction) = decode(word) else {
                continue;
            };
            if instruction.flow(ADDRESS) != Flow::Next {
                continue;
            }
            let name = instruction.encoding().name();
            let text = instruction.display(ADDRESS).to_string();
            let semantics = match lift_opaque(&instruction, ADDRESS) {
                Ok(semantics) => semantics,
                Err(error) => {
                    failures.insert(name, format!("{word:#010x} `{text}`: {error:?}"));
                    continue;
                }
            };
            if let Err(error) = verify(&semantics, &AARCH64) {
                failures.insert(name, format!("{word:#010x} `{text}`: {error}"));
                continue;
            }
            if parse(&print(&semantics, &AARCH64), &AARCH64).as_ref() != Ok(&semantics) {
                failures.insert(name, format!("{word:#010x} `{text}`: no round trip"));
            }
            let widths = output_widths(&semantics);
            let listed = opaque_outputs(&instruction, ADDRESS)
                .ok()
                .map(|outputs| outputs.len());
            if widths.iter().any(|&width| width > 128) || listed != Some(widths.len()) {
                failures.insert(
                    name,
                    format!("{word:#010x} `{text}`: outputs {widths:?}, listed {listed:?}"),
                );
            }
            encodings.insert(name);
            let mut wrote = Written::default();
            written(&semantics.body, &mut wrote);
            for id in expected(instruction) {
                checked += 1;
                if !wrote.registers.contains(&id) {
                    failures.insert(
                        name,
                        format!("{word:#010x} `{text}`: {id:?} not made unknown"),
                    );
                }
            }
            if let Some(access) = instruction.memory()
                && matches!(
                    access.kind,
                    MemoryKind::Store
                        | MemoryKind::StoreExclusive
                        | MemoryKind::Atomic
                        | MemoryKind::Copy
                )
            {
                stores += 1;
                let bytes_stored = if access.size > 0 {
                    wrote.stores > 0 || wrote.intrinsics > 0
                } else {
                    wrote.intrinsics > 0
                };
                if !bytes_stored {
                    failures.insert(name, format!("{word:#010x} `{text}`: no memory written"));
                }
            }
        }
    }
    let shown: Vec<&String> = failures.values().collect();
    assert!(
        failures.is_empty(),
        "{} encodings:\n{shown:#?}",
        failures.len()
    );
    // Almost every A64 encoding continues with the next instruction.
    assert!(encodings.len() > 4000, "only {} encodings", encodings.len());
    assert!(
        checked > 100_000 && stores > 10_000,
        "{checked} writes, {stores} stores"
    );
}

/// SP is written back by a pre-indexed store through it, exactly; the
/// stored bytes are derived values; `dc zva` runs `unlifted`, `msr` to a
/// system register `unlifted_registers` (of what it reads, written where
/// L0 has the register); FPSR is written by a floating-point add; a
/// scalar register is as wide as it is (`d15` is `v15`'s low 64 bits),
/// read or written.
#[test]
fn opaque_semantics_of_known_shapes() {
    let lifted = |word: u32| {
        let instruction = decode(word).unwrap();
        let semantics = lift_opaque(&instruction, ADDRESS).unwrap();
        let mut wrote = Written::default();
        written(&semantics.body, &mut wrote);
        (semantics, wrote)
    };
    // str x0, [sp, #-16]!: one 8-byte store; sp becomes sp - 16, not an
    // unknown value.
    let (semantics, wrote) = lifted(0xf81f_0fe0);
    let text = print(&semantics, &AARCH64);
    assert_eq!(wrote.stores, 1, "{text}");
    let sp = semantics.body.iter().find_map(|statement| {
        if let Stmt::Write { view, value } = statement
            && view.register == SP
        {
            Some(*value)
        } else {
            None
        }
    });
    assert!(
        matches!(
            semantics.expr(sp.unwrap()),
            Some((Expr::Binary(Binary::Add, _, _), 64))
        ),
        "{text}"
    );
    // dc zva, x0
    let (semantics, _) = lifted(0xd50b_7420);
    assert_eq!(
        intrinsics(&semantics),
        ["unlifted"],
        "{}",
        print(&semantics, &AARCH64)
    );
    // msr fpmr, x9 writes a system register L0 does not declare: x9 may be
    // read back from there, so it is an input of the intrinsic, and
    // nothing L0 has is written; msr fpcr, x9 writes fpcr.
    let (semantics, wrote) = lifted(0xd51b_4449);
    assert!(
        intrinsics(&semantics) == ["unlifted_registers"]
            && reads(&semantics)
                .iter()
                .any(|view| view.register == registers::x(9))
            && wrote.registers.iter().all(|&id| id == registers::BTYPE),
        "{}",
        print(&semantics, &AARCH64)
    );
    let (semantics, wrote) = lifted(0xd51b_4409);
    assert!(
        intrinsics(&semantics) == ["unlifted_registers"] && wrote.registers.contains(&FPCR),
        "{}",
        print(&semantics, &AARCH64)
    );
    // fadd d0, d1, d2
    let (semantics, wrote) = lifted(0x1e62_2820);
    assert!(
        wrote.registers.contains(&registers::v(0)) && wrote.registers.contains(&FPSR),
        "{}",
        print(&semantics, &AARCH64)
    );
    // b is a control transfer: not over-approximated.
    assert!(lift_opaque(&decode(0x1400_0010).unwrap(), ADDRESS).is_err());
    // str d15, [sp, #0x18] reads v15's low 64 bits, not v15 whole (which
    // made a caller pass `unsigned __int128`); ldr d15, [x2, #0xa0] makes
    // v15 a 64-bit output zero-extended.
    let v15 = registers::v(15);
    let (semantics, _) = lifted(0xfd00_0fef);
    let read: Vec<u16> = reads(&semantics)
        .iter()
        .filter(|view| view.register == v15)
        .map(|view| view.width)
        .collect();
    assert_eq!(read, [64], "{}", print(&semantics, &AARCH64));
    let (semantics, wrote) = lifted(0xfd40_504f);
    let outputs = output_widths(&semantics);
    assert!(
        wrote.registers.contains(&v15) && outputs.contains(&64) && !outputs.contains(&128),
        "{}",
        print(&semantics, &AARCH64)
    );
    // stp q0, q1, [sp]: 32 bytes stored, two 128-bit outputs.
    let (semantics, wrote) = lifted(0xad00_07e0);
    assert!(
        wrote.stores == 1 && output_widths(&semantics).starts_with(&[128, 128]),
        "{}",
        print(&semantics, &AARCH64)
    );
}

/// The widths of the outputs of the intrinsics `semantics` runs, in order.
fn output_widths(semantics: &Semantics) -> Vec<u16> {
    semantics
        .body
        .iter()
        .filter_map(|statement| {
            if let Stmt::Intrinsic { outputs, .. } = statement {
                Some(outputs)
            } else {
                None
            }
        })
        .flatten()
        .map(|local| semantics.locals[local.0 as usize])
        .collect()
}

/// The names of the intrinsics `semantics` runs, in order.
fn intrinsics(semantics: &Semantics) -> Vec<&'static str> {
    semantics
        .body
        .iter()
        .filter_map(|statement| {
            if let Stmt::Intrinsic { intrinsic, .. } = statement {
                AARCH64.intrinsic(*intrinsic).map(|info| info.name)
            } else {
                None
            }
        })
        .collect()
}

/// The register views `semantics` reads.
fn reads(semantics: &Semantics) -> Vec<View> {
    semantics
        .body
        .iter()
        .filter_map(|statement| {
            if let Stmt::Read { view, .. } = statement {
                Some(*view)
            } else {
                None
            }
        })
        .collect()
}
