//! The checker on purpose: hand-written L0 for five of the dozen
//! encodings (`subs`, `add`, `b.eq`, `ldr`, `stp`), each right and with a
//! deliberate bug of a kind semantics really get wrong (x86's borrow for
//! Arm's carry, flags written by a non-flag-setting form, the wrong flag
//! tested, an unscaled offset, the SP alignment check forgotten).
//! The right ones must be proved equivalent to sail-arm, the buggy ones
//! must get a counterexample that shows the bug.
//!
//! And an encoding UNDEFINED in the execution context (`subp`, `FEAT_MTE`
//! not implemented): Sail's decode throws `Error_Undefined`, which must be
//! the processor's UNDEFINED exception, so an L0 that traps is proved and
//! one that completes is refuted.
//!
//! Needs z3 on the `PATH` and the Jib snapshot (`BINBUN_ISLA_IR`, default
//! `~/.cache/binbun-isla/armv9p4.ir`, fetched by `scripts/isla-snapshot.sh`);
//! skipped with a notice otherwise.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_semantics::Builder;
use binbun_semantics::ir::{
    Binary, Declarations, ExprId, Flag, RegisterInfo, Semantics, Trap, View,
};
use binbun_semantics::smt;
use isla_check::{Counterexample, Model, Verdict, check, with_model};

/// The registers of the AArch64 contract, in its order.
const NAMES: [(&str, u16); 72] = [
    ("x0", 64),
    ("x1", 64),
    ("x2", 64),
    ("x3", 64),
    ("x4", 64),
    ("x5", 64),
    ("x6", 64),
    ("x7", 64),
    ("x8", 64),
    ("x9", 64),
    ("x10", 64),
    ("x11", 64),
    ("x12", 64),
    ("x13", 64),
    ("x14", 64),
    ("x15", 64),
    ("x16", 64),
    ("x17", 64),
    ("x18", 64),
    ("x19", 64),
    ("x20", 64),
    ("x21", 64),
    ("x22", 64),
    ("x23", 64),
    ("x24", 64),
    ("x25", 64),
    ("x26", 64),
    ("x27", 64),
    ("x28", 64),
    ("x29", 64),
    ("x30", 64),
    ("sp", 64),
    ("pc", 64),
    ("n", 1),
    ("z", 1),
    ("c", 1),
    ("v", 1),
    ("btype", 2),
    ("v0", 128),
    ("v1", 128),
    ("v2", 128),
    ("v3", 128),
    ("v4", 128),
    ("v5", 128),
    ("v6", 128),
    ("v7", 128),
    ("v8", 128),
    ("v9", 128),
    ("v10", 128),
    ("v11", 128),
    ("v12", 128),
    ("v13", 128),
    ("v14", 128),
    ("v15", 128),
    ("v16", 128),
    ("v17", 128),
    ("v18", 128),
    ("v19", 128),
    ("v20", 128),
    ("v21", 128),
    ("v22", 128),
    ("v23", 128),
    ("v24", 128),
    ("v25", 128),
    ("v26", 128),
    ("v27", 128),
    ("v28", 128),
    ("v29", 128),
    ("v30", 128),
    ("v31", 128),
    ("fpcr", 32),
    ("fpsr", 32),
];

const REGISTERS: [RegisterInfo; 72] = {
    let mut registers = [RegisterInfo { name: "", width: 0 }; 72];
    let mut index = 0;
    while index < 72 {
        registers[index] = RegisterInfo {
            name: NAMES[index].0,
            width: NAMES[index].1,
        };
        index += 1;
    }
    registers
};

const AARCH64: Declarations = Declarations {
    registers: &REGISTERS,
    intrinsics: &[],
};

/// Where the instructions are.
const PC: u64 = 0x0000_7fff_1234_5000;

fn whole(name: &str) -> View {
    let id = AARCH64.find(name).unwrap();
    View {
        register: id,
        offset: 0,
        width: AARCH64.info(id).unwrap().width,
    }
}

fn read(b: &mut Builder, name: &str) -> ExprId {
    b.read(whole(name))
}

fn write(b: &mut Builder, name: &str, value: ExprId) {
    b.write(whole(name), value);
}

/// Every instruction leaves BTYPE 0 unless it is an indirect branch.
fn clear_btype(b: &mut Builder) {
    let zero = b.constant(2, 0);
    write(b, "btype", zero);
}

/// `subs x0, x1, #5`; `borrow` writes x86's borrow as the carry.
fn subs(borrow: bool) -> Semantics {
    let mut b = Builder::new();
    let x = read(&mut b, "x1");
    let five = b.constant(64, 5);
    let zero = b.constant(64, 0);
    let result = b.binary(Binary::Sub, x, five);
    write(&mut b, "x0", result);
    let negative = b.extract(result, 63, 1);
    let is_zero = b.binary(Binary::Eq, result, zero);
    let borrowed = b.flag(Flag::SubBorrow, x, five, zero);
    let carry = if borrow {
        borrowed
    } else {
        let one = b.constant(1, 1);
        b.binary(Binary::Xor, borrowed, one)
    };
    let overflow = b.flag(Flag::SubOverflow, x, five, zero);
    write(&mut b, "n", negative);
    write(&mut b, "z", is_zero);
    write(&mut b, "c", carry);
    write(&mut b, "v", overflow);
    clear_btype(&mut b);
    b.finish().unwrap()
}

/// `add x0, x1, x2, lsl #3`; `flags` also sets Z as `adds` would.
fn add(flags: bool) -> Semantics {
    let mut b = Builder::new();
    let x = read(&mut b, "x1");
    let y = read(&mut b, "x2");
    let three = b.constant(64, 3);
    let shifted = b.binary(Binary::Shl, y, three);
    let sum = b.binary(Binary::Add, x, shifted);
    write(&mut b, "x0", sum);
    if flags {
        let zero = b.constant(64, 0);
        let is_zero = b.binary(Binary::Eq, sum, zero);
        write(&mut b, "z", is_zero);
    }
    clear_btype(&mut b);
    b.finish().unwrap()
}

/// `b.eq #8`; `flag` is the flag tested (`z` is right).
fn b_eq(flag: &str) -> Semantics {
    let mut b = Builder::new();
    let condition = read(&mut b, flag);
    b.begin_if(condition);
    let target = b.constant(64, PC + 8);
    b.jump(target);
    b.end_if();
    clear_btype(&mut b);
    b.finish().unwrap()
}

/// An UNDEFINED instruction.
fn undefined() -> Semantics {
    let mut b = Builder::new();
    b.trap(Trap::InvalidInstruction);
    b.finish().unwrap()
}

/// `subp x0, x1, x2` as if `FEAT_MTE` were implemented: the difference of
/// the 56-bit addresses, sign-extended.
fn subp() -> Semantics {
    let mut b = Builder::new();
    let x = read(&mut b, "x1");
    let y = read(&mut b, "x2");
    let x = b.extract(x, 0, 56);
    let x = b.sext(x, 64);
    let y = b.extract(y, 0, 56);
    let y = b.sext(y, 64);
    let difference = b.binary(Binary::Sub, x, y);
    write(&mut b, "x0", difference);
    clear_btype(&mut b);
    b.finish().unwrap()
}

/// `ldr x0, [x1, #8]` (`imm12` = 1, scaled by 8); `unscaled` forgets the
/// scaling.
fn ldr(unscaled: bool) -> Semantics {
    let mut b = Builder::new();
    let base = read(&mut b, "x1");
    let offset = b.constant(64, if unscaled { 1 } else { 8 });
    let address = b.binary(Binary::Add, base, offset);
    let value = b.load(address, 8);
    write(&mut b, "x0", value);
    clear_btype(&mut b);
    b.finish().unwrap()
}

/// `stp x29, x30, [sp, #-16]!`; `unchecked` forgets the SP alignment
/// check.
fn stp(unchecked: bool) -> Semantics {
    let mut b = Builder::new();
    let sp = read(&mut b, "sp");
    if !unchecked {
        let fifteen = b.constant(64, 15);
        let zero = b.constant(64, 0);
        let low = b.binary(Binary::And, sp, fifteen);
        let misaligned = b.binary(Binary::Ne, low, zero);
        b.begin_if(misaligned);
        b.trap(Trap::Stack);
        b.end_if();
    }
    let sixteen = b.constant(64, 16);
    let address = b.binary(Binary::Sub, sp, sixteen);
    let first = read(&mut b, "x29");
    let second = read(&mut b, "x30");
    b.store(address, first);
    let eight = b.constant(64, 8);
    let next = b.binary(Binary::Add, address, eight);
    b.store(next, second);
    write(&mut b, "sp", address);
    clear_btype(&mut b);
    b.finish().unwrap()
}

fn input(counterexample: &Counterexample, name: &str) -> u64 {
    let (_, value) = counterexample
        .inputs
        .iter()
        .find(|(input, _)| input == name)
        .unwrap_or_else(|| panic!("no input {name} in {counterexample}"));
    smt::parse_literal(value).unwrap().low_u64()
}

/// The verdict for `semantics`, which must be a counterexample.
fn refuted(verdict: Verdict) -> Counterexample {
    match verdict {
        Verdict::Counterexample(counterexample) => counterexample,
        Verdict::Equivalent { .. } | Verdict::Unsupported(_) => {
            panic!("expected a counterexample, got {verdict}")
        }
    }
}

fn cases(model: &Model<'_>) {
    let verify = |word: u32, semantics: &Semantics| {
        let verdict = check(model, word, PC, semantics, &AARCH64);
        eprintln!("{word:#010x}: {verdict}");
        verdict
    };
    let equivalent = |word: u32, semantics: Semantics| {
        let verdict = verify(word, &semantics);
        assert!(
            matches!(verdict, Verdict::Equivalent { .. }),
            "{word:#010x}: {verdict}"
        );
        verdict
    };

    // subs x0, x1, #5: Arm's carry is NOT borrow.
    equivalent(0xf100_1420, subs(false));
    let wrong = refuted(verify(0xf100_1420, &subs(true)));
    assert_eq!(wrong.differences, ["c"], "{wrong}");

    // add x0, x1, x2, lsl #3 sets no flags.
    equivalent(0x8b02_0c20, add(false));
    let wrong = refuted(verify(0x8b02_0c20, &add(true)));
    assert_eq!(wrong.differences, ["z"], "{wrong}");

    // b.eq tests Z: two paths, taken and not.
    let Verdict::Equivalent { paths, .. } = equivalent(0x5400_0040, b_eq("z")) else {
        unreachable!()
    };
    assert_eq!(paths, 2);
    let wrong = refuted(verify(0x5400_0040, &b_eq("n")));
    assert_eq!(wrong.differences, ["next pc"], "{wrong}");
    assert_ne!(input(&wrong, "n"), input(&wrong, "z"), "{wrong}");

    // ldr x0, [x1, #8]: the immediate is scaled by the access size.
    equivalent(0xf940_0420, ldr(false));
    let wrong = refuted(verify(0xf940_0420, &ldr(true)));
    assert!(
        wrong
            .differences
            .iter()
            .any(|what| what == "bytes read" || what == "x0"),
        "{wrong}"
    );

    // stp x29, x30, [sp, #-16]!: a misaligned SP faults (SCTLR_EL1.SA0).
    let Verdict::Equivalent { exceptions, .. } = equivalent(0xa9bf_7bfd, stp(false)) else {
        unreachable!()
    };
    assert!(exceptions > 0);
    let wrong = refuted(verify(0xa9bf_7bfd, &stp(true)));
    assert_eq!(wrong.differences, ["no trap"], "{wrong}");
    assert!(
        wrong.exception.as_deref().unwrap().contains("EC 0x26"),
        "{wrong}"
    );
    assert_ne!(input(&wrong, "sp") & 15, 0, "{wrong}");

    // subp x0, x1, x2 is UNDEFINED without FEAT_MTE: the exception, EC 0.
    let Verdict::Equivalent { exceptions, .. } = equivalent(0x9ac2_0020, undefined()) else {
        unreachable!()
    };
    assert!(exceptions > 0);
    let wrong = refuted(verify(0x9ac2_0020, &subp()));
    assert_eq!(wrong.differences, ["no trap"], "{wrong}");
    assert!(
        wrong.exception.as_deref().unwrap().contains("EC 0x0"),
        "{wrong}"
    );
}

#[test]
fn right_semantics_are_proved_and_bugs_are_found() {
    let path = std::env::var("BINBUN_ISLA_IR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.cache/binbun-isla/armv9p4.ir")
    });
    let Ok(ir) = std::fs::read_to_string(&path) else {
        eprintln!("skipped: no Jib snapshot at {path} (set BINBUN_ISLA_IR)");
        return;
    };
    if std::process::Command::new("z3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipped: cannot run z3");
        return;
    }
    with_model(&ir, 4, Some(300), cases).unwrap();
}
