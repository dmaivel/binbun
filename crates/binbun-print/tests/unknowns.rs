#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Unknown values that are not the architecture's, printed by where they
//! come from and never as a constant: a parameter's bits above its declared
//! width do not print (the parameter prints at its width); a register a
//! call leaves, an entry value no parameter holds, and lowering's fallback
//! are named, one name per value, each declared from `binbun_defs.h`'s helper
//! in both views; what still prints as 0 is counted. Every function
//! compiles without warnings.

mod common;

use binbun_ast::ir::{Callee, Expr, ExprId, Function, Origin, Stmt};
use binbun_print::c::{self, Opaque, Unknowns};
use binbun_print::layout;
use binbun_print::style::Style;
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_ssa::ir::Unknown;
use common::{Builder, DECLARATIONS, Scratch, compilers, warnings};

const RDI: RegisterId = RegisterId(0);

/// `f` printed in the view `opaque` stands for, and its unknowns.
fn printed(f: &Function, opaque: Opaque) -> (String, Unknowns) {
    let printed = c::function(f, &DECLARATIONS, &Style::kr(), &|_: u64| None, opaque).unwrap();
    (
        layout::render(&printed.document, &Style::kr()),
        printed.counts.unknowns,
    )
}

/// `int64_t widened(int32_t a1)`: `a1` with unknown bits above it, as a
/// 32-bit parameter whose register is returned whole.
fn widened() -> Function {
    let mut b = Builder::new(0x1000, "widened");
    let int32 = b.int(32);
    let int64 = b.int(64);
    b.f.returns = Some(int64);
    let a1 = b.param(int32);
    let low = b.read(a1);
    let high = b.e(Expr::Undefined(32, Unknown::Parameter, None));
    let whole = b.e(Expr::Concat { high, low });
    let ret = b.ret(whole);
    b.done(vec![ret])
}

/// `uint64_t leftovers(void)`: what the call of `sub_2400` at 0x2010 left
/// in `rdi`, twice, plus `rdi`'s entry value and two of lowering's
/// fallbacks.
fn leftovers() -> Function {
    let mut b = Builder::new(0x2000, "leftovers");
    let uint64 = b.uint(64);
    b.f.returns = Some(uint64);
    let void = b.code(Vec::new(), None, false);
    let called = b.call(Callee::Address(0x2400), Vec::new(), void, Vec::new());
    b.f.provenance
        .set_stmt(called, &[Origin::Instruction(0x2010)]);
    let call = Unknown::Call {
        address: 0x2010,
        register: RDI,
    };
    let unknown = |b: &mut Builder, unknown| b.e(Expr::Undefined(64, unknown, None));
    let first = unknown(&mut b, call);
    let again = unknown(&mut b, call);
    let entry = unknown(
        &mut b,
        Unknown::Entry {
            register: Some(RDI),
        },
    );
    let lowering = unknown(&mut b, Unknown::Lowering);
    let other = unknown(&mut b, Unknown::Lowering);
    let sum = [again, entry, lowering, other]
        .into_iter()
        .fold(first, |sum, term: ExprId| b.bin(Binary::Add, sum, term));
    let ret = b.ret(sum);
    b.done(vec![called, ret])
}

/// `uint32_t landing(void)`: a value at a landing pad, still 0.
fn landing() -> Function {
    let mut b = Builder::new(0x3000, "landing");
    let uint32 = b.uint(32);
    b.f.returns = Some(uint32);
    let value = b.e(Expr::Undefined(32, Unknown::Landing, None));
    let ret = b.ret(value);
    b.done(vec![ret])
}

/// `uint64_t merged(uint64_t a1)`: a local `v` that is `a1` on one path
/// and what the call at 0x4010 left in `rdi` on the other; then what the
/// call at 0x4020 left there if `a1 == 1` (`v`'s earlier value reaches
/// it); `a1` given what the call at 0x4030 left if `a1 == 2` (its entry
/// value reaches it); a local `u` given what the call at 0x4050 left if
/// `a1 == 3`, then 7 if `a1 == 4` and 8 if not; `w` given only what the
/// call at 0x4040 left; `v + ` the call at 0x4020's leftover again
/// `+ w + u` returned.
fn merged() -> Function {
    let mut b = Builder::new(0x4000, "merged");
    let uint64 = b.uint(64);
    b.f.returns = Some(uint64);
    let a1 = b.param(uint64);
    let merged = b.local(uint64);
    let left = |b: &mut Builder, address| {
        b.e(Expr::Undefined(
            64,
            Unknown::Call {
                address,
                register: RDI,
            },
            None,
        ))
    };
    let first = left(&mut b, 0x4010);
    let given = b.assign(merged, first);
    let x = b.read(a1);
    let kept = b.assign(merged, x);
    let x = b.read(a1);
    let zero = b.c(64, 0);
    let condition = b.bin(Binary::Eq, x, zero);
    let branch = b.s(Stmt::If {
        condition,
        then: vec![given],
        otherwise: vec![kept],
    });
    let second = left(&mut b, 0x4020);
    let again = b.assign(merged, second);
    let x = b.read(a1);
    let one = b.c(64, 1);
    let condition = b.bin(Binary::Eq, x, one);
    let only = b.when(condition, vec![again]);
    // A parameter given what the call at 0x4030 left: merged with its
    // entry value.
    let third = left(&mut b, 0x4030);
    let reset = b.assign(a1, third);
    let x = b.read(a1);
    let two = b.c(64, 2);
    let condition = b.bin(Binary::Eq, x, two);
    let parameter = b.when(condition, vec![reset]);
    // A local nothing writes before what the call at 0x4050 left, written
    // after.
    let later = b.local(uint64);
    let fifth = left(&mut b, 0x4050);
    let first_u = b.assign(later, fifth);
    let x = b.read(a1);
    let three = b.c(64, 3);
    let condition = b.bin(Binary::Eq, x, three);
    let early = b.when(condition, vec![first_u]);
    let seven = b.c(64, 7);
    let second_u = b.assign(later, seven);
    let eight = b.c(64, 8);
    let third_u = b.assign(later, eight);
    let x = b.read(a1);
    let four = b.c(64, 4);
    let condition = b.bin(Binary::Eq, x, four);
    let late = b.s(Stmt::If {
        condition,
        then: vec![second_u],
        otherwise: vec![third_u],
    });
    // A local given only what the call at 0x4040 left: no other path.
    let alone = b.local(uint64);
    let fourth = left(&mut b, 0x4040);
    let single = b.assign(alone, fourth);
    let value = b.read(merged);
    let used = left(&mut b, 0x4020);
    let sum = b.bin(Binary::Add, value, used);
    let other = b.read(alone);
    let sum = b.bin(Binary::Add, sum, other);
    let other = b.read(later);
    let sum = b.bin(Binary::Add, sum, other);
    let ret = b.ret(sum);
    b.done(vec![branch, only, parameter, early, late, single, ret])
}

/// `uint64_t under(uint64_t a1)`: a 512-bit local `v` given `a1` under
/// 384 bits of lowering's fallback (a `zmm` register whose upper bits
/// lowering has no expression for), then its low 128 bits replaced by
/// `a1 + a1` (an SSE instruction writing the register), then `v`'s bits
/// 128 to 191 returned.
fn under() -> Function {
    let mut b = Builder::new(0x5000, "under");
    let uint64 = b.uint(64);
    let bits512 = b.bits(512);
    b.f.returns = Some(uint64);
    let a1 = b.param(uint64);
    let v = b.local(bits512);
    let high = b.e(Expr::Undefined(384, Unknown::Lowering, None));
    let x = b.read(a1);
    let low = b.ext(false, x, 128);
    let whole = b.e(Expr::Concat { high, low });
    let given = b.assign(v, whole);
    let x = b.read(v);
    let high = b.bits_of(x, 128, 384);
    let x = b.read(a1);
    let y = b.read(a1);
    let sum = b.bin(Binary::Add, x, y);
    let low = b.ext(false, sum, 128);
    let whole = b.e(Expr::Concat { high, low });
    let replaced = b.assign(v, whole);
    let x = b.read(v);
    let lane = b.bits_of(x, 128, 64);
    let ret = b.ret(lane);
    b.done(vec![given, replaced, ret])
}

/// The non-blank lines of `text`, trimmed.
fn lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

#[test]
fn a_parameter_prints_at_its_declared_width() {
    for opaque in [Opaque::Calls, Opaque::Asm] {
        let (text, unknowns) = printed(&widened(), opaque);
        let lines = lines(&text);
        assert!(lines.contains(&"return a1;"), "{text}");
        let mut code = lines.iter().filter(|line| !line.starts_with("/*"));
        assert!(
            code.all(|line| !line.contains("<<") && !line.contains("0x")),
            "{text}"
        );
        assert_eq!(unknowns, Unknowns::default(), "{text}");
    }
}

#[test]
fn leftovers_entry_values_and_fallbacks_are_named_never_zero() {
    for opaque in [Opaque::Calls, Opaque::Asm] {
        let (text, unknowns) = printed(&leftovers(), opaque);
        let lines = lines(&text);
        let declared = [
            "uint64_t _RDI_clobbered = binbun_undefined_u64(); /* sub_2400 called at 0x2010 may change RDI */",
            "uint64_t _RDI_entry = binbun_undefined_u64(); /* RDI at entry: no parameter of the function */",
            "uint64_t _unknown = binbun_undefined_u64(); /* a value binbun has no expression for */",
            "uint64_t _unknown_2 = binbun_undefined_u64(); /* a value binbun has no expression for */",
        ];
        for declaration in declared {
            assert!(lines.contains(&declaration), "{declaration} in\n{text}");
        }
        // One name for the one value a call left, used twice.
        assert_eq!(text.matches("_RDI_clobbered").count(), 3, "{text}");
        assert!(
            lines.contains(
                &"return _RDI_clobbered + _RDI_clobbered + _RDI_entry + _unknown + _unknown_2;"
            ),
            "{text}"
        );
        assert_eq!(
            unknowns,
            Unknowns {
                call: 2,
                entry: 1,
                lowering: 2,
                ..Unknowns::default()
            }
        );
    }
}

#[test]
fn an_unknown_above_a_value_without_a_c_type_is_named_at_the_whole_width() {
    for opaque in [Opaque::Calls, Opaque::Asm] {
        let (text, unknowns) = printed(&under(), opaque);
        let lines = lines(&text);
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            lines.contains(
                &"u64x8 _unknown = binbun_undefined_u512(); /* a value binbun has no expression for */"
            ),
            "{text}"
        );
        assert!(
            flat.contains("v1 = (u64x8)(u128x4){a1, ((u128x4)_unknown)[1], ((u128x4)_unknown)[2], ((u128x4)_unknown)[3]};"),
            "{text}"
        );
        assert!(
            flat.contains(
                "v1 = (u64x8)(u128x4){a1 + a1, ((u128x4)v1)[1], ((u128x4)v1)[2], ((u128x4)v1)[3]};"
            ),
            "{text}"
        );
        assert!(lines.contains(&"return v1[2];"), "{text}");
        assert!(!text.contains("{0"), "{text}");
        assert_eq!(
            unknowns,
            Unknowns {
                lowering: 1,
                ..Unknowns::default()
            }
        );
    }
}

#[test]
fn a_landing_pads_value_still_prints_as_zero_and_is_counted() {
    let (text, unknowns) = printed(&landing(), Opaque::Calls);
    assert!(lines(&text).contains(&"return 0;"), "{text}");
    assert_eq!(
        unknowns,
        Unknowns {
            landing: 1,
            ..Unknowns::default()
        }
    );
}

#[test]
fn the_reading_view_leaves_a_merged_local_unassigned_where_nothing_reaches() {
    let (text, unknowns) = printed(&merged(), Opaque::Asm);
    let lines = lines(&text);
    // `v` not assigned on the path the call at 0x4010 left `rdi`, nor `u`
    // where the call at 0x4050 did (the `if` left with nothing to do
    // gone), and those names, used nowhere else, not declared.
    assert!(
        !text.contains("0x4010") && !text.contains("0x4050") && !text.contains("a1 == 3"),
        "{text}"
    );
    assert!(
        lines.contains(&"if (a1 != 0) {") || lines.contains(&"if (a1 != 0)"),
        "{text}"
    );
    assert!(!lines.iter().any(|line| line.contains("= 0;")), "{text}");
    // Where an earlier value would seem to flow on (`v`'s from the first
    // `if`, `a1`'s entry value), or nothing else writes the local (`w`),
    // the assignment stays, named; so does the leftover the return uses.
    for kept in ["a1 == 1", "a1 == 2", "a1 == 4", "0x4030", "0x4040"] {
        assert!(text.contains(kept), "{kept} in\n{text}");
    }
    assert_eq!(text.matches("0x4020").count(), 1, "{text}");
    assert_eq!(text.matches("_RDI_clobbered").count(), 7, "{text}");
    assert_eq!(
        unknowns,
        Unknowns {
            call: 4,
            ..Unknowns::default()
        }
    );
    // The exact view keeps every assignment.
    let (text, unknowns) = printed(&merged(), Opaque::Calls);
    for kept in ["0x4010", "0x4050", "a1 == 3"] {
        assert!(text.contains(kept), "{kept} in\n{text}");
    }
    assert_eq!(text.matches("_RDI_clobbered").count(), 11, "{text}");
    assert_eq!(
        unknowns,
        Unknowns {
            call: 6,
            ..Unknowns::default()
        }
    );
}

#[test]
fn named_unknowns_compile_without_warnings() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: no C compiler to check with");
        return;
    }
    let scratch = Scratch::new("unknowns");
    for f in [widened(), leftovers(), landing(), merged(), under()] {
        for opaque in [Opaque::Calls, Opaque::Asm] {
            // The reading view's merged local is unassigned on a path, which
            // compilers warn of.
            let unassigned = opaque == Opaque::Asm && f.address == 0x4000;
            let (text, _) = printed(&f, opaque);
            scratch.write("out.c", &text);
            for &compiler in &compilers {
                let stderr = scratch
                    .compile(compiler, &["-c", "-o", "out.o", "-O2"], &["out.c"])
                    .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
                if !unassigned {
                    assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
                }
            }
        }
    }
}
