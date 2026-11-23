//! The rule language of processor profiles (`binbun_semantics::rule`):
//! what it refuses to read, the widths it gives, and its values, with
//! undefined input bits making undefined only what depends on them.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::Value;
use binbun_semantics::ir::{Binary, Expr, ExprId, Local};
use binbun_semantics::rule::Rule;

/// SHRD's inputs, as its site names them.
const SHRD: [&str; 6] = ["dst", "src", "count", "old", "defined.dst", "defined.cf"];

fn value(width: u16, bits: u64) -> Value {
    Value::defined(Bits::from_u64(width, bits))
}

/// `text` over SHRD's inputs at operand size `osz`, for inputs `values`
/// (dst, src, count, old, defined.dst, defined.cf).
fn shrd(text: &str, osz: u16, width: u16, values: &[Value; 6]) -> Value {
    let rule = Rule::parse(text, &SHRD).unwrap();
    let compiled = rule.instantiate(&[osz, osz, 8, 1, osz, 1], width).unwrap();
    compiled.eval(values).unwrap()
}

fn error(text: &str) -> String {
    Rule::parse(text, &SHRD).unwrap_err().0
}

#[test]
fn text_that_is_no_rule_is_refused_with_a_reason() {
    // Each names what is wrong.
    for (text, culprit) in [
        ("cf", "cf"),
        ("defined.of", "defined.of"),
        ("msb(dst, src)", "msb"),
        ("bit(dst)", "bit"),
        ("dst src", "src"),
        ("dst $ src", "$"),
        ("0xzz", "0xzz"),
        ("if count == 1 { dst } { src }", "else"),
        ("msb dst", "("),
    ] {
        assert!(error(text).contains(culprit), "{text}: {}", error(text));
    }
    // Cut short.
    for text in ["", "(dst ^ src", "msb(dst", "dst ^", "if count { 1 } else"] {
        assert!(Rule::parse(text, &SHRD).is_err(), "{text}");
    }
}

#[test]
fn widths_follow_from_the_inputs() {
    let widths = [64, 64, 8, 1, 64, 1];
    let fits = |text: &str, width: u16| {
        Rule::parse(text, &SHRD)
            .unwrap()
            .instantiate(&widths, width)
            .map(|_| ())
            .map_err(|error| error.0)
    };
    // One bit: flags of values, comparisons, a bit, parity.
    for text in [
        "msb(dst)",
        "bit(src, 0) ^ msb(dst)",
        "count == 1",
        "count < osz",
        "parity8(defined.dst)",
        "bit(dst, count)",
        "bits(dst, osz - 2, 1)",
        "old",
        "0",
        "if count == 0 { old } else { defined.cf }",
    ] {
        assert_eq!(fits(text, 1), Ok(()), "{text}");
    }
    // A literal takes its operand's width; a narrower operand is
    // zero-extended to the wider; a shift keeps its value's width.
    for text in [
        "dst",
        "dst + 1",
        "dst ^ count",
        "dst << count",
        "dst >> 3",
        "zext(old, osz)",
        "sext(count, 64)",
        "popcount(src)",
        "!dst",
        "if count == 8 { dst } else { 0 }",
    ] {
        assert_eq!(fits(text, 64), Ok(()), "{text}");
    }
    assert_eq!(fits("trunc(dst, 16)", 16), Ok(()));
    assert_eq!(fits("bits(dst, 8, 8)", 8), Ok(()));
    // Not these widths.
    for (text, width) in [
        ("dst", 1),
        ("msb(dst)", 64),
        ("bits(dst, 60, 8)", 8),
        ("bits(dst, 0, 0)", 0),
        ("zext(dst, 32)", 32),
        ("trunc(dst, 72)", 72),
        ("bits(dst, count, 1)", 1),
        ("(1 + 2) == 3", 1),
    ] {
        assert!(fits(text, width).is_err(), "{text} as {width} bits");
    }
    assert_eq!(
        fits("1 + 2", 1),
        Ok(()),
        "a constant takes the result's width"
    );
    // A rule is width-generic: `osz` is the first input's width.
    let rule = Rule::parse("bits(dst, osz - 2, 1)", &SHRD).unwrap();
    for osz in [8, 16, 32, 64] {
        assert!(
            rule.instantiate(&[osz, osz, 8, 1, osz, 1], 1).is_ok(),
            "{osz}"
        );
    }
}

#[test]
fn the_shrd_rules_of_the_probe_give_the_measured_values() {
    let flags = |dst: u64, result: u64, osz: u16, count: u64| {
        [
            value(osz, dst),
            value(osz, dst),
            value(8, count),
            value(1, 0),
            value(osz, result),
            value(1, 0),
        ]
    };
    // Raptor Cove: OF as if the count were 1.
    let p = "bit(src, 0) ^ msb(dst)";
    // Gracemont: OF of the last one-bit step.
    let e = "msb(defined.dst) ^ bit(defined.dst, osz - 2)";
    // The post's `shrd rdx, rdx, 0x1d` on 0x8f: 0x47800000000.
    let post = flags(0x8f, 0x478_0000_0000, 64, 0x1d);
    assert_eq!(shrd(p, 64, 1, &post), value(1, 1));
    assert_eq!(shrd(e, 64, 1, &post), value(1, 0));
    // The mistyped probe input, 0x4780000000: 0 on both.
    let probe = flags(0x47_8000_0000, 0x23c, 64, 0x1d);
    assert_eq!(shrd(p, 64, 1, &probe), value(1, 0));
    assert_eq!(shrd(e, 64, 1, &probe), value(1, 0));
    // `shrd edx, edx, 0x1d` on 0x80000000: 1 on the P-cores, 0 on the
    // E-cores.
    let narrow = flags(0x8000_0000, 4, 32, 0x1d);
    assert_eq!(shrd(p, 32, 1, &narrow), value(1, 1));
    assert_eq!(shrd(e, 32, 1, &narrow), value(1, 0));
}

#[test]
fn operations_have_their_dsl_meaning() {
    let inputs = |dst: u64, count: u64| {
        [
            value(16, dst),
            value(16, 0x00ff),
            value(8, count),
            value(1, 1),
            value(16, 0x8001),
            value(1, 0),
        ]
    };
    let at = |text: &str, width: u16, dst: u64, count: u64| {
        shrd(text, 16, width, &inputs(dst, count))
            .known()
            .unwrap()
            .low_u128()
    };
    assert_eq!(at("parity8(defined.dst)", 1, 0, 0), 0, "0x01: odd");
    assert_eq!(at("parity8(src)", 1, 0, 0), 1, "0xff: even");
    assert_eq!(at("popcount(src)", 16, 0, 0), 8);
    assert_eq!(at("bit(dst, count)", 1, 0b100, 2), 1);
    assert_eq!(at("bit(dst, 99)", 1, 0xffff, 0), 0, "past the width");
    assert_eq!(at("bits(dst, 4, 8)", 8, 0x1230, 0), 0x23);
    assert_eq!(at("sext(count, 16)", 16, 0, 0x80), 0xff80);
    assert_eq!(at("zext(count, 16)", 16, 0, 0x80), 0x80);
    assert_eq!(at("trunc(dst, 8)", 8, 0x1234, 0), 0x34);
    assert_eq!(at("dst - 1", 16, 0, 0), 0xffff);
    assert_eq!(at("dst << count", 16, 1, 15), 0x8000);
    assert_eq!(at("dst >> count", 16, 0x8000, 15), 1);
    assert_eq!(at("!dst", 16, 0x00ff, 0), 0xff00);
    assert_eq!(
        at("dst | src & 0xf", 16, 0x100, 0),
        0x10f,
        "& binds tighter"
    );
    assert_eq!(at("dst ^ src == 0xff", 1, 0, 0), 1, "== binds looser");
    assert_eq!(at("dst + 2 * 3", 16, 1, 0), 7, "* binds tighter than +");
    assert_eq!(at("count <= 3", 1, 0, 3), 1);
    assert_eq!(at("count != osz", 1, 0, 16), 0);
    assert_eq!(at("if count == 8 { bit(dst, 0) } else { 0 }", 1, 1, 8), 1);
    assert_eq!(at("if count == 8 { bit(dst, 0) } else { 0 }", 1, 1, 9), 0);
    assert_eq!(at("if count { 1 } else { 0 }", 1, 0, 5), 1, "not 0: true");
}

#[test]
fn undefined_inputs_make_undefined_only_what_depends_on_them() {
    let rule = |text: &str| Rule::parse(text, &SHRD).unwrap();
    let widths = [64, 64, 8, 1, 64, 1];
    // `old` and `defined.cf` unknown (not kept by lowering).
    let inputs = [
        value(64, 0x8f),
        value(64, 0x8f),
        value(8, 0x1d),
        Value::unknown(1),
        value(64, 0x478_0000_0000),
        Value::unknown(1),
    ];
    let eval = |text: &str| {
        rule(text)
            .instantiate(&widths, 1)
            .unwrap()
            .eval(&inputs)
            .unwrap()
    };
    assert_eq!(eval("bit(src, 0) ^ msb(dst)"), value(1, 1));
    assert_eq!(eval("old"), Value::unknown(1));
    assert_eq!(eval("old ^ msb(dst)"), Value::unknown(1));
    assert_eq!(eval("old & 0"), value(1, 0), "AND with a defined 0");
    assert_eq!(eval("defined.cf | 1"), value(1, 1), "OR with a defined 1");
    assert_eq!(
        eval("if count == 0x1d { msb(dst) } else { old }"),
        value(1, 0),
        "a defined condition takes one arm"
    );
    assert_eq!(
        eval("if old { msb(dst) } else { bit(dst, 0) }"),
        Value::unknown(1),
        "an undefined condition between different arms"
    );
    // Some bits of a wide input undefined: an extraction of defined bits
    // is defined.
    let partly = Value {
        bits: Bits::from_u64(64, 0x8f),
        undefined: Bits::from_u64(64, 0xffff_0000_0000_0000),
    };
    let wide = rule("bits(dst, 0, 8)").instantiate(&widths, 8).unwrap();
    let mut some = inputs;
    some[0] = partly;
    assert_eq!(wide.eval(&some).unwrap(), value(8, 0x8f));
    assert_eq!(
        rule("msb(dst)")
            .instantiate(&widths, 1)
            .unwrap()
            .eval(&some)
            .unwrap(),
        Value::unknown(1)
    );
}

#[test]
fn eval_refuses_inputs_it_was_not_made_for() {
    let compiled = Rule::parse("msb(dst)", &SHRD)
        .unwrap()
        .instantiate(&[64, 64, 8, 1, 64, 1], 1)
        .unwrap();
    assert!(compiled.eval(&[value(64, 0)]).is_err());
    let narrow = [
        value(32, 0),
        value(64, 0),
        value(8, 0),
        value(1, 0),
        value(64, 0),
        value(1, 0),
    ];
    assert!(compiled.eval(&narrow).is_err());
}

#[test]
fn a_rule_emits_into_a_semantics_over_its_inputs() {
    let rule = Rule::parse("bit(src, 0) ^ msb(dst)", &SHRD).unwrap();
    let compiled = rule.instantiate(&[64, 64, 8, 1, 64, 1], 1).unwrap();
    // A semantics with its own expressions; the inputs are some of them.
    let mut exprs: Vec<(Expr, u16)> =
        vec![(Expr::Local(Local(0)), 64), (Expr::Local(Local(1)), 64)];
    let inputs: Vec<ExprId> = [1, 0, 0, 0, 0, 0].into_iter().map(ExprId).collect();
    let result = compiled.emit(&mut exprs, &inputs);
    assert_eq!(exprs[result.0 as usize].1, 1);
    let Expr::Binary(Binary::Xor, a, b) = exprs[result.0 as usize].0 else {
        panic!("{exprs:?}");
    };
    assert_eq!(
        exprs[a.0 as usize].0,
        Expr::Extract {
            value: ExprId(0),
            offset: 0,
            width: 1
        },
        "src is expression 0"
    );
    assert_eq!(
        exprs[b.0 as usize].0,
        Expr::Extract {
            value: ExprId(1),
            offset: 63,
            width: 1
        },
        "dst is expression 1"
    );
    // A rule that is an input emits nothing.
    let old = Rule::parse("old", &SHRD)
        .unwrap()
        .instantiate(&[64, 64, 8, 1, 64, 1], 1)
        .unwrap();
    let before = exprs.len();
    let inputs: Vec<ExprId> = (0..6).map(ExprId).collect();
    assert_eq!(old.emit(&mut exprs, &inputs), ExprId(3));
    assert_eq!(exprs.len(), before);
}
