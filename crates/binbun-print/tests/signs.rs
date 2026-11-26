#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Each local's signedness chosen on the conversion plan: a local whose
//! type nothing declared prints signed or unsigned as fewer casts are then
//! needed in the statements that read or write it; a tie keeps its
//! spelling, and parameters keep theirs.

mod common;

use binbun_ast::ir::{Expr, ExprId, Stmt, VarId, VarKind};
use binbun_print::style::Style;
use binbun_semantics::ir::Binary;
use common::{Builder, print};

/// `var op k`.
fn with(b: &mut Builder, op: Binary, var: VarId, k: u64) -> ExprId {
    let read = b.read(var);
    let k = b.c(32, k);
    b.bin(op, read, k)
}

#[test]
fn a_local_takes_the_signedness_that_needs_fewer_casts() {
    // more = n; tie = n; same = n;
    // if (more <u 10) return more /u 3;  unsigned reads
    // if (more <=u 20) return 0;
    // if (more <s 5) return 1;           one signed
    // if (tie <u 7) return 2;
    // if (tie <s 9) return 3;            one each: a tie
    // if (same == more) return 4;        as `more`
    // return n <u 4 ? 5 : 6;             a parameter
    let mut b = Builder::new(0x1000, "choose");
    let int = b.int(32);
    let bits = b.bits(32);
    b.f.returns = Some(int);
    let n = b.var(VarKind::Parameter, int, Some("n"));
    b.f.parameters.push(n);
    let more = b.var(VarKind::Local, bits, Some("more"));
    let tie = b.var(VarKind::Local, bits, Some("tie"));
    let same = b.var(VarKind::Local, bits, Some("same"));
    let mut body = Vec::new();
    for var in [more, tie, same] {
        let read = b.read(n);
        body.push(b.assign(var, read));
    }
    let quotient = with(&mut b, Binary::UDiv, more, 3);
    let (read_same, read_more) = (b.read(same), b.read(more));
    let tests = [
        (with(&mut b, Binary::ULt, more, 10), quotient),
        (with(&mut b, Binary::ULe, more, 20), b.c(32, 0)),
        (with(&mut b, Binary::SLt, more, 5), b.c(32, 1)),
        (with(&mut b, Binary::ULt, tie, 7), b.c(32, 2)),
        (with(&mut b, Binary::SLt, tie, 9), b.c(32, 3)),
        (b.bin(Binary::Eq, read_same, read_more), b.c(32, 4)),
    ];
    for (condition, value) in tests {
        let early = b.ret(value);
        body.push(b.s(Stmt::If {
            condition,
            then: vec![early],
            otherwise: Vec::new(),
        }));
    }
    let below = with(&mut b, Binary::ULt, n, 4);
    let (five, six) = (b.c(32, 5), b.c(32, 6));
    let choice = b.e(Expr::Select {
        condition: below,
        then: five,
        otherwise: six,
    });
    body.push(b.ret(choice));
    let f = b.done(body);
    let (c, counts) = print(&f, &Style::kr());
    assert!(c.contains("uint32_t more"), "{c}");
    assert!(
        c.contains("int32_t tie") && !c.contains("uint32_t tie"),
        "a tie keeps the spelling:\n{c}"
    );
    assert!(
        c.contains("uint32_t same"),
        "compared with `more`, as it:\n{c}"
    );
    assert!(
        c.contains("int32_t n") && !c.contains("uint32_t n"),
        "a parameter keeps its type:\n{c}"
    );
    // `(int32_t)more < 5`, one of `tie`'s two comparisons, and `n`'s.
    assert_eq!(counts.casts, 3, "{c}");
}
