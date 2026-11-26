#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The conversion plan: what it costs by statement, planned again under
//! another type for a local, and the printer's check of it (a plan that
//! does not hold is repaired by C's rules and counted, never printed
//! wrong).

mod common;

use binbun_ast::ir::{Function, StmtId, VarId};
use binbun_ast::types::Type;
use binbun_print::c::{self, Opaque, Planner};
use binbun_print::layout::render;
use binbun_print::style::Style;
use binbun_semantics::ir::Binary;
use common::{Builder, DECLARATIONS};

/// `x = p; if (x < q) return 1; return 0;`, `x` an unsigned local and
/// the comparison signed: the plan casts `x`.
fn signed_compare() -> (Function, VarId, StmtId, StmtId) {
    let mut b = Builder::new(0x1000, "less");
    let int = b.int(32);
    let uint = b.uint(32);
    b.f.returns = Some(int);
    let p = b.param(int);
    let q = b.param(int);
    let x = b.local(uint);
    let read_p = b.read(p);
    let set = b.assign(x, read_p);
    let (read_x, read_q) = (b.read(x), b.read(q));
    let less = b.bin(Binary::SLt, read_x, read_q);
    let one = b.c(32, 1);
    let yes = b.ret(one);
    let branch = b.when(less, vec![yes]);
    let zero = b.c(32, 0);
    let no = b.ret(zero);
    (b.done(vec![set, branch, no]), x, set, branch)
}

/// `f` printed following `plan`, and its unplanned conversions.
fn printed(f: &Function, plan: c::Plan) -> (String, usize) {
    let style = Style::kr();
    let printed = c::planned(f, &DECLARATIONS, &style, &|_| None, Opaque::Calls, plan).unwrap();
    (render(&printed.document, &style), printed.counts.unplanned)
}

#[test]
fn a_statement_costs_the_casts_it_prints() {
    let (f, _, set, branch) = signed_compare();
    let style = Style::kr();
    let planner = Planner::new(&f, &DECLARATIONS, &style, &|_| None, Opaque::Calls).unwrap();
    let plan = planner.into_plan();
    assert_eq!(plan.statement(set).casts, 0);
    assert_eq!(plan.statement(branch).casts, 1);
    assert_eq!(plan.cost().casts, 1);
    let (c, unplanned) = printed(&f, plan);
    assert_eq!(unplanned, 0, "{c}");
    assert!(c.contains("(int32_t)"), "{c}");
}

#[test]
fn a_local_planned_again_as_signed_needs_no_cast() {
    let (f, x, set, branch) = signed_compare();
    let style = Style::kr();
    let mut planner = Planner::new(&f, &DECLARATIONS, &style, &|_| None, Opaque::Calls).unwrap();
    planner.retype(x, Some(Type::Int(32)));
    planner.replan(&[set, branch]).unwrap();
    let plan = planner.into_plan();
    assert_eq!(plan.statement(branch).casts, 0);
    assert_eq!(plan.cost().casts, 0);
    let (c, unplanned) = printed(&f, plan);
    assert_eq!(unplanned, 0, "{c}");
    assert!(!c.contains("(int32_t)") && !c.contains("(uint32_t)"), "{c}");
}

#[test]
fn a_plan_that_does_not_hold_is_repaired_and_counted() {
    let (f, x, set, branch) = signed_compare();
    let style = Style::kr();
    let mut outdated = Planner::new(&f, &DECLARATIONS, &style, &|_| None, Opaque::Calls).unwrap();
    // Retyped, its statements not planned again.
    outdated.retype(x, Some(Type::Int(32)));
    let (repaired, unplanned) = printed(&f, outdated.into_plan());
    assert!(unplanned > 0, "{repaired}");
    let mut planner = Planner::new(&f, &DECLARATIONS, &style, &|_| None, Opaque::Calls).unwrap();
    planner.retype(x, Some(Type::Int(32)));
    planner.replan(&[set, branch]).unwrap();
    let (c, unplanned) = printed(&f, planner.into_plan());
    assert_eq!(unplanned, 0, "{c}");
    assert_eq!(repaired, c);
}
