#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The rewrite rules (`crates/binbun-decompile/rules/*.rules`, compiled
//! into `binbun_decompile::simplify::rules::RULES`): each proved by z3 at
//! every combination of the widths it claims that its width conditions
//! allow (the left side encoded with `binbun_semantics::smt`, the right
//! side too, z3 asked for values of the variables and constants meeting
//! the side conditions where they differ: none allowed), and each
//! matcher checked against its rule's data (it fires on the left side
//! for some constants, and builds the right side).
//!
//! Needs `z3` on the `PATH` for the proofs (skipped with a notice
//! otherwise). `--nocapture` prints the rules by group, the instances
//! proved and the time.

mod common;

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use binbun_ast::ir::{Expr, ExprId, Function, VarKind, Variable};
use binbun_ast::types::{Evidence, Type, Types};
use binbun_decompile::simplify::rules::{self, Literal, Node, RULES, Rule};
use binbun_semantics::bits::{Bits, MAX_WIDTH};
use binbun_semantics::ir::Binary;

use common::{Proofs, run_all};

/// Every combination of the widths `rule` claims that its width
/// conditions allow.
fn instances(rule: &Rule) -> Vec<Vec<i64>> {
    let mut all: Vec<Vec<i64>> = vec![Vec::new()];
    for var in rule.widths {
        all = all
            .into_iter()
            .flat_map(|prefix| {
                var.claimed.iter().map(move |&width| {
                    let mut next = prefix.clone();
                    next.push(i64::from(width));
                    next
                })
            })
            .collect();
    }
    all.retain(|values| {
        rule.constraints.iter().all(|constraint| {
            constraint.relation.holds(
                constraint.left.eval(values).unwrap(),
                constraint.right.eval(values).unwrap(),
            )
        })
    });
    all
}

/// A width as a `u16` in 1..=[`MAX_WIDTH`], if it is one.
fn width(value: Option<i64>) -> Option<u16> {
    u16::try_from(value?)
        .ok()
        .filter(|width| (1..=MAX_WIDTH).contains(width))
}

/// What a rule's leaves are in a function.
struct Leaves {
    vars: Vec<ExprId>,
    constants: Vec<ExprId>,
}

/// `nodes` (a side of a rule, or its conditions) built in `f` over
/// `leaves` with the width variables at `values`: each node's id, `None`
/// where a node is not well formed at those widths.
fn build(f: &mut Function, nodes: &[Node], leaves: &Leaves, values: &[i64]) -> Option<Vec<ExprId>> {
    let mut ids: Vec<ExprId> = Vec::new();
    for node in nodes {
        let at = |index: u8| ids[usize::from(index)];
        let expr = match *node {
            Node::Var(index) => {
                ids.push(leaves.vars[usize::from(index)]);
                continue;
            }
            Node::Const(index) => {
                ids.push(leaves.constants[usize::from(index)]);
                continue;
            }
            Node::Literal { value, width: w } => {
                let w = width(w.eval(values))?;
                let value = match value {
                    Literal::Int(value) => i128::from(value),
                    Literal::Width(lin) => i128::from(lin.eval(values)?),
                };
                Expr::Const(Bits::from_u128(w, value.cast_unsigned()))
            }
            Node::Unary(op, a) => Expr::Unary(op, at(a)),
            Node::Binary(op, a, b) => Expr::Binary(op, at(a), at(b)),
            Node::Flag(op, a, b, c) => Expr::Flag(op, at(a), at(b), at(c)),
            Node::Extract {
                value,
                offset,
                width: w,
            } => Expr::Extract {
                value: at(value),
                offset: u16::try_from(offset.eval(values)?).ok()?,
                width: width(w.eval(values))?,
            },
            Node::Concat { high, low } => Expr::Concat {
                high: at(high),
                low: at(low),
            },
            Node::Extend {
                signed,
                value,
                width: w,
            } => Expr::Extend {
                signed,
                value: at(value),
                width: width(w.eval(values))?,
            },
            Node::Select {
                condition,
                then,
                otherwise,
            } => Expr::Select {
                condition: at(condition),
                then: at(then),
                otherwise: at(otherwise),
            },
        };
        let id = f.add_expr(expr);
        f.width(id)?;
        ids.push(id);
    }
    Some(ids)
}

/// A function with a parameter of each width.
fn function(widths: &[u16]) -> (Function, Vec<ExprId>) {
    let mut f = Function::new(0x1000, Types::new(64));
    let mut reads = Vec::new();
    for &width in widths {
        let ty = f.types.intern(Type::Bits(width));
        let var = f.add_var(Variable {
            kind: VarKind::Parameter,
            name: None,
            ty,
            evidence: Evidence::Default,
            origins: Vec::new(),
        });
        f.parameters.push(var);
        reads.push(f.add_expr(Expr::Var(var)));
    }
    (f, reads)
}

/// Whether `left` and `right` are the same tree.
fn same_tree(f: &Function, left: ExprId, right: ExprId) -> bool {
    if left == right {
        return true;
    }
    let (x, y) = (*f.expr(left).unwrap(), *f.expr(right).unwrap());
    let operands: (Vec<ExprId>, Vec<ExprId>) = (x.operands(f).collect(), y.operands(f).collect());
    operands.0.len() == operands.1.len()
        && blank(x) == blank(y)
        && (operands.0.iter().zip(&operands.1)).all(|(&p, &q)| same_tree(f, p, q))
}

/// `expr` with its operands replaced by `ExprId(0)` (the scalar kinds
/// rules build; others as they are).
fn blank(expr: Expr) -> Expr {
    let o = ExprId(0);
    match expr {
        Expr::Unary(op, _) => Expr::Unary(op, o),
        Expr::Binary(op, ..) => Expr::Binary(op, o, o),
        Expr::Logical(op, ..) => Expr::Logical(op, o, o),
        Expr::Flag(op, ..) => Expr::Flag(op, o, o, o),
        Expr::Extract { offset, width, .. } => Expr::Extract {
            value: o,
            offset,
            width,
        },
        Expr::Concat { .. } => Expr::Concat { high: o, low: o },
        Expr::Extend { signed, width, .. } => Expr::Extend {
            signed,
            value: o,
            width,
        },
        Expr::Select { .. } => Expr::Select {
            condition: o,
            then: o,
            otherwise: o,
        },
        other @ (Expr::Const(_)
        | Expr::Undefined(..)
        | Expr::Var(_)
        | Expr::AddressOf(_)
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. }
        | Expr::Assign { .. }) => other,
    }
}

/// Candidate values of a constant of `width` bits.
fn candidates(width: u16) -> Vec<Bits> {
    let w = u128::from(width);
    [0, 1, 2, 3, 5, 7, w - 1, w, u128::MAX, u128::MAX - 4]
        .into_iter()
        .map(|value| Bits::from_u128(width, value))
        .chain([Bits::from_u64(width, 1).shift_left(u32::from(width) - 1)])
        .collect()
}

/// Checks rule `index`'s matcher at `values`: for some candidate
/// constants it fires on the left side and builds the right side.
/// Whether it fired.
fn matcher_fires(index: usize, rule: &Rule, values: &[i64]) -> bool {
    let var_widths: Vec<u16> = rule
        .vars
        .iter()
        .map(|(_, w)| width(w.eval(values)).unwrap())
        .collect();
    let constant_widths: Vec<u16> = rule
        .constants
        .iter()
        .map(|(_, w)| width(w.eval(values)).unwrap())
        .collect();
    let mut choices: Vec<Vec<Bits>> = vec![Vec::new()];
    for &w in &constant_widths {
        choices = choices
            .into_iter()
            .flat_map(|prefix| {
                candidates(w).into_iter().map(move |bits| {
                    let mut next = prefix.clone();
                    next.push(bits);
                    next
                })
            })
            .collect();
    }
    for constants in choices {
        let (mut f, vars) = function(&var_widths);
        let constants: Vec<ExprId> = constants
            .into_iter()
            .map(|bits| f.add_expr(Expr::Const(bits)))
            .collect();
        let leaves = Leaves { vars, constants };
        let lhs = *build(&mut f, rule.lhs, &leaves, values)
            .unwrap()
            .last()
            .unwrap();
        let Some(new) = rules::apply(&mut f, index, lhs) else {
            continue;
        };
        let rhs = *build(&mut f, rule.rhs, &leaves, values)
            .unwrap_or_else(|| panic!("{}: right side ill-formed at {values:?}", rule.name))
            .last()
            .unwrap();
        assert!(
            same_tree(&f, new, rhs),
            "{}: matcher built something else than the right side at {values:?}",
            rule.name
        );
        return true;
    }
    false
}

#[test]
fn rules_are_proved() {
    let start = Instant::now();
    let mut groups: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut unmatched = Vec::new();
    let mut all: Vec<(&str, Proofs)> = Vec::new();
    for (index, rule) in RULES.iter().enumerate() {
        let mut proofs = Proofs::default();
        let mut proved = 0;
        for values in instances(rule) {
            let mut widths: Vec<u16> = Vec::new();
            let mut valid = true;
            for (_, w) in rule.vars.iter().chain(rule.constants) {
                match width(w.eval(&values)) {
                    Some(w) => widths.push(w),
                    None => valid = false,
                }
            }
            if !valid {
                continue;
            }
            let (mut f, reads) = function(&widths);
            let split = rule.vars.len();
            let leaves = Leaves {
                vars: reads[..split].to_vec(),
                constants: reads[split..].to_vec(),
            };
            let Some(lhs) = build(&mut f, rule.lhs, &leaves, &values) else {
                // No expression of these widths has the left side's shape.
                continue;
            };
            let rhs = build(&mut f, rule.rhs, &leaves, &values)
                .unwrap_or_else(|| panic!("{}: right side ill-formed at {values:?}", rule.name));
            let conditions = build(&mut f, rule.conditions, &leaves, &values)
                .unwrap_or_else(|| panic!("{}: conditions ill-formed at {values:?}", rule.name));
            let holds: Vec<ExprId> = rule
                .holds
                .iter()
                .map(|&root| conditions[usize::from(root)])
                .collect();
            proofs.differ(
                format!("{} at {values:?}", rule.name),
                &f,
                *lhs.last().unwrap(),
                *rhs.last().unwrap(),
                &holds,
            );
            if !matcher_fires(index, rule, &values) {
                unmatched.push(format!("{} at {values:?}", rule.name));
            }
            proved += 1;
        }
        assert!(
            proved > 0,
            "{}: no width it claims is well formed",
            rule.name
        );
        let group = groups.entry(rule.group).or_default();
        group.0 += 1;
        group.1 += proved;
        all.push((rule.name, proofs));
    }
    let built = start.elapsed();
    assert!(
        unmatched.is_empty(),
        "matchers that never fired: {unmatched:#?}"
    );
    // One z3 per rule.
    let (names, proofs): (Vec<&str>, Vec<Proofs>) = all.into_iter().unzip();
    let instances: usize = proofs.iter().map(Proofs::count).sum();
    let Some(results) = run_all(&proofs) else {
        return;
    };
    let mut results: Vec<(&str, Vec<String>, Duration)> = names
        .into_iter()
        .zip(results)
        .map(|(name, (failed, time))| (name, failed, time))
        .collect();
    results.sort_by_key(|&(_, _, time)| Reverse(time));
    println!(
        "{} rules, {instances} instances, by group (rules, instances): {groups:?}; built in {built:.2?}, proved in {:.2?}; slowest: {:?}",
        RULES.len(),
        start.elapsed().saturating_sub(built),
        results
            .iter()
            .take(5)
            .map(|(name, _, time)| format!("{name} {time:.2?}"))
            .collect::<Vec<_>>()
    );
    let failed: Vec<String> = results
        .into_iter()
        .flat_map(|(_, failed, _)| failed)
        .collect();
    assert!(failed.is_empty(), "not proved: {failed:#?}");
}

#[test]
fn the_proof_refutes_a_wrong_rule() {
    // `ne(lshr(x, c), 0) => slt(x, 0)` holds for c = 31 only: without its
    // side condition, z3 must find a counterexample; with c = 31 as the
    // condition, none.
    let (mut f, reads) = function(&[32, 32]);
    let (x, c) = (reads[0], reads[1]);
    let zero = f.add_expr(Expr::Const(Bits::zero(32)));
    let shifted = f.add_expr(Expr::Binary(Binary::LShr, x, c));
    let lhs = f.add_expr(Expr::Binary(Binary::Ne, shifted, zero));
    let rhs = f.add_expr(Expr::Binary(Binary::SLt, x, zero));
    let thirty_one = f.add_expr(Expr::Const(Bits::from_u64(32, 31)));
    let condition = f.add_expr(Expr::Binary(Binary::Eq, c, thirty_one));
    let mut wrong = Proofs::default();
    wrong.differ("unconditional".into(), &f, lhs, rhs, &[]);
    let mut right = Proofs::default();
    right.differ("conditional".into(), &f, lhs, rhs, &[condition]);
    let Some(results) = run_all(&[wrong, right]) else {
        return;
    };
    assert_eq!(results[0].0, ["unconditional: sat"]);
    assert_eq!(results[1].0, Vec::<String>::new());
}
