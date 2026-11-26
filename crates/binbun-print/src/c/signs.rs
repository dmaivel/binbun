//! Each local's signedness chosen on the conversion plan
//! ([`Planner::choose_signs`]): where L2 leaves it free, a local integer
//! prints signed or unsigned as fewer casts are then needed. The printer
//! makes every read what its operation needs whatever the type, so the
//! choice changes only the casts and conversions printed, never a value;
//! and it is presentation only: L2's types stay as they are, the choice
//! lives in the plan ([`super::Plan::types`]).
//!
//! Like Boomerang's signedness hints, a choice by the reads; unlike them
//! (a vote of the operations) and Ghidra's most specific type (one
//! unsigned read makes a variable unsigned), each choice is costed by
//! planning again the statements that read or write the locals, exactly
//! as they would print.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, Place, StmtId, VarId, VarKind};
use binbun_ast::types::{Evidence, Type};
use binbun_semantics::ir::Binary;

use super::PrintError;
use super::plan::{Cost, Plan, Planner};

/// The most rounds over the choices (a change leaves fewer casts, so it
/// ends; few functions take more than two).
const ROUNDS: usize = 4;

/// Locals that take one signedness together (one, or several compared
/// with each other), with their widths, and the statements with plans of
/// their own that read or write any of them.
struct Choice {
    vars: Vec<(VarId, u16)>,
    statements: Vec<StmtId>,
}

impl Planner<'_> {
    /// Each local whose signedness L2 leaves free ([`choices`]) given the
    /// one that costs fewer casts, then fewer conversions, in the
    /// statements that read or write it, planned again under each
    /// ([`Cost`]): first each set of such locals compared with each other
    /// together (which alone would each keep the other's signedness to
    /// agree with it), then each alone, in the order of the locals, a tie
    /// keeping the spelling; over and again while one changes, at most
    /// [`ROUNDS`] times.
    ///
    /// # Errors
    ///
    /// The printer refuses a statement under the types it had planned
    /// (which it planned before).
    pub fn choose_signs(&mut self) -> Result<(), PrintError> {
        let choices = choices(self.function(), self.plan());
        for _ in 0..ROUNDS {
            let mut changed = false;
            for choice in &choices {
                changed |= self.choose_sign(choice)?;
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }

    /// The locals of `choice` given the signedness that costs least in
    /// their statements (all signed, all unsigned, or as they are);
    /// whether that changed a spelling.
    fn choose_sign(&mut self, choice: &Choice) -> Result<bool, PrintError> {
        let now: Vec<Option<Type>> = choice
            .vars
            .iter()
            .map(|(var, _)| self.plan().types().get(var).cloned())
            .collect();
        let mut best = (self.cost_of(&choice.statements), None);
        let mut last = None;
        for signed in [true, false] {
            let typed = |width| {
                if signed {
                    Type::Int(width)
                } else {
                    Type::UInt(width)
                }
            };
            let mut same = true;
            for &(var, width) in &choice.vars {
                same &= self.spelled_as(var, &typed(width));
            }
            if same {
                continue;
            }
            for &(var, width) in &choice.vars {
                self.retype(var, Some(typed(width)));
            }
            last = Some(signed);
            // Refused so typed: never chosen.
            if self.replan(&choice.statements).is_ok() {
                let cost = self.cost_of(&choice.statements);
                if cost < best.0 {
                    best = (cost, Some(signed));
                }
            }
        }
        if last != best.1 {
            for (&(var, width), was) in choice.vars.iter().zip(now) {
                let ty = match best.1 {
                    Some(true) => Some(Type::Int(width)),
                    Some(false) => Some(Type::UInt(width)),
                    None => was,
                };
                self.retype(var, ty);
            }
            self.replan(&choice.statements)?;
        }
        Ok(best.1.is_some())
    }

    /// What `statements` cost as planned now.
    fn cost_of(&self, statements: &[StmtId]) -> Cost {
        statements
            .iter()
            .map(|&id| self.plan().statement(id))
            .fold(Cost::default(), |sum, cost| Cost {
                casts: sum.casts + cost.casts,
                conversions: sum.conversions + cost.conversions,
            })
    }
}

/// The choices of `function`'s locals whose signedness the plan may
/// choose, with the statements of `plan` that read or write them: each
/// set of two or more compared with each other (by `==`, `!=`, `<` or
/// `<=`), then each alone, in the order of the locals. A local's
/// signedness is free if it is an integer (or untyped bits) of 8 to 64
/// bits whose type nothing declared (evidence default or deduced), not a
/// parameter (its callers' declarations give its type), not in memory and
/// not address-taken (a pointer to it has a type too), all of whose reads
/// and writes are in statements with plans of their own.
fn choices(function: &Function, plan: &Plan) -> Vec<Choice> {
    let (uses, links) = uses(function, plan);
    let singles: Vec<Choice> = uses
        .into_iter()
        .filter_map(|(var, statements)| {
            let mut statements = statements?;
            let width = choosable(function, var)?;
            statements.sort_unstable();
            statements.dedup();
            Some(Choice {
                vars: vec![(var, width)],
                statements,
            })
        })
        .collect();
    let index: BTreeMap<VarId, usize> = (0..)
        .zip(&singles)
        .filter_map(|(at, choice)| Some((choice.vars.first()?.0, at)))
        .collect();
    let mut root: Vec<usize> = (0..singles.len()).collect();
    let find = |root: &[usize], mut at: usize| {
        while let Some(&up) = root.get(at).filter(|&&up| up != at) {
            at = up;
        }
        at
    };
    for (a, b) in links {
        if let (Some(&a), Some(&b)) = (index.get(&a), index.get(&b)) {
            let (a, b) = (find(&root, a), find(&root, b));
            if let Some(slot) = root.get_mut(a.max(b)) {
                *slot = a.min(b);
            }
        }
    }
    let mut groups: BTreeMap<usize, Choice> = BTreeMap::new();
    for (at, single) in singles.iter().enumerate() {
        let group = groups.entry(find(&root, at)).or_insert_with(|| Choice {
            vars: Vec::new(),
            statements: Vec::new(),
        });
        group.vars.extend(&single.vars);
        group.statements.extend(&single.statements);
    }
    let mut out: Vec<Choice> = groups
        .into_values()
        .filter(|group| group.vars.len() > 1)
        .map(|mut group| {
            group.statements.sort_unstable();
            group.statements.dedup();
            group
        })
        .collect();
    out.extend(singles);
    out
}

/// The locals each statement `plan` has a plan of its own for reads or
/// writes in `function` (`None`: one is read or written elsewhere, or its
/// address is taken), and the pairs of locals compared with each other.
#[expect(clippy::type_complexity, reason = "a map and a list, each used once")]
fn uses(
    function: &Function,
    plan: &Plan,
) -> (BTreeMap<VarId, Option<Vec<StmtId>>>, Vec<(VarId, VarId)>) {
    let mut uses: BTreeMap<VarId, Option<Vec<StmtId>>> = BTreeMap::new();
    let mut links = Vec::new();
    let mut seen = vec![u32::MAX; function.exprs.len()];
    for (at, owner) in held(function, plan) {
        let Some(stmt) = function.stmt(at) else {
            continue;
        };
        let mut note = |var: VarId, usable: bool| {
            let slot = uses.entry(var).or_insert_with(|| Some(Vec::new()));
            match (slot.as_mut(), owner) {
                (Some(list), Some(owner)) if usable => list.push(owner),
                (Some(_) | None, Some(_) | None) => *slot = None,
            }
        };
        for place in stmt.places() {
            if let &Place::Var(var) = place {
                note(var, true);
            }
        }
        let mut work = stmt.roots();
        while let Some(id) = work.pop() {
            let Some(mark) = seen.get_mut(id.0 as usize) else {
                continue;
            };
            if *mark == at.0 {
                continue;
            }
            *mark = at.0;
            let Some(expr) = function.expr(id) else {
                continue;
            };
            match *expr {
                Expr::Var(var) | Expr::Assign { var, .. } => note(var, true),
                Expr::AddressOf(var) => note(var, false),
                Expr::Binary(
                    Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe | Binary::SLt | Binary::SLe,
                    a,
                    b,
                ) => {
                    if let (Some(a), Some(b)) = (local(function, a), local(function, b))
                        && a != b
                    {
                        links.push((a, b));
                    }
                }
                Expr::Binary(..)
                | Expr::Const(_)
                | Expr::Undefined(..)
                | Expr::Unary(..)
                | Expr::Logical(..)
                | Expr::Flag(..)
                | Expr::Extract { .. }
                | Expr::Concat { .. }
                | Expr::Extend { .. }
                | Expr::Select { .. }
                | Expr::Lanes { .. }
                | Expr::Float { .. }
                | Expr::Cast { .. }
                | Expr::Load { .. }
                | Expr::Call(_)
                | Expr::Exception { .. } => {}
            }
            work.extend(expr.operands(function));
        }
    }
    (uses, links)
}

/// The variable expression `id` reads or assigns, if it does.
fn local(function: &Function, id: ExprId) -> Option<VarId> {
    match *function.expr(id)? {
        Expr::Var(var) | Expr::Assign { var, .. } => Some(var),
        Expr::Const(_)
        | Expr::Undefined(..)
        | Expr::AddressOf(_)
        | Expr::Unary(..)
        | Expr::Binary(..)
        | Expr::Logical(..)
        | Expr::Flag(..)
        | Expr::Extract { .. }
        | Expr::Concat { .. }
        | Expr::Extend { .. }
        | Expr::Select { .. }
        | Expr::Lanes { .. }
        | Expr::Float { .. }
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. } => None,
    }
}

/// The width of local `var`, if its signedness is free: an integer or
/// untyped bits of 8, 16, 32 or 64 bits whose type nothing declared.
fn choosable(function: &Function, var: VarId) -> Option<u16> {
    let variable = function.var(var)?;
    if variable.kind != VarKind::Local
        || !matches!(variable.evidence, Evidence::Default | Evidence::Deduced)
    {
        return None;
    }
    match *function.types.get(variable.ty)? {
        Type::Bits(width) | Type::Int(width) | Type::UInt(width)
            if matches!(width, 8 | 16 | 32 | 64) =>
        {
            Some(width)
        }
        Type::Bits(_)
        | Type::Int(_)
        | Type::UInt(_)
        | Type::Char { .. }
        | Type::Bool(_)
        | Type::Float(_)
        | Type::Pointer(_)
        | Type::Code(_)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Array { .. }
        | Type::Vector { .. }
        | Type::Enum(_) => None,
    }
}

/// The statements of `function` its body holds, each with the statement
/// whose plan holds its conversions: the innermost of it and the
/// statements around it with a plan of its own (`None`: none has).
fn held(function: &Function, plan: &Plan) -> Vec<(StmtId, Option<StmtId>)> {
    let mut held = Vec::new();
    let mut work: Vec<(StmtId, Option<StmtId>)> =
        function.body.iter().rev().map(|&id| (id, None)).collect();
    while let Some((id, around)) = work.pop() {
        let owner = if plan.has(id) { Some(id) } else { around };
        held.push((id, owner));
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        for block in stmt.blocks() {
            work.extend(block.iter().rev().map(|&child| (child, owner)));
        }
    }
    held
}
