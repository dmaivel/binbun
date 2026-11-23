//! Where control goes in a structured body, as the tree passes need it:
//! [`Flow`], found in one walk. A statement's place in the tree says
//! where control falls; these are the edges it does not show: which loops
//! a `break` or a `continue` names (a `continue` reaches a `do`-`while`'s
//! test without running the end of its body), and where the `goto`s to
//! each label are (one from outside an arm enters it without its `if`'s
//! test).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ast::ir::{Function, LabelId, Stmt, StmtId};

use super::refine::falls;

/// The jumps of a structured body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Flow {
    /// The loops and switches a `break` names.
    pub(super) broken: BTreeSet<StmtId>,
    /// The loops a `continue` names.
    pub(super) continued: BTreeSet<StmtId>,
    /// How many `goto`s go to each label.
    jumps: BTreeMap<LabelId, usize>,
}

impl Flow {
    /// The jumps of `function`'s body.
    pub(super) fn of(function: &Function) -> Self {
        let mut flow = Self::default();
        let mut work = function.body.clone();
        while let Some(id) = work.pop() {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            match *stmt {
                Stmt::Break(target) => {
                    flow.broken.insert(target);
                }
                Stmt::Continue(target) => {
                    flow.continued.insert(target);
                }
                Stmt::Goto(label) => *flow.jumps.entry(label).or_default() += 1,
                Stmt::Assign { .. }
                | Stmt::Call { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_)
                | Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::DoWhile { .. }
                | Stmt::For { .. }
                | Stmt::Switch { .. }
                | Stmt::Label(_)
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::Try { .. }
                | Stmt::VaStart { .. } => {}
            }
            work.extend(stmt.blocks().flatten().copied());
        }
        flow
    }

    /// Whether control may go off the end of `block`. Conservative:
    /// `true` unless its last statement never goes on.
    pub(super) fn falls(&self, function: &Function, block: &[StmtId]) -> bool {
        falls(function, block, &self.broken)
    }

    /// A `goto` to `label` was dropped.
    pub(super) fn drop_jump(&mut self, label: LabelId) {
        if let Some(count) = self.jumps.get_mut(&label) {
            *count = count.saturating_sub(1);
        }
    }

    /// Whether a `goto` outside `moved` and `beside` goes to a label in
    /// `moved` (at any depth): control then enters `moved` otherwise than
    /// at its start or from `beside`. Moving such code into the arm of an
    /// `if` that holds `beside` would show under the `if`'s test what
    /// runs without it.
    pub(super) fn entered(&self, function: &Function, moved: &[StmtId], beside: &[StmtId]) -> bool {
        let mut labels: BTreeSet<LabelId> = BTreeSet::new();
        let mut inside: BTreeMap<LabelId, usize> = BTreeMap::new();
        let mut work: Vec<(StmtId, bool)> = moved
            .iter()
            .map(|&id| (id, true))
            .chain(beside.iter().map(|&id| (id, false)))
            .collect();
        while let Some((id, moving)) = work.pop() {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            if let Stmt::Label(label) = *stmt
                && moving
            {
                labels.insert(label);
            }
            if let Stmt::Goto(label) = *stmt {
                *inside.entry(label).or_default() += 1;
            }
            work.extend(stmt.blocks().flatten().map(|&inner| (inner, moving)));
        }
        labels.iter().any(|label| {
            self.jumps.get(label).copied().unwrap_or(0) > inside.get(label).copied().unwrap_or(0)
        })
    }
}
