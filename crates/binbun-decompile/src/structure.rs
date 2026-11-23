//! Structuring passes on L2: a goto-only function (as [`crate::lower`]
//! makes it) to `if`/`else`, loops with `break`/`continue`, and `switch`,
//! with `goto`s only where nothing else fits.
//!
//! [`regions`] is the region graph of any L2 function (one node per L1
//! block its code stands for) with its dominators, post-dominators,
//! natural loops and irreducible edges. The pass [`Structure`] (`structure`, under
//! [`binbun_semantics::core::pass`]'s manager) runs:
//!
//! 1. *Schemas* (always): the goto-only body is read as a graph of blocks
//!    (one per label; each edge carries the copies on it) and laid out
//!    again along its dominator tree (Ramsey's "Beyond Relooper"
//!    translation, in C's terms). A block with one forward in-edge is
//!    placed at that edge (an arm, or after a `goto`); a block where
//!    forward edges join is placed after its immediate dominator's
//!    terminator, joins in reverse post-order, so an `if`'s follow is its
//!    immediate post-dominator when it dominates it. A loop header
//!    becomes `while (1)`; edges back to it are `continue`, edges to the
//!    code after the loop `break`. Of the blocks leaving a loop, its main
//!    exit is one whose code goes on to the rest of the function, then
//!    one on its header's or a latch's edge, then the one with the most
//!    code: it follows the loop. Other joins leaving it follow it too,
//!    unless their code only leaves the function or goes to the main exit
//!    (a local exit path, placed after its dominator inside the loop). An
//!    `if` whose one arm is code and other never goes on gets the code
//!    after it, not nested. A switch arm's block that the previous arm's
//!    code also reaches is placed in its arm, the previous arm falling
//!    through (not the switch's post-dominator or a last default's: that
//!    follows the switch). An edge to anything else is a `goto` (the
//!    input's own, kept with its provenance): a join no fall-through
//!    reaches, an exit of a loop with several, an edge of an irreducible
//!    graph (a retreating edge to a block that does not dominate its
//!    source), a block nested deeper than [`Options::depth`] (placed at
//!    the end of the body). Blocks are never copied. Work: linear in the
//!    blocks and edges, but for loop discovery and exits (the loop nesting
//!    depth per block or edge) and the dominator iteration, all charged
//!    to the [`Budget`].
//! 2. *Refinement* ([`Options::refine`]): an `if` with an arm that
//!    never falls through is turned (negating its condition if needed) so
//!    that the other arm follows it; `while (1) { l: if (c) break; … }`
//!    becomes `l: while (!c) { … }`, and a loop ending in
//!    `if (c) break;` with no `continue` a `do`-`while` (a `goto` to a
//!    label ending its body then being a `continue`).
//!
//! Further passes (short circuits, duplication, SAILR, loop rules) are
//! tree rewrites like refinement, each its own [`Pass`] after
//! [`Structure`]: [`ShortCircuit`] and [`Loops`] (de-inversion, `for`,
//! exit conditions), with [`ArrayLoops`] before it (pointer loops as
//! array loops), [`LoopHeads`] before both (`while (1)` tests
//! simplification uncovered) and [`CommonArms`] first (the code both arms of an
//! `if` begin or end with, before or after it), [`Switches`] (comparison
//! chains on one value as
//! `switch`), [`Exits`] (a `goto` to a small exit replaced by a copy of
//! it, and forward `goto`s folded into `if` arms without copying the
//! skipped code), [`Conditions`] (assignments into the conditions that read
//! them) and [`Forward`] (that fold again, after the others). The schemas
//! give them the shape to work on: every loop a
//! `while (1)` or the `while`/`do`-`while` refinement made, every exit a
//! `break`, `continue` or the input's `goto`.
//!
//! The input's blocks are its labels (each block's code after its label),
//! but the output keeps only the labels a `goto` goes to: L1's blocks are
//! known by their statements' and decisions' provenance
//! (`Origin::Block`), and the function's control graph through them
//! ([`crate::validate::graph`]) is unchanged: the input's statements are
//! reused (keeping their provenance), new nodes are only loops (a
//! `while (c)` or `do`-`while` taking its `if`'s provenance), `break`,
//! `continue`, negated conditions and the `return` of a body that ended
//! without one.

mod analysis;
mod arms;
mod arrays;
mod cfg;
mod conditions;
mod exits;
mod flow;
mod forward;
mod heads;
mod loops;
mod refine;
mod schemas;
mod short;
mod switches;

use core::fmt;

use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;
use binbun_ast::ir::{Function, Stmt, StmtId};
use binbun_semantics::core::pass::{self, Changed, Cx, Pass};

use crate::pass::{L2Env, size};

pub use analysis::{Loop, PostDominator, Regions, regions};
pub use arms::CommonArms;
pub use arrays::ArrayLoops;
pub use conditions::Conditions;
pub use exits::Exits;
pub use forward::Forward;
pub use heads::LoopHeads;
pub use loops::{Loops, Rotated};
pub(crate) use refine::always;
pub use short::ShortCircuit;
pub use switches::Switches;

/// What structuring may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Work allowed per block, edge and statement of the function (the
    /// [`Budget`]): dominator iterations, loop discovery and exits cost
    /// one unit per step. 256 by default.
    pub work: u64,
    /// The deepest nesting of statements the schemas build; a block
    /// placed deeper becomes a `goto` to it, placed at the end of the
    /// body. 48 by default; at least 1 (a loop placed at the end of the
    /// body is laid out there, at depth 0: with no depth at all it would
    /// be placed at the end again, for ever).
    pub depth: usize,
    /// Whether to run refinement (conditions turned to un-nest code,
    /// `while (c)` and `do`-`while` loops).
    pub refine: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            work: 256,
            depth: 48,
            refine: true,
        }
    }
}

/// The work left for a function: [`Options::work`] per unit of its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    left: u64,
}

impl Budget {
    /// The budget of a function of `size` units under `options`.
    pub fn new(options: &Options, size: u64) -> Self {
        Self {
            left: options.work.saturating_mul(size.max(1)),
        }
    }

    /// Spends `work` units.
    ///
    /// # Errors
    ///
    /// [`Refusal::Budget`] if less is left.
    pub fn charge(&mut self, work: u64) -> Result<(), Refusal> {
        self.left = self.left.checked_sub(work).ok_or(Refusal::Budget)?;
        Ok(())
    }
}

/// Why a function was not structured (it is unchanged, in goto form).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The input is not what the pass takes (goto-only L2, a graph
    /// [`regions`] can build).
    Malformed {
        /// The statement concerned, if one.
        stmt: Option<StmtId>,
        /// What is wrong.
        reason: &'static str,
    },
    /// The work exceeded the [`Budget`].
    Budget,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed {
                stmt: Some(stmt),
                reason,
            } => write!(f, "s{}: {reason}", stmt.0),
            Self::Malformed { stmt: None, reason } => f.write_str(reason),
            Self::Budget => f.write_str("structuring needs more work than its budget"),
        }
    }
}

impl core::error::Error for Refusal {}

/// What structuring did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// `goto`s in the input.
    pub gotos_before: usize,
    /// `goto`s left.
    pub gotos_after: usize,
    /// `break`s and `continue`s naming a statement other than the
    /// innermost one they could (printed as `goto`s).
    pub exits: usize,
    /// Loops made.
    pub loops: usize,
    /// `if`s in the output.
    pub ifs: usize,
    /// `switch`es in the output.
    pub switches: usize,
    /// Edges that make the graph irreducible.
    pub irreducible: usize,
    /// Blocks placed at the end of the body for depth ([`Options::depth`]).
    pub deferred: usize,
}

/// The pass `structure`: structures a goto-only body (see the module
/// documentation) under its [`Options`], keeping the [`Stats`] of its last
/// run. It refuses, leaving the function in goto form (as correct), where
/// the body is not goto-only ([`Refusal::Malformed`], as the manager's
/// `Malformed`) or structuring needs more work than [`Options::work`]
/// allows ([`Refusal::Budget`], as `OutOfFuel`). Fuel: a unit per
/// statement and expression, on top of its own budget.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Structure {
    /// What it may do.
    pub options: Options,
    stats: Option<Stats>,
}

impl Structure {
    /// The pass under `options`.
    pub fn new(options: Options) -> Self {
        Self {
            options,
            stats: None,
        }
    }

    /// What its last run did, if it structured the function.
    pub fn stats(&self) -> Option<Stats> {
        self.stats
    }
}

impl<'e> Pass<Function, L2Env<'e>> for Structure {
    fn name(&self) -> &'static str {
        "structure"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, pass::Refusal> {
        self.stats = None;
        cx.fuel.spend(size(function))?;
        let stats = structure(function, &self.options).map_err(|refusal| match refusal {
            Refusal::Budget => pass::Refusal::OutOfFuel,
            Refusal::Malformed { .. } => pass::Refusal::Malformed(refusal.to_string()),
        })?;
        self.stats = Some(stats);
        Ok(Changed::Yes)
    }
}

/// [`Structure`]: work is bounded by `options.work` per block, edge and
/// statement; on a refusal the function is unchanged.
fn structure(function: &mut Function, options: &Options) -> Result<Stats, Refusal> {
    let graph = cfg::Cfg::of(function)?;
    let (successors, exits) = graph.graph();
    let edges: usize = successors.iter().map(Vec::len).sum();
    let size = successors.len() + edges + function.stmts.len();
    let mut budget = Budget::new(options, size as u64);
    let analysis = analysis::Analysis::new(&successors, &exits, &mut budget)?;
    let plan = schemas::Plan::new(&graph, &analysis, &mut budget)?;
    let mut stats = Stats {
        gotos_before: graph.gotos,
        irreducible: analysis.irreducible.len(),
        ..Stats::default()
    };
    stats.deferred = schemas::emit(function, &graph, &plan, options.depth.max(1));
    // Labels no `goto` names first: refinement reads a loop's first and
    // last statements, which they would hide; then those whose `goto`s
    // refinement made `continue`s.
    drop_labels(function);
    if options.refine {
        refine::refine(function);
        drop_labels(function);
    }
    count(function, &mut stats);
    Ok(stats)
}

/// Drops the labels no `goto` goes to.
pub(super) fn drop_labels(function: &mut Function) {
    let mut targets = BTreeSet::new();
    let mut labels = Vec::new();
    let mut holders = Vec::new();
    let mut work = function.body.clone();
    while let Some(id) = work.pop() {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        if let Stmt::Goto(label) = *stmt {
            targets.insert(label);
        } else if let Stmt::Label(label) = *stmt {
            labels.push((id, label));
        }
        let before = work.len();
        for inner in stmt.blocks() {
            work.extend_from_slice(inner);
        }
        if work.len() > before {
            holders.push(id);
        }
    }
    let unused: BTreeSet<StmtId> = labels
        .into_iter()
        .filter(|(_, label)| !targets.contains(label))
        .map(|(id, _)| id)
        .collect();
    if unused.is_empty() {
        return;
    }
    function.body.retain(|id| !unused.contains(id));
    for id in holders {
        if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
            for block in stmt.blocks_mut() {
                block.retain(|id| !unused.contains(id));
            }
        }
    }
}

/// Counts the output's statements into `stats`.
fn count(function: &Function, stats: &mut Stats) {
    // Enclosing breakable statements, innermost last: (statement, loop?).
    fn walk(
        function: &Function,
        block: &[StmtId],
        around: &mut Vec<(StmtId, bool)>,
        stats: &mut Stats,
    ) {
        for &id in block {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            match stmt {
                Stmt::Goto(_) => stats.gotos_after += 1,
                Stmt::Break(target) => {
                    if around.last().map(|&(inner, _)| inner) != Some(*target) {
                        stats.exits += 1;
                    }
                }
                Stmt::Continue(target) => {
                    let inner = around.iter().rev().find(|&&(_, is_loop)| is_loop);
                    if inner.map(|&(inner, _)| inner) != Some(*target) {
                        stats.exits += 1;
                    }
                }
                Stmt::If { .. } => stats.ifs += 1,
                Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } => stats.loops += 1,
                Stmt::Switch { .. } => stats.switches += 1,
                Stmt::Assign { .. }
                | Stmt::Call { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_)
                | Stmt::Label(_)
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::Try { .. }
                | Stmt::VaStart { .. } => {}
            }
            let breakable = stmt.is_loop() || matches!(stmt, Stmt::Switch { .. });
            if breakable {
                around.push((id, stmt.is_loop()));
            }
            for inner in stmt.blocks() {
                walk(function, inner, around, stats);
            }
            if breakable {
                around.pop();
            }
        }
    }
    walk(function, &function.body, &mut Vec::new(), stats);
}
