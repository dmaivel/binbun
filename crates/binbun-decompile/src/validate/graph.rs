//! An L2 function's control flow as a graph of the L1 blocks its nodes
//! stand for ([`Origin::Block`] in its provenance), as C runs it.
//!
//! The nodes: a block's straight-line code ([`Kind::Code`]: statements
//! of one block in a row), its decision ([`Kind::Decision`]: an `if`'s or
//! a loop's condition, a `switch`'s scrutinee; a `switch` naming several
//! blocks, one per value, stands for their chain of comparisons: a
//! decision per value, of its block, to its arm or the next value's, the
//! last one's to the default), joins where control only
//! passes through (a label, the top of a loop) and one exit. A condition
//! is one decision per block: an [`Expr::Logical`] (`&&`, `||`) whose
//! operands are different blocks' decisions is split as C evaluates it
//! (the left operand decides first; the right one only where the left one
//! does not decide), a `!` swaps where its operand goes. A statement
//! without a block (the copies on an edge, a `goto`, a `break`, a new
//! `return` at the end of the body) is not a node: control passes through
//! it. A loop whose condition is the constant 1 (`while (1)`,
//! `do … while (1)`, `for (…; 1; …)`) decides nothing: its top is a
//! [`Kind::Join`] to its body.
//!
//! Exceptions: a statement that may unwind ([`itanium::unwinds`]: but
//! for calls to functions declared never to throw) in a `Try`'s body is its
//! block's decision (the invoke ending its L1 block):
//! on to what follows, or to the `Try`'s dispatch. A call to a function
//! that resumes unwinding ([`Exceptions::resume`]) does not go on. The
//! dispatch ([`Kind::Fork`]) is no block's: control passes through it to
//! each handler, so an unwinding statement's block goes to the handlers'
//! code, as L1's goes to the landing pad's, through the blocks the `Try`'s
//! provenance names as [`Origin::Absorbed`] (the landing pad's own block,
//! its selector tests and resume calls the handlers stand for:
//! [`Graph::absorbed`]). Its edge to where an exception no handler takes
//! propagates (the dispatch of the `Try` around, else the exit), unless
//! the last handler takes every exception, is optional
//! ([`Region::optional`]): the Itanium C++ ABI's personality routine
//! enters a landing pad only with a selector of its clauses, so whether
//! the pad's code tests for others (GCC's resume, or Clang's fall into a
//! handler) is not behaviour. A handler's end goes on after the `Try`, or
//! for one that propagates (a cleanup) to where the exception propagates.
//!
//! From that, [`Graph::flow`] reads the blocks' graph: control enters a
//! block's code at a node of the block ([`Region`]) and runs through its
//! code and at most one decision of its own (the block's terminator) to
//! its successors: a node of another block, or of the same block after
//! its decision or back on its own code (the block again), the exit, or
//! a loop of joins alone ([`Successor::Spin`]).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{
    Arm, Block, Callee, Escape, Expr, ExprId, Function, HandlerKind, LabelId, Logical, Origin,
    Stmt, StmtId,
};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Unary;
use binbun_ssa::ir::BlockId;

use crate::itanium::{self, Exceptions};

/// A node of a [`Graph`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u32);

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Straight-line statements of a block, in a row (the first one
    /// named): one successor, the exit after one that stops.
    Code {
        /// The first statement.
        stmt: StmtId,
        /// The block.
        block: BlockId,
    },
    /// A decision of a block: a condition, or the part of one that is the
    /// block's (successors: where it goes if it holds, then if not), or a
    /// `switch`'s scrutinee (each arm in order, then where no arm matches
    /// if none is the default).
    Decision {
        /// The statement.
        stmt: StmtId,
        /// The block.
        block: BlockId,
    },
    /// Control leaves the function: a return, trap, unreachable point, an
    /// escape that does not continue, or the end of the body.
    Exit,
    /// Control passes through: a label, the top of a loop. One successor.
    Join,
    /// A `Try`'s dispatch: control passes through to one of its
    /// successors (its handlers), or, optionally, on to where an
    /// exception no handler takes propagates ([`Graph::optional`]).
    Fork,
}

impl Kind {
    /// The block it stands for (code and decisions).
    pub fn block(self) -> Option<BlockId> {
        match self {
            Self::Code { block, .. } | Self::Decision { block, .. } => Some(block),
            Self::Exit | Self::Join | Self::Fork => None,
        }
    }
}

/// A node: what it is and where control goes from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// What it is.
    pub kind: Kind,
    /// Where control goes next.
    pub successors: Vec<NodeId>,
}

/// An L2 function's control flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    /// The nodes; the first is the exit.
    pub nodes: Vec<Node>,
    /// Where the body starts.
    pub entry: NodeId,
    /// The L1 blocks the dispatch of a `Try` stands for (a landing pad's
    /// selector tests, a call resuming unwinding): they have no node, and
    /// control passes through them to where they go.
    pub absorbed: BTreeSet<BlockId>,
    /// The optional successor of each `Try`'s dispatch ([`Kind::Fork`])
    /// that has one: where an exception no handler takes propagates.
    pub optional: BTreeMap<NodeId, NodeId>,
}

/// Where control goes from a block (or from the body's start).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Successor {
    /// A block's code or decision.
    Block(BlockId),
    /// Out of the function.
    Exit,
    /// Round a loop with no code or decision of any block, forever.
    Spin,
}

/// Control entering a block's code at a node, and where it goes from
/// there through the block's code and decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    /// The block.
    pub block: BlockId,
    /// Where control enters it.
    pub entry: NodeId,
    /// Where it goes next.
    pub successors: BTreeSet<Successor>,
    /// Where it may also go, which L1 need not (a `Try` dispatch's edge
    /// for an exception no handler takes; not followed further).
    pub optional: BTreeSet<Successor>,
}

/// The blocks' graph of a [`Graph`]: [`Graph::flow`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    /// Where control goes from the body's start.
    pub start: Successor,
    /// Each entry into a block reached from the start, in the order
    /// found (the start's first).
    pub regions: Vec<Region>,
}

impl Flow {
    /// Each block reached, with the union of its regions' successors.
    pub fn blocks(&self) -> BTreeMap<BlockId, BTreeSet<Successor>> {
        let mut blocks: BTreeMap<BlockId, BTreeSet<Successor>> = BTreeMap::new();
        for region in &self.regions {
            blocks
                .entry(region.block)
                .or_default()
                .extend(region.successors.iter().chain(&region.optional).copied());
        }
        blocks
    }
}

/// Statements nested deeper than this are refused.
const DEPTH: usize = 1000;

/// The exit node.
pub const EXIT: NodeId = NodeId(0);

/// Where control goes from a node through joins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Node(NodeId),
    Exit,
    Spin,
}

impl Graph {
    /// The control flow of `function`'s body; calls to the functions that
    /// resume unwinding (`exceptions`) do not return.
    ///
    /// # Errors
    ///
    /// A statement is missing, a label is defined twice or a `goto`'s is
    /// not defined, a `break` or `continue` names no enclosing statement
    /// of its kind, a statement stands for two blocks, a decision (or a
    /// part of a condition) for none, or statements nest deeper than 1000.
    pub fn of(function: &Function, exceptions: &Exceptions) -> Result<Self, String> {
        let mut builder = Builder {
            function,
            exceptions,
            nodes: vec![Node {
                kind: Kind::Exit,
                successors: Vec::new(),
            }],
            labels: BTreeMap::new(),
            breaks: BTreeMap::new(),
            continues: BTreeMap::new(),
            unwinds: Vec::new(),
            absorbed: BTreeSet::new(),
            optional: BTreeMap::new(),
        };
        builder.labels(&function.body, 0)?;
        let entry = builder.block(&function.body, EXIT, 0)?;
        Ok(Self {
            nodes: builder.nodes,
            entry,
            absorbed: builder.absorbed,
            optional: builder.optional,
        })
    }

    /// Node `id`.
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id.0 as usize)
    }

    /// The blocks with a node.
    pub fn blocks(&self) -> BTreeSet<BlockId> {
        self.nodes
            .iter()
            .filter_map(|node| node.kind.block())
            .collect()
    }

    /// The blocks' graph: from the body's start, each entry into a block's
    /// code and where control goes from it (see the module documentation).
    ///
    /// # Errors
    ///
    /// A node is missing, or a join has no successor.
    pub fn flow(&self) -> Result<Flow, String> {
        let resolved = self.resolved()?;
        let target = |id: NodeId| {
            resolved
                .get(id.0 as usize)
                .copied()
                .ok_or_else(|| format!("no node {}", id.0))
        };
        let mut regions = Vec::new();
        let start = self.successor(target(self.entry)?)?;
        let mut work = match target(self.entry)? {
            Target::Node(node) => vec![node],
            Target::Exit | Target::Spin => Vec::new(),
        };
        let mut done = BTreeSet::new();
        // A stack: the start's region first.
        while let Some(entry) = work.pop() {
            if !done.insert(entry) {
                continue;
            }
            let region = self.region(entry, &target, &mut work)?;
            regions.push(region);
        }
        Ok(Flow { start, regions })
    }

    /// The block (or exit, or loop of joins) `target` is.
    fn successor(&self, target: Target) -> Result<Successor, String> {
        Ok(match target {
            Target::Node(id) => Successor::Block(self.block_of(id)?),
            Target::Exit => Successor::Exit,
            Target::Spin => Successor::Spin,
        })
    }

    fn block_of(&self, id: NodeId) -> Result<BlockId, String> {
        self.node(id)
            .and_then(|node| node.kind.block())
            .ok_or_else(|| format!("node {} is no block's", id.0))
    }

    /// The region entered at `entry` (code or a decision): its block's
    /// code from there, then its decision; the entries it reaches pushed
    /// on `work`.
    fn region(
        &self,
        entry: NodeId,
        target: &dyn Fn(NodeId) -> Result<Target, String>,
        work: &mut Vec<NodeId>,
    ) -> Result<Region, String> {
        let block = self.block_of(entry)?;
        let mut reach = Reach::default();
        let mut walked = BTreeSet::new();
        let mut at = entry;
        loop {
            let node = self.node(at).ok_or_else(|| format!("no node {}", at.0))?;
            match node.kind {
                Kind::Code { block: own, .. } if own == block && walked.insert(at) => {
                    let next = node.successors.first().copied().unwrap_or(EXIT);
                    match target(next)? {
                        Target::Node(next)
                            if !matches!(self.node(next).map(|n| n.kind), Some(Kind::Fork)) =>
                        {
                            at = next;
                        }
                        other @ (Target::Node(_) | Target::Exit | Target::Spin) => {
                            self.reach(other, target, false, &mut reach, work, 0)?;
                            break;
                        }
                    }
                }
                Kind::Decision { block: own, .. } if own == block => {
                    for &next in &node.successors {
                        self.reach(target(next)?, target, false, &mut reach, work, 0)?;
                    }
                    break;
                }
                // Another block's node, or its own code again.
                Kind::Code { .. } | Kind::Decision { .. } => {
                    self.reach(Target::Node(at), target, false, &mut reach, work, 0)?;
                    break;
                }
                Kind::Exit | Kind::Join | Kind::Fork => {
                    return Err(format!("node {} is no block's", at.0));
                }
            }
        }
        Ok(Region {
            block,
            entry,
            successors: reach.successors,
            optional: reach.optional,
        })
    }

    /// Adds where control going to `to` goes to `reach` (to its optional
    /// successors if `optional`), through `Try` dispatches (a dispatch's
    /// handlers; optionally where what none takes propagates); the
    /// entries of the regions it enters pushed on `work`.
    fn reach(
        &self,
        to: Target,
        target: &dyn Fn(NodeId) -> Result<Target, String>,
        optional: bool,
        reach: &mut Reach,
        work: &mut Vec<NodeId>,
        depth: usize,
    ) -> Result<(), String> {
        if let Target::Node(id) = to
            && let Some(node) = self.node(id)
            && node.kind == Kind::Fork
        {
            if depth > DEPTH {
                return Err("try dispatches nest too deeply".to_string());
            }
            for &next in &node.successors {
                self.reach(target(next)?, target, optional, reach, work, depth + 1)?;
            }
            if let Some(&outer) = self.optional.get(&id) {
                self.reach(target(outer)?, target, true, reach, work, depth + 1)?;
            }
            return Ok(());
        }
        let successor = self.successor(to)?;
        if optional {
            reach.optional.insert(successor);
        } else {
            reach.successors.insert(successor);
            if let Target::Node(id) = to {
                work.push(id);
            }
        }
        Ok(())
    }

    /// Where control goes from each node through joins.
    fn resolved(&self) -> Result<Vec<Target>, String> {
        let mut resolved: Vec<Option<Target>> = vec![None; self.nodes.len()];
        let mut on_path = vec![false; self.nodes.len()];
        let mut path = Vec::new();
        for start in 0..self.nodes.len() {
            let mut at = start;
            let target = loop {
                if let Some(Some(target)) = resolved.get(at) {
                    break *target;
                }
                if on_path.get(at).copied().unwrap_or(false) {
                    break Target::Spin;
                }
                let node = self.nodes.get(at).ok_or_else(|| format!("no node {at}"))?;
                match node.kind {
                    Kind::Exit => break Target::Exit,
                    Kind::Code { .. } | Kind::Decision { .. } | Kind::Fork => {
                        break Target::Node(NodeId(number(at)));
                    }
                    Kind::Join => {
                        let next = node
                            .successors
                            .first()
                            .ok_or_else(|| format!("join {at} goes nowhere"))?;
                        if let Some(flag) = on_path.get_mut(at) {
                            *flag = true;
                        }
                        path.push(at);
                        at = next.0 as usize;
                    }
                }
            };
            for done in path.drain(..).chain([start]) {
                if let Some(flag) = on_path.get_mut(done) {
                    *flag = false;
                }
                if let Some(slot) = resolved.get_mut(done) {
                    slot.get_or_insert(target);
                }
            }
        }
        Ok(resolved
            .into_iter()
            .map(|t| t.unwrap_or(Target::Exit))
            .collect())
    }
}

/// `index` as a `u32`.
fn number(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}

/// Where control goes from a region.
#[derive(Default)]
struct Reach {
    successors: BTreeSet<Successor>,
    optional: BTreeSet<Successor>,
}

struct Builder<'a> {
    function: &'a Function,
    exceptions: &'a Exceptions,
    nodes: Vec<Node>,
    labels: BTreeMap<LabelId, NodeId>,
    /// Where a `break` of each enclosing loop or switch goes.
    breaks: BTreeMap<StmtId, NodeId>,
    /// Where a `continue` of each enclosing loop goes.
    continues: BTreeMap<StmtId, NodeId>,
    /// The dispatch of each `Try` whose body holds the statements being
    /// built, innermost last: where an exception there goes.
    unwinds: Vec<NodeId>,
    /// The blocks `Try` dispatches absorbed.
    absorbed: BTreeSet<BlockId>,
    /// The optional successor of each `Try`'s dispatch decision.
    optional: BTreeMap<NodeId, NodeId>,
}

/// The two blocks a loop statement's `origins` name, if two: the one
/// deciding at entry, then the one deciding at each iteration
/// ([`Origin::Block`]).
fn entry_and_latch(origins: &[Origin]) -> Option<(BlockId, BlockId)> {
    let mut blocks = origins.iter().filter_map(|origin| match *origin {
        Origin::Block(block) => Some(block),
        Origin::Value(_)
        | Origin::Instruction(_)
        | Origin::Register(_)
        | Origin::Held(_)
        | Origin::Slot(_)
        | Origin::Absorbed(_)
        | Origin::Proved => None,
    });
    match (blocks.next(), blocks.next(), blocks.next()) {
        (Some(entry), Some(latch), None) if entry != latch => Some((entry, latch)),
        _ => None,
    }
}

/// The block among `origins`, if one.
fn block_among(origins: &[Origin]) -> Result<Option<BlockId>, String> {
    let mut blocks = origins.iter().filter_map(|origin| match *origin {
        Origin::Block(block) => Some(block),
        Origin::Value(_)
        | Origin::Instruction(_)
        | Origin::Register(_)
        | Origin::Held(_)
        | Origin::Slot(_)
        | Origin::Absorbed(_)
        | Origin::Proved => None,
    });
    let first = blocks.next();
    match (first, blocks.next()) {
        (Some(a), Some(b)) if a != b => Err(format!("stands for blocks {} and {}", a.0, b.0)),
        (first, _) => Ok(first),
    }
}

/// The blocks among `origins`, in order.
fn blocks_among(origins: &[Origin]) -> Vec<BlockId> {
    origins
        .iter()
        .filter_map(|origin| match *origin {
            Origin::Block(block) => Some(block),
            Origin::Value(_)
            | Origin::Instruction(_)
            | Origin::Register(_)
            | Origin::Held(_)
            | Origin::Slot(_)
            | Origin::Absorbed(_)
            | Origin::Proved => None,
        })
        .collect()
}

impl<'a> Builder<'a> {
    fn stmt(&self, id: StmtId) -> Result<&'a Stmt, String> {
        self.function
            .stmt(id)
            .ok_or_else(|| format!("no statement s{}", id.0))
    }

    fn add(&mut self, kind: Kind) -> NodeId {
        let id = NodeId(number(self.nodes.len()));
        self.nodes.push(Node {
            kind,
            successors: Vec::new(),
        });
        id
    }

    fn set(&mut self, id: NodeId, successors: Vec<NodeId>) {
        if let Some(node) = self.nodes.get_mut(id.0 as usize) {
            node.successors = successors;
        }
    }

    /// The block statement `id` stands for, if one.
    fn block_of(&self, id: StmtId) -> Result<Option<BlockId>, String> {
        block_among(self.function.provenance.stmt(id)).map_err(|e| format!("s{}: {e}", id.0))
    }

    /// The block deciding statement `id`.
    fn decider(&self, id: StmtId) -> Result<BlockId, String> {
        self.block_of(id)?
            .ok_or_else(|| format!("s{}: a decision of no block", id.0))
    }

    /// A join for each label in `block` (and the blocks inside it).
    fn labels(&mut self, block: &Block, depth: usize) -> Result<(), String> {
        if depth > DEPTH {
            return Err("statements nest too deeply".to_string());
        }
        for &id in block {
            let stmt = self.stmt(id)?;
            if let &Stmt::Label(label) = stmt {
                let node = self.add(Kind::Join);
                if self.labels.insert(label, node).is_some() {
                    return Err(format!("label l{} defined twice", label.0));
                }
            }
            for inner in stmt.blocks() {
                self.labels(inner, depth + 1)?;
            }
        }
        Ok(())
    }

    /// The node control reaches entering `block`, after which it goes on
    /// to `next`.
    fn block(&mut self, block: &Block, next: NodeId, depth: usize) -> Result<NodeId, String> {
        if depth > DEPTH {
            return Err("statements nest too deeply".to_string());
        }
        let mut entry = next;
        for &id in block.iter().rev() {
            entry = self.entry(id, entry, depth)?;
        }
        Ok(entry)
    }

    /// Straight-line statement `id` (of `block`, if one), then `next`:
    /// one piece with the code of the same block that follows it.
    fn code(&mut self, id: StmtId, next: NodeId) -> Result<NodeId, String> {
        let Some(block) = self.block_of(id)? else {
            return Ok(next);
        };
        if let Some(node) = self.nodes.get_mut(next.0 as usize)
            && let Kind::Code { stmt, block: other } = &mut node.kind
            && *other == block
        {
            *stmt = id;
            return Ok(next);
        }
        let node = self.add(Kind::Code { stmt: id, block });
        self.set(node, vec![next]);
        Ok(node)
    }

    /// Whether `condition` is the constant 1: the loop it controls decides
    /// nothing.
    fn always(&self, condition: ExprId) -> bool {
        matches!(self.function.expr(condition), Some(Expr::Const(bits)) if *bits == Bits::from_u64(1, 1))
    }

    /// The block of condition `expr` (its own, else `inherited`) if all
    /// of it is one block's decision; `None` if it splits.
    fn uniform(
        &self,
        expr: ExprId,
        inherited: BlockId,
        depth: usize,
    ) -> Result<Option<BlockId>, String> {
        if depth > DEPTH {
            return Err("a condition nests too deeply".to_string());
        }
        let own = block_among(self.function.provenance.expr(expr))
            .map_err(|e| format!("e{}: {e}", expr.0))?
            .unwrap_or(inherited);
        Ok(match self.function.expr(expr) {
            Some(&Expr::Unary(Unary::Not, inner)) => self.uniform(inner, own, depth + 1)?,
            Some(&Expr::Logical(_, left, right)) => {
                let left = self.uniform(left, own, depth + 1)?;
                let right = self.uniform(right, own, depth + 1)?;
                left.filter(|_| left == right)
            }
            Some(_) | None => Some(own),
        })
    }

    /// Where control goes to evaluate condition `expr` of statement
    /// `stmt` (of block `inherited` unless it says otherwise), on to
    /// `then` if it holds, else `otherwise`: one decision per block.
    fn condition(
        &mut self,
        stmt: StmtId,
        expr: ExprId,
        inherited: BlockId,
        [then, otherwise]: [NodeId; 2],
        depth: usize,
    ) -> Result<NodeId, String> {
        if let Some(block) = self.uniform(expr, inherited, depth)? {
            let node = self.add(Kind::Decision { stmt, block });
            self.set(node, vec![then, otherwise]);
            return Ok(node);
        }
        let own = block_among(self.function.provenance.expr(expr))?.unwrap_or(inherited);
        match self.function.expr(expr) {
            Some(&Expr::Unary(Unary::Not, inner)) => {
                self.condition(stmt, inner, own, [otherwise, then], depth + 1)
            }
            Some(&Expr::Logical(op, left, right)) => {
                let right = self.condition(stmt, right, own, [then, otherwise], depth + 1)?;
                let arms = match op {
                    Logical::And => [right, otherwise],
                    Logical::Or => [then, right],
                };
                self.condition(stmt, left, own, arms, depth + 1)
            }
            Some(_) | None => Err(format!("e{}: a condition that does not split", expr.0)),
        }
    }

    /// A loop whose condition is the constant 1: a [`Kind::Join`] at its
    /// top, where `continue` (through `step`) and the end of the body go;
    /// entered through `init`.
    fn endless(
        &mut self,
        id: StmtId,
        [init, body, step]: [&Block; 3],
        next: NodeId,
        depth: usize,
    ) -> Result<NodeId, String> {
        let top = self.add(Kind::Join);
        self.breaks.insert(id, next);
        let step = self.block(step, top, depth)?;
        self.continues.insert(id, step);
        let body = self.block(body, step, depth)?;
        self.set(top, vec![body]);
        self.block(init, top, depth)
    }

    /// A loop deciding by `condition` (at its top, a join): `while` and
    /// `for` (`init` first, `step` where `continue` goes) enter at their
    /// condition, `do`-`while` at its body. A `while` or `for` whose
    /// statement names two blocks ([`entry_and_latch`]) decides at entry
    /// as the first (the guard of the `if (c) do … while (c)` it was) and
    /// at each iteration as the second; one whose statement is
    /// [`Origin::Proved`] decides nothing at entry (its condition is proved
    /// to hold there) and enters its body.
    fn decided(
        &mut self,
        id: StmtId,
        condition: ExprId,
        [init, body, step]: [&Block; 3],
        first: bool,
        next: NodeId,
        depth: usize,
    ) -> Result<NodeId, String> {
        let origins = self.function.provenance.stmt(id);
        let proved = origins.contains(&Origin::Proved);
        let (entry, block) = match entry_and_latch(origins) {
            Some(pair) if first && !proved => pair,
            Some(_) => {
                return Err(format!(
                    "s{}: a do-while or proved loop of two blocks",
                    id.0
                ));
            }
            None if proved && !first => {
                return Err(format!("s{}: a do-while proved at entry", id.0));
            }
            None => {
                let block = self.decider(id)?;
                (block, block)
            }
        };
        let top = self.add(Kind::Join);
        self.breaks.insert(id, next);
        let step = self.block(step, top, depth)?;
        self.continues.insert(id, step);
        let body = self.block(body, step, depth)?;
        let decision = self.condition(id, condition, block, [body, next], depth)?;
        self.set(top, vec![decision]);
        if first {
            let start = if proved {
                body
            } else if entry == block {
                top
            } else {
                self.condition(id, condition, entry, [body, next], depth)?
            };
            self.block(init, start, depth)
        } else {
            Ok(body)
        }
    }

    /// Where control goes entering statement `id`, followed by `next`.
    fn entry(&mut self, id: StmtId, next: NodeId, depth: usize) -> Result<NodeId, String> {
        let stmt = self.stmt(id)?;
        let depth = depth + 1;
        let empty = Block::new();
        if !self.unwinds.is_empty() && itanium::unwinds(self.function, stmt, self.exceptions) {
            return self.invoke(id, stmt, next);
        }
        Ok(match stmt {
            Stmt::Assign { .. } | Stmt::Call { .. } | Stmt::Intrinsic { .. } | Stmt::Expr(_) => {
                let next = if self.resumes(stmt) { EXIT } else { next };
                self.code(id, next)?
            }
            Stmt::Escape { kind, .. } => match kind {
                Escape::NonStandardCall
                | Escape::StackTrick
                | Escape::SystemCall
                | Escape::Atomic
                | Escape::Update(_) => self.code(id, next)?,
                Escape::UnresolvedJump | Escape::ForeignJump | Escape::OverlappingCode => {
                    self.code(id, EXIT)?
                }
            },
            Stmt::Return(_) | Stmt::Trap(_) | Stmt::Unreachable => self.code(id, EXIT)?,
            Stmt::VaStart { .. } => {
                self.absorb(id);
                self.code(id, next)?
            }
            Stmt::Label(label) => {
                let node = self.label(*label)?;
                self.set(node, vec![next]);
                node
            }
            Stmt::Goto(label) => self.label(*label)?,
            Stmt::Break(target) => *self
                .breaks
                .get(target)
                .ok_or_else(|| format!("s{}: break of no enclosing s{}", id.0, target.0))?,
            Stmt::Continue(target) => *self
                .continues
                .get(target)
                .ok_or_else(|| format!("s{}: continue of no enclosing s{}", id.0, target.0))?,
            Stmt::If {
                condition,
                then,
                otherwise,
            } => {
                let block = self.decider(id)?;
                let then = self.block(then, next, depth)?;
                let otherwise = self.block(otherwise, next, depth)?;
                self.condition(id, *condition, block, [then, otherwise], depth)?
            }
            Stmt::While { condition, body } | Stmt::DoWhile { body, condition }
                if self.always(*condition) =>
            {
                self.endless(id, [&empty, body, &empty], next, depth)?
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } if self.always(*condition) => self.endless(id, [init, body, step], next, depth)?,
            Stmt::While { condition, body } => {
                self.decided(id, *condition, [&empty, body, &empty], true, next, depth)?
            }
            Stmt::DoWhile { body, condition } => {
                self.decided(id, *condition, [&empty, body, &empty], false, next, depth)?
            }
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => self.decided(id, *condition, [init, body, step], true, next, depth)?,
            Stmt::Switch { arms, .. } => {
                self.breaks.insert(id, next);
                let mut entries = Vec::with_capacity(arms.len() + 1);
                let mut following = next;
                for arm in arms.iter().rev() {
                    let after = if arm.fallthrough { following } else { next };
                    following = self.block(&arm.body, after, depth)?;
                    entries.push(following);
                }
                entries.reverse();
                let blocks = blocks_among(self.function.provenance.stmt(id));
                if blocks.len() > 1 {
                    return self.chain(id, arms, &entries, &blocks, next);
                }
                let block = self.decider(id)?;
                let node = self.add(Kind::Decision { stmt: id, block });
                if !arms.iter().any(|arm| arm.default) {
                    entries.push(next);
                }
                self.set(node, entries);
                node
            }
            Stmt::Try { body, handlers } => self.try_statement(id, body, handlers, next, depth)?,
        })
    }

    /// Whether `stmt` calls a function that resumes unwinding (which does
    /// not return).
    fn resumes(&self, stmt: &Stmt) -> bool {
        matches!(stmt, Stmt::Call { call, .. }
            if matches!(call.callee, Callee::Address(address) if self.exceptions.resume.contains(&address)))
    }

    /// A `switch` (statement `id`, its `arms` entered at `entries`)
    /// standing for a chain of comparisons, one block each (`blocks`: one
    /// per value, in the arms' order): a decision per value, of its block,
    /// going to its arm or to the next value's, the last to the default
    /// arm or `next`.
    fn chain(
        &mut self,
        id: StmtId,
        arms: &[Arm],
        entries: &[NodeId],
        blocks: &[BlockId],
        next: NodeId,
    ) -> Result<NodeId, String> {
        let cases: Vec<NodeId> = arms
            .iter()
            .zip(entries)
            .flat_map(|(arm, &entry)| arm.values.iter().map(move |_| entry))
            .collect();
        if cases.len() != blocks.len() {
            return Err(format!(
                "s{}: a switch of {} values standing for {} blocks",
                id.0,
                cases.len(),
                blocks.len()
            ));
        }
        let mut following = arms
            .iter()
            .zip(entries)
            .find_map(|(arm, &entry)| arm.default.then_some(entry))
            .unwrap_or(next);
        for (&entry, &block) in cases.iter().zip(blocks).rev() {
            let node = self.add(Kind::Decision { stmt: id, block });
            self.set(node, vec![entry, following]);
            following = node;
        }
        Ok(following)
    }

    /// Statement `id`, which may unwind to the innermost `Try`'s dispatch:
    /// a decision of its block, on to `next` (unless it resumes
    /// unwinding) or to the dispatch.
    fn invoke(&mut self, id: StmtId, stmt: &Stmt, next: NodeId) -> Result<NodeId, String> {
        let dispatch = self.unwinds.last().copied().unwrap_or(EXIT);
        let block = self.decider(id)?;
        let node = self.add(Kind::Decision { stmt: id, block });
        let mut successors = Vec::with_capacity(2);
        if !self.resumes(stmt) {
            // A statement holding blocks: its own decision is its code's.
            let after = match stmt {
                Stmt::Assign { .. }
                | Stmt::Call { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_)
                | Stmt::Escape { .. }
                | Stmt::VaStart { .. } => next,
                Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::DoWhile { .. }
                | Stmt::For { .. }
                | Stmt::Switch { .. }
                | Stmt::Try { .. }
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Label(_)
                | Stmt::Goto(_)
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable => {
                    return Err(format!(
                        "s{}: a call that may unwind in a statement of its own kind",
                        id.0
                    ));
                }
            };
            successors.push(after);
        }
        successors.push(dispatch);
        self.set(node, successors);
        Ok(node)
    }

    /// A `Try` (statement `id`): its body, whose exceptions go to its
    /// dispatch (see the module documentation), then `next`.
    fn try_statement(
        &mut self,
        id: StmtId,
        body: &Block,
        handlers: &[binbun_ast::ir::Handler],
        next: NodeId,
        depth: usize,
    ) -> Result<NodeId, String> {
        let outer = self.unwinds.last().copied().unwrap_or(EXIT);
        let mut entries = Vec::with_capacity(handlers.len() + 1);
        for handler in handlers {
            let end = if handler.kind.propagates() {
                outer
            } else {
                next
            };
            entries.push(self.block(&handler.body, end, depth)?);
        }
        let all = handlers.last().is_some_and(|handler| {
            matches!(
                handler.kind,
                HandlerKind::Landing(_)
                    | HandlerKind::CatchAll
                    | HandlerKind::Cleanup
                    | HandlerKind::Finally
            )
        });
        self.absorb(id);
        let dispatch = self.add(Kind::Fork);
        if !all {
            self.optional.insert(dispatch, outer);
        }
        self.set(dispatch, entries);
        self.unwinds.push(dispatch);
        let entry = self.block(body, next, depth);
        self.unwinds.pop();
        entry
    }

    /// Notes the blocks statement `id` absorbed ([`Origin::Absorbed`]).
    fn absorb(&mut self, id: StmtId) {
        for origin in self.function.provenance.stmt(id) {
            match *origin {
                Origin::Absorbed(block) => {
                    self.absorbed.insert(block);
                }
                Origin::Block(_)
                | Origin::Value(_)
                | Origin::Instruction(_)
                | Origin::Register(_)
                | Origin::Held(_)
                | Origin::Slot(_)
                | Origin::Proved => {}
            }
        }
    }

    fn label(&self, label: LabelId) -> Result<NodeId, String> {
        self.labels
            .get(&label)
            .copied()
            .ok_or_else(|| format!("label l{} is not defined", label.0))
    }
}
