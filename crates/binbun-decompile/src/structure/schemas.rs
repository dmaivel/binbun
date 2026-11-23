//! The schemas pass: where each block goes ([`Plan`]), then the body laid
//! out again from it ([`emit`]). See the module documentation of
//! [`super`].

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{self, Block, Expr, ExprId, Function, LabelId, Stmt, StmtId};
use binbun_semantics::bits::Bits;

use super::analysis::{Analysis, NONE, at, list, number, put};
use super::cfg::{Arm, Case, Cfg, Edge, Term, To};
use super::refine::falls;
use super::{Budget, Refusal};

/// Where each block goes.
#[derive(Clone, Debug)]
pub(super) struct Plan {
    /// The edge (source, index in its terminator's edges) each block is
    /// placed at, if one.
    inline: Vec<(u32, u32)>,
    /// The blocks placed after each block's terminator, in order.
    after: Vec<Vec<u32>>,
    /// The loop each block heads ([`NONE`]: none).
    heads: Vec<u32>,
    /// The blocks placed after each loop, in order.
    after_loop: Vec<Vec<u32>>,
    /// Blocks placed in a switch arm that the arm before falls into.
    falls_into: Vec<bool>,
    /// Blocks not reached from the entry, in order.
    dead: Vec<u32>,
    /// How many blocks each block dominates (itself included).
    size: Vec<u32>,
    /// Where control goes from the blocks each block dominates to blocks
    /// it does not ([`outside`]).
    outside: Vec<u32>,
}

impl Plan {
    /// Places every block of `cfg`.
    pub(super) fn new(
        cfg: &Cfg,
        analysis: &Analysis,
        budget: &mut Budget,
    ) -> Result<Self, Refusal> {
        let count = cfg.nodes.len();
        // Each block's forward in-edges.
        let mut forward: Vec<Vec<(u32, u32)>> = vec![Vec::new(); count];
        for &node in analysis.order() {
            let Some(block) = cfg.node(node) else {
                continue;
            };
            for (index, edge) in block.term.edges().into_iter().enumerate() {
                if let To::Node(target) = edge.target
                    && analysis.position(node) < analysis.position(target)
                    && let Some(slot) = forward.get_mut(target as usize)
                {
                    slot.push((node, number(index)));
                }
            }
        }
        let mut plan = Self {
            inline: vec![(NONE, NONE); count],
            after: vec![Vec::new(); count],
            heads: vec![NONE; count],
            after_loop: vec![Vec::new(); analysis.loops.len()],
            falls_into: vec![false; count],
            dead: (0..number(count))
                .filter(|&node| analysis.position(node) == NONE)
                .collect(),
            size: vec![1; count],
            outside: outside(cfg, analysis),
        };
        for &node in analysis.order().iter().rev() {
            let parent = analysis.idom(node);
            let own = at(&plan.size, node);
            if let Some(slot) = plan.size.get_mut(parent as usize) {
                *slot = slot.saturating_add(own);
            }
        }
        for (l, found) in analysis.loops.iter().enumerate() {
            put(&mut plan.heads, found.header, number(l));
        }
        // The blocks that leave each loop (the outermost they leave).
        let mut exits = vec![Vec::new(); analysis.loops.len()];
        for &node in analysis.order().iter().skip(1) {
            let into = forward.get(node as usize).map_or(&[][..], Vec::as_slice);
            // Code only exceptions enter (a landing pad): in the handler
            // of the first `Try` that unwinds to it; the others jump there.
            if let [first, ..] = into
                && into.iter().all(|&edge| handler_edge(cfg, edge))
            {
                if let Some(slot) = plan.inline.get_mut(node as usize) {
                    *slot = *first;
                }
                continue;
            }
            let anchor = if let [edge] = into {
                if let Some(slot) = plan.inline.get_mut(node as usize) {
                    *slot = *edge;
                }
                edge.0
            } else {
                analysis.idom(node)
            };
            match left(analysis, anchor, node, budget)? {
                Some(l) => {
                    if let Some(slot) = exits.get_mut(l as usize) {
                        slot.push(node);
                    }
                }
                None if into.len() > 1 => {
                    if let Some(slot) = plan.after.get_mut(anchor as usize) {
                        slot.push(node);
                    }
                }
                None => {}
            }
        }
        plan.exits(analysis, &forward, &exits);
        plan.fall_through(cfg, analysis, &forward);
        Ok(plan)
    }

    /// Places the blocks that leave each loop. Its main exit: one whose
    /// code comes back to the rest of the function if any, then one on
    /// the header's or a latch's edge, then the one dominating the most
    /// blocks. A join goes after the loop, unless it is not the main exit,
    /// its code never comes back and its dominator is inside the loop (a
    /// local exit path): then after that dominator. A single exit stays at
    /// its edge, unless it is the main exit and no join follows the loop.
    fn exits(&mut self, analysis: &Analysis, forward: &[Vec<(u32, u32)>], exits: &[Vec<u32>]) {
        let outside = core::mem::take(&mut self.outside);
        let size = core::mem::take(&mut self.size);
        for (l, found) in analysis.loops.iter().enumerate() {
            let leaving = list(exits, number(l));
            // Whether a block's code goes on to the rest of the function
            // (not only out of it, or to another block leaving the loop).
            let escaping = |node: u32| {
                let only = at(&outside, node);
                only != NONE
                    && leaving
                        .binary_search_by_key(&analysis.position(only), |&other| {
                            analysis.position(other)
                        })
                        .is_err()
            };
            let main = leaving.iter().copied().max_by_key(|&node| {
                let tested = list_of(forward, node)
                    .iter()
                    .any(|edge| edge.0 == found.header || found.latches.contains(&edge.0));
                (
                    escaping(node),
                    tested,
                    at(&size, node),
                    analysis.position(node),
                )
            });
            let mut after = Vec::new();
            // Latest first: a join may lead to a later local one.
            let mut local = BTreeSet::new();
            for &node in leaving.iter().rev() {
                if list_of(forward, node).len() < 2 {
                    continue;
                }
                let anchor = analysis.idom(node);
                let only = at(&outside, node);
                let stays = (only == NONE && anchor != found.header)
                    || main == Some(only)
                    || local.contains(&only);
                if Some(node) != main && stays {
                    local.insert(node);
                    if let Some(slot) = self.after.get_mut(anchor as usize) {
                        slot.push(node);
                    }
                } else {
                    after.push(node);
                }
            }
            after.reverse();
            if after.is_empty()
                && let Some(main) = main
            {
                after.push(main);
                if let Some(slot) = self.inline.get_mut(main as usize) {
                    *slot = (NONE, NONE);
                }
            }
            if let Some(slot) = self.after_loop.get_mut(l) {
                *slot = after;
            }
        }
        for after in &mut self.after {
            after.sort_unstable_by_key(|&node| analysis.position(node));
        }
        self.outside = outside;
        self.size = size;
    }

    /// Places in its switch arm a join of the switch that the previous
    /// arm's block (placed in its arm) also reaches, and only it, unless
    /// it is the switch's immediate post-dominator or the target of a last
    /// default arm (then it is the code after the switch).
    fn fall_through(&mut self, cfg: &Cfg, analysis: &Analysis, forward: &[Vec<(u32, u32)>]) {
        for (switch, block) in cfg.nodes.iter().enumerate() {
            let switch = number(switch);
            let Term::Switch { cases, .. } = &block.term else {
                continue;
            };
            let follow = analysis.ipdom(switch);
            let mut previous: Option<u32> = None;
            let mut index = 0;
            for (position, case) in cases.iter().enumerate() {
                let Arm::Edge(edge) = &case.arm else {
                    previous = None;
                    continue;
                };
                let target = match edge.target {
                    To::Node(target) => target,
                    To::End | To::Next => NONE,
                };
                let into = list_of(forward, target);
                let last_default = case.default && position + 1 == cases.len();
                let placed = previous.is_some_and(|before| {
                    follow != Some(target)
                        && !last_default
                        && into.iter().filter(|edge| edge.0 == switch).count() == 1
                        && list(&self.after, switch).contains(&target)
                        && into
                            .iter()
                            .all(|edge| edge.0 == switch || analysis.dominates(before, edge.0))
                });
                if placed {
                    if let Some(after) = self.after.get_mut(switch as usize) {
                        after.retain(|&node| node != target);
                    }
                    if let Some(slot) = self.inline.get_mut(target as usize) {
                        *slot = (switch, index);
                    }
                    if let Some(slot) = self.falls_into.get_mut(target as usize) {
                        *slot = true;
                    }
                }
                let inline = self.inline.get(target as usize) == Some(&(switch, index));
                previous = inline.then_some(target);
                index += 1;
            }
        }
    }
}

fn list_of<T>(lists: &[Vec<T>], index: u32) -> &[T] {
    lists.get(index as usize).map_or(&[], Vec::as_slice)
}

/// Whether edge `(source, index)` is a `Try`'s handler edge.
fn handler_edge(cfg: &Cfg, (source, index): (u32, u32)) -> bool {
    let Some(Term::Try { handlers, .. }) = cfg.node(source).map(|block| &block.term) else {
        return false;
    };
    let edges = handlers
        .iter()
        .filter(|arm| matches!(arm, Arm::Edge(_)))
        .count();
    (index as usize) < edges
}

/// Several blocks ([`outside`]).
const MANY: u32 = NONE - 1;

/// Where control goes from the blocks each block dominates to a block it
/// does not dominate: [`NONE`] (they only leave the function), the one
/// block, or [`MANY`]. Gathered bottom-up over the dominator tree.
fn outside(cfg: &Cfg, analysis: &Analysis) -> Vec<u32> {
    let count = cfg.nodes.len();
    let inside = |node: u32, target: u32| {
        let (enter, exit) = analysis.interval(node);
        let (at, _) = analysis.interval(target);
        enter <= at && at <= exit
    };
    // Up to two targets each (`[MANY, _]`: more).
    let add = |set: &mut [u32; 2], target: u32| {
        *set = match *set {
            [NONE, _] => [target, NONE],
            [first, _] if first == target || first == MANY => *set,
            [first, NONE] => [first, target],
            [_, second] if second == target => *set,
            [_, _] => [MANY, MANY],
        };
    };
    let mut out = vec![[NONE; 2]; count];
    for &node in analysis.order() {
        let Some(set) = out.get_mut(node as usize) else {
            continue;
        };
        for edge in cfg
            .node(node)
            .map_or_else(Vec::new, |block| block.term.edges())
        {
            if let To::Node(target) = edge.target
                && !inside(node, target)
            {
                add(set, target);
            }
        }
    }
    for &node in analysis.order().iter().rev() {
        let parent = analysis.idom(node);
        let own = out.get(node as usize).copied().unwrap_or([NONE; 2]);
        let Some(set) = out.get_mut(parent as usize) else {
            continue;
        };
        for target in own {
            if target == MANY || (target != NONE && !inside(parent, target)) {
                add(set, target);
            }
        }
    }
    out.into_iter()
        .map(|set| match set {
            [only, NONE] => only,
            [_, _] => MANY,
        })
        .collect()
}

/// The outermost loop around `anchor` that `node` is outside of (the
/// loops `node`'s code leaves), if any.
fn left(
    analysis: &Analysis,
    anchor: u32,
    node: u32,
    budget: &mut Budget,
) -> Result<Option<u32>, Refusal> {
    let mut l = at(&analysis.loop_of, anchor);
    let mut outermost = None;
    while let Some(found) = analysis.loop_at(l) {
        budget.charge(1)?;
        if analysis.in_loop(node, l) {
            break;
        }
        outermost = Some(l);
        l = found.parent.unwrap_or(NONE);
    }
    Ok(outermost)
}

/// Where control goes off the end of a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    /// A block's start.
    Node(u32),
    /// The top of the loop the block heads (the body's end).
    Top(u32),
    /// Nowhere: the code must not fall off.
    Nowhere,
}

/// How an arm ends up: code placed at its edge (whose blocks only leave
/// the function, or not; how many blocks), never falling through (a jump,
/// or statements that stop), or falling through (to the code after the
/// `if`, only its copies).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Code { stops: bool, size: u32 },
    Leaves,
    Falls,
}

impl Shape {
    /// Whether control never goes on after the arm.
    fn ends(self) -> bool {
        match self {
            Self::Code { stops, .. } => stops,
            Self::Leaves => true,
            Self::Falls => false,
        }
    }
}

/// Which arm of an `if` of these shapes follows it instead of nesting:
/// code, when the other arm never goes on (the larger if both are code).
fn hoisted(shapes: [Shape; 2]) -> Option<usize> {
    match shapes {
        [Shape::Code { size: a, .. }, Shape::Code { size: b, .. }]
            if shapes[0].ends() && shapes[1].ends() =>
        {
            Some(usize::from(b > a))
        }
        [Shape::Code { .. }, other] if other.ends() => Some(0),
        [other, Shape::Code { .. }] if other.ends() => Some(1),
        [
            Shape::Code { .. } | Shape::Leaves | Shape::Falls,
            Shape::Code { .. } | Shape::Leaves | Shape::Falls,
        ] => None,
    }
}

/// A loop or switch around the code being laid out.
#[derive(Clone, Copy, Debug)]
struct Frame {
    stmt: StmtId,
    /// The loop's header ([`NONE`]: a switch).
    header: u32,
    /// Where control goes after it.
    exit: Target,
    /// Whether a `break` names it.
    broken: bool,
}

/// A block to lay out: its loop (unless `plain`), its code, terminator
/// and what is placed after it.
#[derive(Clone, Copy, Debug)]
struct Item {
    node: u32,
    falloff: Target,
    plain: bool,
}

struct Emitter<'a> {
    function: &'a mut Function,
    cfg: &'a Cfg,
    plan: &'a Plan,
    limit: usize,
    frames: Vec<Frame>,
    /// Blocks placed at the end of the body for depth.
    deferred: Vec<u32>,
    /// Loops a `break` names.
    broken: BTreeSet<StmtId>,
    always: Option<ExprId>,
}

/// Lays `function`'s body out again by `plan`; returns how many blocks
/// were placed at the end for depth.
pub(super) fn emit(function: &mut Function, cfg: &Cfg, plan: &Plan, limit: usize) -> usize {
    let mut emitter = Emitter {
        function,
        cfg,
        plan,
        limit,
        frames: Vec::new(),
        deferred: Vec::new(),
        broken: BTreeSet::new(),
        always: None,
    };
    let start = Item {
        node: 0,
        falloff: Target::Nowhere,
        plain: false,
    };
    let mut body = emitter.sequence(start, 0);
    let mut next = 0;
    while let Some(&node) = emitter.deferred.get(next) {
        next += 1;
        let item = Item {
            node,
            falloff: Target::Nowhere,
            plain: false,
        };
        body.extend(emitter.sequence(item, 0));
    }
    for &node in &plan.dead {
        let item = Item {
            node,
            falloff: Target::Nowhere,
            plain: true,
        };
        body.extend(emitter.sequence(item, 0));
    }
    emitter.function.body = body;
    emitter.deferred.len()
}

/// Pushes `nodes` (to lay out in order, each falling into the next, the
/// last into `last`) on the work stack.
fn chain(work: &mut Vec<Item>, nodes: &[u32], last: Target) {
    for (index, &node) in nodes.iter().enumerate().rev() {
        work.push(Item {
            node,
            falloff: nodes
                .get(index + 1)
                .map_or(last, |&next| Target::Node(next)),
            plain: false,
        });
    }
}

impl Emitter<'_> {
    fn set(&mut self, id: StmtId, stmt: Stmt) {
        if let Some(slot) = self.function.stmts.get_mut(id.0 as usize) {
            *slot = stmt;
        }
    }

    /// `stmt` in the edge's own jump if it has one, else a new statement.
    fn jump(&mut self, jump: Option<StmtId>, stmt: Stmt) -> StmtId {
        match jump {
            Some(id) => {
                self.set(id, stmt);
                id
            }
            None => self.function.add_stmt(stmt),
        }
    }

    fn label(&self, node: u32) -> LabelId {
        self.cfg
            .node(node)
            .and_then(|block| block.label)
            .map_or(LabelId(u32::MAX), |(label, _)| label)
    }

    /// A `goto` to `node` (in `jump`), laid out at the end of the body.
    fn defer(&mut self, node: u32, jump: Option<StmtId>, out: &mut Block) {
        let label = self.label(node);
        out.push(self.jump(jump, Stmt::Goto(label)));
        self.deferred.push(node);
    }

    /// The condition 1.
    fn always(&mut self) -> ExprId {
        if let Some(id) = self.always {
            return id;
        }
        let id = self.function.add_expr(Expr::Const(Bits::from_u64(1, 1)));
        self.always = Some(id);
        id
    }

    /// The block `item` starts, at nesting `depth`.
    fn sequence(&mut self, item: Item, depth: usize) -> Block {
        let mut out = Vec::new();
        let mut work = vec![item];
        self.drain(&mut out, &mut work, depth);
        out
    }

    fn drain(&mut self, out: &mut Block, work: &mut Vec<Item>, depth: usize) {
        while let Some(item) = work.pop() {
            self.item(item, out, work, depth);
        }
    }

    fn item(&mut self, item: Item, out: &mut Block, work: &mut Vec<Item>, depth: usize) {
        let plan = self.plan;
        let l = at(&plan.heads, item.node);
        if !item.plain && l != NONE {
            if depth >= self.limit {
                self.defer(item.node, None, out);
                return;
            }
            let after = list(&plan.after_loop, l);
            let exit = after
                .first()
                .map_or(item.falloff, |&next| Target::Node(next));
            chain(work, after, item.falloff);
            let id = self.function.add_stmt(Stmt::Unreachable);
            self.frames.push(Frame {
                stmt: id,
                header: item.node,
                exit,
                broken: false,
            });
            let body = self.sequence(
                Item {
                    node: item.node,
                    falloff: Target::Top(item.node),
                    plain: true,
                },
                depth + 1,
            );
            if self.frames.pop().is_some_and(|frame| frame.broken) {
                self.broken.insert(id);
            }
            let condition = self.always();
            self.set(id, Stmt::While { condition, body });
            out.push(id);
            return;
        }
        let cfg = self.cfg;
        let Some(block) = cfg.node(item.node) else {
            return;
        };
        if let Some((_, stmt)) = block.label {
            out.push(stmt);
        }
        out.extend_from_slice(&block.code);
        let after = list(&plan.after, item.node);
        let falloff = after
            .first()
            .map_or(item.falloff, |&next| Target::Node(next));
        chain(work, after, item.falloff);
        match &block.term {
            Term::Stop => {}
            Term::Jump(edge) => self.edge((item.node, 0), edge, falloff, out, work, depth),
            &Term::Branch {
                stmt,
                condition,
                ref then,
                ref otherwise,
            } => {
                let arms = [then, otherwise];
                self.branch(
                    item.node,
                    (stmt, condition),
                    arms,
                    falloff,
                    out,
                    work,
                    depth,
                );
            }
            &Term::Switch {
                stmt,
                scrutinee,
                ref cases,
                ref none,
            } => {
                let arms = self.cases(item.node, stmt, cases, none.as_ref(), falloff, depth + 1);
                self.set(stmt, Stmt::Switch { scrutinee, arms });
                out.push(stmt);
            }
            &Term::Try {
                stmt,
                ref handlers,
                ref normal,
            } => {
                let index = self.handlers(item.node, stmt, handlers, depth + 1);
                out.push(stmt);
                self.edge((item.node, index), normal, falloff, out, work, depth);
            }
        }
    }

    /// Lays out the handlers of `node`'s `Try` statement `stmt` at nesting
    /// `depth`: the number of its edges they take (the normal edge's
    /// index).
    fn handlers(&mut self, node: u32, stmt: StmtId, arms: &[Arm], depth: usize) -> u32 {
        // A handler never falls off its end (onto the normal edge's code,
        // laid out after the `Try`): its way out is a jump.
        let mut index = 0;
        let bodies: Vec<Block> = arms
            .iter()
            .map(|arm| self.arm(node, &mut index, arm, Target::Nowhere, depth))
            .collect();
        if let Some(Stmt::Try {
            body: guarded,
            mut handlers,
        }) = self.function.stmt(stmt).cloned()
        {
            for (handler, body) in handlers.iter_mut().zip(bodies) {
                handler.body = body;
            }
            self.set(
                stmt,
                Stmt::Try {
                    body: guarded,
                    handlers,
                },
            );
        }
        index
    }

    /// An `if` (statement, condition) of `node` with these arms. If one
    /// arm is code placed at its edge and the other never falls through,
    /// the code follows the `if` instead of nesting in it.
    #[allow(
        clippy::too_many_arguments,
        reason = "the emitter's state for one terminator"
    )]
    fn branch(
        &mut self,
        node: u32,
        (stmt, condition): (StmtId, ExprId),
        arms: [&Arm; 2],
        falloff: Target,
        out: &mut Block,
        work: &mut Vec<Item>,
        depth: usize,
    ) {
        let [then, otherwise] = arms;
        let indices = [0, u32::from(matches!(then, Arm::Edge(_)))];
        let shapes = [
            self.shape((node, indices[0]), then, falloff),
            self.shape((node, indices[1]), otherwise, falloff),
        ];
        let hoisted = hoisted(shapes);
        let mut blocks = [Vec::new(), Vec::new()];
        for (side, ((arm, mut index), block)) in
            arms.into_iter().zip(indices).zip(&mut blocks).enumerate()
        {
            if hoisted != Some(side) {
                *block = self.arm(node, &mut index, arm, falloff, depth + 1);
            }
        }
        let [then, otherwise] = blocks;
        self.set(
            stmt,
            Stmt::If {
                condition,
                then,
                otherwise,
            },
        );
        out.push(stmt);
        if let Some(side) = hoisted
            && let (Some(Arm::Edge(edge)), Some(&index)) = (arms.get(side), indices.get(side))
        {
            self.edge((node, index), edge, falloff, out, work, depth);
        }
    }

    /// How an arm (edge `from`, if an edge) ends up.
    fn shape(&self, from: (u32, u32), arm: &Arm, falloff: Target) -> Shape {
        let Arm::Edge(edge) = arm else {
            return Shape::Leaves;
        };
        match edge.target {
            To::Node(target)
                if falloff == Target::Node(target) || falloff == Target::Top(target) =>
            {
                Shape::Falls
            }
            To::Node(target) if self.plan.inline.get(target as usize) == Some(&from) => {
                Shape::Code {
                    stops: at(&self.plan.outside, target) == NONE,
                    size: at(&self.plan.size, target),
                }
            }
            To::Node(_) | To::End | To::Next => Shape::Leaves,
        }
    }

    /// A switch's arms, at nesting `depth`.
    fn cases(
        &mut self,
        node: u32,
        stmt: StmtId,
        cases: &[Case],
        unmatched: Option<&Edge>,
        falloff: Target,
        depth: usize,
    ) -> Vec<ir::Arm> {
        self.frames.push(Frame {
            stmt,
            header: NONE,
            exit: falloff,
            broken: false,
        });
        let mut index = 0;
        let mut arms = Vec::with_capacity(cases.len() + 1);
        for (position, case) in cases.iter().enumerate() {
            let next = cases.get(position + 1).and_then(|next| match &next.arm {
                Arm::Edge(Edge {
                    target: To::Node(target),
                    ..
                }) if self.plan.falls_into.get(*target as usize) == Some(&true) => Some(*target),
                Arm::Edge(_) | Arm::Stop(_) => None,
            });
            let own = next.map_or(falloff, Target::Node);
            let body = self.arm(node, &mut index, &case.arm, own, depth);
            let fallthrough = next.is_some() && falls(self.function, &body, &self.broken);
            arms.push(ir::Arm {
                values: case.values.clone(),
                default: case.default,
                body,
                fallthrough,
            });
        }
        if let Some(edge) = unmatched {
            let mut body = Vec::new();
            let mut work = Vec::new();
            self.edge((node, index), edge, falloff, &mut body, &mut work, depth);
            self.drain(&mut body, &mut work, depth);
            if !body.is_empty() {
                arms.push(ir::Arm {
                    values: Vec::new(),
                    default: true,
                    body,
                    fallthrough: false,
                });
            }
        }
        self.frames.pop();
        // An empty arm nothing falls into does what no arm does, once no
        // default arm takes what no other arm does: drop an empty default
        // first, then, without a default, empty cases.
        for defaults in [true, false] {
            if !defaults && arms.iter().any(|arm| arm.default) {
                break;
            }
            let mut falls_in = false;
            arms.retain(|arm| {
                let empty = arm.body.is_empty() && !arm.fallthrough && !falls_in;
                falls_in = arm.fallthrough;
                !(empty && arm.default == defaults)
            });
        }
        arms
    }

    /// An arm (edge number `*index` of `node`, if an edge), at nesting
    /// `depth`.
    fn arm(
        &mut self,
        node: u32,
        index: &mut u32,
        arm: &Arm,
        falloff: Target,
        depth: usize,
    ) -> Block {
        match arm {
            Arm::Stop(block) => block.clone(),
            Arm::Edge(edge) => {
                let mut out = Vec::new();
                let mut work = Vec::new();
                self.edge((node, *index), edge, falloff, &mut out, &mut work, depth);
                *index += 1;
                self.drain(&mut out, &mut work, depth);
                out
            }
        }
    }

    /// Edge `from` (source, index): its copies, then where it goes.
    fn edge(
        &mut self,
        from: (u32, u32),
        edge: &Edge,
        falloff: Target,
        out: &mut Block,
        work: &mut Vec<Item>,
        depth: usize,
    ) {
        out.extend_from_slice(&edge.copies);
        let target = match edge.target {
            To::Node(target) => target,
            To::End | To::Next => {
                out.push(self.jump(edge.jump, Stmt::Return(None)));
                return;
            }
        };
        if falloff == Target::Node(target) || falloff == Target::Top(target) {
            return;
        }
        if self.plan.inline.get(target as usize) == Some(&from) {
            if depth > self.limit {
                self.defer(target, edge.jump, out);
            } else {
                work.push(Item {
                    node: target,
                    falloff,
                    plain: false,
                });
            }
            return;
        }
        let stmt = self
            .exit_to(target)
            .unwrap_or(Stmt::Goto(self.label(target)));
        out.push(self.jump(edge.jump, stmt));
    }

    /// The `break` or `continue` of an enclosing statement that goes to
    /// `target`, the innermost first.
    fn exit_to(&mut self, target: u32) -> Option<Stmt> {
        for frame in self.frames.iter_mut().rev() {
            if frame.exit == Target::Node(target) || frame.exit == Target::Top(target) {
                frame.broken = true;
                return Some(Stmt::Break(frame.stmt));
            }
            if frame.header == target {
                return Some(Stmt::Continue(frame.stmt));
            }
        }
        None
    }
}
