//! A structured function's control flow, statement by statement: what
//! dataflow over L2 (liveness, values) runs on.
//!
//! A statement that may unwind ([`Stmt::may_unwind`]) in a `Try`'s body
//! is preceded by a split ([`Point::Label`]) going to it and to the
//! `Try`'s handlers: an exception leaves before the statement writes
//! anything. A handler's end goes on after the `Try`, or (one that
//! propagates) where an exception at the `Try` goes: the handlers of the
//! `Try` around it, else the exit; so does an exception no handler takes.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Block, Expr, ExprId, Function, Handler, HandlerKind, LabelId, Stmt, StmtId};
use binbun_semantics::bits::Bits;

/// What a node of a [`Flow`] stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Point {
    /// The function's entry, where its parameters (and locals, undefined)
    /// get their values.
    Entry,
    /// Leaving the function.
    Exit,
    /// A statement that holds no blocks: what it evaluates and writes.
    Simple(StmtId),
    /// The condition or scrutinee of a statement that holds blocks.
    Test(StmtId),
    /// A label, where a `goto` may come in; or where a statement may
    /// unwind to the handlers of the `Try` around it. No effect.
    Label,
}

/// The control flow of a function's body: [`Flow::ENTRY`], [`Flow::EXIT`],
/// then a node per statement that evaluates something or is a label, with
/// its successors (`break`, `continue` and `goto` are edges, not nodes).
#[derive(Debug)]
pub(crate) struct Flow {
    pub(crate) points: Vec<Point>,
    pub(crate) successors: Vec<Vec<u32>>,
    /// How many loops each node is in.
    pub(crate) depth: Vec<u32>,
    /// Where control goes on entering each statement of a block, by
    /// statement (`u32::MAX`: in no block).
    pub(crate) entries: Vec<u32>,
}

impl Flow {
    pub(crate) const ENTRY: u32 = 0;
    pub(crate) const EXIT: u32 = 1;

    /// The flow of `function`'s body.
    pub(crate) fn new(function: &Function) -> Self {
        let mut builder = Builder {
            function,
            flow: Self {
                points: vec![Point::Entry, Point::Exit],
                successors: vec![Vec::new(), Vec::new()],
                depth: vec![0, 0],
                entries: vec![u32::MAX; function.stmts.len()],
            },
            labels: BTreeMap::new(),
            breaks: BTreeMap::new(),
            continues: BTreeMap::new(),
            loops: 0,
            unwinds: vec![vec![Self::EXIT]],
        };
        let first = builder.block(&function.body, Self::EXIT);
        if let Some(entry) = builder.flow.successors.first_mut() {
            entry.push(first);
        }
        builder.flow
    }

    /// The predecessors of each node.
    pub(crate) fn predecessors(&self) -> Vec<Vec<u32>> {
        let mut predecessors = vec![Vec::new(); self.points.len()];
        for (from, successors) in (0u32..).zip(&self.successors) {
            for &to in successors {
                if let Some(list) = predecessors.get_mut(to as usize) {
                    list.push(from);
                }
            }
        }
        predecessors
    }
}

struct Builder<'a> {
    function: &'a Function,
    flow: Flow,
    labels: BTreeMap<LabelId, u32>,
    /// Where a `break` of each loop or switch goes.
    breaks: BTreeMap<StmtId, u32>,
    /// Where a `continue` of each loop goes.
    continues: BTreeMap<StmtId, u32>,
    loops: u32,
    /// Where an exception goes from the statements being built, innermost
    /// `Try` last (the first: out of the function).
    unwinds: Vec<Vec<u32>>,
}

impl Builder<'_> {
    fn add(&mut self, point: Point) -> u32 {
        self.flow.points.push(point);
        self.flow.successors.push(Vec::new());
        self.flow.depth.push(self.loops);
        u32::try_from(self.flow.points.len() - 1).unwrap_or(u32::MAX)
    }

    fn link(&mut self, from: u32, to: &[u32]) {
        if let Some(successors) = self.flow.successors.get_mut(from as usize) {
            successors.extend_from_slice(to);
        }
    }

    fn label(&mut self, label: LabelId) -> u32 {
        if let Some(&node) = self.labels.get(&label) {
            return node;
        }
        let node = self.add(Point::Label);
        self.labels.insert(label, node);
        node
    }

    /// `block`'s entry, control going on to `next` after it.
    fn block(&mut self, block: &Block, next: u32) -> u32 {
        let mut entry = next;
        for &id in block.iter().rev() {
            entry = self.stmt(id, entry);
            if let Some(slot) = self.flow.entries.get_mut(id.0 as usize) {
                *slot = entry;
            }
        }
        entry
    }

    /// `node`, preceded by a split to the handlers an exception goes to
    /// if `stmt` may unwind (`node` itself otherwise, or outside every
    /// `Try`, where the exception leaves the function).
    fn unwinding(&mut self, stmt: &Stmt, node: u32) -> u32 {
        let Some(handlers) = self.unwinds.last() else {
            return node;
        };
        if handlers.as_slice() == [Flow::EXIT] || !stmt.may_unwind(self.function) {
            return node;
        }
        let mut successors = vec![node];
        successors.extend_from_slice(handlers);
        let split = self.add(Point::Label);
        self.link(split, &successors);
        split
    }

    /// Statement `id`'s entry, control going on to `next` after it.
    fn stmt(&mut self, id: StmtId, next: u32) -> u32 {
        let function = self.function;
        let Some(stmt) = function.stmt(id) else {
            return next;
        };
        match stmt {
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::Escape { .. }
            | Stmt::VaStart { .. } => {
                let node = self.add(Point::Simple(id));
                self.link(node, &[next]);
                self.unwinding(stmt, node)
            }
            Stmt::Return(_) | Stmt::Trap(_) | Stmt::Unreachable => {
                let node = self.add(Point::Simple(id));
                self.link(node, &[Flow::EXIT]);
                self.unwinding(stmt, node)
            }
            &Stmt::Label(label) => {
                let node = self.label(label);
                self.link(node, &[next]);
                node
            }
            &Stmt::Goto(label) => self.label(label),
            Stmt::Break(target) => self.breaks.get(target).copied().unwrap_or(Flow::EXIT),
            Stmt::Continue(target) => self.continues.get(target).copied().unwrap_or(Flow::EXIT),
            Stmt::If {
                then, otherwise, ..
            } => {
                let test = self.add(Point::Test(id));
                let then = self.block(then, next);
                let otherwise = self.block(otherwise, next);
                self.link(test, &[then, otherwise]);
                self.unwinding(stmt, test)
            }
            &Stmt::While {
                condition,
                ref body,
            } => {
                self.loops += 1;
                let test = self.add(Point::Test(id));
                let top = self.unwinding(stmt, test);
                self.breaks.insert(id, next);
                self.continues.insert(id, top);
                let body = self.block(body, top);
                self.leave(test, body, condition, next);
                self.loops -= 1;
                top
            }
            &Stmt::DoWhile {
                ref body,
                condition,
            } => {
                self.loops += 1;
                let test = self.add(Point::Test(id));
                let top = self.unwinding(stmt, test);
                self.breaks.insert(id, next);
                self.continues.insert(id, top);
                let body = self.block(body, top);
                self.leave(test, body, condition, next);
                self.loops -= 1;
                body
            }
            &Stmt::For {
                ref init,
                condition,
                ref step,
                ref body,
            } => {
                self.loops += 1;
                let test = self.add(Point::Test(id));
                let top = self.unwinding(stmt, test);
                let step = self.block(step, top);
                self.breaks.insert(id, next);
                self.continues.insert(id, step);
                let body = self.block(body, step);
                self.leave(test, body, condition, next);
                self.loops -= 1;
                self.block(init, top)
            }
            Stmt::Switch { arms, .. } => {
                let test = self.add(Point::Test(id));
                self.breaks.insert(id, next);
                let mut entries = Vec::with_capacity(arms.len() + 1);
                let mut following = next;
                for arm in arms.iter().rev() {
                    let after = if arm.fallthrough { following } else { next };
                    following = self.block(&arm.body, after);
                    entries.push(following);
                }
                if !arms.iter().any(|arm| arm.default) {
                    entries.push(next);
                }
                self.link(test, &entries);
                self.unwinding(stmt, test)
            }
            Stmt::Try { body, handlers } => self.try_entry(body, handlers, next),
        }
    }

    /// A `Try`'s entry, control going on to `next` after it: its body,
    /// which unwinds to its handlers' entries (and on out when a handler
    /// propagates, or no handler takes every exception).
    fn try_entry(&mut self, body: &Block, handlers: &[Handler], next: u32) -> u32 {
        let outer = self.unwinds.last().cloned().unwrap_or_default();
        let mut entries = Vec::with_capacity(handlers.len() + outer.len());
        for handler in handlers {
            let after = if handler.kind.propagates() {
                let split = self.add(Point::Label);
                self.link(split, &outer);
                split
            } else {
                next
            };
            entries.push(self.block(&handler.body, after));
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
        if !all {
            entries.extend_from_slice(&outer);
        }
        self.unwinds.push(entries);
        let entry = self.block(body, next);
        self.unwinds.pop();
        entry
    }

    /// A loop's `test` goes on to its `body`, and to `next` unless its
    /// `condition` is the constant 1.
    fn leave(&mut self, test: u32, body: u32, condition: ExprId, next: u32) {
        let forever = matches!(
            self.function.expr(condition),
            Some(Expr::Const(bits)) if *bits == Bits::from_u64(1, 1)
        );
        if forever {
            self.link(test, &[body]);
        } else {
            self.link(test, &[body, next]);
        }
    }
}
