//! A goto-only function's body as a graph of blocks: one per label, and
//! the body's start (node 0), each ending in one terminator whose edges
//! carry the statements on them (an arm's copies before its `goto`).
//!
//! A call that may unwind is a `Try` around it (lowering's form: its
//! handlers' edges, then the normal edge's copies and `goto`): a
//! terminator whose edges are the handlers' first.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Block, Escape, ExprId, Function, LabelId, Stmt, StmtId};
use binbun_semantics::bits::Bits;

use super::Refusal;
use super::analysis::{NONE, number};

/// Where an edge goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum To {
    /// A node.
    Node(u32),
    /// Off the end of the body.
    End,
    /// The statement after the terminator (resolved when the block ends).
    Next,
}

/// An edge: its statements, then its jump.
#[derive(Clone, Debug)]
pub(super) struct Edge {
    /// Statements run on the edge (an arm's copies).
    pub(super) copies: Vec<StmtId>,
    /// The `goto`, if the edge has one (reused for the jump it becomes).
    pub(super) jump: Option<StmtId>,
    /// Where it goes.
    pub(super) target: To,
}

/// An arm of a decision: an edge, or statements that leave the function.
#[derive(Clone, Debug)]
pub(super) enum Arm {
    /// An edge.
    Edge(Edge),
    /// Statements ending in one that does not go on (kept as they are).
    Stop(Block),
}

/// A switch arm.
#[derive(Clone, Debug)]
pub(super) struct Case {
    pub(super) values: Vec<Bits>,
    pub(super) default: bool,
    pub(super) arm: Arm,
}

/// How a block ends.
#[derive(Clone, Debug)]
pub(super) enum Term {
    /// Its last statement leaves the function.
    Stop,
    /// One edge.
    Jump(Edge),
    /// An `if`.
    Branch {
        stmt: StmtId,
        condition: ExprId,
        then: Arm,
        otherwise: Arm,
    },
    /// A `switch`; `none`: where no arm matches, without a default.
    Switch {
        stmt: StmtId,
        scrutinee: ExprId,
        cases: Vec<Case>,
        none: Option<Edge>,
    },
    /// A `Try` (its body straight-line code): its handlers' arms, which an
    /// exception takes, and the edge control takes when the body ends.
    Try {
        stmt: StmtId,
        handlers: Vec<Arm>,
        normal: Edge,
    },
}

impl Term {
    /// The edges, in order (an edge's index in it names it).
    pub(super) fn edges(&self) -> Vec<&Edge> {
        fn arm(arm: &Arm) -> Option<&Edge> {
            match arm {
                Arm::Edge(edge) => Some(edge),
                Arm::Stop(_) => None,
            }
        }
        match self {
            Self::Stop => Vec::new(),
            Self::Jump(edge) => vec![edge],
            Self::Branch {
                then, otherwise, ..
            } => [then, otherwise].into_iter().filter_map(arm).collect(),
            Self::Switch { cases, none, .. } => cases
                .iter()
                .filter_map(|case| arm(&case.arm))
                .chain(none)
                .collect(),
            Self::Try {
                handlers, normal, ..
            } => handlers.iter().filter_map(arm).chain([normal]).collect(),
        }
    }

    /// Whether an arm leaves the function.
    fn stops(&self) -> bool {
        let arm = |arm: &Arm| matches!(arm, Arm::Stop(_));
        match self {
            Self::Stop => true,
            Self::Jump(_) => false,
            Self::Branch {
                then, otherwise, ..
            } => arm(then) || arm(otherwise),
            Self::Switch { cases, .. } => cases.iter().any(|case| arm(&case.arm)),
            Self::Try { handlers, .. } => handlers.iter().any(arm),
        }
    }

    fn edges_mut(&mut self) -> Vec<&mut Edge> {
        fn arm(arm: &mut Arm) -> Option<&mut Edge> {
            match arm {
                Arm::Edge(edge) => Some(edge),
                Arm::Stop(_) => None,
            }
        }
        match self {
            Self::Stop => Vec::new(),
            Self::Jump(edge) => vec![edge],
            Self::Branch {
                then, otherwise, ..
            } => [then, otherwise].into_iter().filter_map(arm).collect(),
            Self::Switch { cases, none, .. } => cases
                .iter_mut()
                .filter_map(|case| arm(&mut case.arm))
                .chain(none.as_mut())
                .collect(),
            Self::Try {
                handlers, normal, ..
            } => handlers
                .iter_mut()
                .filter_map(arm)
                .chain([normal])
                .collect(),
        }
    }
}

/// A block.
#[derive(Clone, Debug)]
pub(super) struct Node {
    /// Its label and the label's statement (none for the body's start).
    pub(super) label: Option<(LabelId, StmtId)>,
    /// Its straight-line statements (and a last one that stops).
    pub(super) code: Vec<StmtId>,
    pub(super) term: Term,
}

/// The graph of a goto-only body.
#[derive(Clone, Debug)]
pub(super) struct Cfg {
    pub(super) nodes: Vec<Node>,
    /// How many `goto`s the body has.
    pub(super) gotos: usize,
}

impl Cfg {
    pub(super) fn node(&self, id: u32) -> Option<&Node> {
        self.nodes.get(id as usize)
    }

    /// Each node's successors, and whether it leaves the function.
    pub(super) fn graph(&self) -> (Vec<Vec<u32>>, Vec<bool>) {
        self.nodes
            .iter()
            .map(|node| {
                let mut exit = node.term.stops();
                let mut successors = Vec::new();
                for edge in node.term.edges() {
                    match edge.target {
                        To::Node(target) => successors.push(target),
                        To::End | To::Next => exit = true,
                    }
                }
                (successors, exit)
            })
            .unzip()
    }

    /// The graph of `function`'s goto-only body.
    ///
    /// # Errors
    ///
    /// [`Refusal::Malformed`] if the body is not in goto form: a loop,
    /// `break` or `continue`, a label inside a statement or defined twice,
    /// a `goto` to no label, an arm other than straight-line statements
    /// then a `goto` or a statement that stops, a switch arm falling
    /// through, statements after a terminator or after an `if` with an arm
    /// that falls through, or the end of the body reached in a function
    /// returning a value.
    pub(super) fn of(function: &Function) -> Result<Self, Refusal> {
        let mut labels = BTreeMap::new();
        for &id in &function.body {
            if let Some(&Stmt::Label(label)) = function.stmt(id) {
                let node = number(labels.len() + 1);
                if labels.insert(label, node).is_some() {
                    return Err(malformed(id, "a label is defined twice"));
                }
            }
        }
        let mut parser = Parser {
            function,
            labels,
            nodes: Vec::new(),
            gotos: 0,
            current: Node {
                label: None,
                code: Vec::new(),
                term: Term::Stop,
            },
            open: true,
            trying: false,
        };
        for &id in &function.body {
            parser.stmt(id)?;
        }
        parser.finish(To::End);
        let falls = parser
            .nodes
            .iter()
            .any(|node| node.term.edges().iter().any(|edge| edge.target == To::End));
        if falls && function.returns.is_some() {
            return Err(Refusal::Malformed {
                stmt: None,
                reason: "control reaches the end of a function returning a value",
            });
        }
        Ok(Self {
            nodes: parser.nodes,
            gotos: parser.gotos,
        })
    }
}

fn malformed(stmt: StmtId, reason: &'static str) -> Refusal {
    Refusal::Malformed {
        stmt: Some(stmt),
        reason,
    }
}

/// Whether `stmt` ends control (graph-wise: an escape that does not go
/// on); `None` if it is not a straight-line statement either.
pub(super) fn stops(stmt: &Stmt) -> Option<bool> {
    match stmt {
        Stmt::Assign { .. }
        | Stmt::Call { .. }
        | Stmt::Intrinsic { .. }
        | Stmt::Expr(_)
        | Stmt::VaStart { .. } => Some(false),
        Stmt::Return(_) | Stmt::Trap(_) | Stmt::Unreachable => Some(true),
        Stmt::Escape { kind, .. } => Some(match kind {
            Escape::NonStandardCall
            | Escape::StackTrick
            | Escape::SystemCall
            | Escape::Atomic
            | Escape::Update(_) => false,
            Escape::UnresolvedJump | Escape::ForeignJump | Escape::OverlappingCode => true,
        }),
        Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Try { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_) => None,
    }
}

struct Parser<'a> {
    function: &'a Function,
    labels: BTreeMap<LabelId, u32>,
    nodes: Vec<Node>,
    gotos: usize,
    current: Node,
    /// Whether `current` has no terminator yet.
    open: bool,
    /// Whether `current` ends in a `Try` whose normal edge (copies, then
    /// a `goto`) is being read.
    trying: bool,
}

impl Parser<'_> {
    fn stmt(&mut self, id: StmtId) -> Result<(), Refusal> {
        let stmt = self
            .function
            .stmt(id)
            .ok_or_else(|| malformed(id, "a statement is missing"))?;
        if let Stmt::Label(label) = *stmt {
            let node = self.labels.get(&label).copied().unwrap_or(NONE);
            self.finish(To::Node(node));
            self.current.label = Some((label, id));
            self.open = true;
            self.trying = false;
            return Ok(());
        }
        if self.trying {
            return self.normal(id, stmt);
        }
        if !self.open {
            return Err(malformed(id, "statements follow a terminator"));
        }
        if let Some(stop) = stops(stmt) {
            self.current.code.push(id);
            if stop {
                self.current.term = Term::Stop;
                self.open = false;
            }
            return Ok(());
        }
        self.current.term = match stmt {
            &Stmt::Goto(label) => Term::Jump(self.goto(id, label, Vec::new())?),
            Stmt::If {
                condition,
                then,
                otherwise,
            } => Term::Branch {
                stmt: id,
                condition: *condition,
                then: self.arm(then)?,
                otherwise: self.arm(otherwise)?,
            },
            Stmt::Switch { scrutinee, arms } => {
                let mut cases: Vec<Case> = Vec::with_capacity(arms.len());
                for arm in arms {
                    if arm.fallthrough {
                        return Err(malformed(id, "a switch arm falls through"));
                    }
                    let body = self.arm(&arm.body)?;
                    self.case(&mut cases, &arm.values, arm.default, body);
                }
                let none = (!arms.iter().any(|arm| arm.default)).then_some(Edge {
                    copies: Vec::new(),
                    jump: None,
                    target: To::Next,
                });
                Term::Switch {
                    stmt: id,
                    scrutinee: *scrutinee,
                    cases,
                    none,
                }
            }
            Stmt::Try { body, handlers } => {
                for &inner in body {
                    let simple = self.function.stmt(inner).and_then(stops);
                    if simple != Some(false) {
                        return Err(malformed(id, "a try whose body is not straight-line code"));
                    }
                }
                let handlers = handlers
                    .iter()
                    .map(|handler| self.arm(&handler.body))
                    .collect::<Result<Vec<_>, _>>()?;
                self.trying = true;
                Term::Try {
                    stmt: id,
                    handlers,
                    normal: Edge {
                        copies: Vec::new(),
                        jump: None,
                        target: To::Next,
                    },
                }
            }
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::Label(_)
            | Stmt::VaStart { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_) => return Err(malformed(id, "the body is not goto-only")),
        };
        self.open = false;
        Ok(())
    }

    /// Statement `id` after a `Try`: a copy on its normal edge, or the
    /// edge's `goto`.
    fn normal(&mut self, id: StmtId, stmt: &Stmt) -> Result<(), Refusal> {
        let Term::Try { normal, .. } = &mut self.current.term else {
            return Err(malformed(id, "statements follow a terminator"));
        };
        match (stops(stmt), stmt) {
            (Some(false), _) => normal.copies.push(id),
            (None, &Stmt::Goto(label)) => {
                let node = self
                    .labels
                    .get(&label)
                    .copied()
                    .ok_or_else(|| malformed(id, "a goto's label is not defined"))?;
                normal.jump = Some(id);
                normal.target = To::Node(node);
                self.gotos += 1;
                self.trying = false;
            }
            (Some(true) | None, _) => {
                return Err(malformed(
                    id,
                    "a try's normal edge is not copies and a jump",
                ));
            }
        }
        Ok(())
    }

    /// Adds an arm to `cases`, into an earlier arm with the same plain
    /// edge if there is one (its `goto` then unused).
    fn case(&mut self, cases: &mut Vec<Case>, values: &[Bits], default: bool, arm: Arm) {
        if let Arm::Edge(edge) = &arm
            && edge.copies.is_empty()
            && let Some(same) = cases.iter_mut().find(|case| match &case.arm {
                Arm::Edge(other) => other.copies.is_empty() && other.target == edge.target,
                Arm::Stop(_) => false,
            })
        {
            same.values.extend_from_slice(values);
            same.default |= default;
            if edge.jump.is_some() {
                self.gotos -= 1;
            }
            return;
        }
        cases.push(Case {
            values: values.to_vec(),
            default,
            arm,
        });
    }

    fn goto(&mut self, id: StmtId, label: LabelId, copies: Vec<StmtId>) -> Result<Edge, Refusal> {
        let node = self
            .labels
            .get(&label)
            .copied()
            .ok_or_else(|| malformed(id, "a goto's label is not defined"))?;
        self.gotos += 1;
        Ok(Edge {
            copies,
            jump: Some(id),
            target: To::Node(node),
        })
    }

    /// An `if` or `switch` arm: straight-line statements, then a `goto`,
    /// a statement that stops, or nothing (on to the next statement).
    fn arm(&mut self, block: &Block) -> Result<Arm, Refusal> {
        let mut copies = Vec::new();
        for (index, &id) in block.iter().enumerate() {
            let stmt = self
                .function
                .stmt(id)
                .ok_or_else(|| malformed(id, "a statement is missing"))?;
            let last = index + 1 == block.len();
            match (stops(stmt), stmt) {
                (Some(false), _) => copies.push(id),
                (Some(true), _) if last => return Ok(Arm::Stop(block.clone())),
                (None, &Stmt::Goto(label)) if last => {
                    return Ok(Arm::Edge(self.goto(id, label, copies)?));
                }
                (Some(true) | None, _) => {
                    return Err(malformed(id, "an arm is not straight-line code and a jump"));
                }
            }
        }
        Ok(Arm::Edge(Edge {
            copies,
            jump: None,
            target: To::Next,
        }))
    }

    /// Ends the current node, control going on to `next`.
    fn finish(&mut self, next: To) {
        if self.open {
            self.current.term = Term::Jump(Edge {
                copies: Vec::new(),
                jump: None,
                target: next,
            });
        }
        for edge in self.current.term.edges_mut() {
            if edge.target == To::Next {
                edge.target = next;
            }
        }
        let node = core::mem::replace(
            &mut self.current,
            Node {
                label: None,
                code: Vec::new(),
                term: Term::Stop,
            },
        );
        self.nodes.push(node);
    }
}
