//! Where a value comes from, and where it goes ([`origins`]): from a
//! variable or a C token's node (its provenance's L1 values), backward
//! through the function's L1 dataflow (SSA) to its sources, and forward
//! to its uses.
//!
//! Sources: constants, undefined values, parameters (a register's entry
//! value), loads (with the address expression), call results (which
//! call). Operations and choices are inner steps with their operands as
//! inputs; a join (a block parameter whose arguments differ, a select) is
//! a fork, one input per argument. Trivial steps are folded into the step
//! they lead to, each recorded ([`Trivial`]), as Pernosco folds them: a
//! truncation to low bits or an extension, an operation that leaves its
//! operand unchanged (`x | 0`, `x ^ 0`, `x ± 0`, `x & x`, `x | x`), a
//! reload of a stack slot from the store that wrote it (a spill, as the
//! stack analysis forwards it), and a block parameter whose arguments are
//! all one value (or itself, round a loop).
//!
//! Interprocedural, to a bounded depth: a parameter's step lists the call
//! sites of the function (from the cross-references) with the chain of
//! the argument each passes, a call result's step the callee's returns
//! with the chain of what each returns. Every step has its machine
//! instructions and the L2 nodes whose provenance names its value (what
//! the C shows of it). The trees are bounded by [`Query::steps`].

use std::collections::{BTreeMap, BTreeSet};

use binbun_ast::ir::{Expr, ExprId, Function as Ast, Node, Origin, StmtId, VarId};
use binbun_decompile::mapping::{Mapping, Source};
use binbun_semantics::Declarations;
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_ssa::constant::Constants;
use binbun_ssa::ir::{BlockId, Definition, Function, Op, Terminator, Type, Value};
use binbun_ssa::stack::Stack;

use super::{Lowered, constant, defined_at, lower, values_of};
use crate::Database;
use crate::cfg::FunctionId;
use crate::decompile::View;
use crate::references::Kind as Reference;

/// How far a query goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    /// The view the function is decompiled in.
    pub view: View,
    /// How many functions away the chains go (0: this function only).
    pub depth: usize,
    /// The most steps of all the chains of one query, other functions'
    /// included.
    pub steps: usize,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            view: View::Exact,
            depth: 1,
            steps: 128,
        }
    }
}

/// What a query starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// A variable: every L1 value it holds.
    Var(VarId),
    /// A C token's node: the L1 values its provenance names (an
    /// expression reading a variable without one: the variable's).
    Node(Node),
}

/// A trivial step, folded ([`Step::folded`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Trivial {
    /// The low bits of a value.
    Truncation,
    /// A value extended.
    Extension,
    /// An operation that leaves its operand unchanged.
    Copy,
    /// A reload of the stack slot a store wrote (a spill).
    Reload,
    /// A block parameter whose arguments are all one value.
    BlockArgument,
}

/// A trivial step folded into the step it leads to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Folded {
    /// What it is.
    pub kind: Trivial,
    /// The value it defines.
    pub value: Value,
    /// Its machine instruction (a block parameter: its block's first).
    pub address: Option<u64>,
}

/// What a step is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A constant.
    Constant(u64),
    /// A value the architecture leaves undefined.
    Undefined,
    /// A parameter: a register's entry value.
    Parameter {
        /// The register.
        register: String,
        /// Its place among the C parameters, if it is one.
        index: Option<usize>,
        /// The call sites and the chain of what each passes (to the
        /// query's depth).
        sites: Vec<Remote>,
    },
    /// A load.
    Load {
        /// The address loaded from, as an expression of sources.
        address: String,
        /// How many bytes.
        bytes: u16,
    },
    /// A call's result.
    Call {
        /// The call's instruction.
        call: u64,
        /// The callee, if constant.
        callee: Option<u64>,
        /// Its name.
        name: Option<String>,
        /// The callee's returns and the chain of what each returns (to the
        /// query's depth).
        returns: Vec<Remote>,
    },
    /// An operation of its inputs.
    Operation(String),
    /// A choice among its inputs (a block parameter whose arguments
    /// differ, a select).
    Join,
    /// Something else that defines a value (an intrinsic, a system call,
    /// what an exception handler receives).
    Other(String),
    /// Not followed: the query's steps are spent.
    Cut,
}

/// A step of a chain in another function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remote {
    /// That function's entry.
    pub function: u64,
    /// Its name.
    pub name: Option<String>,
    /// The call (for a call site) or the return's block (for a return).
    pub address: u64,
    /// The chain there, if followed.
    pub chain: Option<Box<Step>>,
}

/// One step of a chain: a value, what defines it, and its inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The value (after the trivial steps folded).
    pub value: Value,
    /// What it is.
    pub kind: Kind,
    /// Its machine instructions (with the folded steps').
    pub addresses: Vec<u64>,
    /// The L2 nodes whose provenance names it or a folded step's value.
    pub nodes: Vec<Node>,
    /// The trivial steps folded into it, nearest the use first.
    pub folded: Vec<Folded>,
    /// What it is computed from.
    pub inputs: Vec<Self>,
}

impl Step {
    /// How many steps the chain has, this one included (other functions'
    /// not).
    pub fn size(&self) -> usize {
        1 + self.inputs.iter().map(Self::size).sum::<usize>()
    }

    /// The longest path from this step to a source, in steps.
    pub fn depth(&self) -> usize {
        1 + self.inputs.iter().map(Self::depth).max().unwrap_or(0)
    }

    /// How many trivial steps the chain folds.
    pub fn folds(&self) -> usize {
        self.folded.len() + self.inputs.iter().map(Self::folds).sum::<usize>()
    }

    /// Whether the chain folds a trivial step of `kind`.
    pub fn folds_kind(&self, kind: Trivial) -> bool {
        self.folded.iter().any(|folded| folded.kind == kind)
            || self.inputs.iter().any(|input| input.folds_kind(kind))
    }
}

/// A use of a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Use {
    /// The machine instruction (a terminator's: its block's first).
    pub address: u64,
    /// What uses it.
    pub kind: String,
    /// The L2 nodes standing for the use.
    pub nodes: Vec<Node>,
}

/// Where the values of a start come from and where they go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origins {
    /// The function's entry.
    pub entry: u64,
    /// The L1 values started from.
    pub values: Vec<Value>,
    /// The chain of each, backward.
    pub chains: Vec<Step>,
    /// Their uses, trivial steps followed.
    pub uses: Vec<Use>,
}

/// The most values of one start followed (a variable coalesced from many).
const VALUES: usize = 8;

/// The most call sites or returns followed per step.
const REMOTES: usize = 4;

/// The most uses listed.
const USES: usize = 64;

/// The most nested steps of one chain.
const NESTING: usize = 32;

/// Where `start` of function `id` of `database` comes from and goes,
/// under `query`.
///
/// # Errors
///
/// The function cannot be decompiled in the view.
pub fn origins(
    database: &Database<'_>,
    id: FunctionId,
    start: Start,
    query: &Query,
) -> Result<Origins, String> {
    let (lowered, _) = lower(database, id, query.view, &[])?;
    let mut budget = query.steps;
    Ok(origins_lowered(
        database,
        &lowered,
        start,
        query,
        &mut budget,
    ))
}

/// [`origins`] of `lowered`, spending `budget` steps.
pub fn origins_lowered(
    database: &Database<'_>,
    lowered: &Lowered,
    start: Start,
    query: &Query,
    budget: &mut usize,
) -> Origins {
    let tracer = Tracer::new(database, lowered, query, query.depth);
    let mut values = tracer.start(start);
    // A value that is a trivial step from another (a parameter's low
    // half) has that one's chain.
    let mut bases = BTreeSet::new();
    values.retain(|&value| bases.insert(tracer.fold(value).0));
    values.truncate(VALUES);
    let chains = values
        .iter()
        .map(|&value| tracer.backward(value, 0, budget))
        .collect();
    let mut uses = Vec::new();
    for &value in &values {
        tracer.uses(value, &mut uses);
    }
    uses.truncate(USES);
    Origins {
        entry: lowered.entry,
        values,
        chains,
        uses,
    }
}

/// One function's dataflow, as a query reads it.
struct Tracer<'a> {
    database: &'a Database<'a>,
    l1: &'a Function,
    l2: &'a Ast,
    stack: &'a Stack,
    constants: &'a Constants,
    mapping: &'a Mapping,
    declarations: Option<&'static Declarations>,
    query: &'a Query,
    /// How many functions further chains may go.
    depth: usize,
    /// The L2 nodes naming each L1 value.
    nodes: BTreeMap<Value, Vec<Node>>,
    /// The loads that reload each stored value (spills).
    reloads: BTreeMap<Value, Vec<Value>>,
}

impl<'a> Tracer<'a> {
    fn new(
        database: &'a Database<'a>,
        lowered: &'a Lowered,
        query: &'a Query,
        depth: usize,
    ) -> Self {
        let l1 = &lowered.prepared.l1;
        let l2 = &lowered.l2;
        let stack = &*lowered.prepared.facts.stack;
        let constants = &*lowered.prepared.facts.constants;
        let mut nodes: BTreeMap<Value, Vec<Node>> = BTreeMap::new();
        let mut name = |origins: &[Origin], node: Node| {
            for origin in origins {
                if let Origin::Value(value) = origin {
                    nodes.entry(*value).or_default().push(node);
                }
            }
        };
        for (index, variable) in l2.variables.iter().enumerate() {
            name(&variable.origins, Node::Var(VarId(number(index))));
        }
        for index in 0..l2.stmts.len() {
            let id = StmtId(number(index));
            name(l2.provenance.stmt(id), Node::Stmt(id));
        }
        for index in 0..l2.exprs.len() {
            let id = ExprId(number(index));
            name(l2.provenance.expr(id), Node::Expr(id));
        }
        let mut reloads: BTreeMap<Value, Vec<Value>> = BTreeMap::new();
        for inst in &l1.insts {
            if let (Op::Load { .. }, Some(&result)) = (&inst.op, inst.results.first()) {
                let stored = stack.resolve(l1, result);
                if stored != result {
                    reloads.entry(stored).or_default().push(result);
                }
            }
        }
        Self {
            database,
            l1,
            l2,
            stack,
            constants,
            mapping: &lowered.mapping,
            declarations: database.declarations(),
            query,
            depth,
            nodes,
            reloads,
        }
    }

    /// The L1 values `start` names.
    fn start(&self, start: Start) -> Vec<Value> {
        let of_var = |var: VarId| {
            self.l2.var(var).map_or_else(Vec::new, |variable| {
                values_of(self.l1, variable.kind, &variable.origins)
            })
        };
        let named = |origins: &[Origin]| -> Vec<Value> {
            origins
                .iter()
                .filter_map(|origin| {
                    if let Origin::Value(value) = origin {
                        Some(*value)
                    } else {
                        None
                    }
                })
                .collect()
        };
        let mut values = match start {
            Start::Var(var) | Start::Node(Node::Var(var)) => of_var(var),
            Start::Node(Node::Expr(id)) => {
                let values = named(self.l2.provenance.expr(id));
                if let (true, Some(&Expr::Var(var))) = (values.is_empty(), self.l2.expr(id)) {
                    of_var(var)
                } else {
                    values
                }
            }
            Start::Node(Node::Stmt(id)) => named(self.l2.provenance.stmt(id)),
            Start::Node(Node::Type(_)) => Vec::new(),
        };
        values.retain(|&value| matches!(self.l1.ty(value), Some(Type::Bits(_))));
        values.sort_unstable();
        values.dedup();
        values
    }

    /// The chain of `value`, `nesting` steps in, spending `budget`.
    fn backward(&self, value: Value, nesting: usize, budget: &mut usize) -> Step {
        let (value, folded) = self.fold(value);
        let mut addresses: Vec<u64> = folded.iter().filter_map(|f| f.address).collect();
        addresses.extend(defined_at(self.l1, value));
        addresses.sort_unstable();
        addresses.dedup();
        let mut nodes: Vec<Node> = core::iter::once(value)
            .chain(folded.iter().map(|f| f.value))
            .flat_map(|v| self.nodes.get(&v).into_iter().flatten().copied())
            .collect();
        nodes.sort_unstable();
        nodes.dedup();
        let (kind, inputs) = if *budget == 0 || nesting >= NESTING {
            (Kind::Cut, Vec::new())
        } else {
            *budget -= 1;
            self.define(value, budget)
        };
        let inputs = inputs
            .into_iter()
            .map(|input| self.backward(input, nesting + 1, budget))
            .collect();
        Step {
            value,
            kind,
            addresses,
            nodes,
            folded,
            inputs,
        }
    }

    /// What defines `value` (folded), and the values to follow from it.
    fn define(&self, value: Value, budget: &mut usize) -> (Kind, Vec<Value>) {
        if let Some(bits) = self.constant(value) {
            return (Kind::Constant(bits), Vec::new());
        }
        let Some(info) = self.l1.value(value) else {
            return (Kind::Other("unknown".to_owned()), Vec::new());
        };
        let (inst, index) = match info.definition {
            Definition::Parameter {
                block: BlockId(0),
                index,
            } => return (self.parameter(index, budget), Vec::new()),
            Definition::Parameter { block, index } => {
                let mut arguments = self.incoming(block, index as usize);
                arguments.retain(|&argument| argument != value);
                arguments.sort_unstable();
                arguments.dedup();
                return (Kind::Join, arguments);
            }
            Definition::Result { inst, index } => (inst, index),
        };
        let Some(i) = self.l1.inst(inst) else {
            return (Kind::Other("unknown".to_owned()), Vec::new());
        };
        match &i.op {
            Op::Const(bits) => (Kind::Constant(bits.low_u64()), Vec::new()),
            Op::Undefined(..) => (Kind::Undefined, Vec::new()),
            &Op::Load { address, bytes, .. } => (
                Kind::Load {
                    address: self.describe(address, 3),
                    bytes,
                },
                Vec::new(),
            ),
            Op::Call {
                target, changes, ..
            } => {
                let register = (index as usize)
                    .checked_sub(1)
                    .and_then(|position| changes.get(position))
                    .copied();
                (self.call(i.address, *target, register, budget), Vec::new())
            }
            &Op::Select {
                then, otherwise, ..
            } => (Kind::Join, vec![then, otherwise]),
            op @ (Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }) => (Kind::Operation(operation(op)), op.operands()),
            op @ (Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. }) => (Kind::Other(operation(op)), Vec::new()),
        }
    }

    /// `value` with the trivial steps leading to it folded: what it is a
    /// copy of, and the steps.
    fn fold(&self, mut value: Value) -> (Value, Vec<Folded>) {
        let mut folded = Vec::new();
        let mut seen = BTreeSet::new();
        while seen.insert(value) {
            let Some((kind, next)) = self.trivial(value) else {
                break;
            };
            folded.push(Folded {
                kind,
                value,
                address: defined_at(self.l1, value),
            });
            value = next;
        }
        (value, folded)
    }

    /// What `value` is a trivial step from, if it is one.
    fn trivial(&self, value: Value) -> Option<(Trivial, Value)> {
        let (inst, block, index) = match self.l1.value(value)?.definition {
            Definition::Result { inst, .. } => (Some(inst), None, 0),
            Definition::Parameter { block, index } => (None, Some(block), index as usize),
        };
        if let Some(block) = block {
            if block == BlockId(0) {
                return None;
            }
            let mut arguments = self.incoming(block, index);
            arguments.retain(|&argument| argument != value);
            arguments.sort_unstable();
            arguments.dedup();
            return match arguments[..] {
                [only] => Some((Trivial::BlockArgument, only)),
                _ => None,
            };
        }
        let op = &self.l1.inst(inst?)?.op;
        let zero = |v: Value| self.constant(v) == Some(0);
        match *op {
            Op::Extract {
                value: source,
                offset: 0,
                ..
            } => Some((Trivial::Truncation, source)),
            Op::Extend { value: source, .. } => Some((Trivial::Extension, source)),
            Op::Binary(Binary::Or | Binary::Xor | Binary::Add | Binary::Sub, a, b) if zero(b) => {
                Some((Trivial::Copy, a))
            }
            Op::Binary(Binary::Or | Binary::Xor | Binary::Add, a, b) if zero(a) => {
                Some((Trivial::Copy, b))
            }
            Op::Binary(Binary::And | Binary::Or, a, b) if a == b => Some((Trivial::Copy, a)),
            Op::Load { .. } => {
                let stored = self.stack.resolve(self.l1, value);
                (stored != value).then_some((Trivial::Reload, stored))
            }
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => None,
        }
    }

    /// The arguments block `block`'s parameter `index` gets.
    fn incoming(&self, block: BlockId, index: usize) -> Vec<Value> {
        self.l1
            .blocks
            .iter()
            .flat_map(|b| b.terminator.targets())
            .filter(|target| target.block == block)
            .filter_map(|target| target.arguments.get(index).copied())
            .collect()
    }

    /// The entry value of register `index`: a parameter, with its call
    /// sites' arguments.
    fn parameter(&self, index: u32, budget: &mut usize) -> Kind {
        let register = RegisterId(u16::try_from(index).unwrap_or(u16::MAX));
        let name = self
            .declarations
            .and_then(|declarations| declarations.info(register))
            .map_or_else(|| format!("r{index}"), |info| info.name.to_owned());
        let position = self.mapping.parameters.iter().position(
            |source| matches!(source, Source::Register(piece) if piece.register == register),
        );
        let mut sites = Vec::new();
        if self.depth > 0 {
            let entry = self.l1.entry;
            let references = self.database.references().to(entry);
            for reference in references
                .iter()
                .filter(|reference| reference.kind == Reference::Call)
                .take(REMOTES)
            {
                let Some(caller) = reference.function else {
                    continue;
                };
                let chain = self.remote(caller, budget, |tracer| {
                    tracer.l1.insts.iter().find_map(|inst| {
                        if let Op::Call { registers, .. } = &inst.op
                            && inst.address == reference.from
                        {
                            registers.get(usize::from(register.0)).copied()
                        } else {
                            None
                        }
                    })
                });
                sites.push(Remote {
                    function: self.entry_of(caller),
                    name: self.database.data_name(self.entry_of(caller)),
                    address: reference.from,
                    chain,
                });
            }
        }
        Kind::Parameter {
            register: name,
            index: position,
            sites,
        }
    }

    /// The result in `register` of the call at `address` through
    /// `target`, with the callee's returns.
    fn call(
        &self,
        address: u64,
        target: Value,
        register: Option<RegisterId>,
        budget: &mut usize,
    ) -> Kind {
        let callee = self.constant(target);
        let mut returns = Vec::new();
        let function = callee.and_then(|callee| self.database.function_at(callee));
        if let (true, Some(function), Some(register)) = (self.depth > 0, function, register) {
            let mut seen = 0;
            while seen < REMOTES {
                let index = seen;
                let mut at = None;
                let chain = self.remote(function, budget, |tracer| {
                    let (block, value) = tracer
                        .l1
                        .blocks
                        .iter()
                        .filter_map(|block| match &block.terminator {
                            Terminator::Return { state, .. } => state
                                .registers
                                .get(usize::from(register.0))
                                .map(|&value| (block.address, value)),
                            Terminator::Jump(_)
                            | Terminator::Branch { .. }
                            | Terminator::IndirectJump { .. }
                            | Terminator::Leave { .. }
                            | Terminator::Trap(_)
                            | Terminator::Stop
                            | Terminator::Invoke { .. }
                            | Terminator::Open => None,
                        })
                        .nth(index)?;
                    at = Some(block);
                    Some(value)
                });
                let Some(at) = at else {
                    break;
                };
                returns.push(Remote {
                    function: self.entry_of(function),
                    name: self.database.data_name(self.entry_of(function)),
                    address: at,
                    chain,
                });
                seen += 1;
            }
        }
        Kind::Call {
            call: address,
            callee,
            name: callee.and_then(|callee| self.database.data_name(callee)),
            returns,
        }
    }

    /// The chain, in function `id` (one level deeper), of the value `pick`
    /// finds there.
    fn remote(
        &self,
        id: FunctionId,
        budget: &mut usize,
        pick: impl FnOnce(&Tracer<'_>) -> Option<Value>,
    ) -> Option<Box<Step>> {
        if *budget == 0 {
            return None;
        }
        let (lowered, _) = lower(self.database, id, self.query.view, &[]).ok()?;
        let tracer = Tracer::new(self.database, &lowered, self.query, self.depth - 1);
        let value = pick(&tracer)?;
        Some(Box::new(tracer.backward(value, 0, budget)))
    }

    fn entry_of(&self, id: FunctionId) -> u64 {
        self.database
            .function(id)
            .map_or(0, |function| function.entry)
    }

    /// The constant `value` is, by constant propagation (over the image's
    /// read-only memory), as 64 bits.
    fn constant(&self, value: Value) -> Option<u64> {
        self.constants
            .constant(value)
            .map(|bits| bits.low_u64())
            .or_else(|| constant(self.l1, value))
    }

    /// `value` as an expression of what it is computed from, `depth`
    /// operations deep: constants, registers' entry values, stack
    /// addresses (`sp±k`, the entry stack pointer), else `v<n>`.
    fn describe(&self, value: Value, depth: usize) -> String {
        let (value, _) = self.fold(value);
        if let Some(offset) = self.stack.offset(value) {
            return match offset {
                0 => "sp".to_owned(),
                o if o < 0 => format!("sp-{:#x}", o.unsigned_abs()),
                o => format!("sp+{o:#x}"),
            };
        }
        if let Some(bits) = self.constant(value) {
            return format!("{bits:#x}");
        }
        let Some(info) = self.l1.value(value) else {
            return format!("v{}", value.0);
        };
        match info.definition {
            Definition::Parameter {
                block: BlockId(0),
                index,
            } => self
                .declarations
                .and_then(|d| d.info(RegisterId(u16::try_from(index).unwrap_or(u16::MAX))))
                .map_or_else(|| format!("v{}", value.0), |info| info.name.to_owned()),
            Definition::Result { inst, .. } if depth > 0 => {
                let op = self.l1.inst(inst).map(|i| &i.op);
                if let Some(&Op::Binary(op, a, b)) = op
                    && let Some(symbol) = symbol(op)
                {
                    format!(
                        "({} {symbol} {})",
                        self.describe(a, depth - 1),
                        self.describe(b, depth - 1)
                    )
                } else if let Some(&Op::Load { address, .. }) = op {
                    format!("[{}]", self.describe(address, depth - 1))
                } else {
                    format!("v{}", value.0)
                }
            }
            Definition::Parameter { .. } | Definition::Result { .. } => format!("v{}", value.0),
        }
    }

    /// The uses of `value`, through trivial steps, into `out`.
    fn uses(&self, value: Value, out: &mut Vec<Use>) {
        let mut set = BTreeSet::from([value]);
        let mut work = vec![value];
        while let Some(current) = work.pop() {
            if out.len() >= USES {
                return;
            }
            let follow = |next: Value, set: &mut BTreeSet<Value>, work: &mut Vec<Value>| {
                if set.insert(next) {
                    work.push(next);
                }
            };
            for &reload in self.reloads.get(&current).into_iter().flatten() {
                follow(reload, &mut set, &mut work);
            }
            for inst in &self.l1.insts {
                if !inst.op.operands().contains(&current) {
                    continue;
                }
                let result = inst.results.first().copied();
                if let Some(result) = result
                    && self
                        .trivial(result)
                        .is_some_and(|(_, from)| from == current)
                {
                    follow(result, &mut set, &mut work);
                    continue;
                }
                let kind = use_kind(&inst.op, current);
                out.push(Use {
                    address: inst.address,
                    kind,
                    nodes: result
                        .and_then(|result| self.nodes.get(&result))
                        .cloned()
                        .unwrap_or_default(),
                });
            }
            for block in &self.l1.blocks {
                let terminator = &block.terminator;
                if terminator.operands().any(|operand| operand == current) {
                    let kind = match terminator {
                        Terminator::Branch { .. } => "branch condition",
                        Terminator::Return { .. } => "returned",
                        Terminator::Leave { .. } => "passed on (tail call)",
                        Terminator::IndirectJump { .. } => "jump address",
                        Terminator::Jump(_)
                        | Terminator::Trap(_)
                        | Terminator::Stop
                        | Terminator::Invoke { .. }
                        | Terminator::Open => "terminator",
                    };
                    out.push(Use {
                        address: block.address,
                        kind: kind.to_owned(),
                        nodes: Vec::new(),
                    });
                }
                for target in terminator.targets() {
                    for (position, &argument) in target.arguments.iter().enumerate() {
                        if argument != current {
                            continue;
                        }
                        let Some(&parameter) = self
                            .l1
                            .block(target.block)
                            .and_then(|b| b.parameters.get(position))
                        else {
                            continue;
                        };
                        if self.trivial(parameter).is_some() {
                            follow(parameter, &mut set, &mut work);
                        } else {
                            out.push(Use {
                                address: block.address,
                                kind: "joins".to_owned(),
                                nodes: self.nodes.get(&parameter).cloned().unwrap_or_default(),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// The name of `op`'s operation.
fn operation(op: &Op) -> String {
    match op {
        Op::Unary(unary, _) => format!("{unary:?}"),
        Op::Binary(binary, ..) => format!("{binary:?}"),
        Op::Flag(flag, ..) => format!("{flag:?}"),
        Op::Float { op, .. } => format!("{op:?}"),
        Op::Lanes { op, .. } => format!("{op:?}"),
        Op::Extract { offset, width, .. } => format!("Extract {width} bits at {offset}"),
        Op::Concat { .. } => "Concat".to_owned(),
        Op::Extend { signed, width, .. } => {
            format!(
                "{} {width}",
                if *signed { "SignExtend" } else { "ZeroExtend" }
            )
        }
        Op::Select { .. } => "Select".to_owned(),
        Op::Const(_) => "Const".to_owned(),
        Op::Undefined(..) => "Undefined".to_owned(),
        Op::Load { .. } => "Load".to_owned(),
        Op::Store { .. } => "Store".to_owned(),
        Op::Intrinsic { intrinsic, .. } => format!("intrinsic {}", intrinsic.0),
        Op::Call { .. } => "Call".to_owned(),
        Op::SystemCall { .. } => "system call".to_owned(),
        Op::Landing { .. } => "exception landing".to_owned(),
    }
}

/// How `op` uses `value`, one of its operands.
fn use_kind(op: &Op, value: Value) -> String {
    match op {
        Op::Store { value: stored, .. } if *stored == value => "stored".to_owned(),
        Op::Store { .. } => "store address".to_owned(),
        Op::Load { .. } => "load address".to_owned(),
        Op::Call { target, .. } if *target == value => "called".to_owned(),
        Op::Call { .. } => "call argument".to_owned(),
        Op::Const(_)
        | Op::Undefined(..)
        | Op::Unary(..)
        | Op::Binary(..)
        | Op::Flag(..)
        | Op::Extract { .. }
        | Op::Concat { .. }
        | Op::Extend { .. }
        | Op::Select { .. }
        | Op::Lanes { .. }
        | Op::Float { .. }
        | Op::Intrinsic { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => operation(op),
    }
}

/// `index` as a `u32` id.
fn number(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}

/// The C operator of `op`, where an address expression shows one.
fn symbol(op: Binary) -> Option<&'static str> {
    [
        (Binary::Add, "+"),
        (Binary::Sub, "-"),
        (Binary::Mul, "*"),
        (Binary::Shl, "<<"),
        (Binary::And, "&"),
        (Binary::Or, "|"),
    ]
    .into_iter()
    .find_map(|(candidate, text)| (candidate == op).then_some(text))
}
