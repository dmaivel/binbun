//! Data reachability: paths along calls where a value goes on, as the
//! origin query's interprocedural steps follow it (a parameter's value to
//! each call site's argument): "can data from A's argument reach B?".
//!
//! Within a function ([`flows`]), each integer parameter of the
//! convention is followed forward through its L1 dataflow: an operation
//! or choice of a value it reaches reaches its result, a block parameter
//! any of whose arguments it reaches is reached, and a load is reached if
//! its address is (what a pointer parameter points to goes with it) or if
//! it reloads a stack slot a reached value was stored to (a spill, as the
//! stack analysis forwards it). Memory as a whole is not followed (a value
//! stored elsewhere and loaded back is lost), nor are call results (what
//! a callee returns of its arguments). A call or a tail call (a jump out
//! with the registers) whose argument register holds a reached value
//! passes it on in that argument, if the callee takes it: a function's
//! interface (as decompilation finds it) says which argument registers it
//! reads, every one if it is variadic; an import, or a function without
//! an interface, is taken to read them all. A function that does not
//! lift passes nothing on.
//!
//! Across functions ([`paths`]), the search of [`super::paths`] runs over
//! states (a function, the argument the value is in), along the calls the
//! value goes on through, from the start's parameter to any call reaching
//! the end. Only the functions on some path by calls alone are lifted.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};

use binbun_decompile::mapping::Source;
use binbun_ssa::ir::{BlockId, Definition, Function, Op, Terminator, Value};
use binbun_ssa::stack::Stack;

use super::paths::{PathQuery, Paths, Space, search};
use super::{CallGraph, Node};
use crate::Database;
use crate::cfg::FunctionId;
use crate::references::last_instruction;
use crate::target::convention;

/// A parameter's value passed on at a call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Flow {
    /// The call (or tail call) instruction.
    pub site: u64,
    /// The parameter (0 the first integer one of the convention).
    pub parameter: u8,
    /// The argument it is passed in.
    pub argument: u8,
}

/// The flows of function `id` of `database` (see the module's
/// documentation), by site; empty if it does not lift.
pub fn flows(database: &Database<'_>, id: FunctionId) -> Vec<Flow> {
    let (Ok(prepared), interfaces) = database.prepare(id, &[]) else {
        return Vec::new();
    };
    let Some(declarations) = database.declarations() else {
        return Vec::new();
    };
    let arguments = convention(database.image(), declarations).arguments;
    // One bit each in a mask of 16.
    let registers: Vec<u16> = arguments
        .iter()
        .take(16)
        .map(|register| register.0)
        .collect();
    let l1 = &prepared.l1;
    let reached = reach(l1, &prepared.facts.stack, &registers);
    let mask = |value: Value| reached.get(&value).copied().unwrap_or(0);
    let every = u16::try_from((1u32 << registers.len()) - 1).unwrap_or(u16::MAX);
    // The argument registers the callees at `site` read.
    let taken = |site: u64| {
        database
            .calls()
            .callees(id)
            .iter()
            .filter(|call| call.site == site)
            .fold(0u16, |bits, call| {
                let interface = match call.callee {
                    Node::Function(callee) => database
                        .function(callee)
                        .and_then(|f| interfaces.interfaces.get(&f.entry)),
                    Node::Import(_) => None,
                };
                bits | interface.map_or(every, |interface| {
                    if interface.variadic {
                        return every;
                    }
                    interface
                        .parameters
                        .iter()
                        .filter_map(|source| match source {
                            Source::Register(piece) => {
                                registers.iter().position(|&r| r == piece.register.0)
                            }
                            Source::Stack { .. } => None,
                        })
                        .fold(0, |bits, position| bits | (1 << position))
                })
            })
    };
    let mut out = Vec::new();
    let mut passed = |site: u64, state: &[Value]| {
        let taken = taken(site);
        for (argument, &register) in registers.iter().enumerate() {
            if taken & (1 << argument) == 0 {
                continue;
            }
            let carried = state.get(usize::from(register)).map_or(0, |&v| mask(v));
            for parameter in 0..registers.len() {
                if carried & (1 << parameter) != 0 {
                    out.push(Flow {
                        site,
                        parameter: u8::try_from(parameter).unwrap_or(u8::MAX),
                        argument: u8::try_from(argument).unwrap_or(u8::MAX),
                    });
                }
            }
        }
    };
    for inst in &l1.insts {
        if let Op::Call { registers, .. } = &inst.op {
            passed(inst.address, registers);
        }
    }
    let program = database.program();
    for block in &l1.blocks {
        if let Terminator::Leave { state, .. } = &block.terminator {
            let site = program
                .block_containing(block.address)
                .and_then(|b| program.blocks.get(b))
                .and_then(|b| last_instruction(database.image(), b));
            if let Some(site) = site {
                passed(site, &state.registers);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Which of the entry values of `registers` (bit `i` for the `i`th) each
/// value of `l1` is computed from (see the module's documentation).
fn reach(l1: &Function, stack: &Stack, registers: &[u16]) -> HashMap<Value, u16> {
    let mut reached: HashMap<Value, u16> = HashMap::new();
    if let Some(entry) = l1.blocks.first() {
        for &parameter in &entry.parameters {
            if let Some(info) = l1.value(parameter)
                && let Definition::Parameter {
                    block: BlockId(0),
                    index,
                } = info.definition
                && let Some(bit) = registers.iter().position(|&r| u32::from(r) == index)
            {
                reached.insert(parameter, 1 << bit);
            }
        }
    }
    let mask =
        |reached: &HashMap<Value, u16>, value: Value| reached.get(&value).copied().unwrap_or(0);
    loop {
        let mut changed = false;
        let mut add = |reached: &mut HashMap<Value, u16>, value: Value, bits: u16| {
            if bits == 0 {
                return;
            }
            let slot = reached.entry(value).or_insert(0);
            if *slot | bits != *slot {
                *slot |= bits;
                changed = true;
            }
        };
        for inst in &l1.insts {
            let bits = match &inst.op {
                &Op::Load { address, .. } => {
                    let reload = inst
                        .results
                        .first()
                        .map(|&result| stack.resolve(l1, result))
                        .filter(|&stored| Some(&stored) != inst.results.first());
                    mask(&reached, address) | reload.map_or(0, |v| mask(&reached, v))
                }
                Op::Store { .. }
                | Op::Call { .. }
                | Op::SystemCall { .. }
                | Op::Intrinsic { .. }
                | Op::Landing { .. } => 0,
                op @ (Op::Const(_)
                | Op::Undefined(..)
                | Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Concat { .. }
                | Op::Extend { .. }
                | Op::Select { .. }
                | Op::Lanes { .. }
                | Op::Float { .. }) => op
                    .operands()
                    .into_iter()
                    .fold(0, |bits, v| bits | mask(&reached, v)),
            };
            for &result in &inst.results {
                add(&mut reached, result, bits);
            }
        }
        for block in &l1.blocks {
            for target in block.terminator.targets() {
                let Some(into) = l1.block(target.block) else {
                    continue;
                };
                for (&parameter, &argument) in into.parameters.iter().zip(&target.arguments) {
                    let bits = mask(&reached, argument);
                    add(&mut reached, parameter, bits);
                }
            }
        }
        if !changed {
            return reached;
        }
    }
}

/// The call graph as a [`Space`] of (node, argument) states along flows.
struct Data<'d> {
    database: &'d Database<'d>,
    graph: &'d CallGraph,
    /// The nodes on some path by calls alone.
    allowed: BTreeSet<Node>,
    /// Each function's flows, once found.
    flows: BTreeMap<FunctionId, Vec<Flow>>,
    cancel: &'d AtomicBool,
}

impl Space for Data<'_> {
    type State = (Node, u8);

    fn node(&self, (node, _): (Node, u8)) -> Node {
        node
    }

    fn argument(&self, (_, argument): (Node, u8)) -> Option<u8> {
        Some(argument)
    }

    fn next(&mut self, (node, argument): (Node, u8), out: &mut Vec<((Node, u8), u64)>) {
        let Node::Function(id) = node else {
            return;
        };
        if !self.allowed.contains(&node) || self.cancel.load(Ordering::Relaxed) {
            return;
        }
        let flows = self
            .flows
            .entry(id)
            .or_insert_with(|| flows(self.database, id));
        for flow in flows.iter().filter(|flow| flow.parameter == argument) {
            for call in self
                .graph
                .callees(id)
                .iter()
                .filter(|c| c.site == flow.site)
            {
                if self.allowed.contains(&call.callee) {
                    out.push(((call.callee, flow.argument), flow.site));
                }
            }
        }
    }
}

/// The paths of `database`'s call graph under `query` along which the
/// value of the start's parameter `parameter` (0 the first) goes on; `None`
/// if `cancel` was set. Without a path by calls alone, that search's
/// answer.
pub fn paths(
    database: &Database<'_>,
    query: &PathQuery,
    parameter: u8,
    cancel: &AtomicBool,
) -> Option<Paths> {
    let graph = database.calls();
    let by_calls = graph.paths(query, cancel)?;
    let (Some(from), Some(_)) = (query.from, by_calls.shortest) else {
        return Some(by_calls);
    };
    let mut space = Data {
        database,
        graph,
        allowed: by_calls.subgraph.nodes.iter().copied().collect(),
        flows: BTreeMap::new(),
        cancel,
    };
    let found = search(&mut space, graph, (from, parameter), query, cancel)?;
    (!cancel.load(Ordering::Relaxed)).then_some(found)
}
