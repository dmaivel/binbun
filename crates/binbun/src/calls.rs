//! The call graph ([`CallGraph`]): which function calls which, from
//! recovery's control flow, and the questions asked of it (a function's
//! neighbourhood, the paths from one function to another), answered as
//! lists rather than drawings of everything.
//!
//! An edge is a call site ([`Call`]): a block's call to a function's entry
//! or to an import (through its pointer slot: the PLT stub's `jmp [slot]`
//! is its thunk's edge, the slot's fixed value a direct call where the
//! [`Resolver`](crate::cfg::Resolver) proved one), a jump to another
//! function's entry (a tail call, conditional ones included), and each
//! case of a resolved computed jump that is another function's entry. A
//! call or jump recovery could not resolve (through a register, a pointer
//! slot that is no import, a far address) is kept per function as
//! [`Unresolved`]: the graph never pretends to be complete where it is
//! not.
//!
//! - [`CallGraph::neighbourhood`]: a function's callers so many levels up
//!   and callees so many down, with each pair's calls counted.
//! - [`CallGraph::paths`] ([`paths`]): the shortest paths from one
//!   function to another through ordered waypoints, avoiding functions,
//!   and the subgraph of every path (its size and the shortest length),
//!   cancellable.
//! - [`data`]: the same search along calls where a parameter's value
//!   flows on into the callee's arguments ("can data from A's argument
//!   reach B?").
//! - [`sites`]: each call site's arguments as the C passes them, with
//!   their known values or ranges.

pub mod data;
pub mod paths;
pub mod sites;

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

use binbun_loader::Image;

pub use paths::{Hop, PathQuery, Paths};

use crate::cfg::{Destination, Exit, FunctionId, Program};
use crate::references::last_instruction;

/// What a call reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    /// A function of the program.
    Function(FunctionId),
    /// An import, by the address of its pointer slot.
    Import(u64),
}

/// How a call site reaches its callee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A call instruction.
    Call,
    /// A jump to the callee's entry: a tail call (taken or conditional).
    Tail,
    /// A case of a resolved computed jump that is the callee's entry.
    Table,
}

/// One call site: a caller reaching a callee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Call {
    /// The calling function.
    pub caller: FunctionId,
    /// The instruction making the call or jump.
    pub site: u64,
    /// What it reaches.
    pub callee: Node,
    /// How.
    pub kind: Kind,
}

/// A call or jump out of a function whose destination is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unresolved {
    /// The function making it.
    pub caller: FunctionId,
    /// The instruction.
    pub site: u64,
    /// Whether it is a jump (a tail call through a pointer) rather than a
    /// call.
    pub tail: bool,
}

/// Every call of a program, by caller and by callee.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallGraph {
    /// The calls, sorted by caller, then site and callee.
    calls: Vec<Call>,
    /// Indices of `calls`, sorted by callee, then caller and site.
    by_callee: Vec<u32>,
    /// The unresolved calls, sorted by caller and site.
    unresolved: Vec<Unresolved>,
    /// The imports' names, by slot.
    imports: BTreeMap<u64, String>,
    /// How many functions the program has.
    functions: usize,
}

impl CallGraph {
    /// The calls of `program`, recovered from `image`.
    pub fn build(image: &Image<'_>, program: &Program) -> Self {
        let mut calls = Vec::new();
        let mut unresolved = Vec::new();
        for (caller, function) in program.functions.iter() {
            let other = |address: u64| {
                program
                    .function_at(address)
                    .filter(|&id| id != caller && function.parts.binary_search(&address).is_err())
            };
            for &block_id in &function.blocks {
                let Some(block) = program.blocks.get(block_id) else {
                    continue;
                };
                let Some(site) = last_instruction(image, block) else {
                    continue;
                };
                let mut push = |callee: Node, kind: Kind| {
                    calls.push(Call {
                        caller,
                        site,
                        callee,
                        kind,
                    });
                };
                let (destination, kind) = match block.exit {
                    Exit::Call { callee, .. } => (Some(callee), Kind::Call),
                    Exit::Jump(destination) | Exit::Branch(destination) => {
                        (Some(destination), Kind::Tail)
                    }
                    Exit::Next | Exit::Return | Exit::Stop | Exit::Invalid | Exit::Limit => {
                        (None, Kind::Call)
                    }
                };
                match destination {
                    Some(Destination::Address(target)) => {
                        let callee = if kind == Kind::Call {
                            program.function_at(target)
                        } else {
                            other(target)
                        };
                        if let Some(callee) = callee {
                            push(Node::Function(callee), kind);
                        }
                    }
                    Some(Destination::Import(slot)) => push(Node::Import(slot), kind),
                    Some(Destination::Pointer(_)) => unresolved.push(Unresolved {
                        caller,
                        site,
                        tail: kind == Kind::Tail,
                    }),
                    Some(Destination::Indirect | Destination::Far)
                        if kind == Kind::Call && program.table(block_id).is_none() =>
                    {
                        unresolved.push(Unresolved {
                            caller,
                            site,
                            tail: false,
                        });
                    }
                    Some(Destination::Indirect | Destination::Far) | None => {}
                }
                for &target in program.table(block_id).map_or(&[][..], |t| &t.targets) {
                    if let Some(callee) = other(target) {
                        push(Node::Function(callee), Kind::Table);
                    }
                }
            }
        }
        let imports = image
            .imports
            .iter()
            .map(|import| (import.slot, import.name.clone()))
            .collect();
        Self::new(calls, unresolved, imports, program.functions.len())
    }

    /// The index of `calls`.
    fn new(
        mut calls: Vec<Call>,
        mut unresolved: Vec<Unresolved>,
        imports: BTreeMap<u64, String>,
        functions: usize,
    ) -> Self {
        calls.sort_unstable();
        calls.dedup();
        unresolved.sort_unstable();
        unresolved.dedup();
        let mut by_callee: Vec<u32> = (0..calls.len())
            .filter_map(|index| u32::try_from(index).ok())
            .collect();
        by_callee.sort_unstable_by_key(|&index| {
            calls
                .get(index as usize)
                .map(|call| (call.callee, call.caller, call.site))
        });
        Self {
            calls,
            by_callee,
            unresolved,
            imports,
            functions,
        }
    }

    /// Every call, by caller.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// The calls `caller` makes, by site.
    pub fn callees(&self, caller: FunctionId) -> &[Call] {
        let first = self.calls.partition_point(|call| call.caller < caller);
        let last = self.calls.partition_point(|call| call.caller <= caller);
        self.calls.get(first..last).unwrap_or_default()
    }

    /// The calls reaching `callee`, by caller and site.
    pub fn callers(&self, callee: Node) -> impl Iterator<Item = &Call> {
        let key = |index: &u32| self.calls.get(*index as usize).map(|call| call.callee);
        let first = self
            .by_callee
            .partition_point(|index| key(index) < Some(callee));
        let last = self
            .by_callee
            .partition_point(|index| key(index) <= Some(callee));
        self.by_callee
            .get(first..last)
            .unwrap_or_default()
            .iter()
            .filter_map(|&index| self.calls.get(index as usize))
    }

    /// The calls and jumps out of `caller` whose destination is not known.
    pub fn unresolved(&self, caller: FunctionId) -> &[Unresolved] {
        let first = self.unresolved.partition_point(|u| u.caller < caller);
        let last = self.unresolved.partition_point(|u| u.caller <= caller);
        self.unresolved.get(first..last).unwrap_or_default()
    }

    /// The name of the import whose pointer slot is at `slot`.
    pub fn import_name(&self, slot: u64) -> Option<&str> {
        self.imports.get(&slot).map(String::as_str)
    }

    /// Every import: its slot and name, by slot.
    pub fn imports(&self) -> impl Iterator<Item = (u64, &str)> {
        self.imports
            .iter()
            .map(|(&slot, name)| (slot, name.as_str()))
    }

    /// How many functions the program has.
    pub fn functions(&self) -> usize {
        self.functions
    }

    /// The nodes `node` calls (`down`) or is called by, each once, in
    /// order.
    pub fn next(&self, node: Node, down: bool) -> Vec<Node> {
        let mut out: Vec<Node> = if down {
            match node {
                Node::Function(id) => self.callees(id).iter().map(|call| call.callee).collect(),
                Node::Import(_) => Vec::new(),
            }
        } else {
            self.callers(node)
                .map(|call| Node::Function(call.caller))
                .collect()
        };
        out.sort_unstable();
        out.dedup();
        out
    }

    /// `centre`'s callers up to `up` levels up and callees up to `down`
    /// levels down, at most `most` nodes (nearer levels first, callees
    /// before callers on a level), with every call between two of them.
    pub fn neighbourhood(&self, centre: Node, up: usize, down: usize, most: usize) -> Subgraph {
        let mut level: BTreeMap<Node, i32> = BTreeMap::new();
        level.insert(centre, 0);
        let mut nodes = vec![centre];
        let mut frontiers = [vec![centre], vec![centre]];
        let deepest = up.max(down);
        'levels: for depth in 1..=deepest {
            for (side, frontier) in frontiers.iter_mut().enumerate() {
                let downwards = side == 0;
                if depth > if downwards { down } else { up } {
                    frontier.clear();
                    continue;
                }
                let mut found = Vec::new();
                for &node in frontier.iter() {
                    for next in self.next(node, downwards) {
                        if level.contains_key(&next) {
                            continue;
                        }
                        if nodes.len() >= most {
                            break 'levels;
                        }
                        let at = i32::try_from(depth).unwrap_or(i32::MAX);
                        level.insert(next, if downwards { at } else { -at });
                        nodes.push(next);
                        found.push(next);
                    }
                }
                *frontier = found;
            }
        }
        Subgraph::of(self, nodes, |node| level.get(&node).copied().unwrap_or(0))
    }

    /// [`paths::search`] of this graph under `query`; `None` if `cancel`
    /// was set while searching.
    pub fn paths(&self, query: &PathQuery, cancel: &AtomicBool) -> Option<Paths> {
        paths::calls(self, query, cancel)
    }
}

/// An edge of a [`Subgraph`]: the calls from one of its nodes to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    /// The caller's index among the nodes.
    pub from: usize,
    /// The callee's.
    pub to: usize,
    /// The call sites, by address.
    pub sites: Vec<u64>,
}

/// Some functions of a call graph and the calls between them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subgraph {
    /// The nodes; the first is the one asked about (a neighbourhood's
    /// centre, a path's start).
    pub nodes: Vec<Node>,
    /// Each node's level: callees below 0 positive, callers negative (a
    /// path's: its distance from the start).
    pub levels: Vec<i32>,
    /// The edges, by caller and callee.
    pub edges: Vec<Edge>,
    /// Each node's unresolved calls (0 for an import).
    pub unresolved: Vec<usize>,
}

impl Subgraph {
    /// `nodes` of `graph` with every call between them and their `level`s.
    fn of(graph: &CallGraph, nodes: Vec<Node>, level: impl Fn(Node) -> i32) -> Self {
        let index: BTreeMap<Node, usize> = nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        let mut edges: BTreeMap<(usize, usize), Vec<u64>> = BTreeMap::new();
        for (from, &node) in nodes.iter().enumerate() {
            let Node::Function(id) = node else {
                continue;
            };
            for call in graph.callees(id) {
                if let Some(&to) = index.get(&call.callee) {
                    edges.entry((from, to)).or_default().push(call.site);
                }
            }
        }
        let unresolved = nodes
            .iter()
            .map(|&node| match node {
                Node::Function(id) => graph.unresolved(id).len(),
                Node::Import(_) => 0,
            })
            .collect();
        Self {
            levels: nodes.iter().map(|&node| level(node)).collect(),
            nodes,
            edges: edges
                .into_iter()
                .map(|((from, to), sites)| Edge { from, to, sites })
                .collect(),
            unresolved,
        }
    }
}

#[cfg(test)]
mod tests {
    use binbun_semantics::core::Id as _;

    use super::*;

    fn f(n: u32) -> FunctionId {
        FunctionId::from_raw(n)
    }

    fn call(from: u32, site: u64, callee: Node) -> Call {
        Call {
            caller: f(from),
            site,
            callee,
            kind: Kind::Call,
        }
    }

    /// 0 → 1 → 2 → import, 0 → 2 twice, 3 → 0.
    pub(super) fn sample() -> CallGraph {
        let calls = vec![
            call(0, 0x10, Node::Function(f(1))),
            call(0, 0x14, Node::Function(f(2))),
            call(0, 0x18, Node::Function(f(2))),
            call(1, 0x20, Node::Function(f(2))),
            call(2, 0x30, Node::Import(0x900)),
            call(3, 0x40, Node::Function(f(0))),
        ];
        let unresolved = vec![Unresolved {
            caller: f(1),
            site: 0x24,
            tail: false,
        }];
        let imports = BTreeMap::from([(0x900, "puts".to_owned())]);
        CallGraph::new(calls, unresolved, imports, 4)
    }

    #[test]
    fn callers_and_callees_by_node() {
        let graph = sample();
        let sites: Vec<u64> = graph
            .callers(Node::Function(f(2)))
            .map(|c| c.site)
            .collect();
        assert_eq!(sites, [0x14, 0x18, 0x20]);
        assert_eq!(graph.callees(f(1)).len(), 1);
        assert_eq!(graph.next(Node::Function(f(0)), true).len(), 2);
        assert_eq!(graph.unresolved(f(1)).len(), 1);
        assert_eq!(graph.import_name(0x900), Some("puts"));
    }

    #[test]
    fn neighbourhood_levels_and_multiplicity() {
        let graph = sample();
        let around = graph.neighbourhood(Node::Function(f(0)), 1, 1, 64);
        assert_eq!(
            around.nodes,
            [
                Node::Function(f(0)),
                Node::Function(f(1)),
                Node::Function(f(2)),
                Node::Function(f(3))
            ]
        );
        assert_eq!(around.levels, [0, 1, 1, -1]);
        // 0 → 2 twice is one edge with two sites; 1 → 2 is between two
        // nodes shown, so it is drawn too.
        let twice = around
            .edges
            .iter()
            .find(|e| e.from == 0 && e.to == 2)
            .expect("an edge from 0 to 2");
        assert_eq!(twice.sites, [0x14, 0x18]);
        assert!(around.edges.iter().any(|e| e.from == 1 && e.to == 2));
        assert_eq!(around.unresolved, [0, 1, 0, 0]);
        // Two levels down reach the import; a cap of 2 nodes stops early.
        let deeper = graph.neighbourhood(Node::Function(f(0)), 0, 2, 64);
        assert!(deeper.nodes.contains(&Node::Import(0x900)));
        assert_eq!(
            graph
                .neighbourhood(Node::Function(f(0)), 1, 1, 2)
                .nodes
                .len(),
            2
        );
    }
}
