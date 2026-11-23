//! Paths from one function to another: through ordered waypoints,
//! avoiding functions, the shortest first, with the
//! subgraph every such path lies in ("N nodes, shortest path M").
//!
//! The search runs over states: a node of the call graph (or, for data
//! reachability, a node and the argument the value is in: [`data`](super::data))
//! and how many waypoints the path has passed. A breadth-first search from
//! the start finds each state's distance; one backward from the goals
//! (the end with every waypoint passed) keeps the states on some path: the
//! subgraph. Paths are then listed by length, shortest first, each a
//! simple path in the states (a function may recur only between
//! waypoints), depth-first within the subgraph with each step bounded by
//! the distance left to a goal, until the limit, a length 6 calls past
//! the shortest, or a budget of steps. Everything is in the order of the
//! input, so the same query gets the same answer. Cancelling (an atomic
//! flag, read every 256 states) stops it with no answer.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};

use super::{CallGraph, Edge, Node, Subgraph};

/// How many calls past the shortest the paths listed may be.
const LONGER: usize = 6;

/// The most steps the listing of paths takes.
const BUDGET: usize = 200_000;

/// What to look for.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathQuery {
    /// Where paths start.
    pub from: Option<Node>,
    /// Where they end.
    pub to: Option<Node>,
    /// The nodes they pass, in order.
    pub through: Vec<Node>,
    /// The nodes they never pass.
    pub avoid: Vec<Node>,
    /// The most paths listed.
    pub limit: usize,
}

/// A step of a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hop {
    /// The function or import reached.
    pub node: Node,
    /// The call site reaching it from the hop before (`None` for the
    /// first).
    pub site: Option<u64>,
    /// For data reachability: the argument the value is passed in (0 the
    /// first), or the parameter it starts in for the first hop.
    pub argument: Option<u8>,
}

/// What a path search found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Paths {
    /// The paths, shortest first.
    pub paths: Vec<Vec<Hop>>,
    /// The calls on the shortest path, if there is one.
    pub shortest: Option<usize>,
    /// Every node on some path and the calls between them on paths, the
    /// start first, each node's level its distance from the start.
    pub subgraph: Subgraph,
    /// Whether every path up to the limit's length bound was listed (not
    /// cut by the budget of steps).
    pub complete: bool,
}

/// A search space: the states after a state, each with the call site
/// taking it there, and the node a state stands for.
pub(crate) trait Space {
    /// A state.
    type State: Copy + Ord;

    /// The node `state` is at.
    fn node(&self, state: Self::State) -> Node;

    /// The argument `state` carries the value in, if any.
    fn argument(&self, state: Self::State) -> Option<u8>;

    /// The states after `state`, each with a site taking it there, into
    /// `out`.
    fn next(&mut self, state: Self::State, out: &mut Vec<(Self::State, u64)>);
}

/// The call graph as a [`Space`]: a state is a node.
struct Calls<'g> {
    graph: &'g CallGraph,
}

impl Space for Calls<'_> {
    type State = Node;

    fn node(&self, state: Node) -> Node {
        state
    }

    fn argument(&self, _: Node) -> Option<u8> {
        None
    }

    fn next(&mut self, state: Node, out: &mut Vec<(Node, u64)>) {
        if let Node::Function(id) = state {
            out.extend(
                self.graph
                    .callees(id)
                    .iter()
                    .map(|call| (call.callee, call.site)),
            );
        }
    }
}

/// The paths of `graph` under `query`; `None` if cancelled.
pub(super) fn calls(graph: &CallGraph, query: &PathQuery, cancel: &AtomicBool) -> Option<Paths> {
    let Some(start) = query.from else {
        return Some(Paths::default());
    };
    search(&mut Calls { graph }, graph, start, query, cancel)
}

/// A state of the search: a space's state and how many waypoints were
/// passed.
type At<S> = (S, usize);

/// Each state's steps: the states after it, each with the call sites
/// taking it there.
type Steps<T> = BTreeMap<At<T>, Vec<(At<T>, Vec<u64>)>>;

/// Each state's distance (from the start, or left to an end).
type Distances<T> = BTreeMap<At<T>, usize>;

/// What the forward search finds: each state's distance and its steps.
type Reached<T> = (Distances<T>, Steps<T>);

/// The calls between the subgraph's nodes, each with its sites.
type CallSites = BTreeMap<(Node, Node), BTreeSet<u64>>;

/// Where paths end: at the end, every waypoint passed in order.
struct Ends<'q> {
    to: Node,
    through: &'q [Node],
}

impl Ends<'_> {
    /// How many waypoints are passed at `node`, `passed` before it.
    fn advance(&self, node: Node, passed: usize) -> usize {
        if self.through.get(passed) == Some(&node) {
            passed + 1
        } else {
            passed
        }
    }

    /// Whether a path ends at `node` with `passed` waypoints passed.
    fn reached(&self, node: Node, passed: usize) -> bool {
        node == self.to && passed == self.through.len()
    }
}

/// The paths in `space` (over `graph`) from `start` under `query`; `None`
/// if cancelled.
pub(crate) fn search<S: Space>(
    space: &mut S,
    graph: &CallGraph,
    start: S::State,
    query: &PathQuery,
    cancel: &AtomicBool,
) -> Option<Paths> {
    let Some(to) = query.to else {
        return Some(Paths::default());
    };
    let ends = Ends {
        to,
        through: &query.through,
    };
    let first: At<S::State> = (start, ends.advance(space.node(start), 0));
    let (distance, steps) = forward(space, query, &ends, first, cancel)?;
    let left = backward(space, &ends, &distance, &steps);
    let shortest = left.get(&first).copied();
    let Some(shortest) = shortest else {
        return Some(Paths {
            complete: true,
            subgraph: subgraph(graph, &[(space.node(start), 0)], &BTreeMap::new()),
            ..Paths::default()
        });
    };
    let (order, edges) = on_paths(space, start, &distance, &steps, &left);

    // The paths, shortest first.
    let mut lister = Lister {
        steps: &steps,
        left: &left,
        goal: &|(state, passed)| ends.reached(space.node(state), passed),
        stack: vec![(first, None)],
        on: BTreeSet::from([first]),
        out: Vec::new(),
        limit: query.limit,
        budget: BUDGET,
        cancel,
    };
    for length in shortest..=shortest + LONGER {
        if lister.out.len() >= lister.limit || lister.budget == 0 {
            break;
        }
        lister.walk(first, length)?;
    }
    let complete = lister.budget > 0;
    let paths = lister
        .out
        .into_iter()
        .map(|path| {
            path.into_iter()
                .map(|((state, _), site)| Hop {
                    node: space.node(state),
                    site,
                    argument: space.argument(state),
                })
                .collect()
        })
        .collect();
    Some(Paths {
        paths,
        shortest: Some(shortest),
        subgraph: subgraph(graph, &order, &edges),
        complete,
    })
}

/// Forward from `first`: each state's distance and its steps (none after
/// an end: nothing after it is on a path); `None` if cancelled.
fn forward<S: Space>(
    space: &mut S,
    query: &PathQuery,
    ends: &Ends<'_>,
    first: At<S::State>,
    cancel: &AtomicBool,
) -> Option<Reached<S::State>> {
    let mut distance: Distances<S::State> = BTreeMap::from([(first, 0)]);
    let mut steps: Steps<S::State> = BTreeMap::new();
    let mut queue = VecDeque::from([first]);
    let mut found = Vec::new();
    let mut seen = 0usize;
    while let Some(at) = queue.pop_front() {
        seen += 1;
        if seen.is_multiple_of(256) && cancel.load(Ordering::Relaxed) {
            return None;
        }
        if ends.reached(space.node(at.0), at.1) {
            continue;
        }
        let here = distance.get(&at).copied().unwrap_or(0);
        found.clear();
        space.next(at.0, &mut found);
        let mut out: Vec<(At<S::State>, Vec<u64>)> = Vec::new();
        for &(state, site) in &found {
            let node = space.node(state);
            if query.avoid.contains(&node) {
                continue;
            }
            let next = (state, ends.advance(node, at.1));
            match out.iter_mut().find(|(s, _)| *s == next) {
                Some((_, sites)) => sites.push(site),
                None => out.push((next, vec![site])),
            }
            distance.entry(next).or_insert_with(|| {
                queue.push_back(next);
                here + 1
            });
        }
        steps.insert(at, out);
    }
    Some((distance, steps))
}

/// Backward from the ends reached: the distance left from each state on
/// a path.
fn backward<S: Space>(
    space: &S,
    ends: &Ends<'_>,
    distance: &BTreeMap<At<S::State>, usize>,
    steps: &Steps<S::State>,
) -> BTreeMap<At<S::State>, usize> {
    let mut before: BTreeMap<At<S::State>, Vec<At<S::State>>> = BTreeMap::new();
    for (&at, out) in steps {
        for (next, _) in out {
            before.entry(*next).or_default().push(at);
        }
    }
    let mut left: BTreeMap<At<S::State>, usize> = BTreeMap::new();
    let mut queue: VecDeque<At<S::State>> = VecDeque::new();
    for &at in distance.keys() {
        if ends.reached(space.node(at.0), at.1) {
            left.insert(at, 0);
            queue.push_back(at);
        }
    }
    while let Some(at) = queue.pop_front() {
        let here = left.get(&at).copied().unwrap_or(0);
        for &previous in before.get(&at).into_iter().flatten() {
            left.entry(previous).or_insert_with(|| {
                queue.push_back(previous);
                here + 1
            });
        }
    }
    left
}

/// The subgraph: the nodes of the states on some path (the start first,
/// then by level) and the calls between them.
fn on_paths<S: Space>(
    space: &S,
    start: S::State,
    distance: &BTreeMap<At<S::State>, usize>,
    steps: &Steps<S::State>,
    left: &BTreeMap<At<S::State>, usize>,
) -> (Vec<(Node, usize)>, CallSites) {
    let mut levels: BTreeMap<Node, usize> = BTreeMap::new();
    let mut edges: CallSites = BTreeMap::new();
    for (&at, &d) in distance {
        if !left.contains_key(&at) {
            continue;
        }
        let node = space.node(at.0);
        let level = levels.entry(node).or_insert(d);
        *level = (*level).min(d);
        for (next, sites) in steps.get(&at).into_iter().flatten() {
            if left.contains_key(next) {
                edges
                    .entry((node, space.node(next.0)))
                    .or_default()
                    .extend(sites);
            }
        }
    }
    let mut order: Vec<(Node, usize)> = levels.into_iter().collect();
    order.sort_by_key(|&(node, level)| (node != space.node(start), level, node));
    (order, edges)
}

/// Lists simple paths of one length, depth first.
struct Lister<'a, T: Copy + Ord> {
    steps: &'a Steps<T>,
    left: &'a BTreeMap<At<T>, usize>,
    goal: &'a dyn Fn(At<T>) -> bool,
    /// The path so far, each state with the site reaching it.
    stack: Vec<(At<T>, Option<u64>)>,
    /// The states on it.
    on: BTreeSet<At<T>>,
    out: Vec<Vec<(At<T>, Option<u64>)>>,
    limit: usize,
    budget: usize,
    cancel: &'a AtomicBool,
}

impl<T: Copy + Ord> Lister<'_, T> {
    /// Extends the path at `at` to paths of `length` calls in all; `None`
    /// if cancelled.
    fn walk(&mut self, at: At<T>, length: usize) -> Option<()> {
        let depth = self.stack.len() - 1;
        if (self.goal)(at) {
            if depth == length {
                self.out.push(self.stack.clone());
            }
            return Some(());
        }
        for (next, sites) in self.steps.get(&at).into_iter().flatten() {
            if self.out.len() >= self.limit || self.budget == 0 {
                return Some(());
            }
            self.budget -= 1;
            if self.budget.is_multiple_of(256) && self.cancel.load(Ordering::Relaxed) {
                return None;
            }
            let Some(&left) = self.left.get(next) else {
                continue;
            };
            if depth + 1 + left > length || self.on.contains(next) {
                continue;
            }
            self.on.insert(*next);
            self.stack.push((*next, sites.first().copied()));
            let walked = self.walk(*next, length);
            self.stack.pop();
            self.on.remove(next);
            walked?;
        }
        Some(())
    }
}

/// The subgraph of `graph` of `nodes` (with their levels, in order) and
/// the calls on paths between them (`edges`, with their sites).
fn subgraph(graph: &CallGraph, nodes: &[(Node, usize)], edges: &CallSites) -> Subgraph {
    let index: BTreeMap<Node, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, &(n, _))| (n, i))
        .collect();
    let edges = edges
        .iter()
        .filter_map(|(&(from, to), sites)| {
            Some(Edge {
                from: *index.get(&from)?,
                to: *index.get(&to)?,
                sites: sites.iter().copied().collect(),
            })
        })
        .collect();
    Subgraph {
        nodes: nodes.iter().map(|&(node, _)| node).collect(),
        levels: nodes
            .iter()
            .map(|&(_, level)| i32::try_from(level).unwrap_or(i32::MAX))
            .collect(),
        edges,
        unresolved: nodes
            .iter()
            .map(|&(node, _)| match node {
                Node::Function(id) => graph.unresolved(id).len(),
                Node::Import(_) => 0,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use crate::cfg::FunctionId;
    use binbun_semantics::core::Id as _;

    use super::super::tests::sample;
    use super::*;

    fn n(raw: u32) -> Node {
        Node::Function(FunctionId::from_raw(raw))
    }

    fn query(from: Node, to: Node) -> PathQuery {
        PathQuery {
            from: Some(from),
            to: Some(to),
            limit: 10,
            ..PathQuery::default()
        }
    }

    fn nodes(path: &[Hop]) -> Vec<Node> {
        path.iter().map(|hop| hop.node).collect()
    }

    #[test]
    fn shortest_first_with_subgraph() {
        let graph = sample();
        let never = AtomicBool::new(false);
        let found = graph
            .paths(&query(n(3), Node::Import(0x900)), &never)
            .expect("not cancelled");
        // 3 → 0 → 2 → puts (3 calls), then 3 → 0 → 1 → 2 → puts.
        assert_eq!(found.shortest, Some(3));
        let listed: Vec<Vec<Node>> = found.paths.iter().map(|p| nodes(p)).collect();
        assert_eq!(
            listed,
            [
                vec![n(3), n(0), n(2), Node::Import(0x900)],
                vec![n(3), n(0), n(1), n(2), Node::Import(0x900)],
            ]
        );
        // The first hop has no site; 0 → 2 is reached from its first site.
        let first = found.paths.first().expect("a path");
        assert_eq!(first.first().and_then(|h| h.site), None);
        assert_eq!(first.get(2).and_then(|h| h.site), Some(0x14));
        assert_eq!(found.subgraph.nodes.len(), 5);
        assert_eq!(found.subgraph.nodes.first(), Some(&n(3)));
        assert!(found.complete);
    }

    #[test]
    fn waypoints_avoidance_and_no_path() {
        let graph = sample();
        let never = AtomicBool::new(false);
        let through = PathQuery {
            through: vec![n(1)],
            ..query(n(0), n(2))
        };
        let found = graph.paths(&through, &never).expect("not cancelled");
        assert_eq!(found.paths.len(), 1);
        assert_eq!(found.shortest, Some(2));
        // The subgraph leaves out the direct call 0 → 2, on no such path.
        assert!(!found.subgraph.edges.iter().any(|e| {
            found.subgraph.nodes.get(e.from) == Some(&n(0))
                && found.subgraph.nodes.get(e.to) == Some(&n(2))
        }));
        let avoiding = PathQuery {
            avoid: vec![n(2)],
            ..query(n(0), Node::Import(0x900))
        };
        let none = graph.paths(&avoiding, &never).expect("not cancelled");
        assert_eq!(none.shortest, None);
        assert_eq!(none.paths, Vec::<Vec<Hop>>::new());
        // Backwards along calls there is no path.
        assert_eq!(
            graph
                .paths(&query(n(2), n(0)), &never)
                .expect("not cancelled")
                .shortest,
            None
        );
    }

    #[test]
    fn cancelled_gives_nothing() {
        // A chain of 1,000 functions, each calling the next.
        let calls = (0..999u32)
            .map(|i| super::super::Call {
                caller: FunctionId::from_raw(i),
                site: u64::from(i) * 4,
                callee: n(i + 1),
                kind: super::super::Kind::Call,
            })
            .collect();
        let graph = CallGraph::new(calls, Vec::new(), BTreeMap::new(), 1000);
        let chain = query(n(0), n(999));
        assert_eq!(graph.paths(&chain, &AtomicBool::new(true)), None);
        let found = graph
            .paths(&chain, &AtomicBool::new(false))
            .expect("not cancelled");
        assert_eq!(found.shortest, Some(999));
        assert_eq!(found.paths.first().map(Vec::len), Some(1000));
    }
}
