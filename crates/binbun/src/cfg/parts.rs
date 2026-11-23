//! Joining the parts of functions that recovery first found as functions
//! of their own (cold parts) into the functions they belong to, by the
//! rule of the [crate] documentation.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use binbun_semantics::core::Arena;

use crate::cfg::recover::successors;
use crate::cfg::{
    Block, BlockId, Destination, EdgeKind, Exit, Frame, Function, SeedKind, Table, Unwind,
};

/// What the join reads of recovery's results.
pub(crate) struct Graph<'a> {
    /// Every block.
    pub(crate) blocks: &'a Arena<BlockId, Block>,
    /// The blocks, by start.
    pub(crate) by_start: &'a BTreeMap<u64, BlockId>,
    /// The resolved tables of computed jumps, by the end of their block.
    pub(crate) tables: &'a BTreeMap<u64, Table>,
    /// The extents of functions known from seeds: start to end.
    pub(crate) extents: &'a BTreeMap<u64, u64>,
    /// How the extents not entered by a call are entered, by start.
    pub(crate) frames: &'a BTreeMap<u64, Frame>,
    /// Code split off functions ([`crate::cfg::Seed::Split`]): start to
    /// end and the function it was split off, where known.
    pub(crate) splits: &'a BTreeMap<u64, (u64, Option<u64>)>,
    /// The call-site ranges with a landing pad, by start.
    pub(crate) unwind: &'a Unwind,
    /// The user's ends of functions ([`crate::Seed::End`]): start to end.
    /// Nothing is joined into such a function.
    pub(crate) ends: &'a BTreeMap<u64, u64>,
}

/// How other functions' code enters a function.
#[derive(Clone, Debug, Default)]
struct Entered {
    /// The blocks of other functions that go to its entry, each with
    /// whether it is a conditional branch taken there.
    from: Vec<(BlockId, bool)>,
    /// Whether some call goes to it.
    called: bool,
}

/// The functions and what the join knows about them.
struct Join<'f, 'g> {
    functions: &'f [Function],
    graph: &'g Graph<'g>,
    /// Each function's index, by entry.
    by_entry: HashMap<u64, usize>,
    /// The functions each block is in.
    owners: HashMap<BlockId, Vec<usize>>,
    /// How each function is entered.
    entered: Vec<Entered>,
    /// The function each function is joined into (itself if none): a
    /// forest whose roots are the functions that remain.
    parent: Vec<usize>,
}

/// Joins each function of `functions` that is a part of another into it
/// (its blocks, landing pads and parts become that function's, and it is
/// removed), except a part only landing pads lead to, which stays a
/// function marked [`Function::part_of`].
pub(crate) fn join(functions: &mut Vec<Function>, graph: &Graph<'_>) {
    let (parent, part_of) = {
        let mut join = Join::new(functions, graph);
        while join.round() {}
        let part_of = join.keep_unreached();
        (join.parent, part_of)
    };
    merge(functions, graph, &parent, &part_of);
}

impl<'f, 'g> Join<'f, 'g> {
    fn new(functions: &'f [Function], graph: &'g Graph<'g>) -> Self {
        let by_entry = functions
            .iter()
            .enumerate()
            .map(|(index, function)| (function.entry, index))
            .collect();
        let mut owners: HashMap<BlockId, Vec<usize>> = HashMap::new();
        for (index, function) in functions.iter().enumerate() {
            for &block in &function.blocks {
                owners.entry(block).or_default().push(index);
            }
        }
        let mut join = Self {
            functions,
            graph,
            by_entry,
            owners,
            entered: vec![Entered::default(); functions.len()],
            parent: (0..functions.len()).collect(),
        };
        join.find_entries();
        join
    }

    /// Fills [`Self::entered`]: every call to a function's entry, and every
    /// jump or branch to it (or falling into it) from another function.
    fn find_entries(&mut self) {
        let graph = self.graph;
        for (id, block) in graph.blocks.iter() {
            if let Exit::Call {
                callee: Destination::Address(target),
                ..
            } = block.exit
                && let Some(entered) = self
                    .by_entry
                    .get(&target)
                    .and_then(|&index| self.entered.get_mut(index))
            {
                entered.called = true;
            }
            let Some(from) = self.owners.get(&id) else {
                continue;
            };
            for (kind, target) in successors(graph.tables, graph.unwind, *block) {
                let Some(&index) = self.by_entry.get(&target) else {
                    continue;
                };
                if from.contains(&index) {
                    continue;
                }
                if let Some(entered) = self.entered.get_mut(index) {
                    entered.from.push((id, kind == EdgeKind::Taken));
                }
            }
        }
    }

    /// The function `index` is joined into, through any chain of joins
    /// (itself if none).
    fn root(&self, mut index: usize) -> usize {
        while let Some(&next) = self.parent.get(index)
            && next != index
        {
            index = next;
        }
        index
    }

    /// One round: joins each function not joined yet that is a part of
    /// another (with what this round has joined so far). Whether any was.
    fn round(&mut self) -> bool {
        let mut changed = false;
        for index in 0..self.functions.len() {
            if self.root(index) != index || !self.may_be_part(index) {
                continue;
            }
            // Split-off code whose unwind information names its function:
            // a part of it, whoever else's code (other split-off pieces of
            // it not joined yet) goes there.
            if let Some(owner) = self.split_owner(index)
                && let Some(parent) = self.parent.get_mut(index)
            {
                *parent = owner;
                changed = true;
                continue;
            }
            if self
                .entered
                .get(index)
                .is_none_or(|entered| entered.from.is_empty())
            {
                continue;
            }
            let Some(owner) = self.single_owner(index) else {
                continue;
            };
            // The user said where the owner ends.
            if self
                .functions
                .get(owner)
                .is_some_and(|f| self.graph.ends.contains_key(&f.entry))
            {
                continue;
            }
            if self.evidence(index, owner)
                && let Some(parent) = self.parent.get_mut(index)
            {
                *parent = owner;
                changed = true;
            }
        }
        changed
    }

    /// Whether function `index` may be a part: no call goes to it, and no
    /// seed says it is a function's start other than its symbol or its
    /// unwind table entry, which does not start an outermost frame (the
    /// user's word never is such evidence). (Another function's code must
    /// also enter it, unless its unwind information names its function:
    /// [`Self::round`].)
    fn may_be_part(&self, index: usize) -> bool {
        let (Some(function), Some(entered)) = (self.functions.get(index), self.entered.get(index))
        else {
            return false;
        };
        let seeds = function.seeds;
        !entered.called
            && self.graph.frames.get(&function.entry) != Some(&Frame::Outermost)
            && !seeds.contains(SeedKind::Entry)
            && !seeds.contains(SeedKind::Export)
            && !seeds.contains(SeedKind::Pointer)
            && !seeds.contains(SeedKind::Reference)
            && !seeds.contains(SeedKind::User)
    }

    /// The one function (as joined so far) whose code enters function
    /// `index`, other than itself, if there is exactly one.
    fn single_owner(&self, index: usize) -> Option<usize> {
        let entered = self.entered.get(index)?;
        let mut owner = None;
        for (block, _) in &entered.from {
            for &from in self.owners.get(block).into_iter().flatten() {
                let root = self.root(from);
                if root == index {
                    continue;
                }
                match owner {
                    None => owner = Some(root),
                    Some(known) if known == root => {}
                    Some(_) => return None,
                }
            }
        }
        owner
    }

    /// Whether something says function `index`, entered only from
    /// `owner`, is no function of its own: it jumps back into `owner`, its
    /// unwind table entry starts inside a frame, it lies in code split off
    /// a function, or `owner` enters it by a conditional branch.
    fn evidence(&self, index: usize, owner: usize) -> bool {
        let Some(function) = self.functions.get(index) else {
            return false;
        };
        let conditional = self
            .entered
            .get(index)
            .is_some_and(|entered| entered.from.iter().any(|&(_, conditional)| conditional));
        conditional
            || self.graph.frames.get(&function.entry) == Some(&Frame::Inside)
            || self.split_off(function.entry)
            || self.jumps_back(function, owner)
    }

    /// Whether `address` lies in code split off a function.
    fn split_off(&self, address: u64) -> bool {
        self.split_at(address).is_some()
    }

    /// The code split off a function that `address` lies in: its start
    /// and, where known, the function it was split off.
    fn split_at(&self, address: u64) -> Option<(u64, Option<u64>)> {
        self.graph
            .splits
            .range(..=address)
            .next_back()
            .filter(|&(_, &(end, _))| address < end)
            .map(|(&start, &(_, owner))| (start, owner))
    }

    /// The function (as joined so far) that the split-off code function
    /// `index` starts in was split off, where its unwind information names
    /// one the program has, other than itself.
    fn split_owner(&self, index: usize) -> Option<usize> {
        let entry = self.functions.get(index)?.entry;
        let (_, owner) = self.split_at(entry)?;
        let root = self.root(*self.by_entry.get(&owner?)?);
        (root != index).then_some(root)
    }

    /// Whether a block of `function` goes into the code or extent of a
    /// function joined into `owner` (or `owner` itself), other than to its
    /// entry.
    fn jumps_back(&self, function: &Function, owner: usize) -> bool {
        let graph = self.graph;
        function
            .blocks
            .iter()
            .filter_map(|&id| graph.blocks.get(id))
            .flat_map(|&block| successors(graph.tables, graph.unwind, block))
            .any(|(_, target)| self.inside(target, owner))
    }

    /// Whether `address` lies in the extent or the code of a function
    /// joined into `owner` (or `owner` itself), and is not that function's
    /// entry.
    fn inside(&self, address: u64, owner: usize) -> bool {
        let graph = self.graph;
        let by_extent = graph
            .extents
            .range(..=address)
            .next_back()
            .filter(|&(_, &end)| address < end)
            .and_then(|(start, _)| self.by_entry.get(start).copied());
        let by_block = graph
            .by_start
            .get(&address)
            .and_then(|block| self.owners.get(block))
            .into_iter()
            .flatten()
            .copied();
        by_extent.into_iter().chain(by_block).any(|index| {
            self.root(index) == owner
                && self
                    .functions
                    .get(index)
                    .is_some_and(|function| function.entry != address)
        })
    }

    /// Undoes the joins of the parts whose entry their function's code
    /// does not reach from its entry, through its calls' landing pads too
    /// (only landing pads no recovered call unwinds to lead there): for
    /// each, the entry of the function it is a part of.
    fn keep_unreached(&mut self) -> Vec<Option<u64>> {
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for index in 0..self.functions.len() {
            let root = self.root(index);
            if root != index {
                groups.entry(root).or_default().push(index);
            }
        }
        let mut part_of = vec![None; self.functions.len()];
        for (owner, members) in groups {
            let Some(entry) = self.functions.get(owner).map(|function| function.entry) else {
                continue;
            };
            let reached = self.reached(owner, entry);
            for member in members {
                let unreached = self
                    .functions
                    .get(member)
                    .is_some_and(|function| !reached.contains(&function.entry));
                if unreached && let Some(slot) = part_of.get_mut(member) {
                    *slot = Some(entry);
                }
            }
        }
        for (index, owner) in part_of.iter().enumerate() {
            if owner.is_some()
                && let Some(parent) = self.parent.get_mut(index)
            {
                *parent = index;
            }
        }
        part_of
    }

    /// The starts of the blocks of `owner` and the functions joined into
    /// it that control reaches from its `entry`, an exception unwinding
    /// through a call included ([`EdgeKind::Unwind`]).
    fn reached(&self, owner: usize, entry: u64) -> BTreeSet<u64> {
        let graph = self.graph;
        let mut reached = BTreeSet::new();
        let mut work = vec![entry];
        while let Some(address) = work.pop() {
            let Some(&id) = graph.by_start.get(&address) else {
                continue;
            };
            let ours = self
                .owners
                .get(&id)
                .is_some_and(|indices| indices.iter().any(|&index| self.root(index) == owner));
            if !ours || !reached.insert(address) {
                continue;
            }
            if let Some(&block) = graph.blocks.get(id) {
                work.extend(
                    successors(graph.tables, graph.unwind, block).map(|(_, target)| target),
                );
            }
        }
        reached
    }
}

/// Joins each funclet of `funclets` (its function, by its address) that
/// recovery found as a function to the function it belongs to: the one
/// starting there, or that joined it as a part (and, for a funclet's
/// funclets, the funclet's own function), listing it in its
/// [`Function::funclets`] and marking it [`Function::part_of`].
pub(crate) fn funclets(functions: &mut [Function], funclets: &BTreeMap<u64, u64>) {
    let mut owners: HashMap<u64, usize> = HashMap::new();
    for (index, function) in functions.iter().enumerate() {
        owners.insert(function.entry, index);
        for &part in &function.parts {
            owners.entry(part).or_insert(index);
        }
    }
    let root = |mut address: u64| {
        for _ in 0..funclets.len() {
            match funclets.get(&address) {
                Some(&function) if function != address => address = function,
                _ => break,
            }
        }
        address
    };
    for &address in funclets.keys() {
        let (Some(&funclet), Some(&owner)) = (owners.get(&address), owners.get(&root(address)))
        else {
            continue;
        };
        let Some(entry) = functions.get(owner).map(|f| f.entry) else {
            continue;
        };
        if funclet == owner || functions.get(funclet).is_none_or(|f| f.entry != address) {
            continue;
        }
        if let Some(function) = functions.get_mut(funclet) {
            function.part_of = Some(entry);
        }
        if let Some(function) = functions.get_mut(owner) {
            function.funclets.push(address);
        }
    }
    for function in functions {
        function.funclets.sort_unstable();
        function.funclets.dedup();
    }
}

/// Moves each function of `functions` joined into another (`parent`, a
/// forest) into its root, removes it, and marks the parts `part_of` names.
fn merge(
    functions: &mut Vec<Function>,
    graph: &Graph<'_>,
    parent: &[usize],
    part_of: &[Option<u64>],
) {
    let root = |mut index: usize| {
        while let Some(&next) = parent.get(index)
            && next != index
        {
            index = next;
        }
        index
    };
    for (index, &owner) in part_of.iter().enumerate() {
        if let Some(function) = functions.get_mut(index) {
            function.part_of = owner;
        }
    }
    for index in 0..functions.len() {
        let owner = root(index);
        if owner == index {
            continue;
        }
        let Some(part) = functions.get_mut(index) else {
            continue;
        };
        let entry = part.entry;
        let returns = part.returns;
        let blocks = core::mem::take(&mut part.blocks);
        let parts = core::mem::take(&mut part.parts);
        let pads = core::mem::take(&mut part.landing_pads);
        if let Some(owner) = functions.get_mut(owner) {
            owner.blocks.extend(blocks);
            owner.parts.push(entry);
            owner.parts.extend(parts);
            owner.landing_pads.extend(pads);
            owner.returns |= returns;
        }
    }
    let mut index = 0;
    functions.retain(|_| {
        let keep = root(index) == index;
        index += 1;
        keep
    });
    for function in functions.iter_mut().filter(|f| !f.parts.is_empty()) {
        function
            .blocks
            .sort_unstable_by_key(|&id| graph.blocks.get(id).map_or(u64::MAX, |b| b.start));
        function.blocks.dedup();
        function.parts.sort_unstable();
        function.landing_pads.sort_unstable();
        function.landing_pads.dedup();
    }
}
