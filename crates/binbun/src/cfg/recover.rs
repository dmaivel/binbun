//! The recursive-descent engine.
//!
//! Each function has a worklist of block addresses to visit. Visiting a
//! block decodes it if new (or splits the block it lies in), then queues
//! its successors. A call to a function whose fate is not decided yet makes
//! the caller wait for it: the call's fallthrough is queued only if the
//! callee turns out to return. Reaching another function's entry (a tail
//! call, or falling into it) is the same: this one returns if that one
//! does.
//!
//! A function returns if some block returns, or it jumps somewhere
//! unresolved, or into a function or import that returns. That is decided
//! as soon as one such path is found (more code cannot undo it), and
//! otherwise once its worklist is empty and it waits for nobody. When only
//! functions waiting for each other are left, none of them has a path that
//! returns without assuming another of them returns: the least fixed point
//! is that none returns, and so they are decided.
//!
//! A computed jump ([`Destination::Indirect`]) is put aside until the
//! function's worklist is empty; then the [`Resolver`] is asked, once,
//! where it goes, from the function's blocks so far. A single target (a
//! pointer slot) replaces the block's destination, and the jump is
//! followed as if it had named it. Otherwise its table is asked for: the
//! targets it knows are queued like a jump's, and the function goes on; a
//! jump it does not know is unresolved, and only then may the function
//! return through it. So no function is decided before the resolver has
//! answered for its jumps.
//!
//! A computed call is asked about when it is reached, from its block
//! alone (compilers load a slot's address right before calling through
//! it): a single target replaces its destination before its fallthrough is
//! queued, so a call through the slot of an import that never returns
//! does not fall through. Asking from the whole function would hold every
//! call's fallthrough back until the function's worklist empties, and
//! have the resolver analyse the growing function again for each call in
//! a row (minutes on large binaries, as measured with L1).
//!
//! No native recursion: everything runs from explicit worklists, however
//! deep the input's call chains.
//!
//! Once everything is recovered, the functions that are parts of another
//! (cold parts) are joined into it (the `parts` module; the rule is the
//! crate's).
//!
//! The user's corrections are seeds too, and only change what they name:
//! code of no function ([`Seed::Flow`]) is recovered as a function would
//! be and left out of the functions; bytes that are no code
//! ([`Seed::NotCode`]) never decode; a function's end ([`Seed::End`])
//! makes control leaving its range a tail call; an address that starts no
//! function ([`Seed::NoFunction`]) is never made one.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use binbun_isa::{Architecture, Flow, FlowStep, Target};
use binbun_semantics::core::{Arena, Memory};

use crate::cfg::parts::{self, Graph};
use crate::cfg::{
    Block, BlockId, Callee, Callees, Conflict, Destination, EdgeKind, Exit, Frame, Function,
    FunctionId, Program, Resolver, Returns, Seed, SeedKind, SeedKinds, Table, Unwind, program,
    static_successors, unwind_successor,
};

/// How far recovery goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Whether call targets become functions and are recovered too (else
    /// calls are assumed to return, unless to an import known not to).
    pub follow_calls: bool,
    /// The most instructions in one block; longer runs end it with
    /// [`Exit::Limit`].
    pub max_block_instructions: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            follow_calls: true,
            max_block_instructions: 1 << 16,
        }
    }
}

/// Recovers the program reachable from `seeds` in `memory`, decoded as
/// `architecture` code in `mode`. `callees` tells which pointer slots are
/// imports and what is known about whether callees return; `resolver`, where
/// computed jumps go.
///
/// Seeds of kind [`SeedKind::Pointer`] are weaker: they are recovered
/// afterwards, and only those outside every block found from the others
/// become functions (a pointer into a function is a jump table entry or
/// similar, not a function's start). Addresses the recovered code computes
/// ([`binbun_isa::Instruction::computed_address`]) are weak in the same way,
/// recovered last, until they find no more code.
/// Neither makes a function where `resolver` says the bytes are data
/// ([`Resolver::data`]: a string a compiler put among the code), which
/// the program records ([`Program::data`]).
pub fn recover<A: Architecture, M: Memory, C: Callees + ?Sized>(
    architecture: &A,
    mode: A::Mode,
    memory: &M,
    seeds: &[Seed],
    callees: &C,
    resolver: &mut dyn Resolver,
    options: &Options,
) -> Program {
    let mut recovery = Recovery {
        architecture,
        mode,
        memory,
        callees,
        resolver,
        options,
        blocks: Arena::new(),
        by_start: BTreeMap::new(),
        functions: Vec::new(),
        by_entry: BTreeMap::new(),
        extents: BTreeMap::new(),
        frames: BTreeMap::new(),
        splits: BTreeMap::new(),
        runnable: Vec::new(),
        conflicts: Vec::new(),
        references: Vec::new(),
        tables: BTreeMap::new(),
        unwind: BTreeMap::new(),
        funclets: BTreeMap::new(),
        not_code: BTreeMap::new(),
        no_function: BTreeSet::new(),
        ends: BTreeMap::new(),
        boundaries: BTreeSet::new(),
        data: BTreeMap::new(),
    };
    recovery.constrain(seeds);
    // Last pushed runs first; seeds in reverse run in address order.
    for seed in seeds.iter().rev() {
        match *seed {
            Seed::Function(_, SeedKind::Pointer)
            | Seed::Extent { .. }
            | Seed::Split { .. }
            | Seed::Unwind { .. }
            | Seed::Funclet { .. }
            | Seed::NotCode { .. }
            | Seed::End { .. }
            | Seed::NoFunction(_) => {}
            Seed::Function(address, _)
            | Seed::Code {
                function: address, ..
            } if recovery.refused(address) => {}
            Seed::Function(address, kind) => {
                recovery.function(address, kind);
            }
            Seed::Code { function, address } => {
                let index = recovery.function(function, SeedKind::Unwind);
                let state = recovery.state(index);
                state.roots.push(address);
                state.pads.push(address);
                recovery.queue(index, address);
            }
            Seed::Flow(address) => recovery.flow(address),
        }
    }
    recovery.run();
    let mut pointers: Vec<u64> = seeds.iter().filter_map(Seed::pointer).collect();
    pointers.sort_unstable();
    pointers.dedup();
    let mut added = false;
    for &address in pointers.iter().rev() {
        if (recovery.by_entry.contains_key(&address)
            || (!recovery.contains(address) && !recovery.is_data(address)))
            && !recovery.refused(address)
        {
            recovery.function(address, SeedKind::Pointer);
            added = true;
        }
    }
    if added {
        recovery.run();
    }
    // Computed addresses, in address order, each recovered before the next
    // is tried (so one inside code another leads to is not taken for a
    // function), until they lead to no new code.
    loop {
        let mut references = core::mem::take(&mut recovery.references);
        references.sort_unstable();
        references.dedup();
        let mut added = false;
        for address in references {
            if recovery.refused(address) {
                continue;
            }
            if recovery.by_entry.contains_key(&address) {
                recovery.function(address, SeedKind::Reference);
            } else if !recovery.contains(address)
                && !recovery.is_data(address)
                && recovery.decode(address).is_some()
            {
                recovery.function(address, SeedKind::Reference);
                recovery.run();
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    recovery.finish()
}

/// A function during recovery.
struct State {
    entry: u64,
    seeds: SeedKinds,
    /// Whether it is code of no function ([`Seed::Flow`]): recovered as a
    /// function is, never one (no other function waits for it, and it is
    /// left out of the result).
    loose: bool,
    /// Code of the function its entry does not reach (landing pads).
    roots: Vec<u64>,
    /// Its landing pads (among `roots`).
    pads: Vec<u64>,
    /// Block addresses still to visit.
    worklist: Vec<u64>,
    /// Block addresses visited (dropped once all work is done).
    visited: HashSet<u64>,
    /// Callees this function waits for.
    pending: u32,
    /// Computed jumps and calls found and not asked about yet: their
    /// block's start and end.
    jumps: Vec<(u64, u64)>,
    /// The ends of the computed jumps and calls asked about.
    asked: HashSet<u64>,
    /// Whether some path found so far returns.
    returns: bool,
    /// Whether it returns, once decided (from the start, if the caller of
    /// recovery knows).
    decided: Option<bool>,
    /// Who waits for this function: the waiting function and the call's
    /// fallthrough (`None` for a tail call, which returns if this does).
    waiters: Vec<(usize, Option<u64>)>,
}

struct Recovery<'a, A: Architecture, M, C: ?Sized, R: ?Sized> {
    architecture: &'a A,
    mode: A::Mode,
    memory: &'a M,
    callees: &'a C,
    resolver: &'a mut R,
    options: &'a Options,
    blocks: Arena<BlockId, Block>,
    by_start: BTreeMap<u64, BlockId>,
    functions: Vec<State>,
    by_entry: BTreeMap<u64, usize>,
    /// The extents of functions known from seeds: start to end.
    extents: BTreeMap<u64, u64>,
    /// How the extents not entered by a call are entered, by start.
    frames: BTreeMap<u64, Frame>,
    /// Code split off functions ([`Seed::Split`]): start to end and the
    /// function it was split off, where known.
    splits: BTreeMap<u64, (u64, Option<u64>)>,
    /// Functions with work to do.
    runnable: Vec<usize>,
    conflicts: Vec<Conflict>,
    /// Addresses the decoded code computes, not yet tried as functions.
    references: Vec<u64>,
    /// The resolved targets of computed jumps, by the end of their block
    /// (which a split keeps).
    tables: BTreeMap<u64, Table>,
    /// The call-site ranges with a landing pad, by start.
    unwind: Unwind,
    /// The funclets ([`Seed::Funclet`]): their function, by address.
    funclets: BTreeMap<u64, u64>,
    /// The bytes no instruction may overlap ([`Seed::NotCode`]): start to
    /// end.
    not_code: BTreeMap<u64, u64>,
    /// The addresses no function starts at ([`Seed::NoFunction`]).
    no_function: BTreeSet<u64>,
    /// The user's ends of functions ([`Seed::End`]): start to end.
    ends: BTreeMap<u64, u64>,
    /// Those ends, where blocks end too.
    boundaries: BTreeSet<u64>,
    /// The data computed addresses and pointers point to
    /// ([`Resolver::data`]): start to end.
    data: BTreeMap<u64, u64>,
}

impl<A: Architecture, M: Memory, C: Callees + ?Sized, R: Resolver + ?Sized>
    Recovery<'_, A, M, C, R>
{
    /// Takes what `seeds` say of the code besides where it starts:
    /// functions' extents and frames, call sites' landing pads,
    /// funclets, and the user's corrections (bytes that are no code,
    /// functions' ends, addresses that start no function).
    fn constrain(&mut self, seeds: &[Seed]) {
        for seed in seeds {
            match *seed {
                Seed::Extent {
                    function,
                    end,
                    frame,
                } => {
                    let known = self.extents.entry(function).or_insert(end);
                    *known = (*known).max(end);
                    if frame != Frame::Call {
                        self.frames.insert(function, frame);
                    }
                }
                Seed::Unwind { start, end, pad } => {
                    self.unwind.insert(start, (end, pad));
                }
                Seed::Split { start, end, owner } => {
                    self.splits.insert(start, (end, owner));
                }
                Seed::Funclet { function, address } => {
                    self.funclets.insert(address, function);
                }
                Seed::NotCode { start, end } => {
                    let known = self.not_code.entry(start).or_insert(end);
                    *known = (*known).max(end);
                }
                Seed::End { function, end } => {
                    self.ends.insert(function, end);
                    self.boundaries.insert(end);
                }
                Seed::NoFunction(address) => {
                    self.no_function.insert(address);
                }
                Seed::Function(..) | Seed::Code { .. } | Seed::Flow(_) => {}
            }
        }
        // The user's end replaces what an unwind table says.
        for (&function, &end) in &self.ends {
            self.extents.insert(function, end);
        }
    }

    /// The function at `entry`, made one (and queued) if new.
    fn function(&mut self, entry: u64, kind: SeedKind) -> usize {
        if let Some(&index) = self.by_entry.get(&entry) {
            self.state(index).seeds.insert(kind);
            return index;
        }
        let index = self.functions.len();
        let mut seeds = SeedKinds::default();
        seeds.insert(kind);
        // What the caller knows wins over what the code shows.
        let decided = match self.callees.returns(Callee::Address(entry)) {
            Returns::Yes => Some(true),
            Returns::No => Some(false),
            Returns::Unknown => None,
        };
        self.functions.push(State {
            entry,
            seeds,
            loose: false,
            worklist: vec![entry],
            roots: Vec::new(),
            pads: Vec::new(),
            visited: HashSet::new(),
            pending: 0,
            jumps: Vec::new(),
            asked: HashSet::new(),
            returns: false,
            decided,
            waiters: Vec::new(),
        });
        self.by_entry.insert(entry, index);
        self.runnable.push(index);
        index
    }

    /// Code of no function at `address` ([`Seed::Flow`]), unless a
    /// function starts there: recovered as one, apart from the functions.
    fn flow(&mut self, address: u64) {
        if self.by_entry.contains_key(&address) {
            return;
        }
        let index = self.functions.len();
        self.functions.push(State {
            entry: address,
            seeds: SeedKinds::default(),
            loose: true,
            worklist: vec![address],
            roots: Vec::new(),
            pads: Vec::new(),
            visited: HashSet::new(),
            pending: 0,
            jumps: Vec::new(),
            asked: HashSet::new(),
            returns: false,
            decided: None,
            waiters: Vec::new(),
        });
        self.runnable.push(index);
    }

    /// Whether the user's corrections say no function starts at `address`
    /// ([`Seed::NoFunction`], or it is no code: [`Seed::NotCode`]).
    fn refused(&self, address: u64) -> bool {
        self.no_function.contains(&address)
            || self.not_code_overlaps(address, address.saturating_add(1))
    }

    /// Whether `start..end` overlaps bytes that are no code
    /// ([`Seed::NotCode`]).
    fn not_code_overlaps(&self, start: u64, end: u64) -> bool {
        !self.not_code.is_empty()
            && self
                .not_code
                .range(..end)
                .next_back()
                .is_some_and(|(_, &e)| e > start)
    }

    /// Whether `address` is outside the user's range of function `index`'s
    /// code ([`Seed::End`]).
    fn beyond(&self, index: usize, address: u64) -> bool {
        let Some(state) = self.functions.get(index) else {
            return false;
        };
        !state.loose
            && self
                .ends
                .get(&state.entry)
                .is_some_and(|&end| address < state.entry || address >= end)
    }

    /// Whether the bytes at `address` are data ([`Resolver::data`]); if
    /// so, they are recorded as such.
    fn is_data(&mut self, address: u64) -> bool {
        if self.data.contains_key(&address) {
            return true;
        }
        let Some(end) = self.resolver.data(address).filter(|&end| end > address) else {
            return false;
        };
        self.data.insert(address, end);
        true
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "indices come from `functions` itself"
    )]
    fn state(&mut self, index: usize) -> &mut State {
        &mut self.functions[index]
    }

    fn run(&mut self) {
        loop {
            while let Some(index) = self.runnable.pop() {
                self.advance(index);
            }
            // Only functions waiting for each other are left, none with a
            // path that returns: none returns.
            let stuck: Vec<usize> = (0..self.functions.len())
                .filter(|&index| {
                    self.functions
                        .get(index)
                        .is_some_and(|f| f.decided.is_none())
                })
                .collect();
            if stuck.is_empty() {
                break;
            }
            for index in stuck {
                self.decide(index, false);
            }
        }
    }

    /// Visits the queued blocks of function `index`, and those its computed
    /// jumps lead to; decides it once a path returns, or once it has nothing
    /// left to visit, ask about or wait for.
    fn advance(&mut self, index: usize) {
        let entry = self.state(index).entry;
        loop {
            while let Some(address) = self.state(index).worklist.pop() {
                if !self.state(index).visited.insert(address) {
                    continue;
                }
                // Into another function: this one returns if that one does.
                match self.by_entry.get(&address) {
                    Some(&other) if address != entry => self.depend(index, other, None),
                    // Out of the user's range: a tail call.
                    _ if self.beyond(index, address) => {
                        if self.refused(address) {
                            self.state(index).returns = true;
                        } else {
                            let callee = self.function(address, SeedKind::Call);
                            self.depend(index, callee, None);
                        }
                    }
                    _ => self.visit(index, address),
                }
            }
            self.resolve(index);
            if self.state(index).worklist.is_empty() {
                break;
            }
        }
        let state = self.state(index);
        let (returns, pending) = (state.returns, state.pending);
        if pending == 0 {
            state.visited = HashSet::new();
        }
        if state.decided.is_none() && (returns || pending == 0) {
            self.decide(index, returns);
        }
    }

    /// Decides whether function `index` returns, letting its waiters go on.
    fn decide(&mut self, index: usize, returns: bool) {
        self.state(index).decided = Some(returns);
        self.release(index, returns);
    }

    /// Lets everyone waiting for function `index` go on, as if it returns
    /// (`returns`) or not.
    fn release(&mut self, index: usize, returns: bool) {
        let waiters = std::mem::take(&mut self.state(index).waiters);
        for (waiter, fallthrough) in waiters {
            let state = self.state(waiter);
            state.pending -= 1;
            if returns {
                match fallthrough {
                    Some(address) => state.worklist.push(address),
                    None => state.returns = true,
                }
            }
            self.runnable.push(waiter);
        }
    }

    /// Function `index` continues at `address`.
    fn queue(&mut self, index: usize, address: u64) {
        self.state(index).worklist.push(address);
    }

    /// Asks the resolver about the computed jumps of function `index` not
    /// asked about yet: one it knows a single destination of goes there
    /// from now on (in every function that has its block); else the
    /// targets of its table are queued as the function's code (or tail
    /// calls), and a jump it does not know may return.
    fn resolve(&mut self, index: usize) {
        let jumps = std::mem::take(&mut self.state(index).jumps);
        let entry = self.state(index).entry;
        // The function's blocks change only once the targets are visited.
        let mut known: Option<Vec<Block>> = None;
        for (start, end) in jumps {
            if !self.state(index).asked.insert(end) {
                continue;
            }
            let Some((id, jump)) = self.jump_block(start, end) else {
                self.state(index).returns = true;
                continue;
            };
            // Resolved when another function with this block asked.
            if let Exit::Jump(destination) = jump.exit
                && destination != Destination::Indirect
            {
                self.jump(index, destination);
                continue;
            }
            let blocks = known.get_or_insert_with(|| self.blocks_so_far(index));
            if let Some(destination) = self.single(entry, blocks, jump) {
                if let Some(block) = self.blocks.get_mut(id) {
                    block.exit = Exit::Jump(destination);
                }
                self.jump(index, destination);
                continue;
            }
            let found = self.resolver.table(entry, blocks, jump);
            let Some(found) = found.filter(|table| !table.targets.is_empty()) else {
                self.state(index).returns = true;
                continue;
            };
            for &target in &found.targets {
                self.transfer(index, target);
            }
            // Asked from another function too (shared code): both answers.
            let table = self.tables.entry(end).or_default();
            table.targets.extend(found.targets);
            table.targets.sort_unstable();
            table.targets.dedup();
            table.inferred |= found.inferred;
        }
    }

    /// The destination the resolver knows the computed jump or call ending
    /// `jump` always has (of the function at `entry` made of `blocks`).
    fn single(&mut self, entry: u64, blocks: &[Block], jump: Block) -> Option<Destination> {
        let target = self.resolver.target(entry, blocks, jump)?;
        Some(self.destination(target)).filter(|&d| d != Destination::Indirect)
    }

    /// The block that ends at `end` in a jump, computed when it was decoded
    /// from `start` (it may have been split, and the jump resolved, since).
    fn jump_block(&self, start: u64, end: u64) -> Option<(BlockId, Block)> {
        self.by_start
            .range(start..end)
            .rev()
            .filter_map(|(_, &id)| Some((id, *self.blocks.get(id)?)))
            .find(|(_, b)| b.end == end && matches!(b.exit, Exit::Jump(_)))
    }

    /// The decoded blocks of function `index`, by address.
    fn blocks_so_far(&self, index: usize) -> Vec<Block> {
        let Some(state) = self.functions.get(index) else {
            return Vec::new();
        };
        self.body(state.entry, &state.roots)
            .into_iter()
            .filter_map(|id| self.blocks.get(id).copied())
            .collect()
    }

    /// The addresses control can go to next from `block`: those its exit
    /// states, the table resolved for its computed jump, and a call's
    /// landing pad.
    fn successors(&self, block: Block) -> impl Iterator<Item = (EdgeKind, u64)> + '_ {
        successors(&self.tables, &self.unwind, block)
    }

    /// Whether a decoded block contains `address`.
    fn contains(&self, address: u64) -> bool {
        self.by_start
            .range(..=address)
            .next_back()
            .and_then(|(_, &id)| self.blocks.get(id))
            .is_some_and(|b| address < b.end || b.start == address)
    }

    /// Function `index` reaches the block at `address`.
    fn visit(&mut self, index: usize, address: u64) {
        let id = self.block(address);
        let Some(&block) = self.blocks.get(id) else {
            return;
        };
        // The landing pad an exception unwinding through a call goes to is
        // the caller's code, whether or not the callee returns.
        if let Some((_, pad)) = unwind_successor(&self.unwind, block) {
            self.queue(index, pad);
        }
        match block.exit {
            Exit::Next => self.queue(index, block.end),
            // A switch or a jump through a pointer the code loads: asked
            // about once the worklist is empty.
            Exit::Jump(Destination::Indirect) => {
                self.state(index).jumps.push((block.start, block.end));
            }
            Exit::Jump(destination) => self.jump(index, destination),
            Exit::Branch(destination) => {
                self.jump(index, destination);
                self.queue(index, block.end);
            }
            // A call through a pointer the code loads: asked about now,
            // from its block alone, so that its fallthrough need not wait.
            Exit::Call {
                callee: Destination::Indirect,
                returns,
            } => {
                let callee = self
                    .single(block.start, &[block], block)
                    .unwrap_or(Destination::Indirect);
                if let Some(decoded) = self.blocks.get_mut(id) {
                    decoded.exit = Exit::Call { callee, returns };
                }
                self.call(index, callee, block.end);
            }
            Exit::Call { callee, .. } => self.call(index, callee, block.end),
            Exit::Return => self.state(index).returns = true,
            Exit::Stop | Exit::Invalid | Exit::Limit => {}
        }
    }

    /// Function `index` jumps to `destination`: within itself, or as a tail
    /// call to another function or an import.
    fn jump(&mut self, index: usize, destination: Destination) {
        match destination {
            Destination::Address(target) => self.transfer(index, target),
            Destination::Import(slot) => {
                if self.import_returns(slot) != Returns::No {
                    self.state(index).returns = true;
                }
            }
            // Unresolved (a tail call through a pointer, a computed jump the
            // resolver does not know): it may return.
            Destination::Pointer(_) | Destination::Indirect | Destination::Far => {
                self.state(index).returns = true;
            }
        }
    }

    /// Function `index` jumps to `target`. Within its extent (or with no
    /// extent known) the target is its code, unless it is another
    /// function's entry, which is decided when visited ([`Self::extent`]:
    /// a function entered in split-off code has that code's). Out of its
    /// extent, into another known extent, the target is that function's
    /// code, unless it is a stub's ([`Self::is_stub`]: one unwind table
    /// entry covers a whole PLT, whose stubs are no parts of one
    /// function); there and anywhere else, it is a tail call to a new
    /// function.
    fn transfer(&mut self, index: usize, target: u64) {
        let entry = self.state(index).entry;
        let outside = self
            .extent(entry)
            .is_some_and(|extent| !extent.contains(&target));
        if !outside || self.by_entry.contains_key(&target) || !self.options.follow_calls {
            return self.queue(index, target);
        }
        if self.refused(target) {
            return self.queue(index, target);
        }
        let owner = self
            .extents
            .range(..=target)
            .next_back()
            .filter(|&(_, &end)| target < end)
            .map(|(&start, _)| start)
            .filter(|_| !self.is_stub(target));
        match owner.and_then(|start| self.by_entry.get(&start).copied()) {
            // That function's code (a cold part's way back): the owner
            // recovers it, and this one returns if the owner does.
            Some(other) => {
                self.adopt(other, target);
                self.depend(index, other, None);
            }
            None if owner.is_some() => self.queue(index, target),
            None => {
                let callee = self.function(target, SeedKind::Call);
                self.depend(index, callee, None);
            }
        }
    }

    /// The extent of the function at `entry`: its unwind table entry's, or
    /// the code split off another function it is entered in
    /// ([`Seed::Split`]: its jumps back are its owner's code).
    fn extent(&self, entry: u64) -> Option<core::ops::Range<u64>> {
        self.extents.get(&entry).map(|&end| entry..end).or_else(|| {
            self.splits
                .range(..=entry)
                .next_back()
                .filter(|&(_, &(end, _))| entry < end)
                .map(|(&start, &(end, _))| start..end)
        })
    }

    /// Whether the code at `address` is a stub's: a jump through a
    /// pointer at a constant address (an import's slot, or the slot of a
    /// function the image defines itself and lets other modules define
    /// first), at once or after one instruction that goes on (`endbr64`).
    fn is_stub(&self, address: u64) -> bool {
        let mut at = address;
        for _ in 0..2 {
            let Some(step) = self.decode(at) else {
                return false;
            };
            match step.flow {
                Flow::Next => at = at.saturating_add(step.len as u64),
                Flow::Jump(target) => return matches!(target, Target::Pointer { .. }),
                Flow::Branch(_)
                | Flow::Call(_)
                | Flow::Return
                | Flow::Trap { .. }
                | Flow::SystemCall
                | Flow::ExceptionReturn
                | Flow::Halt => return false,
            }
        }
        false
    }

    /// Function `index` also has the code at `address`, which its own
    /// blocks may not reach.
    fn adopt(&mut self, index: usize, address: u64) {
        let state = self.state(index);
        if !state.roots.contains(&address) {
            state.roots.push(address);
            state.worklist.push(address);
            self.runnable.push(index);
        }
    }

    /// Function `index` calls `callee`, continuing at `fallthrough` if it
    /// returns. A call to no executable code (a weak symbol left
    /// undefined, linked to 0) makes no function.
    fn call(&mut self, index: usize, callee: Destination, fallthrough: u64) {
        match callee {
            Destination::Address(target)
                if self.options.follow_calls
                    && !self.refused(target)
                    && self.executable(target) =>
            {
                let callee = self.function(target, SeedKind::Call);
                if callee == index {
                    // Recursion: the outer call returns if anything does.
                    self.queue(index, fallthrough);
                } else {
                    self.depend(index, callee, Some(fallthrough));
                }
            }
            Destination::Import(slot) if self.import_returns(slot) == Returns::No => {}
            Destination::Address(target)
                if self.callees.returns(Callee::Address(target)) == Returns::No => {}
            Destination::Address(_)
            | Destination::Import(_)
            | Destination::Pointer(_)
            | Destination::Indirect
            | Destination::Far => self.queue(index, fallthrough),
        }
    }

    /// Function `index` continues at `fallthrough` (or returns, for `None`)
    /// if function `callee` returns.
    fn depend(&mut self, index: usize, callee: usize, fallthrough: Option<u64>) {
        match self.state(callee).decided {
            Some(true) => match fallthrough {
                Some(address) => self.queue(index, address),
                None => self.state(index).returns = true,
            },
            Some(false) => {}
            None => {
                self.state(callee).waiters.push((index, fallthrough));
                self.state(index).pending += 1;
            }
        }
    }

    fn import_returns(&self, slot: u64) -> Returns {
        self.callees.returns(Callee::Import(slot))
    }

    /// The block starting at `address`: an existing one, one split off the
    /// block `address` lies in, or a newly decoded one.
    fn block(&mut self, address: u64) -> BlockId {
        if let Some(&id) = self.by_start.get(&address) {
            return id;
        }
        let enclosing = self
            .by_start
            .range(..address)
            .next_back()
            .map(|(_, &id)| id)
            .filter(|&id| self.blocks.get(id).is_some_and(|b| address < b.end));
        if let Some(id) = enclosing {
            if let Some(split) = self.split(id, address) {
                return split;
            }
            // Inside another block's instruction: overlapping code.
            if let Some(block) = self.blocks.get(id) {
                self.conflicts.push(Conflict {
                    instruction: address,
                    block: block.start,
                });
            }
        }
        self.decode_block(address)
    }

    /// Splits block `id` at `address` if an instruction of it starts there:
    /// the first part falls into the second, which keeps the exit.
    fn split(&mut self, id: BlockId, address: u64) -> Option<BlockId> {
        let block = *self.blocks.get(id)?;
        let mut pc = block.start;
        let mut count = 0;
        while pc < address {
            pc = pc.checked_add(self.decode(pc)?.len as u64)?;
            count += 1;
        }
        if pc != address {
            return None;
        }
        let first = self.blocks.get_mut(id)?;
        first.end = address;
        first.instructions = count;
        first.exit = Exit::Next;
        let second = self.blocks.push(Block {
            start: address,
            end: block.end,
            instructions: block.instructions - count,
            exit: block.exit,
        });
        self.by_start.insert(address, second);
        Some(second)
    }

    /// Decodes a new block from `start`, up to a control transfer, a call,
    /// the start of another block, or bytes that are no code.
    fn decode_block(&mut self, start: u64) -> BlockId {
        let mut pc = start;
        let mut count = 0;
        // The first block start after `pc`: no block is added while this
        // one is decoded, so one lookup serves until it is passed.
        let mut next_start = self.next_start(start);
        // The user's end of a function after `pc` ([`Seed::End`]).
        let boundary = start
            .checked_add(1)
            .and_then(|after| self.boundaries.range(after..).next().copied());
        let exit = loop {
            if pc != start && (Some(pc) == next_start || Some(pc) == boundary) {
                break Exit::Next;
            }
            if count >= self.options.max_block_instructions {
                break Exit::Limit;
            }
            let Some(step) = self.decode(pc) else {
                break Exit::Invalid;
            };
            let Some(next) = pc.checked_add(step.len as u64) else {
                break Exit::Invalid;
            };
            // Another block starting inside this instruction: the bytes
            // are decoded two ways.
            if let Some(other) = next_start
                && other < next
            {
                self.conflicts.push(Conflict {
                    instruction: pc,
                    block: other,
                });
                next_start = self.next_start(next - 1);
            }
            let flow = step.flow;
            if let Some(address) = step.computed_address {
                self.references.push(address);
            }
            count += 1;
            pc = next;
            match flow {
                Flow::Next | Flow::SystemCall | Flow::Trap { conditional: true } => {}
                Flow::Jump(target) => break Exit::Jump(self.destination(target)),
                Flow::Branch(target) => break Exit::Branch(self.destination(target)),
                Flow::Call(target) => {
                    break Exit::Call {
                        callee: self.destination(target),
                        returns: Returns::Unknown,
                    };
                }
                Flow::Return => break Exit::Return,
                Flow::Trap { conditional: false } | Flow::Halt | Flow::ExceptionReturn => {
                    break Exit::Stop;
                }
            }
        };
        let id = self.blocks.push(Block {
            start,
            end: pc,
            instructions: count,
            exit,
        });
        self.by_start.insert(start, id);
        id
    }

    /// The first block start after `address`.
    fn next_start(&self, address: u64) -> Option<u64> {
        let after = address.checked_add(1)?;
        self.by_start.range(after..).next().map(|(&start, _)| start)
    }

    /// Whether `address` is mapped and executable.
    fn executable(&self, address: u64) -> bool {
        self.memory
            .region(address)
            .is_some_and(|r| r.permissions.execute)
    }

    /// What recovery needs of the instruction at `address`, if it is
    /// executable code that decodes.
    fn decode(&self, address: u64) -> Option<FlowStep> {
        if !self.executable(address) {
            return None;
        }
        let mut buffer = [0u8; 32];
        let wanted = buffer.get_mut(..A::MAX_LENGTH.min(32))?;
        let read = self.memory.read(address, wanted).ok()?;
        let step = self
            .architecture
            .decode_flow(buffer.get(..read)?, self.mode, address)
            .ok()?;
        let end = address.checked_add(step.len as u64)?;
        (!self.not_code_overlaps(address, end)).then_some(step)
    }

    fn destination(&self, target: Target) -> Destination {
        match target {
            Target::Address(address) => Destination::Address(address),
            Target::Pointer { address, .. } if self.callees.is_import(address) => {
                Destination::Import(address)
            }
            Target::Pointer { address, size } => self
                .callees
                .slot(address, size)
                .map_or(Destination::Pointer(address), Destination::Address),
            Target::Indirect => Destination::Indirect,
            Target::Far { .. } => Destination::Far,
        }
    }

    /// The result: call sites annotated with whether they return, and each
    /// function's blocks.
    fn finish(mut self) -> Program {
        let decided: BTreeMap<u64, bool> = self
            .functions
            .iter()
            .filter(|f| !f.loose)
            .map(|f| (f.entry, f.decided.unwrap_or(f.returns)))
            .collect();
        let follow_calls = self.options.follow_calls;
        let callees = self.callees;
        for (_, block) in self.blocks.iter_mut() {
            if let Exit::Call { callee, returns } = &mut block.exit {
                *returns = match *callee {
                    Destination::Address(target) if follow_calls => match decided.get(&target) {
                        Some(true) => Returns::Yes,
                        Some(false) => Returns::No,
                        None => Returns::Unknown,
                    },
                    Destination::Import(slot) => callees.returns(Callee::Import(slot)),
                    Destination::Address(target) => callees.returns(Callee::Address(target)),
                    Destination::Pointer(_) | Destination::Indirect | Destination::Far => {
                        Returns::Unknown
                    }
                };
            }
        }
        let mut states: Vec<&State> = self.functions.iter().filter(|f| !f.loose).collect();
        states.sort_unstable_by_key(|f| f.entry);
        let mut found: Vec<Function> = states
            .into_iter()
            .map(|state| {
                let mut landing_pads = state.pads.clone();
                landing_pads.sort_unstable();
                landing_pads.dedup();
                Function {
                    entry: state.entry,
                    seeds: state.seeds,
                    blocks: self.body(state.entry, &state.roots),
                    returns: decided.get(&state.entry).copied().unwrap_or(false),
                    parts: Vec::new(),
                    landing_pads,
                    part_of: None,
                    funclets: Vec::new(),
                }
            })
            .collect();
        // Parts are joined only where calls are followed: with callees
        // not recovered, nothing tells who else enters a part.
        if follow_calls {
            parts::join(
                &mut found,
                &Graph {
                    blocks: &self.blocks,
                    by_start: &self.by_start,
                    tables: &self.tables,
                    extents: &self.extents,
                    frames: &self.frames,
                    splits: &self.splits,
                    unwind: &self.unwind,
                    ends: &self.ends,
                },
            );
            parts::funclets(&mut found, &self.funclets);
        }
        let mut functions: Arena<FunctionId, Function> = Arena::with_capacity(found.len());
        for function in found {
            functions.push(function);
        }
        let tables = self
            .blocks
            .iter()
            .filter(|(_, block)| block.exit == Exit::Jump(Destination::Indirect))
            .filter_map(|(id, block)| Some((id, self.tables.get(&block.end)?.clone())))
            .collect();
        // Data no function starts at and no block overlaps (a later call
        // there made it code), the first where two overlap.
        let mut data = BTreeMap::new();
        let mut covered = 0;
        for (&start, &end) in &self.data {
            let overlapped = self
                .by_start
                .range(..end)
                .next_back()
                .and_then(|(_, &id)| self.blocks.get(id))
                .is_some_and(|block| block.end > start);
            if start >= covered && !overlapped && !self.by_entry.contains_key(&start) {
                data.insert(start, end);
                covered = end;
            }
        }
        program(
            self.blocks,
            self.by_start,
            functions,
            self.conflicts,
            tables,
            self.unwind,
            data,
        )
    }

    /// The blocks reachable from `entry` (and `roots`) without entering
    /// another function or jumping out of its extent.
    fn body(&self, entry: u64, roots: &[u64]) -> Vec<BlockId> {
        let extent = self.extent(entry);
        let mut seen = HashSet::new();
        let mut stack = vec![entry];
        stack.extend_from_slice(roots);
        let mut blocks = Vec::new();
        while let Some(address) = stack.pop() {
            if !seen.insert(address) {
                continue;
            }
            let Some(&id) = self.by_start.get(&address) else {
                continue;
            };
            let Some(&block) = self.blocks.get(id) else {
                continue;
            };
            blocks.push((address, id));
            for (kind, target) in self.successors(block) {
                let jump = matches!(kind, EdgeKind::Jump | EdgeKind::Taken | EdgeKind::Table);
                let leaves = jump && extent.as_ref().is_some_and(|e| !e.contains(&target));
                if !leaves && (target == entry || !self.by_entry.contains_key(&target)) {
                    stack.push(target);
                }
            }
        }
        blocks.sort_unstable_by_key(|&(address, _)| address);
        blocks.into_iter().map(|(_, id)| id).collect()
    }
}

/// The addresses control can go to next from `block`: those its exit
/// states, and the table in `tables` (by the end of their block) resolved
/// for its computed jump, and a call's landing pad in `unwind`.
pub(crate) fn successors<'a>(
    tables: &'a BTreeMap<u64, Table>,
    unwind: &'a Unwind,
    block: Block,
) -> impl Iterator<Item = (EdgeKind, u64)> + 'a {
    let table = if block.exit == Exit::Jump(Destination::Indirect) {
        tables.get(&block.end)
    } else {
        None
    };
    static_successors(block)
        .chain(
            table
                .into_iter()
                .flat_map(|table| &table.targets)
                .map(|&target| (EdgeKind::Table, target)),
        )
        .chain(unwind_successor(unwind, block))
}
