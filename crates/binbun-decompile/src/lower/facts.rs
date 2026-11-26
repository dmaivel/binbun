//! The state of one lowering and the facts it starts from: the L1
//! analyses ([`Facts`]: constants, the stack, dominators), each value's
//! definition, the copies seen through ([`Lowering::canon`]) and what each
//! value is ([`Kind`]).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

use binbun_ast::types::{TypeId, Types};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_ssa::constant::Constants;
use binbun_ssa::graph::{Dominators, predecessors};
use binbun_ssa::ir::{BlockId, Definition, Function, InstId, Op, Terminator, Type, Unknown, Value};
use binbun_ssa::stack::Stack;

use super::atomic::Atomics;
use super::calls::{Callee, Formatting, Returns};
use super::coalesce::Classes;
use super::frame::Frame;
use super::needed::Needed;
use super::variadic::{Plan, Unprinted};
use super::{
    Context, Counts, DebugCounts, Facts, Formats, Frames, Interface, LowerError, Variadic,
};
use crate::mapping::Source;
use crate::prototype::{DebugStated, SystemCall, UserStated};
use crate::typing::{Outcome, Rounded, Solved};

/// Where a value is defined: a block and a position in it (0: the block's
/// parameters; `k + 1`: its instruction `k`; then the terminator, then the
/// copies on its outgoing edges).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Def {
    pub(super) block: u32,
    pub(super) pos: u32,
}

impl Def {
    /// No definition lowered (a memory value, or one of a block the entry
    /// does not reach).
    pub(super) const NONE: Self = Self {
        block: u32::MAX,
        pos: 0,
    };
}

/// A call: an `Op::Call` instruction or a block leaving the function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Site {
    /// A call that returns here.
    Call(InstId),
    /// A tail call: the block's `Terminator::Leave`.
    Tail(BlockId),
}

/// The strongly connected components of the graph whose node `i` has the
/// edges `edges[i]` (Tarjan's algorithm, walked without recursion), each
/// after every component it reaches.
fn components(edges: &[Vec<usize>]) -> Vec<Vec<usize>> {
    const UNSEEN: usize = usize::MAX;
    let count = edges.len();
    let mut number = vec![UNSEEN; count];
    let mut low = vec![0; count];
    let mut on_stack = vec![false; count];
    let mut stack = Vec::new();
    let mut found = Vec::new();
    let mut next = 0;
    // The walk: each node being visited, with how many of its edges are.
    let mut walk: Vec<(usize, usize)> = Vec::new();
    let mut enter = |node: usize,
                     number: &mut Vec<usize>,
                     low: &mut Vec<usize>,
                     on_stack: &mut Vec<bool>,
                     stack: &mut Vec<usize>| {
        if let (Some(n), Some(l), Some(o)) = (
            number.get_mut(node),
            low.get_mut(node),
            on_stack.get_mut(node),
        ) {
            (*n, *l, *o) = (next, next, true);
        }
        next += 1;
        stack.push(node);
    };
    for root in 0..count {
        if number.get(root) != Some(&UNSEEN) {
            continue;
        }
        enter(root, &mut number, &mut low, &mut on_stack, &mut stack);
        walk.push((root, 0));
        while let Some(&(node, taken)) = walk.last() {
            if let Some(&target) = edges.get(node).and_then(|targets| targets.get(taken)) {
                if let Some(top) = walk.last_mut() {
                    top.1 += 1;
                }
                match number.get(target).copied() {
                    Some(UNSEEN) => {
                        enter(target, &mut number, &mut low, &mut on_stack, &mut stack);
                        walk.push((target, 0));
                    }
                    Some(seen) if on_stack.get(target) == Some(&true) => {
                        if let Some(l) = low.get_mut(node) {
                            *l = (*l).min(seen);
                        }
                    }
                    Some(_) | None => {}
                }
                continue;
            }
            walk.pop();
            let node_low = low.get(node).copied().unwrap_or(0);
            if let Some(&(parent, _)) = walk.last()
                && let Some(l) = low.get_mut(parent)
            {
                *l = (*l).min(node_low);
            }
            if number.get(node) == Some(&node_low) {
                let mut component = Vec::new();
                while let Some(member) = stack.pop() {
                    if let Some(o) = on_stack.get_mut(member) {
                        *o = false;
                    }
                    component.push(member);
                    if member == node {
                        break;
                    }
                }
                found.push(component);
            }
        }
    }
    found
}

/// What [`Lowering::new`] finds of a function before reading its
/// context: each value's definition and what it is a copy of.
#[derive(Clone, Debug)]
pub(super) struct Start {
    defs: Vec<Def>,
    canon: Vec<Value>,
}

/// What a value is, as lowering sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// No bit vector lowered (memory, or code the entry does not reach).
    None,
    /// A constant.
    Const(Bits),
    /// An unknown value of this width, and where it comes from.
    Undefined(u16, Unknown),
    /// The address at this offset from the entry stack pointer.
    Address(i64),
    /// A register's entry value.
    Entry(RegisterId),
    /// A block parameter.
    Phi,
    /// A pure operation's result.
    Pure(InstId),
    /// A (not atomic) load's result.
    Load(InstId),
    /// A result an instruction writes to a variable: an intrinsic's
    /// output, a system call's changed register, an atomic load, a call's
    /// return value where it is a whole register.
    Result(InstId),
    /// A register after a call whose return value has only `width` of its
    /// bits, from bit `offset` (its other bits undefined); its variable
    /// holds those bits.
    CallView {
        /// The call.
        inst: InstId,
        /// Where the returned bits start in the register.
        offset: u16,
        /// How many bits of the register the return value gives.
        width: u16,
    },
}

/// The state of one lowering.
pub(super) struct Lowering<'a, 'c> {
    pub(super) l1: &'a Function,
    pub(super) cx: &'a Context<'c>,
    pub(super) constants: &'a Constants,
    pub(super) stack: &'a Stack,
    pub(super) dominators: &'a Dominators,
    pub(super) preds: Vec<Vec<(BlockId, usize)>>,
    /// Each value's definition.
    pub(super) defs: Vec<Def>,
    /// Each value's copy seen through: itself, or an earlier value it
    /// equals.
    pub(super) canon: Vec<Value>,
    /// What each canonical value is.
    pub(super) kinds: Vec<Kind>,
    /// The L2 function's types.
    pub(super) types: Types,
    /// The width of addresses.
    pub(super) pointer: u16,
    /// Each call's callee.
    pub(super) callees: BTreeMap<Site, Callee>,
    /// Each system call whose number is a constant a declaration knows.
    pub(super) system_calls: BTreeMap<InstId, SystemCall>,
    /// Whether a `futex` call's operation has a command the code does not
    /// settle ([`crate::lower::Found::unsettled_futex`]).
    pub(super) unsettled_futex: bool,
    /// The function's own signature.
    pub(super) returns: Returns,
    /// `void *`, where the function is an allocator wrapper
    /// ([`Self::allocation`]) no declaration types the return value of:
    /// what it returns is any object's.
    pub(super) allocator: Option<TypeId>,
    /// The frame.
    pub(super) frame: Frame,
    /// What is needed, and folded.
    pub(super) needed: Needed,
    /// The variables of values.
    pub(super) classes: Classes,
    /// The block parameters and arguments (parameter, argument) where the
    /// argument is proved zero on every edge it arrives by
    /// ([`Self::null_arguments`]): the edge's copy is of 0, and the two
    /// share no variable.
    pub(super) nulls: BTreeSet<(Value, Value)>,
    /// Copies emitted on edges.
    pub(super) copies: usize,
    /// The solver's constraints, solved, between folding and rounding.
    pub(super) solved: Option<Solved>,
    /// The solver's rounded types, which emit applies.
    pub(super) typed: Option<Rounded>,
    /// What the solver did.
    pub(super) typing: Outcome,
    /// Whether it is a variadic definition ([`Self::find_variadic`]).
    pub(super) variadic: Variadic,
    /// How it is printed as C's variadic function, if it is.
    pub(super) va: Option<Plan>,
    /// What a recognised AAPCS64 `va_start` it does not print as C's
    /// tells of its format ([`Self::own_format`]).
    pub(super) unprinted: Option<Unprinted>,
    /// The atomic groups lowered as one update each
    /// ([`Self::find_atomics`]).
    pub(super) atomics: Atomics,
    /// What debug information states about its body
    /// ([`Prototypes::debug`](crate::prototype::Prototypes::debug)).
    pub(super) debug: Option<DebugStated>,
    /// What became of it (emit counts).
    pub(super) debug_counts: DebugCounts,
    /// The types the user states for its variables
    /// ([`Prototypes::user`](crate::prototype::Prototypes::user)).
    pub(super) user: UserStated,
}

/// The most passes seeing through copies takes.
const CANON_PASSES: usize = 256;

impl<'a, 'c> Lowering<'a, 'c> {
    /// The facts about `l1`, with its analyses `facts`, under `cx`.
    pub(super) fn new(
        l1: &'a Function,
        facts: &'a Facts,
        cx: &'a Context<'c>,
    ) -> Result<Self, LowerError> {
        facts
            .well_formed(l1, cx.declarations)
            .map_err(LowerError::Malformed)?;
        let entry = l1
            .blocks
            .first()
            .ok_or_else(|| LowerError::Malformed("no entry block".into()))?;
        if !matches!(entry.terminator, Terminator::Jump(_)) {
            return Err(LowerError::Malformed(
                "the entry block does not jump".into(),
            ));
        }
        if let Some(open) = l1
            .blocks
            .iter()
            .position(|block| matches!(block.terminator, Terminator::Open))
        {
            return Err(LowerError::Malformed(format!("block {open} is open")));
        }
        let pointer = cx
            .declarations
            .info(cx.stack_pointer)
            .map(|info| info.width)
            .ok_or_else(|| LowerError::Malformed("no stack pointer".into()))?;
        let preds = predecessors(l1);
        let mut lowering = Self {
            l1,
            cx,
            constants: &facts.constants,
            stack: &facts.stack,
            dominators: &facts.dominators,
            preds,
            defs: vec![Def::NONE; l1.values.len()],
            canon: (0..l1.values.len())
                .map(|index| Value(u32::try_from(index).unwrap_or(u32::MAX)))
                .collect(),
            kinds: vec![Kind::None; l1.values.len()],
            types: Types::new(pointer),
            pointer,
            callees: BTreeMap::new(),
            system_calls: BTreeMap::new(),
            unsettled_futex: false,
            allocator: None,
            returns: Returns::default(),
            frame: Frame::default(),
            needed: Needed::default(),
            classes: Classes::default(),
            nulls: BTreeSet::new(),
            copies: 0,
            solved: None,
            typed: None,
            typing: Outcome::default(),
            variadic: Variadic::default(),
            va: None,
            unprinted: None,
            atomics: Atomics::default(),
            debug: None,
            debug_counts: DebugCounts::default(),
            user: UserStated::default(),
        };
        // Each value's definition and what it is a copy of read only the
        // function and its analyses: found once, kept with the analyses,
        // and taken up again by each later lowering of it. What each
        // value is reads the context (the registers dropped from its
        // parameters), so it is found each time.
        if let Some(start) = facts.start.get() {
            lowering.defs.clone_from(&start.defs);
            lowering.canon.clone_from(&start.canon);
        } else {
            lowering.definitions();
            lowering.see_through();
            let _ = facts.start.set(Start {
                defs: lowering.defs.clone(),
                canon: lowering.canon.clone(),
            });
        }
        lowering.classify();
        Ok(lowering)
    }

    /// The passes that find the signature: calls and what their results
    /// are (so a callee's narrow result returned on is narrow), returns,
    /// the frame, what is needed, the parameters.
    pub(super) fn signature(&mut self) {
        self.debug = self.cx.prototypes.debug(self.l1.entry, &mut self.types);
        self.user = self.cx.prototypes.user(self.l1.entry, &mut self.types);
        self.find_atomics();
        self.resolve_calls();
        self.resolve_system_calls();
        self.call_results();
        // Again, now that the registers calls change are known unknown: a
        // callee known only by its address takes no argument register
        // holding only another call's leftovers.
        self.resolve_calls();
        self.call_results();
        self.find_returns();
        self.build_frame(&[]);
        self.find_variadic();
        self.find_needed();
        if self.find_vector_returns() {
            self.find_needed();
        }
        self.find_parameters();
        self.find_allocator();
    }

    /// [`Self::allocator`].
    fn find_allocator(&mut self) {
        let parameters: Vec<Source> = self
            .needed
            .parameters
            .iter()
            .map(|parameter| parameter.source)
            .collect();
        let pointer = self.types.pointer_width();
        let returns_pointer =
            matches!(self.returns.pieces.as_slice(), [piece] if piece.width == pointer);
        self.allocator =
            (returns_pointer && !self.returns.stated && self.allocation(&parameters).is_some())
                .then(|| self.types.intern(binbun_ast::types::Type::Pointer(None)));
    }

    /// The passes before the L2 function is built.
    pub(super) fn prepare(&mut self) {
        self.signature();
        self.fold();
        self.solve_types();
        self.coalesce();
        self.round_types();
    }

    /// The function's interface: its parameters and return value; `None`
    /// if it leaves for code it does not know.
    pub(super) fn interface(&self) -> Option<Interface> {
        let unknown = self.blocks().any(|(id, block)| match &block.terminator {
            Terminator::IndirectJump { targets, .. } => targets.is_empty(),
            Terminator::Leave { .. } => self
                .callees
                .get(&Site::Tail(id))
                .is_none_or(|callee| callee.foreign),
            Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::Invoke { .. }
            | Terminator::Return { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => false,
        });
        if unknown {
            return None;
        }
        let called = self.called_variadic();
        let parameters: Vec<Source> = self
            .needed
            .parameters
            .iter()
            .map(|parameter| parameter.source)
            .filter(|source| called.as_ref().is_none_or(|named| named.contains(source)))
            .collect();
        Some(Interface {
            alloc_size: self.allocation(&parameters),
            parameters,
            returns: self.returns.pieces.clone(),
            variadic: self.va.is_some() || called.is_some(),
            format: self.own_format(),
        })
    }

    /// The named parameters of a variadic definition recognised but not
    /// printed as C's ([`Self::find_variadic`]: its body reads the
    /// `va_list` as C's `va_arg` hides, which compilers expand in place),
    /// where no declared prototype says it is not variadic. Its prologue's
    /// saves and its `va_start` prove what its callers pass whatever its
    /// body's printing: the named arguments, then the registers a call
    /// sets, as to one printed as C's. The body, with no `va_start` to
    /// print, still names every register the saves read as a parameter;
    /// those are no part of how it is called.
    fn called_variadic(&self) -> Option<Vec<Source>> {
        let named = self.variadic.recognised?;
        if self.va.is_some() || self.variadic.declared == Some(false) || named.stack != 0 {
            return None;
        }
        let convention = self.cx.convention;
        let registers: Vec<RegisterId> = convention
            .arguments
            .iter()
            .take(usize::from(named.integer))
            .chain(
                convention
                    .float_arguments
                    .iter()
                    .take(usize::from(named.vector)),
            )
            .copied()
            .collect();
        Some(
            self.needed
                .parameters
                .iter()
                .map(|parameter| parameter.source)
                .filter(|source| {
                    matches!(source, Source::Register(piece) if registers.contains(&piece.register))
                })
                .collect(),
        )
    }

    /// The constant addresses the calls and tail calls go to (after
    /// [`Self::resolve_calls`]): those whose interfaces lowering looks up.
    pub(super) fn callee_addresses(&self) -> BTreeSet<u64> {
        self.callees
            .values()
            .filter_map(|callee| callee.target)
            .collect()
    }

    /// Counts for corpus metrics.
    pub(super) fn counts(&self) -> Counts {
        let mut formats = Formats::default();
        for callee in self.callees.values() {
            let slot = match callee.format {
                None => continue,
                Some(Formatting::Parsed) => &mut formats.parsed,
                Some(Formatting::NotConstant) => &mut formats.not_constant,
                Some(Formatting::Unplaced) => &mut formats.unplaced,
                Some(Formatting::Refused(refusal)) => {
                    let Some(slot) = formats.refused.get_mut(refusal.index()) else {
                        continue;
                    };
                    slot
                }
            };
            *slot += 1;
        }
        let list = self.va.as_ref().and_then(|va| va.list);
        let mut frames = Frames::default();
        for (&slot, &region) in &self.frame.region_of {
            let promoted = self
                .frame
                .regions
                .get(region)
                .is_some_and(|r| r.promoted.is_some() && list != Some(r.offset));
            let inside = self.frame.slots.get(slot).is_some_and(|s| {
                self.frame
                    .regions
                    .get(region)
                    .is_some_and(|r| s.offset >= r.offset && s.end <= r.end())
            });
            if promoted {
                frames.promoted_slots += 1;
            } else if inside && self.frame.is_struct(region, list) {
                frames.struct_slots += 1;
            }
        }
        frames.promoted = self
            .frame
            .regions
            .iter()
            .filter(|r| r.promoted.is_some() && list != Some(r.offset))
            .count();
        Counts {
            values: self.classes.values(),
            variables: self.classes.count(),
            copies: self.copies,
            over_budget: self.classes.over_budget,
            formats,
            typing: self.typing,
            variadic: self.variadic,
            frames,
            debug: self.debug_counts,
        }
    }

    /// Whether block `id` is lowered (the entry reaches it, and no
    /// `va_start` absorbed it).
    pub(super) fn reached(&self, id: BlockId) -> bool {
        self.dominators.reachable(id) && self.va.as_ref().is_none_or(|va| !va.blocks.contains(&id))
    }

    /// The blocks lowered, in order.
    pub(super) fn blocks(&self) -> impl Iterator<Item = (BlockId, &'a binbun_ssa::ir::Block)> {
        let l1 = self.l1;
        l1.blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (BlockId(u32::try_from(index).unwrap_or(u32::MAX)), block))
            .filter(|&(id, _)| self.reached(id))
    }

    /// The width of value `v` (0 for memory).
    pub(super) fn width(&self, v: Value) -> u16 {
        match self.l1.ty(v) {
            Some(Type::Bits(width)) => width,
            Some(Type::Memory) | None => 0,
        }
    }

    /// Register `r`'s width.
    pub(super) fn register_width(&self, r: RegisterId) -> u16 {
        self.cx.declarations.info(r).map_or(0, |info| info.width)
    }

    /// `v` with copies seen through.
    pub(super) fn canonical(&self, v: Value) -> Value {
        self.canon.get(v.0 as usize).copied().unwrap_or(v)
    }

    /// What `v` (seen through copies) is.
    pub(super) fn kind(&self, v: Value) -> Kind {
        let v = self.canonical(v);
        self.kinds.get(v.0 as usize).copied().unwrap_or(Kind::None)
    }

    /// Where `v` is defined.
    pub(super) fn def(&self, v: Value) -> Def {
        self.defs.get(v.0 as usize).copied().unwrap_or(Def::NONE)
    }

    /// The instruction defining `v`, if one.
    pub(super) fn defining(&self, v: Value) -> Option<(InstId, &'a Op)> {
        let l1 = self.l1;
        match l1.value(v)?.definition {
            Definition::Result { inst, .. } => l1.inst(inst).map(|i| (inst, &i.op)),
            Definition::Parameter { .. } => None,
        }
    }

    /// The arguments block `block`'s parameter `index` gets, from each
    /// lowered predecessor: (predecessor, argument).
    pub(super) fn incoming(&self, block: BlockId, index: usize) -> Vec<(BlockId, Value)> {
        self.incoming_edges(block, index)
            .into_iter()
            .map(|(pred, _, argument)| (pred, argument))
            .collect()
    }

    /// [`Self::incoming`], with each edge's position among its
    /// predecessor's targets (a branch's: 0 `then`, 1 `otherwise`).
    pub(super) fn incoming_edges(
        &self,
        block: BlockId,
        index: usize,
    ) -> Vec<(BlockId, usize, Value)> {
        let l1 = self.l1;
        self.preds
            .get(block.0 as usize)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter(|&&(pred, _)| self.reached(pred))
            .filter_map(|&(pred, edge)| {
                let target = l1.block(pred)?.terminator.targets().nth(edge)?;
                Some((pred, edge, *target.arguments.get(index)?))
            })
            .collect()
    }

    /// Each value's definition, in the blocks lowered.
    fn definitions(&mut self) {
        let blocks: Vec<_> = self.blocks().collect();
        for (id, block) in blocks {
            for &parameter in &block.parameters {
                if let Some(def) = self.defs.get_mut(parameter.0 as usize) {
                    *def = Def {
                        block: id.0,
                        pos: 0,
                    };
                }
            }
            for (k, &inst) in block.insts.iter().enumerate() {
                let pos = u32::try_from(k + 1).unwrap_or(u32::MAX);
                for &result in self.l1.inst(inst).map_or(&[][..], |i| i.results.as_slice()) {
                    if let Some(def) = self.defs.get_mut(result.0 as usize) {
                        *def = Def { block: id.0, pos };
                    }
                }
            }
        }
    }

    /// Follows `canon` to its end, compressing the path.
    fn find(&mut self, v: Value) -> Value {
        let mut root = v;
        for _ in 0..self.canon.len() {
            let next = self.canonical(root);
            if next == root {
                break;
            }
            root = next;
        }
        let mut at = v;
        while at != root {
            let next = self.canonical(at);
            if let Some(slot) = self.canon.get_mut(at.0 as usize) {
                *slot = root;
            }
            at = next;
        }
        root
    }

    /// The one value (seen through copies) block `id`'s parameter `index`,
    /// `parameter`, gets from every lowered predecessor but itself, if
    /// they all pass the same; every argument is seen through, as
    /// [`Self::find`] shortens the paths it walks. `incoming`'s arguments,
    /// read in place: this runs for every parameter on every pass of
    /// [`Self::see_through`].
    fn only_argument(&mut self, id: BlockId, index: usize, parameter: Value) -> Option<Value> {
        let l1 = self.l1;
        let mut only = None;
        let mut trivial = true;
        let preds = self.preds.get(id.0 as usize).map_or(0, Vec::len);
        for k in 0..preds {
            let Some(&(pred, edge)) = self.preds.get(id.0 as usize).and_then(|list| list.get(k))
            else {
                continue;
            };
            if !self.reached(pred) {
                continue;
            }
            let Some(&argument) = l1
                .block(pred)
                .and_then(|block| block.terminator.targets().nth(edge))
                .and_then(|target| target.arguments.get(index))
            else {
                continue;
            };
            let argument = self.find(argument);
            if argument == parameter {
                continue;
            }
            match only {
                None => only = Some(argument),
                Some(other) if other == argument => {}
                Some(_) => trivial = false,
            }
        }
        only.filter(|_| trivial)
    }

    /// Sees through copies: block parameters whose arguments are all one
    /// value (or the parameter itself); extractions that are a whole
    /// value, the low or high part of a concatenation, or the low part of
    /// an extension; `a & a` and `a | a`; and a pure operation that repeats
    /// an earlier one of its block on the same operands.
    fn see_through(&mut self) {
        let l1 = self.l1;
        let blocks: Vec<_> = self.blocks().collect();
        for _ in 0..CANON_PASSES {
            let mut changed = false;
            for &(id, block) in &blocks {
                if id.0 == 0 {
                    continue;
                }
                for (index, &parameter) in block.parameters.iter().enumerate() {
                    if self.find(parameter) != parameter {
                        continue;
                    }
                    if let Some(value) = self.only_argument(id, index, parameter)
                        && let Some(slot) = self.canon.get_mut(parameter.0 as usize)
                    {
                        *slot = value;
                        changed = true;
                    }
                }
                let mut seen: BTreeMap<u64, Vec<(Op, Value)>> = BTreeMap::new();
                for &inst in &block.insts {
                    let Some(i) = l1.inst(inst) else {
                        continue;
                    };
                    let Some(&result) = i.results.first() else {
                        continue;
                    };
                    if !pure(&i.op) || self.find(result) != result {
                        continue;
                    }
                    let mut op = i.op.clone();
                    op.map_values(&mut |v| self.find(v));
                    let same = match op {
                        Op::Extract {
                            value,
                            offset,
                            width,
                        } => self.part_of(value, offset, width),
                        Op::Binary(Binary::And | Binary::Or, a, b) if a == b => Some(a),
                        Op::Const(_)
                        | Op::Undefined(..)
                        | Op::Unary(..)
                        | Op::Binary(..)
                        | Op::Flag(..)
                        | Op::Concat { .. }
                        | Op::Extend { .. }
                        | Op::Select { .. }
                        | Op::Lanes { .. }
                        | Op::Float { .. }
                        | Op::Load { .. }
                        | Op::Store { .. }
                        | Op::Intrinsic { .. }
                        | Op::Call { .. }
                        | Op::SystemCall { .. }
                        | Op::Landing { .. } => None,
                    };
                    let same = same.or_else(|| {
                        let key = fingerprint(&op);
                        let bucket = seen.entry(key).or_default();
                        let earlier = bucket
                            .iter()
                            .find(|(other, _)| *other == op)
                            .map(|&(_, value)| value);
                        if earlier.is_none() {
                            bucket.push((op, result));
                        }
                        earlier
                    });
                    if let Some(same) = same
                        && same != result
                        && let Some(slot) = self.canon.get_mut(result.0 as usize)
                    {
                        *slot = same;
                        changed = true;
                    }
                }
            }
            if !changed {
                // Passes changing nothing more, the cycles of parameters
                // the rules above take one at a time cannot merge.
                if !self.merge_parameter_cycles(&blocks) {
                    break;
                }
            }
        }
        for index in 0..self.canon.len() {
            let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
            self.find(v);
        }
    }

    /// Sees through the cycles of block parameters that only pass one
    /// another on, around a loop that carries a value it never changes,
    /// and get a single value from outside the cycle: each is that value
    /// (every one of them holds, on every path, either it or another's).
    /// [`Self::only_argument`] takes them one at a time, and each gets
    /// another's besides that value, so none was seen through (Braun et
    /// al., "Simple and Efficient Construction of Static Single Assignment
    /// Form", 2013: redundant phi cycles). The components are taken
    /// callees of the graph first, so a cycle whose single outside value
    /// is another cycle's sees through to that one's. Whether any did.
    fn merge_parameter_cycles(&mut self, blocks: &[(BlockId, &'a binbun_ssa::ir::Block)]) -> bool {
        let mut open: Vec<Value> = Vec::new();
        let mut place: BTreeMap<Value, usize> = BTreeMap::new();
        let mut gets: Vec<Vec<Value>> = Vec::new();
        for &(id, block) in blocks {
            if id.0 == 0 {
                continue;
            }
            for (index, &parameter) in block.parameters.iter().enumerate() {
                if self.find(parameter) != parameter {
                    continue;
                }
                let incoming = self.incoming(id, index);
                let values = incoming
                    .into_iter()
                    .map(|(_, argument)| self.find(argument))
                    .collect();
                place.insert(parameter, open.len());
                open.push(parameter);
                gets.push(values);
            }
        }
        let edges: Vec<Vec<usize>> = gets
            .iter()
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| place.get(v).copied())
                    .collect()
            })
            .collect();
        let mut merged = false;
        for component in components(&edges) {
            if component.len() < 2 {
                continue;
            }
            let members: BTreeSet<Value> = component
                .iter()
                .filter_map(|&node| open.get(node).copied())
                .collect();
            let mut outside = BTreeSet::new();
            for &node in &component {
                for &value in gets.get(node).map_or(&[][..], Vec::as_slice) {
                    let value = self.find(value);
                    if !members.contains(&value) {
                        outside.insert(value);
                    }
                }
            }
            let (Some(&value), 1) = (outside.first(), outside.len()) else {
                continue;
            };
            for &member in &members {
                if let Some(slot) = self.canon.get_mut(member.0 as usize) {
                    *slot = value;
                    merged = true;
                }
            }
        }
        merged
    }

    /// The value that is exactly `width` bits of `source` from `offset`,
    /// if one is.
    fn part_of(&mut self, source: Value, offset: u16, width: u16) -> Option<Value> {
        if offset == 0 && width == self.width(source) {
            return Some(source);
        }
        match *self.defining(source)?.1 {
            Op::Concat { high, low } => {
                let low_width = self.width(low);
                if offset == 0 && width == low_width {
                    Some(self.find(low))
                } else if offset == low_width && width == self.width(high) {
                    Some(self.find(high))
                } else {
                    None
                }
            }
            Op::Extend { value, .. } if offset == 0 && width == self.width(value) => {
                Some(self.find(value))
            }
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Extend { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => None,
        }
    }

    /// What each canonical value is (calls' results are refined once
    /// callees are known).
    fn classify(&mut self) {
        let l1 = self.l1;
        for index in 0..l1.values.len() {
            let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
            if self.canonical(v) != v || self.def(v) == Def::NONE {
                continue;
            }
            let kind = self.classify_one(v);
            if let Some(slot) = self.kinds.get_mut(index) {
                *slot = kind;
            }
        }
        self.fold_constants();
    }

    /// Folds the constants propagation could not see (those of `a ^ a`,
    /// `a - a`) through extensions, extractions, concatenations and
    /// bitwise and additive operations.
    fn fold_constants(&mut self) {
        let l1 = self.l1;
        let constant = |this: &Self, v: Value| match this.kind(v) {
            Kind::Const(bits) => Some(bits),
            Kind::None
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Load(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => None,
        };
        for _ in 0..CANON_PASSES {
            let mut changed = false;
            for index in 0..l1.values.len() {
                let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
                let Kind::Pure(inst) = self.kind(v) else {
                    continue;
                };
                if self.canonical(v) != v {
                    continue;
                }
                let Some(i) = l1.inst(inst) else {
                    continue;
                };
                let folded = match i.op {
                    Op::Extend {
                        signed,
                        value,
                        width,
                    } => constant(self, value).map(|bits| {
                        if signed {
                            bits.sext(width)
                        } else {
                            bits.zext(width)
                        }
                    }),
                    Op::Extract {
                        value,
                        offset,
                        width,
                    } => constant(self, value).map(|bits| bits.extract(offset, width)),
                    Op::Concat { high, low } => constant(self, high)
                        .zip(constant(self, low))
                        .map(|(high, low)| high.concat(&low)),
                    Op::Binary(op, a, b) => {
                        constant(self, a)
                            .zip(constant(self, b))
                            .and_then(|(a, b)| match op {
                                Binary::And => Some(a.and(&b)),
                                Binary::Or => Some(a.or(&b)),
                                Binary::Xor => Some(a.xor(&b)),
                                Binary::Add => Some(a.wrapping_add(&b)),
                                Binary::Sub => Some(a.wrapping_sub(&b)),
                                Binary::Mul
                                | Binary::UDiv
                                | Binary::URem
                                | Binary::SDiv
                                | Binary::SRem
                                | Binary::Shl
                                | Binary::LShr
                                | Binary::AShr
                                | Binary::Rol
                                | Binary::Ror
                                | Binary::Eq
                                | Binary::Ne
                                | Binary::ULt
                                | Binary::ULe
                                | Binary::SLt
                                | Binary::SLe => None,
                            })
                    }
                    Op::Const(_)
                    | Op::Undefined(..)
                    | Op::Unary(..)
                    | Op::Flag(..)
                    | Op::Select { .. }
                    | Op::Lanes { .. }
                    | Op::Float { .. }
                    | Op::Load { .. }
                    | Op::Store { .. }
                    | Op::Intrinsic { .. }
                    | Op::Call { .. }
                    | Op::SystemCall { .. }
                    | Op::Landing { .. } => None,
                };
                if let Some(bits) = folded
                    && bits.width() == self.width(v)
                {
                    self.set_kind(v, Kind::Const(bits));
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn classify_one(&self, v: Value) -> Kind {
        let l1 = self.l1;
        let Some(info) = l1.value(v) else {
            return Kind::None;
        };
        let Type::Bits(width) = info.ty else {
            return Kind::None;
        };
        if let Some(bits) = self.constants.constant(v) {
            return Kind::Const(bits);
        }
        if let Some((_, &Op::Binary(Binary::Xor | Binary::Sub, a, b))) = self.defining(v)
            && self.canonical(a) == self.canonical(b)
        {
            return Kind::Const(Bits::zero(width));
        }
        if let Some(offset) = self.stack.offset(v) {
            return Kind::Address(offset);
        }
        match info.definition {
            Definition::Parameter { block, index } => {
                if block.0 != 0 {
                    return Kind::Phi;
                }
                let register = RegisterId(u16::try_from(index).unwrap_or(u16::MAX));
                if self.cx.program_counter == Some(register) {
                    return Kind::Const(Bits::from_u64(width, l1.entry));
                }
                if let Some(&(_, value)) =
                    self.cx.fixed.iter().find(|(fixed, _)| *fixed == register)
                {
                    return Kind::Const(Bits::from_u64(width, value));
                }
                if self.cx.dropped.contains(&register) {
                    let register = Some(register);
                    return Kind::Undefined(width, Unknown::Entry { register });
                }
                Kind::Entry(register)
            }
            Definition::Result { inst, .. } => match l1.inst(inst).map(|i| &i.op) {
                Some(&Op::Undefined(unknown, _)) => Kind::Undefined(width, unknown),
                Some(Op::Load { atomic: None, .. }) => Kind::Load(inst),
                Some(
                    Op::Load {
                        atomic: Some(_), ..
                    }
                    | Op::Intrinsic { .. }
                    | Op::Call { .. }
                    | Op::SystemCall { .. }
                    | Op::Landing { .. },
                ) => Kind::Result(inst),
                Some(
                    Op::Const(_)
                    | Op::Unary(..)
                    | Op::Binary(..)
                    | Op::Flag(..)
                    | Op::Extract { .. }
                    | Op::Concat { .. }
                    | Op::Extend { .. }
                    | Op::Select { .. }
                    | Op::Lanes { .. }
                    | Op::Float { .. },
                ) => Kind::Pure(inst),
                Some(Op::Store { .. }) | None => Kind::None,
            },
        }
    }

    /// Sets the kind of canonical value `v`.
    pub(super) fn set_kind(&mut self, v: Value, kind: Kind) {
        let v = self.canonical(v);
        if let Some(slot) = self.kinds.get_mut(v.0 as usize) {
            *slot = kind;
        }
    }
}

/// Whether `op` is a pure operation whose result depends only on its
/// operands (not `Undefined`, each occurrence of which is its own).
fn pure(op: &Op) -> bool {
    match op {
        Op::Const(_)
        | Op::Unary(..)
        | Op::Binary(..)
        | Op::Flag(..)
        | Op::Extract { .. }
        | Op::Concat { .. }
        | Op::Extend { .. }
        | Op::Select { .. }
        | Op::Lanes { .. }
        | Op::Float { .. } => true,
        Op::Undefined(..)
        | Op::Load { .. }
        | Op::Store { .. }
        | Op::Intrinsic { .. }
        | Op::Call { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => false,
    }
}

/// A hash of `op` (FNV-1a), to find equal operations.
fn fingerprint(op: &Op) -> u64 {
    struct Fnv(u64);
    impl Hasher for Fnv {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for &byte in bytes {
                self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
            }
        }
    }
    let mut hasher = Fnv(0xcbf2_9ce4_8422_2325);
    op.hash(&mut hasher);
    hasher.finish()
}
