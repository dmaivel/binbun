//! A function's canonical form and its identity: its L1 reduced to what it
//! observably does, with registers, block order, frame layout and
//! addresses gone, hashed.
//!
//! - **Roots** are what the function does: stores outside its own frame
//!   (inside it too where a frame address escapes), calls, system calls,
//!   intrinsics, landing pads; and each block's way out: returns (every
//!   result register of the convention), tail calls, branches, traps.
//!   Everything else counts only as far as a root uses it, so saves and
//!   restores, spills (forwarded by [`Stack::resolve`]), stack adjustment
//!   and unread flags are gone.
//! - **Values** hash by their operation, width and operands' hashes;
//!   commutative operands sorted; `x - c` as `x + -c`; comparisons one
//!   way (`a <= b` as `!(b < a)`, `a != b` as `!(a == b)`), a negated
//!   condition as its condition with the arms swapped; constants as
//!   constant propagation found them; a stack address as its offset from
//!   the entry stack pointer; a register's entry value by the register
//!   (its role in the convention: an allocation's choice of temporaries is
//!   gone in SSA). A load hashes with the last root that changed memory
//!   before it, so loads between two stores may come in any order.
//! - **Addresses**: a constant of pointer width the image maps is a slot:
//!   a call's target `code#k`, any other `ref#k`, `k` by first use in the
//!   canonical order; a read-only NUL-terminated string is its contents'
//!   hash instead ([`Referent::Text`]).
//!   In a position-independent image only a constant computed from the
//!   program counter or loaded from a relocated slot is an address
//!   ([`Surroundings::position_independent`]); a number written in an
//!   instruction never is. A call through a fixed import's slot or its
//!   PLT entry calls that slot's code slot ([`Surroundings::import`],
//!   [`Surroundings::stub`]).
//! - **Calls** carry the argument registers the callee reads before
//!   writing ([`Surroundings::reads`], from its own L1, [`reads`]); for a
//!   callee not known, those written since entry.
//! - **Blocks** are numbered by a depth-first walk from the entry, a
//!   branch's arms in the order of its condition with negations taken
//!   off; a block that only jumps on is passed through, and a block with
//!   one way in that its predecessor jumps to joins it. Block parameters
//!   are hashed by their block and the values coming in, refined over
//!   three rounds, so a loop's values are told apart by what flows round
//!   them.
//!
//! The identity is BLAKE3 over the blocks' records in that order, 128
//! bits, of [`VERSION`].

use std::collections::{BTreeMap, BTreeSet, HashMap};

use binbun_semantics::Declarations;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, RegisterId, Unary};
use binbun_ssa::condition::{Comparison, Relation, comparison};
use binbun_ssa::constant::Constants;
use binbun_ssa::ir::{
    BlockId, Definition, Function, Inst, InstId, Op, Target, Terminator, Type, Value,
};
use binbun_ssa::stack::Stack;

use crate::{Fingerprint, Identity};

/// The identity version: bumped by every change to the canonical form.
pub const VERSION: u32 = 2;

/// The rounds of block-parameter refinement.
const ROUNDS: usize = 3;

/// An identity with fewer operations than this, and nothing distinctive,
/// is trivial.
pub const TRIVIAL_OPERATIONS: u32 = 8;

/// The registers of a calling convention the canonical form uses.
#[derive(Clone, Debug)]
pub struct Abi<'a> {
    /// The architecture's registers.
    pub declarations: &'a Declarations,
    /// The stack pointer.
    pub stack_pointer: RegisterId,
    /// The integer argument registers, in order.
    pub arguments: Vec<RegisterId>,
    /// The vector argument registers, in order.
    pub float_arguments: Vec<RegisterId>,
    /// The integer result registers.
    pub results: Vec<RegisterId>,
    /// The vector result registers.
    pub float_results: Vec<RegisterId>,
    /// The registers a system call takes: its number, then its arguments.
    pub system_call: Vec<RegisterId>,
}

impl Abi<'_> {
    /// Every argument register: the integer ones, then the vector ones
    /// (bit `i` of an argument mask is the `i`th).
    pub fn argument_registers(&self) -> Vec<RegisterId> {
        self.arguments
            .iter()
            .chain(&self.float_arguments)
            .copied()
            .collect()
    }

    /// Every result register: the integer ones, then the vector ones.
    pub fn result_registers(&self) -> Vec<RegisterId> {
        self.results
            .iter()
            .chain(&self.float_results)
            .copied()
            .collect()
    }
}

/// What an address the image maps holds, for the canonical form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Referent {
    /// A NUL-terminated string in read-only memory: the hash of its bytes.
    Text(u128),
    /// Anything else.
    Other,
}

/// What the canonical form asks of the image around a function.
pub trait Surroundings {
    /// What `address` refers to, if the image maps it.
    fn referent(&self, address: u64) -> Option<Referent>;
    /// The argument registers (a mask over [`Abi::arguments`]) the
    /// function at `callee` reads, if it is known.
    fn reads(&self, callee: u64) -> Option<u32>;
    /// Whether `slot` is the slot of an import the loader fills before
    /// the program runs and that never changes (a fixed code pointer): a
    /// call or jump through it is a call of the import, a code slot.
    fn import(&self, slot: u64) -> bool;
    /// The slot of a fixed import ([`Surroundings::import`]) the code at
    /// `address` does nothing but jump through (a PLT entry, `jmp
    /// [slot]`): a call of it is a call of the import.
    fn stub(&self, address: u64) -> Option<u64>;
    /// Whether the image is loaded where the loader chooses (a
    /// position-independent executable or library at 0): its code then
    /// computes every address from the program counter or loads one the
    /// loader relocated ([`Surroundings::relocated`]), and a number
    /// written in an instruction is never an address, whatever the image
    /// maps there.
    fn position_independent(&self) -> bool;
    /// Whether the loader writes any of the `bytes` bytes at `address` (a
    /// relocation): what is loaded from there may be an address.
    fn relocated(&self, address: u64, bytes: u16) -> bool;
}

/// One function's L1 with the analyses the canonical form reads.
#[derive(Clone, Copy, Debug)]
pub struct Input<'a> {
    /// The L1, after decompilation's L1 passes.
    pub function: &'a Function,
    /// Constant propagation over it.
    pub constants: &'a Constants,
    /// Its stack.
    pub stack: &'a Stack,
    /// The convention.
    pub abi: &'a Abi<'a>,
}

/// A function's canonical form: its identity, size and features.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Canonical {
    /// The identity.
    pub identity: Identity,
    /// The operations the roots reach, and the roots.
    pub operations: u32,
    /// Whether the identity is trivial: fewer than
    /// [`TRIVIAL_OPERATIONS`] operations and no string, distinctive
    /// constant or system call.
    pub trivial: bool,
    /// The fingerprint's features, without callee names, which
    /// [`Canonical::code`]'s addresses give.
    pub fingerprint: Fingerprint,
    /// The address of each code slot, by number.
    pub code: Vec<u64>,
    /// The address of each other slot, by number.
    pub data: Vec<u64>,
    /// The argument registers each call compares (a mask over
    /// [`Abi::argument_registers`]), by the address of its instruction.
    pub masks: BTreeMap<u64, u32>,
}

/// The tags of the hashed records.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Tag {
    Const = 1,
    Slot,
    Code,
    Text,
    Frame,
    Entry,
    Phi,
    Undefined,
    Unary,
    Binary,
    Not,
    Flag,
    Extract,
    Concat,
    Extend,
    Select,
    Lanes,
    Float,
    Load,
    Result,
    Memory,
    Store,
    Call,
    SystemCall,
    Intrinsic,
    Landing,
    Return,
    Leave,
    Branch,
    IndirectJump,
    Trap,
    Stop,
    Invoke,
    Jump,
    Node,
    Open,
}

/// A record hashed to 128 bits.
fn record(tag: Tag, numbers: &[u64], children: &[u128]) -> u128 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[tag as u8]);
    for number in numbers {
        hasher.update(&number.to_le_bytes());
    }
    for child in children {
        hasher.update(&child.to_le_bytes());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    u128::from_le_bytes(out)
}

/// A stable number for an enum value of another crate, from its `Debug`
/// form.
fn named(value: &impl core::fmt::Debug) -> u64 {
    let text = format!("{value:?}");
    let hash = blake3::hash(text.as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_le_bytes(out)
}

/// Whether `bits` is a distinctive constant: not 0, 1, all ones
/// or a power of two up to 4096.
fn distinctive(bits: &Bits) -> bool {
    let value = bits.low_u64();
    !(bits.is_zero()
        || value == 1
        || *bits == Bits::ones(bits.width())
        || (value.is_power_of_two() && value <= 4096 && bits.width() <= 64))
}

/// Whether constant `bits` of the machine instruction at `at` is the
/// program counter as the lifter writes it: the next instruction's
/// address (an instruction is at most 15 bytes).
fn counter(bits: &Bits, at: u64) -> bool {
    bits.width() == 64 && (1..=15).contains(&bits.low_u64().wrapping_sub(at))
}

/// A block of the canonical graph: L1 blocks joined, and its successors.
#[derive(Clone, Debug, Default)]
struct Node {
    blocks: Vec<BlockId>,
    /// The successors, in canonical order: (node, L1 target block).
    successors: Vec<usize>,
    /// Whether the last block's branch condition is taken negated (its
    /// arms swapped).
    negated: bool,
}

/// How values are hashed in one round.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Before the graph is canonical: no block numbers, no root numbers,
    /// slots by kind.
    Shape,
    /// A refinement round: block and root numbers, slots by kind.
    Round,
    /// The last round: slots numbered by first use.
    Last,
}

/// The canonicalizer of one function.
struct Canon<'a, S: Surroundings> {
    input: Input<'a>,
    surroundings: &'a S,
    /// Each block's L1 predecessors: (block, jump index).
    predecessors: Vec<Vec<(BlockId, usize)>>,
    /// The blocks reachable from the entry.
    reachable: Vec<bool>,
    /// The entry block's parameters: register index (the memory: `None`).
    entry: HashMap<Value, Option<usize>>,
    resolved: HashMap<Value, Value>,
    /// Instruction ids that are roots.
    roots: BTreeSet<InstId>,
    nodes: Vec<Node>,
    node_of: HashMap<BlockId, usize>,
    root_number: HashMap<InstId, u64>,
    /// Block parameters' hashes from the previous round.
    phis: HashMap<Value, u128>,
    mode: Mode,
    memo: HashMap<Value, u128>,
    /// Slot-agnostic hashes for ordering commutative operands in the last
    /// round.
    agnostic: HashMap<Value, u128>,
    code: Vec<u64>,
    data: Vec<u64>,
    code_numbers: HashMap<u64, u64>,
    data_numbers: HashMap<u64, u64>,
    fingerprint: Fingerprint,
    operations: u32,
    counted: BTreeSet<Value>,
    masks: BTreeMap<u64, u32>,
    /// Whether each value is computed from an address constant ([`Canon::derived`]).
    derived: HashMap<Value, bool>,
    /// Whether each value's constant may be an address in a
    /// position-independent image ([`Canon::relative`]).
    relative: HashMap<Value, bool>,
}

/// The canonical form of `input`'s function in `surroundings`.
pub fn canonical<S: Surroundings>(input: Input<'_>, surroundings: &S) -> Canonical {
    let function = input.function;
    let mut canon = Canon {
        input,
        surroundings,
        predecessors: vec![Vec::new(); function.blocks.len()],
        reachable: vec![false; function.blocks.len()],
        entry: HashMap::new(),
        resolved: HashMap::new(),
        roots: BTreeSet::new(),
        nodes: Vec::new(),
        node_of: HashMap::new(),
        root_number: HashMap::new(),
        phis: HashMap::new(),
        mode: Mode::Shape,
        memo: HashMap::new(),
        agnostic: HashMap::new(),
        code: Vec::new(),
        data: Vec::new(),
        code_numbers: HashMap::new(),
        data_numbers: HashMap::new(),
        fingerprint: Fingerprint::default(),
        operations: 0,
        counted: BTreeSet::new(),
        masks: BTreeMap::new(),
        derived: HashMap::new(),
        relative: HashMap::new(),
    };
    canon.prepare();
    canon.structure();
    let mut identity = 0;
    for round in 0..=ROUNDS {
        canon.mode = if round == ROUNDS {
            Mode::Last
        } else {
            Mode::Round
        };
        canon.memo.clear();
        canon.agnostic.clear();
        let mut phis = HashMap::new();
        if round == ROUNDS {
            identity = canon.serialize();
        } else {
            canon.refine(&mut phis);
            canon.phis = phis;
        }
    }
    canon.finish(identity)
}

impl<'a, S: Surroundings> Canon<'a, S> {
    fn function(&self) -> &'a Function {
        self.input.function
    }

    /// Predecessors, reachability, the entry's parameters and the roots.
    fn prepare(&mut self) {
        let function = self.function();
        let mut stack = vec![BlockId(0)];
        while let Some(block) = stack.pop() {
            let Some(seen) = self.reachable.get_mut(block.0 as usize) else {
                continue;
            };
            if *seen {
                continue;
            }
            *seen = true;
            let Some(info) = function.block(block) else {
                continue;
            };
            for (index, target) in info.terminator.targets().enumerate() {
                if let Some(list) = self.predecessors.get_mut(target.block.0 as usize) {
                    list.push((block, index));
                }
                stack.push(target.block);
            }
        }
        if let Some(entry) = function.blocks.first() {
            let count = entry.parameters.len();
            for (index, &parameter) in entry.parameters.iter().enumerate() {
                self.entry
                    .insert(parameter, (index + 1 < count).then_some(index));
            }
        }
        let escaped = self.input.stack.escaped();
        for (block, info) in function.blocks.iter().enumerate() {
            if !self.reachable.get(block).copied().unwrap_or(false) {
                continue;
            }
            for &id in &info.insts {
                let Some(inst) = function.inst(id) else {
                    continue;
                };
                let root = match &inst.op {
                    Op::Store { address, .. } => {
                        escaped || self.input.stack.offset(*address).is_none()
                    }
                    Op::Call { .. }
                    | Op::SystemCall { .. }
                    | Op::Intrinsic { .. }
                    | Op::Landing { .. } => true,
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
                    | Op::Load { .. } => false,
                };
                if root {
                    self.roots.insert(id);
                }
            }
        }
    }

    /// Whether `block` only jumps on: no parameters, no roots, a jump.
    fn passable(&self, block: BlockId) -> bool {
        let Some(info) = self.function().block(block) else {
            return false;
        };
        block.0 != 0
            && info.parameters.is_empty()
            && matches!(info.terminator, Terminator::Jump(_))
            && !info.insts.iter().any(|id| self.roots.contains(id))
    }

    /// Where a jump to `block` ends up past blocks that only jump on.
    fn thread(&self, mut block: BlockId) -> BlockId {
        let mut seen = BTreeSet::new();
        while self.passable(block) && seen.insert(block) {
            match self.function().block(block).map(|b| &b.terminator) {
                Some(Terminator::Jump(target)) => block = target.block,
                _ => break,
            }
        }
        block
    }

    /// The jumps out of `block` (L1 targets), threaded, in canonical order;
    /// whether its condition is negated.
    fn successors(&mut self, block: BlockId) -> (Vec<BlockId>, bool) {
        let function = self.function();
        let Some(info) = function.block(block) else {
            return (Vec::new(), false);
        };
        let mut negated = false;
        let mut targets: Vec<BlockId> = info
            .terminator
            .targets()
            .map(|target| self.thread(target.block))
            .collect();
        if let Terminator::Branch { condition, .. } = &info.terminator {
            let (negation, _) = self.condition(*condition);
            if negation {
                targets.reverse();
                negated = true;
            }
        }
        (targets, negated)
    }

    /// The canonical graph: nodes in depth-first order from the entry.
    fn structure(&mut self) {
        let function = self.function();
        let Some(Terminator::Jump(start)) = function.blocks.first().map(|b| &b.terminator) else {
            return;
        };
        let start = self.thread(start.block);
        // How many threaded jumps reach each block.
        let mut incoming: HashMap<BlockId, usize> = HashMap::new();
        for (index, info) in function.blocks.iter().enumerate() {
            let id = BlockId(u32::try_from(index).unwrap_or(u32::MAX));
            if !self.reachable.get(index).copied().unwrap_or(false) || self.passable(id) {
                continue;
            }
            for target in info.terminator.targets() {
                *incoming.entry(self.thread(target.block)).or_default() += 1;
            }
        }
        *incoming.entry(start).or_default() += 1;
        let mut stack = vec![start];
        let mut pending: Vec<(usize, Vec<BlockId>)> = Vec::new();
        while let Some(first) = stack.pop() {
            if self.node_of.contains_key(&first) {
                continue;
            }
            let index = self.nodes.len();
            let mut node = Node::default();
            let mut current = first;
            loop {
                node.blocks.push(current);
                self.node_of.insert(current, index);
                let (targets, negated) = self.successors(current);
                let joins = match (
                    &function.block(current).map(|b| &b.terminator),
                    targets.as_slice(),
                ) {
                    (Some(Terminator::Jump(_)), &[next]) => {
                        next != start
                            && incoming.get(&next) == Some(&1)
                            && !self.node_of.contains_key(&next)
                    }
                    _ => false,
                };
                if joins {
                    current = targets.first().copied().unwrap_or(current);
                    continue;
                }
                node.negated = negated;
                for &target in targets.iter().rev() {
                    stack.push(target);
                }
                pending.push((index, targets));
                break;
            }
            self.nodes.push(node);
        }
        for (index, targets) in pending {
            let successors = targets
                .iter()
                .filter_map(|block| self.node_of.get(block).copied())
                .collect();
            if let Some(node) = self.nodes.get_mut(index) {
                node.successors = successors;
            }
        }
        let mut number = 0;
        for node in &self.nodes {
            for &block in &node.blocks {
                let Some(info) = function.block(block) else {
                    continue;
                };
                for id in &info.insts {
                    let store = matches!(function.inst(*id).map(|i| &i.op), Some(Op::Store { .. }));
                    if self.roots.contains(id) && !store {
                        self.root_number.insert(*id, number);
                        number += 1;
                    }
                }
            }
        }
    }

    /// `value` with copies taken off: a forwarded stack load's stored
    /// value, a block parameter every way in passes the same value.
    fn resolve(&mut self, value: Value) -> Value {
        if let Some(&done) = self.resolved.get(&value) {
            return done;
        }
        // Guards cycles: a parameter met again is itself.
        self.resolved.insert(value, value);
        let function = self.function();
        let result = match function.value(value).map(|info| info.definition) {
            Some(Definition::Result { inst, .. }) => {
                if matches!(function.inst(inst).map(|i| &i.op), Some(Op::Load { .. })) {
                    let stored = self.input.stack.resolve(function, value);
                    if stored == value {
                        value
                    } else {
                        self.resolve(stored)
                    }
                } else {
                    value
                }
            }
            Some(Definition::Parameter { block, index }) if block.0 != 0 => {
                let mut same: Option<Value> = None;
                let mut trivial = true;
                let predecessors = self
                    .predecessors
                    .get(block.0 as usize)
                    .cloned()
                    .unwrap_or_default();
                for (from, jump) in predecessors {
                    let Some(argument) = function
                        .block(from)
                        .and_then(|b| b.terminator.targets().nth(jump))
                        .and_then(|t| t.arguments.get(index as usize))
                        .copied()
                    else {
                        trivial = false;
                        break;
                    };
                    let argument = self.resolve(argument);
                    if argument == value {
                        continue;
                    }
                    match same {
                        None => same = Some(argument),
                        Some(other) if other == argument => {}
                        Some(_) => {
                            trivial = false;
                            break;
                        }
                    }
                }
                match same {
                    Some(same) if trivial => same,
                    Some(_) | None => value,
                }
            }
            Some(Definition::Parameter { .. }) | None => value,
        };
        self.resolved.insert(value, result);
        result
    }

    /// A condition with negations taken off: whether it is negated, and
    /// its base's hash.
    fn condition(&mut self, value: Value) -> (bool, u128) {
        let value = self.resolve(value);
        let function = self.function();
        let computed = self.input.constants.constant(value).is_none() || self.derived(value);
        if computed
            && self.width(value) == 1
            && let Some(comparison) = comparison(function, self.input.constants, value)
        {
            self.count(value, "cmp");
            return self.compared(comparison);
        }
        let op = match function.value(value).map(|info| info.definition) {
            Some(Definition::Result { inst, .. }) if computed => {
                function.inst(inst).map(|i| i.op.clone())
            }
            _ => None,
        };
        match op {
            Some(Op::Unary(Unary::Not, a)) if self.width(value) == 1 => {
                let (negated, base) = self.condition(a);
                (!negated, base)
            }
            Some(Op::Binary(Binary::Xor, a, b)) if self.width(value) == 1 && self.is_one(b) => {
                let (negated, base) = self.condition(a);
                (!negated, base)
            }
            Some(Op::Binary(Binary::Xor, a, b)) if self.width(value) == 1 && self.is_one(a) => {
                let (negated, base) = self.condition(b);
                (!negated, base)
            }
            _ => (false, self.hash(value)),
        }
    }

    /// A comparison in one form: equality (operands in hash order), or
    /// `a < b` (unsigned or signed), negated if need be; against a
    /// constant, `a < K` (`a <= 2` is `a < 3`, `2 < a` is `!(a < 3)`).
    fn compared(&mut self, comparison: Comparison) -> (bool, u128) {
        let Comparison {
            relation,
            left,
            right,
        } = comparison;
        // To `Eq`, `ULt` or `SLt`, operands possibly swapped, and whether
        // negated.
        let (negated, base, swap) = match relation {
            Relation::Eq => (false, Relation::Eq, false),
            Relation::Ne => (true, Relation::Eq, false),
            Relation::ULt => (false, Relation::ULt, false),
            Relation::SLt => (false, Relation::SLt, false),
            Relation::UGt => (false, Relation::ULt, true),
            Relation::SGt => (false, Relation::SLt, true),
            // `a <= b` is `!(b < a)`.
            Relation::ULe => (true, Relation::ULt, true),
            Relation::SLe => (true, Relation::SLt, true),
            // `a >= b` is `!(a < b)`.
            Relation::UGe => (true, Relation::ULt, false),
            Relation::SGe => (true, Relation::SLt, false),
        };
        let (mut negated, mut a, mut b) = if swap {
            (negated, right, left)
        } else {
            (negated, left, right)
        };
        if base == Relation::Eq {
            let mut pair = [self.hash(a), self.hash(b)];
            pair.sort_unstable();
            return (negated, record(Tag::Binary, &[named(&Binary::Eq)], &pair));
        }
        // `K < x` as `!(x < K + 1)`.
        let constant = |canon: &mut Self, v: Value| {
            let v = canon.resolve(v);
            canon.input.constants.constant(v).filter(|bits| {
                (!canon.addressable(v) || !canon.is_address(bits)) && !canon.derived(v)
            })
        };
        let mut right_constant = constant(self, b);
        if right_constant.is_none()
            && let Some(k) = constant(self, a)
        {
            let width = k.width();
            let limit = if base == Relation::ULt {
                Bits::ones(width)
            } else {
                Bits::ones(width).shift_right(1)
            };
            if k != limit {
                negated = !negated;
                core::mem::swap(&mut a, &mut b);
                right_constant = Some(k.wrapping_add(&Bits::from_u64(width, 1)));
            }
        }
        let op = if base == Relation::ULt {
            Binary::ULt
        } else {
            Binary::SLt
        };
        let left_hash = self.hash(a);
        let right_hash = match right_constant {
            // `b` is where the constant comes from (swapped).
            Some(k) => self.constant_of(b, &k),
            None => self.hash(b),
        };
        (
            negated,
            record(Tag::Binary, &[named(&op)], &[left_hash, right_hash]),
        )
    }

    /// The hash of bits `offset`.. `offset + width` of `value`, looking
    /// through partial register writes (a concatenation's other part),
    /// zero extensions and extractions ([`project`]): `mov cl, [rsi]` reads
    /// none of the old `rcx`, and a `double` argument none of its vector
    /// register's upper lanes.
    fn project(&mut self, value: Value, offset: u16, width: u16) -> u128 {
        let parts = {
            let function = self.function();
            let constants = self.input.constants;
            let stack = self.input.stack;
            project(
                function,
                &|v| stack.resolve(function, v),
                constants,
                value,
                offset,
                width,
            )
        };
        let mut hashes = Vec::with_capacity(parts.len());
        for (part, offset, width) in parts {
            hashes.push(match part {
                Projection::Zero => self.immediate(&Bits::from_u64(width, 0)),
                Projection::Bits(base) => {
                    let base = self.resolve(base);
                    if offset == 0 && width == self.width(base) {
                        self.hash(base)
                    } else {
                        let source = self.hash(base);
                        record(
                            Tag::Extract,
                            &[u64::from(offset), u64::from(width)],
                            &[source],
                        )
                    }
                }
            });
        }
        match hashes.as_slice() {
            [single] => *single,
            _ => record(Tag::Concat, &[u64::from(width)], &hashes),
        }
    }

    fn is_one(&mut self, value: Value) -> bool {
        let value = self.resolve(value);
        self.input
            .constants
            .constant(value)
            .is_some_and(|bits| bits.low_u64() == 1)
    }

    fn width(&self, value: Value) -> u16 {
        match self.function().ty(value) {
            Some(Type::Bits(width)) => width,
            Some(Type::Memory) | None => 0,
        }
    }

    /// The result registers a return's `registers` are hashed in: the
    /// first integer one, and the first vector one where a floating-point
    /// operation computed its low part. The others, and a vector register
    /// holding anything else, are what the function left there more often
    /// than what it returns (a copy's data, a temporary of a register
    /// allocation): a prototype says which it returns, and the
    /// canonical form has none.
    fn returned(&mut self, registers: &[Value]) -> Vec<RegisterId> {
        let abi = self.input.abi;
        let mut returned: Vec<RegisterId> = abi.results.first().copied().into_iter().collect();
        if let Some(&float) = abi.float_results.first()
            && let Some(&value) = registers.get(usize::from(float.0))
            && self.floating(value)
        {
            returned.push(float);
        }
        returned
    }

    /// Whether the low part of `value` comes from a floating-point
    /// operation ([`floating`]).
    fn floating(&self, value: Value) -> bool {
        let function = self.function();
        let stack = self.input.stack;
        floating(function, &|v| stack.resolve(function, v), value)
    }

    /// Counts `value`'s operation once, of class `class`, in the last
    /// round.
    fn count(&mut self, value: Value, class: &str) {
        if self.mode == Mode::Last && self.counted.insert(value) {
            self.operations += 1;
            *self.fingerprint.ops.entry(class.to_owned()).or_default() += 1;
        }
    }

    /// The hash of `value` in the current round.
    fn hash(&mut self, value: Value) -> u128 {
        let value = self.resolve(value);
        if let Some(&done) = self.memo.get(&value) {
            return done;
        }
        let hash = self.compute(value);
        self.memo.insert(value, hash);
        hash
    }

    /// The slot-agnostic hash of `value` (for ordering in the last round).
    fn agnostic_hash(&mut self, value: Value) -> u128 {
        if self.mode != Mode::Last {
            return self.hash(value);
        }
        let value = self.resolve(value);
        if let Some(&done) = self.agnostic.get(&value) {
            return done;
        }
        let saved = (
            core::mem::take(&mut self.memo),
            core::mem::replace(&mut self.mode, Mode::Round),
        );
        // A refinement round's hash with this round's block parameters.
        let hash = self.hash(value);
        let agnostic = core::mem::replace(&mut self.memo, saved.0);
        self.mode = saved.1;
        self.agnostic.extend(agnostic);
        self.agnostic.insert(value, hash);
        hash
    }

    /// Hashes of `values` in the order of their slot-agnostic hashes.
    fn sorted(&mut self, values: &[Value]) -> Vec<u128> {
        let mut keyed: Vec<(u128, Value)> = values
            .iter()
            .map(|&value| (self.agnostic_hash(value), value))
            .collect();
        keyed.sort_by_key(|&(key, _)| key);
        keyed
            .into_iter()
            .map(|(_, value)| self.hash(value))
            .collect()
    }

    /// A slot for the address `address`: a code slot if `code`.
    fn slot(&mut self, address: u64, code: bool) -> u128 {
        if self.mode != Mode::Last {
            return record(Tag::Slot, &[u64::from(code)], &[]);
        }
        let (numbers, list) = if code {
            (&mut self.code_numbers, &mut self.code)
        } else {
            (&mut self.data_numbers, &mut self.data)
        };
        let next = list.len() as u64;
        let number = *numbers.entry(address).or_insert_with(|| {
            list.push(address);
            next
        });
        record(if code { Tag::Code } else { Tag::Slot }, &[number], &[])
    }

    /// A constant's hash: a slot or string if it is an address the image
    /// maps.
    fn constant(&mut self, bits: &Bits) -> u128 {
        if matches!(bits.width(), 32 | 64)
            && let Some(referent) = self.surroundings.referent(bits.low_u64())
        {
            return match referent {
                Referent::Text(text) => {
                    if self.mode == Mode::Last {
                        self.fingerprint.strings.insert(format!("{text:032x}"));
                    }
                    record(Tag::Text, &[], &[text])
                }
                Referent::Other => self.slot(bits.low_u64(), false),
            };
        }
        // An address negated (`lea -table(%rax)`): the slot, negated.
        let negated = bits.wrapping_neg();
        if self.is_address(&negated) {
            let slot = self.constant(&negated);
            return record(Tag::Unary, &[named(&Unary::Neg)], &[slot]);
        }
        // A wide constant (stored in one vector store) of words that are
        // addresses: word by word.
        let width = bits.width();
        if width > 64 && width.is_multiple_of(64) {
            let words: Vec<Bits> = (0..width / 64).map(|i| bits.extract(i * 64, 64)).collect();
            if words.iter().any(|word| self.is_address(word)) {
                let hashes: Vec<u128> = words.iter().map(|word| self.constant(word)).collect();
                return record(Tag::Concat, &[u64::from(width)], &hashes);
            }
        }
        self.literal(bits)
    }

    /// A number's hash, never an address.
    fn literal(&mut self, bits: &Bits) -> u128 {
        if self.mode == Mode::Last && distinctive(bits) {
            self.fingerprint.constants.insert(bits.low_u64());
        }
        let bytes: Vec<u64> = bits
            .to_le_bytes()
            .collect::<Vec<u8>>()
            .chunks(8)
            .map(|chunk| {
                let mut word = [0u8; 8];
                if let Some(dest) = word.get_mut(..chunk.len()) {
                    dest.copy_from_slice(chunk);
                }
                u64::from_le_bytes(word)
            })
            .collect();
        let mut numbers = vec![u64::from(bits.width())];
        numbers.extend(bytes);
        record(Tag::Const, &numbers, &[])
    }

    /// The hash of constant `bits` of `value`: a slot or string where it
    /// may be an address ([`Canon::addressable`]), else a number.
    fn constant_of(&mut self, value: Value, bits: &Bits) -> u128 {
        if self.addressable(value) {
            self.constant(bits)
        } else {
            self.literal(bits)
        }
    }

    /// The hash of a number the code writes itself (a zero extension's
    /// upper bits, `xor eax, eax`): an address only where the image's
    /// code may write addresses as numbers (not position-independent).
    fn immediate(&mut self, bits: &Bits) -> u128 {
        if self.surroundings.position_independent() {
            self.literal(bits)
        } else {
            self.constant(bits)
        }
    }

    /// Whether `value`'s constant may be an address: anywhere in an image
    /// that is not position-independent; in one that is, only where it is
    /// computed from the program counter or loaded from a slot the loader
    /// relocates ([`Canon::relative`]).
    fn addressable(&mut self, value: Value) -> bool {
        !self.surroundings.position_independent() || self.relative(value)
    }

    /// Whether `value` is computed from the program counter (a constant
    /// of the next instruction's address, as the lifter writes `rip`) or
    /// from a load of a slot the loader relocates
    /// ([`Surroundings::relocated`]), by pure operations; a block
    /// parameter if any value coming in is.
    fn relative(&mut self, value: Value) -> bool {
        let value = self.resolve(value);
        if let Some(&known) = self.relative.get(&value) {
            return known;
        }
        self.relative.insert(value, false);
        let function = self.function();
        let operands = match function.value(value).map(|info| info.definition) {
            Some(Definition::Result { inst, .. }) => match function.inst(inst) {
                Some(Inst {
                    op: Op::Const(bits),
                    address,
                    ..
                }) => {
                    let counter = counter(bits, *address);
                    self.relative.insert(value, counter);
                    return counter;
                }
                Some(Inst {
                    op: Op::Load { address, bytes, .. },
                    ..
                }) => {
                    let address = self.resolve(*address);
                    let relocated = self
                        .input
                        .constants
                        .constant(address)
                        .is_some_and(|at| self.surroundings.relocated(at.low_u64(), *bytes));
                    self.relative.insert(value, relocated);
                    return relocated;
                }
                Some(Inst {
                    op:
                        op @ (Op::Unary(..)
                        | Op::Binary(..)
                        | Op::Flag(..)
                        | Op::Extract { .. }
                        | Op::Concat { .. }
                        | Op::Extend { .. }
                        | Op::Select { .. }),
                    ..
                }) => op.operands(),
                _ => Vec::new(),
            },
            Some(Definition::Parameter { block, index }) => self
                .predecessors
                .get(block.0 as usize)
                .into_iter()
                .flatten()
                .filter_map(|&(from, jump)| {
                    function
                        .block(from)?
                        .terminator
                        .targets()
                        .nth(jump)?
                        .arguments
                        .get(index as usize)
                        .copied()
                })
                .collect(),
            None => Vec::new(),
        };
        let relative = operands.into_iter().any(|operand| self.relative(operand));
        self.relative.insert(value, relative);
        relative
    }

    /// Whether `bits` is an address the image maps (a 32- or 64-bit
    /// constant).
    fn is_address(&self, bits: &Bits) -> bool {
        matches!(bits.width(), 32 | 64) && self.surroundings.referent(bits.low_u64()).is_some()
    }

    /// Whether `value` is computed from an address constant by pure
    /// operations (`&x * 1103515245`, `p - &x`): constant propagation
    /// folds it to a number that depends on where `x` is, so it is hashed
    /// as the computation.
    fn derived(&mut self, value: Value) -> bool {
        if let Some(&known) = self.derived.get(&value) {
            return known;
        }
        self.derived.insert(value, false);
        let function = self.function();
        let operands = match function.value(value).map(|info| info.definition) {
            Some(Definition::Result { inst, .. }) => match function.inst(inst).map(|i| &i.op) {
                Some(Op::Const(bits)) => {
                    let address = self.addressable(value)
                        && (self.is_address(bits) || self.is_address(&bits.wrapping_neg()));
                    self.derived.insert(value, address);
                    return address;
                }
                Some(
                    op @ (Op::Unary(..)
                    | Op::Binary(..)
                    | Op::Flag(..)
                    | Op::Extract { .. }
                    | Op::Concat { .. }
                    | Op::Extend { .. }
                    | Op::Select { .. }),
                ) => op.operands(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        let derived = operands.into_iter().any(|operand| {
            let operand = self.resolve(operand);
            self.derived(operand)
        });
        self.derived.insert(value, derived);
        derived
    }

    fn compute(&mut self, value: Value) -> u128 {
        let function = self.function();
        if let Some(offset) = self.input.stack.offset(value) {
            return record(Tag::Frame, &[offset.cast_unsigned()], &[]);
        }
        if let Some(bits) = self.input.constants.constant(value)
            && ((self.addressable(value) && self.is_address(&bits)) || !self.derived(value))
        {
            return self.constant_of(value, &bits);
        }
        let width = u64::from(self.width(value));
        match function.value(value).map(|info| info.definition) {
            None => record(Tag::Undefined, &[0], &[]),
            Some(Definition::Parameter { block, .. }) if block.0 == 0 => {
                match self.entry.get(&value).copied().flatten() {
                    Some(register) => record(Tag::Entry, &[register as u64, width], &[]),
                    None => record(Tag::Memory, &[u64::MAX], &[]),
                }
            }
            Some(Definition::Parameter { block, .. }) => {
                let node = self.node_of.get(&block).copied().unwrap_or(usize::MAX) as u64;
                match self.mode {
                    Mode::Shape => record(Tag::Phi, &[width], &[]),
                    Mode::Round | Mode::Last => match self.phis.get(&value) {
                        Some(&hash) => hash,
                        None => record(Tag::Phi, &[node, width], &[]),
                    },
                }
            }
            Some(Definition::Result { inst, index }) => {
                let Some(op) = function.inst(inst).map(|i| i.op.clone()) else {
                    return record(Tag::Undefined, &[1], &[]);
                };
                self.operation(value, inst, index, &op, width)
            }
        }
    }

    /// The hash of result `index` of `inst` (`op`), `value`.
    #[expect(clippy::too_many_lines, reason = "one arm per operation")]
    fn operation(&mut self, value: Value, inst: InstId, index: u32, op: &Op, width: u64) -> u128 {
        if width == 1
            && matches!(op, Op::Unary(..) | Op::Binary(..) | Op::Flag(..))
            && comparison(self.function(), self.input.constants, value).is_some()
        {
            return self.negatable(value);
        }
        match op {
            Op::Const(bits) => self.constant_of(value, bits),
            // A site's inputs are derived from operands, not behaviour of
            // their own: they do not count in the identity.
            Op::Undefined(unknown, _) => {
                // Where it comes from, but never an address (the
                // instruction's, a call's): those move when the code is
                // linked elsewhere.
                use binbun_ssa::ir::Unknown;
                let kind = match unknown {
                    Unknown::Architecture { register, .. } => named(&register.map(|r| r.0)),
                    Unknown::Parameter => named(&"parameter"),
                    Unknown::Call { .. } => named(&"call"),
                    Unknown::Landing => named(&"landing"),
                    Unknown::Entry { .. } => named(&"entry"),
                    Unknown::Unwritten => named(&"unwritten"),
                    Unknown::Lowering => named(&"lowering"),
                };
                record(Tag::Undefined, &[kind, width], &[])
            }
            &Op::Unary(op, a) => {
                if op == Unary::Not && width == 1 {
                    return self.negatable(value);
                }
                self.count(value, if op == Unary::Not { "logic" } else { "bits" });
                let a = self.hash(a);
                record(Tag::Unary, &[named(&op), width], &[a])
            }
            &Op::Binary(op, a, b) => self.binary(value, op, a, b, width),
            &Op::Flag(op, a, b, c) => {
                self.count(value, "flag");
                let operands = [self.hash(a), self.hash(b), self.hash(c)];
                record(Tag::Flag, &[named(&op), width], &operands)
            }
            &Op::Extract {
                value: source,
                offset,
                width: bits,
            } => self.project(source, offset, bits),
            &Op::Concat { high, low } => {
                let operands = [self.hash(high), self.hash(low)];
                record(Tag::Concat, &[width], &operands)
            }
            &Op::Extend {
                signed,
                value: source,
                width: bits,
            } => {
                self.count(value, "extend");
                let source = self.hash(source);
                record(
                    Tag::Extend,
                    &[u64::from(signed), u64::from(bits)],
                    &[source],
                )
            }
            &Op::Select {
                condition,
                then,
                otherwise,
            } => {
                self.count(value, "select");
                let (negated, base) = self.condition(condition);
                let (then, otherwise) = if negated {
                    (otherwise, then)
                } else {
                    (then, otherwise)
                };
                let operands = [base, self.hash(then), self.hash(otherwise)];
                record(Tag::Select, &[width], &operands)
            }
            &Op::Lanes {
                lanes,
                op,
                operands,
            } => {
                self.count(value, "lanes");
                let hashes: Vec<u128> = operands
                    .iter()
                    .take(op.arity())
                    .map(|&operand| self.hash(operand))
                    .collect();
                record(Tag::Lanes, &[named(&op), u64::from(lanes), width], &hashes)
            }
            &Op::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            } => {
                self.count(value, "float");
                let mut hashes = vec![self.hash(rounding)];
                for &operand in operands.iter().take(op.arity()) {
                    hashes.push(self.hash(operand));
                }
                record(
                    Tag::Float,
                    &[named(&op), named(&format), u64::from(lanes), named(&output)],
                    &hashes,
                )
            }
            &Op::Load {
                memory,
                address,
                bytes,
                ..
            } => {
                self.count(value, &format!("load{bytes}"));
                let operands = [self.hash(address), self.hash(memory)];
                record(Tag::Load, &[u64::from(bytes)], &operands)
            }
            // The memory after a store is the memory before it: loads are
            // told apart by calls and merges, not by the order of the
            // stores before them, which compilers choose.
            &Op::Store { memory, .. } => self.hash(memory),
            Op::Call { .. } | Op::SystemCall { .. } | Op::Intrinsic { .. } | Op::Landing { .. } => {
                let which = match op {
                    Op::Call { changes, .. }
                    | Op::SystemCall { changes, .. }
                    | Op::Landing {
                        receives: changes, ..
                    } => index
                        .checked_sub(1)
                        .and_then(|i| changes.get(i as usize))
                        .map_or(u64::MAX, |r| u64::from(r.0)),
                    Op::Intrinsic { .. }
                    | Op::Store { .. }
                    | Op::Const(_)
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
                    | Op::Load { .. } => u64::from(index),
                };
                let number = match self.mode {
                    Mode::Shape => named(&core::mem::discriminant(op)),
                    Mode::Round | Mode::Last => {
                        self.root_number.get(&inst).copied().unwrap_or(u64::MAX)
                    }
                };
                record(Tag::Result, &[number, which, width], &[])
            }
        }
    }

    /// A 1-bit condition's hash: its base, negated if it is.
    fn negatable(&mut self, value: Value) -> u128 {
        let (negated, base) = self.condition(value);
        if negated {
            record(Tag::Not, &[], &[base])
        } else {
            base
        }
    }

    /// The hash of `value`, `op` of `a` and `b`.
    fn binary(&mut self, value: Value, op: Binary, a: Value, b: Value, width: u64) -> u128 {
        let class = match op {
            Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe | Binary::SLt | Binary::SLe => {
                return self.negatable(value);
            }
            Binary::Xor if width == 1 && (self.is_one(a) || self.is_one(b)) => {
                return self.negatable(value);
            }
            Binary::Xor | Binary::Sub if self.resolve(a) == self.resolve(b) => {
                return self.immediate(&Bits::from_u64(u16::try_from(width).unwrap_or(64), 0));
            }
            Binary::Add | Binary::Sub => "add",
            Binary::Mul => "mul",
            Binary::UDiv | Binary::URem | Binary::SDiv | Binary::SRem => "div",
            Binary::And | Binary::Or | Binary::Xor => "logic",
            Binary::Shl | Binary::LShr | Binary::AShr | Binary::Rol | Binary::Ror => "shift",
        };
        self.count(value, class);
        // `x - c` as `x + -c` (but `x - &g`, which is a slot).
        let subtrahend = self.resolve(b);
        if op == Binary::Sub
            && let Some(bits) = self.input.constants.constant(subtrahend)
            && !self.derived(subtrahend)
        {
            let constant = self.constant_of(subtrahend, &bits.wrapping_neg());
            let mut pair = [self.hash(a), constant];
            pair.sort_unstable();
            return record(Tag::Binary, &[named(&Binary::Add), width], &pair);
        }
        let commutative = matches!(
            op,
            Binary::Add | Binary::Mul | Binary::And | Binary::Or | Binary::Xor
        );
        let operands = if commutative {
            let mut pair = self.sorted(&[a, b]);
            pair.sort_unstable();
            pair
        } else {
            vec![self.hash(a), self.hash(b)]
        };
        record(Tag::Binary, &[named(&op), width], &operands)
    }

    /// The argument mask of a call to `target` with `registers`: the
    /// callee's reads if known, else the argument registers written since
    /// entry.
    fn call_mask(&mut self, target: Option<u64>, registers: &[Value]) -> u32 {
        if let Some(mask) = target.and_then(|t| self.surroundings.reads(t)) {
            return mask;
        }
        let mut mask = 0;
        let integers = self.input.abi.arguments.len();
        for (bit, register) in self.input.abi.argument_registers().iter().enumerate() {
            let Some(&value) = registers.get(usize::from(register.0)) else {
                continue;
            };
            let value = self.resolve(value);
            // A vector register counts only holding a floating-point
            // result, not a copy's data left in it.
            if self.entry.get(&value).copied().flatten() != Some(usize::from(register.0))
                && (bit < integers || self.floating(value))
            {
                mask |= 1 << bit;
            }
        }
        mask
    }

    /// The import slot `target` is loaded from, if it is the whole of one
    /// ([`Surroundings::import`]): `call [__imp_X]`, `call [rip+GOT]`.
    fn import_slot(&mut self, target: Value) -> Option<u64> {
        slot_of(self.input, target).filter(|&slot| self.surroundings.import(slot))
    }

    /// A call's (or tail call's) target and arguments.
    fn call(&mut self, tag: Tag, at: u64, target: Value, registers: &[Value], extra: u64) -> u128 {
        let target = self.resolve(target);
        let constant = self
            .input
            .constants
            .constant(target)
            .filter(|bits| bits.width() == 64)
            .map(|bits| bits.low_u64());
        // A call of a PLT entry is a call of its import: what it reads is
        // not known.
        let stub = constant.and_then(|address| self.surroundings.stub(address));
        let constant = constant.filter(|_| stub.is_none());
        let target_hash = match constant {
            Some(address) if self.surroundings.referent(address).is_some() => {
                self.slot(address, true)
            }
            Some(_) => self.hash(target),
            // Through an import's slot: the import, its slot's code slot.
            None => match stub.or_else(|| self.import_slot(target)) {
                Some(slot) => self.slot(slot, true),
                None => self.hash(target),
            },
        };
        let mask = self.call_mask(constant, registers);
        if self.mode == Mode::Last {
            self.masks.insert(at, mask);
        }
        let mut operands = vec![target_hash];
        for (bit, register) in self.input.abi.argument_registers().iter().enumerate() {
            if mask & (1 << bit) != 0
                && let Some(&value) = registers.get(usize::from(register.0))
            {
                // An argument is at most a word (a vector register's
                // `double`): its upper bits carry nothing.
                operands.push(self.project(value, 0, 64.min(self.width(value))));
            }
        }
        record(tag, &[u64::from(mask), extra], &operands)
    }

    /// The hash of root `inst`.
    fn root(&mut self, id: InstId) -> u128 {
        let Some(inst) = self.function().inst(id) else {
            return 0;
        };
        match &inst.op {
            Op::Store {
                memory,
                address,
                value,
                ..
            } => {
                let bytes = u64::from(self.width(*value) / 8);
                if self.mode == Mode::Last {
                    *self
                        .fingerprint
                        .ops
                        .entry(format!("store{bytes}"))
                        .or_default() += 1;
                }
                let operands = [self.hash(*address), self.hash(*value), self.hash(*memory)];
                record(Tag::Store, &[bytes], &operands)
            }
            Op::Call {
                target,
                memory,
                registers,
                ..
            } => {
                if self.mode == Mode::Last {
                    self.fingerprint.calls += 1;
                }
                let memory = self.hash(*memory);
                let call = self.call(Tag::Call, inst.address, *target, registers, 0);
                record(Tag::Call, &[], &[call, memory])
            }
            Op::SystemCall {
                memory, registers, ..
            } => {
                if self.mode == Mode::Last {
                    self.fingerprint.system_calls += 1;
                }
                let mut operands = vec![self.hash(*memory)];
                for register in self.input.abi.system_call.clone() {
                    if let Some(&value) = registers.get(usize::from(register.0)) {
                        operands.push(self.hash(value));
                    }
                }
                record(Tag::SystemCall, &[], &operands)
            }
            Op::Intrinsic {
                intrinsic,
                memory,
                inputs,
            } => {
                let name = self
                    .input
                    .abi
                    .declarations
                    .intrinsic(*intrinsic)
                    .map_or(u64::from(intrinsic.0), |info| named(&info.name));
                let mut operands = vec![self.hash(*memory)];
                for &input in inputs {
                    operands.push(self.hash(input));
                }
                record(Tag::Intrinsic, &[name], &operands)
            }
            Op::Landing { memory, .. } => {
                let memory = self.hash(*memory);
                record(Tag::Landing, &[], &[memory])
            }
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
            | Op::Load { .. } => 0,
        }
    }

    /// The hash of the terminator of `block`, the last of node `node`.
    fn terminator(&mut self, block: BlockId, negated: bool) -> u128 {
        let Some(info) = self.function().block(block) else {
            return 0;
        };
        let last = self.mode == Mode::Last;
        match &info.terminator {
            Terminator::Jump(_) => record(Tag::Jump, &[], &[]),
            Terminator::Branch { condition, .. } => {
                let (_, base) = self.condition(*condition);
                record(Tag::Branch, &[u64::from(negated)], &[base])
            }
            Terminator::IndirectJump { address, targets } => {
                let address = self.hash(*address);
                record(Tag::IndirectJump, &[targets.len() as u64], &[address])
            }
            Terminator::Return { state, .. } => {
                if last {
                    self.fingerprint.returns += 1;
                }
                let mut operands = vec![self.hash(state.memory)];
                for register in self.returned(&state.registers) {
                    if let Some(&value) = state.registers.get(usize::from(register.0)) {
                        let resolved = self.resolve(value);
                        if last
                            && self.entry.get(&resolved).copied().flatten()
                                != Some(usize::from(register.0))
                        {
                            self.fingerprint.results.insert(register.0);
                        }
                        operands.push(self.project(value, 0, 64.min(self.width(value))));
                    }
                }
                record(Tag::Return, &[], &operands)
            }
            Terminator::Leave {
                address,
                state,
                returns,
            } => {
                if last {
                    self.fingerprint.calls += 1;
                }
                let memory = self.hash(state.memory);
                let call = self.call(
                    Tag::Leave,
                    info.end,
                    *address,
                    &state.registers,
                    u64::from(*returns),
                );
                record(Tag::Leave, &[], &[call, memory])
            }
            Terminator::Trap(trap) => {
                if last {
                    self.fingerprint.traps += 1;
                }
                record(Tag::Trap, &[named(trap)], &[])
            }
            Terminator::Stop => record(Tag::Stop, &[], &[]),
            Terminator::Invoke { .. } => record(Tag::Invoke, &[], &[]),
            Terminator::Open => record(Tag::Open, &[], &[]),
        }
    }

    /// The record of node `index`.
    fn node(&mut self, index: usize) -> u128 {
        let Some(node) = self.nodes.get(index).cloned() else {
            return 0;
        };
        let function = self.function();
        // Roots in order, but each run of stores between other roots
        // sorted: the order of independent stores is the compiler's.
        let mut operands = Vec::new();
        let mut stores: Vec<u128> = Vec::new();
        for &block in &node.blocks {
            let Some(info) = function.block(block) else {
                continue;
            };
            for id in &info.insts {
                if !self.roots.contains(id) {
                    continue;
                }
                let hash = self.root(*id);
                if matches!(function.inst(*id).map(|i| &i.op), Some(Op::Store { .. })) {
                    stores.push(hash);
                } else {
                    stores.sort_unstable();
                    operands.append(&mut stores);
                    operands.push(hash);
                }
            }
        }
        stores.sort_unstable();
        operands.append(&mut stores);
        if let Some(&last) = node.blocks.last() {
            operands.push(self.terminator(last, node.negated));
        }
        let successors: Vec<u64> = node.successors.iter().map(|&s| s as u64).collect();
        record(Tag::Node, &successors, &operands)
    }

    /// One refinement round: every reachable block parameter's hash from
    /// the values coming in, in canonical order of the ways in.
    fn refine(&mut self, phis: &mut HashMap<Value, u128>) {
        let function = self.function();
        for index in 0..self.nodes.len() {
            let _ = self.node(index);
        }
        for (block_index, info) in function.blocks.iter().enumerate() {
            let block = BlockId(u32::try_from(block_index).unwrap_or(u32::MAX));
            if block.0 == 0 || !self.reachable.get(block_index).copied().unwrap_or(false) {
                continue;
            }
            let Some(&node) = self.node_of.get(&block) else {
                continue;
            };
            // The ways in, by the canonical number of the node they leave.
            let mut ways: Vec<(u64, usize, BlockId, usize)> = self
                .predecessors
                .get(block_index)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|(from, jump)| {
                    let order = self.order_of(from);
                    (order, jump, from, jump)
                })
                .collect();
            ways.sort_unstable_by_key(|&(order, jump, ..)| (order, jump));
            for (position, &parameter) in info.parameters.iter().enumerate() {
                let mut incoming = Vec::new();
                for &(.., from, jump) in &ways {
                    let argument = function
                        .block(from)
                        .and_then(|b| b.terminator.targets().nth(jump))
                        .and_then(|t: &Target| t.arguments.get(position))
                        .copied();
                    if let Some(argument) = argument {
                        incoming.push(self.hash(argument));
                    }
                }
                let width = u64::from(self.width(parameter));
                phis.insert(
                    parameter,
                    record(Tag::Phi, &[node as u64, width], &incoming),
                );
            }
        }
    }

    /// The canonical number of the node `block` is in (passed-through
    /// blocks: the node they lead to; the entry block: none).
    fn order_of(&self, block: BlockId) -> u64 {
        if let Some(&node) = self.node_of.get(&block) {
            return node as u64;
        }
        if block.0 == 0 {
            return u64::MAX;
        }
        // A block that only jumps on: by where it goes, after the others.
        u64::MAX - 1
    }

    /// The last round: every node's record, hashed in order.
    fn serialize(&mut self) -> u128 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&VERSION.to_le_bytes());
        for index in 0..self.nodes.len() {
            let record = self.node(index);
            hasher.update(&record.to_le_bytes());
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        u128::from_le_bytes(out)
    }

    fn finish(mut self, identity: u128) -> Canonical {
        let operations = self
            .operations
            .saturating_add(u32::try_from(self.root_number.len()).unwrap_or(u32::MAX));
        let mut back = 0;
        for (index, node) in self.nodes.iter().enumerate() {
            back +=
                u32::try_from(node.successors.iter().filter(|&&s| s <= index).count()).unwrap_or(0);
        }
        let fingerprint = &mut self.fingerprint;
        fingerprint.blocks = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
        fingerprint.loops = back;
        fingerprint.size = operations;
        let trivial = operations < TRIVIAL_OPERATIONS
            && fingerprint.strings.is_empty()
            && fingerprint.constants.is_empty()
            && fingerprint.system_calls == 0;
        Canonical {
            identity: Identity(identity),
            operations,
            trivial,
            fingerprint: self.fingerprint,
            code: self.code,
            data: self.data,
            masks: self.masks,
        }
    }
}

/// What a function does with its argument registers' entry values
/// ([`reads`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reads {
    /// The argument registers (a mask over [`Abi::arguments`]) whose entry
    /// values it uses itself.
    pub direct: u32,
    /// Those it passes on unchanged to a call or tail call, with the
    /// callee's address if constant: it reads them if the callee does.
    pub forwards: Vec<(Option<u64>, u32)>,
}

/// Which argument registers `input`'s function reads before writing
/// ([`Reads`]): those whose entry values a store, branch, system call,
/// intrinsic, result register or a call's argument computed from them
/// uses; those passed on unchanged to a callee are forwarded, for the
/// caller to resolve against the callee's own reads.
#[expect(
    clippy::too_many_lines,
    reason = "the roots, then the walk back from them"
)]
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "every other operation reads its operands"
)]
pub fn reads(input: Input<'_>) -> Reads {
    let function = input.function;
    let abi = input.abi;
    let mut entry: HashMap<Value, usize> = HashMap::new();
    if let Some(block) = function.blocks.first() {
        for (index, &parameter) in block.parameters.iter().enumerate() {
            entry.insert(parameter, index);
        }
    }
    let arguments = abi.argument_registers();
    let bit_of = |register: usize| arguments.iter().position(|r| usize::from(r.0) == register);
    let mut predecessors: Vec<Vec<(BlockId, usize)>> = vec![Vec::new(); function.blocks.len()];
    for (index, block) in function.blocks.iter().enumerate() {
        for (jump, target) in block.terminator.targets().enumerate() {
            if let Some(list) = predecessors.get_mut(target.block.0 as usize) {
                list.push((BlockId(u32::try_from(index).unwrap_or(u32::MAX)), jump));
            }
        }
    }
    let mut observed: BTreeSet<(Value, bool)> = BTreeSet::new();
    // Each value with whether it is an operand of a floating-point or
    // lane operation (a vector register's entry value counts only so).
    let mut work: Vec<(Value, bool)> = Vec::new();
    let mut forwards: BTreeMap<Option<u64>, u32> = BTreeMap::new();
    // Arguments at a call: entry values of the same register forwarded,
    // anything else used.
    let mut call = |target: Value, registers: &[Value], work: &mut Vec<(Value, bool)>| {
        let callee = input
            .constants
            .constant(target)
            .filter(|bits| bits.width() == 64)
            .map(|bits| bits.low_u64());
        for register in &arguments {
            let Some(&value) = registers.get(usize::from(register.0)) else {
                continue;
            };
            let parts = low_word(input, value);
            if parts
                .iter()
                .all(|&part| untouched(input, &predecessors, &entry, part, usize::from(register.0)))
            {
                if let Some(bit) = bit_of(usize::from(register.0)) {
                    *forwards.entry(callee).or_default() |= 1 << bit;
                }
            } else {
                work.extend(parts.into_iter().map(|part| (part, false)));
            }
        }
        if callee.is_none() {
            work.push((target, false));
        }
    };
    for (index, block) in function.blocks.iter().enumerate() {
        if !input
            .constants
            .reachable(BlockId(u32::try_from(index).unwrap_or(u32::MAX)))
        {
            continue;
        }
        for id in &block.insts {
            let Some(inst) = function.inst(*id) else {
                continue;
            };
            match &inst.op {
                Op::Store { address, value, .. } => {
                    // A store to the frame (a spill, a variadic
                    // prologue's register save area) reads nothing until
                    // something loads it back.
                    if input.stack.offset(*address).is_none() {
                        work.push((*address, false));
                        work.push((*value, false));
                    }
                }
                Op::Intrinsic { inputs, .. } => {
                    work.extend(inputs.iter().map(|&input| (input, false)));
                }
                Op::SystemCall { registers, .. } => {
                    for register in &abi.system_call {
                        if let Some(&value) = registers.get(usize::from(register.0)) {
                            work.push((value, false));
                        }
                    }
                }
                Op::Call {
                    target, registers, ..
                } => call(*target, registers, &mut work),
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
                | Op::Load { .. }
                | Op::Landing { .. } => {}
            }
        }
        match &block.terminator {
            Terminator::Branch { condition, .. } => work.push((*condition, false)),
            Terminator::IndirectJump { address, .. } => work.push((*address, false)),
            Terminator::Return { state, .. } => {
                // A result register still holding its entry value is no
                // read of it; nor a vector register holding other than a
                // floating-point result (as [`Canon::returned`]).
                let returned =
                    abi.results
                        .first()
                        .into_iter()
                        .chain(abi.float_results.first().filter(|r| {
                            state.registers.get(usize::from(r.0)).is_some_and(|&v| {
                                floating(function, &|v| input.stack.resolve(function, v), v)
                            })
                        }));
                for register in returned {
                    if let Some(&value) = state.registers.get(usize::from(register.0)) {
                        for part in low_word(input, value) {
                            if !untouched(
                                input,
                                &predecessors,
                                &entry,
                                part,
                                usize::from(register.0),
                            ) {
                                work.push((part, false));
                            }
                        }
                    }
                }
            }
            Terminator::Leave { address, state, .. } => {
                call(*address, &state.registers, &mut work);
            }
            Terminator::Jump(_)
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Invoke { .. }
            | Terminator::Open => {}
        }
    }
    let mut direct = 0;
    let integers = abi.arguments.len();
    while let Some((value, numeric)) = work.pop() {
        if !observed.insert((value, numeric)) || input.constants.constant(value).is_some() {
            continue;
        }
        match function.value(value).map(|info| info.definition) {
            Some(Definition::Parameter { block, index }) if block.0 == 0 => {
                if let Some(bit) = entry.get(&value).copied().and_then(bit_of)
                    && (bit < integers || numeric)
                {
                    direct |= 1 << bit;
                }
                let _ = index;
            }
            Some(Definition::Parameter { block, index }) => {
                for &(from, jump) in predecessors.get(block.0 as usize).into_iter().flatten() {
                    if let Some(&argument) = function
                        .block(from)
                        .and_then(|b| b.terminator.targets().nth(jump))
                        .and_then(|t| t.arguments.get(index as usize))
                    {
                        work.push((argument, numeric));
                    }
                }
            }
            Some(Definition::Result { inst, .. }) => {
                let Some(inst) = function.inst(inst) else {
                    continue;
                };
                match &inst.op {
                    Op::Load { address, .. } => {
                        let stored = input.stack.resolve(function, value);
                        if stored == value {
                            work.push((*address, false));
                        } else {
                            work.push((stored, numeric));
                        }
                    }
                    Op::Call { .. }
                    | Op::SystemCall { .. }
                    | Op::Intrinsic { .. }
                    | Op::Landing { .. }
                    | Op::Store { .. } => {}
                    // `xor eax, eax`: zero, whatever the register held.
                    &Op::Binary(Binary::Xor | Binary::Sub, a, b) if same_bits(function, a, b) => {}
                    // Only the bits it extracts.
                    &Op::Extract {
                        value: source,
                        offset,
                        width,
                    } => {
                        let resolve = |v| input.stack.resolve(function, v);
                        for (part, ..) in
                            project(function, &resolve, input.constants, source, offset, width)
                        {
                            if let Projection::Bits(base) = part {
                                work.push((base, numeric));
                            }
                        }
                    }
                    other @ (Op::Float { .. } | Op::Lanes { .. }) => {
                        work.extend(other.operands().into_iter().map(|operand| (operand, true)));
                    }
                    other => work.extend(
                        other
                            .operands()
                            .into_iter()
                            .map(|operand| (operand, numeric)),
                    ),
                }
            }
            None => {}
        }
    }
    Reads {
        direct,
        forwards: forwards
            .into_iter()
            .map(|(callee, mask)| (callee, mask & !direct))
            .filter(|&(_, mask)| mask != 0)
            .collect(),
    }
}

/// The constant address of the 8-byte slot `target` is loaded from, if
/// it is one (`call [slot]`), seen through the stack.
fn slot_of(input: Input<'_>, target: Value) -> Option<u64> {
    let function = input.function;
    let target = input.stack.resolve(function, target);
    let Some(Definition::Result { inst, .. }) = function.value(target).map(|v| v.definition) else {
        return None;
    };
    let Some(&Op::Load { address, bytes, .. }) = function.inst(inst).map(|i| &i.op) else {
        return None;
    };
    let address = input.stack.resolve(function, address);
    let slot = input.constants.constant(address)?;
    (bytes == 8 && slot.width() == 64).then(|| slot.low_u64())
}

/// Whether `value` is register `register`'s entry value wherever it is
/// computed: that value (a stack slot it was saved in included), or a
/// block parameter every way into which passes such a value (or the
/// parameter itself, round a loop).
fn untouched(
    input: Input<'_>,
    predecessors: &[Vec<(BlockId, usize)>],
    entry: &HashMap<Value, usize>,
    value: Value,
    register: usize,
) -> bool {
    let function = input.function;
    let mut seen = BTreeSet::new();
    let mut work = vec![value];
    while let Some(value) = work.pop() {
        let value = input.stack.resolve(function, value);
        if !seen.insert(value) {
            continue;
        }
        if let Some(&index) = entry.get(&value) {
            if index != register {
                return false;
            }
            continue;
        }
        let Some(Definition::Parameter { block, index }) =
            function.value(value).map(|v| v.definition)
        else {
            return false;
        };
        let Some(ways) = predecessors.get(block.0 as usize) else {
            return false;
        };
        if ways.is_empty() || seen.len() > 4096 {
            return false;
        }
        for &(from, jump) in ways {
            let Some(&argument) = function
                .block(from)
                .and_then(|b| b.terminator.targets().nth(jump))
                .and_then(|t| t.arguments.get(index as usize))
            else {
                return false;
            };
            work.push(argument);
        }
    }
    true
}

/// Whether the low part of `value` comes from a floating-point operation
/// (through the concatenations, extractions and extensions of partial
/// register writes), each value seen through `resolve`.
fn floating(function: &Function, resolve: &dyn Fn(Value) -> Value, value: Value) -> bool {
    let mut current = resolve(value);
    for _ in 0..16 {
        let next = match function.value(current).map(|v| v.definition) {
            Some(Definition::Result { inst, .. }) => match function.inst(inst).map(|i| &i.op) {
                Some(Op::Float { .. }) => return true,
                Some(&Op::Concat { low, .. }) => low,
                Some(
                    &Op::Extract {
                        value: source,
                        offset: 0,
                        ..
                    }
                    | &Op::Extend { value: source, .. },
                ) => source,
                _ => return false,
            },
            _ => return false,
        };
        current = resolve(next);
    }
    false
}

/// Whether `a` and `b` hold the same bits whatever those are: one value,
/// or the same bits extracted from one (`xor edx, edx`).
fn same_bits(function: &Function, a: Value, b: Value) -> bool {
    let extraction = |v: Value| match function.value(v).map(|info| info.definition) {
        Some(Definition::Result { inst, .. }) => match function.inst(inst).map(|i| &i.op) {
            Some(&Op::Extract {
                value,
                offset,
                width,
            }) => Some((value, offset, width)),
            _ => None,
        },
        _ => None,
    };
    a == b || extraction(a).is_some_and(|x| extraction(b) == Some(x))
}

/// What bits of a value come down to ([`project`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Projection {
    /// Bits of this value.
    Bits(Value),
    /// Zeros (above a zero extension).
    Zero,
}

/// Bits `offset`.. `offset + width` of `value`, looked for through
/// concatenations (the parts they lie in), zero extensions and
/// extractions (each value seen through `resolve`; constants are not
/// looked through): the values they are bits of, and where, low bits
/// first.
fn project(
    function: &Function,
    resolve: &dyn Fn(Value) -> Value,
    constants: &Constants,
    value: Value,
    offset: u16,
    width: u16,
) -> Vec<(Projection, u16, u16)> {
    let mut parts = Vec::new();
    project_into(
        function, resolve, constants, value, offset, width, 0, &mut parts,
    );
    parts
}

/// [`project`], appending to `parts`, `depth` deep.
#[expect(clippy::too_many_arguments, reason = "a recursion's state")]
fn project_into(
    function: &Function,
    resolve: &dyn Fn(Value) -> Value,
    constants: &Constants,
    value: Value,
    offset: u16,
    width: u16,
    depth: u32,
    parts: &mut Vec<(Projection, u16, u16)>,
) {
    let bits = |v: Value| match function.ty(v) {
        Some(Type::Bits(width)) => width,
        Some(Type::Memory) | None => 0,
    };
    let value = resolve(value);
    let defined = function.value(value).and_then(|v| match v.definition {
        Definition::Result { inst, .. } => function.inst(inst).map(|i| &i.op),
        Definition::Parameter { .. } => None,
    });
    let op = if depth >= 64 || constants.constant(value).is_some() {
        None
    } else {
        defined
    };
    match op {
        Some(&Op::Concat { high, low }) => {
            let split = bits(low);
            if offset + width <= split {
                project_into(
                    function,
                    resolve,
                    constants,
                    low,
                    offset,
                    width,
                    depth + 1,
                    parts,
                );
            } else if offset >= split {
                project_into(
                    function,
                    resolve,
                    constants,
                    high,
                    offset - split,
                    width,
                    depth + 1,
                    parts,
                );
            } else {
                project_into(
                    function,
                    resolve,
                    constants,
                    low,
                    offset,
                    split - offset,
                    depth + 1,
                    parts,
                );
                project_into(
                    function,
                    resolve,
                    constants,
                    high,
                    0,
                    offset + width - split,
                    depth + 1,
                    parts,
                );
            }
        }
        Some(&Op::Extract {
            value: source,
            offset: inner,
            ..
        }) => project_into(
            function,
            resolve,
            constants,
            source,
            offset + inner,
            width,
            depth + 1,
            parts,
        ),
        Some(&Op::Extend {
            signed,
            value: source,
            ..
        }) if offset + width <= bits(source) || (offset >= bits(source) && !signed) => {
            if offset >= bits(source) {
                parts.push((Projection::Zero, offset, width));
            } else {
                project_into(
                    function,
                    resolve,
                    constants,
                    source,
                    offset,
                    width,
                    depth + 1,
                    parts,
                );
            }
        }
        _ => parts.push((Projection::Bits(value), offset, width)),
    }
}

/// The values the low word (at most 64 bits) of `value` is made of
/// ([`project`]): what an argument or result in a register carries.
fn low_word(input: Input<'_>, value: Value) -> Vec<Value> {
    let function = input.function;
    let width = match function.ty(value) {
        Some(Type::Bits(width)) => width.min(64),
        Some(Type::Memory) | None => return Vec::new(),
    };
    project(
        function,
        &|v| input.stack.resolve(function, v),
        input.constants,
        value,
        0,
        width,
    )
    .into_iter()
    .filter_map(|(part, ..)| match part {
        Projection::Bits(base) => Some(base),
        Projection::Zero => None,
    })
    .collect()
}
