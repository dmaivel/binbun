//! What is needed (the values effects, conditions, jumps and the return
//! value use, transitively), the parameters, and how each needed value is
//! lowered ([`Role`]): inline, a parameter, folded into its one use, or a
//! variable.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::Origin;
use binbun_ast::types::{Evidence, TypeId};
use binbun_semantics::ir::{Binary, LaneOp, RegisterId};
use binbun_ssa::condition::{FloatRelation, comparison, float_relation};
use binbun_ssa::implied::{Key, zero_test};
use binbun_ssa::ir::{BlockId, Definition, InstId, Op, Terminator, Value};
use binbun_ssa::stack::{authenticated_entry, entry_value, top_byte_view};

use super::facts::{Def, Kind, Lowering, Site};
use super::frame::Home;
use crate::mapping::{Piece, Source};
use crate::validate::Link;

/// What of calls' register arguments counts as needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Passing {
    /// Every argument.
    All,
    /// What an argument is computed from, where it is not only entry
    /// values passed on unchanged through block parameters
    /// ([`Lowering::computed`]).
    Computed,
    /// None.
    None,
}

/// On which runs a value is used ([`Lowering::needed_from`]): none, only
/// those where a test of a value against zero holds as stated (its
/// [`Key`] and whether the value is zero there), or any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Under {
    Never,
    When(Key, bool),
    Always,
}

impl Under {
    /// What a value used on the runs of `self` and on those of `other` is
    /// used on: one guard alone if both are it, else any run.
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Never, under) | (under, Self::Never) => under,
            (Self::When(a, za), Self::When(b, zb)) if a == b && za == zb => self,
            (Self::When(..) | Self::Always, Self::When(..) | Self::Always) => Self::Always,
        }
    }
}

/// A use by a statement or a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Use {
    /// The low `bits` bits of a value.
    Value(Value, u16),
    /// A read of a slot (a local's or a stack parameter's).
    Slot(usize),
}

/// A parameter of the function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Parameter {
    /// Where it is at entry.
    pub(super) source: Source,
    /// Its type.
    pub(super) ty: TypeId,
    /// Why it has that type.
    pub(super) evidence: Evidence,
    /// Its register or stack slot.
    pub(super) origin: Origin,
}

/// How a needed value is lowered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    /// Not needed.
    None,
    /// An expression wherever it is used (a constant, an undefined value,
    /// a stack address, a stack parameter's read).
    Inline,
    /// A register's entry value: its parameter's variable.
    Parameter(usize),
    /// Folded into its one use, evaluated at this position of its block.
    Fold(u32),
    /// A load kept only for its fault: evaluated and dropped.
    Drop,
    /// A variable.
    Var,
}

/// What is needed, and how it is lowered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Needed {
    /// Per canonical value: whether it is needed.
    pub(super) values: Vec<bool>,
    /// Per canonical value: how many of its low bits are used.
    pub(super) bits: Vec<u16>,
    /// Per slot: whether a needed read reads it.
    pub(super) slots: Vec<bool>,
    /// The parameters, in order.
    pub(super) parameters: Vec<Parameter>,
    /// The parameter of each register's entry value.
    pub(super) registers: BTreeMap<RegisterId, usize>,
    /// The parameter of each stack slot.
    pub(super) stack: BTreeMap<usize, usize>,
    /// The bytes of the frame's memory that hold a stack argument the
    /// function reads (first byte from the entry stack pointer, how
    /// many), each with its parameter: they take its value at entry.
    pub(super) entry: Vec<(i64, u16, usize)>,
    /// The thread pointer and the floating-point control register, where
    /// their entry values are needed and the function leaves them as the
    /// convention requires: read from environment variables, no
    /// parameters ([`Lowering::environment_registers`]).
    pub(super) environment: Vec<RegisterId>,
    /// Per canonical value: how it is lowered.
    pub(super) roles: Vec<Role>,
}

/// Where a value is used, when it has one use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum User {
    /// By another value.
    Value(Value),
    /// By the statement at this position.
    At(Def),
}

/// How many extensions, extractions and operations [`Lowering::significant`]
/// and [`Lowering::low_part`] look through.
const PEEL: usize = 8;

/// The most stack parameters added for the stack arguments a function
/// does not read ([`Lowering::find_parameters`]).
const PADDING: usize = 64;

impl Lowering<'_, '_> {
    /// The uses of value `v` (canonical) by its own definition.
    pub(super) fn inputs(&self, v: Value) -> Vec<Use> {
        let full = |value: Value| Use::Value(value, self.width(value));
        match self.kind(v) {
            Kind::Pure(inst) => {
                let Some(i) = self.l1.inst(inst) else {
                    return Vec::new();
                };
                if let Some(relation) = self.float_relation(v) {
                    return vec![full(relation.left), full(relation.right)];
                }
                if self.width(v) == 1
                    && let Some(compare) = self.compare(v)
                {
                    return vec![full(compare.left), full(compare.right)];
                }
                match i.op {
                    Op::Extract {
                        value,
                        offset,
                        width,
                    } => {
                        vec![Use::Value(value, offset.saturating_add(width))]
                    }
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
                    | Op::Landing { .. } => i.op.operands().into_iter().map(full).collect(),
                }
            }
            Kind::Load(inst) => {
                let Some(&Op::Load { address, .. }) = self.l1.inst(inst).map(|i| &i.op) else {
                    return Vec::new();
                };
                match self.frame.accesses.get(&inst) {
                    Some(&slot) if self.home(slot) != Home::Frame => vec![Use::Slot(slot)],
                    Some(_) | None => vec![full(address)],
                }
            }
            Kind::Phi => {
                let Some(&binbun_ssa::ir::ValueInfo {
                    definition: Definition::Parameter { block, index },
                    ..
                }) = self.l1.value(v)
                else {
                    return Vec::new();
                };
                self.incoming(block, index as usize)
                    .into_iter()
                    .map(|(_, argument)| full(argument))
                    .collect()
            }
            // A keyed hash is not a statement of its own (see `needed`):
            // what uses its value needs its inputs.
            Kind::Result(inst) if self.keyed_hash(inst) => self.statement_uses(inst),
            Kind::None
            | Kind::Const(_)
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => Vec::new(),
        }
    }

    /// The comparison 1-bit value `v` is, if it is one.
    pub(super) fn compare(&self, v: Value) -> Option<binbun_ssa::condition::Comparison> {
        if self.float_relation(v).is_some() {
            return None;
        }
        comparison(self.l1, self.constants, v)
    }

    /// The float relation value `v` is, if it is one: 1 for some
    /// outcomes of one float comparison and 0 for the others, however
    /// the flags it left were combined ([`float_relation`]).
    pub(super) fn float_relation(&self, v: Value) -> Option<FloatRelation> {
        float_relation(self.l1, self.constants, v)
    }

    /// Whether `inst` is a keyed hash: an intrinsic whose inputs do not
    /// escape (`compute_pac`), which has no effect.
    pub(super) fn keyed_hash(&self, inst: InstId) -> bool {
        matches!(
            self.l1.inst(inst).map(|i| &i.op),
            Some(&Op::Intrinsic { intrinsic, .. })
                if self
                    .cx
                    .declarations
                    .intrinsic(intrinsic)
                    .is_some_and(|info| !info.escapes)
        )
    }

    /// Whether `inst` is a keyed hash ([`Self::keyed_hash`]) no needed
    /// value comes from: it has no effect to show.
    pub(super) fn idle_hash(&self, inst: InstId) -> bool {
        self.keyed_hash(inst)
            && self.l1.inst(inst).is_some_and(|i| {
                !i.results
                    .iter()
                    .any(|&result| self.width(result) > 0 && self.is_needed(result))
            })
    }

    /// Where slot `slot` lives.
    pub(super) fn home(&self, slot: usize) -> Home {
        self.frame.slots.get(slot).map_or(Home::Frame, |s| s.home)
    }

    /// The uses of value `v` (canonical) by its own definition when only
    /// its low `bits` bits are used: as [`inputs`](Self::inputs), but a
    /// concatenation uses its high part only if bits of it are used, and
    /// its low part, an extension's operand and an extraction's source
    /// only as far as the used bits reach. So the bits a register keeps
    /// through a narrower write (SSE's `movsd` keeps the rest of `zmm0`)
    /// are not used unless something reads them, nor through a block
    /// parameter (a block's arguments are used as far as its parameter's
    /// used bits reach).
    fn demanded(&self, v: Value, bits: u16) -> Vec<Use> {
        if self.kind(v) == Kind::Phi {
            return self
                .inputs(v)
                .into_iter()
                .map(|used| match used {
                    Use::Value(value, width) => Use::Value(value, width.min(bits)),
                    Use::Slot(_) => used,
                })
                .collect();
        }
        let Kind::Pure(inst) = self.kind(v) else {
            return self.inputs(v);
        };
        if self.float_relation(v).is_some() || (self.width(v) == 1 && self.compare(v).is_some()) {
            return self.inputs(v);
        }
        match self.l1.inst(inst).map(|i| &i.op) {
            Some(&Op::Concat { high, low }) => {
                let low_width = self.width(low);
                let mut uses = vec![Use::Value(low, bits.min(low_width))];
                if bits > low_width {
                    uses.push(Use::Value(high, bits - low_width));
                }
                uses
            }
            Some(&Op::Extend { value, .. }) => vec![Use::Value(value, bits.min(self.width(value)))],
            Some(&Op::Extract {
                value,
                offset,
                width,
            }) => vec![Use::Value(value, offset.saturating_add(bits.min(width)))],
            Some(&Op::Binary(Binary::And, a, b)) => {
                let (low_a, low_b) = self.and_reads(a, b);
                let within = if self.width(v) > 64 { bits } else { u16::MAX };
                vec![
                    Use::Value(a, low_a.min(within)),
                    Use::Value(b, low_b.min(within)),
                ]
            }
            // A bitwise operation on a vector register read only in its
            // low lane (`andps` with a mask, then `ucomisd`) reads that
            // lane of its operands: `Emit` takes the bits of each.
            Some(
                &(Op::Binary(Binary::Or | Binary::Xor, a, b)
                | Op::Lanes {
                    op: LaneOp::Binary(Binary::And | Binary::Or | Binary::Xor),
                    operands: [a, b, _],
                    ..
                }),
            ) if self.width(v) > 64 => vec![
                Use::Value(a, bits.min(self.width(a))),
                Use::Value(b, bits.min(self.width(b))),
            ],
            Some(_) | None => self.inputs(v),
        }
    }

    /// How many low bits of each operand of `a & b` the result reads: all
    /// of them, but only the low part of a concatenation the operand is
    /// ([`Self::low_part`]) where the other operand may have no bit set
    /// above it. So the bits a register keeps through a
    /// narrower write (`sete dl` keeps the rest of `rdx`) are not used by
    /// an `and` with a value that is 0 there (`and eax, edx` after `xor
    /// eax, eax; sete al`), and make no parameter. A mask alone narrows
    /// nothing (`edi & 4` reads `edi`): the operation's width is the
    /// evidence for its operand's. [`Emit`](super::emit) builds the
    /// operand from those bits, so what the others come from is not read.
    pub(super) fn and_reads(&self, a: Value, b: Value) -> (u16, u16) {
        let reads = |operand: Value, other: Value| {
            let width = self.width(operand);
            let low = self.significant(other, PEEL).max(1);
            self.low_part(operand, low)
                .map_or(width, |part| part.min(width))
        };
        (reads(a, b), reads(b, a))
    }

    /// An upper bound on how many low bits of `v` may be set: its bits
    /// from there up are 0 on every path. Looks through `depth`
    /// operations.
    fn significant(&self, v: Value, depth: usize) -> u16 {
        let v = self.canonical(v);
        let width = self.width(v);
        if let Kind::Const(bits) = self.kind(v) {
            let zeros = u16::try_from(bits.leading_zeros()).unwrap_or(0);
            return bits.width().saturating_sub(zeros).min(width);
        }
        let Some(depth) = depth.checked_sub(1) else {
            return width;
        };
        let bound = match self.defining(v).map(|(_, op)| op) {
            Some(&Op::Extend {
                signed: false,
                value,
                ..
            }) => self.significant(value, depth),
            Some(&Op::Extract { value, offset, .. }) => {
                self.significant(value, depth).saturating_sub(offset)
            }
            Some(&Op::Concat { high, low }) => match self.significant(high, depth) {
                0 => self.significant(low, depth),
                set => self.width(low).saturating_add(set),
            },
            Some(&Op::Binary(Binary::And, a, b)) => {
                self.significant(a, depth).min(self.significant(b, depth))
            }
            Some(&Op::Binary(Binary::Or | Binary::Xor, a, b)) => {
                self.significant(a, depth).max(self.significant(b, depth))
            }
            Some(_) | None => width,
        };
        bound.min(width)
    }

    /// The width of the low part of the concatenation `v` is, through
    /// extractions from bit 0 and extensions, where the low `low` bits of
    /// `v` are within it (reading only that part reads nothing of the
    /// concatenation's high part): no wider than any of the extractions
    /// and extended values on the way.
    fn low_part(&self, v: Value, low: u16) -> Option<u16> {
        let mut v = self.canonical(v);
        let mut within = self.width(v);
        for _ in 0..PEEL {
            if !matches!(self.kind(v), Kind::Pure(_)) {
                return None;
            }
            let inner = match self.defining(v).map(|(_, op)| op) {
                Some(&Op::Concat { low: part, .. }) => {
                    let part = self.width(part).min(within);
                    return (low <= part).then_some(part);
                }
                Some(&Op::Extract {
                    value,
                    offset: 0,
                    width,
                }) if low <= width => value,
                Some(&Op::Extend { value, .. }) if low <= self.width(value) => value,
                Some(_) | None => return None,
            };
            v = self.canonical(inner);
            within = within.min(self.width(v));
        }
        None
    }

    /// Whether store `inst` is lowered: not a call's push nor one a
    /// `va_start` stands for, and, to a local's slot, only if the slot is
    /// read.
    pub(super) fn store_lowered(&self, inst: InstId) -> bool {
        if self.frame.pushes.contains(&inst) || self.va_store(inst) {
            return false;
        }
        match self.frame.accesses.get(&inst) {
            Some(&slot) if self.home(slot) == Home::Local => {
                self.needed.slots.get(slot).copied().unwrap_or(false)
            }
            Some(_) | None => true,
        }
    }

    /// Whether `inst` is a store a `va_start` stands for.
    pub(super) fn va_store(&self, inst: InstId) -> bool {
        self.va.as_ref().is_some_and(|va| va.stores.contains(&inst))
    }

    /// The uses of instruction `inst` as a statement (none for a pure
    /// operation or a load, whose uses are their [`inputs`](Self::inputs)).
    pub(super) fn statement_uses(&self, inst: InstId) -> Vec<Use> {
        let Some(i) = self.l1.inst(inst) else {
            return Vec::new();
        };
        let full = |value: Value| Use::Value(value, self.width(value));
        if self.atomics.absorbed.contains(&inst) {
            return Vec::new();
        }
        match &i.op {
            // An update's operands as far as they are available where it
            // is evaluated ([`Lowering::early`]).
            Op::Load {
                address,
                atomic: Some(_),
                ..
            } if let Some((_, operands)) = self.atomics.updates.get(&inst) => {
                let at = i.results.first().map_or(Def::NONE, |&old| self.def(old));
                core::iter::once(*address)
                    .chain(
                        operands
                            .iter()
                            .filter_map(|&operand| self.early(operand, at)),
                    )
                    .map(full)
                    .collect()
            }
            Op::Load {
                address,
                atomic: Some(_),
                ..
            } => vec![full(*address)],
            Op::Store {
                address,
                value,
                atomic,
                ..
            } => {
                if self.frame.pushes.contains(&inst) {
                    return Vec::new();
                }
                match self.frame.accesses.get(&inst) {
                    Some(&slot) if atomic.is_none() && self.home(slot) != Home::Frame => {
                        vec![full(*value)]
                    }
                    Some(_) | None => vec![full(*address), full(*value)],
                }
            }
            Op::Call {
                target, registers, ..
            } => self.call_uses(Site::Call(inst), *target, registers, Passing::All),
            Op::Intrinsic { inputs, .. } => inputs.iter().map(|&v| full(v)).collect(),
            Op::SystemCall { registers, .. } => self
                .system_call_registers(inst)
                .iter()
                .filter_map(|r| registers.get(usize::from(r.0)))
                .map(|&v| full(v))
                .collect(),
            // A landing pad's values are what the unwinder hands the code:
            // no use.
            Op::Landing { .. }
            | Op::Load { atomic: None, .. }
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
            | Op::Float { .. } => Vec::new(),
        }
    }

    /// The uses of a call at `site` to `target` in a state of `registers`
    /// (and the stack pointer, for a call's `StackTrick` escape); its
    /// register arguments as `arguments` says ([`Passing`]).
    fn call_uses(
        &self,
        site: Site,
        target: Value,
        registers: &[Value],
        arguments: Passing,
    ) -> Vec<Use> {
        let Some(callee) = self.callees.get(&site) else {
            return Vec::new();
        };
        let mut uses = Vec::new();
        let sp = registers.get(usize::from(self.cx.stack_pointer.0)).copied();
        if self.frame.tricks.contains(&site)
            && let Some(sp) = sp
        {
            uses.push(Use::Value(sp, self.width(sp)));
        }
        if callee.foreign || (callee.target.is_none() && callee.import.is_none()) {
            uses.push(Use::Value(target, self.width(target)));
        }
        if callee.foreign {
            return uses;
        }
        for (index, source) in callee.arguments.iter().enumerate() {
            match *source {
                Source::Register(Piece {
                    register,
                    offset,
                    width,
                }) => {
                    if let Some(&value) = registers.get(usize::from(register.0)) {
                        match arguments {
                            Passing::All => {
                                uses.push(Use::Value(value, offset.saturating_add(width)));
                            }
                            Passing::Computed => uses.extend(
                                self.computed(value)
                                    .into_iter()
                                    .map(|leaf| Use::Value(leaf, self.width(leaf))),
                            ),
                            Passing::None => {}
                        }
                    }
                }
                Source::Stack { .. } => match self.frame.arguments.get(&(site, index)) {
                    Some(&slot) if self.home(slot) != Home::Frame => uses.push(Use::Slot(slot)),
                    Some(_) | None => {
                        if let Some(sp) = sp {
                            uses.push(Use::Value(sp, self.width(sp)));
                        }
                    }
                },
            }
        }
        uses
    }

    /// Whether the return of block `block` goes to the address the caller
    /// left. In a link register: its entry value, wherever it is computed
    /// (restored from the frame slot it was saved to: [`Stack::holds`];
    /// signed with pointer authentication and authenticated back, which
    /// gives it exactly: [`authenticated_entry`]), or AArch64's
    /// branch-target view of it ([`top_byte_view`]), which is the same
    /// address for a return address a call left.
    ///
    /// [`Stack::holds`]: binbun_ssa::stack::Stack::holds
    pub(super) fn caller_return(&self, address: Value) -> bool {
        match self.cx.link {
            Link::Register(register) => {
                let address = top_byte_view(self.l1, address).unwrap_or(address);
                let Some(entry) = entry_value(self.l1, register) else {
                    return false;
                };
                self.kind(address) == Kind::Entry(register)
                    || self.stack.holds(self.l1, address, entry)
                    || self
                        .cx
                        .declarations
                        .find_intrinsic("compute_pac")
                        .is_some_and(|hash| {
                            authenticated_entry(
                                self.l1,
                                self.constants,
                                self.stack,
                                hash,
                                entry,
                                address,
                            )
                        })
            }
            Link::Stack { bytes } => {
                if self.frame.return_written {
                    return false;
                }
                let Kind::Load(inst) = self.kind(address) else {
                    return false;
                };
                matches!(
                    self.l1.inst(inst).map(|i| &i.op),
                    Some(&Op::Load { address, bytes: read, atomic: None, .. })
                        if read == bytes && self.address(address) == Some(0)
                )
            }
        }
    }

    /// The uses of block `block`'s terminator.
    pub(super) fn terminator_uses(&self, block: BlockId) -> Vec<Use> {
        let Some(b) = self.l1.block(block) else {
            return Vec::new();
        };
        let full = |value: Value| Use::Value(value, self.width(value));
        match &b.terminator {
            // The branch on the count register a `va_start` absorbed.
            Terminator::Branch { .. }
                if self
                    .va
                    .as_ref()
                    .and_then(|va| va.guard)
                    .is_some_and(|(guard, _)| guard == block) =>
            {
                Vec::new()
            }
            Terminator::Branch { condition, .. } => vec![full(*condition)],
            Terminator::IndirectJump { address, .. } => vec![full(*address)],
            Terminator::Return { address, state } => {
                let mut uses: Vec<Use> = self
                    .returns
                    .pieces
                    .iter()
                    .filter_map(|piece| {
                        let value = *state.registers.get(usize::from(piece.register.0))?;
                        Some(Use::Value(value, piece.offset.saturating_add(piece.width)))
                    })
                    .collect();
                if !self.caller_return(*address) {
                    uses.push(full(*address));
                }
                uses
            }
            Terminator::Leave { address, state, .. } => {
                self.call_uses(Site::Tail(block), *address, &state.registers, Passing::All)
            }
            Terminator::Jump(_)
            | Terminator::Invoke { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => Vec::new(),
        }
    }

    /// Whether load `inst` is of memory other than the frame's locals and
    /// stack parameters and the slots of fixed imports (kept for its fault
    /// even if unused; the loader maps a fixed import's slot, so reading
    /// it cannot fault).
    fn memory_load(&self, inst: InstId) -> bool {
        !self.frame.accesses.contains_key(&inst) && self.fixed_slot_of(inst).is_none()
    }

    /// What is needed: from the effects, conditions, jumps and the return
    /// value, transitively.
    pub(super) fn find_needed(&mut self) {
        let (needed, bits, slots) = self.needed_from(Passing::All);
        self.needed.values = needed;
        self.needed.bits = bits;
        self.needed.slots = slots;
    }

    /// The registers whose entry value is needed other than as a call's
    /// register argument, after [`find_parameters`](Self::find_parameters)
    /// ([`Found::reads`](super::Found::reads)): with a declared prototype,
    /// every register it places a parameter in too.
    pub(super) fn entry_reads(&self) -> BTreeSet<RegisterId> {
        self.entry_reads_with(Passing::None)
    }

    /// The registers whose entry value is needed other than passed on
    /// unchanged (through block parameters) as a call's register argument:
    /// [`Self::entry_reads`] and those a call's argument is computed from
    /// (part of [`Found::opaque`](super::Found::opaque): the callee reads
    /// what is computed).
    pub(super) fn computed_reads(&self) -> BTreeSet<RegisterId> {
        self.entry_reads_with(Passing::Computed)
    }

    /// The registers whose entry value is needed, calls' register
    /// arguments as `arguments` says, and those its declared prototype
    /// places parameters in. Not the parameters added to the declared
    /// ones for registers only passed on to calls: a declaration states
    /// where its parameters are, and any other register is the
    /// function's as without one, by what its body does with it.
    fn entry_reads_with(&self, arguments: Passing) -> BTreeSet<RegisterId> {
        let mut reads = self.body_reads(arguments);
        if let Some(declared) = &self.returns.declared {
            reads.extend(declared.iter().filter_map(|(source, ..)| match source {
                Source::Register(piece) => Some(piece.register),
                Source::Stack { .. } => None,
            }));
        }
        reads
    }

    /// The registers whose entry value the body needs, calls' register
    /// arguments as `arguments` says (a declared prototype's parameters
    /// only where so).
    fn body_reads(&self, arguments: Passing) -> BTreeSet<RegisterId> {
        let (needed, ..) = self.needed_from(arguments);
        let count = u16::try_from(self.cx.declarations.registers.len()).unwrap_or(u16::MAX);
        (0..count)
            .map(RegisterId)
            .filter(|&register| {
                entry_value(self.l1, register).is_some_and(|value| {
                    let value = self.canonical(value);
                    self.kind(value) == Kind::Entry(register)
                        && needed.get(value.0 as usize).copied().unwrap_or(false)
                })
            })
            .collect()
    }

    /// Per value, whether it is needed other than as a call's register
    /// argument ([`find_needed`](Self::find_needed) without those): what
    /// the function's own code computes with.
    pub(super) fn needed_apart_from_arguments(&self) -> Vec<bool> {
        self.needed_from(Passing::None).0
    }

    /// What is needed ([`find_needed`](Self::find_needed)), calls' register
    /// arguments as `arguments` says: per value, whether needed and its
    /// bits used; per slot, whether read.
    fn needed_from(&self, arguments: Passing) -> (Vec<bool>, Vec<u16>, Vec<bool>) {
        let count = self.l1.values.len();
        let mut needed = vec![false; count];
        let mut bits = vec![0u16; count];
        let mut under = vec![Under::Never; count];
        let mut slots = vec![false; self.frame.slots.len()];
        let mut work: Vec<(Use, Under)> = self
            .roots(arguments)
            .into_iter()
            .map(|root| (root, Under::Always))
            .collect();
        let stores = self.slot_stores();
        while let Some((item, guard)) = work.pop() {
            match item {
                Use::Value(value, used) => {
                    let value = self.canonical(value);
                    let index = value.0 as usize;
                    let (Some(seen), Some(width), Some(was)) = (
                        needed.get_mut(index),
                        bits.get_mut(index),
                        under.get_mut(index),
                    ) else {
                        continue;
                    };
                    let wider = used > *width;
                    *width = (*width).max(used);
                    let joined = was.join(guard);
                    if !*seen || wider || joined != *was {
                        *seen = true;
                        *was = joined;
                        let used = *width;
                        work.extend(self.guarded(value, used, joined));
                    }
                }
                Use::Slot(slot) => {
                    if let Some(seen) = slots.get_mut(slot)
                        && !*seen
                    {
                        *seen = true;
                        for &value in stores.get(&slot).map_or(&[][..], Vec::as_slice) {
                            work.push((Use::Value(value, self.width(value)), Under::Always));
                        }
                    }
                }
            }
        }
        (needed, bits, slots)
    }

    /// [`Self::demanded`], each use with the runs it is on, value `v`
    /// being used on those of `under`: a pure operation's and a block
    /// parameter's operands on the same runs (a pure value has no effect
    /// and no fault); a select's arms only where its condition, a test
    /// against zero, chooses them; a block parameter used only where a
    /// test holds not its argument on an edge whose own branch tested the
    /// same value the other way ([`Self::guarded_phi`]); anything else on
    /// any run.
    fn guarded(&self, v: Value, bits: u16, under: Under) -> Vec<(Use, Under)> {
        let each = |uses: Vec<Use>, guard: Under| -> Vec<(Use, Under)> {
            uses.into_iter()
                .map(|used| match used {
                    Use::Value(..) => (used, guard),
                    Use::Slot(_) => (used, Under::Always),
                })
                .collect()
        };
        match self.kind(v) {
            Kind::Phi => {
                if let Under::When(key, zero) = under
                    && let Some(uses) = self.guarded_phi(v, bits, key, zero)
                {
                    return uses;
                }
                each(self.demanded(v, bits), Under::Always)
            }
            Kind::Pure(inst) => {
                if let Some(&Op::Select {
                    condition,
                    then,
                    otherwise,
                }) = self.l1.inst(inst).map(|i| &i.op)
                    && let Some((key, zero_if_true)) = zero_test(self.l1, condition)
                    && self.float_relation(v).is_none()
                    && !(self.width(v) == 1 && self.compare(v).is_some())
                {
                    return vec![
                        (Use::Value(condition, self.width(condition)), under),
                        (
                            Use::Value(then, self.width(then)),
                            Under::When(key, zero_if_true),
                        ),
                        (
                            Use::Value(otherwise, self.width(otherwise)),
                            Under::When(key, !zero_if_true),
                        ),
                    ];
                }
                each(self.demanded(v, bits), under)
            }
            Kind::None
            | Kind::Const(_)
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Load(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => each(self.demanded(v, bits), Under::Always),
        }
    }

    /// The arguments block parameter `v` reads (its low `bits` bits) on
    /// the runs where the value of `key` is zero or not as `zero` says:
    /// not that of an edge whose own branch tested `key` the other way.
    /// The value tested must be the same on each edge as at the use: its
    /// block strictly dominates the parameter's (else a loop's back edge
    /// could carry a test of an earlier iteration's), else `None`.
    fn guarded_phi(&self, v: Value, bits: u16, key: Key, zero: bool) -> Option<Vec<(Use, Under)>> {
        let Definition::Parameter { block, index } = self.l1.value(v)?.definition else {
            return None;
        };
        let tested = BlockId(self.def(key.0).block);
        if tested == block || !self.dominators.dominates(tested, block) {
            return None;
        }
        Some(
            self.incoming_edges(block, index as usize)
                .into_iter()
                .filter(|&(pred, edge, _)| !self.edge_tests(pred, edge, key, !zero))
                .map(|(_, _, argument)| {
                    (
                        Use::Value(argument, self.width(argument).min(bits)),
                        Under::When(key, zero),
                    )
                })
                .collect(),
        )
    }

    /// Whether edge `edge` of block `pred` is taken only where the value
    /// of `key` is zero or not as `zero` says: `pred` branches on that
    /// test and this is the side it holds on.
    fn edge_tests(&self, pred: BlockId, edge: usize, key: Key, zero: bool) -> bool {
        let Some(Terminator::Branch { condition, .. }) = self.l1.block(pred).map(|b| &b.terminator)
        else {
            return false;
        };
        let Some((tested, zero_if_true)) = zero_test(self.l1, *condition) else {
            return false;
        };
        tested == key
            && (if edge == 0 {
                zero_if_true
            } else {
                !zero_if_true
            }) == zero
    }

    /// The uses what is needed starts from: effects, conditions, jumps and
    /// the return value; calls' register arguments as `arguments` says.
    fn roots(&self, arguments: Passing) -> Vec<Use> {
        let mut work: Vec<Use> = Vec::new();
        for (id, block) in self.blocks() {
            for &inst in &block.insts {
                if self.va_store(inst) {
                    continue;
                }
                let Some(i) = self.l1.inst(inst) else {
                    continue;
                };
                match &i.op {
                    Op::Store { atomic: None, .. } => {
                        if self.frame.pushes.contains(&inst) {
                            continue;
                        }
                        if let Some(&slot) = self.frame.accesses.get(&inst)
                            && self.home(slot) != Home::Frame
                        {
                            continue;
                        }
                        work.extend(self.statement_uses(inst));
                    }
                    Op::Load { atomic: None, .. } => {
                        if self.memory_load(inst)
                            && let Some(&result) = i.results.first()
                        {
                            work.push(Use::Value(result, self.width(result)));
                        }
                    }
                    Op::Load {
                        atomic: Some(_), ..
                    }
                    | Op::Intrinsic { .. } => {
                        // A keyed hash has no effect: only what uses its
                        // value needs it.
                        if self.keyed_hash(inst) {
                            continue;
                        }
                        work.extend(self.statement_uses(inst));
                        // An update's value read is needed only where
                        // something uses it; an absorbed load's is the
                        // update's.
                        if self.atomics.updates.contains_key(&inst)
                            || self.atomics.absorbed.contains(&inst)
                        {
                            continue;
                        }
                        for &result in &i.results {
                            if self.width(result) > 0 {
                                work.push(Use::Value(result, self.width(result)));
                            }
                        }
                    }
                    Op::Call {
                        target, registers, ..
                    } => {
                        work.extend(self.call_uses(
                            Site::Call(inst),
                            *target,
                            registers,
                            arguments,
                        ));
                    }
                    Op::Store { .. } | Op::SystemCall { .. } => {
                        work.extend(self.statement_uses(inst));
                    }
                    Op::Const(_)
                    | Op::Undefined(..)
                    | Op::Landing { .. }
                    | Op::Unary(..)
                    | Op::Binary(..)
                    | Op::Flag(..)
                    | Op::Extract { .. }
                    | Op::Concat { .. }
                    | Op::Extend { .. }
                    | Op::Select { .. }
                    | Op::Lanes { .. }
                    | Op::Float { .. } => {}
                }
            }
            match block.terminator {
                Terminator::Leave {
                    address, ref state, ..
                } => {
                    work.extend(self.call_uses(
                        Site::Tail(id),
                        address,
                        &state.registers,
                        arguments,
                    ));
                }
                Terminator::Jump(_)
                | Terminator::Branch { .. }
                | Terminator::IndirectJump { .. }
                | Terminator::Return { .. }
                | Terminator::Invoke { .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Open => work.extend(self.terminator_uses(id)),
            }
        }
        work
    }

    /// The values stored to each local's slot.
    fn slot_stores(&self) -> BTreeMap<usize, Vec<Value>> {
        let mut stores: BTreeMap<usize, Vec<Value>> = BTreeMap::new();
        for (&inst, &slot) in &self.frame.accesses {
            if let Some(&Op::Store { value, .. }) = self.l1.inst(inst).map(|i| &i.op) {
                stores.entry(slot).or_default().push(value);
            }
        }
        stores
    }

    /// Whether canonical value `v` is needed.
    pub(super) fn is_needed(&self, v: Value) -> bool {
        self.needed
            .values
            .get(self.canonical(v).0 as usize)
            .copied()
            .unwrap_or(false)
    }

    /// The parameters: the prototype's, else the integer argument
    /// registers up to the last needed (all if there are stack
    /// parameters), the vector ones up to the last needed, other registers
    /// whose entry value is needed, and the stack parameters by offset;
    /// then any register or stack parameter needed but not declared. The
    /// thread pointer and the floating-point control register are none
    /// where they are the environment ([`Self::environment_registers`]).
    pub(super) fn find_parameters(&mut self) {
        let mut parameters = Vec::new();
        let mut registers = BTreeMap::new();
        let mut stack = BTreeMap::new();
        // The frame's bytes that take a stack parameter's value at entry,
        // and the slots that have theirs.
        let mut entry = Vec::new();
        let mut covered = BTreeSet::new();
        let environment = self.environment_registers();
        let mut stack_slots: Vec<usize> = (0..self.frame.slots.len())
            .filter(|&slot| match self.home(slot) {
                Home::Parameter => self.needed.slots.get(slot).copied().unwrap_or(false),
                Home::Frame => self.entry_read(slot),
                Home::Local => false,
            })
            .collect();
        if let Some(declared) = self.returns.declared.clone() {
            for (source, ty, evidence) in declared {
                let origin = match source {
                    Source::Register(piece) => {
                        registers.insert(piece.register, parameters.len());
                        Origin::Register(piece.register)
                    }
                    Source::Stack { offset, bytes } => {
                        // The slot that is the parameter, or holds it (an
                        // aggregate's bytes, declared 8 at a time, read
                        // 16 at once).
                        let end = offset.saturating_add(i64::from(bytes));
                        let held = stack_slots.iter().copied().find(|&slot| {
                            self.frame
                                .slots
                                .get(slot)
                                .is_some_and(|s| s.offset <= offset && end <= s.end)
                        });
                        match held {
                            Some(slot) if self.home(slot) == Home::Parameter => {
                                stack.insert(slot, parameters.len());
                            }
                            Some(slot) => {
                                entry.push((offset, bytes, parameters.len()));
                                covered.insert(slot);
                            }
                            None => {}
                        }
                        Origin::Slot(offset)
                    }
                };
                parameters.push(Parameter {
                    source,
                    ty,
                    evidence,
                    origin,
                });
            }
        } else {
            for (register, float) in self.standard_parameters(!stack_slots.is_empty()) {
                if registers.contains_key(&register) {
                    continue;
                }
                registers.insert(register, parameters.len());
                let parameter = self.register_parameter(register, float);
                parameters.push(parameter);
            }
        }
        // Inputs no declaration or convention names.
        let count = u16::try_from(self.cx.declarations.registers.len()).unwrap_or(u16::MAX);
        for register in (0..count).map(RegisterId) {
            if registers.contains_key(&register)
                || self.entry_bits(register) == 0
                || environment.contains(&register)
            {
                continue;
            }
            registers.insert(register, parameters.len());
            let float = self.cx.convention.float_arguments.contains(&register);
            let parameter = self.register_parameter(register, float);
            parameters.push(parameter);
        }
        stack_slots.retain(|slot| !stack.contains_key(slot) && !covered.contains(slot));
        self.stack_parameters(&stack_slots, &mut parameters, &mut stack, &mut entry);
        self.needed.parameters = parameters;
        self.needed.registers = registers;
        self.needed.stack = stack;
        self.needed.entry = entry;
        self.needed.environment = environment;
    }

    /// The stack parameters no declaration states, onto `parameters`: one
    /// per slot of `slots` (those read that hold an argument, by offset),
    /// into `stack` (the parameter of each stack parameter's slot) or
    /// `entry` (the bytes of the frame's memory that take a parameter's
    /// value at entry).
    ///
    /// C lays stack parameters out one after another from the
    /// convention's first stack argument, so an argument the function
    /// does not read still takes its place: without a declaration, each
    /// pointer-sized slot before a read one is a parameter too (up to
    /// [`PADDING`] of them), or `[entry + 0x20]` read alone would be the
    /// seventh argument, not the tenth. A hole is not known to be one
    /// argument (it may be part of an aggregate passed by value); as many
    /// pointer-sized ones take the same bytes.
    fn stack_parameters(
        &mut self,
        slots: &[usize],
        parameters: &mut Vec<Parameter>,
        stack: &mut BTreeMap<usize, usize>,
        entry: &mut Vec<(i64, u16, usize)>,
    ) {
        let word = i64::from(self.pointer / 8).max(1);
        let mut next = i64::from(self.cx.link_bytes()) + i64::from(self.cx.convention.shadow);
        let mut padded = 0;
        let pad = self.returns.declared.is_none();
        for &slot in slots {
            let Some((offset, size)) = self.frame.slots.get(slot).map(|s| (s.offset, s.bytes()))
            else {
                continue;
            };
            // No scalar has the size of accesses that overlap in part.
            if self.home(slot) == Home::Frame && (!size.is_power_of_two() || size > 64) {
                continue;
            }
            while pad && padded < PADDING && next.saturating_add(word) <= offset {
                let bytes = u16::try_from(word).unwrap_or(u16::MAX);
                let ty = self.bits(bytes.saturating_mul(8));
                parameters.push(Parameter {
                    source: Source::Stack {
                        offset: next,
                        bytes,
                    },
                    ty,
                    evidence: Evidence::Default,
                    origin: Origin::Slot(next),
                });
                next += word;
                padded += 1;
            }
            let bytes = u16::try_from(size).unwrap_or(u16::MAX);
            let ty = self.bits(bytes.saturating_mul(8));
            if self.home(slot) == Home::Frame {
                entry.push((offset, bytes, parameters.len()));
            } else {
                stack.insert(slot, parameters.len());
            }
            parameters.push(Parameter {
                source: Source::Stack { offset, bytes },
                ty,
                evidence: Evidence::Default,
                origin: Origin::Slot(offset),
            });
            let end = offset.saturating_add_unsigned(size);
            next = next.max(end.saturating_add(word - 1).div_euclid(word) * word);
        }
    }

    /// Whether slot `slot`, which lives in the frame's memory, holds a
    /// stack argument the function reads: a needed load, or a call's
    /// stack argument, may read what the caller left there
    /// ([`Frame::entry_reads`](super::frame::Frame::entry_reads)). It is then a
    /// parameter whose value the bytes take at entry: C's parameter is
    /// the only way to what the caller passed (a slot the function also
    /// writes, `mov r8, [rsp + 8]` then `mov [rsp + 8], r11`, or one of a
    /// frame whose address is taken, or one holding several declared
    /// parameters, is no stack parameter of its own).
    fn entry_read(&self, slot: usize) -> bool {
        let frame = &self.frame;
        let loaded = frame.entry_reads.iter().any(|inst| {
            frame.accesses.get(inst) == Some(&slot)
                && self.l1.inst(*inst).is_some_and(|i| {
                    i.results
                        .iter()
                        .any(|&result| self.width(result) > 0 && self.is_needed(result))
                })
        });
        loaded
            || frame
                .entry_arguments
                .iter()
                .any(|key| frame.arguments.get(key) == Some(&slot))
    }

    /// The convention's environment registers whose entry values are
    /// needed, no prototype declares a parameter, and the function leaves
    /// as the convention requires at every call and wherever control
    /// leaves it (L1 says nothing of a register between those points, so
    /// a change undone before them is not seen):
    /// - The thread pointer where it holds its entry value there: the
    ///   function does not change it. Calls do not change it (no
    ///   convention lists it among the registers they may change).
    /// - The floating-point control register where its controls are its
    ///   entry value's there ([`Self::keeps_controls`]); status flags its
    ///   operations raise do not count. A read of the entry value's
    ///   status flags reads the flags the caller left, the environment's
    ///   too (C's floating-point environment is its status flags and its
    ///   control modes: C11 7.6), so it makes no parameter either.
    fn environment_registers(&self) -> Vec<RegisterId> {
        let convention = self.cx.convention;
        let mut environment = Vec::new();
        if let Some(register) = convention.thread_pointer
            && let Some(entry) = self.environment_entry(register)
            && self.left_as(register, |value| self.canonical(value) == entry)
        {
            environment.push(register);
        }
        for control in &convention.float_control {
            if self.environment_entry(control.register).is_some()
                && self.left_as(control.register, |value| {
                    self.keeps_controls(value, control.status_bits, &mut Vec::new())
                })
            {
                environment.push(control.register);
            }
        }
        environment
    }

    /// The canonical entry value of register `register`, if it is needed
    /// and no prototype declares the register a parameter.
    fn environment_entry(&self, register: RegisterId) -> Option<Value> {
        let declared = self.returns.declared.as_ref().is_some_and(|declared| {
            declared.iter().any(|(source, ..)| {
                matches!(source, Source::Register(piece) if piece.register == register)
            })
        });
        if declared || self.entry_bits(register) == 0 {
            return None;
        }
        entry_value(self.l1, register).map(|value| self.canonical(value))
    }

    /// Whether register `register`'s value satisfies `holds` at every call
    /// and system call (its value passed) and wherever control leaves the
    /// function.
    fn left_as(&self, register: RegisterId, holds: impl Fn(Value) -> bool) -> bool {
        let index = usize::from(register.0);
        let holds = |registers: &[Value]| registers.get(index).is_none_or(|&value| holds(value));
        self.blocks().all(|(_, block)| {
            let exits = match &block.terminator {
                Terminator::Return { state, .. } | Terminator::Leave { state, .. } => {
                    holds(&state.registers)
                }
                Terminator::Jump(_)
                | Terminator::Branch { .. }
                | Terminator::IndirectJump { .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Invoke { .. }
                | Terminator::Open => true,
            };
            exits
                && block
                    .insts
                    .iter()
                    .all(|&inst| match self.l1.inst(inst).map(|i| &i.op) {
                        Some(Op::Call { registers, .. } | Op::SystemCall { registers, .. }) => {
                            holds(registers)
                        }
                        Some(_) | None => true,
                    })
        })
    }

    /// Whether value `v` of the floating-point control register has its
    /// controls (the bits above its low `status` ones) from the entry
    /// value: the entry value; what a call left (the convention keeps the
    /// controls across calls, though L1 knows nothing of the register
    /// after one: its value is the call's or undefined); such a value with
    /// status flags raised (or-ed with a zero extension of `status` bits
    /// or fewer, or a constant of only those); a block parameter of such
    /// values. `seen` holds the block
    /// parameters being looked at (a loop's keeps them if its other
    /// incoming values do).
    fn keeps_controls(&self, v: Value, status: u16, seen: &mut Vec<Value>) -> bool {
        let v = self.canonical(v);
        let called = self.l1.value(v).is_some_and(|info| match info.definition {
            Definition::Result { inst, .. } => {
                matches!(self.l1.inst(inst).map(|i| &i.op), Some(Op::Call { .. }))
            }
            Definition::Parameter { .. } => false,
        });
        match self.kind(v) {
            Kind::Entry(_) | Kind::Undefined(..) => true,
            Kind::Phi => {
                let Some(&binbun_ssa::ir::ValueInfo {
                    definition: Definition::Parameter { block, index },
                    ..
                }) = self.l1.value(v)
                else {
                    return false;
                };
                if seen.contains(&v) {
                    return true;
                }
                seen.push(v);
                self.incoming(block, index as usize)
                    .into_iter()
                    .all(|(_, argument)| self.keeps_controls(argument, status, seen))
            }
            Kind::Pure(inst) => match self.l1.inst(inst).map(|i| &i.op) {
                Some(&Op::Binary(Binary::Or, a, b)) => {
                    let flags = |x: Value| match self.kind(x) {
                        Kind::Pure(inst) => matches!(
                            self.l1.inst(inst).map(|i| &i.op),
                            Some(&Op::Extend { signed: false, value, .. })
                                if self.width(value) <= status
                        ),
                        Kind::Const(bits) => {
                            let leading = u16::try_from(bits.leading_zeros()).unwrap_or(u16::MAX);
                            bits.width().saturating_sub(leading) <= status
                        }
                        Kind::None
                        | Kind::Undefined(..)
                        | Kind::Address(_)
                        | Kind::Entry(_)
                        | Kind::Phi
                        | Kind::Load(_)
                        | Kind::Result(_)
                        | Kind::CallView { .. } => false,
                    };
                    (flags(b) && self.keeps_controls(a, status, seen))
                        || (flags(a) && self.keeps_controls(b, status, seen))
                }
                Some(_) | None => false,
            },
            Kind::Result(_) | Kind::CallView { .. } => called,
            Kind::None | Kind::Const(_) | Kind::Address(_) | Kind::Load(_) => false,
        }
    }

    /// How many low bits of register `register`'s entry value are used
    /// (0: none; the stack pointer and fixed registers: none).
    fn entry_bits(&self, register: RegisterId) -> u16 {
        let Some(value) = entry_value(self.l1, register) else {
            return 0;
        };
        if self.kind(value) != Kind::Entry(register) || !self.is_needed(value) {
            return 0;
        }
        self.needed.bits.get(value.0 as usize).copied().unwrap_or(0)
    }

    /// The convention's argument registers that are parameters, without a
    /// prototype, each with whether it is a vector one: the integer ones up
    /// to the last whose entry value is needed (all of them if there are
    /// stack parameters, `stack`), then the vector ones up to the last
    /// needed. Where arguments take registers by position, a position's
    /// parameter is its vector register if only that one is needed, else
    /// its integer register, up to the last position either is needed in
    /// (all of them with stack parameters). A variadic definition printed
    /// as C's has its named ones instead, needed or not.
    fn standard_parameters(&self, stack: bool) -> Vec<(RegisterId, bool)> {
        let convention = self.cx.convention;
        let needed = |register: &RegisterId| self.entry_bits(*register) > 0;
        let last = |list: &[RegisterId]| list.iter().rposition(needed).map_or(0, |index| index + 1);
        let integers = if let Some(va) = &self.va {
            usize::from(va.named.integer)
        } else if stack {
            convention.arguments.len()
        } else {
            last(&convention.arguments)
        };
        let vectors = match &self.va {
            Some(va) => usize::from(va.named.vector),
            None => last(&convention.float_arguments),
        };
        if !convention.positional {
            let integers = convention.arguments.iter().take(integers);
            let vectors = convention.float_arguments.iter().take(vectors);
            return integers
                .map(|&register| (register, false))
                .chain(vectors.map(|&register| (register, true)))
                .collect();
        }
        (0..integers.max(vectors))
            .filter_map(|position| {
                let integer = convention.arguments.get(position);
                match convention.float_arguments.get(position) {
                    Some(vector) if needed(vector) && !integer.is_some_and(needed) => {
                        Some((*vector, true))
                    }
                    Some(_) | None => integer.map(|&register| (register, false)),
                }
            })
            .collect()
    }

    /// A parameter for register `register`, a vector argument register if
    /// `float`: as wide as its widest use, rounded up to a power of two of
    /// at least 8 bits, and no wider than the convention passes an
    /// argument in it ([`argument_width`](Self::argument_width)): the
    /// entry value's bits above are no argument.
    fn register_parameter(&mut self, register: RegisterId, float: bool) -> Parameter {
        let full = self.argument_width(register, float);
        let used = self.entry_bits(register);
        let width = if used == 0 && float {
            // Kept for its position only: a `double` takes the register,
            // where a whole vector wider than the target's goes to memory
            // and moves the ones after it.
            full.min(64)
        } else if used == 0 || full < 8 {
            full
        } else {
            used.max(8).next_power_of_two().min(full)
        };
        Parameter {
            source: Source::Register(Piece {
                register,
                offset: 0,
                width,
            }),
            ty: self.bits(width),
            evidence: Evidence::Default,
            origin: Origin::Register(register),
        }
    }
}

impl Lowering<'_, '_> {
    /// How each needed value is lowered: values used once by a later
    /// statement of their own block, with nothing in between writing what
    /// they read, are folded into it.
    pub(super) fn fold(&mut self) {
        let count = self.l1.values.len();
        let tally = self.tally();
        let blocks: Vec<_> = self.blocks().collect();
        let mut roles = vec![Role::None; count];
        for &(id, block) in &blocks {
            let writes = self.writes(id);
            for &parameter in &block.parameters {
                if self.canonical(parameter) == parameter && self.is_needed(parameter) {
                    let role = self.fixed_role(parameter).unwrap_or(Role::Var);
                    if let Some(slot) = roles.get_mut(parameter.0 as usize) {
                        *slot = role;
                    }
                }
            }
            for (k, &inst) in block.insts.iter().enumerate().rev() {
                let pos = u32::try_from(k + 1).unwrap_or(u32::MAX);
                let Some(i) = self.l1.inst(inst) else {
                    continue;
                };
                for &result in &i.results {
                    if self.canonical(result) != result || !self.is_needed(result) {
                        continue;
                    }
                    let index = result.0 as usize;
                    let role = self.fixed_role(result).unwrap_or_else(|| {
                        let n = tally.counts.get(index).copied().unwrap_or(0);
                        let last = tally.last.get(index).copied().flatten();
                        self.fold_role(id, pos, inst, n, last, &roles, &writes)
                    });
                    if let Some(slot) = roles.get_mut(index) {
                        *slot = role;
                    }
                }
            }
        }
        self.needed.roles = roles;
    }

    /// How many uses each canonical value has, and where the last is.
    fn tally(&self) -> Tally {
        let count = self.l1.values.len();
        let mut tally = Tally {
            counts: vec![0; count],
            last: vec![None; count],
        };
        let mut add = |value: Value, user: User| {
            let index = value.0 as usize;
            if let Some(n) = tally.counts.get_mut(index) {
                *n = n.saturating_add(1);
            }
            if let Some(slot) = tally.last.get_mut(index) {
                *slot = Some(user);
            }
        };
        let blocks: Vec<_> = self.blocks().collect();
        for &(id, block) in &blocks {
            for (k, &parameter) in block.parameters.iter().enumerate() {
                if self.canonical(parameter) == parameter && self.is_needed(parameter) {
                    for (pred, argument) in self.incoming(id, k) {
                        let at = Def {
                            block: pred.0,
                            pos: self.edge_pos(pred),
                        };
                        add(self.canonical(argument), User::At(at));
                    }
                }
            }
            for (k, &inst) in block.insts.iter().enumerate() {
                let at = Def {
                    block: id.0,
                    pos: u32::try_from(k + 1).unwrap_or(u32::MAX),
                };
                let Some(i) = self.l1.inst(inst) else {
                    continue;
                };
                if matches!(i.op, Op::Store { .. }) && !self.store_lowered(inst) {
                    continue;
                }
                for item in self.statement_uses(inst) {
                    if let Use::Value(value, _) = item {
                        add(self.canonical(value), User::At(at));
                    }
                }
                for &result in &i.results {
                    if self.canonical(result) != result || !self.is_needed(result) {
                        continue;
                    }
                    if matches!(self.kind(result), Kind::Phi) {
                        continue;
                    }
                    for item in self.inputs(result) {
                        if let Use::Value(value, _) = item {
                            add(self.canonical(value), User::Value(result));
                        }
                    }
                }
            }
            let at = Def {
                block: id.0,
                pos: self.terminator_pos(id),
            };
            for item in self.terminator_uses(id) {
                if let Use::Value(value, _) = item {
                    add(self.canonical(value), User::At(at));
                }
            }
        }
        tally
    }

    /// The role of a needed value whatever its uses: inline, a parameter,
    /// a variable a statement writes; `None` for a pure value or a load.
    fn fixed_role(&self, v: Value) -> Option<Role> {
        match self.kind(v) {
            Kind::None | Kind::Const(_) | Kind::Undefined(..) | Kind::Address(_) => {
                Some(Role::Inline)
            }
            Kind::Entry(register) => Some(
                self.needed
                    .registers
                    .get(&register)
                    .map_or(Role::Inline, |&index| Role::Parameter(index)),
            ),
            Kind::Phi | Kind::Result(_) | Kind::CallView { .. } => Some(Role::Var),
            Kind::Load(inst) => match self.frame.accesses.get(&inst) {
                Some(&slot) if self.home(slot) == Home::Parameter => Some(Role::Inline),
                Some(_) | None => None,
            },
            Kind::Pure(_) => None,
        }
    }

    /// The role of pure value or load `inst` at `pos` of block `block`
    /// with `n` uses, the last by `user`.
    #[allow(clippy::too_many_arguments, reason = "the facts of one decision")]
    fn fold_role(
        &self,
        block: BlockId,
        pos: u32,
        inst: InstId,
        n: u32,
        user: Option<User>,
        roles: &[Role],
        writes: &Writes,
    ) -> Role {
        let load = matches!(
            self.l1.inst(inst).map(|i| &i.op),
            Some(Op::Load { atomic: None, .. })
        );
        if n == 0 {
            return if load { Role::Drop } else { Role::Var };
        }
        if n > 1 {
            return Role::Var;
        }
        let eval = match user {
            Some(User::At(at)) if at.block == block.0 && at.pos > pos => at.pos,
            Some(User::Value(user)) => {
                let def = self.def(user);
                if def.block != block.0 || def.pos <= pos {
                    return Role::Var;
                }
                match roles.get(user.0 as usize) {
                    Some(&Role::Fold(eval)) => eval,
                    Some(_) | None => def.pos,
                }
            }
            Some(User::At(_)) | None => return Role::Var,
        };
        if load {
            let clear = match self.frame.accesses.get(&inst) {
                Some(&slot) if self.home(slot) == Home::Local => writes
                    .slots
                    .iter()
                    .all(|&(at, s)| s != slot || at <= pos || at >= eval),
                Some(_) | None => writes.memory.iter().all(|&at| at <= pos || at >= eval),
            };
            if !clear {
                return Role::Var;
            }
        }
        Role::Fold(eval)
    }

    /// Whether folded load `result` is read under an arm of a select of
    /// its block (the arm itself, or folded into it): the machine reads
    /// it whichever arm is chosen (`cmovne eax, [rdi]` reads `[rdi]`
    /// either way), and C's `?:` evaluates only the chosen one, so the
    /// read, and its fault, would be gone on the other. A load of the
    /// function's own frame cannot fault, nor one of data the image maps.
    pub(super) fn selected_load(&self, result: Value) -> bool {
        let Kind::Load(load) = self.kind(result) else {
            return false;
        };
        if self.frame.accesses.contains_key(&load) {
            return false;
        }
        if let Some(&Op::Load { address, .. }) = self.l1.inst(load).map(|i| &i.op)
            && let Kind::Const(bits) = self.kind(address)
            && self
                .cx
                .data
                .data(bits.low_u64(), u64::from(self.width(result).div_ceil(8)))
                .is_some()
        {
            return false;
        }
        let Some(block) = self.l1.block(BlockId(self.def(result).block)) else {
            return false;
        };
        block.insts.iter().any(|&inst| {
            let Some(&Op::Select {
                then, otherwise, ..
            }) = self.l1.inst(inst).map(|i| &i.op)
            else {
                return false;
            };
            let mut work = vec![self.canonical(then), self.canonical(otherwise)];
            let mut steps = 0usize;
            while let Some(value) = work.pop() {
                steps += 1;
                if value == result {
                    return true;
                }
                if steps > 64 || !matches!(self.role(value), Role::Fold(_)) {
                    continue;
                }
                if let Some((_, op)) = self.defining(value) {
                    work.extend(
                        op.operands()
                            .into_iter()
                            .map(|operand| self.canonical(operand)),
                    );
                }
            }
            false
        })
    }

    /// The position of block `block`'s terminator.
    pub(super) fn terminator_pos(&self, block: BlockId) -> u32 {
        let n = self.l1.block(block).map_or(0, |b| b.insts.len());
        u32::try_from(n + 1).unwrap_or(u32::MAX)
    }

    /// The position of the copies on block `block`'s outgoing edges.
    pub(super) fn edge_pos(&self, block: BlockId) -> u32 {
        self.terminator_pos(block).saturating_add(1)
    }

    /// The positions in block `block` of statements writing memory, and
    /// of stores to locals' slots.
    fn writes(&self, block: BlockId) -> Writes {
        let mut writes = Writes::default();
        let Some(b) = self.l1.block(block) else {
            return writes;
        };
        for (k, &inst) in b.insts.iter().enumerate() {
            let pos = u32::try_from(k + 1).unwrap_or(u32::MAX);
            let Some(i) = self.l1.inst(inst) else {
                continue;
            };
            match i.op {
                Op::Store { atomic: None, .. } => {
                    if !self.store_lowered(inst) {
                        continue;
                    }
                    match self.frame.accesses.get(&inst) {
                        Some(&slot) if self.home(slot) == Home::Local => {
                            writes.slots.push((pos, slot));
                        }
                        Some(_) | None => writes.memory.push(pos),
                    }
                }
                Op::Store { .. }
                | Op::Load {
                    atomic: Some(_), ..
                }
                | Op::Call { .. }
                | Op::Intrinsic { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. } => writes.memory.push(pos),
                Op::Load { atomic: None, .. }
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
                | Op::Float { .. } => {}
            }
        }
        writes
    }

    /// How canonical value `v` is lowered.
    pub(super) fn role(&self, v: Value) -> Role {
        self.needed
            .roles
            .get(self.canonical(v).0 as usize)
            .copied()
            .unwrap_or(Role::None)
    }
}

/// The positions of writes in a block.
#[derive(Default)]
struct Writes {
    memory: Vec<u32>,
    slots: Vec<(u32, usize)>,
}

/// Each value's uses: how many, and the last.
struct Tally {
    counts: Vec<u32>,
    last: Vec<Option<User>>,
}
