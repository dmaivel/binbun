//! The L1 data model: one function's code in SSA form.
//!
//! - Every [`Value`] is defined once: as a block parameter (in place of a
//!   φ) or as an instruction's result. Its [`Type`] is a bit vector or
//!   [`Type::Memory`].
//! - Registers are variables per full register of the architecture's
//!   [`Declarations`](binbun_semantics::Declarations): a view of a
//!   register is an [`Op::Extract`], a write to part of one combines the
//!   new bits with the rest ([`Op::Concat`]).
//! - Memory is one variable: loads, stores, intrinsics and calls take the
//!   memory before them and those that change it give a new one, so a
//!   load names the stores it follows.
//! - Block 0 is the entry: no instructions, a parameter for each register
//!   (in register order) and then the memory, and a jump to the block at
//!   the function's entry address. Nothing jumps to it.
//! - Exits ([`Terminator::Return`], [`Terminator::Leave`]) carry every
//!   register's final value and the memory.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{
    Binary, Flag, FloatOp, FloatOutput, Format, IntrinsicId, LaneOp, RegisterId, SiteId, Trap,
    Unary,
};

/// A value of a [`Function`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Value(pub u32);

/// A block of a [`Function`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub u32);

/// An instruction of a [`Function`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstId(pub u32);

/// What a value is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    /// A bit vector of this many bits.
    Bits(u16),
    /// The whole memory.
    Memory,
}

/// Where a value is defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Definition {
    /// Parameter `index` of `block`.
    Parameter {
        /// The block.
        block: BlockId,
        /// Its position among the block's parameters.
        index: u32,
    },
    /// Result `index` of `inst`.
    Result {
        /// The instruction.
        inst: InstId,
        /// Its position among the instruction's results.
        index: u32,
    },
}

/// Where an unknown value ([`Op::Undefined`], and L2's undefined
/// expression) comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unknown {
    /// Bits the architecture leaves undefined, which processors may set
    /// differently: those the instruction at `address` writes to
    /// `register` (`None`: to no register's value, such as a store's or a
    /// condition's), at `site` of the architecture's semantics, whose
    /// inputs the undefined value carries.
    Architecture {
        /// The instruction.
        address: u64,
        /// The register it leaves undefined.
        register: Option<RegisterId>,
        /// The site ([`binbun_semantics::ir::SiteInfo`]), if the
        /// architecture names one.
        site: Option<SiteId>,
    },
    /// A parameter's bits above its declared width.
    Parameter,
    /// A register a call may change and does not return in, or the bits
    /// of one it returns in beyond its return value: those of `register`
    /// after the call at `address`.
    Call {
        /// The call instruction.
        address: u64,
        /// The register.
        register: RegisterId,
    },
    /// A register the unwinder does not restore at a landing pad.
    Landing,
    /// The entry value of a register (`None`: a stack slot) the function
    /// takes no parameter in (an unnamed argument register a variadic
    /// function's `va_list` stands for, or one its interface drops).
    Entry {
        /// The register.
        register: Option<RegisterId>,
    },
    /// A variable or stack slot read before any write.
    Unwritten,
    /// None of those: a value lowering has no expression for (its
    /// fallback), or a placeholder nothing reads.
    Lowering,
}

impl Unknown {
    /// Whether the architecture leaves the value undefined
    /// ([`Unknown::Architecture`]): processors may differ, so no pass may
    /// choose a value for it.
    #[must_use]
    pub const fn architectural(self) -> bool {
        matches!(self, Self::Architecture { .. })
    }
}

/// A value's type and definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValueInfo {
    /// The type.
    pub ty: Type,
    /// The definition.
    pub definition: Definition,
}

/// An operation. Pure operations are L0's ([`binbun_semantics::ir::Expr`])
/// over values; the others are ordered by the memory they take.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    /// A constant (one result, its width).
    Const(Bits),
    /// An unknown value (one result, of the instruction's result type),
    /// and where it comes from; each occurrence is its own. The values are
    /// a site's inputs ([`Unknown::Architecture`]), in the site's order:
    /// what a processor's choice may depend on (none for other unknowns).
    /// They are kept, never operands ([`Op::operands`]): for every analysis
    /// the value is a fresh one, as the architecture says; only a run on a
    /// processor's profile reads them ([`Op::inputs`]). A value replaced
    /// is replaced here too ([`Op::map_values`]), no pass deletes a
    /// definition, and the verifier checks that each input's definition
    /// dominates.
    Undefined(Unknown, Vec<Value>),
    /// An operation of one operand.
    Unary(Unary, Value),
    /// An operation of two operands.
    Binary(Binary, Value, Value),
    /// A flag computation.
    Flag(Flag, Value, Value, Value),
    /// `width` bits of `value` from bit `offset`.
    Extract {
        /// The source.
        value: Value,
        /// The first bit.
        offset: u16,
        /// The number of bits.
        width: u16,
    },
    /// `high` above `low`.
    Concat {
        /// The high part.
        high: Value,
        /// The low part.
        low: Value,
    },
    /// `value` zero- or sign-extended to `width` bits.
    Extend {
        /// Sign (true) or zero extension.
        signed: bool,
        /// The source.
        value: Value,
        /// The resulting width.
        width: u16,
    },
    /// `then` if the 1-bit `condition` is 1, else `otherwise`.
    Select {
        /// The condition.
        condition: Value,
        /// The value if it holds.
        then: Value,
        /// The value if not.
        otherwise: Value,
    },
    /// `op` lane by lane (L0's `Expr::Lanes`).
    Lanes {
        /// How many lanes.
        lanes: u16,
        /// The operation.
        op: LaneOp,
        /// The operands (the unused ones repeat the first).
        operands: [Value; 3],
    },
    /// An IEEE 754 operation (L0's `Expr::Float`).
    Float {
        /// The operation.
        op: FloatOp,
        /// The format of the operands' lanes.
        format: Format,
        /// How many lanes.
        lanes: u16,
        /// The result, or the exceptions.
        output: FloatOutput,
        /// The 2-bit rounding.
        rounding: Value,
        /// The operands (the unused ones repeat the first).
        operands: [Value; 3],
    },
    /// `bytes` bytes of `memory` at `address`, little-endian (one result).
    Load {
        /// The memory read.
        memory: Value,
        /// The address.
        address: Value,
        /// The number of bytes.
        bytes: u16,
        /// The atomic group (an L0 `atomic` block) it belongs to.
        atomic: Option<u32>,
    },
    /// `memory` with `value` stored at `address` (one result: the new
    /// memory).
    Store {
        /// The memory written.
        memory: Value,
        /// The address.
        address: Value,
        /// The value, a whole number of bytes.
        value: Value,
        /// The atomic group it belongs to.
        atomic: Option<u32>,
    },
    /// An intrinsic: results are its outputs, then the new memory.
    Intrinsic {
        /// The intrinsic.
        intrinsic: IntrinsicId,
        /// The memory before it.
        memory: Value,
        /// The inputs.
        inputs: Vec<Value>,
    },
    /// A call that returns here: results are the new memory, then a value
    /// for each register in `changes`, in that order.
    Call {
        /// The callee's address.
        target: Value,
        /// The return address.
        return_address: Value,
        /// The memory before it.
        memory: Value,
        /// Every register's value at the call, in register order.
        registers: Vec<Value>,
        /// The registers the call may change.
        changes: Vec<RegisterId>,
    },
    /// Enters the operating system and returns here: results as for
    /// [`Op::Call`].
    SystemCall {
        /// The memory before it.
        memory: Value,
        /// Every register's value at the system call, in register order.
        registers: Vec<Value>,
        /// The registers the system may change.
        changes: Vec<RegisterId>,
    },
    /// Where an exception unwinding through a call of the function enters
    /// it (a landing pad): the first instruction of the block a
    /// [`Terminator::Invoke`] unwinds to. Results: the new memory (the
    /// callee ran, in part), then a value for each register of
    /// `receives`, in that order: what the unwinder hands the code (for
    /// the Itanium C++ ABI, the exception object and the selector), unknown
    /// like a call's results.
    Landing {
        /// The memory at the call.
        memory: Value,
        /// The registers the unwinder sets.
        receives: Vec<RegisterId>,
    },
}

/// An instruction: an operation and its results.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Inst {
    /// The operation.
    pub op: Op,
    /// Its results.
    pub results: Vec<Value>,
    /// The address of the machine instruction it comes from.
    pub address: u64,
}

/// A jump to a block, with a value for each of its parameters.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    /// The block.
    pub block: BlockId,
    /// The arguments, one per parameter.
    pub arguments: Vec<Value>,
}

/// The state at an exit from the function.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    /// Every register's value, in register order.
    pub registers: Vec<Value>,
    /// The memory.
    pub memory: Value,
}

/// How control leaves a block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Terminator {
    /// To a block.
    Jump(Target),
    /// To `then` if the 1-bit `condition` is 1, else to `otherwise`.
    Branch {
        /// The condition.
        condition: Value,
        /// Where it goes if the condition holds.
        then: Target,
        /// Where it goes if not.
        otherwise: Target,
    },
    /// To the code at a computed address: one of `targets`, those known
    /// (none while unresolved).
    IndirectJump {
        /// The address.
        address: Value,
        /// The blocks it is known to reach.
        targets: Vec<Target>,
    },
    /// A return from the function to `address`.
    Return {
        /// The return address.
        address: Value,
        /// The state at the return.
        state: State,
    },
    /// Control leaves the function other than by returning: a jump to code
    /// outside it (a tail call), or to an address not known.
    Leave {
        /// Where it goes.
        address: Value,
        /// The state when it leaves.
        state: State,
        /// Whether the code it goes to may return to the function's caller.
        /// `false` for a tail call to code known never to return: like a
        /// call followed by [`Stop`](Self::Stop), its way out is no return
        /// (it says nothing about what the function returns).
        returns: bool,
    },
    /// The instruction traps.
    Trap(Trap),
    /// Execution does not go on: a call that does not return.
    Stop,
    /// The block's last instruction, an [`Op::Call`], returns to `normal`,
    /// or an exception unwinds through it to `unwind`, a block that starts
    /// with an [`Op::Landing`]. The unwinder restores the caller's frame:
    /// `unwind`'s arguments are the callee-saved registers' values at the
    /// call, the stack pointer before the call pushed anything, and the
    /// memory at the call.
    Invoke {
        /// Where the call returns to.
        normal: Target,
        /// Where an exception goes.
        unwind: Target,
    },
    /// Not built yet (only during construction).
    Open,
}

/// A basic block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Block {
    /// The address of the machine instruction it starts in (the entry
    /// block: the function's entry).
    pub address: u64,
    /// The address of the machine instruction its terminator comes from:
    /// the one that leaves it (a branch, a jump, a return), else its last
    /// (control falls through to the next block; the entry block: the
    /// function's entry).
    pub end: u64,
    /// Its parameters.
    pub parameters: Vec<Value>,
    /// Its instructions, in order.
    pub insts: Vec<InstId>,
    /// How control leaves it.
    pub terminator: Terminator,
}

/// One function's code in SSA form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Function {
    /// The entry address.
    pub entry: u64,
    /// The blocks; block 0 is the entry block.
    pub blocks: Vec<Block>,
    /// The instructions.
    pub insts: Vec<Inst>,
    /// The values.
    pub values: Vec<ValueInfo>,
    /// The register each value the machine code held in one was first
    /// held in, as built (a register's write, a block's parameter for a
    /// register): presentation only, for naming what the value becomes.
    /// A value a pass makes has none.
    pub held: BTreeMap<Value, RegisterId>,
}

impl Function {
    /// Block `id`.
    pub fn block(&self, id: BlockId) -> Option<&Block> {
        self.blocks.get(id.0 as usize)
    }

    /// Instruction `id`.
    pub fn inst(&self, id: InstId) -> Option<&Inst> {
        self.insts.get(id.0 as usize)
    }

    /// Value `id`'s type and definition.
    pub fn value(&self, id: Value) -> Option<&ValueInfo> {
        self.values.get(id.0 as usize)
    }

    /// Value `id`'s type.
    pub fn ty(&self, id: Value) -> Option<Type> {
        self.value(id).map(|info| info.ty)
    }
}

impl Terminator {
    /// The jumps to blocks it makes, in order (a branch: `then`, then
    /// `otherwise`; an invoke: `normal`, then `unwind`).
    pub fn targets(&self) -> impl Iterator<Item = &Target> {
        let (pair, list): ([Option<&Target>; 2], &[Target]) = match self {
            Self::Jump(target) => ([Some(target), None], &[]),
            Self::Branch {
                then, otherwise, ..
            } => ([Some(then), Some(otherwise)], &[]),
            Self::Invoke { normal, unwind } => ([Some(normal), Some(unwind)], &[]),
            Self::IndirectJump { targets, .. } => ([None, None], targets),
            Self::Return { .. } | Self::Leave { .. } | Self::Trap(_) | Self::Stop | Self::Open => {
                ([None, None], &[])
            }
        };
        pair.into_iter().flatten().chain(list)
    }

    /// [`targets`](Self::targets), to change.
    pub fn targets_mut(&mut self) -> impl Iterator<Item = &mut Target> {
        let (pair, list): ([Option<&mut Target>; 2], &mut [Target]) = match self {
            Self::Jump(target) => ([Some(target), None], &mut []),
            Self::Branch {
                then, otherwise, ..
            } => ([Some(then), Some(otherwise)], &mut []),
            Self::Invoke { normal, unwind } => ([Some(normal), Some(unwind)], &mut []),
            Self::IndirectJump { targets, .. } => ([None, None], targets),
            Self::Return { .. } | Self::Leave { .. } | Self::Trap(_) | Self::Stop | Self::Open => {
                ([None, None], &mut [])
            }
        };
        pair.into_iter().flatten().chain(list)
    }

    /// Replaces each value it uses, jump arguments included, by `f` of it.
    pub fn map_values(&mut self, f: &mut impl FnMut(Value) -> Value) {
        match self {
            Self::Branch { condition, .. } => *condition = f(*condition),
            Self::IndirectJump { address, .. } => *address = f(*address),
            Self::Return { address, state } | Self::Leave { address, state, .. } => {
                *address = f(*address);
                for value in &mut state.registers {
                    *value = f(*value);
                }
                state.memory = f(state.memory);
            }
            Self::Jump(_) | Self::Invoke { .. } | Self::Trap(_) | Self::Stop | Self::Open => {}
        }
        for target in self.targets_mut() {
            for value in &mut target.arguments {
                *value = f(*value);
            }
        }
    }

    /// The values it uses, other than in jump arguments.
    pub fn operands(&self) -> impl Iterator<Item = Value> + '_ {
        let (first, state) = match self {
            Self::Branch { condition, .. } => (Some(*condition), None),
            Self::IndirectJump { address, .. } => (Some(*address), None),
            Self::Return { address, state } | Self::Leave { address, state, .. } => {
                (Some(*address), Some(state))
            }
            Self::Jump(_) | Self::Invoke { .. } | Self::Trap(_) | Self::Stop | Self::Open => {
                (None, None)
            }
        };
        let registers = state.map_or(&[][..], |state| &state.registers);
        first
            .into_iter()
            .chain(registers.iter().copied())
            .chain(state.map(|state| state.memory))
    }
}

impl Op {
    /// Replaces each value it uses by `f` of it.
    pub fn map_values(&mut self, f: &mut impl FnMut(Value) -> Value) {
        match self {
            Self::Const(_) => {}
            Self::Undefined(_, inputs) => {
                for input in inputs {
                    *input = f(*input);
                }
            }
            Self::Unary(_, a) | Self::Extract { value: a, .. } | Self::Extend { value: a, .. } => {
                *a = f(*a);
            }
            Self::Binary(_, a, b) | Self::Concat { high: a, low: b } => {
                *a = f(*a);
                *b = f(*b);
            }
            Self::Flag(_, a, b, c)
            | Self::Select {
                condition: a,
                then: b,
                otherwise: c,
            }
            | Self::Lanes {
                operands: [a, b, c],
                ..
            } => {
                *a = f(*a);
                *b = f(*b);
                *c = f(*c);
            }
            Self::Float {
                rounding,
                operands: [a, b, c],
                ..
            } => {
                *rounding = f(*rounding);
                *a = f(*a);
                *b = f(*b);
                *c = f(*c);
            }
            Self::Load {
                memory, address, ..
            } => {
                *memory = f(*memory);
                *address = f(*address);
            }
            Self::Store {
                memory,
                address,
                value,
                ..
            } => {
                *memory = f(*memory);
                *address = f(*address);
                *value = f(*value);
            }
            Self::Intrinsic { memory, inputs, .. } => {
                *memory = f(*memory);
                for input in inputs {
                    *input = f(*input);
                }
            }
            Self::Call {
                target,
                return_address,
                memory,
                registers,
                ..
            } => {
                *target = f(*target);
                *return_address = f(*return_address);
                *memory = f(*memory);
                for value in registers {
                    *value = f(*value);
                }
            }
            Self::SystemCall {
                memory, registers, ..
            } => {
                *memory = f(*memory);
                for value in registers {
                    *value = f(*value);
                }
            }
            Self::Landing { memory, .. } => *memory = f(*memory),
        }
    }

    /// The values its results are computed from; not a site's inputs
    /// ([`Op::inputs`]).
    pub fn operands(&self) -> Vec<Value> {
        match self {
            Self::Const(_) | Self::Undefined(..) => Vec::new(),
            Self::Unary(_, a) | Self::Extract { value: a, .. } | Self::Extend { value: a, .. } => {
                alloc::vec![*a]
            }
            Self::Binary(_, a, b) | Self::Concat { high: a, low: b } => alloc::vec![*a, *b],
            Self::Flag(_, a, b, c)
            | Self::Select {
                condition: a,
                then: b,
                otherwise: c,
            } => alloc::vec![*a, *b, *c],
            Self::Lanes { op, operands, .. } => operands.iter().take(op.arity()).copied().collect(),
            Self::Float {
                op,
                rounding,
                operands,
                ..
            } => core::iter::once(*rounding)
                .chain(operands.iter().take(op.arity()).copied())
                .collect(),
            Self::Load {
                memory, address, ..
            } => alloc::vec![*memory, *address],
            Self::Store {
                memory,
                address,
                value,
                ..
            } => alloc::vec![*memory, *address, *value],
            Self::Intrinsic { memory, inputs, .. } => core::iter::once(*memory)
                .chain(inputs.iter().copied())
                .collect(),
            Self::Call {
                target,
                return_address,
                memory,
                registers,
                ..
            } => [*target, *return_address, *memory]
                .into_iter()
                .chain(registers.iter().copied())
                .collect(),
            Self::SystemCall {
                memory, registers, ..
            } => core::iter::once(*memory)
                .chain(registers.iter().copied())
                .collect(),
            Self::Landing { memory, .. } => alloc::vec![*memory],
        }
    }

    /// The inputs of an undefined value's site ([`Op::Undefined`]); none
    /// for other operations.
    pub fn inputs(&self) -> &[Value] {
        match self {
            Self::Undefined(_, inputs) => inputs,
            Self::Const(_)
            | Self::Unary(..)
            | Self::Binary(..)
            | Self::Flag(..)
            | Self::Extract { .. }
            | Self::Concat { .. }
            | Self::Extend { .. }
            | Self::Select { .. }
            | Self::Lanes { .. }
            | Self::Float { .. }
            | Self::Load { .. }
            | Self::Store { .. }
            | Self::Intrinsic { .. }
            | Self::Call { .. }
            | Self::SystemCall { .. }
            | Self::Landing { .. } => &[],
        }
    }
}
