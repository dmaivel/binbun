//! The L2 data model: one function as a structured AST, with binbun's
//! exact semantics (not C's).
//!
//! - A [`Function`] owns arenas: its [`Variable`]s, [`Expr`]s and
//!   [`Stmt`]s, named by [`VarId`], [`ExprId`] and [`StmtId`]; its body
//!   and every nested block are lists of statement ids ([`Block`]). Nodes
//!   are only appended: a pass that rewrites one adds the new node and
//!   points its user at it; the old one stays, unused.
//!   One exception: a pass may retype a memory access in place, the `ty`
//!   of an [`Expr::Load`] or of a [`Place::Memory`], when the new type has
//!   the same width. What the code does is unchanged (the same bytes are
//!   read or written), every user stays valid, and the node keeps its id
//!   and provenance.
//! - Expressions are pure but for loads (which may fault): L0's operations
//!   ([`binbun_semantics::ir::Expr`]) over expression ids, plus variable
//!   reads, addresses of variables in memory, reinterpretations and typed
//!   loads, and for calls ([`Expr::Call`], under the rule below). Every
//!   operation has an explicit width and signedness, and
//!   arithmetic wraps at its width; a condition is a 1-bit value. An
//!   operand's id is below its user's. An id may be used more than once;
//!   each use evaluates it. All operands are evaluated, first to last,
//!   but for [`Expr::Logical`] (C's `&&` and `||`), whose right operand
//!   is evaluated only if the left one does not decide: what a load in it
//!   may fault on matters.
//! - Effects are statements, one per statement at its root: an
//!   assignment, a call, an intrinsic or an escape (with the writes of
//!   their results). A call may instead be an expression
//!   ([`Expr::Call`]) in an assignment, an expression statement, a
//!   return, a decision or a call statement's arguments, made once, where
//!   C fixes the order of the statement's calls (a call's callee and
//!   arguments before it, `&&`'s and `||`'s left operand before the
//!   right, a statement's own effect after what it evaluates) and nothing
//!   C evaluates in either order with a call calls or reads memory
//!   ([`verify::ordered`](crate::verify::ordered)). So C's unspecified
//!   order of evaluation cannot matter: `f(g(x), y)` with `y` a local.
//! - Control is structured (`if`, loops, `switch`, with `break` and
//!   `continue` naming the statement they leave) plus labels and `goto`;
//!   a label is only a place a `goto` can go.
//! - Exceptions: a [`Stmt::Try`]'s handlers run when an exception unwinds
//!   out of a call of its body (the calls whose innermost enclosing
//!   `Try` body holds them: not those in its handlers, nor in a `Try`
//!   nested in the body). [`Expr::Exception`] reads what the runtime
//!   handed the handler last entered. Nothing here is particular to one
//!   ABI: which call unwinds where, and how a runtime's raw state (the
//!   Itanium C++ ABI's selector) becomes the handler kinds, is the
//!   lowering's and the structuring passes' business.
//! - Provenance (which L1 values and machine instructions a node stands
//!   for, and which L1 block's code or decision, [`Origin::Block`]) is a
//!   side table ([`Provenance`]), so nodes stay small. A node's
//!   instructions are every instruction whose effect was folded into it:
//!   a pass that replaces, substitutes, removes or rewrites nodes gives
//!   the result the instructions of what it absorbed
//!   ([`Provenance::absorb_expr`]), but those still standing for a node
//!   of their own (a value another statement computes keeps its line).
//!   The frame code no statement stands for (prologue, epilogue) is the
//!   function's entry and exit ([`Provenance::entry`]).
//! - Types are a [`Types`] table; variables carry a type and its
//!   [`Evidence`].
//! - A variadic function ([`Function::variadic`]) reaches its unnamed
//!   arguments through a `va_list` that [`Stmt::VaStart`] initialises,
//!   by its ABI's rule ([`Function::va`]).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{
    Binary, Flag, FloatOp, FloatOutput, Format, IntrinsicId, LaneOp, RegisterId, Trap, Unary,
};
use binbun_ssa::ir::{BlockId, Unknown, Value};

use crate::types::{Evidence, TypeId, Types};
use crate::verify::expr_width;

/// A variable of a [`Function`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarId(pub u32);

/// An expression of a [`Function`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExprId(pub u32);

/// A statement of a [`Function`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StmtId(pub u32);

/// A label of a [`Function`], below [`Function::labels`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LabelId(pub u32);

/// A call of a [`Function`] made by an [`Expr::Call`], below
/// [`Function::calls`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallId(pub u32);

/// The inputs of an [`Expr::Undefined`] of a site, in
/// [`Function::inputs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputsId(pub u32);

/// An input of the site of an [`Expr::Undefined`] ([`Function::inputs`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SiteInput {
    /// Its value, a constant.
    Kept(Bits),
    /// Not kept by lowering: unknown, this many bits wide.
    NotKept(u16),
}

/// A list of statements, run in order.
pub type Block = Vec<StmtId>;

/// A node of a [`Function`], as errors name them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    /// A type.
    Type(TypeId),
    /// A variable.
    Var(VarId),
    /// An expression.
    Expr(ExprId),
    /// A statement.
    Stmt(StmtId),
}

/// What a node stands for in the code it was lowered from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// A value of the L1 function.
    Value(Value),
    /// A machine instruction, by address: one the node stands for (on a
    /// statement from lowering, the first is the one it was lowered from)
    /// or one folded into it.
    Instruction(u64),
    /// A register (of a variable).
    Register(RegisterId),
    /// A register the machine code held a local's values in (of a
    /// variable; presentation only, for naming it by its register): unlike
    /// [`Register`](Self::Register), not one the variable is at entry.
    Held(RegisterId),
    /// The stack slot at the entry stack pointer plus this offset (of a
    /// variable).
    Slot(i64),
    /// An L1 block, by which control flow is checked against L1
    /// (`binbun_decompile::validate::structure`). On a statement: one the
    /// block's code became, before its decision, or the statement making
    /// its decision (an `if`, a loop, a `switch`). On an expression in a
    /// condition: the block whose decision it is, where that is not its
    /// statement's (an operand of an [`Expr::Logical`]). A pass that
    /// replaces such a node gives the replacement the same origin.
    /// On a [`Stmt::Try`]: the block whose decision its dispatch (the
    /// choice among its handlers) is.
    Block(BlockId),
    /// On a [`Stmt::Try`]: an L1 block its dispatch took over, which has
    /// no code of its own left in L2 (a landing pad's test of the runtime's
    /// state, which the choice among the handlers says; a call resuming
    /// unwinding, which the language does implicitly).
    Absorbed(BlockId),
    /// On a `while` or `for` whose statement names one block: its
    /// condition is proved to hold when the loop is entered (a range fact:
    /// the guard before it, the counter's start), so entering it decides
    /// nothing and goes straight to the body; the block named decides each
    /// later iteration. Set by the loop rules where they prove it.
    Proved,
}

/// The operator of an [`Expr::Logical`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Logical {
    /// `&&`: 1 if both are 1; the right operand only if the left is 1.
    And,
    /// `||`: 1 if either is 1; the right operand only if the left is 0.
    Or,
}

/// A value the runtime hands an exception handler when it enters it
/// ([`Expr::Exception`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExceptionValue {
    /// The exception (the Itanium C++ ABI's `_Unwind_Exception *`, what
    /// `__cxa_begin_catch` takes).
    Object,
    /// Which clause of the runtime's table the exception matched (the
    /// Itanium C++ ABI's selector: a type's index, 0 for a cleanup,
    /// negative for an exception specification).
    Selector,
    /// The exception's code (Microsoft structured exception handling's
    /// `GetExceptionCode()`), which `__C_specific_handler` hands an
    /// `__except` block.
    Code,
    /// Whether a termination handler runs because an exception unwinds
    /// (Microsoft structured exception handling's `AbnormalTermination()`,
    /// what `__C_specific_handler` hands a `__finally` block's funclet).
    Abnormal,
}

/// A C++ type an exception handler names, by its run-time type
/// information.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatchType {
    /// The type as the source names it (demangled: `std::exception`), if
    /// known.
    pub name: Option<String>,
    /// The symbol of its type information object (`_ZTISt9exception`), if
    /// known.
    pub symbol: Option<String>,
    /// The address of its type information object, if known.
    pub address: Option<u64>,
}

/// What an exception handler ([`Handler`]) is entered for, and where
/// control goes when it falls off its end.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HandlerKind {
    /// Every exception the runtime's tables send to it, with the runtime's
    /// raw state ([`Expr::Exception`]), which its code tells apart (a
    /// landing pad, before its clauses are recognised), entered at this
    /// address of the binary. Its end goes on after the `Try`.
    Landing(u64),
    /// An exception of this type (or one derived from it). Its end goes on
    /// after the `Try`.
    Catch(CatchType),
    /// Any exception. Its end goes on after the `Try`.
    CatchAll,
    /// Every exception, which goes on unwinding after it (destructors of
    /// locals). Its end propagates the exception.
    Cleanup,
    /// An exception of none of these types (a dynamic exception
    /// specification, `throw(A, B)`). Its end propagates the exception.
    Unexpected(Vec<CatchType>),
    /// `__except (filter)` (Microsoft structured exception handling): an
    /// exception of any kind (a fault, `RaiseException`, a C++ exception)
    /// that its filter takes. Its end goes on after the `Try`.
    Except(SehFilter),
    /// `__finally` (Microsoft structured exception handling): every
    /// exception unwinding out of the body, with the termination handler's
    /// code as the runtime runs it then (the code on the way out without
    /// one, which MSVC compiles apart, follows the `Try`). Its end
    /// propagates the exception.
    Finally,
}

/// The filter of a [`HandlerKind::Except`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SehFilter {
    /// A constant (`EXCEPTION_EXECUTE_HANDLER`, 1: every exception).
    Constant(i32),
    /// The filter funclet at this address of the binary, which evaluates
    /// the filter expression.
    Funclet(u64),
}

impl HandlerKind {
    /// Whether falling off the handler's end propagates the exception
    /// (else control goes on after the `Try`).
    pub const fn propagates(&self) -> bool {
        match self {
            Self::Cleanup | Self::Unexpected(_) | Self::Finally => true,
            Self::Landing(_) | Self::Catch(_) | Self::CatchAll | Self::Except(_) => false,
        }
    }

    /// Whether it is entered for every exception and propagates it at its
    /// end (a cleanup, a `__finally` block).
    pub const fn cleans_up(&self) -> bool {
        matches!(self, Self::Cleanup | Self::Finally)
    }
}

/// A handler of a [`Stmt::Try`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Handler {
    /// What it is entered for.
    pub kind: HandlerKind,
    /// Its statements.
    pub body: Block,
}

/// Where a variable lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VarKind {
    /// A parameter: its position is its place in
    /// [`Function::parameters`]. Not in memory: it has no address.
    Parameter,
    /// A local, not in memory: it has no address, and holds an undefined
    /// value until written.
    Local,
    /// Memory at a fixed address: reads load, writes store.
    Global(u64),
    /// Memory in the function's stack frame, at the stack pointer on entry
    /// plus this offset: the frame (or part of it) once its address
    /// escapes. Reads load, writes store.
    Frame(i64),
    /// What the platform keeps in this register for the whole thread (the
    /// thread pointer: `fs_base`, `gs_base`, `tpidr_el0`): its value at
    /// entry. Not in memory (no address), never written, and no
    /// parameter: callers do not pass it.
    Environment(RegisterId),
}

/// A variable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Variable {
    /// Where it lives.
    pub kind: VarKind,
    /// Its name, if known, and why it has it (presentation only).
    pub name: Option<Name>,
    /// Its type: one that fits a value for a parameter or local; one with
    /// a whole number of bytes for a variable in memory.
    pub ty: TypeId,
    /// Why it has that type.
    pub evidence: Evidence,
    /// The registers, stack slots and L1 values it was made from.
    pub origins: Vec<Origin>,
}

/// A variable's name and the evidence for it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    /// The name (made a unique C identifier when printed).
    pub text: String,
    /// Where it comes from.
    pub origin: NameOrigin,
}

impl Name {
    /// `text`, from `origin`.
    pub fn new(text: impl Into<String>, origin: NameOrigin) -> Self {
        Self {
            text: text.into(),
            origin,
        }
    }
}

/// Where a variable's name comes from, strongest first: a stronger source
/// replaces a weaker one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameOrigin {
    /// The user's rename, above all.
    User,
    /// The platform's convention (the `va_list`, `ap`).
    Convention,
    /// Debug information.
    Debug,
    /// The function's declared prototype (a parameter's declared name).
    Declared,
    /// A callee's declared parameter the variable is passed as (the name
    /// passed most, of those of this strength).
    Argument,
    /// The counter a `for` loop steps (`i`, `j`, `k` by nesting).
    Counter,
    /// The one variable the function returns (`result`).
    Result,
}

/// An expression. Operands are [`ExprId`]s below its own; widths are in
/// bits and follow L0's rules ([`binbun_semantics::verify`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Expr {
    /// A constant.
    Const(Bits),
    /// An unknown value of this width, and where it comes from; each
    /// evaluation is its own. One the architecture leaves undefined
    /// ([`Unknown::architectural`]) no pass may choose a value for; one of
    /// a site may have its site's inputs ([`Function::inputs`]), which are
    /// not operands.
    Undefined(u16, Unknown, Option<InputsId>),
    /// The value of a variable (a load, for one in memory).
    Var(VarId),
    /// The address of a variable in memory ([`VarKind::Global`] or
    /// [`VarKind::Frame`]), pointer-wide.
    AddressOf(VarId),
    /// An operation of one operand.
    Unary(Unary, ExprId),
    /// An operation of two operands of the same width.
    Binary(Binary, ExprId, ExprId),
    /// C's `&&` or `||` of two 1-bit operands: the left one, then the
    /// right one only if the left one does not decide (`&&`: it is 1;
    /// `||`: it is 0). 1 bit.
    Logical(Logical, ExprId, ExprId),
    /// A flag computation (1 bit) of three operands of the same width.
    Flag(Flag, ExprId, ExprId, ExprId),
    /// `width` bits of `value` from bit `offset` (a truncation, at 0).
    Extract {
        /// The source.
        value: ExprId,
        /// The first bit.
        offset: u16,
        /// The number of bits.
        width: u16,
    },
    /// `high` above `low`; the width is the sum.
    Concat {
        /// The high part.
        high: ExprId,
        /// The low part.
        low: ExprId,
    },
    /// `value` zero- or sign-extended to `width` bits (more than its own).
    Extend {
        /// Sign (true) or zero extension.
        signed: bool,
        /// The source.
        value: ExprId,
        /// The resulting width.
        width: u16,
    },
    /// `then` if the 1-bit `condition` is 1, else `otherwise` (only the
    /// chosen one matters, but both are evaluated: they are pure).
    Select {
        /// The condition.
        condition: ExprId,
        /// The value if it holds.
        then: ExprId,
        /// The value if not.
        otherwise: ExprId,
    },
    /// `op` lane by lane (L0's `Expr::Lanes`).
    Lanes {
        /// How many lanes.
        lanes: u16,
        /// The operation.
        op: LaneOp,
        /// The operands ([`LaneOp::arity`] of them; the unused ones repeat
        /// the first).
        operands: [ExprId; 3],
    },
    /// An IEEE 754 operation (L0's `Expr::Float`); conversions between
    /// integers and floats are these ([`FloatOp::FromInt`],
    /// [`FloatOp::ToInt`]).
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
        rounding: ExprId,
        /// The operands ([`FloatOp::arity`] of them; the unused ones repeat
        /// the first).
        operands: [ExprId; 3],
    },
    /// `value`'s bits, unchanged, as type `ty` (of the same width): where
    /// the meaning of the bits changes (an integer's bits as a float, a
    /// number as a pointer). Conversions that change bits are operations
    /// (extension, extraction, [`Expr::Float`]).
    Cast {
        /// The value.
        value: ExprId,
        /// The type its bits are read as.
        ty: TypeId,
    },
    /// The bytes at `address` (pointer-wide), little-endian, as a value of
    /// type `ty` (a whole number of bytes, at most a value's width).
    Load {
        /// The address.
        address: ExprId,
        /// The type read.
        ty: TypeId,
    },
    /// Call [`Function::calls`]`[id]` and take its return value (of its
    /// signature's return type, which it has). Its operands are the
    /// call's computed callee, then its arguments, all below it; they are
    /// evaluated, then the call made. Where it may be is the module's
    /// rule: in an order C fixes.
    Call(CallId),
    /// C's assignment expression `var = value`: evaluates `value`, writes
    /// it to `var` (a parameter or local, not in memory, of its width)
    /// and is that value. An effect, like a call: only in the condition
    /// of an `if` or a loop, where C orders it with everything else the
    /// condition evaluates and nothing C does not order with it reads or
    /// writes `var` ([`crate::verify`]).
    Assign {
        /// The variable written.
        var: VarId,
        /// The value.
        value: ExprId,
    },
    /// What the runtime handed the exception handler entered last (in a
    /// handler, or code it reaches), `width` bits; undefined if none was.
    Exception {
        /// Which value.
        value: ExceptionValue,
        /// Its width.
        width: u16,
    },
}

/// Where an assignment or a result goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Place {
    /// A whole variable (a store, for one in memory).
    Var(VarId),
    /// The bytes at `address`, little-endian, as type `ty` (a whole number
    /// of bytes, at most a value's width).
    Memory {
        /// The address (pointer-wide).
        address: ExprId,
        /// The type written.
        ty: TypeId,
    },
}

/// What a call calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Callee {
    /// Code at a known address.
    Address(u64),
    /// The code whose address the import slot at this address holds: a
    /// slot the loader fills before the program runs and that never
    /// changes after, so a call through it always calls its import (it
    /// is called as a load of the slot would be, without one).
    Import(u64),
    /// Code at a computed address (pointer-wide).
    Expr(ExprId),
}

/// A call.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Call {
    /// What it calls.
    pub callee: Callee,
    /// The arguments: one per parameter of the signature, of its width,
    /// and any number more if it is variadic.
    pub arguments: Vec<ExprId>,
    /// The callee's type: a [`Type::Code`](crate::types::Type::Code).
    pub signature: TypeId,
    /// The types of the arguments past the signature's parameters, in
    /// order, where a declaration states them (a parsed format string of a
    /// `printf`-like callee): each fits its argument's width; at most one
    /// per such argument. Empty: none stated (C's default argument
    /// promotions are all that is known).
    pub variadic: Vec<TypeId>,
}

/// Where a call is made: a [`Stmt::Call`], or an [`Expr::Call`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallSite {
    /// The call statement.
    Stmt(StmtId),
    /// The call expression.
    Expr(ExprId),
}

impl CallSite {
    /// The origins of the call in `provenance` (its statement's or
    /// expression's).
    pub fn origins(self, provenance: &Provenance) -> &[Origin] {
        match self {
            Self::Stmt(id) => provenance.stmt(id),
            Self::Expr(id) => provenance.expr(id),
        }
    }
}

/// An arm of a [`Stmt::Switch`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Arm {
    /// The values that select it, of the scrutinee's width; distinct
    /// across the switch.
    pub values: Vec<Bits>,
    /// Whether it is also the default (at most one arm is).
    pub default: bool,
    /// Its statements.
    pub body: Block,
    /// Whether control goes on into the next arm's body at the end of this
    /// one (never for the last arm); if not, it leaves the switch.
    pub fallthrough: bool,
}

/// What C cannot say: each a [`Stmt::Escape`], counted per function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Escape {
    /// A computed jump whose targets are not known; operand: the address.
    UnresolvedJump,
    /// A jump into another function's body (not its entry); operand: the
    /// address.
    ForeignJump,
    /// Code that overlaps other code; operand: the address it runs at.
    OverlappingCode,
    /// A call with arguments in registers no C convention uses; operands:
    /// the target, then the values passed; results: the values it gives.
    NonStandardCall,
    /// Stack use the stack analysis cannot follow; operands: the values
    /// involved.
    StackTrick,
    /// Entering the operating system; operands: the values in the
    /// convention's registers; results: the values it gives.
    SystemCall,
    /// A memory access of an atomic group (an L0 `atomic` block: a locked
    /// read-modify-write) lowering did not make one [`Escape::Update`]
    /// of: each access atomic, the group not; operands: the address, then
    /// the value stored (a store); results: the value loaded (a load).
    /// The instruction in its provenance names the group.
    Atomic,
    /// An atomic group as the one operation it is: memory read, changed
    /// as the [`Update`] says and written back, indivisibly. Operands:
    /// the address, then the update's (one; a compare-and-exchange's two,
    /// the value expected and the one to store); results: the value read
    /// (none where nothing uses it). Among the escapes for its shape, not
    /// because C cannot say it (`atomic_fetch_add`): the counts leave it
    /// out.
    Update(Update),
}

/// What an atomic read-modify-write ([`Escape::Update`]) writes back,
/// from the value it read and its operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Update {
    /// The operand (`xchg`).
    Exchange,
    /// Their sum (`lock xadd`, `lock add`, `lock inc`).
    Add,
    /// The value read less the operand (`lock sub`, `lock dec`).
    Sub,
    /// Their `and` (`lock and`, `lock btr`).
    And,
    /// Their `or` (`lock or`, `lock bts`).
    Or,
    /// Their exclusive or (`lock xor`, `lock btc`).
    Xor,
    /// The second operand if the value read is the first, else what was
    /// there (`lock cmpxchg`).
    CompareExchange,
}

impl Update {
    /// How many operands it takes after the address.
    pub const fn arity(self) -> usize {
        match self {
            Self::CompareExchange => 2,
            Self::Exchange | Self::Add | Self::Sub | Self::And | Self::Or | Self::Xor => 1,
        }
    }
}

/// A statement.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Stmt {
    /// Evaluates `value`, then the place's address, then writes.
    Assign {
        /// Where.
        place: Place,
        /// What.
        value: ExprId,
    },
    /// A call. The callee and arguments are evaluated first; its return
    /// value goes to `results`, low bits first, their widths summing to
    /// the return type's (none: the value is dropped).
    Call {
        /// Where the return value goes.
        results: Vec<Place>,
        /// The call.
        call: Call,
    },
    /// An intrinsic (L0's meaning): `inputs` evaluated in order, its
    /// outputs to `results`, one each.
    Intrinsic {
        /// Where the outputs go.
        results: Vec<Place>,
        /// The intrinsic.
        intrinsic: IntrinsicId,
        /// The inputs.
        inputs: Vec<ExprId>,
    },
    /// Evaluates an expression and drops it: a load kept for its fault.
    Expr(ExprId),
    /// `then` if the 1-bit condition is 1, else `otherwise`.
    If {
        /// The condition.
        condition: ExprId,
        /// Run if it holds.
        then: Block,
        /// Run if not (empty for none).
        otherwise: Block,
    },
    /// While the 1-bit condition is 1 (checked first), the body.
    While {
        /// The condition.
        condition: ExprId,
        /// The body.
        body: Block,
    },
    /// The body, then again while the 1-bit condition is 1.
    DoWhile {
        /// The body.
        body: Block,
        /// The condition.
        condition: ExprId,
    },
    /// `init`, then while the 1-bit condition is 1: the body, then `step`.
    /// `continue` goes to `step`. `init` and `step` hold only assignments,
    /// calls, intrinsics and expression statements.
    For {
        /// Run once, first.
        init: Block,
        /// The condition.
        condition: ExprId,
        /// Run after each pass of the body.
        step: Block,
        /// The body.
        body: Block,
    },
    /// Runs the arm whose values hold the scrutinee (else the default arm,
    /// else nothing) and, while arms fall through, the ones after it.
    Switch {
        /// The value switched on.
        scrutinee: ExprId,
        /// The arms, in order.
        arms: Vec<Arm>,
    },
    /// Leaves the loop or switch statement named, which encloses it.
    Break(StmtId),
    /// Goes on with the next iteration of the loop named, which encloses
    /// it: to its condition (`while`, `do`-`while`) or step (`for`).
    Continue(StmtId),
    /// Where a [`Stmt::Goto`] goes; each label is defined once.
    Label(LabelId),
    /// Goes to a label anywhere in the function (into blocks, too: the
    /// code around the label then runs as if reached normally).
    Goto(LabelId),
    /// Returns, with a value of the return type if the function has one.
    Return(Option<ExprId>),
    /// The machine traps here.
    Trap(Trap),
    /// Control never gets here (after a call that does not return).
    Unreachable,
    /// Something C cannot say; `operands` evaluated in order, `results`
    /// written if control goes on.
    Escape {
        /// What.
        kind: Escape,
        /// Its operands.
        operands: Vec<ExprId>,
        /// Where what it gives goes.
        results: Vec<Place>,
    },
    /// The body; when an exception unwinds out of one of its calls (those
    /// whose innermost enclosing `Try` body it is), the first handler that
    /// is entered for it, in order. If none is, the exception propagates.
    /// An exception propagating from a statement (a call, a handler that
    /// propagates) goes to the handlers of the innermost `Try` whose body
    /// holds it, else out of the function.
    Try {
        /// The statements guarded.
        body: Block,
        /// The handlers, in the order they are tried (at least one).
        handlers: Vec<Handler>,
    },
    /// C's `va_start(list, last)` (`last`: the last parameter) in a
    /// variadic function, by its ABI ([`Function::va`]): saves the
    /// unnamed argument registers' entry values where the `va_list` finds
    /// them, then writes the `va_list` variable `list` (a whole variable)
    /// to walk the unnamed arguments from the first.
    VaStart {
        /// The `va_list` variable ([`Place::Var`]).
        list: Place,
    },
}

/// Which origins each expression and statement has, in one pool (a node
/// with none costs nothing), and the instructions of the function's
/// frame code no statement stands for: its entry's (the prologue: saves
/// of callee-saved registers, the stack pointer lowered, the frame
/// pointer set), which its signature stands for, and its exit's (the
/// epilogue: the restores and the stack pointer raised), which its
/// closing brace stands for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Provenance {
    exprs: Vec<Span>,
    stmts: Vec<Span>,
    origins: Vec<Origin>,
    entry: Vec<Origin>,
    exit: Vec<Origin>,
}

/// A range of [`Provenance::origins`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Span {
    start: u32,
    len: u32,
}

/// What [`Stmt::VaStart`] does in a variadic function, by its ABI: the
/// saves of the unnamed argument registers, then the `va_list` it writes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Va {
    /// The `va_list`.
    pub list: VaList,
    /// The saves of the unnamed argument registers, in order.
    pub saves: Vec<Save>,
}

/// A `va_list` as [`Stmt::VaStart`] writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VaList {
    /// System V x86-64's `struct __va_list_tag[1]`, a 24-byte variable in
    /// memory: `gp_offset` and `fp_offset` (32 bits each: where the next
    /// integer and vector argument is in the register save area), the
    /// address of the stack arguments after the named ones
    /// (`overflow_arg_area`) and that of the register save area
    /// (`reg_save_area`), each the entry stack pointer plus an offset.
    Tag {
        /// The first `gp_offset`: 8 per named integer argument.
        gp_offset: u32,
        /// The first `fp_offset`: 48, plus 16 per named vector argument;
        /// `None` where the function leaves the field unset (GCC, where
        /// no `va_arg` reads a vector register): its bytes are then left
        /// as they were.
        fp_offset: Option<u32>,
        /// The offset of `overflow_arg_area` from the entry stack pointer.
        overflow: i64,
        /// The offset of `reg_save_area` from the entry stack pointer.
        save_area: i64,
    },
    /// A pointer to the first unnamed argument (Microsoft x64's
    /// `char *`): the entry stack pointer plus this offset.
    Pointer(i64),
    /// AAPCS64's `struct __va_list`, a 32-byte variable in memory: the
    /// address of the stack arguments after the named ones (`__stack`,
    /// at 0), the ends of the integer and vector register save areas
    /// (`__gr_top` at 8, `__vr_top` at 16) and the negative offsets from
    /// them of the next integer and vector argument (`__gr_offs` at 24,
    /// `__vr_offs` at 28), each address the entry stack pointer plus an
    /// offset.
    Aapcs64 {
        /// The offset of `__stack` from the entry stack pointer.
        stack: i64,
        /// The offset of `__gr_top`; `None` where the function leaves the
        /// field unset (no integer register saved): its bytes are then
        /// left as they were.
        gr_top: Option<i64>,
        /// The offset of `__vr_top`, as `gr_top` for vector registers.
        vr_top: Option<i64>,
        /// The first `__gr_offs`: −8 per unnamed integer register.
        gr_offs: i32,
        /// The first `__vr_offs`: −16 per unnamed vector register.
        vr_offs: i32,
    },
}

/// A save of the low `bytes` bytes of an argument register's entry value
/// at the entry stack pointer plus `offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Save {
    /// The register.
    pub register: RegisterId,
    /// Where, from the entry stack pointer.
    pub offset: i64,
    /// How many bytes.
    pub bytes: u16,
    /// If set, the save is made only where the low byte of this
    /// register's entry value is not 0 (System V's `al`: an upper bound
    /// on the vector registers the caller passes).
    pub guard: Option<RegisterId>,
}

/// One function as a structured AST.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// The entry address.
    pub address: u64,
    /// Its name, if known.
    pub name: Option<String>,
    /// The parameters, in order (each a [`VarKind::Parameter`]).
    pub parameters: Vec<VarId>,
    /// The return type (fits a value), or `None` for no value.
    pub returns: Option<TypeId>,
    /// Why it has that return type ([`Evidence::Default`] until a pass or
    /// a declaration says more).
    pub returns_evidence: Evidence,
    /// Whether it takes more arguments than its parameters (C's `...`).
    pub variadic: bool,
    /// What its [`Stmt::VaStart`]s do (a variadic function that has one).
    pub va: Option<Va>,
    /// The frame's structs: [`VarKind::Frame`] variables whose struct
    /// type lowering made of the frame's slots (a field per slot, at its
    /// offset).
    pub frames: Vec<VarId>,
    /// The frame's promoted objects: [`VarKind::Frame`] variables of the
    /// type a declaration gives the bytes whose address a call is passed.
    pub promoted: Vec<VarId>,
    /// The types its nodes name.
    pub types: Types,
    /// The variables.
    pub variables: Vec<Variable>,
    /// The expressions.
    pub exprs: Vec<Expr>,
    /// The calls [`Expr::Call`]s make (only appended, as expressions).
    pub calls: Vec<Call>,
    /// The inputs of undefined values of sites ([`Expr::Undefined`]), in
    /// each site's order (only appended): each one's value where lowering
    /// knows it as a constant, not kept otherwise. They are never
    /// operands, so no pass sees them and the C never depends on them; a
    /// value kept as an expression would be a use that changes what the
    /// passes do, or, unseen by them, could go stale. A run on a
    /// processor's profile reads them, an input not kept as unknown bits:
    /// the value is unknown where the rule depends on one (L1 keeps every
    /// input).
    pub inputs: Vec<Vec<SiteInput>>,
    /// The statements; each is in exactly one block of the body, or
    /// unused.
    pub stmts: Vec<Stmt>,
    /// How many labels there are.
    pub labels: u32,
    /// The body.
    pub body: Block,
    /// Where locals are declared, when not at the top of the body: the
    /// [`VarKind::Local`]s declared just before each statement, in the
    /// block holding it (a `for`'s `init`: in the loop's header). Each
    /// one's scope is the rest of that block (the whole `for`), where it
    /// starts undefined each time control passes its declaration; the
    /// statement it is declared at, where that assigns the whole of it
    /// ([`Place::Var`]: an assignment, a call's one result), is its
    /// initializer in C. Empty until a pass places them
    /// (binbun-decompile's `scopes`).
    pub declared: BTreeMap<StmtId, Vec<VarId>>,
    /// The values proved for index expressions (`i` in an access at `p +
    /// k + i·s`), read signed at their width: every value the expression
    /// has where its one statement evaluates it lies in `lo..=hi`. A
    /// printer may subscript an array field with it (`p->a[i]`) where
    /// that keeps it within the array, as C requires. Empty until a pass
    /// proves them (binbun-decompile's `indices`, after every pass that
    /// rewrites expressions).
    pub indices: BTreeMap<ExprId, (i128, i128)>,
    /// What its expressions and statements stand for.
    pub provenance: Provenance,
}

/// `index` as a `u32` id.
fn number(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}

impl Function {
    /// A function at `address` with types from `types` and nothing else:
    /// no parameters, no return value, an empty body.
    pub fn new(address: u64, types: Types) -> Self {
        Self {
            address,
            name: None,
            parameters: Vec::new(),
            returns: None,
            returns_evidence: Evidence::Default,
            variadic: false,
            va: None,
            frames: Vec::new(),
            promoted: Vec::new(),
            types,
            variables: Vec::new(),
            exprs: Vec::new(),
            calls: Vec::new(),
            inputs: Vec::new(),
            stmts: Vec::new(),
            labels: 0,
            body: Vec::new(),
            declared: BTreeMap::new(),
            indices: BTreeMap::new(),
            provenance: Provenance::default(),
        }
    }

    /// Adds a variable (a parameter still has to be listed in
    /// [`parameters`](Self::parameters)).
    pub fn add_var(&mut self, variable: Variable) -> VarId {
        self.variables.push(variable);
        VarId(number(self.variables.len() - 1))
    }

    /// Adds an expression (its operands must exist already).
    pub fn add_expr(&mut self, expr: Expr) -> ExprId {
        self.exprs.push(expr);
        ExprId(number(self.exprs.len() - 1))
    }

    /// Adds a call for an [`Expr::Call`] (its callee and arguments must
    /// exist already).
    pub fn add_call(&mut self, call: Call) -> CallId {
        self.calls.push(call);
        CallId(number(self.calls.len() - 1))
    }

    /// Adds the inputs of an [`Expr::Undefined`].
    pub fn add_inputs(&mut self, inputs: Vec<SiteInput>) -> InputsId {
        self.inputs.push(inputs);
        InputsId(number(self.inputs.len() - 1))
    }

    /// Inputs `id`.
    pub fn site_inputs(&self, id: InputsId) -> &[SiteInput] {
        self.inputs.get(id.0 as usize).map_or(&[], Vec::as_slice)
    }

    /// Adds a statement, in no block yet.
    pub fn add_stmt(&mut self, stmt: Stmt) -> StmtId {
        self.stmts.push(stmt);
        StmtId(number(self.stmts.len() - 1))
    }

    /// A new label.
    pub fn add_label(&mut self) -> LabelId {
        self.labels += 1;
        LabelId(self.labels - 1)
    }

    /// Variable `id`.
    pub fn var(&self, id: VarId) -> Option<&Variable> {
        self.variables.get(id.0 as usize)
    }

    /// Expression `id`.
    pub fn expr(&self, id: ExprId) -> Option<&Expr> {
        self.exprs.get(id.0 as usize)
    }

    /// Call `id`.
    pub fn call(&self, id: CallId) -> Option<&Call> {
        self.calls.get(id.0 as usize)
    }

    /// `expr` with each operand replaced by `map` of it (in
    /// [`Expr::operands`] order); a call whose operands change is a new
    /// call ([`Function::add_call`]).
    pub fn map_operands(&mut self, expr: Expr, map: &mut dyn FnMut(ExprId) -> ExprId) -> Expr {
        let Expr::Call(id) = expr else {
            return expr.map_own(map);
        };
        let Some(call) = self.call(id) else {
            return expr;
        };
        let mut new = call.clone();
        if let Callee::Expr(target) = &mut new.callee {
            *target = map(*target);
        }
        for argument in &mut new.arguments {
            *argument = map(*argument);
        }
        if self.call(id) == Some(&new) {
            expr
        } else {
            Expr::Call(self.add_call(new))
        }
    }

    /// Statement `id`.
    pub fn stmt(&self, id: StmtId) -> Option<&Stmt> {
        self.stmts.get(id.0 as usize)
    }

    /// The `va_list` variable a [`Stmt::VaStart`] (used or not) writes, if
    /// one does: the first.
    pub fn va_list(&self) -> Option<VarId> {
        self.va.as_ref()?;
        self.stmts.iter().find_map(|stmt| {
            if let Stmt::VaStart {
                list: Place::Var(var),
            } = *stmt
            {
                Some(var)
            } else {
                None
            }
        })
    }

    /// The width of expression `id`, if it is well formed (its operands
    /// first, with an explicit stack; linear in the size of its tree).
    pub fn width(&self, id: ExprId) -> Option<u16> {
        let mut widths: BTreeMap<ExprId, u16> = BTreeMap::new();
        let mut work = vec![(id, false)];
        while let Some((at, ready)) = work.pop() {
            if widths.contains_key(&at) {
                continue;
            }
            let expr = self.expr(at)?;
            if ready {
                let width = expr_width(self, expr, &mut |operand| {
                    widths.get(&operand).copied().ok_or_else(String::new)
                })
                .ok()?;
                widths.insert(at, width);
            } else {
                work.push((at, true));
                for operand in expr.operands(self) {
                    // Operands come before their users, so this ends.
                    if operand >= at {
                        return None;
                    }
                    work.push((operand, false));
                }
            }
        }
        widths.get(&id).copied()
    }
}

impl Expr {
    /// The expressions it uses, in evaluation order (a call's, from
    /// `function`'s [`Function::calls`]).
    pub fn operands<'f>(&self, function: &'f Function) -> impl Iterator<Item = ExprId> + 'f {
        let none = [None; 4];
        let (list, call) = match *self {
            Self::Const(_)
            | Self::Undefined(..)
            | Self::Var(_)
            | Self::AddressOf(_)
            | Self::Exception { .. } => (none, None),
            Self::Call(id) => (none, function.call(id)),
            Self::Unary(_, a)
            | Self::Extract { value: a, .. }
            | Self::Extend { value: a, .. }
            | Self::Cast { value: a, .. }
            | Self::Load { address: a, .. }
            | Self::Assign { value: a, .. } => ([Some(a), None, None, None], None),
            Self::Binary(_, a, b) | Self::Logical(_, a, b) | Self::Concat { high: a, low: b } => {
                ([Some(a), Some(b), None, None], None)
            }
            Self::Flag(_, a, b, c)
            | Self::Select {
                condition: a,
                then: b,
                otherwise: c,
            } => ([Some(a), Some(b), Some(c), None], None),
            Self::Lanes {
                op,
                operands: [a, b, c],
                ..
            } => {
                let mut list = [Some(a), Some(b), Some(c), None];
                truncate(&mut list, op.arity());
                (list, None)
            }
            Self::Float {
                op,
                rounding,
                operands: [a, b, c],
                ..
            } => {
                let mut list = [Some(rounding), Some(a), Some(b), Some(c)];
                truncate(&mut list, op.arity() + 1);
                (list, None)
            }
        };
        list.into_iter()
            .flatten()
            .chain(call.into_iter().flat_map(Call::operands))
    }

    /// `self` with each operand it holds itself replaced by `map` of it:
    /// all of them, but for an [`Expr::Call`], whose operands are its
    /// call's ([`Function::map_operands`] maps those).
    #[must_use]
    pub fn map_own(self, map: &mut dyn FnMut(ExprId) -> ExprId) -> Self {
        match self {
            Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::Var(_)
            | Expr::AddressOf(_)
            | Expr::Call(_)
            | Expr::Exception { .. } => self,
            Expr::Unary(op, a) => Expr::Unary(op, map(a)),
            Expr::Binary(op, a, b) => Expr::Binary(op, map(a), map(b)),
            Expr::Logical(op, a, b) => Expr::Logical(op, map(a), map(b)),
            Expr::Flag(op, a, b, c) => Expr::Flag(op, map(a), map(b), map(c)),
            Expr::Extract {
                value,
                offset,
                width,
            } => Expr::Extract {
                value: map(value),
                offset,
                width,
            },
            Expr::Concat { high, low } => Expr::Concat {
                high: map(high),
                low: map(low),
            },
            Expr::Extend {
                signed,
                value,
                width,
            } => Expr::Extend {
                signed,
                value: map(value),
                width,
            },
            Expr::Select {
                condition,
                then,
                otherwise,
            } => Expr::Select {
                condition: map(condition),
                then: map(then),
                otherwise: map(otherwise),
            },
            Expr::Lanes {
                lanes,
                op,
                operands: [a, b, c],
            } => Expr::Lanes {
                lanes,
                op,
                operands: [map(a), map(b), map(c)],
            },
            Expr::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands: [a, b, c],
            } => Expr::Float {
                op,
                format,
                lanes,
                output,
                rounding: map(rounding),
                operands: [map(a), map(b), map(c)],
            },
            Expr::Cast { value, ty } => Expr::Cast {
                value: map(value),
                ty,
            },
            Expr::Load { address, ty } => Expr::Load {
                address: map(address),
                ty,
            },
            Expr::Assign { var, value } => Expr::Assign {
                var,
                value: map(value),
            },
        }
    }
}

impl Call {
    /// The expressions it evaluates, in order: a computed callee, then the
    /// arguments.
    pub fn operands(&self) -> impl Iterator<Item = ExprId> + '_ {
        let callee = match self.callee {
            Callee::Address(_) | Callee::Import(_) => None,
            Callee::Expr(id) => Some(id),
        };
        callee.into_iter().chain(self.arguments.iter().copied())
    }
}

/// Clears all but the first `len` of `list`.
fn truncate(list: &mut [Option<ExprId>; 4], len: usize) {
    for slot in list.iter_mut().skip(len) {
        *slot = None;
    }
}

impl Stmt {
    /// The expressions it evaluates itself (not those of the blocks it
    /// holds), in evaluation order: a value before the address of the
    /// place it goes to, a call's callee and arguments before its
    /// results' addresses.
    pub fn roots(&self) -> Vec<ExprId> {
        let address = |place: &Place| match *place {
            Place::Var(_) => None,
            Place::Memory { address, .. } => Some(address),
        };
        match self {
            Self::Assign { place, value } => {
                core::iter::once(*value).chain(address(place)).collect()
            }
            Self::Call { results, call } => call
                .operands()
                .chain(results.iter().filter_map(address))
                .collect(),
            Self::Intrinsic {
                results,
                inputs: operands,
                ..
            }
            | Self::Escape {
                operands, results, ..
            } => operands
                .iter()
                .copied()
                .chain(results.iter().filter_map(address))
                .collect(),
            &Self::Expr(id)
            | &Self::If { condition: id, .. }
            | &Self::While { condition: id, .. }
            | &Self::DoWhile { condition: id, .. }
            | &Self::For { condition: id, .. }
            | &Self::Switch { scrutinee: id, .. }
            | &Self::Return(Some(id)) => vec![id],
            Self::Return(None)
            | Self::Break(_)
            | Self::Continue(_)
            | Self::Label(_)
            | Self::Goto(_)
            | Self::Trap(_)
            | Self::Unreachable
            | Self::Try { .. }
            | Self::VaStart { .. } => Vec::new(),
        }
    }

    /// The blocks it holds, in order: `then` and `otherwise`; a loop's
    /// body (a `for`'s `init`, `step`, then body); each arm's body; a
    /// `Try`'s body, then each handler's.
    pub fn blocks(&self) -> impl Iterator<Item = &Block> {
        let (fixed, arms, handlers): ([Option<&Block>; 3], &[Arm], &[Handler]) = match self {
            Self::If {
                then, otherwise, ..
            } => ([Some(then), Some(otherwise), None], &[], &[]),
            Self::While { body, .. } | Self::DoWhile { body, .. } => {
                ([Some(body), None, None], &[], &[])
            }
            Self::For {
                init, step, body, ..
            } => ([Some(init), Some(step), Some(body)], &[], &[]),
            Self::Switch { arms, .. } => ([None, None, None], arms, &[]),
            Self::Try { body, handlers } => ([Some(body), None, None], &[], handlers),
            Self::Assign { .. }
            | Self::Call { .. }
            | Self::Intrinsic { .. }
            | Self::Expr(_)
            | Self::Break(_)
            | Self::Continue(_)
            | Self::Label(_)
            | Self::Goto(_)
            | Self::Return(_)
            | Self::Trap(_)
            | Self::Unreachable
            | Self::Escape { .. }
            | Self::VaStart { .. } => ([None, None, None], &[], &[]),
        };
        fixed
            .into_iter()
            .flatten()
            .chain(arms.iter().map(|arm| &arm.body))
            .chain(handlers.iter().map(|handler| &handler.body))
    }

    /// The blocks it holds, as [`Stmt::blocks`], to change.
    pub fn blocks_mut(&mut self) -> impl Iterator<Item = &mut Block> {
        let (fixed, arms, handlers): ([Option<&mut Block>; 3], &mut [Arm], &mut [Handler]) =
            match self {
                Self::If {
                    then, otherwise, ..
                } => ([Some(then), Some(otherwise), None], &mut [], &mut []),
                Self::While { body, .. } | Self::DoWhile { body, .. } => {
                    ([Some(body), None, None], &mut [], &mut [])
                }
                Self::For {
                    init, step, body, ..
                } => ([Some(init), Some(step), Some(body)], &mut [], &mut []),
                Self::Switch { arms, .. } => ([None, None, None], arms, &mut []),
                Self::Try { body, handlers } => ([Some(body), None, None], &mut [], handlers),
                Self::Assign { .. }
                | Self::Call { .. }
                | Self::Intrinsic { .. }
                | Self::Expr(_)
                | Self::Break(_)
                | Self::Continue(_)
                | Self::Label(_)
                | Self::Goto(_)
                | Self::Return(_)
                | Self::Trap(_)
                | Self::Unreachable
                | Self::Escape { .. }
                | Self::VaStart { .. } => ([None, None, None], &mut [], &mut []),
            };
        fixed
            .into_iter()
            .flatten()
            .chain(arms.iter_mut().map(|arm| &mut arm.body))
            .chain(handlers.iter_mut().map(|handler| &mut handler.body))
    }

    /// Whether it is a loop (`while`, `do`-`while`, `for`).
    pub const fn is_loop(&self) -> bool {
        matches!(
            self,
            Self::While { .. } | Self::DoWhile { .. } | Self::For { .. }
        )
    }

    /// The places it writes itself: an assignment's, a call's,
    /// intrinsic's or escape's results, the `va_list` `va_start` writes.
    pub fn places(&self) -> &[Place] {
        match self {
            Self::Assign { place, .. } | Self::VaStart { list: place } => {
                core::slice::from_ref(place)
            }
            Self::Call { results, .. }
            | Self::Intrinsic { results, .. }
            | Self::Escape { results, .. } => results,
            Self::Expr(_)
            | Self::If { .. }
            | Self::While { .. }
            | Self::DoWhile { .. }
            | Self::For { .. }
            | Self::Switch { .. }
            | Self::Try { .. }
            | Self::Break(_)
            | Self::Continue(_)
            | Self::Label(_)
            | Self::Goto(_)
            | Self::Return(_)
            | Self::Trap(_)
            | Self::Unreachable => &[],
        }
    }

    /// Whether an exception may unwind out of it itself (not the blocks it
    /// holds): a call, a call with a non-standard convention, or a call in
    /// an expression it evaluates. Such a statement directly in a
    /// [`Stmt::Try`]'s body unwinds to its handlers.
    pub fn may_unwind(&self, function: &Function) -> bool {
        match self {
            Self::Call { .. }
            | Self::Escape {
                kind: Escape::NonStandardCall,
                ..
            } => true,
            Self::Assign { .. }
            | Self::Intrinsic { .. }
            | Self::Expr(_)
            | Self::If { .. }
            | Self::While { .. }
            | Self::DoWhile { .. }
            | Self::For { .. }
            | Self::Switch { .. }
            | Self::Break(_)
            | Self::Continue(_)
            | Self::Label(_)
            | Self::Goto(_)
            | Self::Return(_)
            | Self::Trap(_)
            | Self::Unreachable
            | Self::Escape { .. }
            | Self::Try { .. }
            | Self::VaStart { .. } => {
                let mut work = self.roots();
                let mut seen = BTreeSet::new();
                while let Some(id) = work.pop() {
                    if !seen.insert(id) {
                        continue;
                    }
                    match function.expr(id) {
                        Some(Expr::Call(_)) => return true,
                        Some(expr) => work.extend(expr.operands(function)),
                        None => {}
                    }
                }
                false
            }
        }
    }
}

impl Provenance {
    /// The origins of expression `id`.
    pub fn expr(&self, id: ExprId) -> &[Origin] {
        self.range(self.exprs.get(id.0 as usize))
    }

    /// The origins of statement `id`.
    pub fn stmt(&self, id: StmtId) -> &[Origin] {
        self.range(self.stmts.get(id.0 as usize))
    }

    /// Makes `origins` those of expression `id`.
    pub fn set_expr(&mut self, id: ExprId, origins: &[Origin]) {
        let span = self.add(origins);
        set(&mut self.exprs, id.0 as usize, span);
    }

    /// Makes `origins` those of statement `id`.
    pub fn set_stmt(&mut self, id: StmtId, origins: &[Origin]) {
        let span = self.add(origins);
        set(&mut self.stmts, id.0 as usize, span);
    }

    /// Adds `origin` to those of statement `id` (in place if they end the
    /// pool, else moved to its end).
    pub fn add_stmt_origin(&mut self, id: StmtId, origin: Origin) {
        let span = self.stmts.get(id.0 as usize).copied().unwrap_or_default();
        let start = span.start as usize;
        let span = if span.len > 0 && start + span.len as usize == self.origins.len() {
            span
        } else {
            let moved = number(self.origins.len());
            self.origins
                .extend_from_within(start..start + span.len as usize);
            Span {
                start: moved,
                len: span.len,
            }
        };
        self.origins.push(origin);
        set(
            &mut self.stmts,
            id.0 as usize,
            Span {
                len: span.len + 1,
                ..span
            },
        );
    }

    /// Adds to the origins of expression `id` the instructions among
    /// `folded` it does not have: those of what a pass folded into it (an
    /// expression or statement it replaced or made unneeded). They follow
    /// its own, in ascending order, each once; nothing else of `folded` is
    /// taken (its L1 values and blocks are its own, which the expression
    /// does not stand for).
    pub fn absorb_expr(&mut self, id: ExprId, folded: &[Origin]) {
        if let Some(merged) = absorbed(self.expr(id), folded) {
            self.set_expr(id, &merged);
        }
    }

    /// [`absorb_expr`](Self::absorb_expr) for statement `id`.
    pub fn absorb_stmt(&mut self, id: StmtId, folded: &[Origin]) {
        if let Some(merged) = absorbed(self.stmt(id), folded) {
            self.set_stmt(id, &merged);
        }
    }

    /// The instructions of the function's entry code (its prologue) no
    /// statement stands for: its signature's.
    pub fn entry(&self) -> &[Origin] {
        &self.entry
    }

    /// The instructions of the function's exit code (its epilogue) no
    /// statement stands for: its closing brace's.
    pub fn exit(&self) -> &[Origin] {
        &self.exit
    }

    /// Makes `origins` those of the function's entry code
    /// ([`entry`](Self::entry)).
    pub fn set_entry(&mut self, origins: &[Origin]) {
        self.entry = origins.to_vec();
    }

    /// Makes `origins` those of the function's exit code
    /// ([`exit`](Self::exit)).
    pub fn set_exit(&mut self, origins: &[Origin]) {
        self.exit = origins.to_vec();
    }

    fn range(&self, span: Option<&Span>) -> &[Origin] {
        span.and_then(|span| {
            let start = span.start as usize;
            self.origins.get(start..start + span.len as usize)
        })
        .unwrap_or(&[])
    }

    /// Appends `origins` to the pool.
    fn add(&mut self, origins: &[Origin]) -> Span {
        let start = number(self.origins.len());
        self.origins.extend_from_slice(origins);
        Span {
            start,
            len: number(origins.len()),
        }
    }
}

/// Sets entry `index` of `spans`, growing it as needed.
fn set(spans: &mut Vec<Span>, index: usize, span: Span) {
    if spans.len() <= index {
        spans.resize(index + 1, Span::default());
    }
    if let Some(slot) = spans.get_mut(index) {
        *slot = span;
    }
}

/// `own` with the instructions of `folded` it does not have after it, in
/// ascending order, each once; `None` if it has them all.
fn absorbed(own: &[Origin], folded: &[Origin]) -> Option<Vec<Origin>> {
    let mut new: Vec<Origin> = folded
        .iter()
        .filter(|origin| matches!(origin, Origin::Instruction(_)) && !own.contains(origin))
        .copied()
        .collect();
    if new.is_empty() {
        return None;
    }
    new.sort_unstable();
    new.dedup();
    let mut merged = Vec::with_capacity(own.len() + new.len());
    merged.extend_from_slice(own);
    merged.append(&mut new);
    Some(merged)
}
