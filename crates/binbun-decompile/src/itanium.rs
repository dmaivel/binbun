//! Exception handling under the Itanium C++ ABI (`__gxx_personality_v0`,
//! as GCC and Clang compile it for ELF): what is particular to it, beside
//! the ABI-neutral `Try` of L2 ([`binbun_ast::ir::Stmt::Try`]).
//!
//! - **What a landing pad receives** ([`exception_value`]): the unwinder
//!   sets two registers (x86-64 `rax` and `rdx`, AArch64 `x0` and `x1`):
//!   the exception object, then the selector, the filter of the action the
//!   personality routine matched (a type table index above 0, 0 for a
//!   cleanup, below 0 for an exception specification). L1's
//!   `Op::Landing` gives them in that order.
//! - **The landing pads' clauses** ([`Exceptions`]): per landing pad, its
//!   action chain from the exception tables, with each action's selector.
//! - **Resuming** ([`Exceptions::resume`]): a landing pad whose exception
//!   no clause takes, or whose cleanup is done, calls `_Unwind_Resume`
//!   with the exception object; unwinding goes on (C++'s implicit
//!   propagation).
//! - **Passes**: [`CatchDispatch`] (`catch-dispatch`, before structuring)
//!   turns a landing pad's tests of the selector into its `Try`'s
//!   handlers, one per action; [`TryRegions`] (`try-regions`, after)
//!   merges the `Try`s of one landing pad into one around the code between
//!   them, nests a `Try` whose chain ends with another's in it, and drops
//!   what C++ says implicitly (a cleanup's resume, a handler's jump to the
//!   code after its `Try`).

mod dispatch;
mod regions;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ast::ir::{Call, Callee, ExceptionValue, Expr, Function, HandlerKind, Stmt};

pub use dispatch::CatchDispatch;
pub use regions::TryRegions;

/// An action of a landing pad's chain: what the pad is entered for, and
/// the selector the personality routine hands it then.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Action {
    /// What the pad is entered for (never [`HandlerKind::Landing`]).
    pub kind: HandlerKind,
    /// The selector.
    pub selector: i64,
}

/// What decompilation knows about a program's exceptions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exceptions {
    /// Each landing pad's action chain, in the order the personality
    /// routine tries them, by the pad's address: where every call site
    /// unwinding to the pad lists the same chain.
    pub pads: BTreeMap<u64, Vec<Action>>,
    /// The functions that resume unwinding (`_Unwind_Resume`, the base
    /// ABI's), by address: their imports' thunks.
    pub resume: BTreeSet<u64>,
    /// The functions declared never to throw (C++ `throw()` or
    /// `noexcept`, `__attribute__((nothrow))`: the C++ ABI's
    /// `__cxa_begin_catch`, glibc's `__THROW` functions), by address:
    /// their imports' thunks, as the type library declares them. A call
    /// to one may join a `Try`'s body ([`TryRegions`]) whatever its call
    /// site says (compilers leave such calls in ranges that unwind out of
    /// the function).
    pub nothrow: BTreeSet<u64>,
    /// Why the action chain of each landing pad [`pads`](Self::pads) lacks
    /// is not known, by the pad's address.
    pub unknown: BTreeMap<u64, Unknown>,
    /// Whether the pads are those of funclets built into their functions
    /// (Microsoft x64), whose cleanups resume into the function's next
    /// handler rather than list it in their own chain: [`TryRegions`]
    /// then keeps a merged `Try` from taking in a `Try` with one of its
    /// cleanups inside another statement.
    pub funclets: bool,
}

impl Exceptions {
    /// None known.
    pub const fn new() -> Self {
        Self {
            pads: BTreeMap::new(),
            resume: BTreeSet::new(),
            nothrow: BTreeSet::new(),
            unknown: BTreeMap::new(),
            funclets: false,
        }
    }
}

/// Why a landing pad's action chain is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unknown {
    /// Its table's personality routine is not the Itanium C++ ABI's (or
    /// not named).
    Personality,
    /// The call sites unwinding to it list different chains.
    Disagree,
    /// Its table's action records are damaged.
    Damaged,
}

/// Why a `Try` keeps its landing pad's handler ([`HandlerKind::Landing`],
/// the goto floor) after [`CatchDispatch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Floor {
    /// The pad's action chain is not known.
    Unknown(Unknown),
    /// The pad's code does not test the selector as the walk follows
    /// (an `if` it cannot decide before code that is not the dispatch's,
    /// a path no action takes that does not resume unwinding).
    Dispatch,
    /// Code the dispatch would stand for is also reached otherwise.
    Shared,
}

impl core::fmt::Display for Floor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unknown(Unknown::Personality) => "other personality",
            Self::Unknown(Unknown::Disagree) => "call sites disagree",
            Self::Unknown(Unknown::Damaged) => "damaged actions",
            Self::Dispatch => "dispatch not recognised",
            Self::Shared => "dispatch code shared",
        })
    }
}

/// No exceptions known.
pub static NONE: Exceptions = Exceptions::new();

/// What the register `index` of the ones a landing pad receives (L1's
/// `Op::Landing` results, after the memory) holds: the exception object,
/// then the selector.
pub const fn exception_value(index: usize) -> Option<ExceptionValue> {
    match index {
        0 => Some(ExceptionValue::Object),
        1 => Some(ExceptionValue::Selector),
        _ => None,
    }
}

/// Whether an exception may unwind out of `stmt` itself (not the blocks
/// it holds): [`Stmt::may_unwind`], but for calls to functions that never
/// throw ([`Exceptions::nothrow`]).
pub fn unwinds(function: &Function, stmt: &Stmt, exceptions: &Exceptions) -> bool {
    if !stmt.may_unwind(function) {
        return false;
    }
    let nothrow = |call: &Call| matches!(call.callee, Callee::Address(address) if exceptions.nothrow.contains(&address));
    let mut work = stmt.roots();
    match stmt {
        Stmt::Call { call, .. } if nothrow(call) => work.extend(call.operands()),
        Stmt::Call { .. } | Stmt::Escape { .. } => return true,
        Stmt::Assign { .. }
        | Stmt::Intrinsic { .. }
        | Stmt::Expr(_)
        | Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable
        | Stmt::Try { .. }
        | Stmt::VaStart { .. } => {}
    }
    let mut seen = BTreeSet::new();
    while let Some(id) = work.pop() {
        if !seen.insert(id) {
            continue;
        }
        match function.expr(id) {
            Some(&Expr::Call(call)) => match function.call(call) {
                Some(call) if nothrow(call) => work.extend(call.operands()),
                Some(_) | None => return true,
            },
            Some(expr) => work.extend(expr.operands(function)),
            None => {}
        }
    }
    false
}
