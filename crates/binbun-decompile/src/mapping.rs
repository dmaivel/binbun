//! What lowering ([`crate::lower`]) says about how an L2 function stands
//! for its L1 function: where its parameters, return value and call
//! arguments are in L1's state. The checks of [`crate::validate`] run on
//! it (and on the L2 provenance's `Origin::Block`s: which L1 block each
//! statement and decision stands for).
//!
//! Registers and the stack pointer are the architecture's (from the
//! environment); stack offsets are relative to the stack pointer as a
//! callee sees it on entry (x86-64: the address of the return address, so
//! the first stack argument is at +8; AArch64: the first stack argument is
//! at +0).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use binbun_semantics::ir::RegisterId;
use binbun_ssa::ir::Value;

/// `width` bits of a register from bit `offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Piece {
    /// The register.
    pub register: RegisterId,
    /// The first bit.
    pub offset: u16,
    /// The number of bits.
    pub width: u16,
}

/// Where a value is in L1's state at a point (the entry, a call).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Bits of a register.
    Register(Piece),
    /// `bytes` bytes of memory at the stack pointer plus `offset`,
    /// little-endian.
    Stack {
        /// The offset from the stack pointer.
        offset: i64,
        /// The number of bytes.
        bytes: u16,
    },
}

/// How one call's arguments and result are in L1's state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallSite {
    /// One per argument of the L2 call, in order (of the arguments'
    /// widths), in the state at the call: L1's `Op::Call` `registers`, or
    /// a tail call's `Terminator::Leave` state.
    pub arguments: Vec<Source>,
    /// Where the callee's return value is after the call, low bits first
    /// (widths summing to the L2 call's result width; empty if none).
    pub results: Vec<Piece>,
}

/// How an L2 function stands for its L1 function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mapping {
    /// One per L2 parameter (in `Function::parameters` order), in L1's
    /// state at entry.
    pub parameters: Vec<Source>,
    /// Where L1's registers at a return hold the L2 return value, low bits
    /// first: widths summing to the return type's; empty if it returns no
    /// value.
    pub returns: Vec<Piece>,
    /// Each call, by the L1 value of its target: `Op::Call`'s `target`, or
    /// a tail call's `Terminator::Leave` `address`. The L2 `Stmt::Call`
    /// has `Origin::Value` of that value in its provenance.
    pub calls: BTreeMap<Value, CallSite>,
    /// The registers whose entry value L2 takes as undefined, since they
    /// are dropped from the function's interface ([`Context::dropped`](crate::lower::Context::dropped):
    /// no callee reads what it passes on of them, or every caller leaves
    /// garbage there): L1 is compared with L2 from states where they are
    /// undefined.
    pub dropped: Vec<RegisterId>,
    /// The unnamed argument registers of a variadic definition printed as
    /// C's (`Stmt::VaStart`): C reaches them only through the `va_list`,
    /// so L2 takes their entry values as undefined elsewhere (where the
    /// function passes one on in place to a callee, an undefined
    /// argument), and L1 is compared with L2 from states where they are
    /// undefined.
    pub unnamed: Vec<RegisterId>,
    /// The low bits of a register a declared parameter narrower than the
    /// register is passed in (a 32-bit `int` in a 64-bit register, a
    /// `double` in a vector register): the calling convention leaves the
    /// bits above unspecified, so no caller defines them, and L1 is
    /// compared with L2 from states where they are undefined.
    pub declared: Vec<Piece>,
}
