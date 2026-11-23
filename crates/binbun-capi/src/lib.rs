//! binbun's C API: `libbinbun`, a shared and a static library. What every
//! part shares (the version, statuses, strings) is declared by
//! `include/binbun/core.h`; the disassemblers by `include/binbun/disasm.h`
//! (with the large enumerations in the generated `disasm_generated.h`);
//! `include/binbun/binbun.h` includes them all. The header-only
//! `include/binbun/core.hpp` and `disasm.hpp` wrap them for C++.
//!
//! The headers are the authority on the ABI; this crate implements it. Every
//! type here that C sees has a fixed layout, pinned by `const` assertions
//! next to it and by the C test's `_Static_assert`s on the header, so the
//! two cannot drift apart.
//!
//! An instruction is decoded once into storage the caller owns (an opaque
//! block of `uint64_t`, holding the decoder's own instruction and a tag);
//! functions then read it: identity, operands, flags, control flow, and text
//! as a string or as tokens. The decoder for either architecture
//! ([`generic`], `binbun_decode`) keeps the instruction's address and bytes
//! beside the native instruction, and answers what both architectures share
//! as [`binbun_disasm`] does. Nothing allocates, nothing calls back, there is
//! no global state, and every entry point catches panics (which needs
//! `panic = "unwind"`) and reports them as [`Status::Failed`] or the
//! function's documented failure value.
//!
//! `unsafe` is confined to the `ffi` module, the conversions of C's pointers into
//! references and slices; every entry point checks its pointers and then
//! calls safe code.
//!
//! That safe code is public too, for Rust that speaks the C API's
//! vocabulary without its pointers (binbun's Python module): the decoders'
//! values as C sees them ([`Status`], [`Branch::new`], [`x86::failure`],
//! [`x86::X86Operand::new`], `From` the AArch64 decoder's operands into
//! the `A64*` structures, ...) and the token writers
//! ([`x86::write_tokens`], [`aarch64::write_tokens`]) into any
//! [`TokenSink`].
//!
//! # Building against it
//!
//! The crate builds `libbinbun` as a shared library, a static
//! library and an rlib; features `x86` and `aarch64` (both default) choose
//! the decoders, and a library built without one lacks its functions
//! (`binbun_x86_*`, `binbun_aarch64_*`). Panics are caught at every entry
//! point, which needs `panic = "unwind"` (the default): built with
//! `panic = "abort"`, a bug aborts the process instead of returning
//! `BINBUN_STATUS_FAILED`.
//!
//! A Rust crate that builds C or C++ against the library depends on this
//! one (and names it, `use binbun_capi as _;`, so that it is linked in);
//! the crate sets `links = "binbun"`, so its build script reads the header
//! directory as `DEP_BINBUN_INCLUDE`.
//!
//! Every function is thread-safe: there is no shared state, so any function
//! may run on any thread at the same time; instruction storage may be read
//! by several threads at once but not while a decode writes it, and a
//! decoder belongs to one thread at a time.

mod ffi;
mod text;

#[cfg(feature = "aarch64")]
pub mod aarch64;
#[cfg(any(feature = "x86", feature = "aarch64"))]
pub mod generic;
#[cfg(feature = "x86")]
pub mod x86;

use std::ffi::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};

use binbun_isa::{Flow, Target};

pub use text::{NO_OPERAND, TextSize, Token, TokenKind, TokenSink};

/// The library's major version.
pub const VERSION_MAJOR: u32 = 0;
/// The library's minor version.
pub const VERSION_MINOR: u32 = 1;
/// The library's patch version.
pub const VERSION_PATCH: u32 = 0;
/// The version as one number, `major << 16 | minor << 8 | patch`, as
/// `BINBUN_VERSION` in `binbun/core.h`.
pub const VERSION: u32 = VERSION_MAJOR << 16 | VERSION_MINOR << 8 | VERSION_PATCH;

/// The version of the library loaded, to compare with the header's
/// `BINBUN_VERSION`.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_version() -> u32 {
    VERSION
}

/// What a decode or another call came to (`binbun_status`).
///
/// Values 0 to 15 are about the call (`binbun/core.h`); from
/// [`Status::Invalid`] (16) to 63, why bytes are no instruction
/// (`binbun/disasm.h`).
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    /// Done.
    Ok = 0,
    /// A decoder has no bytes left; nothing was written.
    End = 1,
    /// The bytes end before the instruction does.
    Truncated = 2,
    /// A pointer the call needs is null.
    NullPointer = 3,
    /// An argument has no meaning (an unknown mode).
    BadArgument = 4,
    /// The library failed internally (a bug); nothing was written.
    Failed = 5,
    /// x86: no instruction has this encoding.
    Invalid = 16,
    /// x86: the instruction would be longer than 15 bytes.
    X86TooLong = 17,
    /// x86: the instruction does not exist in the mode.
    X86InvalidMode = 18,
    /// x86: a register field encodes no register.
    X86BadRegister = 19,
    /// x86: `LOCK` on an instruction that does not allow it.
    X86BadLockPrefix = 20,
    /// x86: `66`, `F2` or `F3` where none is allowed.
    X86BadLegacyPrefix = 21,
    /// x86: `REX` where none is allowed.
    X86BadRexPrefix = 22,
    /// x86: an opcode map that does not exist.
    X86BadMap = 23,
    /// x86: `EVEX.V'` is 0 outside 64-bit mode.
    X86BadEvexVPrime = 24,
    /// x86: `EVEX.z` without a mask register.
    X86BadEvexZeroing = 25,
    /// x86: `EVEX.L'L` is 3 without embedded rounding.
    X86BadEvexLength = 26,
    /// x86: a gather's index, destination and mask registers are not all
    /// different.
    X86GatherRegisters = 27,
    /// x86: registers that must differ are the same.
    X86BadRegisterMatch = 28,
    /// AArch64: no encoding has the word.
    Aarch64Unallocated = 32,
    /// AArch64: the encoding's decode makes the word UNDEFINED.
    Aarch64Undefined = 33,
    /// AArch64: the word is CONSTRAINED UNPREDICTABLE, rejected as LLVM
    /// rejects it.
    Aarch64Unpredictable = 34,
}

impl Status {
    /// What the status means, in a few words.
    pub const fn description(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::End => "end of buffer",
            Self::Truncated => "instruction is truncated",
            Self::NullPointer => "null pointer",
            Self::BadArgument => "bad argument",
            Self::Failed => "internal failure",
            Self::Invalid => "invalid instruction",
            Self::X86TooLong => "instruction is longer than 15 bytes",
            Self::X86InvalidMode => "instruction is invalid in this mode",
            Self::X86BadRegister => "invalid register encoding",
            Self::X86BadLockPrefix => "LOCK prefix is not allowed",
            Self::X86BadLegacyPrefix => "66, F2 or F3 prefix is not allowed",
            Self::X86BadRexPrefix => "REX prefix is not allowed",
            Self::X86BadMap => "invalid opcode map",
            Self::X86BadEvexVPrime => "EVEX.V' must be 1 outside 64-bit mode",
            Self::X86BadEvexZeroing => "EVEX.z requires a mask register",
            Self::X86BadEvexLength => "EVEX.L'L is 3 without embedded rounding",
            Self::X86GatherRegisters => "gather index, destination and mask registers must differ",
            Self::X86BadRegisterMatch => "registers that must differ are the same",
            Self::Aarch64Unallocated => "unallocated encoding",
            Self::Aarch64Undefined => "undefined instruction",
            Self::Aarch64Unpredictable => "constrained unpredictable instruction",
        }
    }

    /// The status numbered `code`.
    pub const fn from_code(code: i32) -> Option<Self> {
        Some(match code {
            0 => Self::Ok,
            1 => Self::End,
            2 => Self::Truncated,
            3 => Self::NullPointer,
            4 => Self::BadArgument,
            5 => Self::Failed,
            16 => Self::Invalid,
            17 => Self::X86TooLong,
            18 => Self::X86InvalidMode,
            19 => Self::X86BadRegister,
            20 => Self::X86BadLockPrefix,
            21 => Self::X86BadLegacyPrefix,
            22 => Self::X86BadRexPrefix,
            23 => Self::X86BadMap,
            24 => Self::X86BadEvexVPrime,
            25 => Self::X86BadEvexZeroing,
            26 => Self::X86BadEvexLength,
            27 => Self::X86GatherRegisters,
            28 => Self::X86BadRegisterMatch,
            32 => Self::Aarch64Unallocated,
            33 => Self::Aarch64Undefined,
            34 => Self::Aarch64Unpredictable,
            _ => return None,
        })
    }
}

/// What a status means, in a few words of lower-case English; empty for a
/// number that is no status.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_status_name(status: i32) -> Str {
    guard(Str::EMPTY, || {
        Status::from_code(status).map_or(Str::EMPTY, |status| Str::new(status.description()))
    })
}

/// A string that is not NUL-terminated: `length` bytes at `data`
/// (`binbun_str`). The strings the library hands out are constants of the
/// library, valid while it is loaded.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Str {
    /// The first byte; never null.
    pub data: *const c_char,
    /// The number of bytes.
    pub length: usize,
}

const _: () = assert!(size_of::<Str>() == 2 * size_of::<usize>());

impl Str {
    /// The empty string.
    pub const EMPTY: Self = Self::new("");

    /// `text`, which lives as long as the library.
    pub const fn new(text: &'static str) -> Self {
        Self {
            data: text.as_ptr().cast(),
            length: text.len(),
        }
    }
}

/// Bits of an operand's access: read.
pub const ACCESS_READ: u8 = 1;
/// Bits of an operand's access: written.
pub const ACCESS_WRITE: u8 = 2;

/// How an instruction transfers control (`binbun_branch_kind`), as
/// [`binbun_isa::Flow`] says.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BranchKind {
    /// Execution continues with the next instruction.
    None = 0,
    /// A jump, conditional or not.
    Jump = 1,
    /// A call.
    Call = 2,
    /// A return from a call.
    Return = 3,
    /// A software interrupt or deliberate exception, conditional or not.
    Trap = 4,
    /// An entry to the operating system or hypervisor.
    SystemCall = 5,
    /// A return from an interrupt, exception or system call.
    ExceptionReturn = 6,
    /// A halt until the next interrupt.
    Halt = 7,
}

/// Where a jump or call goes (`binbun_target_kind`), as
/// [`binbun_isa::Target`] says.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TargetKind {
    /// The instruction neither jumps nor calls.
    None = 0,
    /// A known address, in `target`.
    Address = 1,
    /// The address stored in memory at `target`, `pointer_size` bytes.
    Pointer = 2,
    /// A register or a computed memory operand.
    Indirect = 3,
    /// A segmented address: `selector` and the offset in `target`.
    Far = 4,
}

/// What an instruction does to the flow of control, as it would at an
/// address (`binbun_branch`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Branch {
    /// A [`BranchKind`].
    pub kind: u8,
    /// Whether the jump or trap happens only when a condition holds.
    pub conditional: bool,
    /// Whether execution can continue with the next instruction.
    pub falls_through: bool,
    /// A [`TargetKind`].
    pub target_kind: u8,
    /// The size in bytes of the pointer of a [`TargetKind::Pointer`].
    pub pointer_size: u8,
    /// Zero.
    pub reserved: u8,
    /// The segment selector of a [`TargetKind::Far`].
    pub selector: u16,
    /// The address, the pointer's address, or the far offset; 0 otherwise.
    pub target: u64,
}

// The layout the header describes, on 64-bit targets.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Branch>() == 16 && align_of::<Branch>() == 8);

impl Branch {
    /// No instruction: kind none, falls through.
    const NONE: Self = Self {
        kind: BranchKind::None as u8,
        conditional: false,
        falls_through: false,
        target_kind: TargetKind::None as u8,
        pointer_size: 0,
        reserved: 0,
        selector: 0,
        target: 0,
    };

    /// `flow` as C sees it.
    pub fn new(flow: Flow) -> Self {
        let (kind, conditional, target) = match flow {
            Flow::Next => (BranchKind::None, false, None),
            Flow::Jump(target) => (BranchKind::Jump, false, Some(target)),
            Flow::Branch(target) => (BranchKind::Jump, true, Some(target)),
            Flow::Call(target) => (BranchKind::Call, false, Some(target)),
            Flow::Return => (BranchKind::Return, false, None),
            Flow::Trap { conditional } => (BranchKind::Trap, conditional, None),
            Flow::SystemCall => (BranchKind::SystemCall, false, None),
            Flow::ExceptionReturn => (BranchKind::ExceptionReturn, false, None),
            Flow::Halt => (BranchKind::Halt, false, None),
        };
        let mut branch = Self {
            kind: kind as u8,
            conditional,
            falls_through: flow.falls_through(),
            ..Self::NONE
        };
        match target {
            None => {}
            Some(Target::Address(address)) => {
                branch.target_kind = TargetKind::Address as u8;
                branch.target = address;
            }
            Some(Target::Pointer { address, size }) => {
                branch.target_kind = TargetKind::Pointer as u8;
                branch.target = address;
                branch.pointer_size = size;
            }
            Some(Target::Indirect) => branch.target_kind = TargetKind::Indirect as u8,
            Some(Target::Far { selector, offset }) => {
                branch.target_kind = TargetKind::Far as u8;
                branch.selector = selector;
                branch.target = offset;
            }
        }
        branch
    }
}

/// Text options: none (`BINBUN_TEXT_DEFAULT`).
pub const TEXT_DEFAULT: u32 = 0;
/// Text option, AArch64 only: labels as offsets from the instruction (or
/// its page), as LLVM's C API writes them, instead of the addresses they
/// name (`BINBUN_TEXT_RELATIVE_LABELS`).
pub const TEXT_RELATIVE_LABELS: u32 = 1;

/// Runs `body`, or returns `failed` if it panics: no panic crosses into C.
#[expect(
    clippy::inline_always,
    reason = "each entry point's body is inlined into it, not called through closures"
)]
#[inline(always)]
fn guard<T>(failed: T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(failed)
}

/// Runs a call that returns a status, [`Status::Failed`] if it panics.
#[inline]
fn status(body: impl FnOnce() -> Result<(), Status>) -> Status {
    guard(Status::Failed, || match body() {
        Ok(()) => Status::Ok,
        Err(status) => status,
    })
}

/// `body` of the instruction of type `I` in the storage at `inst`, tagged
/// `tag`, or `failed` if it holds none or `body` panics.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[inline]
unsafe fn read<S, I, T: Copy>(
    inst: *const S,
    tag: u64,
    failed: T,
    body: impl FnOnce(&I) -> T,
) -> T {
    // SAFETY: passed on from the caller.
    match unsafe { ffi::load::<S, I>(inst, tag) } {
        Some(instruction) => guard(failed, || body(instruction)),
        None => failed,
    }
}

/// A name passed as `length` bytes at `name`, if it is UTF-8.
///
/// # Safety
///
/// `name` is null or readable for `length` bytes.
unsafe fn name<'a>(name: *const c_char, length: usize) -> Option<&'a str> {
    // SAFETY: passed on from the caller.
    let bytes = unsafe { ffi::bytes(name.cast::<u8>(), length) }.ok()?;
    std::str::from_utf8(bytes).ok()
}
