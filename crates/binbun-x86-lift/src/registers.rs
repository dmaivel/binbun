//! What x86 declares to L0, registers and intrinsics, and where decoder
//! registers live.
//!
//! Each piece of state is one register: the 64-bit general-purpose
//! registers (sub-registers are views: `eax` is bits 0..32 of `rax`, `ah`
//! bits 8..16), the instruction pointer, each status flag as a 1-bit
//! register, the `FS`/`GS` segment bases, the vector registers `zmm0`–
//! `zmm15` (`xmm`/`ymm` are views), `mxcsr`, and the x87 state: the eight
//! physical registers `fpr0`–`fpr7` (`st(i)` is `fpr((top + i) mod 8)`),
//! the control word, the status word apart from TOP and the condition
//! codes (`fsw`), TOP (`ftop`), the condition codes `c0`–`c3` as 1-bit
//! registers, and the abridged tag word `ftw` (bit *i*: `fpr`*i* in use);
//! then AVX-512's state: the mask registers `k0`–`k7` and the vector
//! registers `zmm16`–`zmm31`. No instruction with semantics touches
//! AVX-512's state yet; instructions without semantics read and write it
//! ([`lift_opaque`](crate::lift_opaque)).
//!
//! Not declared: APX's `r16`–`r31`, AMX's tiles and their configuration,
//! segment selectors, control, debug and model-specific registers, bounds
//! and the CET shadow stack pointer, `PKRU` and `XCR0`. Only instructions
//! without semantics touch them, and what those write is an unknown value
//! that only another such instruction can read back.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use binbun_semantics::ir::{Declarations, IntrinsicInfo, RegisterId, RegisterInfo, View};
use binbun_x86::{Flag, Register, RegisterClass};

use crate::sites;

const fn info(name: &'static str, width: u16) -> RegisterInfo {
    RegisterInfo { name, width }
}

/// The registers, in [`RegisterId`] order.
const REGISTERS: [RegisterInfo; 83] = [
    info("rax", 64),
    info("rcx", 64),
    info("rdx", 64),
    info("rbx", 64),
    info("rsp", 64),
    info("rbp", 64),
    info("rsi", 64),
    info("rdi", 64),
    info("r8", 64),
    info("r9", 64),
    info("r10", 64),
    info("r11", 64),
    info("r12", 64),
    info("r13", 64),
    info("r14", 64),
    info("r15", 64),
    info("rip", 64),
    info("cf", 1),
    info("pf", 1),
    info("af", 1),
    info("zf", 1),
    info("sf", 1),
    info("of", 1),
    info("df", 1),
    info("fs_base", 64),
    info("gs_base", 64),
    info("zmm0", 512),
    info("zmm1", 512),
    info("zmm2", 512),
    info("zmm3", 512),
    info("zmm4", 512),
    info("zmm5", 512),
    info("zmm6", 512),
    info("zmm7", 512),
    info("zmm8", 512),
    info("zmm9", 512),
    info("zmm10", 512),
    info("zmm11", 512),
    info("zmm12", 512),
    info("zmm13", 512),
    info("zmm14", 512),
    info("zmm15", 512),
    info("mxcsr", 32),
    info("fpr0", 80),
    info("fpr1", 80),
    info("fpr2", 80),
    info("fpr3", 80),
    info("fpr4", 80),
    info("fpr5", 80),
    info("fpr6", 80),
    info("fpr7", 80),
    info("fcw", 16),
    info("fsw", 16),
    info("ftop", 3),
    info("c0", 1),
    info("c1", 1),
    info("c2", 1),
    info("c3", 1),
    info("ftw", 8),
    info("k0", 64),
    info("k1", 64),
    info("k2", 64),
    info("k3", 64),
    info("k4", 64),
    info("k5", 64),
    info("k6", 64),
    info("k7", 64),
    info("zmm16", 512),
    info("zmm17", 512),
    info("zmm18", 512),
    info("zmm19", 512),
    info("zmm20", 512),
    info("zmm21", 512),
    info("zmm22", 512),
    info("zmm23", 512),
    info("zmm24", 512),
    info("zmm25", 512),
    info("zmm26", 512),
    info("zmm27", 512),
    info("zmm28", 512),
    info("zmm29", 512),
    info("zmm30", 512),
    info("zmm31", 512),
];

/// An intrinsic whose inputs may escape through it (all of x86's: none is a
/// keyed hash) and that may change memory.
const fn intrinsic(
    name: &'static str,
    inputs: &'static [u16],
    outputs: &'static [u16],
) -> IntrinsicInfo {
    IntrinsicInfo {
        name,
        inputs,
        outputs,
        escapes: true,
        stores: true,
        opaque: false,
    }
}

/// Values the processor or the system supplies, and effects outside the
/// modelled state.
const INTRINSICS: [IntrinsicInfo; 23] = [
    // Leaf and subleaf (eax, ecx) to eax, ebx, ecx, edx.
    intrinsic("cpuid", &[32, 32], &[32, 32, 32, 32]),
    // The time-stamp counter.
    intrinsic("rdtsc", &[], &[64]),
    // The time-stamp counter and IA32_TSC_AUX.
    intrinsic("rdtscp", &[], &[64, 32]),
    // IA32_TSC_AUX.
    intrinsic("rdpid", &[], &[32]),
    // An extended control register (ecx) to edx:eax, and whether the
    // processor has it (#GP if not).
    intrinsic("xgetbv", &[32], &[64, 1]),
    // A random number, and whether one was available.
    intrinsic("rdrand", &[], &[64, 1]),
    intrinsic("rdseed", &[], &[64, 1]),
    // Whether a transaction (RTM, HLE) is running, and whether the
    // processor has them (#UD if not).
    intrinsic("xtest", &[], &[1, 1]),
    // Memory ordering: loads, stores, both.
    intrinsic("lfence", &[], &[]),
    intrinsic("sfence", &[], &[]),
    intrinsic("mfence", &[], &[]),
    // An instruction without semantics that may write memory (see
    // `lift_opaque`): what it reads in, an unknown value for each register
    // it writes out; it may change any memory, and store what it read (so
    // a stack address it reads is seen to escape). `unlifted_registers`,
    // last, is one that writes no memory.
    IntrinsicInfo {
        opaque: true,
        ..intrinsic("unlifted", &[], &[])
    },
    // RCPPS and RSQRTPS on one single-precision lane: approximations whose
    // bits differ between processor models.
    intrinsic("rcp", &[32], &[32]),
    intrinsic("rsqrt", &[32], &[32]),
    // Approximate: the x87 transcendentals, whose results differ between
    // processor models. The operands (st(0), then st(1) where the
    // instruction reads it) and the control word in; the result and its
    // status out: the exceptions it raises (invalid operation, denormal,
    // divide by zero, overflow, underflow, precision: bits 0 to 5) and
    // whether it was rounded up (C1, bit 6). The semantics compute the
    // rest exactly (stack, tags, NaNs, the out-of-range C2, special
    // operands).
    intrinsic("f2xm1", &[80, 16], &[80, 8]),
    intrinsic("fsin", &[80, 16], &[80, 8]),
    intrinsic("fcos", &[80, 16], &[80, 8]),
    // The sine, then the cosine.
    intrinsic("fsincos", &[80, 16], &[80, 80, 8]),
    intrinsic("fptan", &[80, 16], &[80, 8]),
    intrinsic("fpatan", &[80, 80, 16], &[80, 8]),
    intrinsic("fyl2x", &[80, 80, 16], &[80, 8]),
    intrinsic("fyl2xp1", &[80, 80, 16], &[80, 8]),
    IntrinsicInfo {
        stores: false,
        opaque: true,
        ..intrinsic("unlifted_registers", &[], &[])
    },
];

/// What x86 declares to L0.
pub const X86: Declarations = Declarations {
    registers: &REGISTERS,
    intrinsics: &INTRINSICS,
    sites: &sites::INFO,
};

/// `rax`; the general-purpose registers follow in encoding order (`rcx`,
/// `rdx`, `rbx`, `rsp`, `rbp`, `rsi`, `rdi`, `r8`–`r15`).
pub const RAX: RegisterId = RegisterId(0);
/// The stack pointer.
pub const RSP: RegisterId = RegisterId(4);
/// The instruction pointer.
pub const RIP: RegisterId = RegisterId(16);
/// The `FS` segment base.
pub const FS_BASE: RegisterId = RegisterId(24);
/// The `GS` segment base.
pub const GS_BASE: RegisterId = RegisterId(25);
/// `zmm0`; `zmm1`–`zmm15` follow.
pub const ZMM0: RegisterId = RegisterId(26);
/// The SSE control and status register.
pub const MXCSR: RegisterId = RegisterId(42);
/// Physical x87 register 0; `fpr1`–`fpr7` follow.
pub const FPR0: RegisterId = RegisterId(43);
/// The x87 control word.
pub const FCW: RegisterId = RegisterId(51);
/// The x87 status word without TOP and the condition codes: the exception
/// flags (bits 0 to 5), the stack fault (6), the error summary (7) and
/// busy (15); the other bits are 0.
pub const FSW: RegisterId = RegisterId(52);
/// The x87 TOP: the physical register that is `st(0)`.
pub const FTOP: RegisterId = RegisterId(53);
/// The x87 condition code C0; C1–C3 follow.
pub const C0: RegisterId = RegisterId(54);
/// The abridged x87 tag word: bit *i* set if `fpr`*i* is in use.
pub const FTW: RegisterId = RegisterId(58);
/// The mask register `k0`; `k1`–`k7` follow.
pub const K0: RegisterId = RegisterId(59);
/// `zmm16`; `zmm17`–`zmm31` follow.
pub const ZMM16: RegisterId = RegisterId(67);

/// The whole of register `id`.
pub fn whole(id: RegisterId) -> View {
    let width = X86.info(id).map_or(64, |info| info.width);
    View {
        register: id,
        offset: 0,
        width,
    }
}

/// The 1-bit register of a status flag, if L0 models it.
pub const fn flag(flag: Flag) -> Option<RegisterId> {
    Some(RegisterId(match flag {
        Flag::Cf => 17,
        Flag::Pf => 18,
        Flag::Af => 19,
        Flag::Zf => 20,
        Flag::Sf => 21,
        Flag::Of => 22,
        Flag::Df => 23,
        Flag::Tf
        | Flag::If
        | Flag::Iopl
        | Flag::Nt
        | Flag::Rf
        | Flag::Vm
        | Flag::Ac
        | Flag::Vif
        | Flag::Vip
        | Flag::Id => return None,
        Flag::Fc0 => C0.0,
        Flag::Fc1 => C0.0 + 1,
        Flag::Fc2 => C0.0 + 2,
        Flag::Fc3 => C0.0 + 3,
    }))
}

/// Where a vector register lives: a view of `zmm`*n* as wide as the
/// register (`xmm`*n* is bits 0..128), for `n` from 0 to 31.
pub fn vector(register: Register) -> Option<View> {
    let (first, width) = match register.class() {
        RegisterClass::Xmm => (Register::XMM0, 128),
        RegisterClass::Ymm => (Register::YMM0, 256),
        RegisterClass::Zmm => (Register::ZMM0, 512),
        RegisterClass::Bndcfg
        | RegisterClass::Bndstat
        | RegisterClass::Bound
        | RegisterClass::Cr
        | RegisterClass::Dr
        | RegisterClass::Flags
        | RegisterClass::Gpr
        | RegisterClass::Ip
        | RegisterClass::Mask
        | RegisterClass::Mmx
        | RegisterClass::Msr
        | RegisterClass::Mxcsr
        | RegisterClass::Pseudo
        | RegisterClass::Pseudox87
        | RegisterClass::Sr
        | RegisterClass::Tmp
        | RegisterClass::Treg
        | RegisterClass::Uif
        | RegisterClass::X87
        | RegisterClass::Xcr => return None,
    };
    let index = (register as u16)
        .checked_sub(first as u16)
        .filter(|&index| index < 32)?;
    let id = if index < 16 {
        ZMM0.0 + index
    } else {
        ZMM16.0 + index - 16
    };
    Some(View {
        register: RegisterId(id),
        offset: 0,
        width,
    })
}

/// The register of mask register `register` (`k0`–`k7`), whole.
pub fn mask(register: Register) -> Option<RegisterId> {
    if register.class() != RegisterClass::Mask {
        return None;
    }
    let index = (register as u16)
        .checked_sub(Register::K0 as u16)
        .filter(|&index| index < 8)?;
    Some(RegisterId(K0.0 + index))
}

/// What a part of `view` is called, by its width: `(width, name)` pairs,
/// narrowest first, each a view of `view` from its first bit (a read of
/// `w` bits of it is called by the first at least `w` wide). `rax`:
/// `al`, `ax`, `eax`, `rax`; bits 8..16 of `rax`: `ah`; `zmm17`: `xmm17`,
/// `ymm17`, `zmm17`; a mask register, a flag and the rest: their name.
pub fn names(view: View) -> Vec<(u16, String)> {
    let mut names: Vec<(u16, String)> = Register::ALL
        .iter()
        .filter_map(|&register| {
            let part = gpr(register).or_else(|| vector(register))?;
            (part.register == view.register
                && part.offset == view.offset
                && part.width <= view.width)
                .then(|| (part.width, String::from(register.name())))
        })
        .collect();
    names.sort();
    names.dedup_by_key(|(width, _)| *width);
    if names.is_empty()
        && let Some(info) = X86.info(view.register)
    {
        let name = if view.offset == 0 && view.width == info.width {
            String::from(info.name)
        } else {
            format!("{}_{}_{}", info.name, view.offset, view.width)
        };
        names.push((view.width, name));
    }
    names
}

/// Where a general-purpose register lives (in 64-bit mode): a view of its
/// full register. The decoder's 64-bit registers are contiguous in
/// encoding order (`RAX`, `RCX`, ..., `R15`, then APX's `R16`–`R31`, which
/// L0 does not model yet).
pub fn gpr(register: Register) -> Option<View> {
    if register.class() != RegisterClass::Gpr {
        return None;
    }
    let index = (register.full() as u16)
        .checked_sub(Register::RAX as u16)
        .filter(|&index| index < 16)?;
    Some(View {
        register: RegisterId(RAX.0 + index),
        offset: u16::try_from(register.offset()).ok()?,
        width: u16::try_from(register.width()).ok()?,
    })
}
