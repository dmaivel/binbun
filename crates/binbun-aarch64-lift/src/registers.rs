//! What AArch64 declares to L0, and where decoder registers live.
//!
//! Each piece of state is one register: the general-purpose registers
//! `x0`–`x30` (64 bits; `w`*n* is the view of bits 0..32), the stack pointer
//! `sp` (`SP_EL0`: the context is EL0), the program counter `pc`, the
//! condition flags `n`, `z`, `c`, `v` as 1-bit registers, `PSTATE.BTYPE`
//! (`btype`, 2 bits), the SIMD and floating-point registers `v0`–`v31` (128
//! bits; `b`, `h`, `s`, `d`, `q` *n* are views of their low bits), and
//! `fpcr` and `fpsr`; then the thread pointers `tpidr_el0` and
//! `tpidrro_el0` (read-only at EL0), and the `PSTATE` fields EL0 may change
//! by name: `dit`, `ssbs`, `tco` (1 bit each). The zero register is no
//! state: reading it gives 0, writing it does nothing.
//!
//! `pc` is declared for completeness: L0 never reads or writes it, since
//! an instruction's address is known when it is lifted and control
//! transfers are statements.
//!
//! Intrinsics are what the execution context (EL0 under Linux) leaves to
//! the processor or the system: the pointer authentication code
//! (`compute_pac`, Arm's `ComputePAC` with the
//! process's keys, which are EL1 state), barriers, events, the exclusive
//! monitors, memory ordering (`acquire`, `release`), system registers whose
//! values the system supplies and cache maintenance; and an instruction
//! without semantics ([`lift_opaque`](crate::lift_opaque)): `unlifted`,
//! which may write memory of an extent the decoder cannot state, or
//! `unlifted_registers`, which writes no memory but what its semantics
//! store, each with inputs and outputs of its own (what the instruction
//! reads, an unknown value for each location it writes). What the context
//! fixes (SP alignment checking,
//! top-byte-ignore, the 48-bit virtual address size) L0 computes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use binbun_aarch64::operand::{ElementSize, Register, RegisterClass};
use binbun_semantics::ir::{Declarations, IntrinsicInfo, RegisterId, RegisterInfo, View};

const fn info(name: &'static str, width: u16) -> RegisterInfo {
    RegisterInfo { name, width }
}

/// The registers, in [`RegisterId`] order.
const REGISTERS: [RegisterInfo; 77] = [
    info("x0", 64),
    info("x1", 64),
    info("x2", 64),
    info("x3", 64),
    info("x4", 64),
    info("x5", 64),
    info("x6", 64),
    info("x7", 64),
    info("x8", 64),
    info("x9", 64),
    info("x10", 64),
    info("x11", 64),
    info("x12", 64),
    info("x13", 64),
    info("x14", 64),
    info("x15", 64),
    info("x16", 64),
    info("x17", 64),
    info("x18", 64),
    info("x19", 64),
    info("x20", 64),
    info("x21", 64),
    info("x22", 64),
    info("x23", 64),
    info("x24", 64),
    info("x25", 64),
    info("x26", 64),
    info("x27", 64),
    info("x28", 64),
    info("x29", 64),
    info("x30", 64),
    info("sp", 64),
    info("pc", 64),
    info("n", 1),
    info("z", 1),
    info("c", 1),
    info("v", 1),
    info("btype", 2),
    info("v0", 128),
    info("v1", 128),
    info("v2", 128),
    info("v3", 128),
    info("v4", 128),
    info("v5", 128),
    info("v6", 128),
    info("v7", 128),
    info("v8", 128),
    info("v9", 128),
    info("v10", 128),
    info("v11", 128),
    info("v12", 128),
    info("v13", 128),
    info("v14", 128),
    info("v15", 128),
    info("v16", 128),
    info("v17", 128),
    info("v18", 128),
    info("v19", 128),
    info("v20", 128),
    info("v21", 128),
    info("v22", 128),
    info("v23", 128),
    info("v24", 128),
    info("v25", 128),
    info("v26", 128),
    info("v27", 128),
    info("v28", 128),
    info("v29", 128),
    info("v30", 128),
    info("v31", 128),
    info("fpcr", 32),
    info("fpsr", 32),
    info("tpidr_el0", 64),
    info("tpidrro_el0", 64),
    info("dit", 1),
    info("ssbs", 1),
    info("tco", 1),
];

/// An intrinsic whose inputs may escape through it (the conservative
/// default: see [`IntrinsicInfo::escapes`]).
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

/// What L0 does not compute (see the module documentation).
const INTRINSICS: [IntrinsicInfo; 21] = [
    // An instruction without semantics that may write memory of an extent
    // the decoder cannot state (see `lift_opaque`): what it reads in, an
    // unknown value for each location it writes out; it may change any
    // memory, and store what it read (a stack address it reads escapes).
    // `unlifted_registers`, last, is one whose stores its semantics make.
    IntrinsicInfo {
        opaque: true,
        ..intrinsic("unlifted", &[], &[])
    },
    // Arm's `ComputePAC(data, modifier, key)` with the process's key: key
    // 0 to 4 is APIAKey, APIBKey, APDAKey, APDBKey, APGAKey. The 64-bit
    // code; the semantics insert, compare and strip it (AddPAC, Auth). A
    // keyed hash: its output cannot be used to recover or access its
    // inputs, so a stack address used as the modifier (PACIASP's SP) does
    // not escape.
    IntrinsicInfo {
        escapes: false,
        ..intrinsic("compute_pac", &[64, 64, 3], &[64])
    },
    // Barriers. Each orders at least the accesses its option names (L1
    // keeps memory order around them); none is an acquire or release of
    // one access. DMB with its option (CRm: the domain in bits 3:2, the
    // access types in bits 1:0); DSB likewise, bit 4 set for the nXS form;
    // ISB; the speculation barriers SB, CSDB (data values only), SSBB and
    // PSSBB (speculative store bypass).
    intrinsic("dmb", &[4], &[]),
    intrinsic("dsb", &[5], &[]),
    intrinsic("isb", &[], &[]),
    intrinsic("sb", &[], &[]),
    intrinsic("csdb", &[], &[]),
    intrinsic("ssbb", &[], &[]),
    intrinsic("pssbb", &[], &[]),
    // Waiting and events: WFE (waits unless the event register is set,
    // then clears it), WFI (waits for an interrupt), SEV (signals an event
    // to all processors), SEVL (sets the local event register).
    intrinsic("wfe", &[], &[]),
    intrinsic("wfi", &[], &[]),
    intrinsic("sev", &[], &[]),
    intrinsic("sevl", &[], &[]),
    // A system register EL0 may read whose value the processor or the
    // system supplies (timers, identification, cache geometry): its
    // encoding `op0:op1:CRn:CRm:op2` (2, 3, 4, 4, 3 bits) in, the value out.
    // The semantics decide which encodings EL0 may read.
    intrinsic("system_register", &[16], &[64]),
    // Cache maintenance by virtual address (DC CVAU, CVAC, CVAP, CVADP,
    // CIVAC, IC IVAU): the operation (the SYS encoding as
    // `op0:op1:CRn:CRm:op2`, op0 being 1, as for `system_register`) and the
    // address. Only caches change: the data a program sees stays the same.
    // A translation fault for an unmapped address is the machine's, as
    // translation is (qemu-user raises none).
    intrinsic("cache_maintenance", &[16, 64], &[]),
    // The exclusive monitors (Arm's `AArch64.SetExclusiveMonitors`): a
    // load exclusive of `bytes` (8 bits) bytes at `address` (64) marks them
    // for that block, after its access succeeded.
    intrinsic("exclusive_load", &[64, 8], &[]),
    // A store exclusive of `bytes` bytes at `address`: 1 if the monitors
    // fail (`!AArch64.ExclusiveMonitorsPass`) and nothing is stored, 0 if
    // the store happens; either way the local monitor is cleared. It
    // follows the store's alignment check (Arm's order) and precedes its
    // other aborts: a failing store exclusive takes no translation or
    // permission fault (IMPLEMENTATION DEFINED; Arm's pseudocode and qemu
    // order it so, the Apple M3 does not).
    intrinsic("exclusive_store", &[64, 8], &[1]),
    // CLREX: clears the local monitor (`ClearExclusiveLocal`).
    intrinsic("clear_exclusive", &[], &[]),
    // Memory ordering: acquire (no later access is observed before the
    // access it follows) and release (no earlier access is observed after
    // the access it precedes).
    intrinsic("acquire", &[], &[]),
    intrinsic("release", &[], &[]),
    IntrinsicInfo {
        stores: false,
        opaque: true,
        ..intrinsic("unlifted_registers", &[], &[])
    },
];

/// What AArch64 declares to L0.
pub const AARCH64: Declarations = Declarations {
    registers: &REGISTERS,
    intrinsics: &INTRINSICS,
    sites: &[],
};

/// `x0`; `x1`–`x30` follow ([`x`]).
pub const X0: RegisterId = RegisterId(0);
/// The stack pointer (`SP_EL0`).
pub const SP: RegisterId = RegisterId(31);
/// The program counter.
pub const PC: RegisterId = RegisterId(32);
/// The negative flag.
pub const N: RegisterId = RegisterId(33);
/// The zero flag.
pub const Z: RegisterId = RegisterId(34);
/// The carry flag.
pub const C: RegisterId = RegisterId(35);
/// The overflow flag.
pub const V: RegisterId = RegisterId(36);
/// `PSTATE.BTYPE`: the branch type the next instruction checks in a guarded
/// page.
pub const BTYPE: RegisterId = RegisterId(37);
/// `v0`; `v1`–`v31` follow ([`v`]).
pub const V0: RegisterId = RegisterId(38);
/// The floating-point control register.
pub const FPCR: RegisterId = RegisterId(70);
/// The floating-point status register.
pub const FPSR: RegisterId = RegisterId(71);
/// `TPIDR_EL0`: the thread pointer.
pub const TPIDR_EL0: RegisterId = RegisterId(72);
/// `TPIDRRO_EL0`: the thread pointer EL0 can only read.
pub const TPIDRRO_EL0: RegisterId = RegisterId(73);
/// `PSTATE.DIT`: data-independent timing.
pub const DIT: RegisterId = RegisterId(74);
/// `PSTATE.SSBS`: speculative store bypass safe.
pub const SSBS: RegisterId = RegisterId(75);
/// `PSTATE.TCO`: tag check override.
pub const TCO: RegisterId = RegisterId(76);

/// General-purpose register `x`*n* (`n` below 31; 31 is the zero register or
/// the stack pointer, which are not this).
pub const fn x(n: u8) -> RegisterId {
    RegisterId(X0.0 + n as u16)
}

/// SIMD and floating-point register `v`*n* (`n` below 32).
pub const fn v(n: u8) -> RegisterId {
    RegisterId(V0.0 + n as u16)
}

/// The whole of register `id`.
pub fn whole(id: RegisterId) -> View {
    let width = AARCH64.info(id).map_or(64, |info| info.width);
    View {
        register: id,
        offset: 0,
        width,
    }
}

/// Where a general-purpose register operand lives: a view of `x`*n* or of
/// `sp` (`w`*n* and `wsp` are their low 32 bits). `None` for the zero
/// register (no state) and for other register classes.
pub fn general(register: Register) -> Option<View> {
    let (width, stack) = match register.class {
        RegisterClass::W => (32, false),
        RegisterClass::X => (64, false),
        RegisterClass::Wsp => (32, true),
        RegisterClass::Xsp => (64, true),
        RegisterClass::B
        | RegisterClass::H
        | RegisterClass::S
        | RegisterClass::D
        | RegisterClass::Q
        | RegisterClass::V
        | RegisterClass::Z
        | RegisterClass::P
        | RegisterClass::Pn
        | RegisterClass::Zt
        | RegisterClass::C
        | RegisterClass::Ffr => return None,
    };
    let id = match register.number {
        0..31 => x(register.number),
        31 if stack => SP,
        _ => return None,
    };
    Some(View {
        register: id,
        offset: 0,
        width,
    })
}

/// Where a SIMD and floating-point register operand lives: a view of
/// `v`*n*. A scalar (`b3` to `q3`) is its low bits; a vector of `count`
/// elements (`v3.8b`, `v3.4s`) its low `count` × element bits; an element
/// (`v3.d[1]`) its bits at the index. `None` for other classes and for an
/// element size without a count or index (SVE's `z3.d`).
pub fn simd(register: Register) -> Option<View> {
    let element = |size: ElementSize| -> u16 {
        match size {
            ElementSize::B => 8,
            ElementSize::H => 16,
            ElementSize::S => 32,
            ElementSize::D => 64,
            ElementSize::Q => 128,
        }
    };
    let (offset, width) = match register.class {
        RegisterClass::B => (0, 8),
        RegisterClass::H => (0, 16),
        RegisterClass::S => (0, 32),
        RegisterClass::D => (0, 64),
        RegisterClass::Q => (0, 128),
        RegisterClass::V => {
            let arrangement = register.arrangement?;
            let size = element(arrangement.element);
            match (register.index, arrangement.count) {
                (Some(index), _) => (u16::from(index) * size, size),
                (None, 0) => return None,
                (None, count) => (0, u16::from(count) * size),
            }
        }
        RegisterClass::W
        | RegisterClass::X
        | RegisterClass::Wsp
        | RegisterClass::Xsp
        | RegisterClass::Z
        | RegisterClass::P
        | RegisterClass::Pn
        | RegisterClass::Zt
        | RegisterClass::C
        | RegisterClass::Ffr => return None,
    };
    (register.number < 32 && offset + width <= 128).then(|| View {
        register: v(register.number),
        offset,
        width,
    })
}

/// What a part of `view` is called, by its width: `(width, name)` pairs,
/// narrowest first, each a view of `view` from its first bit (a read of
/// `w` bits of it is called by the first at least `w` wide). `x3`: `w3`,
/// `x3`; `sp`: `wsp`, `sp`; `v3`: `b3`, `h3`, `s3`, `d3`, `q3`; a flag and
/// the rest: their name.
pub fn names(view: View) -> Vec<(u16, String)> {
    let id = view.register.0;
    let parts: &[(u16, &str)] = if view.register == SP {
        &[(32, "wsp"), (64, "sp")]
    } else if id < SP.0 {
        &[(32, "w"), (64, "x")]
    } else if (V0.0..V0.0 + 32).contains(&id) {
        &[(8, "b"), (16, "h"), (32, "s"), (64, "d"), (128, "q")]
    } else {
        &[]
    };
    let number = if view.register == SP {
        String::new()
    } else {
        format!("{}", id.saturating_sub(if id < SP.0 { X0.0 } else { V0.0 }))
    };
    let mut names: Vec<(u16, String)> = parts
        .iter()
        .filter(|&&(width, _)| view.offset == 0 && width <= view.width)
        .map(|&(width, prefix)| (width, format!("{prefix}{number}")))
        .collect();
    if names.is_empty()
        && let Some(info) = AARCH64.info(view.register)
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
