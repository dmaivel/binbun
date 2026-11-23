//! An image's architecture and calling convention, as each stage needs
//! them: what calls and system calls do in L1 (x86-64 System V for ELF,
//! Microsoft x64 for PE, AArch64 AAPCS64; through
//! [`ImageEnvironment`]), how lowering passes arguments ([`convention`]),
//! the setup the differential check runs a function under
//! ([`setup`]), and how C spells the platform's thread pointer
//! ([`thread_pointer`]; its register is the convention's
//! [`Convention::thread_pointer`]).

use binbun_aarch64_lift::AARCH64;
use binbun_aarch64_lift::registers::{self as a64};
use binbun_decompile::lower::Convention;
use binbun_decompile::validate::{Link, Setup};
use binbun_loader::{Format, Image, Machine};
use binbun_print::c::ThreadPointer;
use binbun_semantics::{Bits, Declarations, RegisterId};
use binbun_ssa::{CallEffect, Unwind};
use binbun_x86_lift::X86;
use binbun_x86_lift::registers::{RIP, RSP};

use crate::lift::{ImageEnvironment, SsaError};

/// The status flags a call may change (all but the direction flag).
const STATUS_FLAGS: [&str; 6] = ["cf", "pf", "af", "zf", "sf", "of"];

/// The vector and floating-point state a call may change, in both
/// conventions: every vector register (Microsoft x64 keeps the low halves
/// of `xmm6`–`xmm15`, which L0's whole registers cannot say), `mxcsr` (its
/// sticky flags), and the x87 registers, status, TOP and tags (the stack is
/// empty at calls; `st(0)` may hold a result), and AVX-512's mask registers
/// and `zmm16`–`zmm31` (no callee keeps them); the x87 control word is
/// kept.
const FLOATING: [&str; 56] = [
    "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10",
    "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "mxcsr", "fpr0", "fpr1", "fpr2", "fpr3", "fpr4",
    "fpr5", "fpr6", "fpr7", "fsw", "ftop", "c0", "c1", "c2", "c3", "ftw", "k0", "k1", "k2", "k3",
    "k4", "k5", "k6", "k7", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23",
    "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31",
];

/// The instruction sets lifted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Isa {
    X86_64,
    A64,
}

impl Isa {
    /// The instruction set of `image`'s code.
    pub(crate) fn of(image: &Image<'_>) -> Result<Self, SsaError> {
        match image.machine {
            Machine::X86_64 => Ok(Self::X86_64),
            Machine::Aarch64 => Ok(Self::A64),
            other @ (Machine::X86 | Machine::Arm | Machine::Other) => {
                Err(SsaError(format!("{other:?} code is not lifted yet")))
            }
        }
    }
}

/// An architecture's L0 and calling convention, as L1 construction and the
/// stack analyses need them.
#[derive(Clone, Debug)]
pub(crate) struct Abi {
    pub(crate) declarations: &'static Declarations,
    pub(crate) stack_pointer: RegisterId,
    /// The registers calls take arguments in.
    pub(crate) arguments: Vec<RegisterId>,
    /// A call's effect (it returns).
    pub(crate) call: CallEffect,
    /// A system call's effect.
    pub(crate) system_call: CallEffect,
    /// What the unwinder hands a landing pad, where the format's exception
    /// tables are the Itanium C++ ABI's (ELF): the registers it sets (the
    /// exception object, then the selector) and the size of the return
    /// address a call pushes (the unwinder restores the stack pointer from
    /// before the push).
    pub(crate) exceptions: Option<(Vec<RegisterId>, i64)>,
}

impl Abi {
    /// The convention of `image`'s code.
    ///
    /// # Errors
    ///
    /// The image's code is not lifted.
    pub(crate) fn of(image: &Image<'_>) -> Result<Self, SsaError> {
        Ok(match Isa::of(image)? {
            Isa::X86_64 => x86_64(image.format),
            Isa::A64 => aapcs64(image.format),
        })
    }

    /// What an exception unwinding through a call to the landing pad
    /// `pad` hands it: the registers a call keeps (all but those it may
    /// change, the stack pointer and those the pad receives) at their
    /// value at the call, the stack pointer before the call pushed
    /// anything, and the exception registers; `None` where exception
    /// tables are not read (PE).
    pub(crate) fn unwind(&self, pad: u64) -> Option<Unwind> {
        let (receives, pushed) = self.exceptions.as_ref()?;
        let kept = (0..self.declarations.registers.len())
            .map(|index| RegisterId(u16::try_from(index).unwrap_or(u16::MAX)))
            .filter(|register| {
                *register != self.stack_pointer
                    && !self.call.changes.contains(register)
                    && !receives.contains(register)
            })
            .collect();
        Some(Unwind {
            pad,
            kept,
            stack: Some((self.stack_pointer, *pushed)),
            receives: receives.clone(),
            ..Unwind::default()
        })
    }
}

/// The ids of the registers `names` of `declarations`.
fn registers<'n>(
    declarations: &Declarations,
    names: impl IntoIterator<Item = &'n str>,
) -> Vec<RegisterId> {
    names
        .into_iter()
        .filter_map(|name| declarations.find(name))
        .collect()
}

/// x86-64, by the image's format: System V for ELF and Mach-O, Microsoft
/// x64 for PE.
///
/// - A call may change the caller-saved registers (System V: `rax`, `rcx`,
///   `rdx`, `rsi`, `rdi`, `r8`–`r11`; Microsoft: `rax`, `rcx`, `rdx`,
///   `r8`–`r11`), the status flags and the floating-point state
///   ([`FLOATING`]; Microsoft's keeps the low 128 bits of `zmm6`–`zmm15`,
///   `xmm6`–`xmm15`: "Nonvolatile (XMM), Volatile (upper half of
///   YMM)"), leaves the direction flag clear and pops its return address
///   (`rsp` + 8).
/// - A system call changes `rax`, `rcx` and `r11` (Linux: the result, and
///   the return address and flags `syscall` saves; macOS's too, with the
///   carry flag saying whether it failed, among the flags), or on
///   Windows the caller-saved registers and the status flags.
fn x86_64(format: Format) -> Abi {
    let names = |names: &[&str]| registers(&X86, names.iter().copied());
    let flags = STATUS_FLAGS.iter().chain(&FLOATING).copied();
    let (call, system_call, arguments, kept_low) = match format {
        Format::Elf | Format::MachO => (
            registers(
                &X86,
                ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
                    .into_iter()
                    .chain(flags),
            ),
            if format == Format::MachO {
                registers(
                    &X86,
                    ["rax", "rdx", "rcx", "r11"].into_iter().chain(STATUS_FLAGS),
                )
            } else {
                names(&["rax", "rcx", "r11"])
            },
            names(&["rdi", "rsi", "rdx", "rcx", "r8", "r9"]),
            Vec::new(),
        ),
        Format::Pe => {
            let changes = registers(
                &X86,
                ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]
                    .into_iter()
                    .chain(flags),
            );
            let kept_low = (6..16)
                .filter_map(|n| X86.find(&format!("zmm{n}")))
                .map(|register| (register, 128))
                .collect();
            (
                changes.clone(),
                changes,
                names(&["rcx", "rdx", "r8", "r9"]),
                kept_low,
            )
        }
    };
    let known = X86
        .find("df")
        .map(|df| (df, Bits::from_u64(1, 0)))
        .into_iter()
        .collect();
    let exceptions = match format {
        Format::Elf | Format::MachO => Some((names(&["rax", "rdx"]), 8)),
        // An `__except` block: `__C_specific_handler` unwinds to it with
        // the exception code as the return value (`rax`).
        Format::Pe => Some((names(&["rax"]), 8)),
    };
    Abi {
        declarations: &X86,
        stack_pointer: RSP,
        arguments,
        call: CallEffect {
            changes: call,
            kept_low,
            known,
            stack: Some((RSP, 8)),
            returns: true,
        },
        system_call: CallEffect {
            changes: system_call,
            kept_low: Vec::new(),
            known: Vec::new(),
            stack: None,
            returns: true,
        },
        exceptions,
    }
}

/// AArch64: the procedure call standard (AAPCS64; Linux, Windows and
/// Apple's platforms agree on what is kept), by the image's format for
/// system calls.
///
/// - Arguments in `x0`–`x7`, results in `x0` and `x1`.
/// - A call may change `x0`–`x17` (`x8` the indirect result, `x16` and
///   `x17` the veneer scratch registers) and, but on Windows, `x18` (a
///   temporary on Linux; Windows' platform register, the thread's TEB,
///   which no code changes), the link register `x30`, the condition
///   flags, `btype`, every vector register but the low 64 bits of
///   `v8`–`v15` (`d8`–`d15`, which the callee keeps: "Use of the SIMD
///   and Floating-Point registers") and the cumulative flags in `fpsr`; it
///   keeps `x19`–`x29`, `sp` (no return address is pushed) and `fpcr`.
/// - A Linux system call (`svc #0`) changes only `x0`.
/// - A Darwin system call (`svc #0x80`) changes `x0` and `x1` (its
///   results) and the condition flags (the carry says whether it
///   failed).
fn aapcs64(format: Format) -> Abi {
    let last = match format {
        Format::Pe => 17,
        Format::Elf | Format::MachO => 18,
    };
    let changes = (0..=last)
        .chain([30])
        .map(a64::x)
        .chain([a64::N, a64::Z, a64::C, a64::V, a64::BTYPE, a64::FPSR])
        .chain((0..32).map(a64::v))
        .collect();
    Abi {
        declarations: &AARCH64,
        stack_pointer: a64::SP,
        arguments: (0..8).map(a64::x).collect(),
        call: CallEffect {
            changes,
            kept_low: (8..16).map(|n| (a64::v(n), 64)).collect(),
            known: Vec::new(),
            stack: Some((a64::SP, 0)),
            returns: true,
        },
        system_call: CallEffect {
            changes: match format {
                Format::MachO => vec![a64::x(0), a64::x(1), a64::N, a64::Z, a64::C, a64::V],
                Format::Elf | Format::Pe => vec![a64::x(0)],
            },
            kept_low: Vec::new(),
            known: Vec::new(),
            stack: None,
            returns: true,
        },
        exceptions: Some((vec![a64::x(0), a64::x(1)], 0)),
    }
}

/// The calling convention of `image`'s code (x86-64: System V for ELF,
/// System V as macOS has it for Mach-O, Microsoft x64 for PE; AArch64:
/// AAPCS64, as Apple's platforms change it for Mach-O and Windows for
/// PE), in `declarations`' registers.
pub fn convention(image: &Image<'_>, declarations: &Declarations) -> Convention {
    match (image.machine, image.format) {
        (Machine::Aarch64, Format::MachO) => Convention::darwin_arm64(declarations),
        (Machine::Aarch64, Format::Pe) => Convention::windows_arm64(declarations),
        (Machine::Aarch64, Format::Elf) => Convention::aapcs64(declarations),
        (_, Format::Pe) => Convention::microsoft_x64(declarations),
        (_, Format::Elf) => Convention::system_v(declarations),
        (_, Format::MachO) => Convention::darwin_x86_64(declarations),
    }
}

/// How C spells the thread pointer of `image`'s platform: Windows x64's
/// TEB (in `gs`) through Microsoft's intrinsics, or the KPCR there for
/// kernel-mode code ([`Image::kernel`]); Windows ARM64's TEB or KPCR (in
/// `x18`) as a pointer; else the ELF TLS ABIs'
/// `__builtin_thread_pointer()`, as Clang spells Apple's too (32-bit
/// x86, whose TEB is in `fs`, is not lifted).
pub fn thread_pointer(image: &Image<'_>) -> ThreadPointer {
    match (image.format, image.machine) {
        (Format::Pe, Machine::X86_64) if image.kernel => ThreadPointer::Kpcr,
        (Format::Pe, Machine::X86_64) => ThreadPointer::Teb,
        (Format::Pe, Machine::Aarch64) if image.kernel => ThreadPointer::KpcrX18,
        (Format::Pe, Machine::Aarch64) => ThreadPointer::TebX18,
        (Format::Pe, Machine::X86 | Machine::Arm | Machine::Other)
        | (Format::Elf | Format::MachO, _) => ThreadPointer::Builtin,
    }
}

/// The registers code that only passes a call on (a pure thunk) leaves as
/// it found them when it jumps to the callee: those the convention passes
/// arguments in, and those a call keeps (the stack pointer among them);
/// not the program counter, nor the scratch registers a call may change
/// that carry no argument (AAPCS64's `x16`/`x17`, which a PLT stub
/// loads the target into; the status flags).
///
/// # Errors
///
/// The image's code is not lifted.
pub(crate) fn handed_on(image: &Image<'_>) -> Result<Vec<RegisterId>, SsaError> {
    let abi = Abi::of(image)?;
    let convention = convention(image, abi.declarations);
    let counter = match Isa::of(image)? {
        Isa::X86_64 => RIP,
        Isa::A64 => a64::PC,
    };
    let count = u16::try_from(abi.declarations.registers.len()).unwrap_or(u16::MAX);
    Ok((0..count)
        .map(RegisterId)
        .filter(|register| {
            *register != counter
                && (!abi.call.changes.contains(register)
                    || convention.arguments.contains(register)
                    || convention.float_arguments.contains(register))
        })
        .collect())
}

/// The setup the differential check ([`binbun_decompile::validate::differential`])
/// runs the function of `image` at `entry` under: the image's architecture
/// and convention (x86-64: the return address pushed, the instruction
/// pointer at `entry`, the direction flag clear; AArch64: the return
/// address in `x30`, the program counter at `entry`), 10,000 blocks of
/// fuel, and up to 16 MiB below the entry stack pointer taken as its own
/// stack, with the convention's home space above the return address
/// ([`Convention::shadow`]).
///
/// # Errors
///
/// The image's code is not lifted.
pub fn setup(image: &Image<'_>, entry: u64) -> Result<Setup<'static>, String> {
    let environment = ImageEnvironment::new(image, &[]).map_err(|e| e.0)?;
    let declarations = environment.declarations();
    let (link, fixed) = match image.machine {
        Machine::X86_64 => {
            let df = declarations.find("df").map(|df| (df, 0));
            (
                Link::Stack { bytes: 8 },
                [(RIP, entry)].into_iter().chain(df).collect(),
            )
        }
        Machine::Aarch64 => (Link::Register(a64::x(30)), vec![(a64::PC, entry)]),
        other @ (Machine::X86 | Machine::Arm | Machine::Other) => {
            return Err(format!("{other:?} code is not lifted"));
        }
    };
    Ok(Setup {
        declarations,
        stack_pointer: environment.stack_pointer(),
        link,
        fixed,
        fuel: 10_000,
        frame: 1 << 24,
        shadow: u64::from(convention(image, declarations).shadow),
    })
}
