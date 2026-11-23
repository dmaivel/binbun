//! Semantics for instructions [`lift`](crate::lift) cannot do: not what
//! they do, but everything they might do, so that analyses built on them
//! stay sound.

use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::Semantics;
use binbun_semantics::build::Builder;
use binbun_semantics::ir::{ExprId, RegisterId, View};
use binbun_semantics::ir::{Stmt, Trap};
use binbun_x86::{
    Action, Encoding, FlagAction, Instruction, Mnemonic, Mode, OperandName, Register,
    RegisterClass, Value,
};

use crate::registers::{self, C0, FCW, FPR0, FS_BASE, FSW, FTOP, FTW, GS_BASE, K0, MXCSR, X86};
use crate::registers::{ZMM0, ZMM16};

/// The x87 state: the physical registers, control and status, TOP, the
/// condition codes and the tags.
fn x87_state() -> impl Iterator<Item = RegisterId> {
    (0..8)
        .map(|k| RegisterId(FPR0.0 + k))
        .chain([FCW, FSW, FTOP, FTW])
        .chain((0..4).map(|k| RegisterId(C0.0 + k)))
}

/// The vector registers `zmm0`–`zmm31` and the mask registers `k0`–`k7`.
fn vector_state() -> impl Iterator<Item = RegisterId> {
    (0..16)
        .map(|k| RegisterId(ZMM0.0 + k))
        .chain((0..16).map(|k| RegisterId(ZMM16.0 + k)))
        .chain((0..8).map(|k| RegisterId(K0.0 + k)))
}

/// Where operand register `register` lives in L0, whole or in part: a
/// general-purpose, vector or mask register, `mxcsr`, or a segment base.
/// `None` for the others: flags (from XED's flag record), the instruction
/// pointer (the CFG's), the x87 state (as a whole), and state L0 does not
/// declare.
fn place(register: Register) -> Option<View> {
    if let Some(view) = registers::gpr(register).or_else(|| registers::vector(register)) {
        return Some(view);
    }
    let whole = if register == Register::FSBASE {
        FS_BASE
    } else if register == Register::GSBASE {
        GS_BASE
    } else if register.class() == RegisterClass::Mxcsr {
        MXCSR
    } else {
        registers::mask(register)?
    };
    Some(registers::whole(whole))
}

/// Whether `register` is x87 state: an x87 register, the x87 control and
/// status (XED's pseudo-registers), or an MMX register (the x87 registers'
/// significands).
fn is_x87(register: Register) -> bool {
    matches!(
        register.class(),
        RegisterClass::X87 | RegisterClass::Pseudox87 | RegisterClass::Mmx
    )
}

/// What an instruction reads: the values the outputs are unknown
/// functions of.
#[derive(Default)]
struct Reads {
    values: Vec<ExprId>,
}

impl Reads {
    /// Reads `view`; as an input if `input`.
    fn read(&mut self, b: &mut Builder, view: View, input: bool) {
        let value = b.read(view);
        if input {
            self.values.push(value);
        }
    }
}

/// The register both sources of `instruction` are if it is a zero idiom:
/// an AVX-512 or mask exclusive-or, subtraction or and-not of a register
/// with itself, whose result is 0 whatever the register holds (Intel's
/// optimization manual, "zero idioms": it breaks the dependence, so
/// compilers clear registers with it). Not an input then: a function
/// clearing `zmm16` does not take it as a parameter.
fn zero_idiom(instruction: &Instruction) -> Option<Register> {
    if !matches!(
        instruction.mnemonic(),
        Mnemonic::Vpxord
            | Mnemonic::Vpxorq
            | Mnemonic::Vxorps
            | Mnemonic::Vxorpd
            | Mnemonic::Vpsubb
            | Mnemonic::Vpsubw
            | Mnemonic::Vpsubd
            | Mnemonic::Vpsubq
            | Mnemonic::Vpandnd
            | Mnemonic::Vpandnq
            | Mnemonic::Kxorb
            | Mnemonic::Kxorw
            | Mnemonic::Kxord
            | Mnemonic::Kxorq
    ) {
        return None;
    }
    let mut sources = instruction
        .operands()
        .filter(|operand| !operand.writemask && operand.action.reads())
        .map(|operand| match operand.value {
            Value::Register(register) => register,
            Value::Memory(_)
            | Value::Immediate { .. }
            | Value::SecondImmediate(_)
            | Value::Relative(_)
            | Value::Field(_) => None,
        });
    match (sources.next(), sources.next(), sources.next()) {
        (Some(Some(a)), Some(Some(b)), None) if a == b => Some(a),
        _ => None,
    }
}

/// Reads what `instruction` reads: the registers L0 declares that its
/// operands read (a vector register as wide as the operand, all the x87
/// state for an x87 or MMX register), the destinations it may leave
/// unwritten (what they keep is one of the possible results; under an
/// AVX-512 write mask other than `k0` that keeps what it masks, every
/// vector destination), the
/// base and index registers of its memory operands and address
/// computations, and the status flags it tests. A write mask `k0` is no
/// read (it means no masking), nor are the sources of a zero idiom
/// ([`zero_idiom`]). The registers of a memory operand are no
/// inputs (an address is accessed, not copied: a stack address only
/// accessed through does not escape); those of an address computation
/// (`lea`'s) are.
fn reads(b: &mut Builder, instruction: &Instruction) -> Reads {
    let mut reads = Reads::default();
    let mut x87 = false;
    let merging = !instruction.zeroing()
        && instruction.operands().any(|operand| {
            operand.writemask && operand.value != Value::Register(Some(Register::K0))
        });
    let idiom = zero_idiom(instruction);
    for operand in instruction.operands() {
        match operand.value {
            Value::Register(Some(Register::K0)) if operand.writemask => {}
            Value::Register(Some(register)) => {
                let kept = matches!(
                    operand.action,
                    Action::ConditionalWrite | Action::ReadConditionalWrite
                ) || (merging
                    && operand.action.writes()
                    && registers::vector(register).is_some());
                if (!operand.action.reads() || idiom == Some(register)) && !kept {
                    continue;
                }
                x87 |= is_x87(register);
                if let Some(view) = place(register) {
                    let view = if kept {
                        registers::whole(view.register)
                    } else {
                        view
                    };
                    reads.read(b, view, true);
                }
            }
            Value::Memory(memory) => {
                for register in [memory.base, memory.index].into_iter().flatten() {
                    if let Some(view) = place(register) {
                        reads.read(b, view, operand.name == OperandName::Agen);
                    }
                }
            }
            Value::Register(None)
            | Value::Immediate { .. }
            | Value::SecondImmediate(_)
            | Value::Relative(_)
            | Value::Field(_) => {}
        }
    }
    if x87 {
        for id in x87_state() {
            reads.read(b, registers::whole(id), true);
        }
    }
    if let Some(flags) = instruction.flags() {
        for effect in flags.effects {
            if effect.action == FlagAction::Test
                && let Some(id) = registers::flag(effect.flag)
            {
                reads.read(b, registers::whole(id), true);
            }
        }
    }
    reads
}

/// One location an instruction may write: an output of its intrinsic,
/// `width` bits, goes to `view`, zero-extended to it if wider.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Written {
    /// Where the output goes.
    view: View,
    /// The output's width.
    width: u16,
}

impl Written {
    /// All of register `id`.
    fn whole(id: RegisterId) -> Self {
        let view = registers::whole(id);
        Self {
            view,
            width: view.width,
        }
    }
}

/// Where operand register `register`, which `instruction` (decoded in
/// `mode`) writes as `action` says, gets an output, by x86's write rules:
/// a 32-bit general-purpose register written in 64-bit mode is zero-
/// extended into its register (where it may stay unwritten, the whole
/// register is unknown), an 8- or 16-bit one is only its part; a vector
/// register written by a VEX, EVEX or XOP encoding is zero-extended into
/// its `zmm` register, by a legacy one only its part; a mask register,
/// `mxcsr` and a segment base are written whole.
fn written(
    instruction: &Instruction,
    mode: Mode,
    register: Register,
    action: Action,
) -> Option<Written> {
    let view = place(register)?;
    let whole = registers::whole(view.register);
    let always = !matches!(
        action,
        Action::ConditionalWrite | Action::ReadConditionalWrite
    );
    let class = register.class();
    let extended = if class == RegisterClass::Gpr {
        mode == Mode::Bits64 && view.width == 32
    } else if matches!(
        class,
        RegisterClass::Xmm | RegisterClass::Ymm | RegisterClass::Zmm
    ) {
        instruction.encoding() != Encoding::Legacy
    } else {
        true
    };
    Some(if !extended {
        Written {
            view,
            width: view.width,
        }
    } else if always {
        Written {
            view: whole,
            width: view.width,
        }
    } else {
        Written::whole(view.register)
    })
}

/// The locations `instruction` (decoded in `mode`) may write, in order,
/// each once: the registers L0 declares that its operands (explicit or
/// implied) may write ([`written`]); the second mask register of
/// `vp2intersectd` and `vp2intersectq`, which write a pair but name one;
/// all the x87 state if it writes an x87 or MMX register; all the x87,
/// SSE, AVX and AVX-512 state for the `xrstor` family, which loads the
/// state components it is asked to (XED states none of them); and the
/// status flags XED's flag record says it sets, clears, modifies or leaves
/// undefined. Written memory is not among them.
fn locations(instruction: &Instruction, mode: Mode) -> Vec<Written> {
    let mut out: Vec<Written> = Vec::new();
    let mut x87 = false;
    for operand in instruction.operands() {
        let Value::Register(Some(register)) = operand.value else {
            continue;
        };
        if !operand.action.writes() {
            continue;
        }
        x87 |= is_x87(register);
        if let Some(location) = written(instruction, mode, register, operand.action) {
            out.push(location);
        }
        if matches!(
            instruction.mnemonic(),
            Mnemonic::Vp2intersectd | Mnemonic::Vp2intersectq
        ) && let Some(id) = registers::mask(register)
        {
            out.push(Written::whole(RegisterId(K0.0 + ((id.0 - K0.0) | 1))));
        }
    }
    let restores = matches!(
        instruction.mnemonic(),
        Mnemonic::Xrstor | Mnemonic::Xrstor64 | Mnemonic::Xrstors | Mnemonic::Xrstors64
    );
    if x87 || restores {
        out.extend(x87_state().map(Written::whole));
    }
    if restores {
        out.push(Written::whole(MXCSR));
        out.extend(vector_state().map(Written::whole));
    }
    if let Some(flags) = instruction.flags() {
        for effect in flags.effects {
            match effect.action {
                FlagAction::Test => {}
                FlagAction::Modify
                | FlagAction::Undefined
                | FlagAction::Clear
                | FlagAction::Set
                | FlagAction::FromAh
                | FlagAction::Pop => {
                    if let Some(id) = registers::flag(effect.flag) {
                        out.push(Written::whole(id));
                    }
                }
            }
        }
    }
    let mut seen = Vec::new();
    out.retain(|location| {
        let new = !seen.contains(&location.view);
        seen.push(location.view);
        new
    });
    out
}

/// The widest output of [`lift_opaque`]'s intrinsic: a location wider (a
/// `ymm` or `zmm` register) gets one output for each 128 bits, low bits
/// first, as C has integers no wider.
const PIECE: u16 = 128;

/// The outputs a location `width` bits wide gets: `(offset, width)` in it,
/// low bits first, none wider than [`PIECE`].
fn pieces(width: u16) -> impl Iterator<Item = (u16, u16)> {
    (0..width.div_ceil(PIECE)).map(move |k| (k * PIECE, (width - k * PIECE).min(PIECE)))
}

/// Where each output of [`lift_opaque`]'s intrinsic for `instruction`
/// (decoded in `mode`) goes, in order: the bits it is (a 32-bit output
/// zero-extended into its register is that register's low 32 bits; the
/// outputs of a `zmm` register are its four 128-bit lanes).
pub fn opaque_outputs(instruction: &Instruction, mode: Mode) -> Vec<View> {
    locations(instruction, mode)
        .into_iter()
        .flat_map(|location| {
            pieces(location.width).map(move |(offset, width)| View {
                offset: location.view.offset + offset,
                width,
                ..location.view
            })
        })
        .collect()
}

/// An over-approximation of `instruction` (decoded in `mode`): what it may
/// change becomes unknown, nothing is computed, but what it reads is read
/// so that L1 sees the dependencies.
///
/// It is one intrinsic, `unlifted` if it may write memory, else
/// `unlifted_registers`: its inputs are what the instruction reads
/// ([`reads`]: registers, flags), its outputs an unknown value for each
/// location it may write ([`locations`]; one for each 128 bits of a wider
/// one, concatenated), each then written there. The
/// intrinsic's inputs escape (a stack address it reads may be stored, or
/// kept in state L0 does not declare and read back by another
/// instruction: `kmovq k1, rax`, then `kmovq rcx, k1` with `rax` in the
/// frame), and `unlifted` stands for any change to memory. Registers L0
/// does not declare (APX's `r16`–`r31`, AMX's tiles, segment, control and
/// system registers) get nothing: only another instruction without
/// semantics can read them, and its outputs are unknown values of their
/// own.
///
/// It loads nothing, faults never and transfers no control: use it only
/// for instructions whose flow is sequential (control flow is the CFG's to
/// tell). `address` is not needed: no effect is computed.
pub fn lift_opaque(instruction: &Instruction, mode: Mode, _address: u64) -> Semantics {
    let mut b = Builder::new();
    let reads = reads(&mut b, instruction);
    let stores = instruction.operands().any(|operand| {
        operand.action.writes()
            && operand.name != OperandName::Agen
            && matches!(operand.value, Value::Memory(_))
    });
    let name = if stores {
        "unlifted"
    } else {
        "unlifted_registers"
    };
    let locations = locations(instruction, mode);
    if let Some(intrinsic) = X86.find_intrinsic(name) {
        let widths: Vec<u16> = locations
            .iter()
            .flat_map(|location| pieces(location.width).map(|(_, width)| width))
            .collect();
        let mut outputs = b.intrinsic(intrinsic, &reads.values, &widths).into_iter();
        for location in &locations {
            let mut value = None;
            for (_, piece) in pieces(location.width).zip(outputs.by_ref()) {
                value = Some(match value {
                    Some(low) => b.concat(piece, low),
                    None => piece,
                });
            }
            let Some(value) = value else { continue };
            let value = if location.width < location.view.width {
                b.zext(value, location.view.width)
            } else {
                value
            };
            b.write(location.view, value);
        }
    }
    // Every width above is a register's or 1, so the builder has nothing
    // to object to; should it ever, execution cannot be followed past the
    // instruction.
    b.finish().unwrap_or_else(|_| Semantics {
        body: vec![Stmt::Trap(Trap::InvalidInstruction)],
        ..Semantics::default()
    })
}
