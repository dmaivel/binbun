//! Semantics for instructions [`lift`](crate::lift) cannot do yet: not what
//! they do, but everything they may do, from the decoder's metadata, so
//! that analyses built on them stay sound.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use binbun_aarch64::operand::{
    ExtendKind, Memory, Modifier, NameKind, Offset, Register, RegisterClass, RegisterList,
    ShiftKind, Writeback, Za, ZaList,
};
use binbun_aarch64::{Encoding, FlagSet, Instruction, MemoryKind, Operand};
use binbun_isa::Flow;
use binbun_semantics::Semantics;
use binbun_semantics::build::Builder;
use binbun_semantics::ir::{Binary, ExprId, RegisterId, View};

use crate::lifter::LiftError;
use crate::registers::{self, AARCH64, BTYPE, C, FPCR, FPSR, N, SP, V, Z};

/// `op0:op1:CRn:CRm:op2` of NZCV (the four flag registers) and of SVCR
/// (whose `SM` bit, when it changes, resets the SIMD and floating-point
/// registers and FPSR).
const SYSREG_NZCV: u16 = 0xda10;
const SYSREG_SVCR: u16 = 0xda12;

/// The most bytes one L0 access moves.
const CHUNK: u32 = 64;

/// The L0 registers system register or `PSTATE` field `operand` is, by
/// name in the register file (`fpcr`, `fpsr`; NZCV is the four flag
/// registers); `None` where L0 declares no such register.
fn system_state(operand: Operand) -> Option<Vec<RegisterId>> {
    if let Operand::SystemRegister(register) = operand {
        if register.encoding == SYSREG_NZCV {
            return Some([N, Z, C, V].into());
        }
        let name = register.name?.to_ascii_lowercase();
        return AARCH64.find(&name).map(|id| [id].into());
    }
    if let Operand::Named(named) = operand
        && named.kind == NameKind::PstateField
    {
        return AARCH64.find(named.name).map(|id| [id].into());
    }
    None
}

/// The register an operand register is in L0: the `x` register or `sp` of
/// a general register (`None` for the zero register), the low 8, 16, 32 or
/// 64 bits of the `v` register of a scalar SIMD and floating-point
/// register (`d15` is `v15`'s low 64 bits), the `v` register of a vector
/// or SVE vector register (SVE's `z`*n* holds `v`*n* in its low 128
/// bits); `None` for state L0 does not model (predicates, `zt0`, control
/// registers, FFR).
fn state(register: Register) -> Option<View> {
    let scalar = |width| {
        (register.number < 32).then(|| View {
            width,
            ..registers::whole(registers::v(register.number))
        })
    };
    match register.class {
        RegisterClass::W | RegisterClass::X | RegisterClass::Wsp | RegisterClass::Xsp => {
            registers::general(register)
        }
        RegisterClass::B => scalar(8),
        RegisterClass::H => scalar(16),
        RegisterClass::S => scalar(32),
        RegisterClass::D => scalar(64),
        RegisterClass::Q | RegisterClass::V | RegisterClass::Z => {
            (register.number < 32).then(|| registers::whole(registers::v(register.number)))
        }
        RegisterClass::P
        | RegisterClass::Pn
        | RegisterClass::Zt
        | RegisterClass::C
        | RegisterClass::Ffr => None,
    }
}

/// Whether `register` is a SIMD and floating-point or SVE vector register.
const fn is_vector(register: Register) -> bool {
    matches!(
        register.class,
        RegisterClass::B
            | RegisterClass::H
            | RegisterClass::S
            | RegisterClass::D
            | RegisterClass::Q
            | RegisterClass::V
            | RegisterClass::Z
    )
}

/// The registers of a list, their numbers wrapping as the class's do.
fn members(list: RegisterList) -> impl Iterator<Item = Register> {
    let wrap = u16::from(list.registers().max(1));
    (0..u16::from(list.count)).map(move |k| {
        let number = (u16::from(list.first.number) + k * u16::from(list.stride)) % wrap;
        Register {
            number: u8::try_from(number).unwrap_or(u8::MAX),
            ..list.first
        }
    })
}

/// The `w` register selecting ZA slices (`w12` of `za0h.s[w12, 0]`).
const fn slice_index(za: Za) -> Option<Register> {
    match za.slice {
        Some(slice) => Some(Register::new(RegisterClass::W, slice.index)),
        None => None,
    }
}

/// The registers `operand` reads where it is read (memory operands'
/// registers are the address's, not these).
fn operand_registers(operand: Operand) -> Vec<Register> {
    match operand {
        Operand::Register(register) | Operand::Writeback(register) => [register].into(),
        Operand::List(list) => members(list).collect(),
        Operand::IndexedRegister(indexed) => [indexed.register, indexed.index].into(),
        Operand::Za(za) | Operand::ZaList(ZaList::Slice(za)) => {
            slice_index(za).into_iter().collect()
        }
        Operand::ZaList(ZaList::Tiles(_))
        | Operand::Immediate(_)
        | Operand::Float(_)
        | Operand::Shift(_)
        | Operand::Extend(_)
        | Operand::Memory(_)
        | Operand::Label(_)
        | Operand::Condition(_)
        | Operand::SystemRegister(_)
        | Operand::Named(_)
        | Operand::TableSlice(_) => Vec::new(),
    }
}

/// The registers `operand` writes where it is written: not the index
/// registers that select ZA slices or predicates.
fn written_registers(operand: Operand) -> Vec<Register> {
    match operand {
        Operand::IndexedRegister(indexed) => [indexed.register].into(),
        Operand::Za(_) | Operand::ZaList(_) => Vec::new(),
        Operand::Register(_)
        | Operand::Writeback(_)
        | Operand::List(_)
        | Operand::Immediate(_)
        | Operand::Float(_)
        | Operand::Shift(_)
        | Operand::Extend(_)
        | Operand::Memory(_)
        | Operand::Label(_)
        | Operand::Condition(_)
        | Operand::SystemRegister(_)
        | Operand::Named(_)
        | Operand::TableSlice(_) => operand_registers(operand),
    }
}

/// A location the instruction may write, in the order it is written.
#[derive(Clone, Copy)]
enum Effect {
    /// An output of `width` bits written to `view` (zero-extended into it
    /// if narrower).
    Output {
        /// Where.
        view: View,
        /// The output's width.
        width: u16,
    },
    /// A computed value (an exact writeback) written to `view`.
    Value {
        /// Where.
        view: View,
        /// What.
        value: ExprId,
    },
    /// An output of `bytes` bytes stored at `address`.
    Store {
        /// Where.
        address: ExprId,
        /// How many bytes.
        bytes: u16,
    },
}

/// The over-approximation being built.
struct Opaque {
    b: Builder,
    /// Every value the instruction reads: registers, flags and memory.
    reads: Vec<ExprId>,
    /// The base registers written back and their new values (`None`:
    /// unknown, as for the memory copy and set instructions, whose bases
    /// move by the size copied).
    writebacks: Vec<(View, Option<ExprId>)>,
    /// What it writes, in order.
    effects: Vec<Effect>,
    /// Whether it may write memory L0 cannot place.
    unlifted: bool,
}

impl Opaque {
    /// Reads `view` as one of the instruction's inputs.
    fn read(&mut self, view: View) -> ExprId {
        let value = self.b.read(view);
        self.reads.push(value);
        value
    }

    /// Reads the operand register `register`, if it is L0 state.
    fn read_register(&mut self, register: Register) -> Option<ExprId> {
        let view = state(register)?;
        Some(self.read(view))
    }

    /// `value` zero-extended or truncated to `width` bits.
    fn fit(&mut self, value: ExprId, width: u16) -> ExprId {
        match self.b.width(value).cmp(&width) {
            Ordering::Less => self.b.zext(value, width),
            Ordering::Greater => self.b.extract(value, 0, width),
            Ordering::Equal => value,
        }
    }

    /// Writes an output to register `id` whole.
    fn clobber(&mut self, id: RegisterId) {
        let whole = registers::whole(id);
        self.effects.push(Effect::Output {
            view: whole,
            width: whole.width,
        });
    }

    /// Writes an output to operand register `register`: a `w` register's
    /// value zero-extended into its `x` register (a 32-bit write clears the
    /// upper half), a scalar SIMD and floating-point register's into its
    /// `v` register (a write of `d15` clears `v15`'s upper bits), a vector
    /// register whole.
    fn write_register(&mut self, register: Register) {
        let Some(view) = state(register) else {
            return;
        };
        self.effects.push(Effect::Output {
            view: registers::whole(view.register),
            width: view.width,
        });
    }

    /// The 64-bit value of register offset `index` as `modifier` extends
    /// and shifts it (`[x0, w1, sxtw #2]`); `None` for a vector index.
    fn index(&mut self, index: Register, modifier: Modifier) -> Option<ExprId> {
        let value = match registers::general(index) {
            Some(view) => self.read(view),
            None if index.class == RegisterClass::W => self.b.constant(32, 0),
            None if index.class == RegisterClass::X => self.b.constant(64, 0),
            None => return None,
        };
        let (signed, bits, amount) = match modifier {
            Modifier::None => (false, 64, 0),
            Modifier::Shift(shift) => {
                if shift.kind != ShiftKind::Lsl {
                    return None;
                }
                (false, 64, shift.amount)
            }
            Modifier::Extend(extend) => {
                let (signed, bits) = match extend.kind {
                    ExtendKind::Uxtb => (false, 8),
                    ExtendKind::Uxth => (false, 16),
                    ExtendKind::Uxtw => (false, 32),
                    ExtendKind::Uxtx => (false, 64),
                    ExtendKind::Sxtb => (true, 8),
                    ExtendKind::Sxth => (true, 16),
                    ExtendKind::Sxtw => (true, 32),
                    ExtendKind::Sxtx => (true, 64),
                };
                (signed, bits, extend.amount.unwrap_or(0))
            }
        };
        let low = self.fit(value, bits.min(self.b.width(value)));
        let wide = if signed {
            self.b.sext(low, 64)
        } else {
            self.b.zext(low, 64)
        };
        if amount == 0 {
            return Some(wide);
        }
        let amount = self.b.constant(64, u64::from(amount));
        Some(self.b.binary(Binary::Shl, wide, amount))
    }

    /// Reads memory operand `memory`'s registers and records its writeback
    /// (`exact`: whether the writeback adds the offset); the address it
    /// accesses, `None` where it cannot be computed (a vector base or
    /// offset, a vector-length multiple). The registers are read but are no
    /// inputs of the derived values (an address is accessed, not copied: a
    /// stack address used only to access memory does not escape), but for
    /// a base written back by an amount L0 does not know.
    fn address(&mut self, memory: Memory, exact: bool) -> Option<ExprId> {
        let inputs = self.reads.len();
        let base = if memory.base.is_stack_pointer() {
            Some(self.read(registers::whole(SP)))
        } else if is_vector(memory.base) {
            self.read_register(memory.base);
            None
        } else {
            self.read_register(memory.base)
                .map(|value| self.fit(value, 64))
        };
        let offset = match memory.offset {
            Offset::None => Some(None),
            Offset::Immediate(immediate) => Some(Some(self.b.constant(64, immediate.value))),
            Offset::Register { index, modifier } => {
                if is_vector(index) {
                    self.read_register(index);
                    None
                } else {
                    self.index(index, modifier).map(Some)
                }
            }
            Offset::VectorLength(_) => None,
        };
        let sum = match (base, offset) {
            (Some(base), Some(Some(offset))) => Some(self.b.binary(Binary::Add, base, offset)),
            (Some(base), Some(None)) => Some(base),
            (None, _) | (_, None) => None,
        };
        let accessed = match memory.writeback {
            Writeback::Post => base,
            Writeback::None | Writeback::Pre => sum,
        };
        let moved = exact && !matches!(memory.offset, Offset::None);
        if memory.writeback == Writeback::None || moved {
            self.reads.truncate(inputs);
        }
        if memory.writeback != Writeback::None
            && let Some(view) = registers::general(memory.base)
        {
            self.writebacks
                .push((registers::whole(view.register), sum.filter(|_| moved)));
        }
        accessed
    }

    /// Loads `bytes` bytes at `address` as reads, at most [`CHUNK`] bytes
    /// at a time.
    fn load(&mut self, address: ExprId, bytes: u32) {
        for (offset, size) in chunks(bytes) {
            let at = self.offset(address, offset);
            let value = self.b.load(at, size);
            self.reads.push(value);
        }
    }

    /// Stores outputs over `bytes` bytes at `address`.
    fn store(&mut self, address: ExprId, bytes: u32) {
        for (offset, size) in chunks(bytes) {
            let at = self.offset(address, offset);
            self.effects.push(Effect::Store {
                address: at,
                bytes: size,
            });
        }
    }

    fn offset(&mut self, address: ExprId, offset: u32) -> ExprId {
        if offset == 0 {
            return address;
        }
        let offset = self.b.constant(64, u64::from(offset));
        self.b.binary(Binary::Add, address, offset)
    }
}

/// `bytes` split into L0 accesses: (offset, bytes) pairs.
fn chunks(bytes: u32) -> impl Iterator<Item = (u32, u16)> {
    (0..bytes.div_ceil(CHUNK)).map(move |k| {
        let offset = k * CHUNK;
        let size = (bytes - offset).min(CHUNK);
        (offset, u16::try_from(size).unwrap_or(0))
    })
}

/// Whether `instruction` may change PSTATE.SM (`smstart`, `smstop`, `msr
/// svcr*, #imm`, `msr svcr, x0`), which resets the vector registers and
/// FPSR.
fn changes_streaming_mode(instruction: Instruction) -> bool {
    let word = instruction.word();
    let pstate_svcr = instruction.encoding() == Encoding::MSR_SI_pstate
        && (word >> 16) & 7 == 3
        && (word >> 5) & 7 == 3;
    pstate_svcr
        || instruction.operands().as_slice().iter().any(|operand| {
            matches!(operand, Operand::SystemRegister(register) if register.encoding == SYSREG_SVCR)
        })
}

/// An over-approximation of `instruction` at `address`, which has no
/// semantics yet: what it may change becomes unknown, nothing is computed,
/// but what it reads is read, so that L1 sees the dependencies.
///
/// - It reads every register an operand reads ([`Instruction::access`]),
///   a scalar SIMD and floating-point register as the low bits of its `v`
///   register it is (`d15`: `v15`'s low 64), a vector register whole,
///   the base and offset registers of its memory operand, the registers
///   [`Instruction::implicit`] lists, the flags [`Instruction::flags`]
///   reads, FPCR if it has a SIMD and floating-point or SVE operand, and
///   the system registers L0 models (NZCV, FPCR, FPSR) it reads; it loads
///   what a load, load exclusive or atomic of fixed size
///   ([`Instruction::memory`]) reads, at the address its operand computes
///   (or its label names).
/// - Everything it writes is an output of one intrinsic of those reads:
///   `unlifted` where it may write memory L0 cannot place (below), else
///   `unlifted_registers`; an unknown value per location written, in the
///   order below. The intrinsic's inputs escape: a stack address it reads
///   may be stored, or kept in state L0 does not declare and read back by
///   another instruction (`msr`, then `mrs`).
/// - Written: every register an operand may write (`ReadWrite` included):
///   a `w` register is its `x` register zero-extended, a scalar SIMD and
///   floating-point register its `v` register zero-extended (Arm clears
///   the bits above it), a vector register is its `v` register whole
///   (SVE's `z`*n* holds `v`*n*); every register
///   [`Instruction::implicit`] writes; every flag [`Instruction::flags`]
///   writes; the L0 register a system register or `PSTATE` field is, by
///   name in the register file, where `msr` writes it (NZCV: the four
///   flags); FPSR whenever an
///   operand is a SIMD and floating-point or SVE register (the cumulative
///   exception flags, which the metadata does not state); all vector
///   registers and FPSR where it may change streaming mode; a base register
///   written back (base plus offset, exactly, where the offset is known;
///   else derived from the base, as for the memory copy and set
///   instructions and the pointer-authenticating loads `ldraa` and
///   `ldrab`, which access and write back the authenticated base and so
///   load nothing here). Address registers are no inputs of the intrinsic
///   otherwise: a stack address only accessed through does not escape.
///   Nor is the stack pointer the pointer authentication instructions read
///   implicitly (`paciasp`, `autiasp`): it is their modifier, hashed into
///   the authentication code, so the address does not flow on.
/// - Memory: a store or store exclusive of fixed size stores outputs over
///   its bytes (first of all; one for each 16 bytes of more, lowest
///   addresses first, as C has integers no wider), an atomic loads them
///   and stores outputs (a
///   store exclusive that fails stores nothing: the output covers the old
///   value). Writes of an extent the decoder cannot state (size 0:
///   SVE and SME stores, `stgm`, `stzgm`, memory copy and set), stores at
///   addresses L0 cannot compute (vector bases or offsets) and the system
///   instructions `sys`, `sysl` and `sysp` (`dc zva`, `dc gva` and `dc
///   gzva` write memory; the decoder states no memory access for them) run
///   `unlifted`: it stands for any change to memory, including storing what
///   the instruction read. Allocation tags and the exclusive monitor are not
///   L0 state: tag-only stores (`stg`) write nothing L0 has.
/// - State L0 does not declare (predicates, ZA, `zt0`, FFR, system
///   registers and `PSTATE` fields that are no L0 register, as the register
///   file says) gets nothing: only another instruction without semantics
///   can read it, and its outputs are unknown values of their own.
/// - `PSTATE.BTYPE` is 0 after it, as after every instruction that
///   continues with the next one.
///
/// It faults never (no SP alignment check, no fault of its own; its loads
/// and stores fault as the machine says) and transfers no control.
///
/// # Errors
///
/// [`LiftError::Problem`] if the instruction does not continue with the
/// next one (control flow is the CFG's to tell: only such instructions can
/// be over-approximated), or the builder rejects the semantics.
pub fn lift_opaque(instruction: &Instruction, address: u64) -> Result<Semantics, LiftError> {
    let mut o = plan(*instruction, address)?;
    let name = if o.unlifted {
        "unlifted"
    } else {
        "unlifted_registers"
    };
    if let Some(intrinsic) = AARCH64.find_intrinsic(name) {
        let widths: Vec<u16> = o.effects.iter().flat_map(output_widths).collect();
        let inputs = o.reads.clone();
        let mut outputs = o.b.intrinsic(intrinsic, &inputs, &widths).into_iter();
        for effect in o.effects.clone() {
            match effect {
                Effect::Output { view, .. } => {
                    if let Some(output) = outputs.next() {
                        let value = o.fit(output, view.width);
                        o.b.write(view, value);
                    }
                }
                Effect::Value { view, value } => o.b.write(view, value),
                Effect::Store { address, bytes } => {
                    // The pieces, low bits first: the bytes at the lowest
                    // addresses (little-endian).
                    let mut value = None;
                    for _ in pieces(bytes * 8) {
                        let Some(piece) = outputs.next() else { break };
                        value = Some(match value {
                            Some(low) => o.b.concat(piece, low),
                            None => piece,
                        });
                    }
                    if let Some(value) = value {
                        o.b.store(address, value);
                    }
                }
            }
        }
    }
    o.b.finish().map_err(|errors| {
        LiftError::Problem(
            errors
                .iter()
                .map(|e| e.0.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        )
    })
}

/// Where each output of [`lift_opaque`]'s intrinsic for `instruction` at
/// `address` goes, in order: the register bits it is (a 32-bit output
/// zero-extended into its `x` register is that register's low 32 bits), or
/// `None` for one stored to memory (a store of more than 16 bytes, `stp
/// q0, q1`, is one output for each 16, lowest addresses first).
///
/// # Errors
///
/// As for [`lift_opaque`].
pub fn opaque_outputs(
    instruction: &Instruction,
    address: u64,
) -> Result<Vec<Option<View>>, LiftError> {
    let o = plan(*instruction, address)?;
    Ok(o.effects
        .iter()
        .flat_map(|effect| {
            let view = match *effect {
                Effect::Output { view, width } => Some(View { width, ..view }),
                Effect::Store { .. } | Effect::Value { .. } => None,
            };
            output_widths(effect).into_iter().map(move |_| view)
        })
        .collect())
}

/// The widest output of [`lift_opaque`]'s intrinsic: a store wider gets
/// one output for each 128 bits, low bits first, as C has integers no
/// wider.
const PIECE: u16 = 128;

/// The widths of the outputs `bits` bits get, low bits first, none wider
/// than [`PIECE`].
fn pieces(bits: u16) -> impl Iterator<Item = u16> {
    (0..bits.div_ceil(PIECE)).map(move |k| (bits - k * PIECE).min(PIECE))
}

/// The widths of the intrinsic's outputs `effect` takes, in order.
fn output_widths(effect: &Effect) -> Vec<u16> {
    match *effect {
        Effect::Output { width, .. } => vec![width],
        Effect::Store { bytes, .. } => pieces(bytes * 8).collect(),
        Effect::Value { .. } => Vec::new(),
    }
}

/// What [`lift_opaque`] makes of `instruction` at `address` before its
/// intrinsic: the reads made, and what it writes.
fn plan(instruction: Instruction, address: u64) -> Result<Opaque, LiftError> {
    let flow = instruction.flow(address);
    if flow != Flow::Next {
        return Err(LiftError::Problem(format!(
            "{flow:?}: only instructions that continue with the next one are over-approximated"
        )));
    }
    let mut o = Opaque {
        b: Builder::new(),
        reads: Vec::new(),
        writebacks: Vec::new(),
        effects: Vec::new(),
        unlifted: false,
    };
    let zero = o.b.constant(2, 0);
    o.b.write(registers::whole(BTYPE), zero);
    let accessed = reads(&mut o, instruction, address);
    writes(&mut o, instruction, accessed);
    Ok(o)
}

/// Performs `instruction`'s reads (registers, flags, memory); the address
/// its (first) memory operand or its label accesses.
fn reads(o: &mut Opaque, instruction: Instruction, address: u64) -> Option<ExprId> {
    let access = instruction.memory();
    let exact = access.is_some_and(|access| access.size > 0);
    // LDRAA and LDRAB access, and write back, the authenticated base
    // (`AuthDA`, `AuthDB`): an address L0 does not compute.
    let authenticated = matches!(
        instruction.encoding(),
        Encoding::LDRAA_64_ldst_pac
            | Encoding::LDRAA_64W_ldst_pac
            | Encoding::LDRAB_64_ldst_pac
            | Encoding::LDRAB_64W_ldst_pac
    );
    let operands = instruction.operands();
    let accesses = instruction.access();
    let mut memory = None;
    let mut label = None;
    let mut vector = false;
    for (&operand, &how) in operands.as_slice().iter().zip(accesses.as_slice()) {
        for register in operand_registers(operand) {
            vector |= is_vector(register);
            if how.reads() {
                o.read_register(register);
            }
        }
        if let Operand::Memory(operand) = operand {
            // A second memory operand (a memory copy's source): its
            // registers are read and written back.
            let computed = o.address(operand, exact && memory.is_none() && !authenticated);
            memory.get_or_insert(computed.filter(|_| !authenticated));
        }
        if let Operand::Label(target) = operand {
            label = Some(target.target(address));
        }
        if how.reads() {
            for id in system_state(operand).unwrap_or_default() {
                o.read(registers::whole(id));
            }
        }
    }
    for &register in instruction.implicit().reads {
        if register.is_stack_pointer() {
            // The modifier of the pointer authentication instructions
            // (`paciasp`, `autiasp`, `retaa`): hashed into the code, so the
            // address does not flow on; a dependency, not an input.
            o.b.read(registers::whole(SP));
        } else {
            o.read_register(register);
        }
    }
    let flags = instruction.flags();
    for (flag, id) in [
        (FlagSet::N, N),
        (FlagSet::Z, Z),
        (FlagSet::C, C),
        (FlagSet::V, V),
    ] {
        if flags.read.contains(flag) {
            o.read(registers::whole(id));
        }
    }
    if vector {
        o.read(registers::whole(FPCR));
    }
    let at = match memory {
        Some(first) => first,
        None => label.map(|target| o.b.constant(64, target)),
    };
    let Some(access) = access else {
        return at;
    };
    let loads = matches!(
        access.kind,
        MemoryKind::Load | MemoryKind::LoadExclusive | MemoryKind::Atomic
    );
    if loads
        && access.size > 0
        && let Some(at) = at
    {
        o.load(at, access.size);
    }
    at
}

/// Records `instruction`'s writes: memory, writeback, registers, flags.
fn writes(o: &mut Opaque, instruction: Instruction, accessed: Option<ExprId>) {
    if let Some(access) = instruction.memory() {
        let stores = matches!(
            access.kind,
            MemoryKind::Store | MemoryKind::StoreExclusive | MemoryKind::Atomic | MemoryKind::Copy
        );
        match accessed {
            Some(at) if stores && access.size > 0 => o.store(at, access.size),
            _ => o.unlifted |= stores,
        }
    }
    o.unlifted |= matches!(
        instruction.encoding(),
        Encoding::SYS_CR_systeminstrs
            | Encoding::SYSL_RC_systeminstrs
            | Encoding::SYSP_CR_syspairinstrs
    );
    // The writebacks first: a transfer register that is also the base then
    // ends unknown, which covers what Arm permits for the overlap.
    for (base, value) in o.writebacks.clone() {
        match value {
            Some(value) => o.effects.push(Effect::Value { view: base, value }),
            None => o.clobber(base.register),
        }
    }
    let mut vector = false;
    let operands = instruction.operands();
    for (&operand, &how) in operands
        .as_slice()
        .iter()
        .zip(instruction.access().as_slice())
    {
        for register in operand_registers(operand) {
            vector |= is_vector(register);
        }
        if how.writes() {
            for register in written_registers(operand) {
                o.write_register(register);
            }
            for id in system_state(operand).unwrap_or_default() {
                o.clobber(id);
            }
        }
        if let Operand::Memory(memory) = operand {
            vector |= is_vector(memory.base);
        }
    }
    for &register in instruction.implicit().writes {
        o.write_register(register);
    }
    let flags = instruction.flags();
    for (flag, id) in [
        (FlagSet::N, N),
        (FlagSet::Z, Z),
        (FlagSet::C, C),
        (FlagSet::V, V),
    ] {
        if flags.written.contains(flag) {
            o.clobber(id);
        }
    }
    if changes_streaming_mode(instruction) {
        (0..32).for_each(|n| o.clobber(registers::v(n)));
        // And ZA, the predicates and FFR, which L0 does not declare.
        vector = true;
    }
    if vector {
        o.clobber(FPSR);
    }
}
