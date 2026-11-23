//! The registers an instruction reads and writes, as the decoders report
//! them.

use core::fmt;

#[cfg(feature = "aarch64")]
use binbun_aarch64::operand::{
    ElementSize, Offset, Operand, Register as A64Register, RegisterClass as A64Class,
    SystemRegister, Writeback, Za, ZaList,
};
#[cfg(feature = "x86")]
use binbun_x86::{RegisterClass as X86Class, Value};

#[cfg(feature = "aarch64")]
use crate::aarch64;
#[cfg(feature = "x86")]
use crate::x86;

/// A register, as its architecture names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Register {
    /// An x86 register, as XED names it: a partial register is itself
    /// (`al`, `eax` and `rax` are three registers), and XED's pseudo
    /// registers that are machine state (`x87status`, `msrs`, `tsc`) are
    /// registers too.
    #[cfg(feature = "x86")]
    X86(x86::Register),
    /// An AArch64 register.
    #[cfg(feature = "aarch64")]
    AArch64(AArch64Register),
}

/// An AArch64 register, as the text names it.
#[cfg(feature = "aarch64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AArch64Register {
    /// A register by class and number, without the arrangement, element
    /// index or predicate qualifier the operand writes on it: `x0` and
    /// `w0` are two registers (views of one), as are `v0`, `q0` and `d0`.
    /// Number 31 is `xzr`/`wzr` (class `X`/`W`) or `sp`/`wsp` (class
    /// `Xsp`/`Wsp`); below 31 the class is `X` or `W` (see
    /// [`AArch64Register::of`]). The zero register is listed when it is a
    /// destination (the write is discarded).
    Register {
        /// The class.
        class: aarch64::operand::RegisterClass,
        /// The number.
        number: u8,
    },
    /// The SME array (`za`) or one of its tiles (`za1.d`), without a
    /// slice's direction and selection.
    Za {
        /// The tile number; `None` for the whole array.
        tile: Option<u8>,
        /// The tile's element size.
        element: Option<ElementSize>,
    },
    /// A system register an `MRS`, `MSR`, `MRRS` or `MSRR` names, by its
    /// name for the access (`TPIDR_EL0`; `NZCV` here too) or its
    /// encoding (`S3_0_C15_C2_0`).
    System(SystemRegister),
}

#[cfg(feature = "aarch64")]
impl AArch64Register {
    /// `register` without what is written on it, `x0` of class `Xsp` (a
    /// field where 31 would be `sp`) as class `X`, so that one register
    /// is one value.
    pub const fn of(register: A64Register) -> Self {
        let class = match (register.class, register.number) {
            (A64Class::Xsp, 0..31) => A64Class::X,
            (A64Class::Wsp, 0..31) => A64Class::W,
            (class, _) => class,
        };
        Self::Register {
            class,
            number: register.number,
        }
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "x86")]
            Self::X86(register) => f.write_str(register.name()),
            #[cfg(feature = "aarch64")]
            Self::AArch64(register) => register.fmt(f),
        }
    }
}

#[cfg(feature = "aarch64")]
impl fmt::Display for AArch64Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Register { class, number } => {
                let prefix = match (class, number) {
                    (A64Class::W, 31) => return f.write_str("wzr"),
                    (A64Class::X, 31) => return f.write_str("xzr"),
                    (A64Class::Wsp, 31) => return f.write_str("wsp"),
                    (A64Class::Xsp, 31) => return f.write_str("sp"),
                    (A64Class::Ffr, _) => return f.write_str("ffr"),
                    (A64Class::W | A64Class::Wsp, _) => "w",
                    (A64Class::X | A64Class::Xsp, _) => "x",
                    (A64Class::B, _) => "b",
                    (A64Class::H, _) => "h",
                    (A64Class::S, _) => "s",
                    (A64Class::D, _) => "d",
                    (A64Class::Q, _) => "q",
                    (A64Class::V, _) => "v",
                    (A64Class::Z, _) => "z",
                    (A64Class::P, _) => "p",
                    (A64Class::Pn, _) => "pn",
                    (A64Class::Zt, _) => "zt",
                    (A64Class::C, _) => "c",
                };
                write!(f, "{prefix}{number}")
            }
            Self::Za { tile: None, .. } => f.write_str("za"),
            Self::Za {
                tile: Some(tile),
                element: None,
            } => write!(f, "za{tile}"),
            Self::Za {
                tile: Some(tile),
                element: Some(element),
            } => write!(f, "za{tile}.{element}"),
            Self::System(SystemRegister {
                name: Some(name), ..
            }) => f.write_str(name),
            Self::System(SystemRegister {
                encoding,
                name: None,
            }) => write!(
                f,
                "S{}_{}_C{}_C{}_{}",
                encoding >> 14,
                (encoding >> 11) & 7,
                (encoding >> 7) & 15,
                (encoding >> 3) & 15,
                encoding & 7
            ),
        }
    }
}

/// Room in [`Registers`]: more than any instruction can report. On x86
/// each operand is one register or a memory operand's segment, base and
/// index; on AArch64 each operand is at most 8 registers (a register
/// list is at most 4, `zero`'s tile mask 8, a memory operand 2) and the
/// implicit lists are at most 8.
const CAPACITY: usize = {
    #[cfg(feature = "x86")]
    let x86 = x86::MAX_OPERANDS * 3;
    #[cfg(not(feature = "x86"))]
    let x86 = 0;
    #[cfg(feature = "aarch64")]
    let aarch64 = aarch64::operand::MAX_OPERANDS * 8 + 8;
    #[cfg(not(feature = "aarch64"))]
    let aarch64 = 0;
    if x86 > aarch64 { x86 } else { aarch64 }
};

/// Any register, for the slots of [`Registers`] past its length.
#[cfg(feature = "x86")]
const FILLER: Register = Register::X86(x86::Register::RAX);
#[cfg(all(feature = "aarch64", not(feature = "x86")))]
const FILLER: Register = Register::AArch64(AArch64Register::Za {
    tile: None,
    element: None,
});

/// What an instruction may read or write: each register once, in the
/// order of the instruction's operands (implied ones included), then
/// AArch64's implicit registers.
///
/// These are the decoder's facts, not a complete account of what the
/// instruction does:
///
/// - The condition flags are left out: x86's `flags`/`eflags`/`rflags`
///   (and so XED's x87 condition codes, which are flag records) and
///   AArch64's NZCV, which the native instructions' `flags()` give. An
///   AArch64 `MSR`/`MRS` that names `NZCV` is a system register access and
///   is listed.
/// - On x86 an operand is read or written as XED's action says; a
///   conditional action (`REP`, `CMOVcc`) is a *may*. A memory operand's
///   segment, base and index registers are read (including `rip` of a
///   RIP-relative operand); the memory itself is no register. An AVX-512
///   write mask `k0` (no masking) is not read. XED's pseudo registers
///   that are no machine state are left out: the stack adjustments
///   `stackpush`, `stackpop`, `x87push`, `x87pop` and `x87pop2` (the
///   stack pointer, or the x87 status word, is listed as itself) and the
///   default flag values `dfv0`…`dfv15` of `ccmp` and its kind.
/// - On AArch64 each operand is read or written as its access says;
///   register lists are expanded; a memory operand's base and offset
///   registers are read and the base is written back when its writeback
///   says so; a ZA slice's index register is read; the implicit
///   registers ([`aarch64::Implicit`]) follow. `SYS`'s control registers
///   `c0`…`c15` name an operation, not a register, and are left out.
///   Floating-point control and status (FPCR, FPSR), side effects on
///   system registers (`ELR` of `eret`) and ZA effects of
///   `smstart`/`smstop` are not reported by the decoder and not here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Registers {
    registers: [Register; CAPACITY],
    len: u8,
}

impl Registers {
    /// The most registers an instruction can report: room for every
    /// operand's (on x86 a register or a memory operand's segment, base
    /// and index; on AArch64 up to 8, a register list or `zero`'s tiles)
    /// and AArch64's implicit ones.
    pub const CAPACITY: usize = CAPACITY;

    const fn new() -> Self {
        Self {
            registers: [FILLER; CAPACITY],
            len: 0,
        }
    }

    /// Adds `register` unless it is already in.
    fn insert(&mut self, register: Register) {
        if self.contains(register) {
            return;
        }
        if let Some(slot) = self.registers.get_mut(usize::from(self.len)) {
            *slot = register;
            self.len += 1;
        }
    }

    /// The registers as a slice.
    pub fn as_slice(&self) -> &[Register] {
        self.registers
            .get(..usize::from(self.len))
            .unwrap_or_default()
    }

    /// Number of registers.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether there are none.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `register` is one of them.
    pub fn contains(&self, register: Register) -> bool {
        self.as_slice().contains(&register)
    }

    /// The registers.
    pub fn iter(&self) -> core::slice::Iter<'_, Register> {
        self.as_slice().iter()
    }
}

impl<'a> IntoIterator for &'a Registers {
    type Item = &'a Register;
    type IntoIter = core::slice::Iter<'a, Register>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Which registers are asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    Read,
    Write,
}

/// What an x86 instruction may read or write.
#[cfg(feature = "x86")]
pub(crate) fn x86(instruction: &x86::Instruction, side: Side) -> Registers {
    let mut registers = Registers::new();
    for operand in instruction.operands() {
        match operand.value {
            Value::Register(Some(register)) => {
                let accessed = match side {
                    Side::Read => operand.action.reads(),
                    Side::Write => operand.action.writes(),
                };
                let flags = register.class() == X86Class::Flags;
                let no_mask = operand.writemask && register == x86::Register::K0;
                if accessed && !flags && !no_mask && is_state(register) {
                    registers.insert(Register::X86(register));
                }
            }
            Value::Memory(memory) => {
                if side == Side::Read {
                    for register in [memory.segment, memory.base, memory.index]
                        .into_iter()
                        .flatten()
                        .filter(|&register| is_state(register))
                    {
                        registers.insert(Register::X86(register));
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
    registers
}

/// Whether `register` is machine state, not one of XED's pseudo registers
/// for a stack adjustment or a default flag value (see [`Registers`]).
#[cfg(feature = "x86")]
const fn is_state(register: x86::Register) -> bool {
    use x86::Register as R;
    !matches!(
        register,
        R::STACKPUSH
            | R::STACKPOP
            | R::X87PUSH
            | R::X87POP
            | R::X87POP2
            | R::DFV0
            | R::DFV1
            | R::DFV2
            | R::DFV3
            | R::DFV4
            | R::DFV5
            | R::DFV6
            | R::DFV7
            | R::DFV8
            | R::DFV9
            | R::DFV10
            | R::DFV11
            | R::DFV12
            | R::DFV13
            | R::DFV14
            | R::DFV15
    )
}

/// What an AArch64 instruction may read or write.
#[cfg(feature = "aarch64")]
pub(crate) fn aarch64(instruction: aarch64::Instruction, side: Side) -> Registers {
    let mut registers = Registers::new();
    let mut insert = |register: AArch64Register| registers.insert(Register::AArch64(register));
    let read = side == Side::Read;
    let operands = instruction.operands();
    let access = instruction.access();
    for (operand, access) in operands.iter().zip(access.iter()) {
        let accessed = if read {
            access.reads()
        } else {
            access.writes()
        };
        match *operand {
            Operand::Register(register) | Operand::Writeback(register) => {
                if accessed && register.class != A64Class::C {
                    insert(AArch64Register::of(register));
                }
            }
            Operand::List(list) => {
                if accessed {
                    for i in 0..list.count {
                        insert(AArch64Register::of(list.get(i)));
                    }
                }
            }
            Operand::Memory(memory) => {
                if read {
                    insert(AArch64Register::of(memory.base));
                    if let Offset::Register { index, .. } = memory.offset {
                        insert(AArch64Register::of(index));
                    }
                } else if memory.writeback != Writeback::None {
                    insert(AArch64Register::of(memory.base));
                }
            }
            Operand::Za(za) | Operand::ZaList(ZaList::Slice(za)) => {
                if accessed {
                    insert(tile(za));
                }
                if read && let Some(slice) = za.slice {
                    insert(AArch64Register::Register {
                        class: A64Class::W,
                        number: slice.index,
                    });
                }
            }
            Operand::ZaList(ZaList::Tiles(mask)) => {
                if accessed && mask == 0xff {
                    insert(AArch64Register::Za {
                        tile: None,
                        element: None,
                    });
                } else if accessed {
                    for tile in (0..8).filter(|tile| mask & (1 << tile) != 0) {
                        insert(AArch64Register::Za {
                            tile: Some(tile),
                            element: Some(ElementSize::D),
                        });
                    }
                }
            }
            Operand::TableSlice(_) => {
                if accessed {
                    insert(AArch64Register::Register {
                        class: A64Class::Zt,
                        number: 0,
                    });
                }
            }
            Operand::IndexedRegister(indexed) => {
                if accessed {
                    insert(AArch64Register::of(indexed.register));
                }
                if read {
                    insert(AArch64Register::of(indexed.index));
                }
            }
            Operand::SystemRegister(system) => {
                if accessed {
                    insert(AArch64Register::System(system));
                }
            }
            Operand::Immediate(_)
            | Operand::Float(_)
            | Operand::Shift(_)
            | Operand::Extend(_)
            | Operand::Label(_)
            | Operand::Condition(_)
            | Operand::Named(_) => {}
        }
    }
    let implicit = instruction.implicit();
    let implicit = if read {
        implicit.reads
    } else {
        implicit.writes
    };
    for &register in implicit {
        insert(AArch64Register::of(register));
    }
    registers
}

/// The array or tile `za` is part of.
#[cfg(feature = "aarch64")]
const fn tile(za: Za) -> AArch64Register {
    AArch64Register::Za {
        tile: za.tile,
        element: if za.tile.is_some() { za.element } else { None },
    }
}
