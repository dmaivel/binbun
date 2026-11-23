//! Operands: what an instruction's syntax names, as typed values.
//!
//! An instruction's operands are computed from its word on demand
//! ([`Instruction::operands`](crate::Instruction::operands)) by generated
//! per-syntax code, into a fixed-capacity [`Operands`]; nothing is
//! allocated. The model covers the whole A64 syntax (general, SIMD&FP, SVE
//! and SME registers, register lists, memory operands, immediates, labels,
//! conditions, system registers and named operands such as prefetch
//! operations); the printer writes each as LLVM does.

use core::fmt;

/// A register class: the letter and width a register is written with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegisterClass {
    /// 32-bit general register `w0`…`w30`; number 31 is `wzr`.
    W,
    /// 64-bit general register `x0`…`x30`; number 31 is `xzr`.
    X,
    /// 32-bit general register where number 31 is the stack pointer `wsp`.
    Wsp,
    /// 64-bit general register where number 31 is the stack pointer `sp`.
    Xsp,
    /// 8-bit SIMD&FP scalar `b0`…`b31`.
    B,
    /// 16-bit SIMD&FP scalar `h0`…`h31`.
    H,
    /// 32-bit SIMD&FP scalar `s0`…`s31`.
    S,
    /// 64-bit SIMD&FP scalar `d0`…`d31`.
    D,
    /// 128-bit SIMD&FP scalar `q0`…`q31`.
    Q,
    /// SIMD&FP vector `v0`…`v31`, usually with an arrangement (`v0.16b`)
    /// or an element (`v0.s[1]`).
    V,
    /// SVE vector `z0`…`z31`, with an element size (`z0.s`) or none.
    Z,
    /// SVE predicate `p0`…`p15`, with an element size, a qualifier (`/z`,
    /// `/m`) or neither.
    P,
    /// SVE predicate-as-counter `pn0`…`pn15`.
    Pn,
    /// SME lookup table `zt0`.
    Zt,
    /// System instruction control register `c0`…`c15`: the `CRn` and `CRm`
    /// operands of `SYS`, `SYSL` and `SYSP`.
    C,
    /// The SVE first-fault register `ffr` (number 0), which first-fault
    /// and non-fault loads update; only in
    /// [`Implicit`](crate::Implicit) lists.
    Ffr,
}

/// The size of a vector element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ElementSize {
    /// 8 bits (`b`).
    B,
    /// 16 bits (`h`).
    H,
    /// 32 bits (`s`).
    S,
    /// 64 bits (`d`).
    D,
    /// 128 bits (`q`).
    Q,
}

/// A vector arrangement: `count` elements of `element` (`16b`, `2d`, `4b`
/// for dot products), or just an element size (`count` 0: `v0.s[1]`,
/// `z0.d`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Arrangement {
    /// Number of elements; 0 when only the element size is written.
    pub count: u8,
    /// Element size.
    pub element: ElementSize,
}

/// How a governing predicate treats inactive elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Predication {
    /// `/z`: inactive elements are zeroed.
    Zeroing,
    /// `/m`: inactive elements keep their value.
    Merging,
}

/// A register, possibly with an arrangement, an element index and a
/// predicate qualifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Register {
    /// The class.
    pub class: RegisterClass,
    /// The number; for general registers 31 is the zero register or the
    /// stack pointer, by class.
    pub number: u8,
    /// Arrangement or element size of vector and predicate registers.
    pub arrangement: Option<Arrangement>,
    /// Element index (`v0.s[1]`, `z0.d[2]`).
    pub index: Option<u8>,
    /// Predicate qualifier (`p0/z`).
    pub predication: Option<Predication>,
}

impl Register {
    /// A register of `class` with only a number.
    pub const fn new(class: RegisterClass, number: u8) -> Self {
        Self {
            class,
            number,
            arrangement: None,
            index: None,
            predication: None,
        }
    }

    /// Whether this is the zero register (`wzr`, `xzr`).
    pub const fn is_zero(self) -> bool {
        matches!(self.class, RegisterClass::W | RegisterClass::X) && self.number == 31
    }

    /// Whether this is the stack pointer (`wsp`, `sp`).
    pub const fn is_stack_pointer(self) -> bool {
        matches!(self.class, RegisterClass::Wsp | RegisterClass::Xsp) && self.number == 31
    }
}

/// How a register list is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListStyle {
    /// Every register, separated by commas: `{ v0.16b, v1.16b }`.
    Commas,
    /// The first and last register of a consecutive list: `{ z0.s - z3.s }`.
    Range,
}

/// A list of vector registers: `count` registers from `first`, numbers
/// `stride` apart (modulo [`RegisterList::registers`]: 32, 16 for
/// predicates).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegisterList {
    /// The first register, with the arrangement and index all share.
    pub first: Register,
    /// Number of registers.
    pub count: u8,
    /// Distance between register numbers (1 for consecutive registers).
    pub stride: u8,
    /// How it is written.
    pub style: ListStyle,
}

impl RegisterList {
    /// How many registers the list's class has, where its numbers wrap:
    /// 16 predicates (`{ p15.d, p0.d }`) and control registers, else 32.
    pub const fn registers(self) -> u8 {
        match self.first.class {
            RegisterClass::P | RegisterClass::Pn | RegisterClass::C => 16,
            RegisterClass::Ffr => 1,
            RegisterClass::W
            | RegisterClass::X
            | RegisterClass::Wsp
            | RegisterClass::Xsp
            | RegisterClass::B
            | RegisterClass::H
            | RegisterClass::S
            | RegisterClass::D
            | RegisterClass::Q
            | RegisterClass::V
            | RegisterClass::Z
            | RegisterClass::Zt => 32,
        }
    }

    /// The `i`th register of the list.
    pub const fn get(self, i: u8) -> Register {
        let mut register = self.first;
        register.number = (self.first.number + i * self.stride) % self.registers();
        register
    }
}

/// How a number is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Radix {
    /// `#0x1f`.
    Hex,
    /// `#31`.
    Decimal,
    /// LLVM's `%#016llx` of 64-bit `MOVI` masks: hex zero-padded to 16
    /// characters counting the `0x`, which C leaves out for zero
    /// (`#0x000000000000ff`, `#0000000000000000`).
    PaddedHex,
}

/// An immediate value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Immediate {
    /// The value; two's complement when `signed`.
    pub value: u64,
    /// Whether the value is signed.
    pub signed: bool,
    /// How it is written.
    pub radix: Radix,
}

impl Immediate {
    /// An unsigned value written in hex.
    pub const fn unsigned(value: u64) -> Self {
        Self {
            value,
            signed: false,
            radix: Radix::Hex,
        }
    }

    /// A signed value written in hex.
    pub const fn signed(value: i64) -> Self {
        Self {
            value: value.cast_unsigned(),
            signed: true,
            radix: Radix::Hex,
        }
    }

    /// The same value written in decimal.
    #[must_use]
    pub const fn decimal(self) -> Self {
        Self {
            radix: Radix::Decimal,
            ..self
        }
    }

    /// The same value written as LLVM writes 64-bit `MOVI` masks
    /// ([`Radix::PaddedHex`]).
    #[must_use]
    pub const fn padded_hex(self) -> Self {
        Self {
            radix: Radix::PaddedHex,
            ..self
        }
    }

    /// The value as a signed integer (for unsigned values above
    /// `i64::MAX`, the two's complement reading).
    pub const fn as_i64(self) -> i64 {
        self.value.cast_signed()
    }
}

/// A shift kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShiftKind {
    /// `lsl`.
    Lsl,
    /// `lsr`.
    Lsr,
    /// `asr`.
    Asr,
    /// `ror`.
    Ror,
    /// `msl`, shifting ones in (`AdvSIMD` modified immediates).
    Msl,
    /// `mul`, a multiplier (SVE element counts: `cntb x0, all, mul #4`).
    Mul,
}

/// A shift applied to the operand before it, `lsl #12`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Shift {
    /// The kind.
    pub kind: ShiftKind,
    /// The amount.
    pub amount: u8,
}

/// An extension kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtendKind {
    /// `uxtb`.
    Uxtb,
    /// `uxth`.
    Uxth,
    /// `uxtw`.
    Uxtw,
    /// `uxtx`.
    Uxtx,
    /// `sxtb`.
    Sxtb,
    /// `sxth`.
    Sxth,
    /// `sxtw`.
    Sxtw,
    /// `sxtx`.
    Sxtx,
}

impl ExtendKind {
    /// The extension of the 3-bit `option` field.
    pub const fn from_option(option: u32) -> Self {
        match option & 7 {
            0 => Self::Uxtb,
            1 => Self::Uxth,
            2 => Self::Uxtw,
            3 => Self::Uxtx,
            4 => Self::Sxtb,
            5 => Self::Sxth,
            6 => Self::Sxtw,
            _ => Self::Sxtx,
        }
    }
}

/// An extension applied to the register before it, `uxtw #2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Extend {
    /// The kind.
    pub kind: ExtendKind,
    /// The left shift after extending, when written.
    pub amount: Option<u8>,
}

/// What modifies a register offset of a memory operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Modifier {
    /// Nothing: `[x0, x1]`.
    None,
    /// A shift: `[x0, x1, lsl #3]`.
    Shift(Shift),
    /// An extension: `[x0, w1, sxtw #2]`.
    Extend(Extend),
}

/// The offset of a memory operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Offset {
    /// No offset: `[x0]`.
    None,
    /// An immediate offset: `[x0, #0x10]`.
    Immediate(Immediate),
    /// A register offset: `[x0, x1, lsl #3]`, `[x0, z1.d]`.
    Register {
        /// The offset register.
        index: Register,
        /// Its shift or extension.
        modifier: Modifier,
    },
    /// A multiple of the vector length: `[x0, #-3, mul vl]`.
    VectorLength(i64),
}

/// Whether and when a memory operand writes the address back to its base.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Writeback {
    /// No writeback: `[x0, #0x10]`.
    None,
    /// Pre-index: `[x0, #0x10]!`.
    Pre,
    /// Post-index; the offset is written after the bracket: `[x0], #0x10`.
    Post,
}

/// A memory operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Memory {
    /// The base register (general, or an SVE vector for vector bases).
    pub base: Register,
    /// The offset.
    pub offset: Offset,
    /// Writeback.
    pub writeback: Writeback,
}

/// What a label is relative to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LabelBase {
    /// The instruction's address (branches, `adr`, literal loads).
    Instruction,
    /// The instruction's 4 KiB page (`adrp`).
    Page,
}

/// A PC-relative address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Label {
    /// Offset from the base, in bytes.
    pub offset: i64,
    /// What the offset is relative to.
    pub base: LabelBase,
    /// How the offset is written with
    /// [`LabelStyle::Relative`](crate::LabelStyle::Relative), as LLVM's C
    /// API writes it.
    pub radix: Radix,
}

impl Label {
    /// The address the label names when the instruction is at `address`.
    pub const fn target(self, address: u64) -> u64 {
        let base = match self.base {
            LabelBase::Instruction => address,
            LabelBase::Page => address & !0xfff,
        };
        base.wrapping_add(self.offset.cast_unsigned())
    }
}

/// A condition on the flags (`cond` fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Condition {
    /// `eq`: Z set.
    Eq,
    /// `ne`: Z clear.
    Ne,
    /// `hs` (`cs`): C set.
    Hs,
    /// `lo` (`cc`): C clear.
    Lo,
    /// `mi`: N set.
    Mi,
    /// `pl`: N clear.
    Pl,
    /// `vs`: V set.
    Vs,
    /// `vc`: V clear.
    Vc,
    /// `hi`: C set and Z clear.
    Hi,
    /// `ls`: C clear or Z set.
    Ls,
    /// `ge`: N equals V.
    Ge,
    /// `lt`: N differs from V.
    Lt,
    /// `gt`: Z clear and N equals V.
    Gt,
    /// `le`: Z set or N differs from V.
    Le,
    /// `al`: always.
    Al,
    /// `nv`: always (behaves as `al`).
    Nv,
}

impl Condition {
    /// The condition of a 4-bit `cond` field.
    pub const fn from_bits(bits: u32) -> Self {
        match bits & 15 {
            0 => Self::Eq,
            1 => Self::Ne,
            2 => Self::Hs,
            3 => Self::Lo,
            4 => Self::Mi,
            5 => Self::Pl,
            6 => Self::Vs,
            7 => Self::Vc,
            8 => Self::Hi,
            9 => Self::Ls,
            10 => Self::Ge,
            11 => Self::Lt,
            12 => Self::Gt,
            13 => Self::Le,
            14 => Self::Al,
            _ => Self::Nv,
        }
    }

    /// The condition with the opposite result (`eq` for `ne`); `al` and
    /// `nv` invert to each other.
    #[must_use]
    pub const fn invert(self) -> Self {
        Self::from_bits(self as u32 ^ 1)
    }

    /// The lower-case name, e.g. `hs`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Hs => "hs",
            Self::Lo => "lo",
            Self::Mi => "mi",
            Self::Pl => "pl",
            Self::Vs => "vs",
            Self::Vc => "vc",
            Self::Hi => "hi",
            Self::Ls => "ls",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Gt => "gt",
            Self::Le => "le",
            Self::Al => "al",
            Self::Nv => "nv",
        }
    }
}

/// What a [`Named`] operand names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NameKind {
    /// A prefetch operation (`pldl1keep`).
    Prefetch,
    /// A barrier option (`ish`, `sy`).
    Barrier,
    /// A branch target type (`bti c`).
    BranchTarget,
    /// A `PSTATE` field (`msr spsel, #1`).
    PstateField,
    /// An SVE predicate pattern (`vl64`, `all`).
    Pattern,
    /// A system operation (`dc civac`, `tlbi vae1is`).
    SystemOperation,
    /// Any other keyword (`csync`, `nb`, `keep`).
    Keyword,
}

/// An operand written as a name from a fixed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Named {
    /// What it names.
    pub kind: NameKind,
    /// The name, lower case as LLVM writes it.
    pub name: &'static str,
}

/// A floating-point immediate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Float {
    /// The value.
    pub value: f64,
    /// Whether the value is one of the constants an encoding selects
    /// rather than encodes (Arm's exact FP immediates, the zero of
    /// comparisons), which LLVM writes in shortest form (`#0.0`, `#0.5`);
    /// otherwise LLVM writes eight decimals (`#1.00000000`).
    pub exact: bool,
}

/// Orientation of an SME tile slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SliceDirection {
    /// Horizontal (`za0h`).
    Horizontal,
    /// Vertical (`za0v`).
    Vertical,
}

/// Selection of ZA vectors by a `w8`…`w15` index register and an offset:
/// `[w12, 3]`, `[w8, 0:1]`, `[w9, 7, vgx4]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ZaSlice {
    /// The index register number (8…15 or 12…15).
    pub index: u8,
    /// The first offset.
    pub offset: u8,
    /// The last offset of a range (`0:1`), if written.
    pub last: Option<u8>,
    /// The vector group size (`vgx2`, `vgx4`), if written.
    pub group: Option<u8>,
}

/// The SME array or one of its tiles, whole or sliced: `za`, `za1.d`,
/// `za0h.s[w12, 3]`, `za.d[w8, 0, vgx2]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Za {
    /// The tile number; `None` for the whole array.
    pub tile: Option<u8>,
    /// Element size, if written.
    pub element: Option<ElementSize>,
    /// Slice direction of a tile slice.
    pub direction: Option<SliceDirection>,
    /// The slice selection, if any.
    pub slice: Option<ZaSlice>,
}

/// A braced list of ZA tiles or slices, written without spaces inside the
/// braces as LLVM does: `{za0h.b[w12, 0]}`, `{za0.d, za2.d}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZaList {
    /// One tile slice (SME loads and stores of ZA).
    Slice(Za),
    /// The 64-bit tiles whose bit is set (`ZERO { <mask> }`, bit i =
    /// `zai.d`), written with LLVM's spellings: `za` for all eight,
    /// `za0.h`/`za1.h` for the even/odd tiles, `.s` tiles joined by `,`
    /// when the mask is a set of 32-bit tiles (`{za0.s,za1.s}`, `{}` for
    /// none), else the `.d` tiles joined by `, `.
    Tiles(u8),
}

/// A register selected by a general register plus an offset: the
/// predicate of `PSEL`, `p2.b[w12, 15]` (LLVM writes the offset in
/// decimal).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IndexedRegister {
    /// The register selected from.
    pub register: Register,
    /// The index register (`w12`…`w15`).
    pub index: Register,
    /// The offset added to the index.
    pub offset: u8,
}

/// A system register: its encoding and, if it has one for the access, its
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SystemRegister {
    /// `op0:op1:CRn:CRm:op2` (16 bits, `op0` in bits 15:14).
    pub encoding: u16,
    /// The register's name for this access (`MRS` and `MRRS` read, `MSR`
    /// and `MSRR` write) as LLVM writes it (`TPIDR_EL0`); `None` prints
    /// as `S<op0>_<op1>_C<n>_C<m>_<op2>`.
    pub name: Option<&'static str>,
}

/// One operand.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Operand {
    /// A register.
    Register(Register),
    /// A register list.
    List(RegisterList),
    /// An immediate.
    Immediate(Immediate),
    /// A floating-point immediate.
    Float(Float),
    /// A shift of the operand before it.
    Shift(Shift),
    /// An extension of the register before it.
    Extend(Extend),
    /// A memory operand.
    Memory(Memory),
    /// A register written back, without brackets: the size register of
    /// memory copy and set instructions (`x2!`).
    Writeback(Register),
    /// A PC-relative address.
    Label(Label),
    /// A condition.
    Condition(Condition),
    /// A system register of `MRS`, `MSR`, `MRRS`, `MSRR`.
    SystemRegister(SystemRegister),
    /// A named operand.
    Named(Named),
    /// The SME array, a tile or a slice.
    Za(Za),
    /// A braced list of ZA tiles or a slice.
    ZaList(ZaList),
    /// The lookup table `zt0` indexed in multiples of the vector length:
    /// `zt0[1, mul vl]`. LLVM writes index 0 as plain `zt0`, a
    /// [`RegisterClass::Zt`] register.
    TableSlice(u8),
    /// A register indexed by a general register plus an offset.
    IndexedRegister(IndexedRegister),
}

/// Most operands an instruction has.
pub const MAX_OPERANDS: usize = 8;

/// The operands of an instruction, in syntax order.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Operands {
    operands: [Operand; MAX_OPERANDS],
    len: u8,
}

impl Default for Operands {
    fn default() -> Self {
        Self::new()
    }
}

impl Operands {
    /// No operands.
    pub const fn new() -> Self {
        Self {
            operands: [Operand::Condition(Condition::Al); MAX_OPERANDS],
            len: 0,
        }
    }

    /// Appends `operand`. The generator sizes [`MAX_OPERANDS`] for the
    /// longest syntax, so the operand always fits.
    pub fn push(&mut self, operand: Operand) {
        if let Some(slot) = self.operands.get_mut(usize::from(self.len)) {
            *slot = operand;
            self.len += 1;
        }
    }

    /// The operands as a slice.
    pub fn as_slice(&self) -> &[Operand] {
        self.operands
            .get(..usize::from(self.len))
            .unwrap_or_default()
    }

    /// Number of operands.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether there are none.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The operands.
    pub fn iter(&self) -> core::slice::Iter<'_, Operand> {
        self.as_slice().iter()
    }
}

impl<'a> IntoIterator for &'a Operands {
    type Item = &'a Operand;
    type IntoIter = core::slice::Iter<'a, Operand>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Display for ElementSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::B => "b",
            Self::H => "h",
            Self::S => "s",
            Self::D => "d",
            Self::Q => "q",
        })
    }
}
