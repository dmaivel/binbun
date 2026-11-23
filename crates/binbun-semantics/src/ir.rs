//! The L0 data model: what one instruction does, as statements over pure
//! expressions.
//!
//! - Values are bit vectors of 1 to [`MAX_WIDTH`](crate::bits::MAX_WIDTH)
//!   bits; a condition is a 1-bit value.
//! - State is read and written by statements: [`Stmt::Read`] and
//!   [`Stmt::Load`] define a [`Local`], which expressions then use, so the
//!   order of every state access is explicit and expressions are pure (and
//!   hash-consed per instruction).
//! - Every operation is total: division by zero gives all ones and the
//!   remainder the dividend (SMT-LIB's convention); shifts by the width or
//!   more give 0 (or the sign); an instruction that faults checks first and
//!   [`Stmt::Trap`]s.
//! - Exceptions are precise: an instruction that traps (or whose memory
//!   access faults) has none of its effects, whatever statements ran
//!   before the trap.
//! - [`Expr::Undefined`] stands for a value the architecture leaves
//!   undefined: each occurrence is its own unknown value.
//! - Vectors are bit vectors too: [`Expr::Lanes`] applies a scalar
//!   operation lane by lane, [`Expr::Float`] an IEEE 754 operation to
//!   each lane; across lanes, values are extracted and concatenated.

use alloc::vec::Vec;

use crate::bits::Bits;

/// A register of an architecture's [`Declarations`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegisterId(pub u16);

/// One register: its name (lower case, as printed) and width in bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterInfo {
    /// The name, unique among the registers.
    pub name: &'static str,
    /// The width in bits.
    pub width: u16,
}

/// An intrinsic of an architecture's [`Declarations`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntrinsicId(pub u16);

/// One intrinsic: an operation L0 does not compute, whose results the
/// processor or the system supplies (x86 `cpuid`, `rdtsc`) or whose effects
/// lie outside the modelled state (memory fences): its name (lower case, as
/// printed), the widths of its inputs and outputs, whether its inputs may
/// escape through it, whether it may change memory, and whether it stands
/// for an instruction without semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntrinsicInfo {
    /// The name, unique among the intrinsics.
    pub name: &'static str,
    /// The widths of the inputs, in bits (none for an
    /// [`opaque`](Self::opaque) one).
    pub inputs: &'static [u16],
    /// The widths of the outputs, in bits (none for an
    /// [`opaque`](Self::opaque) one).
    pub outputs: &'static [u16],
    /// Whether its inputs may come back as, or reach, addresses: false for
    /// keyed hashes and other functions whose outputs cannot be used to
    /// recover or access their inputs. Analyses that follow addresses (the
    /// stack's escape) take an address passed to an intrinsic that escapes
    /// as escaping.
    pub escapes: bool,
    /// Whether it may change memory. One that does not still reads it (it
    /// is ordered after the stores before it), but a load after it finds
    /// what the stores before it left.
    pub stores: bool,
    /// Whether it stands for an instruction without semantics (an
    /// architecture's `lift_opaque`): each statement running it has inputs
    /// and outputs of its own, any number of any width (what that
    /// instruction reads, and a value for each location it writes), in
    /// place of [`inputs`](Self::inputs) and [`outputs`](Self::outputs).
    /// Its outputs are unknown values: nothing computes them, and nothing
    /// may take them for constants.
    pub opaque: bool,
}

/// What an architecture declares to L0: its registers, indexed by
/// [`RegisterId`], its intrinsics, indexed by [`IntrinsicId`], and the
/// sites of its undefined values, indexed by [`SiteId`]. Each register is a
/// separate piece of state: architectures declare sub-registers as
/// [`View`]s of a full register, never as registers of their own.
#[derive(Clone, Copy, Debug)]
pub struct Declarations {
    /// The registers, in [`RegisterId`] order.
    pub registers: &'static [RegisterInfo],
    /// The intrinsics, in [`IntrinsicId`] order.
    pub intrinsics: &'static [IntrinsicInfo],
    /// The sites, in [`SiteId`] order.
    pub sites: &'static [SiteInfo],
}

impl Declarations {
    /// The register numbered `id`.
    pub fn info(&self, id: RegisterId) -> Option<&RegisterInfo> {
        self.registers.get(usize::from(id.0))
    }

    /// The register named `name`.
    pub fn find(&self, name: &str) -> Option<RegisterId> {
        let index = self.registers.iter().position(|r| r.name == name)?;
        u16::try_from(index).ok().map(RegisterId)
    }

    /// The intrinsic numbered `id`.
    pub fn intrinsic(&self, id: IntrinsicId) -> Option<&IntrinsicInfo> {
        self.intrinsics.get(usize::from(id.0))
    }

    /// The intrinsic named `name`.
    pub fn find_intrinsic(&self, name: &str) -> Option<IntrinsicId> {
        let index = self.intrinsics.iter().position(|i| i.name == name)?;
        u16::try_from(index).ok().map(IntrinsicId)
    }

    /// The site numbered `id`.
    pub fn site(&self, id: SiteId) -> Option<&SiteInfo> {
        self.sites.get(usize::from(id.0))
    }

    /// The site named `name`.
    pub fn find_site(&self, name: &str) -> Option<SiteId> {
        let index = self.sites.iter().position(|s| s.name == name)?;
        u16::try_from(index).ok().map(SiteId)
    }
}

/// A site of an architecture's [`Declarations`]: one output that one entry
/// of its semantics leaves undefined (x86: `shrd.of`, SHRD's OF for counts
/// other than 1). Processors differ there; a profile says what one does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SiteId(pub u16);

/// One site: its name (`entry.output`, lower case, as printed) and the
/// names of its inputs, in order: what a processor's choice there may
/// depend on (the entry's operands as read, the flags it reads, the
/// output's previous value `old`, the values it defines `defined.<name>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiteInfo {
    /// The name, unique among the sites.
    pub name: &'static str,
    /// The names of the inputs.
    pub inputs: &'static [&'static str],
}

/// Bits `offset..offset + width` of a register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct View {
    /// The register.
    pub register: RegisterId,
    /// The first bit.
    pub offset: u16,
    /// The number of bits.
    pub width: u16,
}

/// A value defined by a statement ([`Stmt::Read`], [`Stmt::Load`],
/// [`Stmt::Intrinsic`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Local(pub u32);

/// An expression of a [`Semantics`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExprId(pub u32);

/// Operations of one operand. The result has the operand's width unless
/// noted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unary {
    /// Bitwise not.
    Not,
    /// Two's complement negation.
    Neg,
    /// Number of 1 bits.
    Popcount,
    /// Number of 0 bits above the highest 1 bit (the width for 0).
    LeadingZeros,
    /// Number of 0 bits below the lowest 1 bit (the width for 0).
    TrailingZeros,
    /// Bytes in reverse order (the width is a multiple of 8).
    ByteSwap,
    /// 1 bit: whether the low 8 bits have an even number of 1 bits (x86's
    /// parity flag; architecture-neutral as an operation).
    EvenParity8,
}

/// Operations of two operands of the same width. The result has that width
/// unless noted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Binary {
    /// Sum modulo 2^width.
    Add,
    /// Difference modulo 2^width.
    Sub,
    /// Low half of the product (widths up to 128).
    Mul,
    /// Unsigned quotient; all ones for a zero divisor (widths up to 128).
    UDiv,
    /// Unsigned remainder; the dividend for a zero divisor (widths up to
    /// 128).
    URem,
    /// Signed quotient, truncated; all ones for a zero divisor, the
    /// dividend for the most negative value divided by -1 (widths up to
    /// 128).
    SDiv,
    /// Signed remainder, with the dividend's sign; the dividend for a zero
    /// divisor, 0 for the most negative value divided by -1 (widths up to
    /// 128).
    SRem,
    /// Bitwise and.
    And,
    /// Bitwise or.
    Or,
    /// Bitwise exclusive or.
    Xor,
    /// Shift left by the second operand (0 from the width on).
    Shl,
    /// Logical shift right (0 from the width on).
    LShr,
    /// Arithmetic shift right (the sign from the width on).
    AShr,
    /// Rotate left by the second operand modulo the width.
    Rol,
    /// Rotate right by the second operand modulo the width.
    Ror,
    /// 1 bit: equal.
    Eq,
    /// 1 bit: not equal.
    Ne,
    /// 1 bit: unsigned less than.
    ULt,
    /// 1 bit: unsigned less than or equal.
    ULe,
    /// 1 bit: signed less than.
    SLt,
    /// 1 bit: signed less than or equal.
    SLe,
}

/// Flag computations with three operands of the same width. Each has an
/// expansion into plain operations ([`crate::expand`]); the interpreter's
/// direct evaluation is tested against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    /// 1 bit: the carry out of `a + b + c`, `c` being 0 or 1.
    AddCarry,
    /// 1 bit: whether `a + b + c` overflows as a signed sum.
    AddOverflow,
    /// 1 bit: the borrow out of `a - b - c`, `c` being 0 or 1.
    SubBorrow,
    /// 1 bit: whether `a - b - c` overflows as a signed difference.
    SubOverflow,
    /// 1 bit: bit 4 of `a ^ b ^ c`, the carry or borrow out of the low
    /// nibble when `c` is the result of `a + b` or `a - b`.
    NibbleCarry,
}

/// A scalar operation of [`Expr::Lanes`], applied to each lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LaneOp {
    /// An operation of one operand.
    Unary(Unary),
    /// An operation of two operands.
    Binary(Binary),
    /// One operand: `width` bits of each lane from bit `offset`.
    Extract {
        /// The first bit.
        offset: u16,
        /// The number of bits.
        width: u16,
    },
    /// One operand: each lane zero- or sign-extended to `width` bits.
    Extend {
        /// Sign (true) or zero extension.
        signed: bool,
        /// The width of each resulting lane.
        width: u16,
    },
    /// Three operands: each 1-bit lane of the first chooses the lane of the
    /// second (1) or the third (0).
    Select,
}

impl LaneOp {
    /// How many operands it takes.
    pub const fn arity(self) -> usize {
        match self {
            Self::Unary(_) | Self::Extract { .. } | Self::Extend { .. } => 1,
            Self::Binary(_) => 2,
            Self::Select => 3,
        }
    }
}

/// An IEEE 754 binary floating-point format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// binary16.
    Half,
    /// binary32.
    Single,
    /// binary64.
    Double,
    /// The x87 80-bit extended format (64-bit significand with an explicit
    /// integer bit).
    Extended,
}

impl Format {
    /// Its width in bits.
    pub const fn width(self) -> u16 {
        match self {
            Self::Half => 16,
            Self::Single => 32,
            Self::Double => 64,
            Self::Extended => 80,
        }
    }

    /// The format `width` bits wide.
    pub const fn of_width(width: u16) -> Option<Self> {
        match width {
            16 => Some(Self::Half),
            32 => Some(Self::Single),
            64 => Some(Self::Double),
            80 => Some(Self::Extended),
            _ => None,
        }
    }
}

/// An IEEE 754 operation of [`Expr::Float`]. Results are rounded as the
/// rounding operand says ([`Rounding`]); a NaN result is the format's
/// default NaN (positive, quiet, payload 0), whatever the operands: which
/// NaN an architecture returns is its semantics' business.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FloatOp {
    /// `a + b`.
    Add,
    /// `a - b`.
    Sub,
    /// `a × b`.
    Mul,
    /// `a / b`.
    Div,
    /// The square root of `a`.
    Sqrt,
    /// `a × b + c`, rounded once.
    MulAdd,
    /// `a` rounded to an integral value in its format.
    RoundToIntegral,
    /// `a` compared with `b`: four bits, one of them set: less (bit 0),
    /// equal (1), greater (2), unordered (3). A signalling comparison
    /// raises invalid for any NaN operand, a quiet one only for a
    /// signalling NaN.
    Compare {
        /// Whether a quiet NaN raises invalid too.
        signaling: bool,
    },
    /// `a` in another format.
    Convert(Format),
    /// The integer `a` (as wide as an operand lane) in the format.
    FromInt {
        /// Whether `a` is signed.
        signed: bool,
    },
    /// `a` as a `width`-bit integer (at most 128); invalid (NaN, or out of
    /// range) gives 0.
    ToInt {
        /// Whether the integer is signed.
        signed: bool,
        /// Its width.
        width: u16,
    },
}

impl FloatOp {
    /// How many operands it takes (besides the rounding).
    pub const fn arity(self) -> usize {
        match self {
            Self::Sqrt
            | Self::RoundToIntegral
            | Self::Convert(_)
            | Self::FromInt { .. }
            | Self::ToInt { .. } => 1,
            Self::Add | Self::Sub | Self::Mul | Self::Div | Self::Compare { .. } => 2,
            Self::MulAdd => 3,
        }
    }
}

/// What an [`Expr::Float`] gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FloatOutput {
    /// The result.
    Value,
    /// The IEEE exceptions it raises: [`EXCEPTIONS`] bits per lane, one
    /// for each [`Exception`].
    Status,
}

/// An IEEE 754 exception, by its bit in a lane of [`FloatOutput::Status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exception {
    /// Invalid operation (bit 0).
    Invalid,
    /// Division by zero (bit 1).
    DivideByZero,
    /// Overflow (bit 2).
    Overflow,
    /// Underflow: a tiny result, after rounding, that is inexact (bit 3).
    Underflow,
    /// Inexact (bit 4).
    Inexact,
}

impl Exception {
    /// Its bit in a status lane.
    pub const fn bit(self) -> u16 {
        match self {
            Self::Invalid => 0,
            Self::DivideByZero => 1,
            Self::Overflow => 2,
            Self::Underflow => 3,
            Self::Inexact => 4,
        }
    }
}

/// The bits of a status lane.
pub const EXCEPTIONS: u16 = 5;

/// How a result is rounded: the value of an [`Expr::Float`]'s 2-bit
/// rounding operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rounding {
    /// To nearest, ties to even (0).
    NearestEven,
    /// Toward negative infinity (1).
    Down,
    /// Toward positive infinity (2).
    Up,
    /// Toward zero (3).
    TowardZero,
}

impl Rounding {
    /// Its value as an operand.
    pub const fn bits(self) -> u64 {
        match self {
            Self::NearestEven => 0,
            Self::Down => 1,
            Self::Up => 2,
            Self::TowardZero => 3,
        }
    }

    /// The rounding a 2-bit operand value stands for.
    pub const fn of_bits(bits: u64) -> Self {
        match bits & 3 {
            0 => Self::NearestEven,
            1 => Self::Down,
            2 => Self::Up,
            _ => Self::TowardZero,
        }
    }
}

/// An expression. Operands are [`ExprId`]s of the same [`Semantics`],
/// always created before their users.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Expr {
    /// A constant.
    Const(Bits),
    /// The value a statement defined.
    Local(Local),
    /// An unknown value of the given width; `serial` makes each occurrence
    /// distinct. [`Semantics::sites`] says which site it is, if any.
    Undefined {
        /// The width in bits.
        width: u16,
        /// Distinguishes occurrences.
        serial: u32,
    },
    /// An operation of one operand.
    Unary(Unary, ExprId),
    /// An operation of two operands.
    Binary(Binary, ExprId, ExprId),
    /// A flag computation.
    Flag(Flag, ExprId, ExprId, ExprId),
    /// `width` bits of `value` starting at bit `offset`.
    Extract {
        /// The source.
        value: ExprId,
        /// The first bit.
        offset: u16,
        /// The number of bits.
        width: u16,
    },
    /// `high` above `low`; the width is the sum.
    Concat {
        /// The high part.
        high: ExprId,
        /// The low part.
        low: ExprId,
    },
    /// `value` zero- or sign-extended to `width` bits (at least its own).
    Extend {
        /// Sign (true) or zero extension.
        signed: bool,
        /// The source.
        value: ExprId,
        /// The resulting width.
        width: u16,
    },
    /// `then` if the 1-bit `condition` is 1, else `otherwise`.
    Select {
        /// The condition.
        condition: ExprId,
        /// The value if it holds.
        then: ExprId,
        /// The value if not.
        otherwise: ExprId,
    },
    /// `op` lane by lane: each operand is split into `lanes` lanes of equal
    /// width, `op` is applied to lane *i* of the operands, and the results
    /// lie side by side (lane 0 lowest).
    Lanes {
        /// How many lanes.
        lanes: u16,
        /// The operation.
        op: LaneOp,
        /// The operands ([`LaneOp::arity`] of them; the unused ones repeat
        /// the first).
        operands: [ExprId; 3],
    },
    /// The IEEE 754 operation `op` on `lanes` lanes of `format`, rounded as
    /// the 2-bit `rounding` says ([`Rounding`]; the same for all lanes):
    /// its result or its exceptions.
    Float {
        /// The operation.
        op: FloatOp,
        /// The format of the operands' lanes ([`FloatOp::FromInt`]: of the
        /// result's).
        format: Format,
        /// How many lanes.
        lanes: u16,
        /// The result, or the exceptions.
        output: FloatOutput,
        /// The 2-bit rounding.
        rounding: ExprId,
        /// The operands ([`FloatOp::arity`] of them; the unused ones repeat
        /// the first).
        operands: [ExprId; 3],
    },
}

impl Expr {
    /// The expression with each operand replaced by `map` of it.
    #[must_use]
    pub fn map_operands(self, map: &mut impl FnMut(ExprId) -> ExprId) -> Self {
        match self {
            Self::Const(_) | Self::Local(_) | Self::Undefined { .. } => self,
            Self::Unary(op, a) => Self::Unary(op, map(a)),
            Self::Binary(op, a, b) => Self::Binary(op, map(a), map(b)),
            Self::Flag(op, a, b, c) => Self::Flag(op, map(a), map(b), map(c)),
            Self::Extract {
                value,
                offset,
                width,
            } => Self::Extract {
                value: map(value),
                offset,
                width,
            },
            Self::Concat { high, low } => Self::Concat {
                high: map(high),
                low: map(low),
            },
            Self::Extend {
                signed,
                value,
                width,
            } => Self::Extend {
                signed,
                value: map(value),
                width,
            },
            Self::Select {
                condition,
                then,
                otherwise,
            } => Self::Select {
                condition: map(condition),
                then: map(then),
                otherwise: map(otherwise),
            },
            Self::Lanes {
                lanes,
                op,
                operands,
            } => Self::Lanes {
                lanes,
                op,
                operands: operands.map(map),
            },
            Self::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            } => Self::Float {
                op,
                format,
                lanes,
                output,
                rounding: map(rounding),
                operands: operands.map(map),
            },
        }
    }

    /// The operands (an undefined value's site inputs are not among them).
    pub fn operands(self) -> Vec<ExprId> {
        let mut operands = Vec::new();
        let _ = self.map_operands(&mut |id| {
            operands.push(id);
            id
        });
        operands
    }
}

/// Why execution stops at a [`Stmt::Trap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Trap {
    /// Division by zero or a quotient that does not fit (x86 `#DE`).
    Divide,
    /// The instruction is not valid here (x86 `#UD`).
    InvalidInstruction,
    /// A breakpoint instruction (x86 `#BP`).
    Breakpoint,
    /// A protection check failed (x86 `#GP`).
    Protection,
    /// A stack access failed a check (x86 `#SS`).
    Stack,
    /// An unmasked floating-point exception (x86 `#XM` for SSE, `#MF` for
    /// the x87).
    FloatingPoint,
    /// A pointer failed authentication and the processor faults for it
    /// (Arm `FEAT_FPAC`; Linux raises SIGILL, `ILL_ILLOPN`).
    Authentication,
    /// A data access is misaligned where the instruction requires alignment
    /// (the AArch64 Alignment fault, x86 `#AC`).
    Alignment,
    /// A software interrupt: the processor enters the handler of this
    /// vector (x86 `INT n`). What the handler does is the platform's:
    /// Windows ends the process at vector `0x29` (`__fastfail`).
    Interrupt(u8),
}

/// A statement. A [`Semantics`] body is a list of them, run in order; the
/// instruction continues at the next one unless a control transfer or trap
/// says otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Stmt {
    /// `local` = the register view's current value.
    Read {
        /// The value defined.
        local: Local,
        /// What is read.
        view: View,
    },
    /// The register view = `value`, which has the view's width.
    Write {
        /// What is written.
        view: View,
        /// The value.
        value: ExprId,
    },
    /// `local` = `bytes` bytes of memory at `address`, little-endian.
    Load {
        /// The value defined.
        local: Local,
        /// The address (as wide as the architecture's addresses).
        address: ExprId,
        /// The number of bytes.
        bytes: u16,
    },
    /// Memory at `address` = `value`, little-endian, `value`'s width / 8
    /// bytes.
    Store {
        /// The address.
        address: ExprId,
        /// The value (a whole number of bytes).
        value: ExprId,
    },
    /// `then` if the 1-bit `condition` is 1, else `otherwise`.
    If {
        /// The condition.
        condition: ExprId,
        /// Statements if it holds.
        then: Vec<Stmt>,
        /// Statements if not.
        otherwise: Vec<Stmt>,
    },
    /// The body, repeated until a [`Stmt::Break`] in it runs.
    Loop(Vec<Stmt>),
    /// Leaves the innermost [`Stmt::Loop`].
    Break,
    /// Stops the instruction: it does not complete, and none of its
    /// effects happen.
    Trap(Trap),
    /// Continues at `target` instead of the next instruction.
    Jump {
        /// The target address.
        target: ExprId,
    },
    /// A call: continues at `target`; `return_address` is where the callee
    /// returns to (the instruction's own effects, such as pushing it, are
    /// separate statements).
    Call {
        /// The target address.
        target: ExprId,
        /// The address the call returns to.
        return_address: ExprId,
    },
    /// A return: continues at `target`.
    Return {
        /// The target address.
        target: ExprId,
    },
    /// The statements, as one indivisible access to memory (an x86 `lock`
    /// prefix): no other processor's memory access falls between them.
    Atomic(Vec<Stmt>),
    /// Enters the operating system (x86 `syscall`); execution continues
    /// with the next instruction when it returns, with whatever effects the
    /// system had.
    SystemCall,
    /// `outputs` = `intrinsic` applied to `inputs`: values the processor or
    /// the system supplies (as wide as the intrinsic declares), or none.
    Intrinsic {
        /// The intrinsic.
        intrinsic: IntrinsicId,
        /// The inputs.
        inputs: Vec<ExprId>,
        /// The values defined.
        outputs: Vec<Local>,
    },
}

impl Stmt {
    /// Replaces each expression the statement (and those inside it) uses
    /// by `map` of it.
    pub fn map_exprs(&mut self, map: &mut impl FnMut(ExprId) -> ExprId) {
        match self {
            Self::Read { .. } | Self::Break | Self::Trap(_) | Self::SystemCall => {}
            Self::Write { value, .. } => *value = map(*value),
            Self::Load { address, .. } => *address = map(*address),
            Self::Store { address, value } => {
                *address = map(*address);
                *value = map(*value);
            }
            Self::If {
                condition,
                then,
                otherwise,
            } => {
                *condition = map(*condition);
                for stmt in then.iter_mut().chain(otherwise) {
                    stmt.map_exprs(map);
                }
            }
            Self::Loop(body) | Self::Atomic(body) => {
                for stmt in body {
                    stmt.map_exprs(map);
                }
            }
            Self::Jump { target } | Self::Return { target } => *target = map(*target),
            Self::Call {
                target,
                return_address,
            } => {
                *target = map(*target);
                *return_address = map(*return_address);
            }
            Self::Intrinsic { inputs, .. } => {
                for input in inputs {
                    *input = map(*input);
                }
            }
        }
    }
}

/// The semantics of one instruction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Semantics {
    /// Expressions with their widths, indexed by [`ExprId`]; each operand
    /// (and each site input) comes before its users.
    pub exprs: Vec<(Expr, u16)>,
    /// The width of each [`Local`], indexed by its number.
    pub locals: Vec<u16>,
    /// The statements.
    pub body: Vec<Stmt>,
    /// The site of each [`Expr::Undefined`] that has one, with its inputs,
    /// in the order of their serials.
    pub sites: Vec<SiteUse>,
}

/// The site of an [`Expr::Undefined`] and the values of its inputs (as the
/// site declares them), which are defined wherever the undefined value is
/// used.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SiteUse {
    /// The undefined value's serial.
    pub serial: u32,
    /// The site.
    pub site: SiteId,
    /// The inputs.
    pub inputs: Vec<ExprId>,
}

impl Semantics {
    /// Expression `id` and its width.
    pub fn expr(&self, id: ExprId) -> Option<(Expr, u16)> {
        self.exprs.get(id.0 as usize).copied()
    }

    /// The width of expression `id` (0 if there is none).
    pub fn width(&self, id: ExprId) -> u16 {
        self.expr(id).map_or(0, |(_, width)| width)
    }

    /// The site of the undefined value numbered `serial`, if it has one.
    pub fn site(&self, serial: u32) -> Option<&SiteUse> {
        self.sites
            .binary_search_by_key(&serial, |site| site.serial)
            .ok()
            .and_then(|index| self.sites.get(index))
    }
}
