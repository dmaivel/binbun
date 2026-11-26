//! C's integer conversions as the printer applies them: what a C value is
//! of the L2 value it stands for, what C's promotions and usual
//! arithmetic conversions make of it, and which conversion makes it what
//! a use needs. Decisions only, on a value's [`Form`]: the printer spells
//! them ([`super::Printer::apply`]).

use core::cmp::Ordering;

use binbun_semantics::bits::Bits;

use super::types::{CTy, IntRep, container, native};

/// What a C value is, of the L2 value `x` of width `w` it stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// The unsigned value of `x`.
    Zero,
    /// The signed value of `x`.
    Sign,
    /// Only congruent to `x` modulo 2^w.
    Low,
}

/// The values of a C integer value's range: `[0, 2^n)` or
/// `[-2^(n-1), 2^(n-1))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Range {
    Unsigned(u16),
    Signed(u16),
}

/// An integer type: signedness and width (`bool`: unsigned, 1 bit).
pub(super) type IntTy = (bool, u16);

/// The integer type of `ty`, if it is one.
pub(super) const fn int_of(ty: CTy) -> Option<IntTy> {
    match ty {
        CTy::Int { signed, bits } => Some((signed, bits)),
        CTy::Bool => Some((false, 1)),
        CTy::Float(_)
        | CTy::Bytes
        | CTy::Pointer(_)
        | CTy::Code(_)
        | CTy::Other(_)
        | CTy::Vector(_) => None,
    }
}

/// The C type of integer type `ty`.
const fn int_type((signed, bits): IntTy) -> CTy {
    CTy::Int { signed, bits }
}

/// `ty` after the integer promotions.
pub(super) const fn promote(ty: IntTy) -> IntTy {
    if ty.1 >= 32 { ty } else { (true, 32) }
}

/// The type of `a op b` for promoted integer types (C's usual arithmetic
/// conversions).
pub(super) fn common(a: IntTy, b: IntTy) -> IntTy {
    let ((a_signed, a_bits), (b_signed, b_bits)) = (a, b);
    if a_signed == b_signed {
        return (a_signed, a_bits.max(b_bits));
    }
    let (unsigned, signed) = if a_signed {
        (b_bits, a_bits)
    } else {
        (a_bits, b_bits)
    };
    if unsigned >= signed {
        (false, unsigned)
    } else {
        (true, signed)
    }
}

/// Whether every value of `range` is a value of `ty`.
pub(super) const fn fits(range: Range, ty: IntTy) -> bool {
    match (range, ty.0) {
        (Range::Unsigned(bits), false) | (Range::Signed(bits), true) => bits <= ty.1,
        (Range::Unsigned(bits), true) => bits < ty.1,
        (Range::Signed(_), false) => false,
    }
}

/// The number of bits of `value`.
fn bit_length(value: u128) -> u16 {
    #[expect(clippy::cast_possible_truncation, reason = "at most 128")]
    let bits = (128 - value.leading_zeros()) as u16;
    bits
}

/// The C integer of an L2 constant read as `class` says: whether it is
/// negative, and its magnitude.
pub(super) fn constant_value(bits: Bits, class: Class) -> (bool, u128) {
    let width = bits.width();
    let unsigned = bits.low_u128();
    if class == Class::Sign && bits.msb() {
        let magnitude = if width >= 128 {
            unsigned.wrapping_neg()
        } else {
            (1u128 << width) - unsigned
        };
        (true, magnitude)
    } else {
        (false, unsigned)
    }
}

/// Whether the integer `(negative, magnitude)` is a value of `ty`.
pub(super) fn holds(ty: IntTy, negative: bool, magnitude: u128) -> bool {
    let (signed, bits) = ty;
    let top = |shift: u16| {
        if shift >= 128 {
            u128::MAX
        } else {
            (1u128 << shift) - 1
        }
    };
    match (signed, negative) {
        (false, true) => magnitude == 0,
        (false, false) => bits >= 128 || magnitude <= top(bits),
        (true, false) => magnitude <= top(bits - 1),
        (true, true) => magnitude == 0 || magnitude - 1 <= top(bits - 1),
    }
}

/// The literal types, narrowest first.
const CANDIDATES: [IntTy; 6] = [
    (true, 32),
    (false, 32),
    (true, 64),
    (false, 64),
    (true, 128),
    (false, 128),
];

/// The narrowest of `int`, `unsigned`, `long`, `unsigned long` and the
/// 128-bit types that holds the constant `bits` read as `class` says.
pub(super) fn narrowest(bits: Bits, class: Class) -> Option<IntTy> {
    let (negative, magnitude) = constant_value(bits, class);
    CANDIDATES
        .into_iter()
        .find(|&ty| holds(ty, negative, magnitude))
}

/// What the conversion rules see of a C value: its type, class, L2 width
/// and constant, without its tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Form {
    /// The C type.
    pub ty: CTy,
    /// What the C value is of the L2 value.
    pub class: Class,
    /// The L2 width.
    pub width: u16,
    /// For a literal: the L2 constant, to print again as a use needs.
    pub constant: Option<Bits>,
    /// Whether it is `x + k`, `k - x` or `x * k` whose literal `k` can be
    /// printed again unsigned ([`unsigned_literal`]).
    pub unsigned_literal: bool,
}

impl Form {
    /// A literal of the constant `bits`, of C type `ty`, read as `class`
    /// says.
    fn literal(bits: Bits, class: Class, ty: IntTy) -> Self {
        let (negative, _) = constant_value(bits, class);
        Self {
            ty: int_type(ty),
            class: if negative { Class::Sign } else { Class::Zero },
            width: bits.width(),
            constant: Some(bits),
            unsigned_literal: false,
        }
    }

    /// A value of `width` bits, of integer type `ty` and `class`, not a
    /// literal.
    const fn computed(ty: IntTy, class: Class, width: u16) -> Self {
        Self {
            ty: int_type(ty),
            class,
            width,
            constant: None,
            unsigned_literal: false,
        }
    }

    /// The range of its C values.
    pub(super) fn range(&self) -> Option<Range> {
        let (signed, bits) = int_of(self.ty)?;
        if let Some(constant) = self.constant {
            let (negative, magnitude) = constant_value(constant, self.class);
            return Some(if negative {
                Range::Signed(bit_length(magnitude - 1) + 1)
            } else {
                Range::Unsigned(bit_length(magnitude))
            });
        }
        Some(match self.class {
            Class::Zero => Range::Unsigned(self.width.min(bits - u16::from(signed))),
            Class::Sign if signed => Range::Signed(self.width.min(bits)),
            Class::Sign | Class::Low if signed => Range::Signed(bits),
            Class::Sign | Class::Low => Range::Unsigned(bits),
        })
    }

    /// Whether it is what `need` asks for.
    pub(super) fn is(&self, need: Class) -> bool {
        let Some((signed, bits)) = int_of(self.ty) else {
            return false;
        };
        match need {
            Class::Low => true,
            Class::Zero => self.class == Class::Zero || (!signed && bits == self.width),
            Class::Sign => {
                self.class == Class::Sign
                    || (signed && bits == self.width)
                    || (self.class == Class::Zero
                        && matches!(self.range(), Some(Range::Unsigned(n)) if n < self.width))
            }
        }
    }

    /// Whether, converted to `ty` (by C's usual arithmetic conversions),
    /// it is what `need` asks for.
    pub(super) fn is_in(&self, ty: IntTy, need: Class) -> bool {
        let Some(range) = self.range() else {
            return false;
        };
        if fits(range, ty) {
            return self.is(need);
        }
        match ty.1.cmp(&self.width) {
            Ordering::Less => false,
            Ordering::Equal => {
                need == Class::Low || need == if ty.0 { Class::Sign } else { Class::Zero }
            }
            Ordering::Greater => need == Class::Low,
        }
    }

    /// Whether, compared with or chosen against a value of type `ty`, it
    /// would draw a warning about mixing signedness: a signed value C
    /// converts to unsigned, unless it is a literal or of an unsigned type
    /// narrower than `int`.
    pub(super) fn mixes(&self, ty: IntTy) -> bool {
        let Some(own) = int_of(self.ty) else {
            return false;
        };
        !ty.0
            && promote(own).0
            && own.0
            && self
                .constant
                .is_none_or(|bits| constant_value(bits, self.class).0)
    }

    /// Its integer type after the promotions.
    pub(super) fn promoted(&self) -> Option<IntTy> {
        int_of(self.ty).map(promote)
    }

    /// Whether it is the null pointer constant: a literal 0.
    pub(super) fn null(&self) -> bool {
        self.constant.is_some_and(|bits| bits.is_zero())
    }

    /// It cast to `ty`: of the same class where every value of its range
    /// is a value of `ty`, else only congruent.
    pub(super) fn cast(self, ty: CTy) -> Self {
        let class = match (int_of(ty), self.range()) {
            (Some(target), Some(range)) if fits(range, target) => self.class,
            _ => Class::Low,
        };
        Self {
            ty,
            class,
            width: self.width,
            constant: None,
            unsigned_literal: false,
        }
    }

    /// Its constant, for a literal ([`Conversion::Literal`]).
    pub(super) fn literal_bits(&self) -> Bits {
        self.constant.unwrap_or(Bits::zero(self.width))
    }

    /// What `conversion` makes of it.
    pub(super) fn after(self, conversion: Conversion) -> Self {
        match conversion {
            Conversion::Keep => self,
            Conversion::UnsignedLiteral => Self {
                ty: int_type((false, self.width)),
                class: Class::Zero,
                unsigned_literal: false,
                ..self
            },
            Conversion::Literal(literal) => {
                Self::literal(self.literal_bits(), literal.class, literal.ty)
            }
            Conversion::Folded(literal) => Self {
                constant: None,
                ..Self::literal(self.literal_bits(), literal.class, literal.ty)
            },
            Conversion::Cast(ty) => self.cast(int_type(ty)),
            Conversion::Negate => Self::computed(
                self.promoted().unwrap_or((true, 32)),
                Class::Sign,
                self.width,
            ),
            Conversion::SignExtend(wide) => Self::computed((true, wide), Class::Sign, self.width),
            Conversion::Mask { ty, .. } => {
                Self::computed(common(ty, (false, ty.1)), Class::Zero, self.width)
            }
        }
    }
}

/// A literal printed again: its constant as a literal of C type `ty`,
/// read as `class` says; `bitwise` prefers hexadecimal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Literal {
    pub class: Class,
    pub ty: IntTy,
    pub bitwise: bool,
}

/// How a value is converted to be what a use needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Conversion {
    /// None: it already is.
    Keep,
    /// `x + k`, `k - x` or `x * k` in the signed type of its width, with
    /// `k` printed unsigned ([`unsigned_literal`]).
    UnsignedLiteral,
    /// A literal printed again.
    Literal(Literal),
    /// A literal printed again, one of an operation's two literal
    /// operands: a typed value the other is fitted to, no longer a
    /// literal to fit.
    Folded(Literal),
    /// A cast to an integer type.
    Cast(IntTy),
    /// `-x` of a 1-bit value 0 or 1: 0 or -1, its sign-extended value.
    Negate,
    /// `sext_n(x, width)`, `x` as exactly the unsigned type of `wide` bits.
    SignExtend(u16),
    /// `x & mask` keeping the value's width; `x` of the promoted type `ty`,
    /// cast to it first where `widen`.
    Mask { widen: bool, ty: IntTy },
}

/// Why no conversion makes a value what a use needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    /// A constant no C literal type holds.
    WideConstant,
    /// A value over 128 bits.
    WideValue,
    /// An operand of an integer operation that is not an integer.
    NotIntegers,
    /// Operands no conversions give a common type.
    NoCommonType,
}

/// The constant `bits` read as `class` says, as a literal of the
/// narrowest type that holds it ([`narrowest`]).
fn constant(bits: Bits, class: Class, bitwise: bool) -> Result<Conversion, Refusal> {
    let ty = narrowest(bits, class).ok_or(Refusal::WideConstant)?;
    Ok(Conversion::Literal(Literal { class, ty, bitwise }))
}

/// How `value` (an integer) is made what `need` asks for: a literal
/// printed again, a cast to the exact type of its width, or at widths C
/// lacks a mask or `sext_n`.
pub(super) fn coerce(value: Form, need: Class) -> Result<Conversion, Refusal> {
    if value.is(need) {
        return Ok(Conversion::Keep);
    }
    if need == Class::Zero && unsigned_literal(value) {
        return Ok(Conversion::UnsignedLiteral);
    }
    let width = value.width;
    if let Some(bits) = value.constant {
        return constant(bits, need, false);
    }
    if native(width) {
        return Ok(Conversion::Cast((need == Class::Sign, width)));
    }
    if width == 1 && need == Class::Sign && value.is(Class::Zero) {
        return Ok(Conversion::Negate);
    }
    let wide = if width < 64 { 64 } else { 128 };
    if width > 128 {
        return Err(Refusal::WideValue);
    }
    if need == Class::Sign {
        return Ok(Conversion::SignExtend(wide));
    }
    let widen = value.promoted().is_some_and(|ty| ty.1 < width);
    let ty = if widen {
        (false, wide)
    } else {
        value.promoted().unwrap_or((false, 32))
    };
    Ok(Conversion::Mask { widen, ty })
}

/// How `value` (an integer congruent to the L2 value) is made exactly
/// C type `(signed, bits)`, `bits` at least its width: unchanged if it is
/// of that type, else cast.
pub(super) fn exact(value: Form, signed: bool, bits: u16) -> Conversion {
    if value.ty == int_type((signed, bits)) {
        return Conversion::Keep;
    }
    if !signed && bits == value.width && unsigned_literal(value) {
        return Conversion::UnsignedLiteral;
    }
    if value.constant.is_some() && bits >= 32 {
        let class = if signed { Class::Sign } else { Class::Zero };
        return Conversion::Literal(Literal {
            class,
            ty: (signed, bits),
            bitwise: false,
        });
    }
    Conversion::Cast((signed, bits))
}

/// Whether `value`, `x + k`, `k - x` or `x * k` in the signed type of its
/// width, is made its zero value by printing the literal `k` unsigned
/// (`x - 14U`, not `(uint32_t)(x - 14)`): C then converts `x` to the
/// unsigned type of the width and computes in it, modulo 2^width.
pub(super) fn unsigned_literal(value: Form) -> bool {
    value.unsigned_literal
        && value.ty == int_type((true, value.width))
        && matches!(value.width, 32 | 64)
}

/// How a literal argument is printed in the class of a parameter of
/// signedness `signed` (so C's conversion does not change its value);
/// anything else as it is.
pub(super) fn arg(value: Form, signed: bool) -> Result<Conversion, Refusal> {
    match value.constant {
        Some(bits) => constant(bits, if signed { Class::Sign } else { Class::Zero }, false),
        None => Ok(Conversion::Keep),
    }
}

/// How a 1-bit condition is made one whose C value is non-zero exactly
/// when it is 1.
pub(super) fn truthy(value: Form) -> Result<Conversion, Refusal> {
    if value.is(Class::Zero) || value.is(Class::Sign) {
        Ok(Conversion::Keep)
    } else {
        coerce(value, Class::Zero)
    }
}

/// How an integer `value` is made one that C's conversion on assignment
/// to an integer type held as `rep` gives the same bits.
pub(super) fn assigned(value: Form, rep: IntRep) -> Result<Conversion, Refusal> {
    if rep.boolean {
        return truthy(value);
    }
    if native(rep.width) {
        return arg(value, rep.signed);
    }
    coerce(value, if rep.signed { Class::Sign } else { Class::Zero })
}

/// Whether C converts a pointer to another pointer type on assignment
/// without a cast: to the same type (`same`), or between pointers to data
/// (`data`) one of which is `void *` (`void`).
pub(super) const fn implicit_pointer(same: bool, data: bool, void: bool) -> bool {
    same || (data && void)
}

/// One of the two operands of a binary operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Side {
    Left,
    Right,
}

/// The most conversions [`operands`] gives: three a round.
const OPERAND_STEPS: usize = 18;

/// The conversions of a binary operation's two operands, in order, and
/// the type C computes in (or why there is none).
#[derive(Debug)]
pub(super) struct Operands {
    steps: [(Side, Conversion); OPERAND_STEPS],
    len: usize,
    /// The type C computes in.
    pub outcome: Result<IntTy, Refusal>,
}

impl Operands {
    /// The conversions, in order.
    pub(super) fn steps(&self) -> &[(Side, Conversion)] {
        self.steps.get(..self.len).unwrap_or(&[])
    }

    /// `conversion` of the operand on `side` (now `form`).
    fn push(&mut self, side: Side, form: &mut Form, conversion: Conversion) {
        *form = form.after(conversion);
        if let Some(step) = self.steps.get_mut(self.len) {
            *step = (side, conversion);
            self.len += 1;
        }
    }

    /// The conversions so far, ending in `outcome`.
    fn ending(mut self, outcome: Result<IntTy, Refusal>) -> Self {
        self.outcome = outcome;
        self
    }
}

/// How the two operands of a binary operation whose operands must be
/// `need` (a comparison: `compare`, which must not mix signedness) are
/// converted: literals typed (`bitwise` prefers hexadecimal), operands
/// widened where C would compute narrower than the operation's width and
/// cast where they are not what is needed.
pub(super) fn operands(
    mut a: Form,
    mut b: Form,
    need: Class,
    compare: bool,
    bitwise: bool,
) -> Operands {
    let mut plan = Operands {
        steps: [(Side::Left, Conversion::Keep); OPERAND_STEPS],
        len: 0,
        outcome: Err(Refusal::NoCommonType),
    };
    let width = a.width.max(b.width);
    for _ in 0..6 {
        if a.constant.is_some() && b.constant.is_some() {
            let bits = a.constant.unwrap_or(Bits::zero(width));
            let class = if need == Class::Sign {
                Class::Sign
            } else {
                Class::Zero
            };
            let Some(ty) = narrowest(bits, class) else {
                return plan.ending(Err(Refusal::WideConstant));
            };
            let literal = Literal { class, ty, bitwise };
            plan.push(Side::Left, &mut a, Conversion::Folded(literal));
        }
        let fitted = if a.constant.is_some() {
            Some((Side::Left, fit_literal(a, b, need, compare, bitwise)))
        } else if b.constant.is_some() {
            Some((Side::Right, fit_literal(b, a, need, compare, bitwise)))
        } else {
            None
        };
        match fitted {
            Some((side, Ok(conversion))) => {
                let form = if side == Side::Left { &mut a } else { &mut b };
                plan.push(side, form, conversion);
            }
            Some((_, Err(refusal))) => return plan.ending(Err(refusal)),
            None => {}
        }
        let (Some(ta), Some(tb)) = (a.promoted(), b.promoted()) else {
            return plan.ending(Err(Refusal::NotIntegers));
        };
        let ty = common(ta, tb);
        if ty.1 < width {
            let wide = container(width).unwrap_or(128).max(32);
            let cast = Conversion::Cast((need == Class::Sign, wide));
            if a.constant.is_none() && (ta.1 <= tb.1 || b.constant.is_some()) {
                plan.push(Side::Left, &mut a, cast);
            } else {
                plan.push(Side::Right, &mut b, cast);
            }
            continue;
        }
        let good = |v: &Form| v.is_in(ty, need) && !(compare && v.mixes(ty));
        let (good_a, good_b) = (good(&a), good(&b));
        if good_a && good_b {
            return plan.ending(Ok(ty));
        }
        // First make each operand what is needed, then keep it so
        // through the conversions.
        let (side, conversion) = if !a.is(need) && a.constant.is_none() {
            (Side::Left, coerce(a, need))
        } else if !b.is(need) && b.constant.is_none() {
            (Side::Right, coerce(b, need))
        } else if !good_a {
            (Side::Left, fix(a, need, ty))
        } else {
            (Side::Right, fix(b, need, ty))
        };
        match conversion {
            Ok(conversion) => {
                let form = if side == Side::Left { &mut a } else { &mut b };
                plan.push(side, form, conversion);
            }
            Err(refusal) => return plan.ending(Err(refusal)),
        }
    }
    plan.ending(Err(Refusal::NoCommonType))
}

/// How `value` is made `need` (or, if it is, cast to the type of `need`'s
/// signedness and `ty`'s width so the conversions keep it).
fn fix(value: Form, need: Class, ty: IntTy) -> Result<Conversion, Refusal> {
    if !value.is(need) {
        return coerce(value, need);
    }
    let bits = container(value.width).unwrap_or(128).max(ty.1);
    let signed = match need {
        Class::Sign => true,
        Class::Zero => false,
        Class::Low => ty.0,
    };
    if let Some(bits_value) = value.constant {
        let class = if signed { Class::Sign } else { Class::Zero };
        return constant(bits_value, class, false);
    }
    Ok(Conversion::Cast((signed, bits)))
}

/// How the literal `literal` is typed to go with `other`: the first of
/// `other`'s promoted type and the candidate types that holds its value as
/// `need` reads it, makes C compute at the width, and keeps `other` what
/// it must be.
fn fit_literal(
    literal: Form,
    other: Form,
    need: Class,
    compare: bool,
    bitwise: bool,
) -> Result<Conversion, Refusal> {
    let bits = literal.literal_bits();
    let width = bits.width();
    let other_ty = other.promoted().unwrap_or((true, 32));
    let class = match need {
        Class::Zero | Class::Sign => need,
        Class::Low => {
            let (negative, magnitude) = constant_value(bits, Class::Sign);
            // A signed operand: `x - 1`, `x & -16`, `x | -1`, not
            // values beyond its type (compilers warn when the result
            // is converted back).
            if negative && magnitude < 1 << 15 && other_ty.0 {
                Class::Sign
            } else {
                Class::Zero
            }
        }
    };
    let (negative, magnitude) = constant_value(bits, class);
    let mut first = None;
    // `int` where it holds the value, else the other operand's type,
    // else the narrowest that does.
    let order = [(true, 32), other_ty].into_iter().chain(CANDIDATES);
    for ty in order {
        if !holds(ty, negative, magnitude) {
            continue;
        }
        let common = common(other_ty, ty);
        if common.1 < width {
            continue;
        }
        let probe = Form::literal(bits, class, ty);
        let keeps = other.is_in(common, need)
            && probe.is_in(common, need)
            && !(compare && (other.mixes(common) || probe.mixes(common)));
        if keeps {
            return Ok(Conversion::Literal(Literal { class, ty, bitwise }));
        }
        first.get_or_insert(ty);
    }
    let ty = first.ok_or(Refusal::WideConstant)?;
    Ok(Conversion::Literal(Literal { class, ty, bitwise }))
}
