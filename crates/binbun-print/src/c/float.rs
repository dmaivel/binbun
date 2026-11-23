//! IEEE 754 operations of one lane: C's `float` and `double` arithmetic
//! (rounding to nearest), the compilers' builtins, and `binbun_defs.h`'s
//! helpers for comparisons, roundings and conversions to integers.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, FloatOp, FloatOutput, Format};

use super::types::CTy;
use super::unlifted::Opaque;
use super::value::{Class, Op, Value};
use super::{PrintError, Printer, error};
use crate::document::Doc;

impl Printer<'_> {
    /// An `Expr::Float`: `operands` are its operands, then the rounding.
    pub(super) fn float(
        &mut self,
        op: FloatOp,
        format: Format,
        lanes: u16,
        output: FloatOutput,
        mut operands: Vec<Value>,
        width: u16,
    ) -> Result<Value, PrintError> {
        if !matches!(format, Format::Single | Format::Double) {
            return Err(self.unsupported(self.node, "x87 extended and half-precision arithmetic"));
        }
        let rounding = operands
            .pop()
            .ok_or_else(|| self.unsupported(self.node, "a float operation without a rounding"))?;
        if output == FloatOutput::Status {
            if lanes != 1 {
                return Err(self.unsupported(self.node, "floating-point status of vectors"));
            }
            return self.float_status(op, format, operands, rounding, width);
        }
        let nearest = rounding.constant.is_some_and(|bits| bits.is_zero());
        let dynamic = matches!(op, FloatOp::RoundToIntegral | FloatOp::ToInt { .. });
        if lanes != 1 {
            if !nearest {
                return Err(self.unsupported(self.node, "vector operations"));
            }
            return self.vector_float(op, format, lanes, operands, width);
        }
        if !nearest && !dynamic {
            return self.float_rounded(op, format, operands, rounding, width);
        }
        let fty = CTy::Float(format);
        if let FloatOp::FromInt { signed } = op {
            let [a] = take(operands)?;
            let a = self.int_view(a)?;
            let a = self.coerce(a, if signed { Class::Sign } else { Class::Zero })?;
            return Ok(self.cast(a, fty).with_width(width));
        }
        let mut floats = Vec::with_capacity(operands.len());
        for operand in operands {
            floats.push(self.as_float(operand, format)?);
        }
        self.float_operation(op, floats, rounding, format, width)
    }

    /// The operands of `op` on `format` as its helper takes them: floats
    /// of the format, a signed integer of 32 or 64 bits to convert.
    fn float_arguments(
        &mut self,
        op: FloatOp,
        format: Format,
        operands: Vec<Value>,
    ) -> Result<Vec<Value>, PrintError> {
        let mut arguments = Vec::with_capacity(operands.len() + 1);
        for operand in operands {
            if matches!(op, FloatOp::FromInt { .. }) {
                let bits = operand.width;
                if !matches!(bits, 32 | 64) {
                    return Err(self.unsupported(self.node, "conversions of odd integers"));
                }
                let operand = self.int_view(operand)?;
                let operand = self.coerce(operand, Class::Sign)?;
                arguments.push(self.cast(operand, CTy::Int { signed: true, bits }));
            } else {
                arguments.push(self.as_float(operand, format)?);
            }
        }
        Ok(arguments)
    }

    /// An operation rounded as the program's own choice says (`rounding`
    /// no constant, or not to nearest): `binbun_defs.h` runs the machine's
    /// instruction under it (`float_mul(a, b, rounding)`), since C's
    /// operator rounds as the compiler assumes.
    fn float_rounded(
        &mut self,
        op: FloatOp,
        format: Format,
        operands: Vec<Value>,
        rounding: Value,
        width: u16,
    ) -> Result<Value, PrintError> {
        let (name, ty) = match op {
            FloatOp::Add => ("float_add", format),
            FloatOp::Sub => ("float_sub", format),
            FloatOp::Mul => ("float_mul", format),
            FloatOp::Div => ("float_div", format),
            FloatOp::Sqrt => ("float_sqrt", format),
            FloatOp::MulAdd => ("float_fma", format),
            FloatOp::Convert(target @ (Format::Single | Format::Double)) if target != format => {
                ("float_convert", target)
            }
            FloatOp::FromInt { signed: true } if format == Format::Single => {
                ("f32_from_sint", format)
            }
            FloatOp::FromInt { signed: true } => ("f64_from_sint", format),
            FloatOp::Convert(_)
            | FloatOp::FromInt { signed: false }
            | FloatOp::RoundToIntegral
            | FloatOp::Compare { .. }
            | FloatOp::ToInt { .. } => {
                return Err(self.unsupported(self.node, "roundings other than to nearest"));
            }
        };
        let mut arguments = self.float_arguments(op, format, operands)?;
        arguments.push(self.rounding(rounding)?);
        Ok(self.helper(name, arguments, CTy::Float(ty), Class::Low, width))
    }

    /// The exceptions an operation raises ([`FloatOutput::Status`]), five
    /// bits: `binbun_defs.h` runs the machine's instruction with no flag set
    /// and reads those it leaves (`float_mul_status(a, b, rounding)`).
    fn float_status(
        &mut self,
        op: FloatOp,
        format: Format,
        operands: Vec<Value>,
        rounding: Value,
        width: u16,
    ) -> Result<Value, PrintError> {
        let name = match op {
            FloatOp::Add => "float_add_status",
            FloatOp::Sub => "float_sub_status",
            FloatOp::Mul => "float_mul_status",
            FloatOp::Div => "float_div_status",
            FloatOp::Sqrt => "float_sqrt_status",
            FloatOp::MulAdd => "float_fma_status",
            FloatOp::RoundToIntegral => "float_round_status",
            FloatOp::Compare { signaling: false } => "float_compare_status",
            FloatOp::Compare { signaling: true } => "float_compare_signaling_status",
            FloatOp::Convert(target @ (Format::Single | Format::Double)) if target != format => {
                "float_convert_status"
            }
            FloatOp::FromInt { signed: true } if format == Format::Single => "f32_from_sint_status",
            FloatOp::FromInt { signed: true } => "f64_from_sint_status",
            FloatOp::ToInt {
                signed: true,
                width: 32,
            } => "float_to_sint32_status",
            FloatOp::ToInt {
                signed: true,
                width: 64,
            } => "float_to_sint64_status",
            FloatOp::Convert(_) | FloatOp::FromInt { signed: false } | FloatOp::ToInt { .. } => {
                return Err(self.unsupported(self.node, "floating-point status"));
            }
        };
        let mut arguments = self.float_arguments(op, format, operands)?;
        if !matches!(op, FloatOp::Compare { .. }) {
            arguments.push(self.rounding(rounding)?);
        }
        let ty = CTy::Int {
            signed: false,
            bits: 8,
        };
        Ok(self.helper(name, arguments, ty, Class::Zero, width))
    }

    /// An operation on floats (`floats`, converted), rounded as `rounding`
    /// says where that is not to nearest.
    fn float_operation(
        &mut self,
        op: FloatOp,
        mut floats: Vec<Value>,
        rounding: Value,
        format: Format,
        width: u16,
    ) -> Result<Value, PrintError> {
        let fty = CTy::Float(format);
        let double = format == Format::Double;
        let name = |single: &'static str, wide: &'static str| if double { wide } else { single };
        let (text, kind) = match op {
            FloatOp::Add => ("+", Op::Additive),
            FloatOp::Sub => ("-", Op::Additive),
            FloatOp::Mul => ("*", Op::Multiplicative),
            FloatOp::Div => ("/", Op::Multiplicative),
            FloatOp::Sqrt => {
                let sqrt = name("__builtin_sqrtf", "__builtin_sqrt");
                return Ok(self.helper(sqrt, floats, fty, Class::Low, width));
            }
            FloatOp::MulAdd => {
                let fma = name("__builtin_fmaf", "__builtin_fma");
                return Ok(self.helper(fma, floats, fty, Class::Low, width));
            }
            FloatOp::RoundToIntegral => {
                floats.push(self.rounding(rounding)?);
                let round = name("binbun_roundf", "binbun_round");
                return Ok(self.helper(round, floats, fty, Class::Low, width));
            }
            FloatOp::Compare { .. } => {
                let ty = CTy::Int {
                    signed: false,
                    bits: 8,
                };
                return Ok(self.helper("fcmp", floats, ty, Class::Zero, width));
            }
            FloatOp::Convert(target) => {
                if !matches!(target, Format::Single | Format::Double) {
                    return Err(
                        self.unsupported(self.node, "x87 extended and half-precision arithmetic")
                    );
                }
                let [a] = take(floats)?;
                return Ok(self.cast(a, CTy::Float(target)).with_width(width));
            }
            FloatOp::ToInt {
                signed,
                width: bits,
            } => {
                if bits > 64 {
                    return Err(self.unsupported(self.node, "conversions to integers over 64 bits"));
                }
                if let Some(converted) = self.in_range(&floats, &rounding, signed, bits, double) {
                    return Ok(converted.with_width(width));
                }
                floats.push(self.literal_number(u64::from(bits), false));
                floats.push(self.rounding(rounding)?);
                let (helper, class) = if signed {
                    ("float_to_sint", Class::Sign)
                } else {
                    ("float_to_uint", Class::Zero)
                };
                return Ok(self.helper(
                    helper,
                    floats,
                    CTy::Int { signed, bits: 64 },
                    class,
                    width,
                ));
            }
            FloatOp::FromInt { .. } => {
                return Err(error(self.node, "a conversion from an integer"));
            }
        };
        let [a, b] = take(floats)?;
        let loads = a.loads || b.loads;
        let (doc, depth) = self.binary_doc(a, text, kind, b);
        Ok(Value {
            doc,
            op: kind,
            ty: fty,
            class: Class::Low,
            width,
            constant: None,
            lvalue: false,
            loads,
            depth,
            address_of: None,
        })
    }

    /// The rounding operand as an `int` argument.
    fn rounding(&mut self, rounding: Value) -> Result<Value, PrintError> {
        let rounding = self.int_view(rounding)?;
        self.coerce(rounding, Class::Zero)
    }

    /// A float converted to an integer of `bits` bits as C converts one,
    /// in the reading view, which assumes the float in the integer's
    /// range (where L2's conversion and C's agree; out of it L2's gives
    /// 0 and C's is undefined, so the exact C calls `binbun_defs.h`): toward
    /// zero a cast, to nearest (the rounding the view assumes the
    /// environment has) `lrint` or `llrint`. `None` otherwise.
    fn in_range(
        &mut self,
        floats: &[Value],
        rounding: &Value,
        signed: bool,
        bits: u16,
        double: bool,
    ) -> Option<Value> {
        let [a] = floats else {
            return None;
        };
        if self.opaque != Opaque::Asm || !matches!(bits, 32 | 64) {
            return None;
        }
        let ty = CTy::Int { signed, bits };
        match rounding.constant?.low_u64() {
            3 => Some(self.cast(a.clone(), ty)),
            0 if signed => {
                let name = match (bits, double) {
                    (64, true) => "__builtin_llrint",
                    (64, false) => "__builtin_llrintf",
                    (_, true) => "__builtin_lrint",
                    (_, false) => "__builtin_lrintf",
                };
                let wide = CTy::Int {
                    signed: true,
                    bits: 64,
                };
                let rounded = self.helper(name, vec![a.clone()], wide, Class::Sign, 64);
                Some(if bits == 64 {
                    rounded
                } else {
                    self.cast(rounded, ty)
                })
            }
            _ => None,
        }
    }

    /// The outcomes `holds` of comparing floats `a` and `b` (bits: less,
    /// equal, greater, unordered; not none, not all) as C: the operator
    /// that holds for exactly those; for a set with unordered, the
    /// negation of the operator for the others (`!(a < b)`, and `a != b`,
    /// which C says holds for a NaN); C's quiet comparison macros for
    /// less-or-greater and unordered. In the exact view the four
    /// relational ones are C's quiet macros too (`isless`): C's operators
    /// are IEEE's signalling comparisons, which GCC compiles as such
    /// (`comisd`), so that a quiet NaN would set the invalid flag, and
    /// trap where the program unmasked it, at a comparison the program
    /// made quietly; what the program's own comparison raises is in its
    /// code around this.
    pub(super) fn float_relation(
        &mut self,
        a: Value,
        b: Value,
        format: Format,
        holds: u8,
    ) -> Result<Value, PrintError> {
        let (a, b) = (self.as_float(a, format)?, self.as_float(b, format)?);
        let unordered = holds & 8 != 0;
        let ordered = if unordered { !holds & 7 } else { holds & 7 };
        let int = CTy::Int {
            signed: true,
            bits: 32,
        };
        let (text, kind) = match (ordered, unordered) {
            (1 | 3 | 4 | 6, _) if self.opaque == Opaque::Calls => {
                let name = match ordered {
                    1 => "__builtin_isless",
                    3 => "__builtin_islessequal",
                    4 => "__builtin_isgreater",
                    _ => "__builtin_isgreaterequal",
                };
                let call = self.helper(name, vec![a, b], int, Class::Zero, 1);
                return Ok(if unordered {
                    self.prefix("!", call, (true, 32), Class::Zero)
                } else {
                    call
                });
            }
            (1, _) => ("<", Op::Relational),
            (3, _) => ("<=", Op::Relational),
            (4, _) => (">", Op::Relational),
            (6, _) => (">=", Op::Relational),
            (2, false) => ("==", Op::Equality),
            (2, true) => ("!=", Op::Equality),
            (5 | 7, _) => {
                let name = if ordered == 5 {
                    "__builtin_islessgreater"
                } else {
                    "__builtin_isunordered"
                };
                let call = self.helper(name, vec![a, b], int, Class::Zero, 1);
                // All three ordered outcomes: not unordered.
                let negate = unordered != (ordered == 7);
                return Ok(if negate {
                    self.prefix("!", call, (true, 32), Class::Zero)
                } else {
                    call
                });
            }
            _ => return Err(error(self.node, "a float relation of no outcome")),
        };
        let loads = a.loads || b.loads;
        let (doc, depth) = self.binary_doc(a, text, kind, b);
        let mut value = Self::built(doc, kind, (true, 32), Class::Zero, 1, &[], depth);
        value.loads = loads;
        Ok(if unordered && kind == Op::Relational {
            self.prefix("!", value, (true, 32), Class::Zero)
        } else {
            value
        })
    }

    /// A float whose sign bit a bitwise operation with a constant
    /// changes, as compilers negate one and take its magnitude (`xorps`,
    /// `andps` and `orps` with a mask): `x ^ sign` is `-x`, `x & ~sign`
    /// `fabs(x)`, `x | sign` `-fabs(x)`, each exactly (IEEE 754's negate
    /// and abs change the sign bit alone, a NaN's too). `None` for
    /// anything else.
    pub(super) fn float_sign(
        &mut self,
        op: Binary,
        a: &Value,
        b: &Value,
        width: u16,
    ) -> Option<Value> {
        let (x, mask) = match (a.constant, b.constant) {
            (None, Some(mask)) => (a, mask),
            (Some(mask), None) => (b, mask),
            (Some(_), Some(_)) | (None, None) => return None,
        };
        let CTy::Float(format) = x.ty else {
            return None;
        };
        if format.width() != width || mask.width() != width {
            return None;
        }
        let sign = Bits::from_u64(width, 1).shift_left(u32::from(width) - 1);
        let (negated, magnitude) = if op == Binary::Xor && mask == sign {
            (true, false)
        } else if op == Binary::And && mask == sign.invert() {
            (false, true)
        } else if op == Binary::Or && mask == sign {
            (true, true)
        } else {
            return None;
        };
        let mut value = x.clone();
        if magnitude {
            let name = if format == Format::Double {
                "__builtin_fabs"
            } else {
                "__builtin_fabsf"
            };
            value = self.helper(name, vec![value], CTy::Float(format), Class::Low, width);
        }
        if negated {
            let (depth, loads) = (value.depth, value.loads);
            let mut doc = vec![Doc::op("-", self.node)];
            let operand = self.operand(value, Op::Unary, false);
            self.append(&mut doc, operand);
            value = Value {
                doc,
                op: Op::Unary,
                ty: CTy::Float(format),
                class: Class::Low,
                width,
                constant: None,
                lvalue: false,
                loads,
                depth,
                address_of: None,
            };
        }
        Some(value)
    }

    /// `value` as a C float of `format`: a float as it is, an integer's
    /// bits through `as_f32` or `as_f64`, a constant number as its
    /// literal ([`float_literal`]).
    pub(super) fn as_float(&mut self, value: Value, format: Format) -> Result<Value, PrintError> {
        if value.ty == CTy::Float(format) {
            return Ok(value);
        }
        if let Some(text) = value.constant.and_then(|bits| float_literal(&bits, format)) {
            let negative = text.starts_with('-');
            return Ok(Value {
                doc: vec![Doc::number(text, self.node)],
                op: if negative { Op::Unary } else { Op::Postfix },
                ty: CTy::Float(format),
                class: Class::Low,
                width: value.width,
                constant: None,
                lvalue: false,
                loads: false,
                depth: 0,
                address_of: None,
            });
        }
        let value = self.int_view(value)?;
        let value = self.arg(value, false)?;
        let width = value.width;
        let name = if format == Format::Double {
            "as_f64"
        } else {
            "as_f32"
        };
        Ok(self.helper(name, vec![value], CTy::Float(format), Class::Low, width))
    }
}

fn take<const N: usize>(operands: Vec<Value>) -> Result<[Value; N], PrintError> {
    <[Value; N]>::try_from(operands).map_err(|_| error(None, "operand count"))
}

/// The C literal of the float of `format` whose bits are `bits`, if it
/// is a number: the shortest decimal that reads back as exactly those
/// bits (what Rust prints; a C compiler rounds a decimal literal
/// correctly), `f` after a `float`'s. Infinities and NaNs have no
/// literal.
fn float_literal(bits: &Bits, format: Format) -> Option<String> {
    match (format, bits.width()) {
        (Format::Double, 64) => {
            let value = f64::from_bits(bits.low_u64());
            value.is_finite().then(|| format!("{value:?}"))
        }
        (Format::Single, 32) => {
            let value = f32::from_bits(u32::try_from(bits.low_u64()).ok()?);
            value.is_finite().then(|| format!("{value:?}f"))
        }
        _ => None,
    }
}
