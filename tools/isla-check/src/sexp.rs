//! isla's terms as SMT-LIB 2 text: its expressions ([`Exp`]), sorts
//! ([`Ty`]), definitions ([`Def`]) and values ([`Val`]).
//!
//! isla's variables are printed `v<N>`; enumerations become 32-bit vectors
//! (member `i` is `i`), constrained to their range where declared, so a
//! script needs no datatypes. Floating-point terms are not supported (the
//! integer, load/store and branch instructions do not produce them).

use std::collections::HashMap;
use std::fmt::Write as _;

use isla_lib::bitvector::BV;
use isla_lib::bitvector::b64::B64;
use isla_lib::bitvector::b129::B129;
use isla_lib::ir::{BitsSegment, Name, Val};
use isla_lib::smt::smtlib::{Def, Exp, Ty};
use isla_lib::smt::{EnumMember, Sym};

/// The width enumerations are encoded in.
pub const ENUM_WIDTH: u32 = 32;

/// isla variable `sym`.
pub fn var(sym: Sym) -> String {
    format!("v{sym}")
}

/// A sort.
///
/// # Errors
///
/// For floating-point sorts.
pub fn sort(ty: &Ty) -> Result<String, String> {
    Ok(match ty {
        Ty::Bool => "Bool".into(),
        Ty::BitVec(width) => format!("(_ BitVec {width})"),
        Ty::Enum(_) => format!("(_ BitVec {ENUM_WIDTH})"),
        Ty::Array(index, element) => format!("(Array {} {})", sort(index)?, sort(element)?),
        Ty::Float(..) | Ty::RoundingMode => return Err("floating-point sort".into()),
    })
}

fn enum_member(member: EnumMember) -> String {
    format!("(_ bv{} {ENUM_WIDTH})", member.member)
}

/// A 64-bit-or-narrower literal.
fn bits64(bits: B64) -> Result<String, String> {
    if bits.len() == 0 {
        return Err("a zero-width bit vector".into());
    }
    Ok(format!("{bits}"))
}

/// A literal of `bits`, least significant first.
fn bit_list(bits: &[bool]) -> Result<String, String> {
    if bits.is_empty() {
        return Err("a zero-width bit vector".into());
    }
    let mut text = String::from("#b");
    for &bit in bits.iter().rev() {
        text.push(if bit { '1' } else { '0' });
    }
    Ok(text)
}

/// A literal of an isla bit vector.
///
/// # Errors
///
/// For zero-width vectors.
pub fn bits(bits: B129) -> Result<String, String> {
    bit_list(&bits.to_vec())
}

/// An expression.
///
/// # Errors
///
/// For floating-point expressions.
pub fn exp(exp: &Exp<Sym>) -> Result<String, String> {
    let mut out = String::new();
    write_exp(&mut out, exp)?;
    Ok(out)
}

fn apply(out: &mut String, function: &str, operands: &[&Exp<Sym>]) -> Result<(), String> {
    out.push('(');
    out.push_str(function);
    for operand in operands {
        out.push(' ');
        write_exp(out, operand)?;
    }
    out.push(')');
    Ok(())
}

fn indexed(out: &mut String, function: &str, operand: &Exp<Sym>) -> Result<(), String> {
    let _ = write!(out, "((_ {function}) ");
    write_exp(out, operand)?;
    out.push(')');
    Ok(())
}

fn write_exp(out: &mut String, exp: &Exp<Sym>) -> Result<(), String> {
    match exp {
        Exp::Var(sym) => out.push_str(&var(*sym)),
        Exp::Bits(list) => out.push_str(&bit_list(list)?),
        Exp::Bits64(value) => out.push_str(&bits64(*value)?),
        Exp::Enum(member) => out.push_str(&enum_member(*member)),
        Exp::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Exp::Eq(a, b) => apply(out, "=", &[a, b])?,
        Exp::Neq(a, b) => {
            out.push_str("(not ");
            apply(out, "=", &[a, b])?;
            out.push(')');
        }
        Exp::And(a, b) => apply(out, "and", &[a, b])?,
        Exp::Or(a, b) => apply(out, "or", &[a, b])?,
        Exp::Not(a) => apply(out, "not", &[a])?,
        Exp::Ite(c, a, b) => apply(out, "ite", &[c, a, b])?,
        Exp::Extract(high, low, a) => indexed(out, &format!("extract {high} {low}"), a)?,
        Exp::ZeroExtend(by, a) => indexed(out, &format!("zero_extend {by}"), a)?,
        Exp::SignExtend(by, a) => indexed(out, &format!("sign_extend {by}"), a)?,
        Exp::App(function, arguments) => {
            let operands: Vec<&Exp<Sym>> = arguments.iter().collect();
            apply(out, &var(*function), &operands)?;
        }
        Exp::Select(array, index) => apply(out, "select", &[array, index])?,
        Exp::Store(array, index, value) => apply(out, "store", &[array, index, value])?,
        Exp::Distinct(operands) => {
            let operands: Vec<&Exp<Sym>> = operands.iter().collect();
            apply(out, "distinct", &operands)?;
        }
        Exp::FPConstant(..)
        | Exp::FPRoundingMode(_)
        | Exp::FPUnary(..)
        | Exp::FPRoundingUnary(..)
        | Exp::FPBinary(..)
        | Exp::FPRoundingBinary(..)
        | Exp::FPfma(..) => return Err("floating-point expression".into()),
        Exp::Bvnot(_)
        | Exp::Bvneg(_)
        | Exp::Bvand(..)
        | Exp::Bvor(..)
        | Exp::Bvxor(..)
        | Exp::Bvnand(..)
        | Exp::Bvnor(..)
        | Exp::Bvxnor(..)
        | Exp::Bvadd(..)
        | Exp::Bvsub(..)
        | Exp::Bvmul(..)
        | Exp::Bvudiv(..)
        | Exp::Bvsdiv(..)
        | Exp::Bvurem(..)
        | Exp::Bvsrem(..)
        | Exp::Bvsmod(..)
        | Exp::Bvult(..)
        | Exp::Bvslt(..)
        | Exp::Bvule(..)
        | Exp::Bvsle(..)
        | Exp::Bvuge(..)
        | Exp::Bvsge(..)
        | Exp::Bvugt(..)
        | Exp::Bvsgt(..)
        | Exp::Bvshl(..)
        | Exp::Bvlshr(..)
        | Exp::Bvashr(..)
        | Exp::Concat(..) => bit_vector(out, exp)?,
    }
    Ok(())
}

/// The SMT-LIB bit-vector operations, which isla names alike.
fn bit_vector(out: &mut String, exp: &Exp<Sym>) -> Result<(), String> {
    let (name, operands): (&str, Vec<&Exp<Sym>>) = match exp {
        Exp::Bvnot(a) => ("bvnot", vec![a]),
        Exp::Bvneg(a) => ("bvneg", vec![a]),
        Exp::Bvand(a, b) => ("bvand", vec![a, b]),
        Exp::Bvor(a, b) => ("bvor", vec![a, b]),
        Exp::Bvxor(a, b) => ("bvxor", vec![a, b]),
        Exp::Bvnand(a, b) => ("bvnand", vec![a, b]),
        Exp::Bvnor(a, b) => ("bvnor", vec![a, b]),
        Exp::Bvxnor(a, b) => ("bvxnor", vec![a, b]),
        Exp::Bvadd(a, b) => ("bvadd", vec![a, b]),
        Exp::Bvsub(a, b) => ("bvsub", vec![a, b]),
        Exp::Bvmul(a, b) => ("bvmul", vec![a, b]),
        Exp::Bvudiv(a, b) => ("bvudiv", vec![a, b]),
        Exp::Bvsdiv(a, b) => ("bvsdiv", vec![a, b]),
        Exp::Bvurem(a, b) => ("bvurem", vec![a, b]),
        Exp::Bvsrem(a, b) => ("bvsrem", vec![a, b]),
        Exp::Bvsmod(a, b) => ("bvsmod", vec![a, b]),
        Exp::Bvult(a, b) => ("bvult", vec![a, b]),
        Exp::Bvslt(a, b) => ("bvslt", vec![a, b]),
        Exp::Bvule(a, b) => ("bvule", vec![a, b]),
        Exp::Bvsle(a, b) => ("bvsle", vec![a, b]),
        Exp::Bvuge(a, b) => ("bvuge", vec![a, b]),
        Exp::Bvsge(a, b) => ("bvsge", vec![a, b]),
        Exp::Bvugt(a, b) => ("bvugt", vec![a, b]),
        Exp::Bvsgt(a, b) => ("bvsgt", vec![a, b]),
        Exp::Bvshl(a, b) => ("bvshl", vec![a, b]),
        Exp::Bvlshr(a, b) => ("bvlshr", vec![a, b]),
        Exp::Bvashr(a, b) => ("bvashr", vec![a, b]),
        Exp::Concat(a, b) => ("concat", vec![a, b]),
        Exp::Var(_)
        | Exp::Bits(_)
        | Exp::Bits64(_)
        | Exp::Enum(_)
        | Exp::Bool(_)
        | Exp::Eq(..)
        | Exp::Neq(..)
        | Exp::And(..)
        | Exp::Or(..)
        | Exp::Not(_)
        | Exp::Extract(..)
        | Exp::ZeroExtend(..)
        | Exp::SignExtend(..)
        | Exp::Ite(..)
        | Exp::App(..)
        | Exp::Select(..)
        | Exp::Store(..)
        | Exp::Distinct(_)
        | Exp::FPConstant(..)
        | Exp::FPRoundingMode(_)
        | Exp::FPUnary(..)
        | Exp::FPRoundingUnary(..)
        | Exp::FPBinary(..)
        | Exp::FPRoundingBinary(..)
        | Exp::FPfma(..) => return Err("not a bit-vector operation".into()),
    };
    apply(out, name, &operands)
}

/// isla's types of its variables, as definitions declare them, for
/// [`Exp::infer`].
#[derive(Debug, Default)]
pub struct Types {
    variables: HashMap<Sym, Ty>,
    functions: HashMap<Sym, (Vec<Ty>, Ty)>,
    /// Sizes of the enumerations seen, by name.
    enums: HashMap<Name, usize>,
}

impl Types {
    /// The type of `sym`, if declared or defined.
    pub fn of(&self, sym: Sym) -> Option<&Ty> {
        self.variables.get(&sym)
    }

    /// The SMT-LIB commands for `def` (none for an enumeration, which has
    /// no SMT counterpart here), recording the types it introduces.
    ///
    /// # Errors
    ///
    /// For floating-point definitions, or a definition whose sort cannot
    /// be inferred.
    pub fn define(&mut self, def: &Def) -> Result<Vec<String>, String> {
        Ok(match def {
            Def::DeclareConst(sym, ty) => {
                self.variables.insert(*sym, ty.clone());
                let mut commands = vec![format!("(declare-const {} {})", var(*sym), sort(ty)?)];
                if let Ty::Enum(id) = ty
                    && let Some(size) = self.enums.get(&id.to_name())
                {
                    commands.push(format!(
                        "(assert (bvult {} (_ bv{size} {ENUM_WIDTH})))",
                        var(*sym)
                    ));
                }
                commands
            }
            Def::DeclareFun(sym, arguments, result) => {
                self.functions
                    .insert(*sym, (arguments.clone(), result.clone()));
                let arguments = arguments.iter().map(sort).collect::<Result<Vec<_>, _>>()?;
                vec![format!(
                    "(declare-fun {} ({}) {})",
                    var(*sym),
                    arguments.join(" "),
                    sort(result)?
                )]
            }
            Def::DefineConst(sym, value) => {
                let ty = value
                    .infer(&self.variables, &self.functions)
                    .ok_or_else(|| format!("cannot infer the sort of {}", var(*sym)))?;
                let command = format!(
                    "(define-fun {} () {} {})",
                    var(*sym),
                    sort(&ty)?,
                    exp(value)?
                );
                self.variables.insert(*sym, ty);
                vec![command]
            }
            Def::DefineEnum(name, size) => {
                self.enums.insert(*name, *size);
                Vec::new()
            }
            Def::Assert(condition) => vec![format!("(assert {})", exp(condition)?)],
        })
    }
}

/// A bit vector or Boolean value.
///
/// # Errors
///
/// For values that are neither (structures, vectors, strings, …).
pub fn val(value: &Val<B129>) -> Result<String, String> {
    Ok(match value {
        Val::Symbolic(sym) => var(*sym),
        Val::Bits(value) => bits(*value)?,
        Val::I64(value) => format!("(_ bv{} 64)", value.cast_unsigned()),
        Val::I128(value) => format!("(_ bv{} 128)", value.cast_unsigned()),
        Val::Bool(value) => (if *value { "true" } else { "false" }).into(),
        Val::Enum(member) => enum_member(*member),
        Val::MixedBits(segments) => {
            let parts = segments
                .iter()
                .map(|segment| match segment {
                    BitsSegment::Symbolic(sym) => Ok(var(*sym)),
                    BitsSegment::Concrete(value) => bits(*value),
                })
                .collect::<Result<Vec<_>, String>>()?;
            if parts.len() == 1 {
                parts.concat()
            } else {
                format!("(concat {})", parts.join(" "))
            }
        }
        Val::String(_)
        | Val::Unit
        | Val::Vector(_)
        | Val::List(_)
        | Val::Struct(_)
        | Val::Ctor(..)
        | Val::SymbolicCtor(..)
        | Val::Ref(_)
        | Val::Poison => return Err("not a bit vector or Boolean".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_are_most_significant_first() {
        assert_eq!(bits(B129::new(0b1101, 5)).unwrap(), "#b01101");
        assert_eq!(bits(B129::new(0x81, 8)).unwrap(), "#b10000001");
        assert_eq!(bit_list(&[true, false, false]).unwrap(), "#b001");
        assert!(bit_list(&[]).is_err());
    }
}
