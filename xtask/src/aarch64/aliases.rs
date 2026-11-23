//! Alias selection: an encoding's aliases, their `condition` and
//! `preferred` expressions compiled to Rust, and the order they are tried
//! in.
//!
//! An alias is written when its condition and its preferred expression both
//! hold. AARCHMRS gives no order among an encoding's aliases and some
//! overlap; [`ORDER`] gives the order where it matters, as LLVM resolves it
//! (otherwise AARCHMRS order). Helper functions the expressions call
//! (`MoveWidePreferred`, `BFXPreferred`, …) are plain Rust in the decoder
//! crate's `pseudocode` module, named in snake case; enumeration constants
//! they compare with (`Sys_DC`) are its constants in upper case (`SYS_DC`).
//! [`ADDED`] holds the conditions LLVM adds to an alias.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use xtask::aarchmrs::{Alias, BinaryOp, Encodeset, Expr};

use super::cond;
use super::symbols::extract;
use crate::Result;
use crate::codegen::lit;

/// Aliases tried before the others of their encoding, by name, first
/// first.
const ORDER: &[(&str, &[&str])] = &[
    // LSL (imms + 1 == immr) is a special case of UBFIZ (imms < immr).
    ("UBFM_32M_bitfield", &["LSL"]),
    ("UBFM_64M_bitfield", &["LSL"]),
];

/// Aliases LLVM 22 never writes, though AARCHMRS prefers them; binbun
/// writes the encoding (or another alias) as LLVM does.
const UNUSED: &[(&str, &str)] = &[
    // LLVM writes `bfi w0, wzr, #lsb, #width`.
    ("BFM_32M_bitfield", "BFC"),
    ("BFM_64M_bitfield", "BFC"),
    // LLVM writes `subps xzr, xn, xm`.
    ("SUBPS_64S_dp_2src", "CMPP"),
    // LLVM writes `sshll v0.8h, v1.8b, #0`, `ushll v0.8h, v1.8b, #0`.
    ("SSHLL_asimdshf_L", "SXTL"),
    ("USHLL_asimdshf_L", "UXTL"),
];

/// Aliases LLVM writes beyond their AARCHMRS condition: only `preferred`
/// is tested.
const UNCONDITIONAL: &[(&str, &str)] = &[
    // `BFI` with `Rn == '11111'` (where Arm writes `BFC`).
    ("BFM_32M_bitfield", "BFI"),
    ("BFM_64M_bitfield", "BFI"),
];

/// Whether the alias's condition is ignored ([`UNCONDITIONAL`]).
pub fn unconditional(encoding: &str, alias: &str) -> bool {
    UNCONDITIONAL.contains(&(encoding, alias))
}

/// The fields `sys_register_allowed` reads.
const SYS_FIELDS: &[&str] = &["op1", "CRn", "CRm", "op2", "Rt"];

/// Conditions LLVM adds to an alias: `(encoding, alias, helper, fields)`;
/// the alias is written only if the `pseudocode` helper, given the fields'
/// values, also returns true.
const ADDED: &[(&str, &str, &str, &[&str])] = &[
    // AArch64InstPrinter::printSysAlias: LLVM writes SYS when an operation
    // takes no register (neither `NeedsReg` nor `OptionalReg`) and Rt is
    // not 31.
    (
        "SYS_CR_systeminstrs",
        "BRB",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    (
        "SYS_CR_systeminstrs",
        "GCSPOPCX",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    (
        "SYS_CR_systeminstrs",
        "GCSPOPX",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    (
        "SYS_CR_systeminstrs",
        "GCSPUSHX",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    (
        "SYS_CR_systeminstrs",
        "GIC",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    (
        "SYS_CR_systeminstrs",
        "GSB",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    (
        "SYS_CR_systeminstrs",
        "IC",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    (
        "SYS_CR_systeminstrs",
        "PLBI",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    (
        "SYS_CR_systeminstrs",
        "TLBI",
        "sys_register_allowed",
        SYS_FIELDS,
    ),
    // LLVM's SVCR fields (`SVCRSM`, `SVCRZA`, `SVCRSMZA`) need
    // `CRm<2:1> != 00`; otherwise it writes `msr S0_3_C4_C<m>_3, xzr`.
    ("MSR_SI_pstate", "SMSTART", "svcr_field", &["CRm"]),
    ("MSR_SI_pstate", "SMSTOP", "svcr_field", &["CRm"]),
];

/// The condition LLVM adds to the alias ([`ADDED`]); `true` if none.
pub fn added(encoding: &str, alias: &str, set: &Encodeset) -> Result<TokenStream> {
    let Some((_, _, helper, fields)) = ADDED
        .iter()
        .find(|(name, other, _, _)| *name == encoding && *other == alias)
    else {
        return Ok(quote! { true });
    };
    let arguments = fields
        .iter()
        .map(|field| {
            let (start, width) =
                cond::field(set, field).ok_or_else(|| format!("unknown field {field}"))?;
            Ok(extract(start, width))
        })
        .collect::<Result<Vec<_>>>()?;
    let helper = format_ident!("{helper}");
    Ok(quote! { pseudocode::#helper(#(#arguments),*) })
}

/// The aliases of an encoding in the order they are tried, without those in
/// [`UNUSED`].
pub fn ordered<'a>(encoding: &str, aliases: &'a [Alias]) -> Vec<&'a Alias> {
    let first: &[&str] = ORDER
        .iter()
        .find(|(name, _)| *name == encoding)
        .map_or(&[], |(_, first)| first);
    let mut out: Vec<&Alias> = first
        .iter()
        .filter_map(|name| aliases.iter().find(|alias| alias.name == *name))
        .collect();
    out.extend(
        aliases
            .iter()
            .filter(|alias| !first.contains(&alias.name.as_str())),
    );
    out.retain(|alias| !UNUSED.contains(&(encoding, alias.name.as_str())));
    out
}

/// A compiled value: its expression and, for bit strings, the width.
struct Value {
    tokens: TokenStream,
    width: Option<u32>,
}

/// Compiles `expr` (over the encoding's fields) to a `bool` expression.
pub fn condition(expr: &Expr, encoding: &Encodeset) -> Result<TokenStream> {
    let value = compile(expr, encoding)?;
    if value.width.is_some() {
        return Err(format!("`{expr}` is not a condition").into());
    }
    Ok(value.tokens)
}

fn compile(expr: &Expr, encoding: &Encodeset) -> Result<Value> {
    let bits = |tokens, width| Value {
        tokens,
        width: Some(width),
    };
    let boolean = |tokens| Value {
        tokens,
        width: None,
    };
    Ok(match expr {
        Expr::Bool(true) => boolean(quote! { true }),
        Expr::Bool(false) => boolean(quote! { false }),
        Expr::Integer(value) => {
            let value = lit(u64::try_from(*value)?);
            Value {
                tokens: quote! { #value },
                width: None,
            }
        }
        Expr::Identifier(name) => {
            if let Some((start, width)) = cond::field(encoding, name) {
                bits(extract(start, width), width)
            } else {
                // Not a field: an enumeration constant of the pseudocode
                // (`Sys_DC`), a constant of the `pseudocode` module
                // (`SYS_DC`).
                let constant = format_ident!("{}", name.to_ascii_uppercase());
                Value {
                    tokens: quote! { pseudocode::#constant },
                    width: None,
                }
            }
        }
        Expr::Bits(pattern) => {
            if pattern.mask().count_ones() != pattern.width() {
                return Err(format!("{pattern} as a value").into());
            }
            let value = lit(pattern.value());
            bits(quote! { #value }, pattern.width())
        }
        Expr::Not(operand) => boolean(negate(operand, encoding)?),
        Expr::Binary { op, left, right } => binary(*op, left, right, encoding)?,
        Expr::Index { base, arguments } => {
            let base = compile(base, encoding)?;
            let [Expr::Integer(bit)] = arguments.as_slice() else {
                return Err(format!("`{expr}`: only single-bit indices").into());
            };
            let bit = lit(u64::try_from(*bit)?);
            let tokens = base.tokens;
            bits(quote! { ((#tokens >> #bit) & 1) }, 1)
        }
        Expr::Call { name, arguments } => call(expr, name, arguments, encoding)?,
        Expr::Set(_) | Expr::Dot(_) | Expr::Field { .. } | Expr::String(_) => {
            return Err(format!("`{expr}` in an alias condition").into());
        }
    })
}

fn binary(op: BinaryOp, left: &Expr, right: &Expr, encoding: &Encodeset) -> Result<Value> {
    let boolean = |tokens| Value {
        tokens,
        width: None,
    };
    Ok(match op {
        BinaryOp::And | BinaryOp::Or => {
            let (left, right) = (condition(left, encoding)?, condition(right, encoding)?);
            boolean(if op == BinaryOp::And {
                and(&left, &right)
            } else {
                or(&left, &right)
            })
        }
        BinaryOp::Eq | BinaryOp::Ne => boolean(equal(left, right, encoding, op == BinaryOp::Ne)?),
        BinaryOp::In => {
            let Expr::Set(items) = right else {
                return Err("IN without a set".into());
            };
            let tests = items
                .iter()
                .map(|item| equal(left, item, encoding, false))
                .collect::<Result<Vec<_>>>()?;
            boolean(quote! { (#(#tests)||*) })
        }
        BinaryOp::Lt => {
            let (left, right) = (
                compile(left, encoding)?.tokens,
                compile(right, encoding)?.tokens,
            );
            boolean(quote! { (#left < #right) })
        }
        BinaryOp::Gt => {
            let (left, right) = (
                compile(left, encoding)?.tokens,
                compile(right, encoding)?.tokens,
            );
            boolean(quote! { (#left > #right) })
        }
        BinaryOp::Ge => {
            let (left, right) = (
                compile(left, encoding)?.tokens,
                compile(right, encoding)?.tokens,
            );
            boolean(quote! { (#left >= #right) })
        }
        BinaryOp::Add => {
            let left = compile(left, encoding)?.tokens;
            let right = compile(right, encoding)?.tokens;
            Value {
                tokens: quote! { (#left + #right) },
                width: None,
            }
        }
        BinaryOp::Concat => {
            let left = compile(left, encoding)?;
            let right = compile(right, encoding)?;
            let width = right.width.ok_or("concatenation of a number")?;
            let total = left.width.ok_or("concatenation of a number")? + width;
            let (left, right, width) = (left.tokens, right.tokens, lit(width));
            Value {
                tokens: quote! { ((#left << #width) | #right) },
                width: Some(total),
            }
        }
        BinaryOp::Implies | BinaryOp::Iff => {
            return Err(format!("`{}` in an alias condition", op.symbol()).into());
        }
    })
}

/// `left == right` (`!=` when `negated`), a pattern on either side matching
/// with its `x` bits free.
fn equal(left: &Expr, right: &Expr, encoding: &Encodeset, negated: bool) -> Result<TokenStream> {
    let operator = if negated {
        quote! { != }
    } else {
        quote! { == }
    };
    let ((other, Expr::Bits(pattern)) | (Expr::Bits(pattern), other)) = (left, right) else {
        let left = compile(left, encoding)?.tokens;
        let right = compile(right, encoding)?.tokens;
        return Ok(quote! { (#left #operator #right) });
    };
    let value = compile(other, encoding)?;
    let tokens = value.tokens;
    let bits = lit(pattern.value());
    // A pattern without `x` bits over the whole value needs no mask.
    if value.width == Some(pattern.width()) && pattern.mask().count_ones() == pattern.width() {
        return Ok(quote! { (#tokens #operator #bits) });
    }
    let mask = lit(pattern.mask());
    Ok(quote! { ((#tokens & #mask) #operator #bits) })
}

/// `!expr`, with the negation pushed into comparisons and connectives so
/// no `!(a == b)` is written.
fn negate(expr: &Expr, encoding: &Encodeset) -> Result<TokenStream> {
    Ok(match expr {
        Expr::Not(operand) => condition(operand, encoding)?,
        Expr::Binary {
            op: op @ (BinaryOp::Eq | BinaryOp::Ne),
            left,
            right,
        } => equal(left, right, encoding, *op == BinaryOp::Eq)?,
        Expr::Binary {
            op: op @ (BinaryOp::And | BinaryOp::Or),
            left,
            right,
        } => {
            let (left, right) = (negate(left, encoding)?, negate(right, encoding)?);
            if *op == BinaryOp::And {
                or(&left, &right)
            } else {
                and(&left, &right)
            }
        }
        Expr::Binary {
            op: BinaryOp::In,
            left,
            right,
        } => {
            let Expr::Set(items) = right.as_ref() else {
                return Err("IN without a set".into());
            };
            let tests = items
                .iter()
                .map(|item| equal(left, item, encoding, true))
                .collect::<Result<Vec<_>>>()?;
            quote! { (#(#tests)&&*) }
        }
        Expr::Call { name, arguments } if name == "IsZero" || name == "IsOnes" => {
            let [argument] = arguments.as_slice() else {
                return Err(format!("`{expr}`: one argument expected").into());
            };
            let value = compile(argument, encoding)?;
            let width = value.width.ok_or_else(|| format!("`{expr}` of a number"))?;
            let tokens = value.tokens;
            let target = lit(if name == "IsZero" {
                0
            } else {
                (1u64 << width) - 1
            });
            quote! { (#tokens != #target) }
        }
        Expr::Bool(_)
        | Expr::Integer(_)
        | Expr::Identifier(_)
        | Expr::Bits(_)
        | Expr::Set(_)
        | Expr::Binary { .. }
        | Expr::Call { .. }
        | Expr::Index { .. }
        | Expr::Dot(_)
        | Expr::Field { .. }
        | Expr::String(_) => {
            let operand = condition(expr, encoding)?;
            match operand.to_string().as_str() {
                "true" => quote! { false },
                "false" => quote! { true },
                _ => quote! { !#operand },
            }
        }
    })
}

/// `left && right`, folding constant `true`/`false`.
pub fn and(left: &TokenStream, right: &TokenStream) -> TokenStream {
    match (left.to_string().as_str(), right.to_string().as_str()) {
        ("true", _) => right.clone(),
        (_, "true") => left.clone(),
        ("false", _) | (_, "false") => quote! { false },
        _ => quote! { (#left && #right) },
    }
}

/// `left || right`, folding constant `true`/`false`.
fn or(left: &TokenStream, right: &TokenStream) -> TokenStream {
    match (left.to_string().as_str(), right.to_string().as_str()) {
        ("false", _) => right.clone(),
        (_, "false") => left.clone(),
        ("true", _) | (_, "true") => quote! { true },
        _ => quote! { (#left || #right) },
    }
}

fn call(expr: &Expr, name: &str, arguments: &[Expr], encoding: &Encodeset) -> Result<Value> {
    if expr.feature_check().is_some() {
        return Ok(Value {
            tokens: quote! { true },
            width: None,
        });
    }
    let compiled = arguments
        .iter()
        .map(|argument| compile(argument, encoding))
        .collect::<Result<Vec<_>>>()?;
    let width = |i: usize| -> Result<u32> {
        compiled
            .get(i)
            .and_then(|value| value.width)
            .ok_or_else(|| format!("`{expr}`: argument {i} is not a bit string").into())
    };
    let tokens: Vec<&TokenStream> = compiled.iter().map(|value| &value.tokens).collect();
    let number = |tokens| Value {
        tokens,
        width: None,
    };
    Ok(match (name, tokens.as_slice()) {
        ("UInt", [value]) => number(quote! { #value }),
        ("IsZero", [value]) => Value {
            tokens: quote! { (#value == 0) },
            width: None,
        },
        ("IsOnes", [value]) => {
            let ones = lit((1u64 << width(0)?) - 1);
            Value {
                tokens: quote! { (#value == #ones) },
                width: None,
            }
        }
        ("BitCount", [value]) => number(quote! { (#value).count_ones() }),
        _ => {
            let function = format_ident!("{}", snake_case(name));
            Value {
                tokens: quote! { pseudocode::#function(#(#tokens),*) },
                width: None,
            }
        }
    })
}

/// `MoveWidePreferred` → `move_wide_preferred`, `SysOp128` → `sys_op128`.
fn snake_case(name: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let next_lower = chars.get(i + 1).is_some_and(char::is_ascii_lowercase);
        let previous_lower = i > 0 && chars.get(i - 1).is_some_and(char::is_ascii_lowercase);
        if c.is_ascii_uppercase() && i > 0 && (previous_lower || next_lower) {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::snake_case;

    #[test]
    fn helper_names_are_snake_case() {
        assert_eq!(snake_case("MoveWidePreferred"), "move_wide_preferred");
        assert_eq!(snake_case("BFXPreferred"), "bfx_preferred");
        assert_eq!(
            snake_case("SVEMoveMaskPreferred"),
            "sve_move_mask_preferred"
        );
        assert_eq!(snake_case("SysOp128"), "sys_op128");
    }
}
