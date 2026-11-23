//! Symbols of the SVE groups (`sve`): immediates, predicate patterns,
//! prefetch operations and the other operands only SVE writes. Registers,
//! lists and memory operands are in [`super::vector`].

use proc_macro2::TokenStream;
use quote::quote;

use super::vector::{any, concat, element_index, fields, shift_element, size_fields};
use super::{Slot, Symbol, decimal, named, push, sign_extend, signed, unsigned};
use crate::Result;
use crate::codegen::lit;

/// Encodings shifting left by a `tsz:imm3` amount (the amount is
/// `tsz:imm3 - esize`); the others shift right (`2 * esize - tsz:imm3`).
const LEFT_SHIFTS: &[&str] = &[
    "lsl_", "sqshl_", "sqshlu_", "uqshl_", "sli_", "sshll", "ushll",
];

/// `#<const>` of shifts by `tsz:imm3` (`tsize:imm3`), in hex: the amount
/// relative to the element size `tsz` gives by its highest set bit.
fn shift_amount(s: &Slot<'_>) -> Result<TokenStream> {
    let tsz = concat(s, &size_fields(s))?;
    let element = shift_element(&tsz);
    let (value, _) = s.value()?;
    let encoding = s.instruction.name.as_str();
    let amount = if LEFT_SHIFTS
        .iter()
        .any(|prefix| encoding.starts_with(prefix))
    {
        quote! { (#value) - (8u32 << #element) }
    } else {
        quote! { (16u32 << #element) - (#value) }
    };
    Ok(push(&unsigned(&amount)))
}

/// `#<const>` of the logical immediates (`imm13`): the bitmask at the
/// element size it repeats in, in hex, as LLVM writes it.
fn logical_immediate(s: &Slot<'_>) -> Result<TokenStream> {
    let imm13 = s.field("imm13")?;
    let element = element_index(s, "<T>")?;
    Ok(push(&unsigned(&quote! {{
        let imm13 = #imm13;
        let value = pseudocode::decode_bit_masks(imm13 >> 12, imm13 & 0x3f, (imm13 >> 6) & 0x3f, 1);
        let bits = 8u32 << #element;
        if bits == 64 { value } else { value & ((1u64 << bits) - 1) }
    }})))
}

/// `#<const>` of `FMOV`/`FDUP`/`FCPY` (`imm8`): `VFPExpandImm`, written
/// with eight decimals.
fn float_immediate(s: &Slot<'_>) -> Result<TokenStream> {
    let (imm8, _) = s.value()?;
    Ok(push(&quote! {
        Operand::Float(Float { value: pseudocode::vfp_expand_imm(#imm8), exact: false })
    }))
}

/// `<const>` of the floating-point operations with an immediate (`i1`):
/// one of two constants by mnemonic (0.5 or 1.0 for `FADD`, `FSUB`,
/// `FSUBR`; 0.0 or 1.0 for `FMAX`, `FMIN` and their `NM` forms; 0.5 or 2.0
/// for `FMUL`), written shortest.
fn float_constant(s: &Slot<'_>) -> Result<TokenStream> {
    let i1 = s.field("i1")?;
    let encoding = s.instruction.name.as_str();
    let (zero, one) = if encoding.starts_with("fmul") {
        (0.5f64, 2.0f64)
    } else if encoding.starts_with("fmax") || encoding.starts_with("fmin") {
        (0.0, 1.0)
    } else {
        (0.5, 1.0)
    };
    Ok(push(&quote! {
        Operand::Float(Float { value: if #i1 == 1 { #one } else { #zero }, exact: true })
    }))
}

/// `#0.0` of the floating-point comparisons with zero.
#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn float_zero(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(
        &quote! { Operand::Float(Float { value: 0.0, exact: true }) },
    ))
}

/// `<const>` of complex rotations (`rot`), in decimal: 90 or 270 for one
/// bit (`CADD`), multiples of 90 for two.
fn rotation(s: &Slot<'_>) -> Result<TokenStream> {
    let (rot, width) = s.value()?;
    let degrees = if width == 1 {
        quote! { 90 + 180 * (#rot) }
    } else {
        quote! { 90 * (#rot) }
    };
    Ok(push(&decimal(&degrees)))
}

/// Whether the encoding's 8-bit immediate is signed: `DUP`, `CPY` and
/// `SMAX`, `SMIN`, `MUL`.
fn signed_imm8(s: &Slot<'_>) -> bool {
    ["dup_", "cpy_", "smax_", "smin_", "mul_"]
        .iter()
        .any(|prefix| s.instruction.name.starts_with(prefix))
}

/// `#<imm>` (`imm8`) with its optional `, <shift>` (`sh`) of `DUP`, `CPY`,
/// `ADD` and the like: LLVM writes the shifted value (sign-extended for
/// `DUP`/`CPY`) as unsigned hex at the element size, but zero shifted as
/// `#0x0, lsl #8`; without a shift, `SMAX`/`SMIN`/`MUL` take a signed
/// immediate, the others an unsigned one.
fn imm8(s: &Slot<'_>) -> Result<TokenStream> {
    let value = s.field("imm8")?;
    let signed_value = sign_extend(&value, 8);
    if s.width("sh").is_err() {
        return Ok(push(&if signed_imm8(s) {
            signed(&signed_value)
        } else {
            unsigned(&value)
        }));
    }
    let (sh, size) = (s.field("sh")?, s.field("size")?);
    let extended = if signed_imm8(s) {
        quote! { (#signed_value).cast_unsigned() }
    } else {
        quote! { u64::from(#value) }
    };
    Ok(push(&unsigned(&quote! {{
        let value = (#extended) << (8 * #sh);
        let bits = 8u32 << #size;
        if bits == 64 { value } else { value & ((1u64 << bits) - 1) }
    }})))
}

/// `{, <shift>}` (`sh`) after an 8-bit immediate: `lsl #8` only for a
/// zero immediate ([`imm8`] writes the others shifted).
fn imm8_shift(s: &Slot<'_>) -> Result<TokenStream> {
    let (sh, value) = (s.field("sh")?, s.field("imm8")?);
    let code = push(&quote! { Operand::Shift(Shift { kind: ShiftKind::Lsl, amount: 8 }) });
    Ok(quote! { if #sh == 1 && #value == 0 { #code } })
}

/// The slot's fields as a signed hex immediate.
fn signed_hex(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, width) = s.value()?;
    Ok(push(&signed(&sign_extend(&value, width))))
}

/// Predicate pattern names by value; other values are written as numbers.
const PATTERNS: &[(u32, &str)] = &[
    (0, "pow2"),
    (1, "vl1"),
    (2, "vl2"),
    (3, "vl3"),
    (4, "vl4"),
    (5, "vl5"),
    (6, "vl6"),
    (7, "vl7"),
    (8, "vl8"),
    (9, "vl16"),
    (10, "vl32"),
    (11, "vl64"),
    (12, "vl128"),
    (13, "vl256"),
    (29, "mul4"),
    (30, "mul3"),
    (31, "all"),
];

/// The operand of a predicate pattern value.
fn pattern_operand(value: &TokenStream) -> TokenStream {
    let arms = PATTERNS.iter().map(|(number, name)| {
        let (number, operand) = (lit(*number), named("Pattern", name));
        quote! { #number => #operand, }
    });
    let other = unsigned(&quote! { other });
    quote! {
        match #value {
            #(#arms)*
            other => #other,
        }
    }
}

/// `{, <pattern>}` of `PTRUE`: left out for `all`.
fn optional_pattern(s: &Slot<'_>) -> Result<TokenStream> {
    let pattern = s.field("pattern")?;
    let operand = pattern_operand(&quote! { pattern });
    Ok(quote! {{
        let pattern = #pattern;
        if pattern != 31 {
            ops.push(#operand);
        }
    }})
}

/// `{, <pattern>{, MUL #<imm>}}` of the element counts: the multiplier is
/// `imm4 + 1`, left out when 1, and the pattern too when it is `all` with
/// no multiplier.
fn pattern_multiplier(s: &Slot<'_>) -> Result<TokenStream> {
    let (pattern, imm4) = (s.field("pattern")?, s.field("imm4")?);
    let operand = pattern_operand(&quote! { pattern });
    Ok(quote! {{
        let pattern = #pattern;
        let multiplier = #imm4 + 1;
        if pattern != 31 || multiplier != 1 {
            ops.push(#operand);
            if multiplier != 1 {
                ops.push(Operand::Shift(Shift { kind: ShiftKind::Mul, amount: multiplier as u8 }));
            }
        }
    }})
}

/// `<prfop>` of the SVE prefetches: `pld`/`pst` by bit 3, the level and
/// the policy; values 6, 7, 14 and 15 in hex.
fn prefetch(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let names = [
        (0u32, "pldl1keep"),
        (1, "pldl1strm"),
        (2, "pldl2keep"),
        (3, "pldl2strm"),
        (4, "pldl3keep"),
        (5, "pldl3strm"),
        (8, "pstl1keep"),
        (9, "pstl1strm"),
        (10, "pstl2keep"),
        (11, "pstl2strm"),
        (12, "pstl3keep"),
        (13, "pstl3strm"),
    ];
    let arms = names.iter().map(|(number, name)| {
        let (number, operand) = (lit(*number), named("Prefetch", name));
        quote! { #number => #operand, }
    });
    let other = unsigned(&quote! { other });
    Ok(push(&quote! {
        match #value {
            #(#arms)*
            other => #other,
        }
    }))
}

/// `<vl>` of the predicate-as-counter operations: `vlx2` or `vlx4`.
fn vector_group(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let (two, four) = (named("Keyword", "vlx2"), named("Keyword", "vlx4"));
    Ok(push(&quote! { if #value == 1 { #four } else { #two } }))
}

pub const SYMBOLS: &[Symbol] = &[
    // Immediates.
    fields("#<const>", &["tszh", "tszl", "imm3"], shift_amount),
    fields("#<const>", &["tsize", "imm3"], shift_amount),
    fields("#<const>", &["imm13"], logical_immediate),
    fields("#<const>", &["imm8"], float_immediate),
    fields("<const>", &["i1"], float_constant),
    fields("<const>", &["rot"], rotation),
    any("#0.0", float_zero),
    fields("#<imm>", &["imm8"], imm8),
    fields("{, <shift>}", &["sh"], imm8_shift),
    fields("#<imm>", &["imm5"], signed_hex),
    fields("#<imm>", &["imm6"], signed_hex),
    fields("#<imm1>", &["imm5"], signed_hex),
    fields("#<imm2>", &["imm5b"], signed_hex),
    // Patterns, prefetch operations, vector groups.
    any("{, <pattern>}", optional_pattern),
    any("{, <pattern>{, MUL #<imm>}}", pattern_multiplier),
    any("<prfop>", prefetch),
    any("<vl>", vector_group),
];
