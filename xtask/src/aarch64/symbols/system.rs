//! Symbols of the system instruction groups: `control/systeminstrs`,
//! `control/systeminstrswithreg`, `control/systemmove`,
//! `control/systemmovepr`, `control/syspairinstrs`, `control/pstate`.
//!
//! System register and operation names come from the decoder's generated
//! `sysreg` tables (`xtask/src/aarch64/sysreg.rs`), which hold LLVM's names.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::{Build, Slot, Symbol, named, push, register, unsigned};
use crate::Result;

/// A symbol matching any fields and forms.
const fn any(key: &'static str, build: fn(&Slot<'_>) -> Result<TokenStream>) -> Symbol {
    Symbol {
        key,
        fields: &[],
        forms: &[],
        build: Build::Operands(build),
    }
}

/// A symbol limited to `forms`.
const fn forms(
    key: &'static str,
    forms: &'static [&'static str],
    build: fn(&Slot<'_>) -> Result<TokenStream>,
) -> Symbol {
    Symbol {
        key,
        fields: &[],
        forms,
        build: Build::Operands(build),
    }
}

/// `op1, CRn, CRm, op2` of the encoding, as call arguments.
fn operation_fields(s: &Slot<'_>) -> Result<TokenStream> {
    let (op1, crn, crm, op2) = (
        s.field("op1")?,
        s.field("CRn")?,
        s.field("CRm")?,
        s.field("op2")?,
    );
    Ok(quote! { #op1, #crn, #crm, #op2 })
}

/// The `sysreg` lookup of the form's instruction: `sys`, `sysl` or `sysp`.
fn operation_lookup(s: &Slot<'_>) -> Result<TokenStream> {
    let table = if s.instruction.name.starts_with("SYSL") {
        "sysl"
    } else if s.instruction.name.starts_with("SYSP") {
        "sysp"
    } else {
        "sys"
    };
    let table = format_ident!("{table}");
    let fields = operation_fields(s)?;
    Ok(quote! { sysreg::#table(#fields) })
}

/// `<dc_op>`, `<tlbi_op>`, `<gicr_op>`, …: the operation's name, lower case
/// as LLVM writes it, from the `sysreg` tables (which hold LLVM's names).
fn operation(s: &Slot<'_>) -> Result<TokenStream> {
    let lookup = operation_lookup(s)?;
    let operand = quote! {
        Operand::Named(Named { kind: NameKind::SystemOperation, name: operation.name })
    };
    Ok(quote! {
        if let Some(operation) = #lookup {
            ops.push(#operand);
        }
    })
}

/// `RCTX` of `CFP`, `DVP`, `COSP`, `CPP`: LLVM writes `rctx`.
#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn rctx(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&named("SystemOperation", "rctx")))
}

/// `#<op1>`, `#<op2>`: hex.
fn hex(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(&unsigned(&value)))
}

/// `<Cn>`, `<Cm>`: `c0`…`c15`.
fn control(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    Ok(push(&register("C", &number)))
}

/// `{, <Xt>}` of `SYS`, `{<Xt>}` of `GCSPOPM`: left out for `xzr`.
fn optional_xt(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    let code = push(&register("X", &number));
    Ok(quote! { if #number != 31 { #code } })
}

/// `{, <Xt>}` of `TLBI`, `IC`, `GIC`, `PLBI`: LLVM writes the register,
/// `xzr` included, when the operation always takes one (its `NeedsReg`),
/// and otherwise leaves out `xzr`.
fn operation_xt(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    let lookup = operation_lookup(s)?;
    let code = push(&register("X", &number));
    Ok(quote! {
        if #number != 31
            || #lookup.is_some_and(|operation| operation.register == sysreg::Register::Always)
        {
            #code
        }
    })
}

/// A register pair `<Xt>, <Xt+1>`; LLVM writes `x30, xzr` and, for 31,
/// `xzr, xzr`.
fn pair(number: &TokenStream) -> TokenStream {
    let first = push(&register("X", number));
    let second = push(&register(
        "X",
        &quote! { if #number == 31 { 31 } else { #number + 1 } },
    ));
    quote! { #first #second }
}

/// `{, <Xt1>, <Xt2>}` of `SYSP`: left out for Rt 31.
fn sysp_pair(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    let code = pair(&number);
    Ok(quote! { if #number != 31 { #code } })
}

/// `{, <Xt1>, <Xt2>}` of `TLBIP`: LLVM always writes the pair, `xzr, xzr`
/// for Rt 31.
fn tlbip_pair(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    Ok(pair(&number))
}

/// `<Xt+1>` of `MRRS`, `MSRR`.
fn next_xt(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    Ok(push(&register(
        "X",
        &quote! { if #number == 31 { 31 } else { #number + 1 } },
    )))
}

/// `(<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)`: `o0:op1:CRn:CRm:op2`
/// with op0 = `1:o0`, named as LLVM names it for the access: `MRS`, `MRRS`
/// read, `MSR`, `MSRR` write.
fn system_register(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let lookup = if s.instruction.name.starts_with("MR") {
        quote! { read }
    } else {
        quote! { write }
    };
    Ok(quote! {
        {
            let encoding = (0x8000 | #value) as u16;
            ops.push(Operand::SystemRegister(SystemRegister {
                encoding,
                name: sysreg::#lookup(encoding),
            }));
        }
    })
}

/// The `sysreg::pstate` lookup of `MSR (immediate)`.
fn pstate_lookup(s: &Slot<'_>) -> Result<TokenStream> {
    let (op1, crm, op2) = (s.field("op1")?, s.field("CRm")?, s.field("op2")?);
    Ok(quote! { sysreg::pstate(#op1, #crm, #op2) })
}

/// `<pstatefield>` of `MSR (immediate)`, spelt as LLVM does (`SPSel`). LLVM
/// writes a word without a field name as the register form,
/// `msr S0_<op1>_C4_C<m>_<op2>, xzr`.
fn pstate_field(s: &Slot<'_>) -> Result<TokenStream> {
    let (op1, crm, op2) = (s.field("op1")?, s.field("CRm")?, s.field("op2")?);
    let lookup = pstate_lookup(s)?;
    Ok(quote! {
        ops.push(match #lookup {
            Some((name, _)) => Operand::Named(Named { kind: NameKind::PstateField, name }),
            None => Operand::SystemRegister(SystemRegister {
                encoding: ((#op1 << 11) | (4 << 7) | (#crm << 3) | #op2) as u16,
                name: None,
            }),
        });
    })
}

/// `#<imm>` of `MSR (immediate)`: the `CRm` bits the field leaves free
/// (all of `CRm`; `CRm<0>` for `ALLINT`, `PM`), or `xzr` where LLVM
/// writes the register form.
fn pstate_value(s: &Slot<'_>) -> Result<TokenStream> {
    let lookup = pstate_lookup(s)?;
    let value = unsigned(&quote! { value });
    let zero = register("X", &quote! { 31 });
    Ok(quote! {
        ops.push(match #lookup {
            Some((_, value)) => #value,
            None => #zero,
        });
    })
}

/// `{<option>}` of `SMSTART`, `SMSTOP`: `CRm<2:1>` selects `sm` (01), `za`
/// (10) or neither (11).
fn streaming_option(s: &Slot<'_>) -> Result<TokenStream> {
    let crm = s.field("CRm")?;
    let (sm, za) = (named("Keyword", "sm"), named("Keyword", "za"));
    Ok(quote! {
        match (#crm >> 1) & 3 {
            1 => ops.push(#sm),
            2 => ops.push(#za),
            _ => {}
        }
    })
}

pub const SYMBOLS: &[Symbol] = &[
    // SYS, SYSL, SYSP.
    any("#<op1>", hex),
    any("#<op2>", hex),
    any("<Cn>", control),
    any("<Cm>", control),
    any("{, <Xt>}", optional_xt),
    forms(
        "{, <Xt>}",
        &[
            "SYS_CR_systeminstrs__GIC",
            "SYS_CR_systeminstrs__IC",
            "SYS_CR_systeminstrs__PLBI",
            "SYS_CR_systeminstrs__TLBI",
        ],
        operation_xt,
    ),
    any("{<Xt>}", optional_xt),
    any("{, <Xt1>, <Xt2>}", sysp_pair),
    forms(
        "{, <Xt1>, <Xt2>}",
        &["SYSP_CR_syspairinstrs__TLBIP"],
        tlbip_pair,
    ),
    // System operations.
    any("<at_op>", operation),
    any("<brb_op>", operation),
    any("<dc_op>", operation),
    any("<gic_op>", operation),
    any("<gicr_op>", operation),
    any("<gsb_op>", operation),
    any("<ic_op>", operation),
    any("<plbi_op>", operation),
    any("<tlbi_op>", operation),
    any("<tlbip_op>", operation),
    any("RCTX", rctx),
    // System registers.
    any(
        "(<systemreg>|S<op0>_<op1>_<Cn>_<Cm>_<op2>)",
        system_register,
    ),
    any("<Xt+1>", next_xt),
    // PSTATE.
    any("<pstatefield>", pstate_field),
    forms("#<imm>", &["MSR_SI_pstate"], pstate_value),
    any("{<option>}", streaming_option),
];
