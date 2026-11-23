//! Symbols of the integer groups: `control` (but system instructions),
//! `dpimm`, `dpreg`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::{
    Build, Slot, Symbol, decimal, named, push, register, shift, sign_extend, signed, unsigned,
};
use crate::Result;
use crate::codegen::lit;

/// A symbol matching any fields and forms.
const fn any(key: &'static str, build: fn(&Slot<'_>) -> Result<TokenStream>) -> Symbol {
    Symbol {
        key,
        fields: &[],
        forms: &[],
        build: Build::Operands(build),
    }
}

/// A symbol for slots encoded in exactly `fields`.
const fn fields(
    key: &'static str,
    fields: &'static [&'static str],
    build: fn(&Slot<'_>) -> Result<TokenStream>,
) -> Symbol {
    Symbol {
        key,
        fields,
        forms: &[],
        build: Build::Operands(build),
    }
}

/// The slot's one field as a general register of `class`.
fn general(s: &Slot<'_>, class: &str) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    Ok(push(&register(class, &number)))
}

fn w(s: &Slot<'_>) -> Result<TokenStream> {
    general(s, "W")
}

fn x(s: &Slot<'_>) -> Result<TokenStream> {
    general(s, "X")
}

fn wsp(s: &Slot<'_>) -> Result<TokenStream> {
    general(s, "Wsp")
}

fn xsp(s: &Slot<'_>) -> Result<TokenStream> {
    general(s, "Xsp")
}

/// `<R><m>`, `<R><t>`: X when the width field (`option<1:0> == 11`, `b5`)
/// says 64 bits, else W.
fn sized_register(s: &Slot<'_>) -> Result<TokenStream> {
    let (size, number) = match s.fields.as_slice() {
        [size, number] => (size.as_str(), number.as_str()),
        _ => return Err(format!("{}: `{}`", s.form, s.key).into()),
    };
    let width_field = s.field(size)?;
    let wide = if size == "option" {
        quote! { #width_field & 3 == 3 }
    } else {
        quote! { #width_field == 1 }
    };
    let number = s.field(number)?;
    let x = register("X", &number);
    let w = register("W", &number);
    Ok(quote! { ops.push(if #wide { #x } else { #w }); })
}

/// The slot's fields, concatenated, as an unsigned hex immediate.
fn hex(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(&unsigned(&value)))
}

/// The slot's fields as a signed hex immediate.
fn signed_hex(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, width) = s.value()?;
    Ok(push(&signed(&sign_extend(&value, width))))
}

/// `SVC`, `HVC`, `SMC`, `BRK`, `HLT` `#<imm>`: hex, but `#0` for zero as
/// LLVM writes it.
fn exception_immediate(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let (hex, zero) = (unsigned(&value), decimal(&quote! { 0 }));
    Ok(quote! { ops.push(if #value == 0 { #zero } else { #hex }); })
}

/// The slot's value plus one (`CBGE` for `CBGT #imm - 1`).
fn plus_one(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(&unsigned(&quote! { (#value) + 1 })))
}

/// The slot's value minus one, signed (`CBLE` for `CBLT #imm + 1`).
fn minus_one(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(&signed(&quote! { i64::from(#value) - 1 })))
}

/// `uimm6` of `ADDG`/`SUBG`: a multiple of the tag granule (16 bytes).
fn tag_offset(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(&unsigned(&quote! { (#value) << 4 })))
}

/// `DecodeBitMasks(N, imms, immr)` of a logical immediate, 32 or 64 bits
/// by `sf`.
fn bitmask_value(s: &Slot<'_>) -> Result<TokenStream> {
    let n = if s.fields.iter().any(|field| field == "N") {
        s.field("N")?
    } else {
        quote! { 0 }
    };
    let (ones, rotation, sf) = (s.field("imms")?, s.field("immr")?, s.field("sf")?);
    Ok(quote! { pseudocode::decode_bit_masks(#n, #ones, #rotation, #sf) })
}

/// The bitmask immediate of `AND`, `ORR`, `EOR`, `ANDS`, `TST`: unsigned.
fn bitmask(s: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&unsigned(&bitmask_value(s)?)))
}

/// The bitmask immediate of `MOV` (`ORR` from the zero register): signed
/// at the register's width, as LLVM writes moved values.
fn moved_bitmask(s: &Slot<'_>) -> Result<TokenStream> {
    let value = bitmask_value(s)?;
    let value = if s.instruction.name.contains("_32") {
        quote! { i64::from((#value) as u32 as i32) }
    } else {
        quote! { (#value).cast_signed() }
    };
    Ok(push(&signed(&value)))
}

/// The value `MOV` (wide immediate) moves: `imm16 << 16 * hw`, inverted for
/// `MOVN`, written signed at the register's width.
fn move_wide(s: &Slot<'_>) -> Result<TokenStream> {
    let (imm16, hw) = (s.field("imm16")?, s.field("hw")?);
    let shifted = quote! { (u64::from(#imm16) << (16 * #hw)) };
    let value = if s.instruction.name.starts_with("MOVN") {
        quote! { !#shifted }
    } else {
        shifted
    };
    let value = if s.instruction.name.contains("_32") {
        quote! { i64::from((#value) as u32 as i32) }
    } else {
        quote! { (#value).cast_signed() }
    };
    Ok(push(&signed(&value)))
}

/// Register size of a bitfield or extract encoding: 32 or 64.
fn datasize(s: &Slot<'_>) -> u32 {
    if s.instruction.name.contains("_64") {
        64
    } else {
        32
    }
}

/// Whether a bitfield alias inserts (`BFI`, `BFC`, `SBFIZ`, `UBFIZ`) rather
/// than extracts.
fn inserts(s: &Slot<'_>) -> bool {
    ["__BFI", "__BFC", "__SBFIZ", "__UBFIZ"]
        .iter()
        .any(|suffix| s.form.ends_with(suffix))
}

/// `<lsb>` of a bitfield alias: `-immr MOD size` when inserting, else
/// `immr`; decimal.
fn bitfield_lsb(s: &Slot<'_>) -> Result<TokenStream> {
    let immr = s.field("immr")?;
    let value = if inserts(s) {
        let mask = lit(datasize(s) - 1);
        quote! { (0u32.wrapping_sub(#immr)) & #mask }
    } else {
        immr
    };
    Ok(push(&decimal(&value)))
}

/// `<width>` of a bitfield alias: `imms + 1` when inserting, else
/// `imms - immr + 1`; decimal.
fn bitfield_width(s: &Slot<'_>) -> Result<TokenStream> {
    let (ones, rotation) = (s.field("imms")?, s.field("immr")?);
    let value = if inserts(s) {
        quote! { #ones + 1 }
    } else {
        quote! { #ones + 1 - #rotation }
    };
    Ok(push(&decimal(&value)))
}

/// `#<shift>` of `LSR`/`ASR` (`immr`) and `LSL` (`size - 1 - imms`);
/// decimal.
fn bitfield_shift(s: &Slot<'_>) -> Result<TokenStream> {
    let value = if s.form.ends_with("__LSL") {
        let (imms, last) = (s.field("imms")?, lit(datasize(s) - 1));
        quote! { #last - #imms }
    } else {
        s.field("immr")?
    };
    Ok(push(&decimal(&value)))
}

/// The slot's one field in decimal.
fn decimal_value(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(&decimal(&value)))
}

/// A label `scale` bytes per unit of the slot's signed field, relative to the
/// instruction, written as `radix`.
fn label(s: &Slot<'_>, scale: i64, base: &str, radix: &str) -> Result<TokenStream> {
    let (value, width) = s.value()?;
    let offset = sign_extend(&value, width);
    let offset = if scale == 1 {
        offset
    } else {
        quote! { #offset * #scale }
    };
    let base = format_ident!("{base}");
    let radix = format_ident!("{radix}");
    Ok(push(&quote! {
        Operand::Label(Label {
            offset: #offset,
            base: LabelBase::#base,
            radix: Radix::#radix,
        })
    }))
}

fn branch_label(s: &Slot<'_>) -> Result<TokenStream> {
    label(s, 4, "Instruction", "Hex")
}

fn adr_label(s: &Slot<'_>) -> Result<TokenStream> {
    if s.form.starts_with("ADRP") {
        label(s, 4096, "Page", "Decimal")
    } else {
        label(s, 1, "Instruction", "Decimal")
    }
}

/// The label of `AUTIASPPC`, `RETAASPPC` and the like: `imm16` words back.
fn backward_label(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(&quote! {
        Operand::Label(Label {
            offset: -(i64::from(#value) << 2),
            base: LabelBase::Instruction,
            radix: Radix::Hex,
        })
    }))
}

fn condition(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(
        &quote! { Operand::Condition(Condition::from_bits(#value)) },
    ))
}

/// `<invcond>` of `CSET`, `CINC` and the like: the encoded condition
/// inverted.
fn inverted_condition(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(
        &quote! { Operand::Condition(Condition::from_bits(#value).invert()) },
    ))
}

/// `{, LSL #12}` of add/subtract immediate when `sh` is set.
fn shift_12(s: &Slot<'_>) -> Result<TokenStream> {
    let (sh, _) = s.value()?;
    let code = push(&shift("Lsl", &quote! { 12 }));
    Ok(quote! { if #sh == 1 { #code } })
}

/// `{, <shift> #<amount>}` of shifted-register forms, omitted for
/// `LSL #0` as LLVM does. The kinds are the value-named alternatives of
/// `<shift>` (`shift_00_LSL`, …).
fn register_shift(s: &Slot<'_>) -> Result<TokenStream> {
    let kind = s.match_names(
        "<shift>",
        |name| {
            let mut variant = name.to_owned();
            variant[..1].make_ascii_uppercase();
            let variant = format_ident!("{variant}");
            quote! { ShiftKind::#variant }
        },
        &quote! { ShiftKind::Ror },
    )?;
    let (shift, amount) = (s.field("shift")?, s.field("imm6")?);
    Ok(quote! {
        {
            let amount = #amount;
            if #shift != 0 || amount != 0 {
                ops.push(Operand::Shift(Shift { kind: #kind, amount: amount as u8 }));
            }
        }
    })
}

/// `{, LSL #<n>}` where the slot's field gives the amount in units of
/// `unit`; omitted when 0.
fn optional_lsl(s: &Slot<'_>, unit: u32) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let amount = if unit == 1 {
        value.clone()
    } else {
        let unit = lit(unit);
        quote! { #value * #unit }
    };
    let code = push(&shift("Lsl", &amount));
    Ok(quote! { if #value != 0 { #code } })
}

fn lsl_halfwords(s: &Slot<'_>) -> Result<TokenStream> {
    optional_lsl(s, 16)
}

fn lsl_amount(s: &Slot<'_>) -> Result<TokenStream> {
    optional_lsl(s, 1)
}

/// `{, <extend> {#<amount>}}` of extended-register forms. LLVM writes
/// `LSL` for `UXTX` (`UXTW` for 32 bits) when the destination or first
/// source is the stack pointer, and leaves out a zero amount.
fn register_extend(s: &Slot<'_>) -> Result<TokenStream> {
    let (option, amount, rn) = (s.field("option")?, s.field("imm3")?, s.field("Rn")?);
    let lsl_option = lit(if s.instruction.name.contains("_64") {
        3u32
    } else {
        2
    });
    // The flag-setting forms (and their CMP/CMN aliases) write XZR, not SP.
    let rd_is_sp =
        !(s.instruction.name.starts_with("ADDS") || s.instruction.name.starts_with("SUBS"));
    let stack = if rd_is_sp {
        let rd = s.field("Rd")?;
        quote! { (#rd == 31 || #rn == 31) }
    } else {
        quote! { #rn == 31 }
    };
    Ok(quote! {
        {
            let option = #option;
            let amount = #amount;
            if option == #lsl_option && #stack {
                if amount != 0 {
                    ops.push(Operand::Shift(Shift { kind: ShiftKind::Lsl, amount: amount as u8 }));
                }
            } else {
                ops.push(Operand::Extend(Extend {
                    kind: ExtendKind::from_option(option),
                    amount: if amount == 0 { None } else { Some(amount as u8) },
                }));
            }
        }
    })
}

/// `RET {<Xn>}`: omitted for `x30`.
fn return_register(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    let code = push(&register("X", &number));
    Ok(quote! { if #number != 30 { #code } })
}

/// `IRG {, <Xm>}`: omitted for `xzr`.
fn optional_xm(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    let code = push(&register("X", &number));
    Ok(quote! { if #number != 31 { #code } })
}

/// `CLREX {#<imm>}`: omitted for 15.
fn clrex_option(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let code = push(&unsigned(&value));
    Ok(quote! { if #value != 15 { #code } })
}

/// `DCPS<n> {#<imm>}`: omitted for 0.
fn dcps_immediate(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let code = push(&unsigned(&value));
    Ok(quote! { if #value != 0 { #code } })
}

/// `ISB {<option>|#<imm>}`: omitted for `SY` (15), else decimal.
fn isb_option(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let code = push(&decimal(&value));
    Ok(quote! { if #value != 15 { #code } })
}

/// `DMB`/`DSB <option>|#<imm>`: the named options, else the value in
/// decimal.
fn barrier_option(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let names = [
        (1u32, "oshld"),
        (2, "oshst"),
        (3, "osh"),
        (5, "nshld"),
        (6, "nshst"),
        (7, "nsh"),
        (9, "ishld"),
        (10, "ishst"),
        (11, "ish"),
        (13, "ld"),
        (14, "st"),
        (15, "sy"),
    ];
    let arms = names.iter().map(|(number, name)| {
        let number = lit(*number);
        let operand = named("Barrier", name);
        quote! { #number => #operand, }
    });
    let fallback = decimal(&quote! { other });
    Ok(quote! {
        ops.push(match #value {
            #(#arms)*
            other => #fallback,
        });
    })
}

/// `DSB <option>nXS`: `imm2` selects `osh`, `nsh`, `ish` or `sy`.
fn barrier_nxs(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let (osh, nsh, ish, sy) = (
        named("Barrier", "oshnxs"),
        named("Barrier", "nshnxs"),
        named("Barrier", "ishnxs"),
        named("Barrier", "synxs"),
    );
    Ok(quote! {
        ops.push(match #value {
            0 => #osh,
            1 => #nsh,
            2 => #ish,
            _ => #sy,
        });
    })
}

/// `BTI {<targets>}`: `op2<2:1>` selects `r`, `c`, `j` or `jc` (LLVM writes
/// `r` where Arm leaves the default target out).
fn bti_targets(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let (r, c, j, jc) = (
        named("BranchTarget", "r"),
        named("BranchTarget", "c"),
        named("BranchTarget", "j"),
        named("BranchTarget", "jc"),
    );
    Ok(quote! {
        ops.push(match #value >> 1 {
            0 => #r,
            1 => #c,
            2 => #j,
            _ => #jc,
        });
    })
}

/// A keyword written when bit 0 of the slot's field is set (`nb`, `ph`).
fn flag_keyword(s: &Slot<'_>, field: &str, name: &str) -> Result<TokenStream> {
    let value = s.field(field)?;
    let code = push(&named("Keyword", name));
    Ok(quote! { if #value & 1 == 1 { #code } })
}

fn nb(s: &Slot<'_>) -> Result<TokenStream> {
    let field = s.fields.first().cloned().unwrap_or_default();
    flag_keyword(s, &field, "nb")
}

fn ph(s: &Slot<'_>) -> Result<TokenStream> {
    flag_keyword(s, "op2", "ph")
}

fn stshstrm(s: &Slot<'_>) -> Result<TokenStream> {
    flag_keyword(s, "op2", "stshstrm")
}

/// `STSHH <policy>`: `op2<0>` selects `keep` or `strm`.
fn policy(s: &Slot<'_>) -> Result<TokenStream> {
    let op2 = s.field("op2")?;
    let (keep, strm) = (named("Keyword", "keep"), named("Keyword", "strm"));
    Ok(quote! { ops.push(if #op2 & 1 == 0 { #keep } else { #strm }); })
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn csync(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&named("Keyword", "csync")))
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn dsync(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&named("Keyword", "dsync")))
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn x16(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&register("X", &quote! { 16 })))
}

/// Condition names by `cond` value, as LLVM writes them.
const CONDITIONS: &[&str] = &[
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

pub const SYMBOLS: &[Symbol] = &[
    // General registers.
    any("<Wd>", w),
    any("<Wn>", w),
    any("<Wm>", w),
    any("<Wa>", w),
    any("<Ws>", w),
    any("<Wt>", w),
    any("<Xd>", x),
    any("<Xn>", x),
    any("<Xm>", x),
    any("<Xa>", x),
    any("<Xs>", x),
    any("<Xt>", x),
    any("<Wd|WSP>", wsp),
    any("<Wn|WSP>", wsp),
    any("<Wm|WSP>", wsp),
    any("<Wt|WSP>", wsp),
    any("<Xd|SP>", xsp),
    any("<Xn|SP>", xsp),
    any("<Xm|SP>", xsp),
    any("<Xt|SP>", xsp),
    any("<R><m>", sized_register),
    any("<R><t>", sized_register),
    any("X16", x16),
    // Immediates.
    any("#<imm>", hex),
    fields("#<imm>", &["N", "imms", "immr"], bitmask),
    fields("#<imm>", &["imms", "immr"], bitmask),
    Symbol {
        key: "#<imm>",
        fields: &[],
        forms: &["ORR_32_log_imm__MOV", "ORR_64_log_imm__MOV"],
        build: Build::Operands(moved_bitmask),
    },
    fields("#<imm>", &["imm16", "hw"], move_wide),
    Symbol {
        key: "#<imm>",
        fields: &[],
        forms: &[
            "BRK_EX_exception",
            "HLT_EX_exception",
            "HVC_EX_exception",
            "SMC_EX_exception",
            "SVC_EX_exception",
        ],
        build: Build::Operands(exception_immediate),
    },
    any("#<imm16>", hex),
    any("#<immp1>", plus_one),
    any("#<imms1>", minus_one),
    any("#<immr>", decimal_value),
    any("#<imms>", decimal_value),
    fields("#<lsb>", &["immr"], bitfield_lsb),
    fields("#<lsb>", &["imms"], hex),
    any("#<width>", bitfield_width),
    fields("#<shift>", &["immr"], bitfield_shift),
    fields("#<shift>", &["imms"], hex),
    fields("#<shift>", &["imm6"], hex),
    any("#<simm>", signed_hex),
    any("#<uimm>", hex),
    any("#<uimm4>", hex),
    any("#<uimm6>", tag_offset),
    any("#<mask>", hex),
    any("#<nzcv>", hex),
    any("#<reason>", hex),
    // Shifts and extensions.
    any("{, <shift>}", shift_12),
    any("{, <shift> #<amount>}", register_shift),
    fields("{, LSL #<shift>}", &["hw"], lsl_halfwords),
    fields("{, LSL #<amount>}", &["imm3"], lsl_amount),
    any("{, <extend>{#<amount>}}", register_extend),
    // Labels.
    fields("<label>", &["imm26"], branch_label),
    fields("<label>", &["imm19"], branch_label),
    fields("<label>", &["imm14"], branch_label),
    fields("<label>", &["imm9"], branch_label),
    fields("<label>", &["immhi", "immlo"], adr_label),
    fields("<label>", &["imm16"], backward_label),
    // Conditions.
    any("<cond>", condition),
    any("<invcond>", inverted_condition),
    Symbol {
        key: "<cond>",
        fields: &[],
        forms: &[],
        build: Build::Text(CONDITIONS),
    },
    // Optional and named operands of branches, hints and barriers.
    any("{<Xn>}", return_register),
    any("{, <Xm>}", optional_xm),
    fields("{#<imm>}", &["CRm"], clrex_option),
    fields("{#<imm>}", &["imm16"], dcps_immediate),
    any("{<option>|#<imm>}", isb_option),
    any("(<option>|#<imm>)", barrier_option),
    any("<option>nXS", barrier_nxs),
    any("{<targets>}", bti_targets),
    any("{<nb>}", nb),
    any("{, <nb>}", nb),
    any("<policy>", policy),
    any("{PH}", ph),
    any("{STSHSTRM}", stshstrm),
    any("CSYNC", csync),
    any("DSYNC", dsync),
];
