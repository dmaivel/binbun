//! Symbols of the load/store groups (`ldst`): single and pair loads and
//! stores, exclusives, atomics, memory copy and set, prefetch, tags and the
//! `AdvSIMD` structure loads and stores.
//!
//! A memory operand is one slot (`[<Xn|SP>{, #<pimm>}]`, `[<Xn|SP>], <Xm>`)
//! and becomes one [`Memory`] operand; a register list is one slot and one
//! `RegisterList`.
//!
//! LLVM's rules met here: an optional offset of 0 is left out (`[x1]`),
//! while pre- and post-index offsets are always written (`[x1, #0x0]!`);
//! offsets are hex, but the fixed post-index amounts of the `AdvSIMD`
//! structure forms and the constant offsets of `LDAPR`, `STLR`, `LDIAPP`
//! and `STILP` are decimal (`[x0], #32`, `[x1, #-8]!`).
//!
//! [`Memory`]: binbun_aarch64::operand::Memory

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::{Build, Slot, Symbol, named, push, register, sign_extend, unsigned};
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

/// The slot's first field as a register of `class`, its number plus
/// `plus` (the second register of a `CASP` pair).
fn numbered(s: &Slot<'_>, class: &str, plus: u32) -> Result<TokenStream> {
    let name = s
        .fields
        .first()
        .ok_or_else(|| format!("{}: `{}` has no field", s.form, s.key))?;
    let number = s.field(name)?;
    let number = if plus == 0 {
        number
    } else {
        let plus = lit(plus);
        quote! { #number + #plus }
    };
    Ok(push(&register(class, &number)))
}

fn w(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "W", 0)
}

fn x(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "X", 0)
}

fn b(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "B", 0)
}

fn h(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "H", 0)
}

fn single(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "S", 0)
}

fn d(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "D", 0)
}

fn q(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "Q", 0)
}

/// `<W(s+1)>`, `<W(t+1)>`: the second register of a `CASP` pair.
fn w_next(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "W", 1)
}

/// `<X(s+1)>`, `<X(t+1)>`: the second register of a `CASP` pair.
fn x_next(s: &Slot<'_>) -> Result<TokenStream> {
    numbered(s, "X", 1)
}

/// `<Xn>!` of memory copy and set: the size register, written back.
fn x_writeback(s: &Slot<'_>) -> Result<TokenStream> {
    let number = s.field("Rn")?;
    Ok(push(&quote! {
        Operand::Writeback(Register::new(RegisterClass::X, (#number) as u8))
    }))
}

/// A memory operand on the base register numbered `base` of `class`.
fn memory(class: &str, base: &TokenStream, offset: &TokenStream, writeback: &str) -> TokenStream {
    let class = format_ident!("{class}");
    let writeback = format_ident!("{writeback}");
    quote! {
        Operand::Memory(Memory {
            base: Register::new(RegisterClass::#class, (#base) as u8),
            offset: #offset,
            writeback: Writeback::#writeback,
        })
    }
}

/// `[<Xn|SP>]`, and `[<Xn|SP>{, #0}]` of the exclusives and atomics, where
/// LLVM leaves the `#0` out.
fn base(s: &Slot<'_>) -> Result<TokenStream> {
    let rn = s.field("Rn")?;
    Ok(push(&memory("Xsp", &rn, &quote! { Offset::None }, "None")))
}

/// `[<Xd>]!`, `[<Xs>]!` of memory copy and set: the address register
/// (where 31 is `xzr`), written back.
fn copy_address(s: &Slot<'_>) -> Result<TokenStream> {
    let name = s
        .fields
        .first()
        .ok_or_else(|| format!("{}: `{}` has no field", s.form, s.key))?;
    let number = s.field(name)?;
    Ok(push(&memory("X", &number, &quote! { Offset::None }, "Pre")))
}

/// A memory operand on `Rn` with the signed byte offset `offset` (an `i64`
/// expression): `writeback` `None` leaves out an offset of 0, as LLVM does;
/// pre- and post-index always write it.
fn immediate_offset(s: &Slot<'_>, offset: &TokenStream, writeback: &str) -> Result<TokenStream> {
    let rn = s.field("Rn")?;
    let some = memory(
        "Xsp",
        &rn,
        &quote! { Offset::Immediate(Immediate::signed(offset)) },
        writeback,
    );
    if writeback != "None" {
        return Ok(quote! {{ let offset: i64 = #offset; ops.push(#some); }});
    }
    let none = memory("Xsp", &rn, &quote! { Offset::None }, "None");
    Ok(quote! {{
        let offset: i64 = #offset;
        ops.push(if offset == 0 { #none } else { #some });
    }})
}

/// Writeback of a memory key: `]!` pre-index, `], ` post-index.
fn writeback(key: &str) -> &'static str {
    if key.ends_with("]!") {
        "Pre"
    } else if key.contains("], ") {
        "Post"
    } else {
        "None"
    }
}

/// log2 of the access size of a single-register load or store: `size`,
/// and `opc<1>:size` for SIMD&FP registers (`Q` is 4).
fn access_scale(s: &Slot<'_>) -> Result<TokenStream> {
    let size = s.field("size")?;
    if s.width("VR").is_err() {
        return Ok(size);
    }
    let (vr, opc) = (s.field("VR")?, s.field("opc")?);
    Ok(quote! { (((#vr & (#opc >> 1)) << 2) | #size) })
}

/// `[<Xn|SP>{, #<pimm>}]`: `imm12` scaled by the access size, unsigned.
fn scaled_unsigned(s: &Slot<'_>) -> Result<TokenStream> {
    let (imm12, scale) = (s.field("imm12")?, access_scale(s)?);
    immediate_offset(s, &quote! { i64::from(#imm12 << #scale) }, "None")
}

/// Bytes per unit of an `imm9` offset: 16 (a tag granule) for the MTE tag
/// loads and stores, else 1.
fn imm9_unit(s: &Slot<'_>) -> i64 {
    if s.instruction.name.ends_with("_ldsttags") {
        16
    } else {
        1
    }
}

/// `[<Xn|SP>{, #<simm>}]`, `[<Xn|SP>, #<simm>]!`, `[<Xn|SP>], #<simm>`:
/// the signed `imm9`, in bytes or tag granules.
fn unscaled_signed(s: &Slot<'_>) -> Result<TokenStream> {
    let value = sign_extend(&s.field("imm9")?, 9);
    let unit = imm9_unit(s);
    let offset = if unit == 1 {
        value
    } else {
        quote! { #value * #unit }
    };
    immediate_offset(s, &offset, writeback(&s.key))
}

/// `LDRAA`/`LDRAB` `[<Xn|SP>{, #<simm>}]{!}`: `S:imm9` in 8-byte units.
fn pac_offset(s: &Slot<'_>) -> Result<TokenStream> {
    let (sign, imm9) = (s.field("S")?, s.field("imm9")?);
    let value = sign_extend(&quote! { (#sign << 9) | #imm9 }, 10);
    immediate_offset(s, &quote! { #value * 8 }, writeback(&s.key))
}

/// Bytes per unit of a pair's `imm7`: 4 for W, S and `LDPSW`, 8 for X and
/// D, 16 for Q (`opc` 10, and 11 for the unprivileged `LDTP`/`STTP` Q
/// pairs); `opc` 11 of general registers is `LDTP`/`STTP` of X.
fn pair_scale(s: &Slot<'_>) -> Result<TokenStream> {
    let (vr, opc) = (s.field("VR")?, s.field("opc")?);
    Ok(quote! {
        (if #vr == 1 { 4i64 << (#opc).min(2) } else { 4i64 << (#opc >> 1) })
    })
}

/// `[<Xn|SP>{, #<imm>}]`, `[<Xn|SP>, #<imm>]!`, `[<Xn|SP>], #<imm>` of
/// pairs: the signed `imm7` scaled by the register size.
fn pair_offset(s: &Slot<'_>) -> Result<TokenStream> {
    let value = sign_extend(&s.field("imm7")?, 7);
    let scale = pair_scale(s)?;
    immediate_offset(s, &quote! { #value * #scale }, writeback(&s.key))
}

/// `STGP` `[<Xn|SP>{, #<imm>}]` and the like: the signed `simm7` in tag
/// granules.
fn tag_pair_offset(s: &Slot<'_>) -> Result<TokenStream> {
    let value = sign_extend(&s.field("simm7")?, 7);
    immediate_offset(s, &quote! { #value * 16 }, writeback(&s.key))
}

/// A memory key with a constant offset (`[<Xn|SP>, #-8]!`,
/// `[<Xn|SP>], #16`): the number in the key, written in decimal as LLVM
/// does.
fn constant_offset(s: &Slot<'_>) -> Result<TokenStream> {
    let text = s
        .key
        .rsplit('#')
        .next()
        .map(|rest| rest.trim_end_matches(['!', ']']))
        .ok_or_else(|| format!("{}: `{}` has no constant", s.form, s.key))?;
    let value: i64 = text
        .parse()
        .map_err(|_| format!("{}: `{}` has no constant", s.form, s.key))?;
    let rn = s.field("Rn")?;
    Ok(push(&memory(
        "Xsp",
        &rn,
        &quote! { Offset::Immediate(Immediate::signed(#value).decimal()) },
        writeback(&s.key),
    )))
}

/// `[<Xn|SP>], <imm>` of the `AdvSIMD` structure forms: the bytes
/// transferred, from the value-named alternatives of `<imm>` (`#16`,
/// `#32`), in decimal.
fn structure_post_immediate(s: &Slot<'_>) -> Result<TokenStream> {
    let amount = s.match_names(
        "<imm>",
        |text| {
            let value: i64 = text.trim_start_matches('#').parse().unwrap_or_default();
            quote! { #value }
        },
        &quote! { 0i64 },
    )?;
    let rn = s.field("Rn")?;
    Ok(push(&memory(
        "Xsp",
        &rn,
        &quote! { Offset::Immediate(Immediate::signed(#amount).decimal()) },
        "Post",
    )))
}

/// `[<Xn|SP>], <Xm>`: post-index by a register.
fn structure_post_register(s: &Slot<'_>) -> Result<TokenStream> {
    let (rn, rm) = (s.field("Rn")?, s.field("Rm")?);
    let offset = quote! {
        Offset::Register {
            index: Register::new(RegisterClass::X, (#rm) as u8),
            modifier: Modifier::None,
        }
    };
    Ok(push(&memory("Xsp", &rn, &offset, "Post")))
}

/// A register-offset memory operand: `index` is the offset register and
/// `modifier` its `Modifier`.
fn register_offset(
    s: &Slot<'_>,
    index: &TokenStream,
    modifier: &TokenStream,
) -> Result<TokenStream> {
    let rn = s.field("Rn")?;
    let offset = quote! { Offset::Register { index: #index, modifier: #modifier } };
    Ok(push(&memory("Xsp", &rn, &offset, "None")))
}

/// `(<Wm>|<Xm>)`: X when `option<0>` is set (`LSL`/`SXTX`/`UXTX`), else W.
fn extended_index(s: &Slot<'_>) -> Result<TokenStream> {
    let (option, rm) = (s.field("option")?, s.field("Rm")?);
    Ok(quote! {
        Register::new(
            if #option & 1 == 1 { RegisterClass::X } else { RegisterClass::W },
            (#rm) as u8,
        )
    })
}

/// `[<Xn|SP>, (<Wm>|<Xm>){, <extend>{<amount>}}]`: `option` 011 is `LSL`,
/// written only when `S` is set; other extensions are written with the
/// amount (the access size) when `S` is set.
fn extended_register(s: &Slot<'_>) -> Result<TokenStream> {
    let index = extended_index(s)?;
    let (option, shifted, scale) = (s.field("option")?, s.field("S")?, access_scale(s)?);
    let modifier = quote! {{
        let option = #option;
        let amount = if #shifted == 1 { Some((#scale) as u8) } else { None };
        match (option, amount) {
            (3, None) => Modifier::None,
            (3, Some(amount)) => Modifier::Shift(Shift { kind: ShiftKind::Lsl, amount }),
            _ => Modifier::Extend(Extend { kind: ExtendKind::from_option(option), amount }),
        }
    }};
    register_offset(s, &index, &modifier)
}

/// `[<Xn|SP>, (<Wm>|<Xm>), <extend>{<amount>}]` of byte accesses: the
/// extension, with `#0` when `S` is set (LLVM writes `uxtw #0`).
fn byte_extended_register(s: &Slot<'_>) -> Result<TokenStream> {
    let index = extended_index(s)?;
    let (option, shifted) = (s.field("option")?, s.field("S")?);
    let modifier = quote! {
        Modifier::Extend(Extend {
            kind: ExtendKind::from_option(#option),
            amount: if #shifted == 1 { Some(0) } else { None },
        })
    };
    register_offset(s, &index, &modifier)
}

/// `[<Xn|SP>, <Xm>{, LSL <amount>}]` of byte accesses: `lsl #0` when `S` is
/// set, as LLVM writes it.
fn byte_shifted_register(s: &Slot<'_>) -> Result<TokenStream> {
    let (rm, shifted) = (s.field("Rm")?, s.field("S")?);
    let index = quote! { Register::new(RegisterClass::X, (#rm) as u8) };
    let modifier = quote! {
        if #shifted == 1 {
            Modifier::Shift(Shift { kind: ShiftKind::Lsl, amount: 0 })
        } else {
            Modifier::None
        }
    };
    register_offset(s, &index, &modifier)
}

/// Number of registers of a list key (`{<Vt>.B, <Vt2>.B}`).
fn list_count(s: &Slot<'_>) -> u8 {
    u8::try_from(s.key.matches("<Vt").count()).unwrap_or_default()
}

/// A list of `count` consecutive vector registers from `Rt`, each written
/// with `arrangement`, and `index` (an `Option<u8>` expression).
fn vector_list(
    s: &Slot<'_>,
    arrangement: &TokenStream,
    index: &TokenStream,
) -> Result<TokenStream> {
    let rt = s.field("Rt")?;
    let count = list_count(s);
    Ok(push(&quote! {
        Operand::List(RegisterList {
            first: Register {
                class: RegisterClass::V,
                number: (#rt) as u8,
                arrangement: Some(#arrangement),
                index: #index,
                predication: None,
            },
            count: #count,
            stride: 1,
            style: ListStyle::Commas,
        })
    }))
}

/// `{<Vt>.<T>, …}`: the arrangement from the value-named alternatives of
/// `<T>` (`8b`, `16b`, … `2d`).
fn arranged_list(s: &Slot<'_>) -> Result<TokenStream> {
    let arrangement = s.match_names(
        "<T>",
        |text| {
            let (digits, element) = text.split_at(text.len() - 1);
            let count: u8 = digits.parse().unwrap_or_default();
            let element = format_ident!("{}", element.to_ascii_uppercase());
            quote! { Arrangement { count: #count, element: ElementSize::#element } }
        },
        &quote! { Arrangement { count: 0, element: ElementSize::B } },
    )?;
    vector_list(s, &arrangement, &quote! { None })
}

/// `{<Vt>.B, …}[<index>]` and the like: one lane of each register; the
/// index is `Q:S:size` for B, `Q:S:size<1>` for H, `Q:S` for S and `Q`
/// for D.
fn lane_list(s: &Slot<'_>) -> Result<TokenStream> {
    let element = s
        .key
        .split_once('.')
        .and_then(|(_, rest)| rest.chars().next())
        .ok_or_else(|| format!("{}: `{}` has no element", s.form, s.key))?;
    let q = s.field("Q")?;
    let index = match element {
        'B' => {
            let (sbit, size) = (s.field("S")?, s.field("size")?);
            quote! { (#q << 3) | (#sbit << 2) | #size }
        }
        'H' => {
            let (sbit, size) = (s.field("S")?, s.field("size")?);
            quote! { (#q << 2) | (#sbit << 1) | (#size >> 1) }
        }
        'S' => {
            let sbit = s.field("S")?;
            quote! { (#q << 1) | #sbit }
        }
        _ => q,
    };
    let element = format_ident!("{element}");
    vector_list(
        s,
        &quote! { Arrangement { count: 0, element: ElementSize::#element } },
        &quote! { Some((#index) as u8) },
    )
}

/// `(<prfop>|#<imm5>)`: `Rt` is type (`pld`, `pli`, `pst`), target (`l1`,
/// `l2`, `l3`, `slc`) and policy (`keep`, `strm`); type 11 is written as a
/// number (LLVM does not name Arm's `ir`).
fn prefetch(s: &Slot<'_>) -> Result<TokenStream> {
    let rt = s.field("Rt")?;
    let mut arms = Vec::new();
    for (kind, kind_name) in ["pld", "pli", "pst"].iter().enumerate() {
        for (target, target_name) in ["l1", "l2", "l3", "slc"].iter().enumerate() {
            for (policy, policy_name) in ["keep", "strm"].iter().enumerate() {
                let value = lit(u32::try_from((kind << 3) | (target << 1) | policy)?);
                let operand = named(
                    "Prefetch",
                    &format!("{kind_name}{target_name}{policy_name}"),
                );
                arms.push(quote! { #value => #operand, });
            }
        }
    }
    let number = unsigned(&quote! { other });
    Ok(quote! {
        ops.push(match #rt {
            #(#arms)*
            other => #number,
        });
    })
}

/// `RPRFM (<rprfop>|#<imm6>)`: `option<2>:option<0>:S:Rt<2:0>`; 0, 1, 4
/// and 5 are `pldkeep`, `pstkeep`, `pldstrm`, `pststrm`, others numbers.
fn range_prefetch(s: &Slot<'_>) -> Result<TokenStream> {
    let (option, sbit, rt) = (s.field("option")?, s.field("S")?, s.field("Rt")?);
    let names = [
        (0u32, "pldkeep"),
        (1, "pstkeep"),
        (4, "pldstrm"),
        (5, "pststrm"),
    ];
    let arms = names.iter().map(|(value, name)| {
        let value = lit(*value);
        let operand = named("Prefetch", name);
        quote! { #value => #operand, }
    });
    let number = unsigned(&quote! { other });
    Ok(quote! {
        ops.push(match ((#option >> 2) << 5) | ((#option & 1) << 4) | (#sbit << 3) | (#rt & 7) {
            #(#arms)*
            other => #number,
        });
    })
}

pub const SYMBOLS: &[Symbol] = &[
    // Registers.
    any("<Wt1>", w),
    any("<Wt2>", w),
    any("<Xt1>", x),
    any("<Xt2>", x),
    any("<W(s+1)>", w_next),
    any("<W(t+1)>", w_next),
    any("<X(s+1)>", x_next),
    any("<X(t+1)>", x_next),
    any("<Bt>", b),
    any("<Ht>", h),
    any("<Hs>", h),
    any("<St>", single),
    any("<Ss>", single),
    any("<St1>", single),
    any("<St2>", single),
    any("<Dt>", d),
    any("<Ds>", d),
    any("<Dt1>", d),
    any("<Dt2>", d),
    any("<Qt>", q),
    any("<Qt1>", q),
    any("<Qt2>", q),
    // Prefetch operations.
    any("(<prfop>|#<imm5>)", prefetch),
    any("(<rprfop>|#<imm6>)", range_prefetch),
    // Memory copy and set.
    any("[<Xd>]!", copy_address),
    any("[<Xs>]!", copy_address),
    any("<Xn>!", x_writeback),
    // Memory operands.
    any("[<Xn|SP>]", base),
    any("[<Xn|SP>{, #0}]", base),
    any("[<Xn|SP>{, #<pimm>}]", scaled_unsigned),
    fields("[<Xn|SP>{, #<simm>}]", &["Rn", "imm9"], unscaled_signed),
    fields("[<Xn|SP>, #<simm>]!", &["Rn", "imm9"], unscaled_signed),
    fields("[<Xn|SP>], #<simm>", &["Rn", "imm9"], unscaled_signed),
    fields("[<Xn|SP>{, #<simm>}]", &["Rn", "S", "imm9"], pac_offset),
    fields("[<Xn|SP>{, #<simm>}]!", &["Rn", "S", "imm9"], pac_offset),
    fields("[<Xn|SP>{, #<imm>}]", &["Rn", "imm7"], pair_offset),
    fields("[<Xn|SP>, #<imm>]!", &["Rn", "imm7"], pair_offset),
    fields("[<Xn|SP>], #<imm>", &["Rn", "imm7"], pair_offset),
    fields("[<Xn|SP>{, #<imm>}]", &["Rn", "simm7"], tag_pair_offset),
    fields("[<Xn|SP>, #<imm>]!", &["Rn", "simm7"], tag_pair_offset),
    fields("[<Xn|SP>], #<imm>", &["Rn", "simm7"], tag_pair_offset),
    any("[<Xn|SP>, #-4]!", constant_offset),
    any("[<Xn|SP>, #-8]!", constant_offset),
    any("[<Xn|SP>, #-16]!", constant_offset),
    any("[<Xn|SP>], #1", constant_offset),
    any("[<Xn|SP>], #2", constant_offset),
    any("[<Xn|SP>], #3", constant_offset),
    any("[<Xn|SP>], #4", constant_offset),
    any("[<Xn|SP>], #6", constant_offset),
    any("[<Xn|SP>], #8", constant_offset),
    any("[<Xn|SP>], #12", constant_offset),
    any("[<Xn|SP>], #16", constant_offset),
    any("[<Xn|SP>], #24", constant_offset),
    any("[<Xn|SP>], #32", constant_offset),
    any("[<Xn|SP>], <imm>", structure_post_immediate),
    any("[<Xn|SP>], <Xm>", structure_post_register),
    any(
        "[<Xn|SP>, (<Wm>|<Xm>){, <extend>{<amount>}}]",
        extended_register,
    ),
    any(
        "[<Xn|SP>, (<Wm>|<Xm>), <extend>{<amount>}]",
        byte_extended_register,
    ),
    any("[<Xn|SP>, <Xm>{, LSL <amount>}]", byte_shifted_register),
    // AdvSIMD register lists.
    any("{<Vt>.<T> }", arranged_list),
    any("{<Vt>.<T>, <Vt2>.<T> }", arranged_list),
    any("{<Vt>.<T>, <Vt2>.<T>, <Vt3>.<T> }", arranged_list),
    any(
        "{<Vt>.<T>, <Vt2>.<T>, <Vt3>.<T>, <Vt4>.<T> }",
        arranged_list,
    ),
    any("{<Vt>.B }[<index>]", lane_list),
    any("{<Vt>.B, <Vt2>.B }[<index>]", lane_list),
    any("{<Vt>.B, <Vt2>.B, <Vt3>.B }[<index>]", lane_list),
    any("{<Vt>.B, <Vt2>.B, <Vt3>.B, <Vt4>.B }[<index>]", lane_list),
    any("{<Vt>.H }[<index>]", lane_list),
    any("{<Vt>.H, <Vt2>.H }[<index>]", lane_list),
    any("{<Vt>.H, <Vt2>.H, <Vt3>.H }[<index>]", lane_list),
    any("{<Vt>.H, <Vt2>.H, <Vt3>.H, <Vt4>.H }[<index>]", lane_list),
    any("{<Vt>.S }[<index>]", lane_list),
    any("{<Vt>.S, <Vt2>.S }[<index>]", lane_list),
    any("{<Vt>.S, <Vt2>.S, <Vt3>.S }[<index>]", lane_list),
    any("{<Vt>.S, <Vt2>.S, <Vt3>.S, <Vt4>.S }[<index>]", lane_list),
    any("{<Vt>.D }[<index>]", lane_list),
    any("{<Vt>.D, <Vt2>.D }[<index>]", lane_list),
    any("{<Vt>.D, <Vt2>.D, <Vt3>.D }[<index>]", lane_list),
    any("{<Vt>.D, <Vt2>.D, <Vt3>.D, <Vt4>.D }[<index>]", lane_list),
];
