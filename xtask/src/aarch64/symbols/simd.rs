//! Symbols of the scalar floating-point and Advanced SIMD groups
//! (`simd_dp`).
//!
//! Register keys are read by their shape ([`simd_register`]): a class
//! (`<V>`, `D`, or the letter of a display such as `<Dd>`, `<Vn>`), a
//! number display, an optional arrangement (`.<T>`, `.16B`, `.H`) and an
//! optional element index (`[<index>]`, `[1]`). The few registers whose
//! number or index depends on the element size have their own entries.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::{Build, Slot, Symbol, decimal, push, register, unsigned};
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

/// A symbol for the forms `forms`.
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

/// A piece of a register key: written out, or a display whose value
/// selects it.
#[derive(Clone, Copy)]
enum Part<'k> {
    Fixed(&'k str),
    Display(&'k str),
}

impl<'k> Part<'k> {
    fn new(text: &'k str) -> Self {
        if text.starts_with('<') {
            Self::Display(text)
        } else {
            Self::Fixed(text)
        }
    }
}

/// A register key taken apart: `<V><d>`, `D<n>`, `<Vd>.<T>`,
/// `<Vm>.H[<index>]`, `<Vn>.D[1]`, `<Vm>[<index>]`.
struct RegisterKey<'k> {
    class: Part<'k>,
    number: &'k str,
    arrangement: Option<Part<'k>>,
    index: Option<Part<'k>>,
}

impl<'k> RegisterKey<'k> {
    fn parse(key: &'k str) -> Option<Self> {
        let (rest, index) = match key.strip_suffix(']') {
            Some(body) => {
                let (rest, index) = body.rsplit_once('[')?;
                (rest, Some(Part::new(index)))
            }
            None => (key, None),
        };
        let (register, arrangement) = match rest.split_once('.') {
            Some((register, arrangement)) => (register, Some(Part::new(arrangement))),
            None => (rest, None),
        };
        let (class, number) = if register.starts_with('<') {
            let end = register.find('>')? + 1;
            let (first, number) = register.split_at_checked(end)?;
            if number.is_empty() {
                // `<Dd>`, `<Vn>`: the class is the display's letter.
                (Part::Fixed(first.get(1..2)?), first)
            } else {
                (Part::Display(first), number)
            }
        } else {
            let start = register.find('<')?;
            let (class, number) = register.split_at_checked(start)?;
            (Part::Fixed(class), number)
        };
        Some(Self {
            class,
            number,
            arrangement,
            index,
        })
    }
}

/// `RegisterClass` variant of a register letter (`v`, `D`).
fn class(letter: &str) -> TokenStream {
    let class = format_ident!("{}", letter.to_ascii_uppercase());
    quote! { RegisterClass::#class }
}

/// `Some(Arrangement { … })` of an arrangement as written: `16b`, `2d`,
/// `4b`, or an element size alone (`h`, count 0).
fn arrangement(text: &str) -> TokenStream {
    let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
    let count = lit(digits.parse::<u8>().unwrap_or(0));
    let element = format_ident!(
        "{}",
        text.get(digits.len()..)
            .unwrap_or_default()
            .to_ascii_uppercase()
    );
    quote! { Some(Arrangement { count: #count, element: ElementSize::#element }) }
}

/// The element index `<index>` (`<index1>`) of an `imm5` form: the bits
/// above the lowest set bit, which gives the element size.
fn imm5_index(s: &Slot<'_>) -> Result<TokenStream> {
    let imm5 = s.field("imm5")?;
    Ok(quote! {{
        let imm5 = #imm5;
        imm5 >> (imm5.trailing_zeros() + 1)
    }})
}

/// `<index2>` of `INS` (element): `imm4` without the bits below the
/// element size `imm5` gives.
fn imm4_index(s: &Slot<'_>) -> Result<TokenStream> {
    let (imm5, imm4) = (s.field("imm5")?, s.field("imm4")?);
    Ok(quote! { (#imm4 >> #imm5.trailing_zeros()) })
}

/// Parts of a register given rather than read from the key's displays.
#[derive(Default)]
struct Given {
    /// The class, a `RegisterClass` expression.
    class: Option<TokenStream>,
    /// The number, an integer expression.
    number: Option<TokenStream>,
    /// The arrangement, an `Option<Arrangement>` expression.
    arrangement: Option<TokenStream>,
    /// The element index, an integer expression.
    index: Option<TokenStream>,
}

/// The register a register key names, its parts `given` or read from the
/// key's displays (the index of `imm5` forms by [`imm5_index`], others
/// concatenated).
fn register_operand(s: &Slot<'_>, given: Given) -> Result<TokenStream> {
    let key = RegisterKey::parse(&s.key).ok_or_else(|| format!("{}: `{}`", s.form, s.key))?;
    let class = match (given.class, key.class) {
        (Some(class), _) => class,
        (None, Part::Fixed(letter)) => class(letter),
        (None, Part::Display(display)) => {
            s.match_names(display, class, &quote! { RegisterClass::V })?
        }
    };
    let number = match given.number {
        Some(number) => number,
        None => s.display(key.number)?.0,
    };
    let arrangement = match (given.arrangement, key.arrangement) {
        (_, None) => quote! { None },
        (Some(arrangement), Some(_)) => arrangement,
        (None, Some(Part::Fixed(text))) => arrangement(&text.to_ascii_lowercase()),
        (None, Some(Part::Display(display))) => {
            s.match_names(display, arrangement, &quote! { None })?
        }
    };
    let index = match (given.index, key.index) {
        (_, None) => quote! { None },
        (Some(index), Some(_)) => quote! { Some((#index) as u8) },
        (None, Some(Part::Fixed(value))) => {
            let value = lit(value.parse::<u8>()?);
            quote! { Some(#value) }
        }
        (None, Some(Part::Display(display))) => {
            let value = if display == "<index2>" {
                imm4_index(s)?
            } else if s.fields.iter().any(|field| field == "imm5") {
                imm5_index(s)?
            } else {
                s.display(display)?.0
            };
            quote! { Some((#value) as u8) }
        }
    };
    Ok(push(&quote! {
        Operand::Register(Register {
            class: #class,
            number: (#number) as u8,
            arrangement: #arrangement,
            index: #index,
            predication: None,
        })
    }))
}

/// A SIMD&FP register as its key reads ([`register_operand`]).
fn simd_register(s: &Slot<'_>) -> Result<TokenStream> {
    register_operand(s, Given::default())
}

/// `<V><d>` of `FMAXNMV`, `FMAXV`, `FMINNMV`, `FMINV` (half precision),
/// where `<V>` is the fixed `H`.
fn half_scalar(s: &Slot<'_>) -> Result<TokenStream> {
    register_operand(
        s,
        Given {
            class: Some(class("H")),
            ..Given::default()
        },
    )
}

/// `Some(Arrangement { … })` of `count` elements of `8 << log2` bits.
fn computed_arrangement(count: &TokenStream, log2: &TokenStream) -> TokenStream {
    quote! {
        Some(Arrangement {
            count: (#count) as u8,
            element: match #log2 {
                0 => ElementSize::B,
                1 => ElementSize::H,
                2 => ElementSize::S,
                _ => ElementSize::D,
            },
        })
    }
}

/// `<T>` of `FAMAX`, `FAMIN`, `FSCALE` (vector), whose `size` is `1x` and
/// whose arrangements AARCHMRS names by `size<0>` alone: words or
/// doublewords by `size<0>`, a 64- or 128-bit vector by `Q`.
fn float_vector(s: &Slot<'_>) -> Result<TokenStream> {
    let (size, q) = (s.field("size")?, s.field("Q")?);
    let arrangement = computed_arrangement(
        &quote! { (2 << #q) >> (#size & 1) },
        &quote! { 2 + (#size & 1) },
    );
    register_operand(s, arranged(arrangement))
}

/// Only the arrangement given.
fn arranged(arrangement: TokenStream) -> Given {
    Given {
        arrangement: Some(arrangement),
        ..Given::default()
    }
}

/// `<Tb>` of `FCVTXN` (vector), which AARCHMRS names without values:
/// `2S`, or `4S` when `Q` is set.
fn single_vector(s: &Slot<'_>) -> Result<TokenStream> {
    let q = s.field("Q")?;
    let arrangement = computed_arrangement(&quote! { 2 << #q }, &quote! { 2 });
    register_operand(s, arranged(arrangement))
}

/// `<Ta>` of `USHLL`, which AARCHMRS names without values: 128 bits of
/// elements twice the size `immh`'s highest set bit gives.
fn long_wide(s: &Slot<'_>) -> Result<TokenStream> {
    let immh = s.field("immh")?;
    let arrangement = computed_arrangement(
        &quote! { 8 >> #immh.ilog2() },
        &quote! { #immh.ilog2() + 1 },
    );
    register_operand(s, arranged(arrangement))
}

/// `<Tb>` of `USHLL`: 64 or 128 bits (`Q`) of elements of the size
/// `immh`'s highest set bit gives.
fn long_narrow(s: &Slot<'_>) -> Result<TokenStream> {
    let (immh, q) = (s.field("immh")?, s.field("Q")?);
    let arrangement = computed_arrangement(
        &quote! { (8 << #q) >> #immh.ilog2() },
        &quote! { #immh.ilog2() },
    );
    register_operand(s, arranged(arrangement))
}

/// `V<m>.<Ts>[<index>]` of integer by-element forms: for halfword elements
/// (`size == 01`) `Rm` is 4 bits and `M` the index's low bit (`H:L:M`);
/// for words the register is `M:Rm` and the index `H:L`.
fn integer_element(s: &Slot<'_>) -> Result<TokenStream> {
    let (size, m, rm) = (s.field("size")?, s.field("M")?, s.field("Rm")?);
    let (h, l) = (s.field("H")?, s.field("L")?);
    register_operand(
        s,
        Given {
            number: Some(quote! { if #size == 1 { #rm } else { (#m << 4) | #rm } }),
            index: Some(
                quote! { if #size == 1 { (#h << 2) | (#l << 1) | #m } else { (#h << 1) | #l } },
            ),
            ..Given::default()
        },
    )
}

/// Only the element index given.
fn indexed(index: TokenStream) -> Given {
    Given {
        index: Some(index),
        ..Given::default()
    }
}

/// `<Vm>.<Ts>[<index>]` of `FCMLA` (element): index `H:L` for halfwords,
/// `H` for words.
fn complex_element(s: &Slot<'_>) -> Result<TokenStream> {
    let (size, h, l) = (s.field("size")?, s.field("H")?, s.field("L")?);
    register_operand(
        s,
        indexed(quote! { if #size == 1 { (#h << 1) | #l } else { #h } }),
    )
}

/// `<Vm>.<Ts>[<index>]` of single and double precision by-element forms:
/// index `H:L` for singles (`sz == 0`), `H` for doubles.
fn float_element(s: &Slot<'_>) -> Result<TokenStream> {
    let (sz, h, l) = (s.field("sz")?, s.field("H")?, s.field("L")?);
    register_operand(
        s,
        indexed(quote! { if #sz == 0 { (#h << 1) | #l } else { #h } }),
    )
}

/// `<Vm>.B[<index>]` of the FP8 by-element multiply-adds (`FMLALB`,
/// `FMLALLBB`, …): the register is `Rm<2:0>` and the index
/// `H:L:M:Rm<3>` (AARCHMRS gives `Rm` whole to both).
fn byte_element(s: &Slot<'_>) -> Result<TokenStream> {
    let (rm, h, l, m) = (s.field("Rm")?, s.field("H")?, s.field("L")?, s.field("M")?);
    register_operand(
        s,
        Given {
            number: Some(quote! { #rm & 7 }),
            index: Some(quote! { (#h << 3) | (#l << 2) | (#m << 1) | (#rm >> 3) }),
            ..Given::default()
        },
    )
}

/// `<Vm>[<index>]` of `LUTI4` (`16B`): the index is `len<1>`, `len<0>`
/// being fixed at 1.
fn nibble_table_index(s: &Slot<'_>) -> Result<TokenStream> {
    let len = s.field("len")?;
    register_operand(s, indexed(quote! { #len >> 1 }))
}

/// `<R><n>` of `DUP`/`INS` (general): X for doubleword elements
/// (`imm5 == x1000`), else W.
fn general_by_element(s: &Slot<'_>) -> Result<TokenStream> {
    let (imm5, rn) = (s.field("imm5")?, s.field("Rn")?);
    let (x, w) = (register("X", &rn), register("W", &rn));
    Ok(quote! { ops.push(if #imm5 & 0xf == 8 { #x } else { #w }); })
}

/// A table list `{ <Vn>.16B, <Vn+1>.16B }`: as many consecutive registers
/// (modulo 32) as the key names, written with commas as LLVM writes
/// Advanced SIMD lists.
fn table_list(s: &Slot<'_>) -> Result<TokenStream> {
    let count = lit(u8::try_from(s.key.matches('<').count())?);
    let element = s
        .key
        .split_once('.')
        .and_then(|(_, rest)| rest.split([',', ' ', '}']).next())
        .ok_or_else(|| format!("{}: `{}`", s.form, s.key))?;
    let arrangement = arrangement(&element.to_ascii_lowercase());
    let (number, _) = s.value()?;
    Ok(push(&quote! {
        Operand::List(RegisterList {
            first: Register {
                class: RegisterClass::V,
                number: (#number) as u8,
                arrangement: #arrangement,
                index: None,
                predication: None,
            },
            count: #count,
            stride: 1,
            style: ListStyle::Commas,
        })
    }))
}

/// Instructions whose `immh:immb` is the shift plus the element size; the
/// others (right shifts, fixed-point conversions) encode twice the element
/// size minus the shift.
const LEFT_SHIFTS: &[&str] = &["SHL", "SLI", "SQSHL", "SQSHLU", "UQSHL", "SSHLL", "USHLL"];

/// `#<shift>`, `#<fbits>` of shifts by immediate: from `immh:immb` and the
/// element size `immh`'s highest set bit gives; hex.
fn shift_amount(s: &Slot<'_>) -> Result<TokenStream> {
    let immh = s.field("immh")?;
    let (value, _) = s.value()?;
    let mnemonic = s.instruction.name.split('_').next().unwrap_or_default();
    let amount = if LEFT_SHIFTS.contains(&mnemonic) {
        quote! { (#value) - esize }
    } else {
        quote! { 2 * esize - (#value) }
    };
    let operand = unsigned(&amount);
    Ok(quote! {{
        let esize = 8u32 << #immh.ilog2();
        ops.push(#operand);
    }})
}

/// `#<fbits>` of conversions between floating-point and fixed-point
/// general registers: `64 - scale`; hex.
fn fixed_point_bits(s: &Slot<'_>) -> Result<TokenStream> {
    let (scale, _) = s.value()?;
    Ok(push(&unsigned(&quote! { 64 - #scale })))
}

/// The slot's fields, concatenated, as an unsigned hex immediate.
fn hex(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    Ok(push(&unsigned(&value)))
}

/// `#<index>` of `EXT`: the byte index `imm4` (`Q` only says whether its
/// top bit may be set); hex.
fn byte_index(s: &Slot<'_>) -> Result<TokenStream> {
    let imm4 = s.field("imm4")?;
    Ok(push(&unsigned(&imm4)))
}

/// A decimal immediate whose value is the text of the slot's value-named
/// alternative (`#<shift>` of `SHLL`, `#<rotate>` of `FCADD`/`FCMLA`), as
/// LLVM writes them.
fn named_decimal(s: &Slot<'_>, display: &str) -> Result<TokenStream> {
    let value = s.match_names(
        display,
        |text| {
            let value = lit(text.parse::<u32>().unwrap_or(0));
            quote! { #value }
        },
        &quote! { 0 },
    )?;
    Ok(push(&decimal(&value)))
}

fn shll_shift(s: &Slot<'_>) -> Result<TokenStream> {
    named_decimal(s, "<shift>")
}

fn rotation(s: &Slot<'_>) -> Result<TokenStream> {
    named_decimal(s, "<rotate>")
}

/// `{, LSL #<amount>}` of `MOVI`, `MVNI`, `ORR`, `BIC` (vector, immediate):
/// bytes `cmode<1>` (halfwords) or `cmode<2:1>` (words), left out for
/// `LSL #0` as LLVM does.
fn optional_lsl(s: &Slot<'_>) -> Result<TokenStream> {
    let cmode = s.field("cmode")?;
    let bits = lit(if s.instruction.name.ends_with("_hl") {
        1u32
    } else {
        3
    });
    Ok(quote! {{
        let amount = (((#cmode >> 1) & #bits) * 8) as u8;
        if amount != 0 {
            ops.push(Operand::Shift(Shift { kind: ShiftKind::Lsl, amount }));
        }
    }})
}

/// `MSL #<amount>` of `MOVI`, `MVNI` (shifting ones): 8 or 16 by
/// `cmode<0>`.
fn msl(s: &Slot<'_>) -> Result<TokenStream> {
    let cmode = s.field("cmode")?;
    Ok(push(
        &quote! { Operand::Shift(Shift { kind: ShiftKind::Msl, amount: (8 << (#cmode & 1)) as u8 }) },
    ))
}

/// `{, LSL #0}` of `MOVI` (8-bit): LLVM never writes it.
#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn nothing(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(TokenStream::new())
}

/// `#0` of comparisons with zero.
#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn zero(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&decimal(&quote! { 0 })))
}

/// `#0.0` of floating-point comparisons with zero: an exact constant, as
/// LLVM writes it.
#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn float_zero(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(
        &quote! { Operand::Float(Float { value: 0.0, exact: true }) },
    ))
}

/// `#<imm>` of `FMOV` (immediate, scalar and vector): `VFPExpandImm` of
/// the 8 bits, written with eight decimals as LLVM does.
fn fp_immediate(s: &Slot<'_>) -> Result<TokenStream> {
    let (imm8, _) = s.value()?;
    Ok(push(&quote! {
        Operand::Float(Float { value: pseudocode::vfp_expand_imm(#imm8), exact: false })
    }))
}

/// `#<imm>` of `MOVI` (64-bit scalar and `2D`): each bit of `imm8` a byte
/// of ones (`AdvSIMDExpandImm` with `op == 1`, `cmode == 1110`), written as
/// LLVM's `%#016llx`.
fn byte_mask(s: &Slot<'_>) -> Result<TokenStream> {
    let (imm8, _) = s.value()?;
    Ok(push(&quote! {
        Operand::Immediate(
            Immediate::unsigned(pseudocode::adv_simd_expand_imm(1, 0b1110, #imm8)).padded_hex()
        )
    }))
}

/// The eight bits `a:b:c:d:e:f:g:h` of modified immediates.
const ABCDEFGH: &[&str] = &["a", "b", "c", "d", "e", "f", "g", "h"];

/// The forms [`float_vector`] reads.
const FLOAT_VECTOR: &[&str] = &[
    "FAMAX_asimdsame_only",
    "FAMIN_asimdsame_only",
    "FSCALE_asimdsame_only",
];

pub const SYMBOLS: &[Symbol] = &[
    // Scalar registers named by their class letter.
    any("<Hd>", simd_register),
    any("<Hn>", simd_register),
    any("<Hm>", simd_register),
    any("<Ha>", simd_register),
    any("<Sd>", simd_register),
    any("<Sn>", simd_register),
    any("<Sm>", simd_register),
    any("<Sa>", simd_register),
    any("<Dd>", simd_register),
    any("<Dn>", simd_register),
    any("<Dm>", simd_register),
    any("<Da>", simd_register),
    any("<Qd>", simd_register),
    any("<Qn>", simd_register),
    any("D<d>", simd_register),
    any("D<n>", simd_register),
    any("D<m>", simd_register),
    any("H<d>", simd_register),
    any("S<d>", simd_register),
    // Scalar registers of a size the encoding selects.
    any("<V><d>", simd_register),
    fields("<V><d>", &["Rd"], half_scalar),
    any("<V><n>", simd_register),
    any("<V><m>", simd_register),
    any("<Va><d>", simd_register),
    any("<Va><n>", simd_register),
    any("<Vb><d>", simd_register),
    any("<Vb><n>", simd_register),
    any("<Vb><m>", simd_register),
    // Vectors.
    any("<Vd>.<T>", simd_register),
    any("<Vn>.<T>", simd_register),
    any("<Vm>.<T>", simd_register),
    any("<Vd>.<Ta>", simd_register),
    any("<Vn>.<Ta>", simd_register),
    any("<Vm>.<Ta>", simd_register),
    any("<Vd>.<Tb>", simd_register),
    any("<Vn>.<Tb>", simd_register),
    any("<Vm>.<Tb>", simd_register),
    any("<Vd>.16B", simd_register),
    any("<Vn>.16B", simd_register),
    any("<Vm>.16B", simd_register),
    any("<Va>.16B", simd_register),
    any("<Vd>.8H", simd_register),
    any("<Vn>.8H", simd_register),
    any("<Vm>.8H", simd_register),
    any("<Vd>.4S", simd_register),
    any("<Vn>.4S", simd_register),
    any("<Vm>.4S", simd_register),
    any("<Va>.4S", simd_register),
    any("<Vd>.2D", simd_register),
    any("<Vn>.2D", simd_register),
    any("<Vm>.2D", simd_register),
    any("<Vn>.2H", simd_register),
    // Elements.
    any("<Vd>.<Ts>[<index>]", simd_register),
    any("<Vd>.<Ts>[<index1>]", simd_register),
    any("<Vn>.<Ts>[<index>]", simd_register),
    any("<Vn>.<Ts>[<index2>]", simd_register),
    any("<Vn>.<T>[<index>]", simd_register),
    any("<Vn>.D[<index>]", simd_register),
    any("<Vn>.S[<index>]", simd_register),
    any("<Vd>.D[1]", simd_register),
    any("<Vn>.D[1]", simd_register),
    any("<Vm>.B[<index>]", byte_element),
    any("<Vm>.H[<index>]", simd_register),
    any("<Vm>.S[<imm2>]", simd_register),
    any("<Vm>.2B[<index>]", simd_register),
    any("<Vm>.2H[<index>]", simd_register),
    any("<Vm>.4B[<index>]", simd_register),
    any("<Vm>[<index>]", simd_register),
    forms("<Vm>[<index>]", &["LUTI4_asimdtbl_L5"], nibble_table_index),
    any("V<m>.<Ts>[<index>]", integer_element),
    fields(
        "<Vm>.<Ts>[<index>]",
        &["M", "Rm", "size", "H", "L"],
        complex_element,
    ),
    fields(
        "<Vm>.<Ts>[<index>]",
        &["M", "Rm", "sz", "L", "H"],
        float_element,
    ),
    any("<R><n>", general_by_element),
    // Arrangements AARCHMRS does not name by value.
    forms("<Vd>.<T>", FLOAT_VECTOR, float_vector),
    forms("<Vn>.<T>", FLOAT_VECTOR, float_vector),
    forms("<Vm>.<T>", FLOAT_VECTOR, float_vector),
    forms("<Vd>.<Tb>", &["FCVTXN_asimdmisc_N"], single_vector),
    forms("<Vd>.<Ta>", &["USHLL_asimdshf_L"], long_wide),
    forms("<Vn>.<Tb>", &["USHLL_asimdshf_L"], long_narrow),
    // Table lists.
    any("{<Vn>.16B }", table_list),
    any("{<Vn>.16B, <Vn+1>.16B }", table_list),
    any("{<Vn>.16B, <Vn+1>.16B, <Vn+2>.16B }", table_list),
    any(
        "{<Vn>.16B, <Vn+1>.16B, <Vn+2>.16B, <Vn+3>.16B }",
        table_list,
    ),
    any("{<Vn>.8H }", table_list),
    any("{<Vn1>.8H, <Vn2>.8H }", table_list),
    // Immediates.
    fields("#<shift>", &["immh", "immb"], shift_amount),
    fields("#<fbits>", &["immh", "immb"], shift_amount),
    fields("#<shift>", &["size"], shll_shift),
    fields("#<fbits>", &["scale"], fixed_point_bits),
    any("#<imm6>", hex),
    any("#<imm8>", hex),
    fields("#<index>", &["Q", "imm4"], byte_index),
    any("#<rotate>", rotation),
    fields("#<imm>", &["imm8"], fp_immediate),
    fields("#<imm>", ABCDEFGH, fp_immediate),
    Symbol {
        key: "#<imm>",
        fields: ABCDEFGH,
        forms: &["MOVI_asimdimm_D_ds", "MOVI_asimdimm_D2_d"],
        build: Build::Operands(byte_mask),
    },
    any("{, LSL #<amount>}", optional_lsl),
    any("{, LSL #0}", nothing),
    any("MSL #<amount>", msl),
    any("#0", zero),
    any("#0.0", float_zero),
    // Mnemonic suffixes.
    Symbol {
        key: "{2}",
        fields: &["Q"],
        forms: &[],
        build: Build::Text(&["", "2"]),
    },
    Symbol {
        key: "<bt>",
        fields: &["Q"],
        forms: &[],
        build: Build::Text(&["b", "t"]),
    },
];
