//! Symbols of the SME groups (`sme`): ZA tiles, tile slices and array
//! vectors, multi-vector register lists, the lookup table ZT0, and the SME
//! loads and stores.
//!
//! Arm's assembly rules do not say which field values the size specifiers
//! (`<T>`, `<Tb>`) stand for; the rules here follow the encodings' decode
//! (`esize`) and are checked against LLVM.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::vector::vector_memory;
use super::{Build, Slot, Symbol, push, register, unsigned};
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

/// A symbol limited to `forms`: SME encodings whose key the shared vector
/// symbols read with another meaning.
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

/// The error for a slot a builder cannot read.
fn unexpected(s: &Slot<'_>) -> Box<dyn std::error::Error> {
    format!("{}: unexpected `{}` {:?}", s.form, s.key, s.fields).into()
}

/// The slot's first field whose name starts with `prefix`.
fn field_named<'s>(s: &'s Slot<'_>, prefix: &str) -> Result<&'s str> {
    s.fields
        .iter()
        .find(|name| name.starts_with(prefix))
        .map(String::as_str)
        .ok_or_else(|| unexpected(s))
}

/// The slot's index fields (`i1`, `i3h`, `i4A`…) concatenated, first most
/// significant.
fn index(s: &Slot<'_>) -> Result<Option<TokenStream>> {
    let mut value: Option<TokenStream> = None;
    for name in s.fields.iter().filter(|name| name.starts_with('i')) {
        let field = s.field(name)?;
        let width = lit(s.width(name)?);
        value = Some(match value {
            None => field,
            Some(high) => quote! { ((#high) << #width) | #field },
        });
    }
    Ok(value)
}

/// `ElementSize` of an element index expression (0 `B` … 3 `D`).
fn element_of(index: &TokenStream) -> TokenStream {
    quote! {
        match #index {
            0 => ElementSize::B,
            1 => ElementSize::H,
            2 => ElementSize::S,
            _ => ElementSize::D,
        }
    }
}

/// `ElementSize` of a size letter.
fn letter(s: &Slot<'_>, letter: char) -> Result<TokenStream> {
    let name = match letter {
        'B' => "B",
        'H' => "H",
        'S' => "S",
        'D' => "D",
        'Q' => "Q",
        _ => return Err(unexpected(s)),
    };
    let name = format_ident!("{name}");
    Ok(quote! { ElementSize::#name })
}

/// The element size a key gives after its first `.`: a letter (`.H`), a
/// size specifier (`.<T>`, `.<Tb>`) or none.
///
/// Size specifiers by field: `size` is the element size of `<T>`; `sz`
/// picks `S`/`D` for `<T>` (ZA accumulators, `FMLA` vectors) and `B`/`H`
/// for `<Tb>` (four-way products); `tsize` `01` picks `S` for `<Tb>`, `1x`
/// `D` (sources of the four-register narrowing shifts).
fn element(s: &Slot<'_>) -> Result<Option<TokenStream>> {
    let Some((_, rest)) = s.key.split_once('.') else {
        return Ok(None);
    };
    let narrow = rest.starts_with("<Tb>");
    if !narrow && !rest.starts_with("<T>") {
        return match rest.chars().next() {
            Some(c @ ('B' | 'H' | 'S' | 'D' | 'Q')) => letter(s, c).map(Some),
            _ => Ok(None),
        };
    }
    let index = if !narrow && s.fields.iter().any(|name| name == "size") {
        s.field("size")?
    } else if s.fields.iter().any(|name| name == "sz") {
        let sz = s.field("sz")?;
        if narrow {
            sz
        } else {
            quote! { 2 + #sz }
        }
    } else if narrow && s.fields.iter().any(|name| name == "tsize") {
        let tsize = s.field("tsize")?;
        quote! { 2 + u32::from(#tsize != 1) }
    } else {
        return Err(unexpected(s));
    };
    Ok(Some(element_of(&index)))
}

/// A Z register (a `Register` expression) numbered `number` with
/// `element` and lane `index`.
fn z_register(
    number: &TokenStream,
    element: Option<&TokenStream>,
    index: Option<&TokenStream>,
) -> TokenStream {
    let arrangement = element.map_or_else(
        || quote! { None },
        |element| quote! { Some(Arrangement { count: 0, element: #element }) },
    );
    let index = index.map_or_else(|| quote! { None }, |index| quote! { Some((#index) as u8) });
    quote! {
        Register {
            class: RegisterClass::Z,
            number: (#number) as u8,
            arrangement: #arrangement,
            index: #index,
            predication: None,
        }
    }
}

/// Code pushing the Z register `register`.
fn push_z(register: &TokenStream) -> TokenStream {
    push(&quote! { Operand::Register(#register) })
}

/// One Z register, `<Zm>.H`, `<Zm>.B[<index>]`, `<Zn>[<index>]`: the
/// register field as is (4-bit fields name `z0`…`z15`), the element from
/// the key, the lane from the index fields.
fn vector(s: &Slot<'_>) -> Result<TokenStream> {
    let number = s.field(field_named(s, "Z")?)?;
    let element = element(s)?;
    let index = index(s)?;
    Ok(push_z(&z_register(
        &number,
        element.as_ref(),
        index.as_ref(),
    )))
}

/// `<Zn>` of a quarter-tile outer product (`FMOP4A`…): an even register
/// of the lower half, `Zn:'0'`.
fn quarter_n(s: &Slot<'_>) -> Result<TokenStream> {
    let number = s.field(field_named(s, "Zn")?)?;
    let element = element(s)?;
    Ok(push_z(&z_register(
        &quote! { (#number) << 1 },
        element.as_ref(),
        None,
    )))
}

/// `<Zm>` of a quarter-tile outer product: an even register of the upper
/// half, `'1':Zm:'0'`.
fn quarter_m(s: &Slot<'_>) -> Result<TokenStream> {
    let number = s.field(field_named(s, "Zm")?)?;
    let element = element(s)?;
    Ok(push_z(&z_register(
        &quote! { 16 | ((#number) << 1) },
        element.as_ref(),
        None,
    )))
}

/// `<Zk>` of the sparse outer products (`FTMOPA`…): `z20`…`z23` or
/// `z28`…`z31` by `K`, `'1':K:'1':Zk`, written without an element when
/// it is indexed (`z23[3]`).
fn sparse_index(s: &Slot<'_>) -> Result<TokenStream> {
    let (k, zk) = (s.field("K")?, s.field("Zk")?);
    let number = quote! { 20 | ((#k) << 3) | #zk };
    let element = element(s)?;
    let index = index(s)?;
    Ok(push_z(&z_register(
        &number,
        element.as_ref(),
        index.as_ref(),
    )))
}

/// `<Zd>.<T>` of the narrowing conversions (`SQCVT`… from four
/// registers): `sz` picks `B` or `H`.
fn narrow_vector(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, sz) = (s.field(field_named(s, "Z")?)?, s.field("sz")?);
    let element = element_of(&sz);
    Ok(push_z(&z_register(&number, Some(&element), None)))
}

/// Number of registers and distance between them of a list key:
/// `{<Zn1>.H-<Zn4>.H }` is 4 consecutive registers, `{<Zt1>.B, <Zt2>.B }`
/// with a `T` (or `D`) field 2 registers 8 apart.
fn list_shape(s: &Slot<'_>) -> Result<(u32, u32, bool)> {
    let count = s
        .key
        .rsplit("<Z")
        .next()
        .and_then(|last| last.chars().find(char::is_ascii_digit))
        .and_then(|digit| digit.to_digit(10))
        .ok_or_else(|| unexpected(s))?;
    let strided = s.fields.iter().any(|name| name == "T" || name == "D");
    let stride = if strided { 16 / count } else { 1 };
    Ok((count, stride, strided))
}

/// A Z register list whose first register is `first`.
fn z_list(s: &Slot<'_>, first: &TokenStream, element: Option<&TokenStream>) -> Result<TokenStream> {
    let (count, stride, strided) = list_shape(s)?;
    let index = index(s)?;
    let first = z_register(first, element, index.as_ref());
    let style = format_ident!("{}", if strided { "Commas" } else { "Range" });
    let (count, stride) = (lit(count), lit(stride));
    Ok(push(&quote! {
        Operand::List(RegisterList {
            first: #first,
            count: #count,
            stride: #stride,
            style: ListStyle::#style,
        })
    }))
}

/// The first register of a list: for consecutive lists the register field
/// as is when it has 5 bits or the count is not a power of two (triples:
/// `z0`…`z7`), else shifted left by log2 of the count (`Zn:'0'` for
/// pairs, `Zn:'00'` for quads); for strided lists `T:'0':Zt` (or
/// `D:'0':Zd`), the high bit selecting the upper half.
fn list_first(s: &Slot<'_>) -> Result<TokenStream> {
    let name = field_named(s, "Z")?;
    let (count, _, strided) = list_shape(s)?;
    let number = s.field(name)?;
    if strided {
        let high = s.field(if s.fields.iter().any(|f| f == "T") {
            "T"
        } else {
            "D"
        })?;
        return Ok(quote! { ((#high) << 4) | #number });
    }
    if s.width(name)? == 5 || !count.is_power_of_two() {
        return Ok(number);
    }
    let shift = lit(count.ilog2());
    Ok(quote! { (#number) << #shift })
}

/// A Z register list: `{ z0.h - z3.h }`, `{ z1.b, z9.b }`, `{ z6, z7 }[1]`.
/// LLVM writes consecutive lists as ranges (the printer applies its rule
/// for pairs and wrapping lists) and strided lists with commas.
fn list(s: &Slot<'_>) -> Result<TokenStream> {
    let first = list_first(s)?;
    let element = element(s)?;
    z_list(s, &first, element.as_ref())
}

/// `{<Zm1>.H-<Zm2>.H }` (any element) of a quarter-tile outer product: a
/// pair in the upper half, `'1':Zm:'0'`.
fn quarter_m_list(s: &Slot<'_>) -> Result<TokenStream> {
    let number = s.field(field_named(s, "Zm")?)?;
    let element = element(s)?;
    z_list(s, &quote! { 16 | ((#number) << 1) }, element.as_ref())
}

/// The source list of the narrowing conversions: `sz` picks `S` or `D`.
fn narrow_source_list(s: &Slot<'_>) -> Result<TokenStream> {
    let first = list_first(s)?;
    let sz = s.field("sz")?;
    let element = element_of(&quote! { 2 + #sz });
    z_list(s, &first, Some(&element))
}

/// A predicate-as-counter `pn8`…`pn15` (`<PNg>`, `<PNv>`), zeroing for
/// `/Z`.
fn counter(s: &Slot<'_>) -> Result<TokenStream> {
    let number = s.field(field_named(s, "PN")?)?;
    let predication = if s.key.ends_with("/Z") {
        quote! { Some(Predication::Zeroing) }
    } else {
        quote! { None }
    };
    Ok(push(&quote! {
        Operand::Register(Register {
            class: RegisterClass::Pn,
            number: (8 + #number) as u8,
            arrangement: None,
            index: None,
            predication: #predication,
        })
    }))
}

/// A merging governing predicate `p0/m`…`p7/m` (`<Pn>/M`, `<Pm>/M`).
fn merging(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    Ok(push(&quote! {
        Operand::Register(Register {
            class: RegisterClass::P,
            number: (#number) as u8,
            arrangement: None,
            index: None,
            predication: Some(Predication::Merging),
        })
    }))
}

/// A whole ZA tile, `za3.s`: the tile field, the element from the key.
fn tile(s: &Slot<'_>) -> Result<TokenStream> {
    let (number, _) = s.value()?;
    let element = element(s)?.ok_or_else(|| unexpected(s))?;
    Ok(push(&quote! {
        Operand::Za(Za {
            tile: Some((#number) as u8),
            element: Some(#element),
            direction: None,
            slice: None,
        })
    }))
}

/// Offsets a ZA selection key writes: one, or a range of 2 or 4
/// (`<offs1>:<offs2>`, `<offs1>:<offs4>`).
fn range_length(key: &str) -> u32 {
    if key.contains("<offs4>") {
        4
    } else if key.contains("<offs2>") {
        2
    } else {
        1
    }
}

/// The selection of a ZA slice key: index register `w<base + field>`, the
/// first offset (the offset field, if any, times the range length) and
/// the last of a range, and the vector group of `VGx2`/`VGx4` (always
/// written by LLVM, also where Arm's syntax makes it optional).
fn selection(s: &Slot<'_>, register: &str, base: u32, offset: Option<&str>) -> Result<TokenStream> {
    let index = s.field(register)?;
    let length = range_length(&s.key);
    let first = if let Some(name) = offset {
        let field = s.field(name)?;
        if length == 1 {
            field
        } else {
            quote! { (#field) * #length }
        }
    } else {
        quote! { 0u32 }
    };
    let last = if length == 1 {
        quote! { None }
    } else {
        let extra = lit(length - 1);
        quote! { Some((first + #extra) as u8) }
    };
    let group = if s.key.contains("VGx2") {
        quote! { Some(2) }
    } else if s.key.contains("VGx4") {
        quote! { Some(4) }
    } else {
        quote! { None }
    };
    let base = lit(base);
    Ok(quote! {{
        let first = #first;
        ZaSlice {
            index: (#base + #index) as u8,
            offset: first as u8,
            last: #last,
            group: #group,
        }
    }})
}

/// The offset field of a ZA selection: a field after the index register
/// one that is not a size field.
fn offset_field<'s>(s: &'s Slot<'_>, register: &str) -> Option<&'s str> {
    s.fields
        .iter()
        .skip_while(|name| *name != register)
        .skip(1)
        .find(|name| !matches!(name.as_str(), "sz" | "size"))
        .map(String::as_str)
}

/// A horizontal or vertical tile slice, `za1h.s[w13, 2]`,
/// `za0v.b[w12, 0x4:0x7]`: the tile field (tile 0 for `ZA0`), `V`, `w12`
/// plus `Rs`, and the offset.
fn tile_slice_value(s: &Slot<'_>) -> Result<TokenStream> {
    let tile = if s.key.trim_start_matches('{').starts_with("<ZA") {
        s.field(s.fields.first().ok_or_else(|| unexpected(s))?)?
    } else {
        quote! { 0u32 }
    };
    let vertical = s.field("V")?;
    let element = element(s)?.ok_or_else(|| unexpected(s))?;
    let selection = selection(s, "Rs", 12, offset_field(s, "Rs"))?;
    Ok(quote! {
        Za {
            tile: Some((#tile) as u8),
            element: Some(#element),
            direction: Some(if #vertical == 0 {
                SliceDirection::Horizontal
            } else {
                SliceDirection::Vertical
            }),
            slice: Some(#selection),
        }
    })
}

/// A tile slice (`MOVA`, `MOVAZ`).
fn tile_slice(s: &Slot<'_>) -> Result<TokenStream> {
    let value = tile_slice_value(s)?;
    Ok(push(&quote! { Operand::Za(#value) }))
}

/// A braced tile slice of the ZA loads and stores, `{za0h.b[w12, 0]}`.
fn braced_tile_slice(s: &Slot<'_>) -> Result<TokenStream> {
    let value = tile_slice_value(s)?;
    Ok(push(&quote! { Operand::ZaList(ZaList::Slice(#value)) }))
}

/// ZA array vectors, `za.s[w8, 7, vgx2]`, `za.d[w9, 0x0:0x3]`,
/// `za[w12, 0]`: `w8` plus `Rv` (`w12` plus `Rv` for the whole-array
/// vector `ZA[<Wv>, <offs>]` of `LDR`/`STR`), the element from the key.
fn array_vector(s: &Slot<'_>) -> Result<TokenStream> {
    let element = element(s)?;
    let element = element.map_or_else(|| quote! { None }, |element| quote! { Some(#element) });
    let base = if s.key.starts_with("ZA[") { 12 } else { 8 };
    let selection = selection(s, "Rv", base, offset_field(s, "Rv"))?;
    Ok(push(&quote! {
        Operand::Za(Za {
            tile: None,
            element: #element,
            direction: None,
            slice: Some(#selection),
        })
    }))
}

/// `ZERO { <mask> }`: the 64-bit tiles of `imm8`, printed with LLVM's
/// spellings.
fn tile_mask(s: &Slot<'_>) -> Result<TokenStream> {
    let (mask, _) = s.value()?;
    Ok(push(
        &quote! { Operand::ZaList(ZaList::Tiles((#mask) as u8)) },
    ))
}

/// `zt0`.
#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn table(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&register("Zt", &quote! { 0 })))
}

/// `{ zt0 }` of `ZERO { ZT0 }`.
#[allow(
    clippy::unnecessary_wraps,
    reason = "symbol builders share one signature"
)]
fn table_list(_: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&quote! {
        Operand::List(RegisterList {
            first: Register::new(RegisterClass::Zt, 0),
            count: 1,
            stride: 1,
            style: ListStyle::Commas,
        })
    }))
}

/// `zt0[48]` of `MOVT`: the byte offset `off3 * 8`.
fn table_element(s: &Slot<'_>) -> Result<TokenStream> {
    let (offset, _) = s.value()?;
    Ok(push(&quote! {
        Operand::Register(Register {
            class: RegisterClass::Zt,
            number: 0,
            arrangement: None,
            index: Some(((#offset) * 8) as u8),
            predication: None,
        })
    }))
}

/// `zt0[1, mul vl]` of `MOVT`; LLVM writes plain `zt0` for offset 0.
fn table_slice(s: &Slot<'_>) -> Result<TokenStream> {
    let (offset, _) = s.value()?;
    let plain = register("Zt", &quote! { 0 });
    Ok(quote! {
        ops.push(match #offset {
            0 => #plain,
            offset => Operand::TableSlice(offset as u8),
        });
    })
}

/// A memory operand with base `Rn` (`sp` for 31) and `offset`.
fn memory(s: &Slot<'_>, offset: &TokenStream) -> Result<TokenStream> {
    let base = s.field("Rn")?;
    Ok(quote! {
        Operand::Memory(Memory {
            base: Register::new(RegisterClass::Xsp, (#base) as u8),
            offset: #offset,
            writeback: Writeback::None,
        })
    })
}

/// `[<Xn|SP>]`.
fn base_only(s: &Slot<'_>) -> Result<TokenStream> {
    Ok(push(&memory(s, &quote! { Offset::None })?))
}

/// `[<Xn|SP>{, #<offs>, MUL VL}]` of `LDR`/`STR` (array vector): `off4`
/// vectors, the same offset as the vector's; LLVM leaves out 0.
fn array_offset(s: &Slot<'_>) -> Result<TokenStream> {
    let offset = s.field("off4")?;
    let offset = quote! {
        match #offset {
            0 => Offset::None,
            multiple => Offset::VectorLength(i64::from(multiple)),
        }
    };
    Ok(push(&memory(s, &offset)?))
}

/// `#<const>` of the four-register narrowing shifts (`SQRSHR`…): the
/// shift `2 * esize - UInt(tsize:imm5)` of the source elements, 32 bits
/// for `tsize` `01`, else 64; hex.
fn narrowing_shift(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, _) = s.value()?;
    let tsize = s.field("tsize")?;
    Ok(push(&unsigned(&quote! {
        (if #tsize == 1 { 64 } else { 128 }) - (#value)
    })))
}

/// The quarter-tile outer products (`FMOP4A`, `SMOP4S`…), whose 3-bit
/// `Zn`/`Zm` fields name even registers of the lower and upper half.
const QUARTER_TILE: &[&str] = &[
    "bfmop4a_za32_zz_h1x1",
    "bfmop4a_za32_zz_h1x2",
    "bfmop4a_za32_zz_h2x1",
    "bfmop4a_za32_zz_h2x2",
    "bfmop4a_za_zz_h1x1",
    "bfmop4a_za_zz_h1x2",
    "bfmop4a_za_zz_h2x1",
    "bfmop4a_za_zz_h2x2",
    "bfmop4s_za32_zz_h1x1",
    "bfmop4s_za32_zz_h1x2",
    "bfmop4s_za32_zz_h2x1",
    "bfmop4s_za32_zz_h2x2",
    "bfmop4s_za_zz_h1x1",
    "bfmop4s_za_zz_h1x2",
    "bfmop4s_za_zz_h2x1",
    "bfmop4s_za_zz_h2x2",
    "fmop4a_za16_z8z8_b1x1",
    "fmop4a_za16_z8z8_b1x2",
    "fmop4a_za16_z8z8_b2x1",
    "fmop4a_za16_z8z8_b2x2",
    "fmop4a_za32_z8z8_b1x1",
    "fmop4a_za32_z8z8_b1x2",
    "fmop4a_za32_z8z8_b2x1",
    "fmop4a_za32_z8z8_b2x2",
    "fmop4a_za32_zz_h1x1",
    "fmop4a_za32_zz_h1x2",
    "fmop4a_za32_zz_h2x1",
    "fmop4a_za32_zz_h2x2",
    "fmop4a_za_zz_d1x1",
    "fmop4a_za_zz_d1x2",
    "fmop4a_za_zz_d2x1",
    "fmop4a_za_zz_d2x2",
    "fmop4a_za_zz_h1x1",
    "fmop4a_za_zz_h1x2",
    "fmop4a_za_zz_h2x1",
    "fmop4a_za_zz_h2x2",
    "fmop4a_za_zz_s1x1",
    "fmop4a_za_zz_s1x2",
    "fmop4a_za_zz_s2x1",
    "fmop4a_za_zz_s2x2",
    "fmop4s_za32_zz_h1x1",
    "fmop4s_za32_zz_h1x2",
    "fmop4s_za32_zz_h2x1",
    "fmop4s_za32_zz_h2x2",
    "fmop4s_za_zz_d1x1",
    "fmop4s_za_zz_d1x2",
    "fmop4s_za_zz_d2x1",
    "fmop4s_za_zz_d2x2",
    "fmop4s_za_zz_h1x1",
    "fmop4s_za_zz_h1x2",
    "fmop4s_za_zz_h2x1",
    "fmop4s_za_zz_h2x2",
    "fmop4s_za_zz_s1x1",
    "fmop4s_za_zz_s1x2",
    "fmop4s_za_zz_s2x1",
    "fmop4s_za_zz_s2x2",
    "smop4a_za32_zz_h1x1",
    "smop4a_za32_zz_h1x2",
    "smop4a_za32_zz_h2x1",
    "smop4a_za32_zz_h2x2",
    "smop4a_za_zz_b1x1",
    "smop4a_za_zz_b1x2",
    "smop4a_za_zz_b2x1",
    "smop4a_za_zz_b2x2",
    "smop4a_za_zz_h1x1",
    "smop4a_za_zz_h1x2",
    "smop4a_za_zz_h2x1",
    "smop4a_za_zz_h2x2",
    "smop4s_za32_zz_h1x1",
    "smop4s_za32_zz_h1x2",
    "smop4s_za32_zz_h2x1",
    "smop4s_za32_zz_h2x2",
    "smop4s_za_zz_b1x1",
    "smop4s_za_zz_b1x2",
    "smop4s_za_zz_b2x1",
    "smop4s_za_zz_b2x2",
    "smop4s_za_zz_h1x1",
    "smop4s_za_zz_h1x2",
    "smop4s_za_zz_h2x1",
    "smop4s_za_zz_h2x2",
    "sumop4a_za_zz_b1x1",
    "sumop4a_za_zz_b1x2",
    "sumop4a_za_zz_b2x1",
    "sumop4a_za_zz_b2x2",
    "sumop4a_za_zz_h1x1",
    "sumop4a_za_zz_h1x2",
    "sumop4a_za_zz_h2x1",
    "sumop4a_za_zz_h2x2",
    "sumop4s_za_zz_b1x1",
    "sumop4s_za_zz_b1x2",
    "sumop4s_za_zz_b2x1",
    "sumop4s_za_zz_b2x2",
    "sumop4s_za_zz_h1x1",
    "sumop4s_za_zz_h1x2",
    "sumop4s_za_zz_h2x1",
    "sumop4s_za_zz_h2x2",
    "umop4a_za32_zz_h1x1",
    "umop4a_za32_zz_h1x2",
    "umop4a_za32_zz_h2x1",
    "umop4a_za32_zz_h2x2",
    "umop4a_za_zz_b1x1",
    "umop4a_za_zz_b1x2",
    "umop4a_za_zz_b2x1",
    "umop4a_za_zz_b2x2",
    "umop4a_za_zz_h1x1",
    "umop4a_za_zz_h1x2",
    "umop4a_za_zz_h2x1",
    "umop4a_za_zz_h2x2",
    "umop4s_za32_zz_h1x1",
    "umop4s_za32_zz_h1x2",
    "umop4s_za32_zz_h2x1",
    "umop4s_za32_zz_h2x2",
    "umop4s_za_zz_b1x1",
    "umop4s_za_zz_b1x2",
    "umop4s_za_zz_b2x1",
    "umop4s_za_zz_b2x2",
    "umop4s_za_zz_h1x1",
    "umop4s_za_zz_h1x2",
    "umop4s_za_zz_h2x1",
    "umop4s_za_zz_h2x2",
    "usmop4a_za_zz_b1x1",
    "usmop4a_za_zz_b1x2",
    "usmop4a_za_zz_b2x1",
    "usmop4a_za_zz_b2x2",
    "usmop4a_za_zz_h1x1",
    "usmop4a_za_zz_h1x2",
    "usmop4a_za_zz_h2x1",
    "usmop4a_za_zz_h2x2",
    "usmop4s_za_zz_b1x1",
    "usmop4s_za_zz_b1x2",
    "usmop4s_za_zz_b2x1",
    "usmop4s_za_zz_b2x2",
    "usmop4s_za_zz_h1x1",
    "usmop4s_za_zz_h1x2",
    "usmop4s_za_zz_h2x1",
    "usmop4s_za_zz_h2x2",
];

/// The four-register narrowing conversions, whose `sz` picks `B`/`H` for
/// `<T>` and `S`/`D` for `<Tb>`.
const NARROWING_CONVERSION: &[&str] = &[
    "sqcvt_z_mz4_",
    "sqcvtu_z_mz4_",
    "sqcvtn_z_mz4_",
    "sqcvtun_z_mz4_",
    "uqcvt_z_mz4_",
    "uqcvtn_z_mz4_",
];

/// The SME symbols.
pub const SYMBOLS: &[Symbol] = &[
    fields("#<const>", &["tsize", "imm5"], narrowing_shift),
    fields("<PNg>", &["PNg"], counter),
    fields("<PNg>/Z", &["PNg"], counter),
    fields("<PNv>", &["PNv"], counter),
    fields("<Pm>/M", &["Pm"], merging),
    fields("<Pn>/M", &["Pn"], merging),
    any("<ZAd><HV>.D[<Ws>, <offs1>:<offs2>]", tile_slice),
    any("<ZAd><HV>.D[<Ws>, <offs1>:<offs4>]", tile_slice),
    any("<ZAd><HV>.D[<Ws>, <offs>]", tile_slice),
    any("<ZAd><HV>.H[<Ws>, <offs1>:<offs2>]", tile_slice),
    any("<ZAd><HV>.H[<Ws>, <offs1>:<offs4>]", tile_slice),
    any("<ZAd><HV>.H[<Ws>, <offs>]", tile_slice),
    any("<ZAd><HV>.Q[<Ws>, <offs>]", tile_slice),
    any("<ZAd><HV>.S[<Ws>, <offs1>:<offs2>]", tile_slice),
    any("<ZAd><HV>.S[<Ws>, <offs1>:<offs4>]", tile_slice),
    any("<ZAd><HV>.S[<Ws>, <offs>]", tile_slice),
    fields("<ZAda>.D", &["ZAda"], tile),
    fields("<ZAda>.H", &["ZAda"], tile),
    fields("<ZAda>.S", &["ZAda"], tile),
    any("<ZAn><HV>.D[<Ws>, <offs1>:<offs2>]", tile_slice),
    any("<ZAn><HV>.D[<Ws>, <offs1>:<offs4>]", tile_slice),
    any("<ZAn><HV>.D[<Ws>, <offs>]", tile_slice),
    any("<ZAn><HV>.H[<Ws>, <offs1>:<offs2>]", tile_slice),
    any("<ZAn><HV>.H[<Ws>, <offs1>:<offs4>]", tile_slice),
    any("<ZAn><HV>.H[<Ws>, <offs>]", tile_slice),
    any("<ZAn><HV>.Q[<Ws>, <offs>]", tile_slice),
    any("<ZAn><HV>.S[<Ws>, <offs1>:<offs2>]", tile_slice),
    any("<ZAn><HV>.S[<Ws>, <offs1>:<offs4>]", tile_slice),
    any("<ZAn><HV>.S[<Ws>, <offs>]", tile_slice),
    fields("<Zk>.B", &["K", "Zk"], sparse_index),
    fields("<Zk>[<index>]", &["K", "Zk", "i2"], sparse_index),
    fields("<Zm>.<Tb>", &["Zm", "sz"], vector),
    fields("<Zm>.B[<index>]", &["Zm", "i2"], vector),
    fields("<Zm>.B[<index>]", &["Zm", "i2h", "i2l"], vector),
    fields("<Zm>.B[<index>]", &["Zm", "i3h", "i3l"], vector),
    fields("<Zm>.B[<index>]", &["Zm", "i4A", "i4B", "i4C"], vector),
    fields("<Zm>.B[<index>]", &["Zm", "i4h", "i4l"], vector),
    fields("<Zm>.D[<index>]", &["Zm", "i1"], vector),
    fields("<Zm>.H[<index>]", &["Zm", "i1"], vector),
    fields("<Zm>.H[<index>]", &["Zm", "i2"], vector),
    fields("<Zm>.H[<index>]", &["Zm", "i3h", "i3l"], vector),
    fields("<Zm>.S[<index>]", &["Zm", "i2"], vector),
    fields("<Zn>.<Tb>", &["Zn", "sz"], vector),
    fields("<Zn>[<index>]", &["Zn", "i1"], vector),
    fields("<Zn>[<index>]", &["Zn", "i2"], vector),
    fields("<Zn>[<index>]", &["Zn", "i3"], vector),
    fields("<Zn>[<index>]", &["Zn", "i4"], vector),
    any("ZA.<T>[<Wv>, <offs1>:<offs4>]", array_vector),
    any("ZA.<T>[<Wv>, <offs1>:<offs4>{, VGx2}]", array_vector),
    any("ZA.<T>[<Wv>, <offs1>:<offs4>{, VGx4}]", array_vector),
    any("ZA.<T>[<Wv>, <offs>{, VGx2}]", array_vector),
    any("ZA.<T>[<Wv>, <offs>{, VGx4}]", array_vector),
    any("ZA.D[<Wv>, <offs1>:<offs2>, VGx2]", array_vector),
    any("ZA.D[<Wv>, <offs1>:<offs2>, VGx4]", array_vector),
    any("ZA.D[<Wv>, <offs1>:<offs2>]", array_vector),
    any("ZA.D[<Wv>, <offs1>:<offs4>, VGx2]", array_vector),
    any("ZA.D[<Wv>, <offs1>:<offs4>, VGx4]", array_vector),
    any("ZA.D[<Wv>, <offs1>:<offs4>]", array_vector),
    any("ZA.D[<Wv>, <offs1>:<offs4>{, VGx2}]", array_vector),
    any("ZA.D[<Wv>, <offs1>:<offs4>{, VGx4}]", array_vector),
    any("ZA.D[<Wv>, <offs>, VGx2]", array_vector),
    any("ZA.D[<Wv>, <offs>, VGx4]", array_vector),
    any("ZA.D[<Wv>, <offs>{, VGx2}]", array_vector),
    any("ZA.D[<Wv>, <offs>{, VGx4}]", array_vector),
    any("ZA.H[<Wv>, <offs1>:<offs2>]", array_vector),
    any("ZA.H[<Wv>, <offs1>:<offs2>{, VGx2}]", array_vector),
    any("ZA.H[<Wv>, <offs1>:<offs2>{, VGx4}]", array_vector),
    any("ZA.H[<Wv>, <offs>{, VGx2}]", array_vector),
    any("ZA.H[<Wv>, <offs>{, VGx4}]", array_vector),
    any("ZA.S[<Wv>, <offs1>:<offs2>]", array_vector),
    any("ZA.S[<Wv>, <offs1>:<offs2>{, VGx2}]", array_vector),
    any("ZA.S[<Wv>, <offs1>:<offs2>{, VGx4}]", array_vector),
    any("ZA.S[<Wv>, <offs1>:<offs4>]", array_vector),
    any("ZA.S[<Wv>, <offs1>:<offs4>{, VGx2}]", array_vector),
    any("ZA.S[<Wv>, <offs1>:<offs4>{, VGx4}]", array_vector),
    any("ZA.S[<Wv>, <offs>, VGx4]", array_vector),
    any("ZA.S[<Wv>, <offs>{, VGx2}]", array_vector),
    any("ZA.S[<Wv>, <offs>{, VGx4}]", array_vector),
    any("ZA0<HV>.B[<Ws>, <offs1>:<offs2>]", tile_slice),
    any("ZA0<HV>.B[<Ws>, <offs1>:<offs4>]", tile_slice),
    any("ZA0<HV>.B[<Ws>, <offs>]", tile_slice),
    any("ZA[<Wv>, <offs>]", array_vector),
    any("ZT0", table),
    fields("ZT0[<offs>]", &["off3"], table_element),
    fields("ZT0{[<offs>, MUL VL]}", &["off2"], table_slice),
    forms("[<Xn|SP>]", &["ldr_zt_br_", "str_zt_br_"], base_only),
    fields(
        "[<Xn|SP>{, #<offs>, MUL VL}]",
        &["Rn", "off4"],
        array_offset,
    ),
    // LD1Q/ST1Q of ZA: the shared base-plus-register shape.
    fields("[<Xn|SP>{, <Xm>, LSL #4}]", &["Rn", "Rm"], vector_memory),
    any("{<ZAt><HV>.D[<Ws>, <offs>] }", braced_tile_slice),
    any("{<ZAt><HV>.H[<Ws>, <offs>] }", braced_tile_slice),
    any("{<ZAt><HV>.Q[<Ws>, <offs>] }", braced_tile_slice),
    any("{<ZAt><HV>.S[<Ws>, <offs>] }", braced_tile_slice),
    fields("{<Zd1>.<T>, <Zd2>.<T> }", &["D", "Zd", "size"], list),
    fields(
        "{<Zd1>.<T>, <Zd2>.<T>, <Zd3>.<T>, <Zd4>.<T> }",
        &["D", "Zd", "size"],
        list,
    ),
    fields("{<Zd1>.<T>-<Zd2>.<T> }", &["Zd", "size"], list),
    fields("{<Zd1>.<T>-<Zd4>.<T> }", &["Zd", "size"], list),
    fields("{<Zd1>.B, <Zd2>.B, <Zd3>.B, <Zd4>.B }", &["D", "Zd"], list),
    fields("{<Zd1>.B-<Zd2>.B }", &["Zd"], list),
    fields("{<Zd1>.B-<Zd4>.B }", &["Zd"], list),
    fields("{<Zd1>.D-<Zd2>.D }", &["Zd"], list),
    fields("{<Zd1>.D-<Zd4>.D }", &["Zd"], list),
    fields("{<Zd1>.H, <Zd2>.H, <Zd3>.H, <Zd4>.H }", &["D", "Zd"], list),
    fields("{<Zd1>.H-<Zd2>.H }", &["Zd"], list),
    fields("{<Zd1>.H-<Zd4>.H }", &["Zd"], list),
    fields("{<Zd1>.Q-<Zd4>.Q }", &["Zd"], list),
    fields("{<Zd1>.S-<Zd2>.S }", &["Zd"], list),
    fields("{<Zd1>.S-<Zd4>.S }", &["Zd"], list),
    fields("{<Zdn1>.<T>-<Zdn2>.<T> }", &["Zdn", "size"], list),
    fields("{<Zdn1>.<T>-<Zdn4>.<T> }", &["Zdn", "size"], list),
    fields("{<Zdn1>.H-<Zdn2>.H }", &["Zdn"], list),
    fields("{<Zdn1>.H-<Zdn4>.H }", &["Zdn"], list),
    fields("{<Zm1>-<Zm2> }[<index>]", &["Zm", "i1"], list),
    fields("{<Zm1>.<T>-<Zm2>.<T> }", &["Zm", "size"], list),
    fields("{<Zm1>.<T>-<Zm2>.<T> }", &["Zm", "sz"], list),
    fields("{<Zm1>.<T>-<Zm4>.<T> }", &["Zm", "size"], list),
    fields("{<Zm1>.<T>-<Zm4>.<T> }", &["Zm", "sz"], list),
    fields("{<Zm1>.<Tb>-<Zm2>.<Tb> }", &["Zm", "sz"], list),
    fields("{<Zm1>.<Tb>-<Zm4>.<Tb> }", &["Zm", "sz"], list),
    fields("{<Zm1>.B-<Zm2>.B }", &["Zm"], list),
    fields("{<Zm1>.B-<Zm4>.B }", &["Zm"], list),
    fields("{<Zm1>.H-<Zm2>.H }", &["Zm"], list),
    fields("{<Zm1>.H-<Zm4>.H }", &["Zm"], list),
    fields("{<Zn1>-<Zn2> }", &["Zn"], list),
    fields("{<Zn1>-<Zn3> }", &["Zn"], list),
    fields("{<Zn1>.<T>-<Zn2>.<T> }", &["Zn", "size"], list),
    fields("{<Zn1>.<T>-<Zn2>.<T> }", &["Zn", "sz"], list),
    fields("{<Zn1>.<T>-<Zn4>.<T> }", &["Zn", "size"], list),
    fields("{<Zn1>.<T>-<Zn4>.<T> }", &["Zn", "sz"], list),
    fields("{<Zn1>.<Tb>-<Zn2>.<Tb> }", &["Zn", "sz"], list),
    fields("{<Zn1>.<Tb>-<Zn4>.<Tb> }", &["Zn", "sz"], list),
    fields("{<Zn1>.<Tb>-<Zn4>.<Tb> }", &["Zn", "tsize"], list),
    fields("{<Zn1>.B-<Zn2>.B }", &["Zn"], list),
    fields("{<Zn1>.B-<Zn4>.B }", &["Zn"], list),
    fields("{<Zn1>.D-<Zn2>.D }", &["Zn"], list),
    fields("{<Zn1>.D-<Zn4>.D }", &["Zn"], list),
    fields("{<Zn1>.H-<Zn4>.H }", &["Zn"], list),
    fields("{<Zn1>.Q-<Zn4>.Q }", &["Zn"], list),
    fields("{<Zn1>.S-<Zn4>.S }", &["Zn"], list),
    fields("{<Zt1>.B, <Zt2>.B }", &["T", "Zt"], list),
    fields("{<Zt1>.B, <Zt2>.B, <Zt3>.B, <Zt4>.B }", &["T", "Zt"], list),
    fields("{<Zt1>.B-<Zt2>.B }", &["Zt"], list),
    fields("{<Zt1>.B-<Zt4>.B }", &["Zt"], list),
    fields("{<Zt1>.D, <Zt2>.D }", &["T", "Zt"], list),
    fields("{<Zt1>.D, <Zt2>.D, <Zt3>.D, <Zt4>.D }", &["T", "Zt"], list),
    fields("{<Zt1>.D-<Zt2>.D }", &["Zt"], list),
    fields("{<Zt1>.D-<Zt4>.D }", &["Zt"], list),
    fields("{<Zt1>.H, <Zt2>.H }", &["T", "Zt"], list),
    fields("{<Zt1>.H, <Zt2>.H, <Zt3>.H, <Zt4>.H }", &["T", "Zt"], list),
    fields("{<Zt1>.H-<Zt2>.H }", &["Zt"], list),
    fields("{<Zt1>.H-<Zt4>.H }", &["Zt"], list),
    fields("{<Zt1>.S, <Zt2>.S }", &["T", "Zt"], list),
    fields("{<Zt1>.S, <Zt2>.S, <Zt3>.S, <Zt4>.S }", &["T", "Zt"], list),
    fields("{<Zt1>.S-<Zt2>.S }", &["Zt"], list),
    fields("{<Zt1>.S-<Zt4>.S }", &["Zt"], list),
    fields("{<mask> }", &["imm8"], tile_mask),
    any("{ZA0<HV>.B[<Ws>, <offs>] }", braced_tile_slice),
    any("{ZT0 }", table_list),
    forms("<Zn>.B", QUARTER_TILE, quarter_n),
    forms("<Zm>.B", QUARTER_TILE, quarter_m),
    forms("{<Zn1>.B-<Zn2>.B }", QUARTER_TILE, list),
    forms("{<Zm1>.B-<Zm2>.B }", QUARTER_TILE, quarter_m_list),
    forms("<Zn>.H", QUARTER_TILE, quarter_n),
    forms("<Zm>.H", QUARTER_TILE, quarter_m),
    forms("{<Zn1>.H-<Zn2>.H }", QUARTER_TILE, list),
    forms("{<Zm1>.H-<Zm2>.H }", QUARTER_TILE, quarter_m_list),
    forms("<Zn>.S", QUARTER_TILE, quarter_n),
    forms("<Zm>.S", QUARTER_TILE, quarter_m),
    forms("{<Zn1>.S-<Zn2>.S }", QUARTER_TILE, list),
    forms("{<Zm1>.S-<Zm2>.S }", QUARTER_TILE, quarter_m_list),
    forms("<Zn>.D", QUARTER_TILE, quarter_n),
    forms("<Zm>.D", QUARTER_TILE, quarter_m),
    forms("{<Zn1>.D-<Zn2>.D }", QUARTER_TILE, list),
    forms("{<Zm1>.D-<Zm2>.D }", QUARTER_TILE, quarter_m_list),
    forms("<Zd>.<T>", NARROWING_CONVERSION, narrow_vector),
    forms(
        "{<Zn1>.<Tb>-<Zn4>.<Tb> }",
        NARROWING_CONVERSION,
        narrow_source_list,
    ),
];
