//! Symbols shared by the SVE and SME groups: Z, P and PN registers with an
//! element size, an index or a predicate qualifier, lists of consecutive
//! registers, and the memory operands of their loads and stores.
//!
//! Keys of one shape share a builder that reads the key: `<Zd>.<T>` is a
//! Z register numbered by `<Zd>`'s fields with the element size `<T>`
//! stands for, `<Pg>/M` a merging predicate, `[<Xn|SP>, <Xm>, LSL #1]` a
//! base plus a shifted register.
//!
//! Element sizes are written by index: 0 for B, 1 H, 2 S, 3 D, 4 Q.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::{Build, Slot, Symbol, push, sign_extend, unsigned};
use crate::Result;
use crate::codegen::lit;

/// A symbol matching any fields and forms.
pub const fn any(key: &'static str, build: fn(&Slot<'_>) -> Result<TokenStream>) -> Symbol {
    Symbol {
        key,
        fields: &[],
        forms: &[],
        build: Build::Operands(build),
    }
}

/// A symbol for slots encoded in exactly `fields`.
pub const fn fields(
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

/// The fields an element size (`<T>`, `<Tb>`, `<V>`, `<R>`) is encoded in.
const SIZE_FIELDS: &[&str] = &["size", "sz", "sf", "tsz", "tszh", "tszl", "tsize", "imm13"];

/// Encodings whose `<T>` in `sz` is B or H rather than S or D.
const SZ_BYTES: &[&str] = &["match_p_p_zz_", "nmatch_p_p_zz_", "compact_z_p_z_s"];

/// Encodings whose `<Tb>` is a quarter of `<T>` (four-way dot products)
/// rather than half.
const QUARTER: &[&str] = &["sdot_z_zzz_", "udot_z_zzz_", "cdot_z_zzz_"];

/// Encodings narrowing `size`-sized elements: their `<T>` is half the
/// element `size` gives, `<Tb>` the element.
const NARROWING: &[&str] = &[
    "addhnb_z_zz_",
    "addhnt_z_zz_",
    "raddhnb_z_zz_",
    "raddhnt_z_zz_",
    "subhnb_z_zz_",
    "subhnt_z_zz_",
    "rsubhnb_z_zz_",
    "rsubhnt_z_zz_",
    "fcvtzsn_z_mz2_",
    "fcvtzun_z_mz2_",
];

/// Encodings shifting left by a `tsz`-encoded amount into wider elements:
/// their `<T>` is twice the element `tsz` gives, `<Tb>` the element.
const WIDENING: &[&str] = &[
    "sshllb_z_zi_",
    "sshllt_z_zi_",
    "ushllb_z_zi_",
    "ushllt_z_zi_",
];

/// The element-size fields among the slot's.
pub fn size_fields(s: &Slot<'_>) -> Vec<String> {
    s.fields
        .iter()
        .filter(|field| SIZE_FIELDS.contains(&field.as_str()))
        .cloned()
        .collect()
}

/// `names` concatenated, the first most significant.
pub fn concat(s: &Slot<'_>, names: &[String]) -> Result<TokenStream> {
    let mut value = quote! { 0u32 };
    for (i, name) in names.iter().enumerate() {
        let field = s.field(name)?;
        value = if i == 0 {
            field
        } else {
            let width = lit(s.width(name)?);
            quote! { ((#value) << #width) | #field }
        };
    }
    Ok(value)
}

/// Whether `tsz` fields encode an element by their lowest set bit, as
/// they do below an index field (`<imm>` = `imm2:tsz` of `DUP`,
/// `i1:tszh:tszl` of `PSEL`), rather than by their highest (shift amounts
/// `tsz:imm3`, the narrowing `SQXTNB`).
fn tsz_is_index(s: &Slot<'_>) -> bool {
    s.width("i1").is_ok() || s.width("imm2").is_ok()
}

/// The element of a `tsz` field by its highest set bit: the element size
/// a shift by `tsz:imm3` works on.
pub fn shift_element(tsz: &TokenStream) -> TokenStream {
    quote! { (#tsz).checked_ilog2().unwrap_or(0) }
}

/// The index (`u32` expression) of the element size `element` writes: a
/// letter (`B`), or `<T>`/`<Tb>` from the slot's size fields.
///
/// `size` is the element (`<Tb>` half of it, a quarter for the four-way
/// dot products, the element itself for the quadword reductions `*QV`;
/// for the narrowing `ADDHNB` and the like `<T>` is half, `<Tb>` the
/// element);
/// `sz` is S or D (B or H for `MATCH`); `tsz` gives the element by its
/// lowest or highest set bit ([`tsz_is_index`]), `<Tb>` being twice that
/// when narrowing; `imm13` gives the element its bitmask repeats in.
pub fn element_index(s: &Slot<'_>, element: &str) -> Result<TokenStream> {
    let fixed = match element {
        "B" => Some(0u32),
        "H" => Some(1),
        "S" => Some(2),
        "D" => Some(3),
        "Q" => Some(4),
        _ => None,
    };
    if let Some(index) = fixed {
        let index = lit(index);
        return Ok(quote! { #index });
    }
    let narrow = element == "<Tb>";
    let names = size_fields(s);
    let encoding = s.instruction.name.as_str();
    let index = match names
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["imm13"] => {
            let imm13 = s.field("imm13")?;
            quote! {
                if #imm13 >> 12 == 1 {
                    3
                } else {
                    (!#imm13 & 0x3f).checked_ilog2().unwrap_or(0).saturating_sub(3)
                }
            }
        }
        ["size"] => {
            let size = s.field("size")?;
            if NARROWING.contains(&encoding) {
                if narrow {
                    size
                } else {
                    quote! { (#size).saturating_sub(1) }
                }
            } else if !narrow || encoding.ends_with("qv_z_p_z_") {
                size
            } else if QUARTER.contains(&encoding) {
                quote! { (#size).saturating_sub(2) }
            } else {
                quote! { (#size).saturating_sub(1) }
            }
        }
        ["sz"] => {
            let sz = s.field("sz")?;
            if SZ_BYTES.contains(&encoding) {
                sz
            } else {
                quote! { #sz + 2 }
            }
        }
        [] => return Err(format!("{}: `{}` has no size fields", s.form, s.key).into()),
        _ => {
            let tsz = concat(s, &names)?;
            if tsz_is_index(s) {
                quote! { (#tsz).trailing_zeros() }
            } else {
                let element = shift_element(&tsz);
                if narrow == WIDENING.contains(&encoding) {
                    element
                } else {
                    quote! { #element + 1 }
                }
            }
        }
    };
    Ok(index)
}

/// An `ElementSize` expression for an element index.
fn element_size(index: &TokenStream) -> TokenStream {
    let constant = match index.to_string().as_str() {
        "0" => Some("B"),
        "1" => Some("H"),
        "2" => Some("S"),
        "3" => Some("D"),
        "4" => Some("Q"),
        _ => None,
    };
    if let Some(name) = constant {
        let name = format_ident!("{name}");
        return quote! { ElementSize::#name };
    }
    quote! {
        match #index {
            0 => ElementSize::B,
            1 => ElementSize::H,
            2 => ElementSize::S,
            3 => ElementSize::D,
            _ => ElementSize::Q,
        }
    }
}

/// How a register's class is written.
enum Class {
    /// One class: `Z`, `P`, `Pn`, `D`, `V`, `W`, `X`.
    Fixed(&'static str),
    /// `<V><d>`: the SIMD&FP scalar of the element size.
    Scalar,
    /// `<R><n>`: X when the width field is all ones, else W.
    General,
}

/// A register as a key writes it: `<Zd>.<T>`, `<Pg>/M`, `<Zm>.S[<imm>]`,
/// `<V><d>`, `<Zd>{[<imm>]}`, `<Pm>.<T>[<Wv>, <imm>]`.
struct Written<'k> {
    class: Class,
    /// The display of the number: `<Zd>`, `<d>`.
    number: &'k str,
    /// The element after the dot: `<T>`, `B`.
    element: Option<&'k str>,
    /// What the brackets hold: `<imm>`, `<Wv>, <imm>`.
    index: Option<&'k str>,
    /// The qualifier after the slash: `Z`, `M`, `<ZM>`.
    predication: Option<&'k str>,
}

/// The class of a register display (`<Zd>`, `<PNg>`).
fn class_of(display: &str) -> Option<&'static str> {
    [
        ("<PN", "Pn"),
        ("<P", "P"),
        ("<Z", "Z"),
        ("<D", "D"),
        ("<V", "V"),
        ("<W", "W"),
        ("<X", "X"),
    ]
    .into_iter()
    .find(|(prefix, _)| display.starts_with(prefix))
    .map(|(_, class)| class)
}

/// `text` split after its first `<…>` display.
fn display_prefix(text: &str) -> Option<(&str, &str)> {
    let end = text.find('>')? + 1;
    Some((text.get(..end)?, text.get(end..)?))
}

/// The register `text` writes, if it is one.
fn parse(text: &str) -> Option<Written<'_>> {
    let (class, rest) = if let Some(rest) = text.strip_prefix("<V>") {
        (Class::Scalar, rest)
    } else if let Some(rest) = text.strip_prefix("<R>") {
        (Class::General, rest)
    } else {
        (Class::Fixed(class_of(text)?), text)
    };
    let (number, mut rest) = display_prefix(rest)?;
    let mut written = Written {
        class,
        number,
        element: None,
        index: None,
        predication: None,
    };
    if let Some(after) = rest.strip_prefix('.') {
        let end = after.find(['[', '{', '/']).unwrap_or(after.len());
        written.element = Some(after.get(..end)?);
        rest = after.get(end..)?;
    }
    if let Some(after) = rest.strip_prefix("{[") {
        let end = after.find("]}")?;
        written.index = Some(after.get(..end)?);
        rest = after.get(end + 2..)?;
    } else if let Some(after) = rest.strip_prefix('[') {
        let end = after.find(']')?;
        written.index = Some(after.get(..end)?);
        rest = after.get(end + 1..)?;
    }
    if let Some(after) = rest.strip_prefix('/') {
        written.predication = Some(after);
        rest = "";
    }
    rest.is_empty().then_some(written)
}

/// The number of a register display: its fields, plus 8 for a 3-bit
/// predicate-as-counter field (`pn8`…`pn15`).
fn number(s: &Slot<'_>, written: &Written<'_>) -> Result<TokenStream> {
    let (value, width) = s.display(written.number)?;
    Ok(match written.class {
        Class::Fixed("Pn") if width == 3 => quote! { #value + 8 },
        Class::Fixed(_) | Class::Scalar | Class::General => value,
    })
}

/// The index of `[<imm>]`: the display's fields, without the `tsz` bits
/// below it when it ends with them (`DUP`, `DUPQ`, `PSEL`).
fn index_value(s: &Slot<'_>, display: &str) -> Result<TokenStream> {
    let (value, _) = s.display(display)?;
    let names = size_fields(s);
    if names.is_empty() || !tsz_is_index(s) {
        return Ok(value);
    }
    let tsz = concat(s, &names)?;
    Ok(quote! { (#value) >> ((#tsz).trailing_zeros() + 1) })
}

/// The `Register` expression `written` stands for, numbered `number`.
fn register_value(
    s: &Slot<'_>,
    written: &Written<'_>,
    number: &TokenStream,
) -> Result<TokenStream> {
    let element = written
        .element
        .map(|element| element_index(s, element))
        .transpose()?;
    let class = match written.class {
        Class::Fixed(class) => {
            let class = format_ident!("{class}");
            quote! { RegisterClass::#class }
        }
        Class::Scalar => {
            let index = element_index(s, "<T>")?;
            quote! {
                match #index {
                    0 => RegisterClass::B,
                    1 => RegisterClass::H,
                    2 => RegisterClass::S,
                    3 => RegisterClass::D,
                    _ => RegisterClass::Q,
                }
            }
        }
        Class::General => {
            let name = s
                .fields
                .first()
                .ok_or_else(|| format!("{}: `{}` has no width field", s.form, s.key))?;
            let (width_field, ones) = (s.field(name)?, lit((1u32 << s.width(name)?) - 1));
            quote! {
                if #width_field == #ones { RegisterClass::X } else { RegisterClass::W }
            }
        }
    };
    let arrangement = match (&written.class, element) {
        (Class::Fixed("V"), Some(index)) => {
            let size = element_size(&index);
            quote! { Some(Arrangement { count: (16u32 >> (#index)) as u8, element: #size }) }
        }
        (_, Some(index)) => {
            let size = element_size(&index);
            quote! { Some(Arrangement { count: 0, element: #size }) }
        }
        (_, None) => quote! { None },
    };
    let index = match written.index {
        Some(display) if display.starts_with('<') && !display.contains(',') => {
            let value = index_value(s, display)?;
            quote! { Some((#value) as u8) }
        }
        _ => quote! { None },
    };
    let predication = match written.predication {
        None => quote! { None },
        Some("Z") => quote! { Some(Predication::Zeroing) },
        Some("M") => quote! { Some(Predication::Merging) },
        Some(_) => {
            let m = s.field("M")?;
            quote! {
                Some(if #m == 1 { Predication::Merging } else { Predication::Zeroing })
            }
        }
    };
    Ok(quote! {
        Register {
            class: #class,
            number: (#number) as u8,
            arrangement: #arrangement,
            index: #index,
            predication: #predication,
        }
    })
}

/// A register written as the key writes it ([`Written`]); a register
/// indexed by `[<Wv>, <imm>]` (`PSEL`) is selected by `w12 + Rv`.
pub fn vector_register(s: &Slot<'_>) -> Result<TokenStream> {
    let written =
        parse(&s.key).ok_or_else(|| format!("{}: `{}` is not a register", s.form, s.key))?;
    let number = number(s, &written)?;
    let register = register_value(s, &written, &number)?;
    if let Some(selection) = written.index.filter(|index| index.contains(',')) {
        let [base, offset] = selection.split(", ").collect::<Vec<_>>()[..] else {
            return Err(format!("{}: `{}`", s.form, s.key).into());
        };
        let (base, _) = s.display(base)?;
        let offset = index_value(s, offset)?;
        return Ok(push(&quote! {
            Operand::IndexedRegister(IndexedRegister {
                register: #register,
                index: Register::new(RegisterClass::W, (12 + #base) as u8),
                offset: (#offset) as u8,
            })
        }));
    }
    Ok(push(&quote! { Operand::Register(#register) }))
}

/// A brace list of consecutive registers: `{<Zt1>.B, <Zt2>.B }`,
/// `{<Zn1>.<Tb>-<Zn2>.<Tb> }`, `{<Zt>.D }`. The count is the last
/// register's number (`<Zt4>`: 4). A field narrower than the register
/// number (`Zn` of 4 bits for a pair) holds the first register divided
/// by 2 for pairs, 4 for quads (triples are not aligned); the printer
/// writes three or more registers as a range unless they wrap past the
/// last register.
pub fn register_list(s: &Slot<'_>) -> Result<TokenStream> {
    let inner = s
        .key
        .strip_prefix('{')
        .and_then(|key| key.strip_suffix('}'))
        .map(str::trim)
        .ok_or_else(|| format!("{}: `{}` is not a list", s.form, s.key))?;
    let first = inner.split([',', '-']).next().unwrap_or_default().trim();
    let last = inner.rsplit([',', '-']).next().unwrap_or_default().trim();
    let written = parse(first).ok_or_else(|| format!("{}: `{}` is not a list", s.form, s.key))?;
    let count = display_prefix(last)
        .and_then(|(display, _)| display.trim_end_matches('>').chars().last())
        .and_then(|digit| digit.to_digit(10))
        .unwrap_or(1);
    let (value, width) = s.display(written.number)?;
    let full = if matches!(written.class, Class::Fixed("P")) {
        4
    } else {
        5
    };
    let number = if width < full && count > 1 && count.is_power_of_two() {
        let shift = lit(count.ilog2());
        quote! { (#value) << #shift }
    } else {
        value
    };
    let first = register_value(s, &written, &number)?;
    let count = lit(count);
    Ok(push(&quote! {
        Operand::List(RegisterList {
            first: #first,
            count: #count,
            stride: 1,
            style: ListStyle::Range,
        })
    }))
}

/// How many registers a load or store transfers, the unit of its
/// `#<imm>, MUL VL` offset: the digit of `LD2B`…`ST4Q`, or the `_2`/`_4`
/// (`_2x8`/`_4x4` when strided) that ends the encoding name of
/// multi-vector `LD1B` and the like.
fn transfer_registers(s: &Slot<'_>) -> u32 {
    let name = s.instruction.name.as_str();
    let mnemonic = name.split('_').next().unwrap_or_default();
    let digit = mnemonic
        .strip_prefix("ld")
        .or_else(|| mnemonic.strip_prefix("st"))
        .and_then(|rest| rest.chars().next())
        .and_then(|digit| digit.to_digit(10));
    let suffix = name
        .rsplit('_')
        .next()
        .and_then(|last| last.split('x').next())
        .and_then(|count| count.parse::<u32>().ok());
    match (digit, suffix) {
        (Some(digit @ 2..=4), _) => digit,
        (_, Some(count @ (2 | 4))) => count,
        _ => 1,
    }
}

/// The bytes a memory element of a load or store is, by its mnemonic:
/// its last letter (`ld1sw`: 4), 16 for `LD1RQ*`, 32 for `LD1RO*`.
fn memory_scale(s: &Slot<'_>) -> u32 {
    let mnemonic = s.instruction.name.split('_').next().unwrap_or_default();
    if mnemonic.starts_with("ld1rq") {
        return 16;
    }
    if mnemonic.starts_with("ld1ro") {
        return 32;
    }
    match mnemonic.chars().last() {
        Some('h') => 2,
        Some('w') => 4,
        Some('d') => 8,
        Some('q') => 16,
        _ => 1,
    }
}

/// The offset of a memory key, as an `Offset` expression and the
/// condition under which an optional offset is left out.
fn memory_offset(s: &Slot<'_>, parts: &[&str]) -> Result<(TokenStream, TokenStream)> {
    Ok(match parts {
        [] => (quote! { Offset::None }, quote! { false }),
        ["#<imm>", "MUL VL"] => {
            let (value, width) = s.display("<imm>")?;
            let multiple = sign_extend(&value, width);
            let multiple = match transfer_registers(s) {
                1 => multiple,
                registers => {
                    let registers = lit(registers);
                    quote! { #multiple * #registers }
                }
            };
            (
                quote! { Offset::VectorLength(#multiple) },
                quote! { #value == 0 },
            )
        }
        ["#<imm>"] => {
            let (value, width) = s.display("<imm>")?;
            let scaled = |value: TokenStream| match memory_scale(s) {
                1 => value,
                scale => {
                    let scale = lit(scale);
                    quote! { #value * #scale }
                }
            };
            // The offsets of LD1R and of vector bases are unsigned; the
            // others signed.
            let unsigned = matches!(s.fields.last().map(String::as_str), Some("imm5" | "imm6"));
            let immediate = if unsigned {
                let offset = scaled(quote! { u64::from(#value) });
                quote! { Immediate::unsigned(#offset) }
            } else {
                let offset = scaled(sign_extend(&value, width));
                quote! { Immediate::signed(#offset) }
            };
            (
                quote! { Offset::Immediate(#immediate) },
                quote! { #value == 0 },
            )
        }
        ["<Xm>", modifier @ ..] => {
            let rm = s.field("Rm")?;
            let modifier = modifier_value(s, modifier)?;
            (
                quote! {
                    Offset::Register {
                        index: Register::new(RegisterClass::X, (#rm) as u8),
                        modifier: #modifier,
                    }
                },
                quote! { #rm == 31 },
            )
        }
        [register, modifier @ ..] => {
            let written = parse(register)
                .ok_or_else(|| format!("{}: `{}` offset {register}", s.form, s.key))?;
            let number = number(s, &written)?;
            let index = register_value(s, &written, &number)?;
            let modifier = modifier_value(s, modifier)?;
            (
                quote! { Offset::Register { index: #index, modifier: #modifier } },
                quote! { false },
            )
        }
    })
}

/// The `Modifier` expression of a register offset's trailing parts:
/// `LSL #<n>`, `<mod>` (`xs`: `uxtw` or `sxtw`), `<mod> #<n>`,
/// `SXTW<amount>` and `<mod> <amount>` (`msz`; LLVM leaves a zero amount
/// out, and `ADR`'s `lsl` with it).
fn modifier_value(s: &Slot<'_>, parts: &[&str]) -> Result<TokenStream> {
    let [part] = parts else {
        return if parts.is_empty() {
            Ok(quote! { Modifier::None })
        } else {
            Err(format!("{}: `{}`", s.form, s.key).into())
        };
    };
    if let Some(shift) = part.strip_prefix("LSL #") {
        let shift = lit(shift.parse::<u8>()?);
        return Ok(quote! {
            Modifier::Shift(Shift { kind: ShiftKind::Lsl, amount: #shift })
        });
    }
    if part.starts_with("<mod>") && *part != "<mod> <amount>" {
        let xs = s.field("xs")?;
        let amount = if let Some((_, amount)) = part.split_once(" #") {
            let amount = lit(amount.parse::<u8>()?);
            quote! { Some(#amount) }
        } else {
            quote! { None }
        };
        return Ok(quote! {
            Modifier::Extend(Extend {
                kind: if #xs == 1 { ExtendKind::Sxtw } else { ExtendKind::Uxtw },
                amount: #amount,
            })
        });
    }
    let msz = s.field("msz")?;
    let kind = match *part {
        "SXTW<amount>" => quote! { ExtendKind::Sxtw },
        "UXTW<amount>" => quote! { ExtendKind::Uxtw },
        "<mod> <amount>" => {
            return Ok(quote! {
                if #msz == 0 {
                    Modifier::None
                } else {
                    Modifier::Shift(Shift { kind: ShiftKind::Lsl, amount: (#msz) as u8 })
                }
            });
        }
        _ => return Err(format!("{}: `{}` modifier {part}", s.form, s.key).into()),
    };
    Ok(quote! {
        Modifier::Extend(Extend {
            kind: #kind,
            amount: if #msz == 0 { None } else { Some((#msz) as u8) },
        })
    })
}

/// A memory operand `[<base>{, <offset>}]`: a general base (`<Xn|SP>`) or
/// a vector one (`<Zn>.D`), and an offset — a multiple of the vector
/// length (`#<imm>, MUL VL`), a byte offset (`#<imm>`, scaled by the
/// element size), a general register (`<Xm>`, `LSL #<n>`) or a vector
/// register (`<Zm>.D`, `<mod> #<n>`). LLVM leaves an optional offset out
/// when it is zero or `xzr`.
pub fn vector_memory(s: &Slot<'_>) -> Result<TokenStream> {
    let inner = s
        .key
        .strip_prefix('[')
        .and_then(|key| key.strip_suffix(']'))
        .ok_or_else(|| format!("{}: `{}` is not a memory operand", s.form, s.key))?;
    let optional = inner.contains('{');
    let text = inner.replace(['{', '}'], "");
    let parts: Vec<&str> = text.split(", ").collect();
    let [base, offset @ ..] = parts.as_slice() else {
        return Err(format!("{}: `{}`", s.form, s.key).into());
    };
    let base = if *base == "<Xn|SP>" {
        let rn = s.field("Rn")?;
        quote! { Register::new(RegisterClass::Xsp, (#rn) as u8) }
    } else {
        let written = parse(base).ok_or_else(|| format!("{}: `{}` base {base}", s.form, s.key))?;
        let number = number(s, &written)?;
        register_value(s, &written, &number)?
    };
    let (offset, absent) = memory_offset(s, offset)?;
    let offset = if optional {
        quote! { if #absent { Offset::None } else { #offset } }
    } else {
        offset
    };
    Ok(push(&quote! {
        Operand::Memory(Memory {
            base: #base,
            offset: #offset,
            writeback: Writeback::None,
        })
    }))
}

/// `#<const>` of the narrowing shifts of a register pair or quad into
/// bytes (`imm3`) or halfwords (`imm4`): `2^width - imm`, in hex.
fn narrowing_shift(s: &Slot<'_>) -> Result<TokenStream> {
    let (value, width) = s.value()?;
    let size = lit(1u32 << width);
    Ok(push(&unsigned(&quote! { #size - (#value) })))
}

pub const SYMBOLS: &[Symbol] = &[
    // Narrowing shifts of a register pair or quad (`SQRSHRN`, `SQRSHR`).
    fields("#<const>", &["imm3"], narrowing_shift),
    fields("#<const>", &["imm4"], narrowing_shift),
    // Registers.
    any("<Dd>", vector_register),
    any("<PNd>.<T>", vector_register),
    any("<PNn>.<T>", vector_register),
    any("<PNn>[<imm>]", vector_register),
    any("<Pd>", vector_register),
    any("<Pd>.<T>", vector_register),
    any("<Pd>.B", vector_register),
    any("<Pd>.D", vector_register),
    any("<Pd>.H", vector_register),
    any("<Pd>.S", vector_register),
    any("<Pdm>.B", vector_register),
    any("<Pdn>.<T>", vector_register),
    any("<Pdn>.B", vector_register),
    any("<Pg>", vector_register),
    any("<Pg>/<ZM>", vector_register),
    any("<Pg>/M", vector_register),
    any("<Pg>/Z", vector_register),
    any("<Pm>.<T>", vector_register),
    any("<Pm>.<T>[<Wv>, <imm>]", vector_register),
    any("<Pm>.B", vector_register),
    any("<Pn>", vector_register),
    any("<Pn>.<T>", vector_register),
    any("<Pn>.B", vector_register),
    any("<Pn>.D", vector_register),
    any("<Pn>.H", vector_register),
    any("<Pn>.S", vector_register),
    any("<Pt>", vector_register),
    any("<Pv>", vector_register),
    any("<Pv>/M", vector_register),
    any("<R><d>", vector_register),
    any("<R><dn>", vector_register),
    any("<R><n>", vector_register),
    fields("<R><m>", &["sf", "Rm"], vector_register),
    fields("<R><m>", &["size", "Rm"], vector_register),
    fields("<R><m>", &["sz", "Rm"], vector_register),
    any("<V><d>", vector_register),
    any("<V><dn>", vector_register),
    any("<V><m>", vector_register),
    any("<V><n>", vector_register),
    any("<Vd>.<T>", vector_register),
    any("<Wdn>", vector_register),
    any("<Xdn>", vector_register),
    any("<Za>.<T>", vector_register),
    any("<Za>.D", vector_register),
    any("<Zd>", vector_register),
    any("<Zd>.<T>", vector_register),
    any("<Zd>.B", vector_register),
    any("<Zd>.D", vector_register),
    any("<Zd>.H", vector_register),
    any("<Zd>.Q", vector_register),
    any("<Zd>.S", vector_register),
    any("<Zd>{[<imm>]}", vector_register),
    any("<Zda>.<T>", vector_register),
    any("<Zda>.D", vector_register),
    any("<Zda>.H", vector_register),
    any("<Zda>.S", vector_register),
    any("<Zdn>.<T>", vector_register),
    any("<Zdn>.B", vector_register),
    any("<Zdn>.D", vector_register),
    any("<Zdn>.H", vector_register),
    any("<Zdn>.S", vector_register),
    any("<Zk>.D", vector_register),
    any("<Zm>", vector_register),
    any("<Zm>.<T>", vector_register),
    any("<Zm>.<Tb>", vector_register),
    any("<Zm>.B", vector_register),
    any("<Zm>.B[<imm>]", vector_register),
    any("<Zm>.D", vector_register),
    any("<Zm>.D[<imm>]", vector_register),
    any("<Zm>.H", vector_register),
    any("<Zm>.H[<imm>]", vector_register),
    any("<Zm>.Q", vector_register),
    any("<Zm>.Q[<index>]", vector_register),
    any("<Zm>.S", vector_register),
    any("<Zm>.S[<imm>]", vector_register),
    any("<Zm>[<index>]", vector_register),
    any("<Zn>", vector_register),
    any("<Zn>.<T>", vector_register),
    any("<Zn>.<T>[<imm>]", vector_register),
    any("<Zn>.<Tb>", vector_register),
    any("<Zn>.B", vector_register),
    any("<Zn>.D", vector_register),
    any("<Zn>.H", vector_register),
    any("<Zn>.Q", vector_register),
    any("<Zn>.S", vector_register),
    any("<Zn>{[<imm>]}", vector_register),
    any("<Zt>", vector_register),
    // Lists of consecutive registers.
    any("{<Pd1>.<T>, <Pd2>.<T> }", register_list),
    any("{<Zd1>.Q-<Zd2>.Q }", register_list),
    any("{<Zda1>.Q-<Zda2>.Q }", register_list),
    any("{<Zdn1>.B-<Zdn2>.B }", register_list),
    any("{<Zdn1>.B-<Zdn4>.B }", register_list),
    any("{<Zn1>.<T>, <Zn2>.<T> }", register_list),
    any("{<Zn1>.<Tb>-<Zn2>.<Tb> }", register_list),
    any("{<Zn1>.B, <Zn2>.B }", register_list),
    any("{<Zn1>.H, <Zn2>.H }", register_list),
    any("{<Zn1>.H-<Zn2>.H }", register_list),
    any("{<Zn1>.S-<Zn2>.S }", register_list),
    any("{<Zn>.<T> }", register_list),
    any("{<Zn>.B }", register_list),
    any("{<Zn>.H }", register_list),
    any("{<Zt1>.B, <Zt2>.B }", register_list),
    any("{<Zt1>.B, <Zt2>.B, <Zt3>.B }", register_list),
    any("{<Zt1>.B, <Zt2>.B, <Zt3>.B, <Zt4>.B }", register_list),
    any("{<Zt1>.D, <Zt2>.D }", register_list),
    any("{<Zt1>.D, <Zt2>.D, <Zt3>.D }", register_list),
    any("{<Zt1>.D, <Zt2>.D, <Zt3>.D, <Zt4>.D }", register_list),
    any("{<Zt1>.H, <Zt2>.H }", register_list),
    any("{<Zt1>.H, <Zt2>.H, <Zt3>.H }", register_list),
    any("{<Zt1>.H, <Zt2>.H, <Zt3>.H, <Zt4>.H }", register_list),
    any("{<Zt1>.Q, <Zt2>.Q }", register_list),
    any("{<Zt1>.Q, <Zt2>.Q, <Zt3>.Q }", register_list),
    any("{<Zt1>.Q, <Zt2>.Q, <Zt3>.Q, <Zt4>.Q }", register_list),
    any("{<Zt1>.S, <Zt2>.S }", register_list),
    any("{<Zt1>.S, <Zt2>.S, <Zt3>.S }", register_list),
    any("{<Zt1>.S, <Zt2>.S, <Zt3>.S, <Zt4>.S }", register_list),
    any("{<Zt>.<T> }", register_list),
    any("{<Zt>.B }", register_list),
    any("{<Zt>.D }", register_list),
    any("{<Zt>.H }", register_list),
    any("{<Zt>.Q }", register_list),
    any("{<Zt>.S }", register_list),
    // Memory operands.
    any("[<Xn|SP>, <Xm>, LSL #1]", vector_memory),
    any("[<Xn|SP>, <Xm>, LSL #2]", vector_memory),
    any("[<Xn|SP>, <Xm>, LSL #3]", vector_memory),
    any("[<Xn|SP>, <Xm>, LSL #4]", vector_memory),
    any("[<Xn|SP>, <Xm>]", vector_memory),
    any("[<Xn|SP>, <Zm>.D, <mod> #1]", vector_memory),
    any("[<Xn|SP>, <Zm>.D, <mod> #2]", vector_memory),
    any("[<Xn|SP>, <Zm>.D, <mod> #3]", vector_memory),
    any("[<Xn|SP>, <Zm>.D, <mod>]", vector_memory),
    any("[<Xn|SP>, <Zm>.D, LSL #1]", vector_memory),
    any("[<Xn|SP>, <Zm>.D, LSL #2]", vector_memory),
    any("[<Xn|SP>, <Zm>.D, LSL #3]", vector_memory),
    any("[<Xn|SP>, <Zm>.D]", vector_memory),
    any("[<Xn|SP>, <Zm>.S, <mod> #1]", vector_memory),
    any("[<Xn|SP>, <Zm>.S, <mod> #2]", vector_memory),
    any("[<Xn|SP>, <Zm>.S, <mod> #3]", vector_memory),
    any("[<Xn|SP>, <Zm>.S, <mod>]", vector_memory),
    any("[<Xn|SP>{, #<imm>, MUL VL}]", vector_memory),
    any("[<Xn|SP>{, #<imm>}]", vector_memory),
    any("[<Xn|SP>{, <Xm>, LSL #1}]", vector_memory),
    any("[<Xn|SP>{, <Xm>, LSL #2}]", vector_memory),
    any("[<Xn|SP>{, <Xm>, LSL #3}]", vector_memory),
    any("[<Xn|SP>{, <Xm>}]", vector_memory),
    any("[<Zn>.<T>, <Zm>.<T>{, <mod> <amount>}]", vector_memory),
    any("[<Zn>.D, <Zm>.D, SXTW<amount>]", vector_memory),
    any("[<Zn>.D, <Zm>.D, UXTW<amount>]", vector_memory),
    any("[<Zn>.D{, #<imm>}]", vector_memory),
    any("[<Zn>.D{, <Xm>}]", vector_memory),
    any("[<Zn>.S{, #<imm>}]", vector_memory),
    any("[<Zn>.S{, <Xm>}]", vector_memory),
];
