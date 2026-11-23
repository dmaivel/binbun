//! The column-oriented metadata files: registers, operand widths, element
//! types and extra widths. None of them use continuation lines; comments and
//! blank lines are skipped as everywhere else.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use binbun_semantics::core::Keyword;

use crate::{Datafile, Error, ErrorKind, value};

/// One row of `all-registers.txt` (XED's `refine_regs.refine_regs_input`).
///
/// The row is `NAME CLASS WIDTH [ENCLOSING[/ENCLOSING32] [ORDINAL [h|- [DISPLAY]]]]`;
/// a three-column row encloses itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register<'a> {
    /// Line number.
    pub line: u32,
    /// Name as written, e.g. `RAX`; XED upper-cases it for the enum.
    pub name: &'a str,
    /// Register class as written, e.g. `gpr`, `xmm`; XED upper-cases it.
    pub class: &'a str,
    /// Width in bits, or `None` for pseudo registers (`NA`).
    pub width: Option<u32>,
    /// Width in 64-bit mode when it differs (`CR0` is `32/64`).
    pub width64: Option<u32>,
    /// Largest register containing this one, e.g. `RAX` for `AX`.
    pub enclosing: &'a str,
    /// Largest containing register outside 64-bit mode, e.g. `EAX` for `AX`.
    pub enclosing32: Option<&'a str>,
    /// Position within its class.
    pub ordinal: u32,
    /// Whether this is one of `AH`, `CH`, `DH`, `BH`.
    pub high_byte: bool,
    /// Name to display instead of `name`, e.g. `mm0` for `MMX0`.
    pub display: Option<&'a str>,
}

/// Parses `all-registers.txt` row by row, without merging duplicates.
///
/// # Errors
///
/// A row with fewer than three or more than seven columns, an unknown sixth
/// column, or a non-numeric width or ordinal.
pub fn registers<'a>(file: &'a Datafile<'_>) -> Result<Vec<Register<'a>>, Error> {
    file.lines()
        .iter()
        .map(|line| {
            let bad = |what: &str| {
                Error::new(
                    line.number,
                    ErrorKind::Malformed(format!("register {what}")),
                )
            };
            let words: Vec<&str> = line.text().split_whitespace().collect();
            let (&[name, class, width], rest) = (
                words.get(..3).unwrap_or_default(),
                words.get(3..).unwrap_or_default(),
            ) else {
                return Err(bad("row needs at least three columns"));
            };
            if rest.len() > 4 {
                return Err(bad("row has more than seven columns"));
            }
            let (width, width64) = match width {
                "NA" => (None, None),
                _ => match width.split_once('/') {
                    Some((narrow, wide)) => (Some(narrow), Some(wide)),
                    None => (Some(width), None),
                },
            };
            let bits = |text: Option<&str>| {
                text.map(str::parse::<u32>)
                    .transpose()
                    .map_err(|_| bad("width"))
            };
            let enclosing = rest.first().copied().unwrap_or(name);
            let (enclosing, enclosing32) = match enclosing.split_once('/') {
                Some((wide, narrow)) => (wide, Some(narrow)),
                None => (enclosing, None),
            };
            let ordinal = rest
                .get(1)
                .map_or(Ok(0), |o| o.parse().map_err(|_| bad("ordinal")))?;
            let high_byte = match rest.get(2).copied() {
                None | Some("-") => false,
                Some("h") => true,
                Some(_) => return Err(bad("sixth column must be `h` or `-`")),
            };
            Ok(Register {
                line: line.number,
                name,
                class,
                width: bits(width)?,
                width64: bits(width64)?,
                enclosing,
                enclosing32,
                ordinal,
                high_byte,
                display: rest.get(3).copied(),
            })
        })
        .collect()
}

/// Merges rows that define the same register, as XED does: the first row
/// fixes the register's position; a later row replaces it if it is wider, or
/// if it is as wide and its enclosing register is wider (`XMM0` is listed
/// under both `YMM0` and `ZMM0`; `ZMM0` wins).
pub fn merge_registers<'r, 'a>(rows: &'r [Register<'a>]) -> Vec<&'r Register<'a>> {
    let width = |register: &Register<'_>| register.width.unwrap_or(1);
    let mut widest: HashMap<CaseInsensitive<'a>, u32> = HashMap::new();
    for row in rows {
        let entry = widest.entry(CaseInsensitive(row.name)).or_insert(0);
        *entry = (*entry).max(width(row));
    }
    let enclosing_width = |register: &Register<'a>| {
        widest
            .get(&CaseInsensitive(register.enclosing))
            .copied()
            .unwrap_or(0)
    };

    let mut merged: Vec<&Register<'a>> = Vec::new();
    let mut position: HashMap<CaseInsensitive<'a>, usize> = HashMap::new();
    for row in rows {
        let key = CaseInsensitive(row.name);
        let Some(&index) = position.get(&key) else {
            position.insert(key, merged.len());
            merged.push(row);
            continue;
        };
        if let Some(kept) = merged.get_mut(index) {
            let wider = width(row) > width(kept);
            let same_width_wider_enclosing =
                width(row) == width(kept) && enclosing_width(row) > enclosing_width(kept);
            if wider || same_width_wider_enclosing {
                *kept = row;
            }
        }
    }
    merged
}

/// A name compared and hashed ignoring ASCII case, as XED upper-cases names.
#[derive(Debug, Clone, Copy)]
struct CaseInsensitive<'a>(&'a str);

impl PartialEq for CaseInsensitive<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for CaseInsensitive<'_> {}

impl Hash for CaseInsensitive<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            state.write_u8(byte.to_ascii_uppercase());
        }
        state.write_u8(0xff);
    }
}

/// One row of `all-widths.txt`: an operand width code (XED's `refine_widths_input`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Width<'a> {
    /// Line number.
    pub line: u32,
    /// Width code as written, e.g. `v`, `mem32real`; XED upper-cases it.
    pub name: &'a str,
    /// Default element type, lower-cased by XED, e.g. `int`, `f80`.
    pub element_type: &'a str,
    /// Width in bits for effective operand sizes 8, 16, 32 and 64.
    pub bits: [u32; 4],
}

/// Parses `all-widths.txt`. A row is `NAME TYPE WIDTH` (one width for every
/// operand size) or `NAME TYPE W16 W32 W64` (and 0 for size 8). Widths are in
/// bytes unless written `Nbits`.
///
/// # Errors
///
/// A row with another number of columns or a malformed width.
pub fn widths<'a>(file: &'a Datafile<'_>) -> Result<Vec<Width<'a>>, Error> {
    file.lines()
        .iter()
        .map(|line| {
            let bad =
                |what: &str| Error::new(line.number, ErrorKind::Malformed(format!("width {what}")));
            let words: Vec<&str> = line.text().split_whitespace().collect();
            let bits = |text: &str| -> Result<u32, Error> {
                let parsed = match text.strip_suffix("bits") {
                    Some(bits) => bits.parse::<u32>().ok(),
                    None => text
                        .parse::<u32>()
                        .ok()
                        .and_then(|bytes| bytes.checked_mul(8)),
                };
                parsed.ok_or_else(|| bad("value"))
            };
            let (name, element_type, bits) = match *words.as_slice() {
                [name, element_type, all] => (name, element_type, [bits(all)?; 4]),
                [name, element_type, w16, w32, w64] => {
                    (name, element_type, [0, bits(w16)?, bits(w32)?, bits(w64)?])
                }
                _ => return Err(bad("row needs three or five columns")),
            };
            Ok(Width {
                line: line.number,
                name,
                element_type,
                bits,
            })
        })
        .collect()
}

/// Base type of an operand element (`all-element-type-base.txt` names them).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "UPPERCASE")]
pub enum ElementBase {
    /// Element count and size come from other fields.
    Variable,
    /// Elements of different widths.
    Struct,
    /// Signed integer.
    Int,
    /// Unsigned integer.
    Uint,
    /// 8-bit signed integer.
    Int8,
    /// 8-bit unsigned integer.
    Uint8,
    /// IEEE half precision.
    Float16,
    /// IEEE single precision.
    Single,
    /// IEEE double precision.
    Double,
    /// x87 80-bit extended precision.
    Longdouble,
    /// x87 packed BCD.
    Longbcd,
    /// bfloat16.
    Bfloat16,
    /// 8-bit brain float.
    Bfloat8,
    /// 6-bit brain float.
    Bfloat6,
    /// 4-bit brain float.
    Bfloat4,
    /// 8-bit hybrid float.
    Hfloat8,
    /// 6-bit hybrid float.
    Hfloat6,
}

/// One row of `all-element-types.txt` (XED's `opnd_types.read_operand_types`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElementType<'a> {
    /// Line number.
    pub line: u32,
    /// Element type name, e.g. `f32`, `2f16`.
    pub name: &'a str,
    /// Its base type.
    pub base: ElementBase,
    /// Bits per element; 0 when it depends on the instruction.
    pub bits: u32,
}

/// Parses `all-element-types.txt`: `NAME BASE BITS` rows.
///
/// # Errors
///
/// A row without three columns, an unknown base type, or a non-numeric width.
pub fn element_types<'a>(file: &'a Datafile<'_>) -> Result<Vec<ElementType<'a>>, Error> {
    file.lines()
        .iter()
        .map(|line| {
            let bad = |what: &str| {
                Error::new(
                    line.number,
                    ErrorKind::Malformed(format!("element type {what}")),
                )
            };
            let &[name, base, bits] = line
                .text()
                .split_whitespace()
                .collect::<Vec<_>>()
                .as_slice()
            else {
                return Err(bad("row needs three columns"));
            };
            Ok(ElementType {
                line: line.number,
                name,
                base: base.parse().map_err(|_| bad("base"))?,
                bits: value::number(bits)
                    .and_then(|b| u32::try_from(b).ok())
                    .ok_or_else(|| bad("bits"))?,
            })
        })
        .collect()
}

/// What an `all-extra-widths.txt` row gives a width to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "snake_case")]
pub enum ExtraWidthKind {
    /// A lookup nonterminal.
    Nt,
    /// A fixed register.
    Reg,
    /// A bare operand such as `AGEN`.
    ImmConst,
}

/// One row of `all-extra-widths.txt`: a width code for operands that do not
/// state one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtraWidth<'a> {
    /// Line number.
    pub line: u32,
    /// What `name` is.
    pub kind: ExtraWidthKind,
    /// Nonterminal, register (without `XED_REG_`) or operand name.
    pub name: &'a str,
    /// Width code.
    pub width: &'a str,
}

/// Parses `all-extra-widths.txt`: `KIND NAME WIDTH` rows.
///
/// # Errors
///
/// A row without three columns or with an unknown kind.
pub fn extra_widths<'a>(file: &'a Datafile<'_>) -> Result<Vec<ExtraWidth<'a>>, Error> {
    file.lines()
        .iter()
        .map(|line| {
            let bad = |what: &str| {
                Error::new(
                    line.number,
                    ErrorKind::Malformed(format!("extra width {what}")),
                )
            };
            let &[kind, name, width] = line
                .text()
                .split_whitespace()
                .collect::<Vec<_>>()
                .as_slice()
            else {
                return Err(bad("row needs three columns"));
            };
            Ok(ExtraWidth {
                line: line.number,
                kind: kind.parse().map_err(|_| bad("kind"))?,
                name,
                width,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ElementBase, ExtraWidthKind, Register, element_types, extra_widths, merge_registers,
        registers, widths,
    };
    use crate::Datafile;

    #[test]
    fn reads_every_register_row_shape() {
        let file = Datafile::new(
            "INVALID INVALID 0\nAH gpr 8 RAX/EAX 4 h\nCR0 cr 32/64 CR0 0\nMMX0 mmx 64 MMX0 0 - mm0\nSTACKPUSH pseudo NA\n",
        );
        let rows = registers(&file).unwrap();
        assert_eq!(
            rows[1],
            Register {
                line: 2,
                name: "AH",
                class: "gpr",
                width: Some(8),
                width64: None,
                enclosing: "RAX",
                enclosing32: Some("EAX"),
                ordinal: 4,
                high_byte: true,
                display: None,
            }
        );
        assert_eq!((rows[0].enclosing, rows[0].ordinal), ("INVALID", 0));
        assert_eq!((rows[2].width, rows[2].width64), (Some(32), Some(64)));
        assert_eq!((rows[3].high_byte, rows[3].display), (false, Some("mm0")));
        assert_eq!(rows[4].width, None);
        assert!(registers(&Datafile::new("AH gpr 8 RAX 4 x")).is_err());
        assert!(registers(&Datafile::new("AH gpr")).is_err());
    }

    #[test]
    fn duplicate_registers_keep_their_position_and_take_the_wider_enclosing_register() {
        let file = Datafile::new(
            "YMM0 ymm 256 YMM0 0\nXMM0 xmm 128 YMM0 0\nZMM0 zmm 512 ZMM0 0\nXMM0 xmm 128 ZMM0 0\nXMM0 xmm 128 YMM0 0\n",
        );
        let rows = registers(&file).unwrap();
        let merged: Vec<_> = merge_registers(&rows)
            .iter()
            .map(|r| (r.name, r.enclosing))
            .collect();
        assert_eq!(
            merged,
            [("YMM0", "YMM0"), ("XMM0", "ZMM0"), ("ZMM0", "ZMM0")]
        );
    }

    #[test]
    fn widths_are_bytes_unless_marked_bits() {
        let file = Datafile::new("b u8 1\ni1 int 1bits\nv int 2 4 8\n");
        let rows = widths(&file).unwrap();
        let bits: Vec<_> = rows.iter().map(|w| w.bits).collect();
        assert_eq!(bits, [[8; 4], [1; 4], [0, 16, 32, 64]]);
        assert!(widths(&Datafile::new("v int 2 4")).is_err());
    }

    #[test]
    fn element_types_and_extra_widths() {
        let file = Datafile::new("2f16 FLOAT16 16\n");
        let types = element_types(&file).unwrap();
        assert_eq!(
            (types[0].name, types[0].base, types[0].bits),
            ("2f16", ElementBase::Float16, 16)
        );
        assert!(element_types(&Datafile::new("x QUAD 16")).is_err());

        let file = Datafile::new("imm_const AGEN pseudo\nnt ArBP asz\n");
        let extra = extra_widths(&file).unwrap();
        let kinds: Vec<_> = extra.iter().map(|e| (e.kind, e.name, e.width)).collect();
        assert_eq!(
            kinds,
            [
                (ExtraWidthKind::ImmConst, "AGEN", "pseudo"),
                (ExtraWidthKind::Nt, "ArBP", "asz")
            ]
        );
    }
}
