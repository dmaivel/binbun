//! Opcode maps (`all-map-descriptions.txt`, XED's `map_info_rdr`).
//!
//! Each row describes one opcode map and what the instruction-length decoder
//! needs to know about it: the escape bytes that select it, and whether its
//! instructions have a ModRM byte, a displacement and an immediate.
//!
//! `NAME SPACE ESCAPE OPCODE ID MODRM DISP IMM OPCPOS 'PATTERN'`, e.g.
//! `legacy-map2 legacy 0x0F 0x38 2 yes no 0 2 '0x0F 0x38'`.

use binbun_semantics::core::Keyword;

use crate::{Datafile, Error, ErrorKind, value};

/// One opcode map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpcodeMap<'a> {
    /// Line number.
    pub line: u32,
    /// Name as written, e.g. `legacy-map2`; XED replaces `-` with `_`.
    pub name: &'a str,
    /// Encoding space.
    pub space: Space,
    /// Legacy escape byte (`0x0F`), legacy maps only.
    pub escape: Option<u8>,
    /// Second legacy opcode byte (`0x38`, `0x3A`), legacy maps only.
    pub opcode: Option<u8>,
    /// Map number, or a symbolic id such as `AMD3DNOW` for legacy maps.
    pub id: MapId<'a>,
    /// Whether instructions have a ModRM byte.
    pub modrm: ModRm,
    /// Whether instructions may have a displacement beyond ModRM's.
    pub displacement: Displacement,
    /// Immediate size.
    pub immediate: Immediate,
    /// Index of the opcode byte in the pattern; -1 is the last byte.
    pub opcode_position: i8,
    /// How the map is named in decode patterns, e.g. `0x0F 0x38` or `V0F38`.
    pub pattern: &'a str,
}

/// Encoding space of a map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "lowercase")]
pub enum Space {
    /// Legacy (escape-byte) encoding.
    Legacy,
    /// VEX.
    Vex,
    /// EVEX.
    Evex,
    /// AMD XOP.
    Xop,
}

/// A map's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapId<'a> {
    /// A map number.
    Number(u8),
    /// A legacy map without a number, e.g. `AMD3DNOW`.
    Named(&'a str),
}

/// ModRM presence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "lowercase")]
pub enum ModRm {
    /// Depends on the opcode.
    Var,
    /// Always present.
    Yes,
    /// Never present.
    No,
}

/// Displacement presence (beyond ModRM-implied displacements).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "lowercase")]
pub enum Displacement {
    /// Depends on the opcode.
    Var,
    /// Never present.
    No,
}

/// Immediate size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Immediate {
    /// Depends on the opcode.
    Var,
    /// Always this many bytes: 0, 1, 2 or 4.
    Bytes(u8),
}

/// Parses `all-map-descriptions.txt`.
///
/// # Errors
///
/// A row without ten fields, an unterminated quote, or a field that is not
/// allowed for the map's space.
pub fn parse<'a>(file: &'a Datafile<'_>) -> Result<Vec<OpcodeMap<'a>>, Error> {
    file.lines()
        .iter()
        .map(|line| parse_line(line.number, line.text()))
        .collect()
}

fn parse_line(line: u32, text: &str) -> Result<OpcodeMap<'_>, Error> {
    let bad = |what: &str| {
        Error::new(
            line,
            ErrorKind::Malformed(format!("map description {what}")),
        )
    };
    let fields = fields(text).ok_or_else(|| bad("quote"))?;
    let &[
        name,
        space,
        escape,
        opcode,
        id,
        modrm,
        displacement,
        immediate,
        position,
        pattern,
    ] = fields.as_slice()
    else {
        return Err(bad("row needs ten fields"));
    };
    let space: Space = space.parse().map_err(|_| bad("space"))?;
    let byte = |text: &str| -> Result<Option<u8>, Error> {
        match text {
            "N/A" => Ok(None),
            hex if hex.starts_with("0x") || hex.starts_with("0X") => value::number(hex)
                .and_then(|v| u8::try_from(v).ok())
                .map(Some)
                .ok_or_else(|| bad("escape byte")),
            _ => Err(bad("escape byte")),
        }
    };
    let (escape, opcode) = (byte(escape)?, byte(opcode)?);
    let numeric_id = value::number(id).and_then(|v| u8::try_from(v).ok());
    let id = match (space, numeric_id, id) {
        (_, Some(number), _) => MapId::Number(number),
        (Space::Legacy, None, "N/A") => return Err(bad("legacy map id")),
        (Space::Legacy, None, named) => MapId::Named(named),
        (Space::Vex | Space::Evex | Space::Xop, None, _) => return Err(bad("map id")),
    };
    if space != Space::Legacy && (escape.is_some() || opcode.is_some()) {
        return Err(bad("escape byte outside the legacy space"));
    }
    let immediate = match immediate {
        "var" => Immediate::Var,
        bytes @ ("0" | "1" | "2" | "4") => {
            Immediate::Bytes(bytes.parse().map_err(|_| bad("immediate"))?)
        }
        _ => return Err(bad("immediate")),
    };
    Ok(OpcodeMap {
        line,
        name,
        space,
        escape,
        opcode,
        id,
        modrm: modrm.parse().map_err(|_| bad("modrm"))?,
        displacement: displacement.parse().map_err(|_| bad("displacement"))?,
        immediate,
        opcode_position: position.parse().map_err(|_| bad("opcode position"))?,
        pattern,
    })
}

/// Whitespace-separated fields where `'…'` is one field (possibly empty or
/// containing spaces), as `shlex.split` reads these rows. `None` for an
/// unterminated quote.
fn fields(text: &str) -> Option<Vec<&str>> {
    let mut fields = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        if let Some(quoted) = rest.strip_prefix('\'') {
            let (field, after) = quoted.split_once('\'')?;
            fields.push(field);
            rest = after.trim_start();
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let (field, after) = rest.split_at(end);
            fields.push(field);
            rest = after.trim_start();
        }
    }
    Some(fields)
}

#[cfg(test)]
mod tests {
    use super::{Displacement, Immediate, MapId, ModRm, OpcodeMap, Space, parse};
    use crate::Datafile;

    #[test]
    fn reads_legacy_and_vex_rows() {
        let file = Datafile::new(
            "legacy-map0 legacy N/A N/A 0 var var var 0 ''\n\
             amd-3dnow legacy 0x0F 0x0F AMD3DNOW yes no 1 -1 '0x0F 0x0F'\n\
             amd-xopA xop N/A N/A 0xA yes no 4 1 'XMAPA'\n",
        );
        let maps = parse(&file).unwrap();
        assert_eq!(maps[0].pattern, "");
        assert_eq!(
            maps[1],
            OpcodeMap {
                line: 2,
                name: "amd-3dnow",
                space: Space::Legacy,
                escape: Some(0x0f),
                opcode: Some(0x0f),
                id: MapId::Named("AMD3DNOW"),
                modrm: ModRm::Yes,
                displacement: Displacement::No,
                immediate: Immediate::Bytes(1),
                opcode_position: -1,
                pattern: "0x0F 0x0F",
            }
        );
        assert_eq!(
            (maps[2].id, maps[2].immediate),
            (MapId::Number(10), Immediate::Bytes(4))
        );
    }

    #[test]
    fn rejects_rows_that_break_the_space_rules() {
        for row in [
            "m vex 0x0F N/A 1 yes no 0 1 'V0F'",
            "m vex N/A N/A NAMED yes no 0 1 'V0F'",
            "m legacy N/A N/A N/A yes no 0 1 ''",
            "m legacy N/A N/A 1 yes no 3 1 ''",
            "m legacy N/A N/A 1 yes yes 0 1 ''",
            "m legacy N/A N/A 1 yes no 0 1 'open",
            "m legacy N/A N/A 1 yes no 0 1",
        ] {
            assert!(parse(&Datafile::new(row)).is_err(), "{row}");
        }
    }
}
