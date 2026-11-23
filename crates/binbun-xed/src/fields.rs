//! Operand storage fields (`all-fields.txt`, XED's `operand_storage.py`).
//!
//! Each line is `NAME SCALAR CTYPE WIDTH VISIBILITY PRINT SCOPE DECODER ENCODER`:
//! one field of the decoder's state, such as `MOD`, `REXW` or `EOSZ`.

use binbun_semantics::core::Keyword;

use crate::{Datafile, Error, ErrorKind};

/// One operand storage field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    /// Line it was defined on.
    pub line: u32,
    /// Field name, e.g. `MOD`.
    pub name: &'a str,
    /// C type XED stores it in, e.g. `xed_bits_t` or `xed_reg_enum_t`.
    pub ctype: &'a str,
    /// Width in bits.
    pub width: u32,
    /// Default operand visibility.
    pub visibility: Visibility,
    /// Whether XED prints the field when dumping decoder state.
    pub print: bool,
    /// Whether XED exposes an accessor for it.
    pub scope: Scope,
    /// The field's role during decoding.
    pub decoder: DecoderIo,
    /// The field's role during encoding.
    pub encoder: EncoderIo,
}

/// Default visibility of an operand stored in a field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "UPPERCASE")]
pub enum Visibility {
    /// Written in assembly.
    Explicit,
    /// Not written in assembly.
    Suppressed,
}

/// Whether a field is part of XED's public API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
#[keyword(rename_all = "UPPERCASE")]
pub enum Scope {
    /// Generator-internal.
    Internal,
    /// Has a public accessor.
    Public,
}

/// A field's role during decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
pub enum DecoderIo {
    /// Set before decoding starts (e.g. the machine mode).
    #[keyword("DI")]
    Input,
    /// Computed by decoding.
    #[keyword("DO")]
    Output,
    /// Encoder-only: constraints on it are ignored in decode patterns.
    #[keyword("DS")]
    Skip,
}

/// A field's role during encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Keyword)]
pub enum EncoderIo {
    /// Supplied by the encoder's caller.
    #[keyword("EI")]
    Input,
    /// Computed by encoding.
    #[keyword("EO")]
    Output,
}

/// Parses `all-fields.txt`, in file order.
///
/// # Errors
///
/// A line without exactly nine words, a duplicate name, an aggregate type
/// other than `SCALAR`, or an unknown keyword.
pub fn parse<'a>(file: &'a Datafile<'_>) -> Result<Vec<Field<'a>>, Error> {
    let mut fields: Vec<Field<'a>> = Vec::with_capacity(file.lines().len());
    for line in file.lines() {
        let bad =
            |what: &str| Error::new(line.number, ErrorKind::Malformed(format!("field {what}")));
        let words: Vec<&str> = line.text().split_whitespace().collect();
        let &[
            name,
            aggregate,
            ctype,
            width,
            visibility,
            print,
            scope,
            decoder,
            encoder,
        ] = words.as_slice()
        else {
            return Err(bad("line needs nine words"));
        };
        if aggregate != "SCALAR" {
            return Err(bad("aggregate type must be SCALAR"));
        }
        if fields.iter().any(|field| field.name == name) {
            return Err(bad("name is defined twice"));
        }
        fields.push(Field {
            line: line.number,
            name,
            ctype,
            width: width.parse().map_err(|_| bad("width"))?,
            visibility: visibility.parse().map_err(|_| bad("visibility"))?,
            print: match print {
                "PRINT" => true,
                "NOPRINT" => false,
                _ => return Err(bad("print flag")),
            },
            scope: scope.parse().map_err(|_| bad("scope"))?,
            decoder: decoder.parse().map_err(|_| bad("decoder role"))?,
            encoder: encoder.parse().map_err(|_| bad("encoder role"))?,
        });
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::{DecoderIo, EncoderIo, Field, Scope, Visibility, parse};
    use crate::Datafile;

    #[test]
    fn reads_every_column() {
        let file =
            Datafile::new("# c\nMOD SCALAR xed_bits_t 2 SUPPRESSED NOPRINT INTERNAL DS EI # x\n");
        assert_eq!(
            parse(&file).unwrap(),
            [Field {
                line: 2,
                name: "MOD",
                ctype: "xed_bits_t",
                width: 2,
                visibility: Visibility::Suppressed,
                print: false,
                scope: Scope::Internal,
                decoder: DecoderIo::Skip,
                encoder: EncoderIo::Input,
            }]
        );
    }

    #[test]
    fn rejects_malformed_lines() {
        let line = "A SCALAR t 1 EXPLICIT PRINT PUBLIC DO EO";
        for source in [
            "A SCALAR t 1 EXPLICIT PRINT PUBLIC DO",
            "A VECTOR t 1 EXPLICIT PRINT PUBLIC DO EO",
            "A SCALAR t x EXPLICIT PRINT PUBLIC DO EO",
            "A SCALAR t 1 EXPLICIT PRINT PUBLIC DX EO",
            &format!("{line}\n{line}"),
        ] {
            assert!(parse(&Datafile::new(source)).is_err(), "{source}");
        }
    }
}
