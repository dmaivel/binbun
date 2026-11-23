//! The decoder state (`generated/state.rs`): one field per XED operand
//! storage field the decoder uses, named after it (`MOD` is `mod_`).
//!
//! Every decoding stage reads and writes this struct: the hand-written
//! length decoder, generated identification and the generated nonterminals.
//!
//! The fields a decoded instruction keeps ([`RESULT`]: those its accessors,
//! operands and formatter read) are a separate struct, `Fields`, which the
//! state holds and dereferences to; the rest are scratch, dropped after
//! decoding, so that an instruction stays small.

use std::collections::BTreeMap;

use binbun_xed::fields::{DecoderIo, Field};
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use super::output;
use crate::Result;
use crate::codegen::{GeneratedFile, XED_NOTICE};

/// How a field is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An unsigned integer.
    Unsigned,
    /// A signed integer (`DISP`).
    Signed,
    /// A register as `Register as u16`, 0 for XED's `INVALID`.
    Register,
    /// An error as `DecodeError as u8`, 0 for none.
    Error,
}

/// A field of the state.
#[derive(Debug, Clone)]
pub struct StateField {
    pub xed: String,
    pub ident: Ident,
    pub kind: Kind,
    pub ty: TokenStream,
}

/// Fields of the state: XED's, except encoder-only ones (`DS`) and the ones
/// the decoder never stores (`CHIP`, `ICLASS`) or never reads ([`UNREAD`]).
/// An integer field is wide
/// enough for its declared width and for the largest constant the grammar
/// stores in it (`NELEM` is declared 4 bits but holds up to 512).
pub fn fields(all: &[Field<'_>], largest: &BTreeMap<&str, u64>) -> Result<Vec<StateField>> {
    all.iter()
        .filter(|f| {
            f.decoder != DecoderIo::Skip
                && !matches!(f.name, "CHIP" | "ICLASS")
                && !UNREAD.contains(&f.name)
        })
        .map(|f| {
            let needed = largest.get(f.name).map_or(0, |&v| 64 - v.leading_zeros());
            let (kind, ty) = match (f.ctype, f.width.max(needed)) {
                ("xed_reg_enum_t", _) => (Kind::Register, quote!(u16)),
                ("xed_error_enum_t", _) => (Kind::Error, quote!(u8)),
                ("xed_int64_t", _) => (Kind::Signed, quote!(i64)),
                ("xed_uint64_t", _) => (Kind::Unsigned, quote!(u64)),
                ("xed_bits_t" | "xed_uint8_t" | "xed_uint16_t", width) if width <= 8 => {
                    (Kind::Unsigned, quote!(u8))
                }
                ("xed_bits_t" | "xed_uint16_t", width) if width <= 16 => {
                    (Kind::Unsigned, quote!(u16))
                }
                (ctype, width) => {
                    return Err(format!(
                        "field {}: no storage for {ctype} of {width} bits",
                        f.name
                    )
                    .into());
                }
            };
            Ok(StateField {
                xed: f.name.to_owned(),
                ident: ident_for(f.name),
                kind,
                ty,
            })
        })
        .collect()
}

/// The Rust field name of XED field `name`.
pub fn ident_for(name: &str) -> Ident {
    match name {
        "MOD" => format_ident!("mod_"),
        _ => format_ident!("{}", name.to_ascii_lowercase()),
    }
}

/// XED fields that nothing reads here: no rule tests them, no lookup is
/// indexed by them, and neither the length decoder nor the instruction
/// API looks at them (XED keeps them for its encoder, its operand
/// accessors or byte positions). They are not stored, and bindings to
/// them are dropped. Reading one is a compile error.
pub const UNREAD: [&str; 29] = [
    "DEFAULT_SEG",
    "DF32",
    "DF64",
    "ENCODER_PREFERRED",
    "ENCODE_FORCE",
    "EVVSPACE",
    "HAS_EGPR",
    "HAS_MODRM",
    "IMM0",
    "IMM1",
    "MAX_BYTES",
    "MEM_WIDTH",
    "MODE_FIRST_PREFIX",
    "MODRM_BYTE",
    "MUST_USE_EVEX",
    "NEEDREX",
    "NOREX",
    "NO_EVEX",
    "NO_VEX",
    "OUTREG",
    "POS_DISP",
    "POS_IMM",
    "POS_IMM1",
    "POS_MODRM",
    "POS_NOMINAL_OPCODE",
    "POS_SIB",
    "RELBR",
    "VEX_C4",
    "VL_IGN",
];

/// The XED fields a decoded instruction keeps: what `Instruction`'s
/// accessors, operands, formatter, flags and flow read.
pub const RESULT: [&str; 51] = [
    "ABSBR",
    "AGEN",
    "ASZ",
    "BASE0",
    "BASE1",
    "BCAST",
    "BRDISP_WIDTH",
    "DFV",
    "DISP",
    "DISP_WIDTH",
    "EASZ",
    "ELEMENT_SIZE",
    "EOSZ",
    "HINT",
    "IMM0SIGNED",
    "IMM_WIDTH",
    "INDEX",
    "LOCK",
    "MEM0",
    "MEM1",
    "MOD",
    "MODE",
    "NELEM",
    "NOMINAL_OPCODE",
    "OSZ",
    "PTR",
    "REALMODE",
    "REG0",
    "REG1",
    "REG2",
    "REG3",
    "REG4",
    "REG5",
    "REG6",
    "REG7",
    "REG8",
    "REG9",
    "REP",
    "RM",
    "ROUNDC",
    "SAE",
    "SCALE",
    "SEG0",
    "SEG1",
    "SMODE",
    "UIMM0",
    "UIMM1",
    "USING_DEFAULT_SEGMENT0",
    "USING_DEFAULT_SEGMENT1",
    "VEXVALID",
    "ZEROING",
];

pub fn generate(fields: &[StateField], all: &[Field<'_>]) -> Result<GeneratedFile> {
    if let Some(missing) = RESULT
        .iter()
        .find(|name| !fields.iter().any(|f| f.xed == **name))
    {
        return Err(format!("kept field {missing} is not a state field").into());
    }
    let declaration = |field: &StateField| {
        let source = all.iter().find(|f| f.name == field.xed);
        let doc = format!(
            " XED `{}`{}.",
            field.xed,
            source.map_or_else(String::new, |f| format!(", {} bits", f.width))
        );
        let (ident, ty) = (&field.ident, &field.ty);
        quote!(#[doc = #doc] pub #ident: #ty,)
    };
    let (kept, scratch): (Vec<&StateField>, Vec<&StateField>) = fields
        .iter()
        .partition(|f| RESULT.contains(&f.xed.as_str()));
    let kept = kept.into_iter().map(declaration);
    let scratch = scratch.into_iter().map(declaration);
    let tokens = quote! {
        use core::ops::{Deref, DerefMut};

        /// The fields of XED's operand storage that a decoded instruction
        /// keeps. Every field is an integer and zero when unset (registers
        /// as `Register as u16`), so fresh fields are all zeros.
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct Fields {
            /// Bytes the length decoder has consumed: the length, once
            /// decoded.
            pub pos: usize,
            #(#kept)*
        }

        /// Decoder state: XED's operand storage, the kept [`Fields`] (which
        /// it dereferences to) and the rest. Every field is an integer and
        /// zero when unset (errors as `DecodeError as u8`), so a fresh state
        /// is all zeros.
        #[derive(Debug, Clone, Default)]
        pub struct State {
            /// The fields a decoded instruction keeps.
            pub fields: Fields,
            /// The instruction's bytes (at most 15), zero-padded (not an XED
            /// field: the length decoder's input).
            pub buf: [u8; 32],
            /// Bytes available in `buf`, at most 15.
            pub max: usize,
            #(#scratch)*
        }

        impl Deref for State {
            type Target = Fields;

            #[inline]
            fn deref(&self) -> &Fields {
                &self.fields
            }
        }

        impl DerefMut for State {
            #[inline]
            fn deref_mut(&mut self) -> &mut Fields {
                &mut self.fields
            }
        }
    };
    Ok(GeneratedFile {
        path: output("state"),
        notice: XED_NOTICE,
        docs: vec!["Decoder state.".to_owned()],
        tokens,
    })
}
