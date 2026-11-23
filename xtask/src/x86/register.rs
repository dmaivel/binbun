//! `Register` and `RegisterClass`.
//!
//! Registers are ordered as in XED's `xed_reg_enum_t`: grouped by class
//! (general-purpose registers further by width, `AH`–`BH` separately), groups
//! in name order, registers within a group by ordinal. Each group is
//! therefore contiguous and indexable by encoding number.

use std::collections::BTreeSet;

use binbun_xed::tables::Register;
use proc_macro2::Literal;
use quote::quote;

use super::output;
use crate::Result;
use crate::codegen::{self, GeneratedFile, XED_NOTICE};
use crate::naming::{camel_case, ident, unique_idents};

/// Register names in `Register` order: the variant numbered `n` is at
/// `n - 1` (XED names, upper case).
pub fn names(merged: &[&Register<'_>]) -> Vec<String> {
    ordered(merged)
        .iter()
        .map(|r| r.name.to_ascii_uppercase())
        .collect()
}

/// The registers of the `Register` enum, in its order.
fn ordered<'r, 'a>(merged: &[&'r Register<'a>]) -> Vec<&'r Register<'a>> {
    let mut registers: Vec<&Register<'_>> = merged
        .iter()
        .copied()
        .filter(|register| !register.class.eq_ignore_ascii_case("invalid"))
        .collect();
    registers.sort_by_cached_key(|register| (group(register), register.ordinal));
    registers
}

#[expect(clippy::too_many_lines, reason = "mostly one quote! template")]
pub fn generate(merged: &[&Register<'_>]) -> Result<GeneratedFile> {
    let registers = ordered(merged);
    let names: Vec<String> = registers
        .iter()
        .map(|r| r.name.to_ascii_uppercase())
        .collect();
    let variants = names
        .iter()
        .map(|name| ident(name))
        .collect::<Result<Vec<_>>>()?;
    let display: Vec<String> = registers
        .iter()
        .map(|r| r.display.unwrap_or(r.name).to_ascii_lowercase())
        .collect();
    let docs = display.iter().map(|name| format!(" `{name}`"));

    let classes: Vec<String> = registers
        .iter()
        .map(|r| r.class.to_ascii_uppercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let class_variants = unique_idents(classes.iter().map(String::as_str), camel_case)?;
    let class_docs = classes
        .iter()
        .map(|class| format!(" XED class `{}`.", class.to_ascii_lowercase()));
    let class_of = registers
        .iter()
        .map(|r| {
            let index = classes
                .binary_search(&r.class.to_ascii_uppercase())
                .map_err(|_| "class")?;
            class_variants.get(index).ok_or_else(|| "class".into())
        })
        .collect::<Result<Vec<_>>>()?;

    let largest = |name: &str| -> Result<proc_macro2::Ident> {
        let upper = name.to_ascii_uppercase();
        if !names.contains(&upper) {
            return Err(format!("register `{name}` encloses itself in an unknown register").into());
        }
        ident(&upper)
    };
    let full = registers
        .iter()
        .map(|r| largest(r.enclosing))
        .collect::<Result<Vec<_>>>()?;
    let full32 = registers
        .iter()
        .map(|r| largest(r.enclosing32.unwrap_or(r.enclosing)))
        .collect::<Result<Vec<_>>>()?;
    let widths = registers
        .iter()
        .map(|r| Literal::u32_unsuffixed(r.width64.or(r.width).unwrap_or(0)));
    let offsets = registers
        .iter()
        .map(|r| Literal::u32_unsuffixed(if r.high_byte { 8 } else { 0 }));
    let count = codegen::count(registers.len());
    // Numbered from 1, so that 0 can stand for "no register" in the
    // decoder state.
    let raws = (1..=registers.len()).map(codegen::count);

    let tokens = quote! {
        use core::fmt;

        /// A register, including XED's pseudo registers (stack pointer
        /// updates, x87 status words, MSRs) that instructions use implicitly.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
        pub enum Register {
            #(#[doc = #docs] #variants = #raws,)*
        }

        /// The kind of a [`Register`].
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum RegisterClass {
            #(#[doc = #class_docs] #class_variants,)*
        }

        impl Register {
            /// Number of registers.
            pub const COUNT: usize = #count;

            /// Every register, in declaration order.
            pub const ALL: [Self; Self::COUNT] = [#(Self::#variants),*];

            /// The register numbered `raw` (`register as u16`), or `None` for
            /// 0 and numbers past the last register.
            pub const fn from_raw(raw: u16) -> Option<Self> {
                match (raw as usize).checked_sub(1) {
                    Some(index) if index < Self::COUNT => Some(Self::ALL[index]),
                    _ => None,
                }
            }

            /// Lower-case display name, e.g. `rax`, `mm0`, `st(0)`.
            pub const fn name(self) -> &'static str {
                match self {
                    #(Self::#variants => #display,)*
                }
            }

            /// The register's class.
            pub const fn class(self) -> RegisterClass {
                match self {
                    #(Self::#variants => RegisterClass::#class_of,)*
                }
            }

            /// The largest register containing this one in 64-bit mode,
            /// e.g. `RAX` for `AL`; a register that is not part of another
            /// is its own full register.
            #[must_use]
            pub const fn full(self) -> Self {
                match self {
                    #(Self::#variants => Self::#full,)*
                }
            }

            /// The largest register containing this one outside 64-bit mode,
            /// e.g. `EAX` for `AL`.
            #[must_use]
            pub const fn full32(self) -> Self {
                match self {
                    #(Self::#variants => Self::#full32,)*
                }
            }

            /// Width in bits in 64-bit mode (XED's
            /// `xed_get_register_width_bits64`); 0 for pseudo registers.
            pub const fn width(self) -> u32 {
                match self {
                    #(Self::#variants => #widths,)*
                }
            }

            /// The bit at which this register starts within its
            /// [`full`](Self::full) register: 8 for `AH`, `CH`, `DH` and
            /// `BH`, otherwise 0.
            pub const fn offset(self) -> u32 {
                match self {
                    #(Self::#variants => #offsets,)*
                }
            }
        }

        impl fmt::Display for Register {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }
    };
    Ok(GeneratedFile {
        path: output("register"),
        notice: XED_NOTICE,
        docs: vec!["Registers.".to_owned()],
        tokens,
    })
}

/// XED's register group: the upper-case class, plus the width and an `h`
/// for the high-byte registers within the general-purpose class.
fn group(register: &Register<'_>) -> String {
    let class = register.class.to_ascii_uppercase();
    if class != "GPR" {
        return class;
    }
    let width = register.width.unwrap_or(0);
    let high = if register.high_byte { "h" } else { "" };
    format!("{class}{width}{high}")
}
