//! `Mnemonic`: one variant per XED iclass that can be decoded.

use std::collections::BTreeSet;

use binbun_xed::instructions::Record;
use quote::quote;

use super::output;
use crate::Result;
use crate::codegen::{self, GeneratedFile, XED_NOTICE};
use crate::naming::{camel_case, unique_idents};

pub fn generate(records: &[&Record<'_>]) -> Result<GeneratedFile> {
    let names: Vec<&str> = records
        .iter()
        .map(|record| record.iclass)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let variants = unique_idents(names.iter().copied(), camel_case)?;
    let count = codegen::count(names.len());
    let docs = names.iter().map(|name| format!(" `{name}`"));

    let tokens = quote! {
        use core::fmt;
        use core::str::FromStr;

        use crate::UnknownName;

        /// An instruction's operation, as XED classifies it (its *iclass*).
        ///
        /// Prefix-dependent operations are separate mnemonics, e.g.
        /// [`Mnemonic::RepMovsb`] next to [`Mnemonic::Movsb`].
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        pub enum Mnemonic {
            #(#[doc = #docs] #variants,)*
        }

        impl Mnemonic {
            /// Number of mnemonics.
            pub const COUNT: usize = #count;

            /// Every mnemonic, in declaration (alphabetical) order.
            pub const ALL: [Self; Self::COUNT] = [#(Self::#variants),*];

            /// XED's name for the mnemonic, e.g. `REP_MOVSB`.
            pub const fn as_str(self) -> &'static str {
                match self {
                    #(Self::#variants => #names,)*
                }
            }
        }

        impl fmt::Display for Mnemonic {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for Mnemonic {
            type Err = UnknownName;

            /// Parses XED's name for a mnemonic (exact, case-sensitive).
            fn from_str(name: &str) -> Result<Self, Self::Err> {
                match Self::ALL.binary_search_by(|mnemonic| mnemonic.as_str().cmp(name)) {
                    Ok(index) => Self::ALL.get(index).copied().ok_or(UnknownName),
                    Err(_) => Err(UnknownName),
                }
            }
        }
    };
    Ok(GeneratedFile {
        path: output("mnemonic"),
        notice: XED_NOTICE,
        docs: vec!["Instruction mnemonics (XED iclasses).".to_owned()],
        tokens,
    })
}
