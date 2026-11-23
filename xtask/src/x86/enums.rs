//! Enums of XED names: one CamelCase variant per name, with `as_str`,
//! `ALL`, `COUNT` and `Display`.

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};

use crate::Result;
use crate::codegen::count;
use crate::naming::{camel_case, unique_idents};

/// The variants for `names` (XED spellings, sorted and unique). A name that
/// starts with digits moves them after its first letter: `3DNOW` becomes
/// `D3now`.
pub fn variants(names: &[&str]) -> Result<Vec<Ident>> {
    unique_idents(names.iter().copied(), |name| {
        let digits = name.len() - name.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits == 0 || digits == name.len() {
            return camel_case(name);
        }
        let (number, rest) = name.split_at(digits);
        let mut letters = rest.chars();
        let first = letters.next().map(|c| c.to_ascii_uppercase()).into_iter();
        camel_case(
            &first
                .chain(number.chars())
                .chain(letters)
                .collect::<String>(),
        )
    })
}

/// An enum `name` documented by `doc` with one variant per XED name. The
/// enclosing module must `use core::fmt`.
pub fn simple(name: &str, doc: &str, names: &[&str]) -> Result<TokenStream> {
    let ident = format_ident!("{name}");
    let variants = variants(names)?;
    let docs = names.iter().map(|name| format!(" `{name}`"));
    let total = count(names.len());
    let repr = if names.len() <= 256 {
        quote!(u8)
    } else {
        quote!(u16)
    };
    Ok(quote! {
        #[doc = #doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(#repr)]
        pub enum #ident {
            #(#[doc = #docs] #variants,)*
        }

        impl #ident {
            /// Number of variants.
            pub const COUNT: usize = #total;

            /// Every variant, in declaration (alphabetical) order.
            pub const ALL: [Self; Self::COUNT] = [#(Self::#variants),*];

            /// XED's name.
            pub const fn as_str(self) -> &'static str {
                match self {
                    #(Self::#variants => #names,)*
                }
            }
        }

        impl fmt::Display for #ident {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    })
}
