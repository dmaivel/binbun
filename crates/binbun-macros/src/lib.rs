//! Procedural macros for binbun.
//!
//! Do not depend on this crate directly: `binbun_semantics::core`
//! re-exports every macro next to the trait it implements, and the
//! generated code names `::binbun_semantics::core`.
//!
//! - [`derive@Id`]: a typed `u32` index, implementing
//!   `binbun_semantics::core::Id`.
//! - [`derive@Keyword`]: a fieldless enum with one spelling per variant,
//!   implementing `binbun_semantics::core::Keyword`, `FromStr` and
//!   `Display`.

mod id;
mod keyword;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derives `binbun_semantics::core::Id` for a single-field tuple struct
/// over `u32`.
///
/// `Debug` and `Display` print the raw index after a prefix, `#[id(prefix = "v")]`
/// (default: the type name followed by `#`).
///
/// ```ignore
/// #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
/// #[id(prefix = "blk")]
/// pub struct Block(u32);
/// ```
#[proc_macro_derive(Id, attributes(id))]
pub fn derive_id(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    id::expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derives `binbun_semantics::core::Keyword`, `FromStr` and `Display` for
/// a fieldless enum whose variants each have one textual spelling.
///
/// A variant's spelling is `#[keyword("...")]`, otherwise its name converted
/// by the container's `#[keyword(rename_all = "...")]` (`"lowercase"`,
/// `"UPPERCASE"`, `"snake_case"`, `"SCREAMING_SNAKE_CASE"`, `"kebab-case"`),
/// otherwise the variant name itself. Duplicate spellings are a compile error.
///
/// ```ignore
/// #[derive(Clone, Copy, PartialEq, Eq, Debug, Keyword)]
/// #[keyword(rename_all = "lowercase")]
/// pub enum Access {
///     #[keyword("r")]
///     Read,
///     Write,
/// }
/// ```
#[proc_macro_derive(Keyword, attributes(keyword))]
pub fn derive_keyword(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    keyword::expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
