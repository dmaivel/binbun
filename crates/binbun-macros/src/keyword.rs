use std::collections::HashMap;

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{Attribute, Data, DeriveInput, Fields, Ident, LitStr};

pub fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            name,
            "`Keyword` can only be derived for enums",
        ));
    };
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "`Keyword` cannot be derived for generic enums",
        ));
    }
    if data.variants.is_empty() {
        return Err(syn::Error::new_spanned(
            name,
            "`Keyword` needs at least one variant",
        ));
    }

    let rename = container_rename(&input.attrs)?;
    let mut seen: HashMap<String, &Ident> = HashMap::new();
    let mut variants = Vec::with_capacity(data.variants.len());
    let mut spellings = Vec::with_capacity(data.variants.len());
    for variant in &data.variants {
        if !matches!(variant.fields, Fields::Unit) {
            return Err(syn::Error::new_spanned(
                variant,
                "`Keyword` variants cannot have fields",
            ));
        }
        let spelling = match variant_spelling(&variant.attrs)? {
            Some(explicit) => explicit,
            None => rename.apply(&variant.ident.to_string()),
        };
        if let Some(previous) = seen.insert(spelling.clone(), &variant.ident) {
            return Err(syn::Error::new_spanned(
                &variant.ident,
                format!("keyword `{spelling}` is already used by `{previous}`"),
            ));
        }
        variants.push(&variant.ident);
        spellings.push(LitStr::new(&spelling, Span::call_site()));
    }
    let count = variants.len();

    Ok(quote! {
        impl ::binbun_semantics::core::Keyword for #name {
            const ALL: &'static [Self] = &[#(Self::#variants),*];

            fn as_str(&self) -> &'static str {
                match self {
                    #(Self::#variants => #spellings,)*
                }
            }

            fn from_keyword(text: &str) -> ::core::option::Option<Self> {
                match text {
                    #(#spellings => ::core::option::Option::Some(Self::#variants),)*
                    _ => ::core::option::Option::None,
                }
            }
        }

        impl #name {
            /// Number of variants.
            pub const COUNT: usize = #count;
        }

        impl ::core::str::FromStr for #name {
            type Err = ::binbun_semantics::core::UnknownKeyword;

            fn from_str(text: &str) -> ::core::result::Result<Self, Self::Err> {
                <Self as ::binbun_semantics::core::Keyword>::from_keyword(text)
                    .ok_or(::binbun_semantics::core::UnknownKeyword::new(::core::stringify!(#name)))
            }
        }

        impl ::core::fmt::Display for #name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(<Self as ::binbun_semantics::core::Keyword>::as_str(self))
            }
        }
    })
}

fn variant_spelling(attrs: &[Attribute]) -> syn::Result<Option<String>> {
    let mut spelling = None;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("keyword")) {
        if spelling.is_some() {
            return Err(syn::Error::new_spanned(
                attr,
                "duplicate `keyword` attribute",
            ));
        }
        let text: LitStr = attr.parse_args()?;
        if text.value().is_empty() {
            return Err(syn::Error::new_spanned(text, "a keyword cannot be empty"));
        }
        spelling = Some(text.value());
    }
    Ok(spelling)
}

/// How a variant name becomes its spelling when no explicit one is given.
#[derive(Clone, Copy)]
enum Rename {
    Verbatim,
    Lower,
    Upper,
    Snake,
    ScreamingSnake,
    Kebab,
}

impl Rename {
    fn apply(self, ident: &str) -> String {
        match self {
            Self::Verbatim => ident.to_owned(),
            Self::Lower => ident.to_lowercase(),
            Self::Upper => ident.to_uppercase(),
            Self::Snake => join_words(ident, '_').to_lowercase(),
            Self::ScreamingSnake => join_words(ident, '_').to_uppercase(),
            Self::Kebab => join_words(ident, '-').to_lowercase(),
        }
    }
}

fn container_rename(attrs: &[Attribute]) -> syn::Result<Rename> {
    let mut rename = Rename::Verbatim;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("keyword")) {
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("rename_all") {
                return Err(meta.error("unknown `keyword` option; expected `rename_all = \"...\"`"));
            }
            let style: LitStr = meta.value()?.parse()?;
            rename = match style.value().as_str() {
                "lowercase" => Rename::Lower,
                "UPPERCASE" => Rename::Upper,
                "snake_case" => Rename::Snake,
                "SCREAMING_SNAKE_CASE" => Rename::ScreamingSnake,
                "kebab-case" => Rename::Kebab,
                _ => {
                    return Err(syn::Error::new_spanned(
                        style,
                        "expected one of \"lowercase\", \"UPPERCASE\", \"snake_case\", \
                         \"SCREAMING_SNAKE_CASE\", \"kebab-case\"",
                    ));
                }
            };
            Ok(())
        })?;
    }
    Ok(rename)
}

/// Splits a `CamelCase` identifier into words and joins them with `separator`.
///
/// A word starts at an uppercase letter that follows a lowercase letter or a
/// digit, or that begins a new word after an acronym (`XMLHttp` → `XML`, `Http`).
/// Digits stay attached to the preceding word (`Avx512F` → `Avx512`, `F`).
fn join_words(ident: &str, separator: char) -> String {
    let chars: Vec<char> = ident.chars().collect();
    let mut out = String::with_capacity(ident.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        let prev = i.checked_sub(1).and_then(|p| chars.get(p));
        let next = chars.get(i + 1);
        let boundary = c.is_uppercase()
            && match prev {
                None => false,
                Some(p) if p.is_lowercase() || p.is_ascii_digit() => true,
                Some(p) => p.is_uppercase() && next.is_some_and(|n| n.is_lowercase()),
            };
        if boundary {
            out.push(separator);
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::join_words;

    #[test]
    fn splits_camel_case_words() {
        assert_eq!(join_words("ReadWrite", '_'), "Read_Write");
        assert_eq!(join_words("X87Alu", '_'), "X87_Alu");
        assert_eq!(join_words("XMLHttpRequest", '_'), "XML_Http_Request");
        assert_eq!(join_words("Avx512F", '_'), "Avx512_F");
        assert_eq!(join_words("Mode64", '_'), "Mode64");
    }
}
