use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitStr, Type};

pub fn expand(input: &DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            name,
            "`Id` can only be derived for a tuple struct `Name(u32)`",
        ));
    };
    let Fields::Unnamed(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(
            &data.fields,
            "`Id` requires a tuple struct with one `u32` field",
        ));
    };
    let mut fields = fields.unnamed.iter();
    let (Some(field), None) = (fields.next(), fields.next()) else {
        return Err(syn::Error::new_spanned(
            &data.fields,
            "`Id` requires exactly one field",
        ));
    };
    if !is_u32(&field.ty) {
        return Err(syn::Error::new_spanned(
            &field.ty,
            "`Id` field must be `u32`",
        ));
    }
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "`Id` cannot be derived for generic types",
        ));
    }

    let prefix = prefix(input)?.unwrap_or_else(|| format!("{name}#"));

    Ok(quote! {
        impl ::binbun_semantics::core::Id for #name {
            #[inline]
            fn from_raw(raw: u32) -> Self {
                Self(raw)
            }

            #[inline]
            fn raw(self) -> u32 {
                self.0
            }
        }

        impl ::core::fmt::Debug for #name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{}{}", #prefix, self.0)
            }
        }

        impl ::core::fmt::Display for #name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(self, f)
            }
        }
    })
}

fn is_u32(ty: &Type) -> bool {
    matches!(ty, Type::Path(path) if path.qself.is_none() && path.path.is_ident("u32"))
}

fn prefix(input: &DeriveInput) -> syn::Result<Option<String>> {
    let mut prefix = None;
    for attr in input.attrs.iter().filter(|attr| attr.path().is_ident("id")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("prefix") {
                prefix = Some(meta.value()?.parse::<LitStr>()?.value());
                Ok(())
            } else {
                Err(meta.error("unknown `id` option; expected `prefix = \"...\"`"))
            }
        })?;
    }
    Ok(prefix)
}
