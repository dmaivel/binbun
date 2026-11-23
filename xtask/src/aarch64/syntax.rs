//! `syntax.rs` of the decoder: alias selection, mnemonics and operands of
//! every form (an encoding's own syntax, or alias `k` of its aliases,
//! numbered from 1 in AARCHMRS order). Every A64 encoding has its syntax:
//! generation fails, listing the keys without a symbol, otherwise.

use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::quote;
use xtask::aarchmrs::Package;

use super::emit::encoding_ident;
use super::model::Encoding;
use super::symbols::{Form, Missing, MnemonicPiece};
use super::{AARCHMRS_NOTICE, aliases, output};
use crate::Result;
use crate::codegen::{GeneratedFile, lit};

/// One form's generated pieces.
struct Generated {
    encoding: usize,
    alias: u8,
    mnemonic: TokenStream,
    operands: TokenStream,
}

/// The mnemonic expression: a string, or a `match` over the value of the
/// one variable piece.
fn mnemonic(form: &str, pieces: &[MnemonicPiece]) -> Result<TokenStream> {
    let variable: Vec<usize> = pieces
        .iter()
        .enumerate()
        .filter(|(_, piece)| matches!(piece, MnemonicPiece::Choice(..)))
        .map(|(i, _)| i)
        .collect();
    let text = |value: Option<usize>| -> String {
        pieces
            .iter()
            .map(|piece| match piece {
                MnemonicPiece::Text(text) => text.clone(),
                MnemonicPiece::Choice(_, names) => value
                    .and_then(|value| names.get(value))
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect()
    };
    match variable.as_slice() {
        [] => {
            let text = text(None);
            Ok(quote! { #text })
        }
        [index] => {
            let Some(MnemonicPiece::Choice(value, names)) = pieces.get(*index) else {
                return Err(format!("{form}: mnemonic piece").into());
            };
            let arms = (0..names.len()).map(|i| {
                let (value, text) = (lit(u64::try_from(i).unwrap_or_default()), text(Some(i)));
                quote! { #value => #text }
            });
            Ok(quote! {
                match #value {
                    #(#arms,)*
                    _ => "",
                }
            })
        }
        _ => Err(format!("{form}: more than one variable mnemonic piece").into()),
    }
}

/// The arms of `mnemonic`: per encoding, a `match` over its aliases with
/// its own syntax as the rest; encodings with the same code share an arm.
fn mnemonics(
    forms: &[Generated],
    variants: &[proc_macro2::Ident],
) -> Result<BTreeMap<String, (TokenStream, Vec<TokenStream>)>> {
    let mut by_encoding: BTreeMap<usize, Vec<&Generated>> = BTreeMap::new();
    for form in forms {
        by_encoding.entry(form.encoding).or_default().push(form);
    }
    let mut arms: BTreeMap<String, (TokenStream, Vec<TokenStream>)> = BTreeMap::new();
    for (index, variant) in variants.iter().enumerate() {
        let forms = by_encoding.get(&index).map_or(&[][..], Vec::as_slice);
        let Some(own) = forms.iter().find(|form| form.alias == 0) else {
            return Err(format!("{variant}: no syntax").into());
        };
        let own = &own.mnemonic;
        let aliases: Vec<TokenStream> = forms
            .iter()
            .filter(|form| form.alias != 0)
            .map(|form| {
                let (alias, code) = (lit(form.alias), &form.mnemonic);
                quote! { #alias => #code, }
            })
            .collect();
        let code = if aliases.is_empty() {
            own.clone()
        } else {
            quote! { match alias { #(#aliases)* _ => #own } }
        };
        arms.entry(code.to_string())
            .or_insert_with(|| (code, Vec::new()))
            .1
            .push(quote! { Encoding::#variant });
    }
    Ok(arms)
}

/// Generates `syntax.rs`.
pub fn generate(encodings: &[Encoding<'_>], package: &Package) -> Result<(GeneratedFile, usize)> {
    let rules = &package.assembly_rules;
    let mut missing = Missing::default();
    let mut forms: Vec<Generated> = Vec::new();
    let mut selects = Vec::new();
    for (index, encoding) in encodings.iter().enumerate() {
        let path: Vec<&str> = encoding.groups.iter().map(|g| g.name.as_str()).collect();
        let path = path.join("/");
        let instruction = encoding.instruction;
        let variant = encoding_ident(encoding.name())?;
        let own = Form {
            name: encoding.name().to_owned(),
            path: &path,
            instruction,
            assembly: &instruction.assembly,
            encoded_in: &instruction.encoded_in,
        };
        let mut push = |form: &Form<'_>, alias: u8, missing: &mut Missing| -> Result<()> {
            if let Some(syntax) = form.syntax(rules, missing)? {
                forms.push(Generated {
                    encoding: index,
                    alias,
                    mnemonic: mnemonic(&form.name, &syntax.mnemonic)?,
                    operands: syntax.operands,
                });
            }
            Ok(())
        };
        push(&own, 0, &mut missing)?;
        let mut tests = Vec::new();
        let mut fallback = quote! { 0 };
        for alias in aliases::ordered(encoding.name(), &instruction.aliases) {
            let number = instruction
                .aliases
                .iter()
                .position(|other| std::ptr::eq(other, alias))
                .map_or(0, |i| i + 1);
            let number = u8::try_from(number)?;
            let form = Form {
                name: format!("{}__{}", encoding.name(), alias.name),
                path: &path,
                instruction,
                assembly: &alias.assembly,
                encoded_in: &alias.encoded_in,
            };
            push(&form, number, &mut missing)?;
            let context = |error: Box<dyn std::error::Error>| format!("{}: {error}", form.name);
            let condition = if aliases::unconditional(encoding.name(), &alias.name) {
                quote! { true }
            } else {
                aliases::condition(&alias.condition, &instruction.encoding).map_err(context)?
            };
            let preferred =
                aliases::condition(&alias.preferred, &instruction.encoding).map_err(context)?;
            let added = aliases::added(encoding.name(), &alias.name, &instruction.encoding)
                .map_err(context)?;
            let test = aliases::and(&aliases::and(&condition, &added), &preferred);
            let number = lit(number);
            if test.to_string() == "true" {
                // Later aliases are never reached.
                fallback = quote! { #number };
                break;
            }
            tests.push(quote! { if #test { #number } });
        }
        if !tests.is_empty() || fallback.to_string() != "0" {
            selects.push(quote! {
                Encoding::#variant => #(#tests else)* { #fallback }
            });
        }
    }
    missing.check()?;

    let variants: Vec<_> = encodings
        .iter()
        .map(|e| encoding_ident(e.name()))
        .collect::<Result<_>>()?;
    let arm = |form: &Generated| {
        let variant = &variants[form.encoding];
        let alias = lit(form.alias);
        quote! { (Encoding::#variant, #alias) }
    };
    // Forms with the same code share an arm.
    let mut operands: BTreeMap<String, (TokenStream, Vec<TokenStream>)> = BTreeMap::new();
    for form in &forms {
        if !form.operands.is_empty() {
            operands
                .entry(form.operands.to_string())
                .or_insert_with(|| (form.operands.clone(), Vec::new()))
                .1
                .push(arm(form));
        }
    }
    let mnemonic_arms = mnemonics(&forms, &variants)?
        .into_values()
        .map(|(code, patterns)| {
            quote! { #(#patterns)|* => #code, }
        });
    let operand_arms = operands.into_values().map(|(code, patterns)| {
        quote! { #(#patterns)|* => { #code } }
    });

    let tokens = quote! {
        use super::encoding::Encoding;
        use crate::operand::*;
        use crate::pseudocode;
        use super::sysreg;

        /// The alias of `encoding` that `word` is written as (its number,
        /// from 1 in AARCHMRS order), or 0 for the encoding's own syntax.
        pub fn select(encoding: Encoding, word: u32) -> u8 {
            match encoding {
                #(#selects,)*
                _ => 0,
            }
        }

        /// The mnemonic of alias `alias` of `encoding` (0: its own syntax),
        /// lower case and with any suffix (`b.eq`).
        pub fn mnemonic(encoding: Encoding, alias: u8, word: u32) -> &'static str {
            match encoding {
                #(#mnemonic_arms)*
            }
        }

        /// Pushes the operands of alias `alias` of `encoding` for `word`.
        pub fn operands(encoding: Encoding, alias: u8, word: u32, ops: &mut Operands) {
            match (encoding, alias) {
                #(#operand_arms)*
                _ => {}
            }
        }
    };
    Ok((
        GeneratedFile {
            path: output("syntax"),
            notice: AARCHMRS_NOTICE,
            docs: vec![
                "Alias selection, mnemonics and operands of the A64 syntax binbun".to_owned(),
                "writes (`xtask/src/aarch64/symbols`).".to_owned(),
            ],
            tokens,
        },
        forms.len(),
    ))
}
