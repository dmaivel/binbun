//! Per-opcode decode handlers (`generated/handlers.rs`).
//!
//! After the length decoder's front (prefixes and opcode), one function per
//! `(encoding space, map, opcode)` does the rest with everything known about
//! the opcode folded in: the length decoder's tail for its packed entry (a
//! constant), the spine nonterminals, identification, and the chosen
//! instruction's pattern and operand nonterminals, called directly.
//!
//! Each such handler is the tail, then the opcode's *body* (everything
//! after the tail). The legacy maps also get 64-bit handlers, whose tail is
//! specialised for 64-bit mode, sharing the body.

use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::dynamic::Chains;
use super::identify::Bin;
use super::ild::OpcodeEntries;
use super::output;
use crate::Result;
use crate::codegen::{GeneratedFile, XED_NOTICE, count, lit};

/// The legacy map whose opcode is the instruction's last byte (3DNow!),
/// known only after the tail: handled by the generic path.
const TRAILING_OPCODE_MAP: (u8, u8) = (0, 4);

pub fn generate(entries: &OpcodeEntries, bins: &[Bin], chains: &Chains) -> Result<GeneratedFile> {
    let bins: BTreeMap<(u8, u8, u8), &Bin> = bins
        .iter()
        .map(|b| ((b.space, b.map, b.opcode), b))
        .collect();
    let mut functions = Vec::new();
    // First, for absent maps: nothing to read.
    let mut tables = vec![quote!([unknown::<0>; 256])];
    let mut tail_tables = vec![quote!([tail_of::<0>; 256])];
    let mut tables64 = vec![quote!([unknown64::<0>; 256])];
    for (&(space, map), opcodes) in entries {
        // The legacy maps reached without a trailing opcode get 64-bit
        // handlers; they come first in `entries`, so their table indices
        // match `HANDLERS`'.
        let legacy = space == 0 && (space, map) != TRAILING_OPCODE_MAP;
        let mut slots = Vec::with_capacity(256);
        let mut tail_slots = Vec::with_capacity(256);
        let mut slots64 = Vec::with_capacity(256);
        for (opcode, &entry) in (0..=255u8).zip(opcodes) {
            let entry = lit(entry);
            let slot = if (space, map) == TRAILING_OPCODE_MAP {
                tail_slots.push(quote!(generic_tail));
                quote!(generic)
            } else if let Some(bin) = bins.get(&(space, map, opcode)) {
                let name = format_ident!("h_{space}_{map}_{opcode:02x}");
                let body = format_ident!("b_{space}_{map}_{opcode:02x}");
                functions.push(body_function(&body, bin, chains)?);
                functions.push(quote! {
                    fn #name(s: &mut State) -> u16 {
                        tail_of::<#entry>(s);
                        if s.error != 0 {
                            return 0;
                        }
                        #body(s)
                    }
                });
                if legacy {
                    let name64 = format_ident!("h64_{map}_{opcode:02x}");
                    functions.push(quote! {
                        fn #name64(s: &mut State) -> u16 {
                            tail64_of::<#entry>(s);
                            if s.error != 0 {
                                return 0;
                            }
                            #body(s)
                        }
                    });
                    slots64.push(quote!(#name64));
                }
                tail_slots.push(quote!(tail_of::<#entry>));
                quote!(#name)
            } else {
                if legacy {
                    slots64.push(quote!(unknown64::<#entry>));
                }
                tail_slots.push(quote!(tail_of::<#entry>));
                quote!(unknown::<#entry>)
            };
            slots.push(slot);
        }
        tables.push(quote!([#(#slots),*]));
        tail_tables.push(quote!([#(#tail_slots),*]));
        if legacy {
            if tables64.len() != tables.len() - 1 {
                return Err("the legacy maps must come first".into());
            }
            tables64.push(quote!([#(#slots64),*]));
        }
    }
    let table_count = count(tables.len());
    let table64_count = count(tables64.len());

    let tokens = quote! {
        use crate::generated::{dynamic, identify};
        use crate::generated::state::State;
        use crate::ild::{tail64_of, tail_of};

        /// Decodes the rest of an instruction whose head the length decoder
        /// has read; returns the instruction number, or 0 with or without
        /// an error in the state.
        pub type Handler = fn(&mut State) -> u16;

        /// The handlers of each map, indexed like `ild::OPCODES` (the first
        /// table is for absent maps).
        pub static HANDLERS: [[Handler; 256]; #table_count] = [#(#tables),*];

        /// The 64-bit-mode handlers of the legacy maps reached without a
        /// trailing opcode, indexed like [`HANDLERS`].
        pub static HANDLERS64: [[Handler; 256]; #table64_count] = [#(#tables64),*];

        /// The length decoder's tail of each opcode, indexed like
        /// [`HANDLERS`].
        pub static TAILS: [[fn(&mut State); 256]; #table_count] = [#(#tail_tables),*];

        /// The tail of an opcode known only after it (3DNow!).
        fn generic_tail(s: &mut State) {
            let entry = s.opcode_entry();
            s.tail(entry);
        }

        /// An opcode no instruction has: the length decoder's tail only.
        fn unknown<const ENTRY: u16>(s: &mut State) -> u16 {
            tail_of::<ENTRY>(s);
            0
        }

        /// [`unknown`] in 64-bit mode.
        fn unknown64<const ENTRY: u16>(s: &mut State) -> u16 {
            tail64_of::<ENTRY>(s);
            0
        }

        /// Any opcode, interpreting its packed entry and dispatching
        /// identification and nonterminals through tables.
        pub fn generic(s: &mut State) -> u16 {
            let entry = s.opcode_entry();
            s.tail(entry);
            if s.error != 0 {
                return 0;
            }
            dynamic::part1(s);
            if s.error != 0 {
                return 0;
            }
            let number = identify::identify(s);
            if number == 0 {
                return 0;
            }
            dynamic::pattern(s, number);
            if s.error != 0 {
                return 0;
            }
            dynamic::operands(s, number);
            number
        }

        #(#functions)*
    };
    Ok(GeneratedFile {
        path: output("handlers"),
        notice: XED_NOTICE,
        docs: vec!["Per-opcode decode handlers.".to_owned()],
        tokens,
    })
}

/// The body of an opcode's handlers: everything after the length decoder's
/// tail.
fn body_function(name: &proc_macro2::Ident, bin: &Bin, chains: &Chains) -> Result<TokenStream> {
    let identify = &bin.function;
    let arms = bin
        .numbers
        .iter()
        .map(|&number| {
            let index = usize::from(number)
                .checked_sub(1)
                .ok_or("instruction number 0")?;
            let pattern = (!chains.empty_patterns[index]).then(|| {
                let f = &chains.patterns[index];
                quote!(dynamic::#f(s); if s.error != 0 { return 0; })
            });
            let operands = (!chains.empty_operands[index]).then(|| {
                let f = &chains.operands[index];
                quote!(dynamic::#f(s);)
            });
            let number = lit(number);
            Ok(quote!(#number => { #pattern #operands }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(quote! {
        // Small (calls), and inlined into the handler and its 64-bit twin.
        #[expect(clippy::inline_always, reason = "measured: a call per decode")]
        #[inline(always)]
        fn #name(s: &mut State) -> u16 {
            dynamic::part1(s);
            let number = identify::#identify(s);
            match number {
                #(#arms)*
                _ => return 0,
            }
            number
        }
    })
}
