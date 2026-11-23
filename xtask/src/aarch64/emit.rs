//! Rendering the generated modules of `binbun-aarch64`.

use std::collections::BTreeMap;

use proc_macro2::{Ident, Literal, TokenStream};
use quote::quote;

use super::checks::{Rejected, Test};
use super::model::Encoding;
use super::tree::{Node, Tree};
use super::{AARCHMRS_NOTICE, output};
use crate::Result;
use crate::codegen::{self, GeneratedFile};
use crate::naming::ident;

/// A 32-bit hexadecimal literal (`0x1f000000`).
fn hex(value: u32) -> Literal {
    format!("{value:#010x}")
        .parse()
        .unwrap_or_else(|_| Literal::u32_unsuffixed(value))
}

/// The variant for an AARCHMRS encoding name: the name itself, which the
/// generator checks is an identifier and not a keyword.
pub fn encoding_ident(name: &str) -> Result<Ident> {
    syn::parse_str::<Ident>(name).map_err(|_| format!("`{name}` is not a Rust identifier"))?;
    ident(name)
}

/// The variant for a feature: its name without `FEAT_`.
pub fn feature_ident(name: &str) -> Result<Ident> {
    let stem = name
        .strip_prefix("FEAT_")
        .ok_or_else(|| format!("feature `{name}` does not start with FEAT_"))?;
    syn::parse_str::<Ident>(stem).map_err(|_| format!("`{stem}` is not a Rust identifier"))?;
    ident(stem)
}

/// `feature.rs`: the features A64 encodings name.
pub fn features(names: &[&str], fat: &[bool]) -> Result<GeneratedFile> {
    let variants = names
        .iter()
        .map(|name| feature_ident(name))
        .collect::<Result<Vec<_>>>()?;
    let count = codegen::count(names.len());
    let docs = names.iter().map(|name| format!(" `{name}`"));
    let fat_variants = variants
        .iter()
        .zip(fat)
        .filter(|(_, fat)| **fat)
        .map(|(v, _)| v);
    let tokens = quote! {
        use core::fmt;
        use core::str::FromStr;

        use crate::UnknownName;

        /// An architecture feature (`FEAT_*`) that A64 encodings require.
        ///
        /// The variant is the feature's name without `FEAT_`: `FEAT_SVE2p1` is
        /// [`Feature::SVE2p1`].
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum Feature {
            #(#[doc = #docs] #variants,)*
        }

        impl Feature {
            /// Number of features.
            pub const COUNT: usize = #count;

            /// Every feature, in declaration (alphabetical) order.
            pub const ALL: [Self; Self::COUNT] = [#(Self::#variants),*];

            /// The feature's name, e.g. `FEAT_SVE2p1`.
            pub const fn name(self) -> &'static str {
                match self {
                    #(Self::#variants => #names,)*
                }
            }

            /// Whether the feature belongs to an unannounced architecture
            /// version (it implies a `vFATAp*` version in Arm's FAT
            /// specification).
            pub const fn fat(self) -> bool {
                matches!(self, #(Self::#fat_variants)|*)
            }
        }

        impl fmt::Display for Feature {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }

        impl FromStr for Feature {
            type Err = UnknownName;

            /// Parses a feature's name, e.g. `FEAT_SVE2p1` (exact,
            /// case-sensitive).
            fn from_str(name: &str) -> Result<Self, Self::Err> {
                match Self::ALL.binary_search_by(|feature| feature.name().cmp(name)) {
                    Ok(index) => Self::ALL.get(index).copied().ok_or(UnknownName),
                    Err(_) => Err(UnknownName),
                }
            }
        }
    };
    Ok(GeneratedFile {
        path: output("feature"),
        notice: AARCHMRS_NOTICE,
        docs: vec!["Architecture features of A64 encodings.".to_owned()],
        tokens,
    })
}

/// `encoding.rs`: one variant per A64 encoding and what is known about it.
pub fn encodings(encodings: &[Encoding<'_>]) -> Result<GeneratedFile> {
    let variants = encodings
        .iter()
        .map(|e| encoding_ident(e.name()))
        .collect::<Result<Vec<_>>>()?;
    let names: Vec<&str> = encodings.iter().map(Encoding::name).collect();
    let count = codegen::count(encodings.len());
    let docs = encodings.iter().map(|e| {
        let path: Vec<&str> = e.groups.iter().map(|g| g.name.as_str()).collect();
        format!(
            " `{}` in `{}`",
            e.instruction.mnemonic().unwrap_or("?"),
            path.join("/")
        )
    });

    // Arms grouped by value, in order of first appearance.
    let grouped = |value: &dyn Fn(&Encoding<'_>) -> TokenStream| {
        let mut arms: Vec<(String, TokenStream, Vec<&Ident>)> = Vec::new();
        for (encoding, variant) in encodings.iter().zip(&variants) {
            let tokens = value(encoding);
            let key = tokens.to_string();
            match arms.iter_mut().find(|(k, _, _)| *k == key) {
                Some((_, _, list)) => list.push(variant),
                None => arms.push((key, tokens, vec![variant])),
            }
        }
        arms.into_iter()
            .map(|(_, tokens, list)| quote! { #(Self::#list)|* => #tokens })
    };
    let mnemonics = grouped(&|e| {
        let mnemonic = e.instruction.mnemonic().unwrap_or_default();
        quote! { #mnemonic }
    });
    let groups = grouped(&|e| {
        let path = e.groups.iter().map(|g| g.name.as_str());
        quote! { &[#(#path),*] }
    });
    for encoding in encodings {
        for feature in &encoding.features {
            feature_ident(feature)?;
        }
    }
    let features = grouped(&|e| {
        let list = e.features.iter().filter_map(|f| feature_ident(f).ok());
        quote! { &[#(Feature::#list),*] }
    });
    let fat = encodings
        .iter()
        .zip(&variants)
        .filter(|(e, _)| e.fat)
        .map(|(_, v)| v);

    let tokens = quote! {
        use core::fmt;
        use core::str::FromStr;

        use super::feature::Feature;
        use crate::UnknownName;

        /// An A64 encoding, as Arm's specification names it.
        ///
        /// The variant is the AARCHMRS encoding name unchanged (`ADD_32_addsub_imm`,
        /// `add_z_zz_`): the names are unique, valid identifiers, so the mapping
        /// is the identity and [`Encoding::name`] returns the variant's name.
        #[allow(non_camel_case_types, reason = "variants are Arm's encoding names")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        pub enum Encoding {
            #(#[doc = #docs] #variants,)*
        }

        impl Encoding {
            /// Number of encodings.
            pub const COUNT: usize = #count;

            /// Every encoding, in declaration (byte-wise alphabetical) order.
            pub const ALL: [Self; Self::COUNT] = [#(Self::#variants),*];

            /// The AARCHMRS name, e.g. `ADD_32_addsub_imm`.
            pub const fn name(self) -> &'static str {
                match self {
                    #(Self::#variants => #names,)*
                }
            }

            /// The mnemonic of the encoding's own syntax (not of an alias),
            /// upper case as Arm writes it, e.g. `ADD` (also for `mov`
            /// spellings of it).
            pub const fn mnemonic(self) -> &'static str {
                match self {
                    #(#mnemonics,)*
                }
            }

            /// The names of the groups the encoding sits in, outermost first,
            /// e.g. `["dpimm", "addsub_imm"]`.
            pub const fn groups(self) -> &'static [&'static str] {
                match self {
                    #(#groups,)*
                }
            }

            /// The features the encoding's condition names (those of the
            /// innermost group naming any if the encoding's own names none;
            /// empty for the base instruction set). Several features mean the
            /// condition combines them, usually as alternatives
            /// (`FEAT_SVE || FEAT_SME`).
            pub const fn features(self) -> &'static [Feature] {
                match self {
                    #(#features,)*
                }
            }

            /// Whether the encoding exists only with features of unannounced
            /// architecture versions (Arm's FAT specification).
            pub const fn fat(self) -> bool {
                matches!(self, #(Self::#fat)|*)
            }
        }

        impl fmt::Display for Encoding {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }

        impl FromStr for Encoding {
            type Err = UnknownName;

            /// Parses an AARCHMRS encoding name (exact, case-sensitive).
            fn from_str(name: &str) -> Result<Self, Self::Err> {
                match Self::ALL.binary_search_by(|encoding| encoding.name().cmp(name)) {
                    Ok(index) => Self::ALL.get(index).copied().ok_or(UnknownName),
                    Err(_) => Err(UnknownName),
                }
            }
        }
    };
    Ok(GeneratedFile {
        path: output("encoding"),
        notice: AARCHMRS_NOTICE,
        docs: vec!["A64 encodings.".to_owned()],
        tokens,
    })
}

/// `decode.rs`: the decode tree, each encoding's decode-time checks applied
/// where the tree finds it.
pub fn decode(
    encodings: &[Encoding<'_>],
    tree: &Tree,
    rejected: &Rejected,
) -> Result<GeneratedFile> {
    let variants = encodings
        .iter()
        .map(|e| encoding_ident(e.name()))
        .collect::<Result<Vec<_>>>()?;
    let (checks, check_functions) = checks(rejected);
    let decoder = Decoder {
        tree,
        encodings,
        variants: &variants,
        checks: &checks,
    };
    let functions = (0..tree.nodes.len()).filter_map(|id| decoder.function(id));
    let tables = rejected.tables.iter().enumerate().map(|(index, bits)| {
        let name = table(index);
        let len = codegen::count(bits.len());
        let bits = bits.iter().map(|&word| {
            format!("{word:#018x}")
                .parse::<Literal>()
                .unwrap_or_else(|_| Literal::u64_unsuffixed(word))
        });
        quote! { const #name: [u64; #len] = [#(#bits),*]; }
    });

    let tokens = quote! {
        use super::encoding::Encoding;
        use crate::Error;

        #(#functions)*

        #(#check_functions)*

        #(#tables)*

        /// Bit `index` of `table`.
        const fn bit(table: &[u64], index: u32) -> bool {
            (table[(index / 64) as usize] >> (index % 64)) & 1 != 0
        }
    };
    Ok(GeneratedFile {
        path: output("decode"),
        notice: AARCHMRS_NOTICE,
        docs: vec![
            "The A64 decode tree: switches on fixed bits, then the remaining fixed".to_owned(),
            "bits and field conditions of the few encodings left, then the decode-time".to_owned(),
            "checks of the encoding found.".to_owned(),
        ],
        tokens,
    })
}

fn table(index: usize) -> Ident {
    Ident::new(&format!("TABLE_{index}"), proc_macro2::Span::call_site())
}

/// The expression of one test of `word`.
fn test(test: &Test) -> TokenStream {
    match test {
        Test::Cubes(cubes) => {
            let tests = cubes.iter().map(|c| {
                let (mask, value) = (hex(c.mask), hex(c.value));
                quote! { word & #mask == #value }
            });
            quote! { #(#tests)||* }
        }
        Test::Table {
            fields,
            table: index,
        } => {
            let mut offset = 0;
            let mut parts = Vec::new();
            for &(start, width) in fields.iter().rev() {
                let field = extract(start, width);
                parts.push(if offset == 0 {
                    field
                } else {
                    let offset = codegen::lit(offset);
                    quote! { (#field) << #offset }
                });
                offset += width;
            }
            let name = table(*index);
            quote! { bit(&#name, #(#parts)|*) }
        }
    }
}

/// `(word >> start) & mask`, without a shift by 0.
fn extract(start: u32, width: u32) -> TokenStream {
    let mask = codegen::lit((1u32 << width) - 1);
    if start == 0 {
        return quote! { word & #mask };
    }
    let start = codegen::lit(start);
    quote! { (word >> #start) & #mask }
}

/// The functions applying the decode-time checks, encodings with the same
/// checks sharing one, and per encoding the name of its function (`None`
/// for encodings without checks). A function returns its `encoding`
/// argument unless the word is UNDEFINED or else CONSTRAINED UNPREDICTABLE.
fn checks(rejected: &Rejected) -> (Vec<Option<Ident>>, Vec<TokenStream>) {
    let mut names: BTreeMap<(&[Test], &[Test]), Ident> = BTreeMap::new();
    let mut functions = Vec::new();
    let per_encoding = rejected
        .undefined
        .iter()
        .zip(&rejected.unpredictable)
        .map(|(undefined, unpredictable)| {
            if undefined.is_empty() && unpredictable.is_empty() {
                return None;
            }
            let key = (undefined.as_slice(), unpredictable.as_slice());
            let name = names.entry(key).or_insert_with(|| {
                let name = Ident::new(
                    &format!("check{}", functions.len()),
                    proc_macro2::Span::call_site(),
                );
                let rejects = [
                    (undefined, quote! { Error::Undefined }),
                    (unpredictable, quote! { Error::Unpredictable }),
                ]
                .into_iter()
                .filter(|(tests, _)| !tests.is_empty())
                .map(|(tests, error)| {
                    let tests = tests.iter().map(test);
                    quote! { if #(#tests)||* { return Err(#error); } }
                });
                functions.push(quote! {
                    #[inline]
                    const fn #name(word: u32, encoding: Encoding) -> Result<Encoding, Error> {
                        #(#rejects)*
                        Ok(encoding)
                    }
                });
                name
            });
            Some(name.clone())
        })
        .collect();
    (per_encoding, functions)
}

/// What the decode tree is emitted from.
struct Decoder<'a> {
    tree: &'a Tree,
    encodings: &'a [Encoding<'a>],
    variants: &'a [Ident],
    /// Per encoding, its check function from [`checks`].
    checks: &'a [Option<Ident>],
}

impl Decoder<'_> {
    fn name(id: usize) -> Ident {
        if id == 0 {
            return Ident::new("decode", proc_macro2::Span::call_site());
        }
        Ident::new(&format!("node{id}"), proc_macro2::Span::call_site())
    }

    /// The function of node `id`: the root, and switches wider than a bit.
    fn function(&self, id: usize) -> Option<TokenStream> {
        let body = match &self.tree.nodes[id] {
            Node::Switch {
                shift,
                width,
                children,
            } if *width > 1 => {
                // Values leading to the same node share an arm, as an
                // or-pattern: about 15% faster than ranges (`0..=3`) on the
                // decode benchmark.
                let mut arms: Vec<(usize, Vec<Literal>)> = Vec::new();
                for (value, child) in children.iter().enumerate() {
                    let Some(child) = *child else { continue };
                    let value = codegen::count(value);
                    match arms.iter_mut().find(|(node, _)| *node == child) {
                        Some((_, values)) => values.push(value),
                        None => arms.push((child, vec![value])),
                    }
                }
                let arms = arms.into_iter().map(|(child, values)| {
                    let body = self.expression(child);
                    quote! { #(#values)|* => #body }
                });
                let field = extract(*shift, *width);
                quote! {
                    match #field {
                        #(#arms,)*
                        _ => Err(Error::Unallocated),
                    }
                }
            }
            Node::Switch { .. } | Node::Leaf { .. } if id == 0 => self.inline(id),
            Node::Switch { .. } | Node::Leaf { .. } => return None,
        };
        let name = Self::name(id);
        let (docs, visibility) = if id == 0 {
            (
                quote! {
                    /// The encoding whose fixed bits and field conditions `word`
                    /// satisfies (the most specific if several do), unless its
                    /// decode-time checks reject the word.
                },
                quote! { pub },
            )
        } else {
            (TokenStream::new(), TokenStream::new())
        };
        Some(quote! {
            #docs
            #[inline]
            #visibility fn #name(word: u32) -> Result<Encoding, Error> {
                #body
            }
        })
    }

    /// The expression decoding `word` from node `id`: a call for switches
    /// wider than a bit, else inline code.
    fn expression(&self, id: usize) -> TokenStream {
        match &self.tree.nodes[id] {
            Node::Switch { width, .. } if *width > 1 => {
                let name = Self::name(id);
                quote! { #name(word) }
            }
            Node::Switch { .. } | Node::Leaf { .. } => self.inline(id),
        }
    }

    /// The code of a one-bit switch (a bit test) or a leaf.
    fn inline(&self, id: usize) -> TokenStream {
        match &self.tree.nodes[id] {
            Node::Switch {
                shift, children, ..
            } => {
                let test = hex(1 << shift);
                let branch = |child: Option<&Option<usize>>| {
                    child.copied().flatten().map_or_else(
                        || quote! { Err(Error::Unallocated) },
                        |child| self.expression(child),
                    )
                };
                let (zero, one) = (branch(children.first()), branch(children.get(1)));
                quote! { if word & #test != 0 { #one } else { #zero } }
            }
            Node::Leaf { candidates, known } => self.leaf(candidates, *known),
        }
    }

    /// The encoding `c` found: its checks applied.
    fn found(&self, c: usize) -> TokenStream {
        let variant = &self.variants[c];
        self.checks[c].as_ref().map_or_else(
            || quote! { Ok(Encoding::#variant) },
            |check| quote! { #check(word, Encoding::#variant) },
        )
    }

    /// Tests of each candidate's remaining fixed bits and field conditions,
    /// most specific first.
    fn leaf(&self, candidates: &[usize], known: u32) -> TokenStream {
        let mut branches = Vec::new();
        let mut tail = quote! { Err(Error::Unallocated) };
        for &c in candidates {
            let encoding = &self.encodings[c];
            let rest = encoding.fixed.mask & !known;
            let mut tests = Vec::new();
            if rest != 0 {
                let (mask, value) = (hex(rest), hex(encoding.fixed.value & rest));
                tests.push(quote! { word & #mask == #value });
            }
            for cube in &encoding.excluded {
                let (mask, value) = (hex(cube.mask), hex(cube.value));
                tests.push(quote! { word & #mask != #value });
            }
            if tests.is_empty() {
                // Candidates after one without tests are unreachable.
                tail = self.found(c);
                break;
            }
            branches.push((tests, self.found(c)));
        }
        let mut branches = branches.into_iter();
        let Some((tests, found)) = branches.next() else {
            return tail;
        };
        let rest = branches.map(|(tests, found)| {
            quote! { else if #(#tests)&&* { #found } }
        });
        quote! { if #(#tests)&&* { #found } #(#rest)* else { #tail } }
    }
}
