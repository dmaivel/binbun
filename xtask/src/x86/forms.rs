//! The decoder's instruction table and `Form` (XED's *iform*).
//!
//! Every pattern of every selected instruction record is one instruction
//! (a form with a `REG[lo-hi]` range is one per `reg`, as in XED). Its form
//! name is the record's `IFORM`, or else XED's `compute_iform`: the iclass
//! followed by one word per operand that is not suppressed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use binbun_xed::StateMacros;
use binbun_xed::fields::{Field, Visibility as FieldVisibility};
use binbun_xed::instructions::Record;
use binbun_xed::operands::{self, Operand, Value, Visibility, Word};
use binbun_xed::pattern::{self, Pattern};
use proc_macro2::TokenStream;
use quote::quote;

use super::enums;
use super::operands::OperandLists;
use super::output;
use crate::Result;
use crate::codegen::{self, GeneratedFile, XED_NOTICE, lit};
use crate::naming::ident;

/// One decodable instruction: a pattern of a record.
#[derive(Debug)]
pub struct Instruction<'a> {
    pub record: &'a Record<'a>,
    pub line: u32,
    /// The pattern as written.
    pub text: &'a str,
    /// The pattern, `REG[lo-hi]` resolved to `reg`.
    pub pattern: Pattern<'a>,
    /// The operands as written.
    pub operand_text: &'a str,
    pub operands: Vec<Operand<'a>>,
    pub form: String,
}

/// Every instruction of `records`, in record order.
pub fn collect<'a>(
    records: &[&'a Record<'a>],
    macros: &StateMacros<'a>,
    fields: &[Field<'_>],
) -> Result<Vec<Instruction<'a>>> {
    let suppressed: HashMap<&str, bool> = fields
        .iter()
        .map(|f| (f.name, f.visibility == FieldVisibility::Suppressed))
        .collect();
    let mut instructions = Vec::new();
    for record in records {
        for form in &record.forms {
            let regs: Vec<Option<u8>> = match pattern::reg_range(form.line, form.pattern)? {
                Some(range) => range.map(Some).collect(),
                None => vec![None],
            };
            let operands: Vec<Operand<'a>> = operands::parse(form.line, form.operands, macros)?
                .into_iter()
                .filter_map(|word| match word {
                    Word::Operand(operand) => Some(operand),
                    Word::Reset => None,
                })
                .collect();
            let name = match form.iform {
                Some(name) => name.to_owned(),
                None => compute_form(record.iclass, &operands, &suppressed)?,
            };
            for reg in regs {
                instructions.push(Instruction {
                    record,
                    line: form.line,
                    text: form.pattern,
                    pattern: pattern::parse_with_reg(form.line, form.pattern, macros, reg)?,
                    operand_text: form.operands,
                    operands: operands.clone(),
                    form: name.clone(),
                });
            }
        }
    }
    Ok(instructions)
}

/// XED's `compute_iform`.
fn compute_form(
    iclass: &str,
    operands: &[Operand<'_>],
    suppressed: &HashMap<&str, bool>,
) -> Result<String> {
    let mut words = vec![iclass.to_owned()];
    for operand in operands {
        let hidden = match operand.visibility {
            Some(Visibility::Suppressed) => true,
            Some(_) => false,
            None => *suppressed
                .get(operand.name)
                .ok_or_else(|| format!("unknown operand field {}", operand.name))?,
        };
        if hidden {
            continue;
        }
        let width = operand.width;
        match &operand.value {
            Value::Lookup(nt) => {
                let mut base = strip_lookup_name(nt).replace("VGPR", "GPR");
                if let Some(width) = width
                    && base != "X87"
                    && !(width == "v" && base.ends_with('v'))
                {
                    base.push_str(width);
                }
                words.push(base);
            }
            Value::Register(register) => {
                let mut name = register.trim_start_matches("XED_REG_").to_ascii_uppercase();
                if let Some(width) = width
                    && width != "f80"
                {
                    name.push_str(width);
                }
                words.push(name);
            }
            Value::Present | Value::Number(_) | Value::Enumerator(_) => {
                let mut name = operand.name.to_ascii_uppercase();
                for (from, to) in [
                    ("IMM0", "IMM"),
                    ("IMM1", "IMM"),
                    ("MEM0", "MEM"),
                    ("MEM1", "MEM"),
                ] {
                    name = name.replace(from, to);
                }
                if let Some(width) = width {
                    name.push_str(width);
                }
                words.push(name);
            }
            Value::Bits(_) | Value::Error(_) => {}
        }
    }
    Ok(words.join("_"))
}

fn as_strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// The ISA set names of `instructions`, sorted: the `IsaSet` enum's
/// variants in order.
pub fn isa_set_names<'a>(instructions: &[Instruction<'a>]) -> Vec<&'a str> {
    instructions
        .iter()
        .map(|i| i.record.isa_set)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// XED's `_strip_ntluf_name`: `GPRv_R` → `GPRv`, `XMM_SE` → `XMM`.
fn strip_lookup_name(name: &str) -> String {
    // `_S[RBE]` anywhere (the matches do not overlap).
    let mut s = String::with_capacity(name.len());
    let bytes = name.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'_'
            && bytes.get(at + 1) == Some(&b'S')
            && matches!(bytes.get(at + 2), Some(b'R' | b'B' | b'E'))
        {
            at += 3;
        } else {
            s.push(char::from(bytes[at]));
            at += 1;
        }
    }
    // `_[RBNEI].*` and `FINAL_.*`: cut at the first match.
    let cut = s
        .char_indices()
        .find(|&(at, c)| {
            c == '_'
                && matches!(
                    s.as_bytes().get(at + 1),
                    Some(b'R' | b'B' | b'N' | b'E' | b'I')
                )
        })
        .map(|(at, _)| at);
    if let Some(at) = cut {
        s.truncate(at);
    }
    if let Some(at) = s.find("FINAL_") {
        s.truncate(at);
    }
    s
}

/// `generated/form.rs`: the `Form` enum and the instruction table.
pub fn generate(
    instructions: &[Instruction<'_>],
    operands: &OperandLists,
    flags: &[TokenStream],
    flows: &[TokenStream],
) -> Result<GeneratedFile> {
    // Forms in name order, each with its iclass.
    let mut forms: BTreeMap<&str, &str> = BTreeMap::new();
    for instruction in instructions {
        let iclass = instruction.record.iclass;
        if let Some(previous) = forms.insert(&instruction.form, iclass)
            && previous != iclass
        {
            return Err(format!(
                "form {} belongs to {previous} and {iclass}",
                instruction.form
            )
            .into());
        }
    }
    let names: Vec<&str> = forms.keys().copied().collect();
    let variants = names
        .iter()
        .map(|name| ident(name))
        .collect::<Result<Vec<_>>>()?;
    let docs = names.iter().map(|name| format!(" `{name}`"));
    let iclasses: BTreeSet<&str> = forms.values().copied().collect();
    let mnemonic_of: HashMap<&str, proc_macro2::Ident> = iclasses
        .iter()
        .map(|&iclass| Ok((iclass, ident(&crate::naming::camel_case(iclass))?)))
        .collect::<Result<_>>()?;
    let mnemonics = forms.values().map(|iclass| &mnemonic_of[iclass]);
    let count = codegen::count(names.len());

    // Attributes, upper-cased as XED does; categories, extensions and ISA
    // sets as written. Each in name order.
    let attributes: BTreeSet<String> = instructions
        .iter()
        .flat_map(|i| i.record.attributes.iter().map(|a| a.to_ascii_uppercase()))
        .collect();
    if attributes.len() > 128 {
        return Err(format!("{} attributes do not fit a u128", attributes.len()).into());
    }
    let attribute_names: Vec<&str> = attributes.iter().map(String::as_str).collect();
    let sorted = |f: for<'r> fn(&'r Record<'_>) -> &'r str| -> Vec<String> {
        instructions
            .iter()
            .map(|i| f(i.record).to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let categories = sorted(|r| r.category);
    let extensions = sorted(|r| r.extension);
    let (category_names, extension_names, isa_set_names) = (
        as_strs(&categories),
        as_strs(&extensions),
        isa_set_names(instructions),
    );
    let enum_defs = [
        enums::simple(
            "Attribute",
            " A property of instructions (XED's attributes).",
            &attribute_names,
        )?,
        enums::simple(
            "Category",
            " A broad kind of instruction (XED's categories).",
            &category_names,
        )?,
        enums::simple(
            "Extension",
            " The ISA extension an instruction belongs to.",
            &extension_names,
        )?,
        enums::simple(
            "IsaSet",
            " The CPUID-detectable feature set an instruction needs (XED's ISA sets).",
            &isa_set_names,
        )?,
    ];
    let (category_variants, extension_variants, isa_set_variants) = (
        enums::variants(&category_names)?,
        enums::variants(&extension_names)?,
        enums::variants(&isa_set_names)?,
    );
    let lookup = |names: &[&str],
                  variants: &[proc_macro2::Ident],
                  name: &str|
     -> Result<proc_macro2::Ident> {
        let index = names
            .binary_search(&name)
            .map_err(|_| format!("unknown name {name}"))?;
        Ok(variants[index].clone())
    };

    let table = instructions
        .iter()
        .zip(&operands.slices)
        .zip(flags)
        .zip(flows)
        .map(|(((instruction, &(first, operand_count)), flags), flow)| {
            let record = instruction.record;
            let variant = ident(&instruction.form)?;
            let mut bits = 0u128;
            for attribute in &record.attributes {
                let upper = attribute.to_ascii_uppercase();
                let index = attribute_names
                    .binary_search(&upper.as_str())
                    .map_err(|_| "attribute")?;
                bits |= 1 << index;
            }
            let bits = proc_macro2::Literal::u128_unsuffixed(bits);
            let category = lookup(&category_names, &category_variants, record.category)?;
            let extension = lookup(&extension_names, &extension_variants, record.extension)?;
            let isa_set = lookup(&isa_set_names, &isa_set_variants, record.isa_set)?;
            let (first, operand_count) = (lit(first), lit(operand_count));
            // XED's `xed_iform_to_iclass_string_intel`: the record's
            // `DISASM`/`DISASM_INTEL`, else the iclass; lower case.
            let intel = record
                .disasm_intel
                .unwrap_or(record.iclass)
                .to_ascii_lowercase();
            Ok(quote!(InstructionInfo {
                form: Form::#variant,
                attributes: Attributes(#bits),
                category: Category::#category,
                extension: Extension::#extension,
                isa_set: IsaSet::#isa_set,
                operands: #first,
                operand_count: #operand_count,
                intel: #intel,
                flags: #flags,
                flow: #flow,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let instruction_count = codegen::count(instructions.len());

    let tokens = quote! {
        use core::fmt;
        use core::str::FromStr;

        use crate::decode::flags::FlagsRule;
        use crate::decode::flow::{Condition, FlowKind};
        use crate::decode::{Attributes, InstructionInfo};
        use crate::{Mnemonic, UnknownName};

        /// An instruction form: a mnemonic with one kind of operands, as XED
        /// names it (its *iform*), e.g. `MOV_GPRv_MEMv`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        #[allow(non_camel_case_types)]
        pub enum Form {
            #(#[doc = #docs] #variants,)*
        }

        impl Form {
            /// Number of forms.
            pub const COUNT: usize = #count;

            /// Every form, in declaration (alphabetical) order.
            pub const ALL: [Self; Self::COUNT] = [#(Self::#variants),*];

            /// XED's name for the form.
            pub const fn as_str(self) -> &'static str {
                match self {
                    #(Self::#variants => #names,)*
                }
            }

            /// The form's mnemonic.
            pub const fn mnemonic(self) -> Mnemonic {
                match self {
                    #(Self::#variants => Mnemonic::#mnemonics,)*
                }
            }
        }

        impl fmt::Display for Form {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for Form {
            type Err = UnknownName;

            /// Parses XED's name for a form (exact, case-sensitive).
            fn from_str(name: &str) -> Result<Self, Self::Err> {
                match Self::ALL.binary_search_by(|form| form.as_str().cmp(name)) {
                    Ok(index) => Self::ALL.get(index).copied().ok_or(UnknownName),
                    Err(_) => Err(UnknownName),
                }
            }
        }

        #(#enum_defs)*

        /// Each decodable instruction, by instruction number minus one.
        pub static INSTRUCTIONS: [InstructionInfo; #instruction_count] = [#(#table),*];
    };
    Ok(GeneratedFile {
        path: output("form"),
        notice: XED_NOTICE,
        docs: vec!["Instruction forms (XED iforms) and the instruction table.".to_owned()],
        tokens,
    })
}
