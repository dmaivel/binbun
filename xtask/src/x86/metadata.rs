//! Analysis metadata: what instructions do to the flags
//! (`generated/flags.rs`, from the `FLAGS` records; XED's `flag_gen.py`),
//! the CPUID bits their ISA sets need (`generated/cpuid.rs`, from
//! `all-cpuid.txt`; XED's `cpuid_rdr.py`), and how they transfer control
//! and on which condition (`generated/flow.rs`, from categories and
//! mnemonics).

use std::collections::HashMap;

use binbun_xed::Datafile;
use binbun_xed::flags::{self, Flag, FlagAction, Qualifier, Strength};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::enums;
use super::forms::{Instruction, isa_set_names};
use super::output;
use crate::Result;
use crate::codegen::{GeneratedFile, XED_NOTICE, count, lit};
use crate::naming::{camel_case, ident};

/// One distinct flags record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Record {
    read: u32,
    written: u32,
    undefined: u32,
    may: bool,
    must: bool,
    effects: Vec<(Flag, FlagAction)>,
}

/// `generated/flags.rs`, and each instruction's `FlagsRule`.
pub fn flags(instructions: &[Instruction<'_>]) -> Result<(GeneratedFile, Vec<TokenStream>)> {
    let mut records: Vec<Record> = Vec::new();
    let mut index: HashMap<Record, u16> = HashMap::new();
    let mut intern = |record: Record| -> Result<u16> {
        if let Some(&id) = index.get(&record) {
            return Ok(id);
        }
        records.push(record.clone());
        let id = u16::try_from(records.len())?;
        index.insert(record, id);
        Ok(id)
    };
    let mut rules = Vec::with_capacity(instructions.len());
    for instruction in instructions {
        let Some(text) = instruction.record.flags else {
            rules.push(quote!(FlagsRule::None));
            continue;
        };
        let parsed = flags::parse(instruction.line, text)?;
        let mut cases: HashMap<Option<Qualifier>, u16> = HashMap::new();
        for record in &parsed {
            cases.insert(record.qualifier, intern(record_of(record))?);
        }
        let case = |q: Qualifier| lit(cases.get(&Some(q)).copied().unwrap_or(0));
        // XED's flags_info_t: complex if any record has a qualifier, then
        // chosen by the immediate (XED can also choose by REP, which no
        // instruction uses: the runtime does not model it).
        let rule = if parsed.iter().all(|r| r.qualifier.is_none()) {
            // XED keeps the last record.
            let id = cases
                .get(&None)
                .copied()
                .ok_or_else(|| format!("line {}: empty FLAGS", instruction.line))?;
            let id = lit(id);
            quote!(FlagsRule::Always(#id))
        } else if parsed
            .iter()
            .any(|r| matches!(r.qualifier, Some(Qualifier::Rep | Qualifier::NoRep)))
        {
            return Err(format!(
                "line {}: REP-qualified FLAGS are not supported",
                instruction.line
            )
            .into());
        } else {
            let (zero, one, other) = (
                case(Qualifier::ImmZero),
                case(Qualifier::ImmOne),
                case(Qualifier::ImmOther),
            );
            quote!(FlagsRule::Count { zero: #zero, one: #one, other: #other })
        };
        rules.push(rule);
    }

    let entries = records.iter().map(|r| {
        let (read, written, undefined) = (lit(r.read), lit(r.written), lit(r.undefined));
        let (may, must) = (r.may, r.must);
        let effects = r.effects.iter().map(|(flag, action)| {
            let flag = format_ident!("{}", format!("{flag:?}"));
            let action = format_ident!("{}", action_variant(*action));
            quote!(FlagEffect { flag: Flag::#flag, action: FlagAction::#action })
        });
        quote!(Flags {
            read: FlagSet(#read),
            written: FlagSet(#written),
            undefined: FlagSet(#undefined),
            may_write: #may,
            must_write: #must,
            effects: &[#(#effects),*],
        })
    });
    let record_count = count(records.len());
    let tokens = quote! {
        use crate::decode::flags::{Flag, FlagAction, FlagEffect, FlagSet, Flags};

        /// Every distinct flags record.
        pub static FLAG_RECORDS: [Flags; #record_count] = [#(#entries),*];
    };
    let file = GeneratedFile {
        path: output("flags"),
        notice: XED_NOTICE,
        docs: vec!["Flags records.".to_owned()],
        tokens,
    };
    Ok((file, rules))
}

/// A record's flag sets as XED computes them (`flags_rec_t`): read for
/// `tst`, written otherwise, undefined for `u`; `iopl` sets both its bits.
fn record_of(record: &flags::FlagRecord) -> Record {
    let (mut read, mut written, mut undefined) = (0, 0, 0);
    for effect in &record.actions {
        let bits = flag_bits(effect.flag);
        if effect.action.reads() {
            read |= bits;
        }
        if effect.action.writes() {
            written |= bits;
        }
        if effect.action == FlagAction::Undefined {
            undefined |= bits;
        }
    }
    Record {
        read,
        written,
        undefined,
        may: record.strength == Strength::May,
        must: record.strength == Strength::Must,
        effects: record.actions.iter().map(|e| (e.flag, e.action)).collect(),
    }
}

/// XED's `xed_flag_set_t` layout.
fn flag_bits(flag: Flag) -> u32 {
    match flag {
        Flag::Cf => 1,
        Flag::Pf => 1 << 2,
        Flag::Af => 1 << 4,
        Flag::Zf => 1 << 6,
        Flag::Sf => 1 << 7,
        Flag::Tf => 1 << 8,
        Flag::If => 1 << 9,
        Flag::Df => 1 << 10,
        Flag::Of => 1 << 11,
        Flag::Iopl => 3 << 12,
        Flag::Nt => 1 << 14,
        Flag::Rf => 1 << 16,
        Flag::Vm => 1 << 17,
        Flag::Ac => 1 << 18,
        Flag::Vif => 1 << 19,
        Flag::Vip => 1 << 20,
        Flag::Id => 1 << 21,
        Flag::Fc0 => 1 << 28,
        Flag::Fc1 => 1 << 29,
        Flag::Fc2 => 1 << 30,
        Flag::Fc3 => 1 << 31,
    }
}

fn action_variant(action: FlagAction) -> &'static str {
    match action {
        FlagAction::Modify => "Modify",
        FlagAction::Test => "Test",
        FlagAction::Undefined => "Undefined",
        FlagAction::Clear => "Clear",
        FlagAction::Set => "Set",
        FlagAction::FromAh => "FromAh",
        FlagAction::Pop => "Pop",
    }
}

/// One CPUID field requirement.
#[derive(Debug, Clone)]
struct Field {
    leaf: u32,
    subleaf: u32,
    register: &'static str,
    low: u8,
    high: u8,
    value: u32,
}

/// `generated/cpuid.rs`: each ISA set's CPUID groups.
pub fn cpuid(instructions: &[Instruction<'_>], file: &Datafile<'_>) -> Result<GeneratedFile> {
    // ISA set → (AVX10 group?, fields), in file order.
    let mut groups: HashMap<String, Vec<(bool, Vec<Field>)>> = HashMap::new();
    for line in file.lines() {
        let text = line.text();
        let (key, value) = text
            .split_once(':')
            .ok_or_else(|| format!("line {}: no `:`", line.number))?;
        let key = key.replace(' ', "").to_ascii_uppercase();
        let mut parts = key.split(',');
        let isa_set = parts
            .next()
            .and_then(|s| s.strip_prefix("XED_ISA_SET_"))
            .ok_or_else(|| format!("line {}: bad isa set", line.number))?;
        let value = value.to_ascii_uppercase();
        let avx10 = match parts.next() {
            Some("AVX10") => true,
            Some("FBIT") => false,
            Some(other) => return Err(format!("line {}: group kind {other}", line.number).into()),
            None => value.contains("AVX10_ENABLED"),
        };
        let fields = value
            .split_whitespace()
            .filter(|word| *word != "N/A")
            .map(|word| {
                field(word).ok_or_else(|| format!("line {}: bad CPUID record {word}", line.number))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !fields.is_empty() {
            groups
                .entry(isa_set.to_owned())
                .or_default()
                .push((avx10, fields));
        }
    }

    let names = isa_set_names(instructions);
    let variants = enums::variants(&names)?;
    let mut arms = Vec::new();
    for (name, variant) in names.iter().zip(&variants) {
        // XED upper-cases ISA set names (`SSE4a` is `SSE4A` in cpuid.txt).
        let Some(sets) = groups.get(&name.to_ascii_uppercase()) else {
            continue;
        };
        let mut sets = sets.clone();
        // AVX10 groups first (XED sorts by group kind).
        sets.sort_by_key(|(avx10, _)| !avx10);
        let mut group_tokens = Vec::new();
        for (_, fields) in &sets {
            let mut field_tokens = Vec::new();
            for f in fields {
                let leaf: TokenStream = format!("{:#x}", f.leaf).parse()?;
                let subleaf: TokenStream = format!("{:#x}", f.subleaf).parse()?;
                let register = format_ident!("{}", f.register);
                let (low, high, value) = (lit(f.low), lit(f.high), lit(f.value));
                field_tokens.push(quote!(CpuidField {
                    leaf: #leaf,
                    subleaf: #subleaf,
                    register: CpuidRegister::#register,
                    low: #low,
                    high: #high,
                    value: #value,
                }));
            }
            group_tokens.push(quote!(&[#(#field_tokens),*]));
        }
        arms.push(quote!(IsaSet::#variant => &[#(#group_tokens),*],));
    }
    let tokens = quote! {
        use crate::IsaSet;
        use crate::cpuid::{CpuidField, CpuidRegister};

        /// The CPUID groups of `isa_set`.
        pub fn groups(isa_set: IsaSet) -> &'static [&'static [CpuidField]] {
            match isa_set {
                #(#arms)*
                _ => &[],
            }
        }
    };
    Ok(GeneratedFile {
        path: output("cpuid"),
        notice: XED_NOTICE,
        docs: vec!["CPUID requirements of ISA sets.".to_owned()],
        tokens,
    })
}

/// A record `NAME.LEAF.SUBLEAF.REG` followed by `.BIT`, `[BIT]` or
/// `[START:END]=VALUE` (leaf and subleaf hexadecimal).
fn field(word: &str) -> Option<Field> {
    let mut parts = word.splitn(4, '.');
    let _name = parts.next()?;
    let leaf = u32::from_str_radix(parts.next()?, 16).ok()?;
    let subleaf = u32::from_str_radix(parts.next()?, 16).ok()?;
    let rest = parts.next()?;
    let (register, low, high, value) = if let Some((register, bits)) = rest.split_once('[') {
        let (bits, value) = bits.split_once(']')?;
        if let Some((low, high)) = bits.split_once(':') {
            let value = value.strip_prefix('=')?.parse().ok()?;
            (register, low.parse().ok()?, high.parse().ok()?, value)
        } else {
            let bit = bits.parse().ok()?;
            (register, bit, bit, 1)
        }
    } else {
        let (register, bit) = rest.split_once('.')?;
        let bit = bit.parse().ok()?;
        (register, bit, bit, 1)
    };
    let register = match register {
        "EAX" => "Eax",
        "EBX" => "Ebx",
        "ECX" => "Ecx",
        "EDX" => "Edx",
        _ => return None,
    };
    Some(Field {
        leaf,
        subleaf,
        register,
        low,
        high,
        value,
    })
}

/// The flag conditions of condition codes, by XED's spelling.
const CONDITIONS: [(&str, &str); 18] = [
    ("O", "Overflow"),
    ("NO", "NotOverflow"),
    ("B", "Below"),
    ("NB", "NotBelow"),
    ("Z", "Zero"),
    ("NZ", "NotZero"),
    ("BE", "BelowOrEqual"),
    ("NBE", "Above"),
    ("S", "Sign"),
    ("NS", "NotSign"),
    ("P", "Parity"),
    ("NP", "NotParity"),
    ("L", "Less"),
    ("NL", "NotLess"),
    ("LE", "LessOrEqual"),
    ("NLE", "Greater"),
    ("F", "False"),
    ("T", "True"),
];

/// The condition of mnemonic `iclass`, as the name of a `Condition`
/// variant: the `cc` of `Jcc`, `SETcc`, `CMOVcc`, `CFCMOVcc`, `CMPccXADD`,
/// `CCMPcc`, `CTESTcc` and `FCMOVcc`, and the count and transaction
/// conditions of `JCXZ`, `LOOP` and `XBEGIN`.
fn condition(iclass: &str) -> Option<&'static str> {
    let special = match iclass {
        "JCXZ" | "JECXZ" | "JRCXZ" => Some("CountZero"),
        "LOOP" => Some("Loop"),
        "LOOPE" => Some("LoopZero"),
        "LOOPNE" => Some("LoopNotZero"),
        "XBEGIN" => Some("TransactionAbort"),
        // x87 conditions are on the flags FCOMI sets: E is Z, U is P.
        "FCMOVB" => Some("Below"),
        "FCMOVBE" => Some("BelowOrEqual"),
        "FCMOVE" => Some("Zero"),
        "FCMOVNB" => Some("NotBelow"),
        "FCMOVNBE" => Some("Above"),
        "FCMOVNE" => Some("NotZero"),
        "FCMOVNU" => Some("NotParity"),
        "FCMOVU" => Some("Parity"),
        _ => None,
    };
    if special.is_some() {
        return special;
    }
    let code = ["CFCMOV", "CMOV", "CCMP", "CTEST", "SET", "J"]
        .iter()
        .find_map(|prefix| iclass.strip_prefix(prefix))
        .or_else(|| {
            iclass
                .strip_prefix("CMP")
                .and_then(|rest| rest.strip_suffix("XADD"))
        })?;
    CONDITIONS
        .iter()
        .find(|(name, _)| *name == code)
        .map(|(_, variant)| *variant)
}

/// How instruction `iclass` of category `category` transfers control, as
/// the name of a `FlowKind` variant.
fn flow_kind(iclass: &str, category: &str) -> &'static str {
    match (category, iclass) {
        // XEND ends a transaction; XABORT outside one does nothing, and
        // inside one the abort goes to XBEGIN's target.
        (_, "XEND" | "XABORT") => "Next",
        ("COND_BR", _) => "Branch",
        ("UNCOND_BR", _) => "Jump",
        ("CALL", _) => "Call",
        ("RET", "RET_NEAR" | "RET_FAR") => "Return",
        ("RET" | "SYSRET", _) | (_, "ERETS" | "ERETU" | "UIRET" | "SEAMRET") => "ExceptionReturn",
        ("INTERRUPT", "INTO" | "BOUND") => "ConditionalTrap",
        ("INTERRUPT", _) | (_, "UD0" | "UD1" | "UD2") => "Trap",
        ("SYSCALL", _) | (_, "VMCALL" | "VMMCALL" | "TDCALL" | "SEAMCALL") => "SystemCall",
        (_, "HLT") => "Halt",
        _ => "Next",
    }
}

/// `generated/flow.rs` (`Mnemonic::condition`), and each instruction's
/// `FlowKind`.
pub fn flow(instructions: &[Instruction<'_>]) -> Result<(GeneratedFile, Vec<TokenStream>)> {
    let kinds = instructions
        .iter()
        .map(|i| {
            let (iclass, category) = (i.record.iclass, i.record.category);
            let kind = format_ident!("{}", flow_kind(iclass, category));
            if kind == "Branch" {
                let condition = condition(iclass).ok_or_else(|| {
                    format!("line {}: branch {iclass} without a condition", i.line)
                })?;
                let condition = format_ident!("{condition}");
                Ok(quote!(FlowKind::Branch(Condition::#condition)))
            } else {
                Ok(quote!(FlowKind::#kind))
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let mut iclasses: Vec<&str> = instructions.iter().map(|i| i.record.iclass).collect();
    iclasses.sort_unstable();
    iclasses.dedup();
    let mut arms = Vec::new();
    for iclass in iclasses {
        if let Some(condition) = condition(iclass) {
            let mnemonic = ident(&camel_case(iclass))?;
            let condition = format_ident!("{condition}");
            arms.push(quote!(Mnemonic::#mnemonic => Some(Condition::#condition),));
        }
    }
    let tokens = quote! {
        use crate::Mnemonic;
        use crate::decode::flow::Condition;

        impl Mnemonic {
            /// The condition the instruction tests: the `cc` of `Jcc`,
            /// `SETcc`, `CMOVcc` and similar, and the count or transaction
            /// condition of `JCXZ`, `LOOP` and `XBEGIN`.
            pub const fn condition(self) -> Option<Condition> {
                match self {
                    #(#arms)*
                    _ => None,
                }
            }
        }
    };
    let file = GeneratedFile {
        path: output("flow"),
        notice: XED_NOTICE,
        docs: vec!["Conditions of mnemonics.".to_owned()],
        tokens,
    };
    Ok((file, kinds))
}
