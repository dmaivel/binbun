//! `flow.rs` of the decoder: how each encoding transfers control and the
//! condition it tests, from the hand-written [`RULES`] below.
//!
//! AARCHMRS's BSD package has no pseudocode (every operation is `// Not
//! specified`), so what an encoding's Execute section does to the PC
//! (`BranchTo(target, BranchType_DIR)`, an exception, an exception return)
//! is restated here, one [`Rule`] per group of encodings that behave alike;
//! each rule's comment quotes the pseudocode it reflects. The fields come
//! from AARCHMRS: a branch's target is the `<label>` display's fields (a
//! signed word offset), a tested register the display encoded in `Rt`.
//! Every encoding of the `control` groups and `UDF` must match exactly one
//! rule, so an encoding a new release adds to them fails generation until
//! it is classified. The rules are checked against exarmo-aarch64, whose
//! branch kinds come from Arm's pseudocode
//! (`crates/binbun-aarch64/tests/oracle.rs`, `flow_matches_exarmo`).

use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::quote;

use super::emit::encoding_ident;
use super::model::Encoding;
use super::symbols::{extract, sign_extend};
use super::{AARCHMRS_NOTICE, output};
use crate::Result;
use crate::codegen::{GeneratedFile, lit};

/// Where a jump or call goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Destination {
    /// `PC64 + offset`, the offset being the `<label>` fields times 4.
    Label,
    /// A register (`X[n, 64]`), possibly authenticated first.
    Register,
}

/// What the encodings of a rule do to the flow of control when their test
/// passes (see [`Test`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transfer {
    /// Nothing: execution continues with the next instruction.
    Next,
    /// `BranchTo(target, BranchType_DIR | BranchType_INDIR)`.
    Jump(Destination),
    /// `X[30] = PC64 + 4; BranchTo(target, BranchType_DIRCALL |
    /// BranchType_INDCALL)`.
    Call(Destination),
    /// `BranchTo(target, BranchType_RET)`.
    Return,
    /// `AArch64.ExceptionReturn(…)` (or, for DRPS, the return from debug
    /// state): the PC comes from `ELR_ELx`.
    ExceptionReturn,
    /// An exception the handler returns from to the next instruction
    /// (`AArch64.CallSupervisor`, `AArch64.CallHypervisor`,
    /// `AArch64.CallSecureMonitor`).
    SystemCall,
    /// A deliberate exception or halt: the instruction does not complete.
    Trap,
}

/// The immediate a compare test compares with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Immediate {
    /// `UInt(imm)`.
    Unsigned,
    /// `SInt(imm)` for the signed and equality conditions, `UInt(imm)` for
    /// the unsigned ones (`HI`, `LO`).
    ByCondition,
}

/// What the transfer depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Test {
    /// Nothing: it always happens.
    Always,
    /// `ConditionHolds(cond)` on the `cond` field; a `cond` of `111x` always
    /// holds, so those words transfer unconditionally.
    Flags,
    /// `IsZero(X[t])` (`true`) or its negation.
    Zero(bool),
    /// `X[t]<bit_pos> == '1'` (`true`) or `'0'`, `bit_pos` being the
    /// `<imm>` fields `b5:b40`.
    Bit(bool),
    /// `X[t]` compared with `X[m]` or the `<imm>` immediate by the condition
    /// the mnemonic ends with (`CBGT`: `gt`).
    Compare(Immediate),
}

/// The encodings of `group` named `mnemonics` (all of the group's when
/// empty) and what they do.
#[derive(Debug, Clone, Copy)]
struct Rule {
    group: &'static str,
    mnemonics: &'static [&'static str],
    transfer: Transfer,
    test: Test,
}

const fn rule(
    group: &'static str,
    mnemonics: &'static [&'static str],
    transfer: Transfer,
    test: Test,
) -> Rule {
    Rule {
        group,
        mnemonics,
        transfer,
        test,
    }
}

use Destination::{Label, Register};
use Test::{Always, Bit, Compare, Flags, Zero};
use Transfer::{Call, ExceptionReturn, Jump, Next, Return, SystemCall, Trap};

/// The rules; an encoding matches at most one.
const RULES: &[Rule] = &[
    // B: `BranchTo(PC64 + offset, BranchType_DIR, FALSE)`.
    rule("control/branch_imm", &["B"], Jump(Label), Always),
    // BL: `X[30] = PC64 + 4; BranchTo(PC64 + offset, BranchType_DIRCALL,
    // FALSE)`.
    rule("control/branch_imm", &["BL"], Call(Label), Always),
    // B.<cond>, BC.<cond>: `if ConditionHolds(cond) then BranchTo(PC64 +
    // offset, BranchType_DIR, …)`.
    rule("control/condbranch", &[], Jump(Label), Flags),
    // CBZ, CBNZ: `if IsZero(operand1) == (op == '0') then BranchTo(PC64 +
    // offset, BranchType_DIR, TRUE)`.
    rule("control/compbranch", &["CBZ"], Jump(Label), Zero(true)),
    rule("control/compbranch", &["CBNZ"], Jump(Label), Zero(false)),
    // TBZ, TBNZ: `if operand<bit_pos> == op then BranchTo(PC64 + offset,
    // BranchType_DIR, TRUE)`.
    rule("control/testbranch", &["TBZ"], Jump(Label), Bit(false)),
    rule("control/testbranch", &["TBNZ"], Jump(Label), Bit(true)),
    // CB<cc> (FEAT_CMPBR): `if <cc> holds for the comparison of X[t] with
    // X[m] (bytes and halfwords: CBB<cc>, CBH<cc>) or UInt(imm6) then
    // BranchTo(PC64 + offset, BranchType_DIR, TRUE)`.
    rule(
        "control/compbranch_imm",
        &[],
        Jump(Label),
        Compare(Immediate::Unsigned),
    ),
    rule(
        "control/compbranch_regs",
        &[],
        Jump(Label),
        Compare(Immediate::Unsigned),
    ),
    rule(
        "control/compbranch_regs2",
        &[],
        Jump(Label),
        Compare(Immediate::Unsigned),
    ),
    // BR, BRAA, BRAAZ, BRAB, BRABZ: `BranchTo(target, BranchType_INDIR,
    // FALSE)`, the target authenticated first by the PAC forms. Whatever
    // the register (`br x30` included), a jump.
    rule(
        "control/branch_reg",
        &["BR", "BRAA", "BRAAZ", "BRAB", "BRABZ"],
        Jump(Register),
        Always,
    ),
    // BLR, BLRAA, BLRAAZ, BLRAB, BLRABZ: `X[30] = PC64 + 4;
    // BranchTo(target, BranchType_INDCALL, FALSE)`.
    rule(
        "control/branch_reg",
        &["BLR", "BLRAA", "BLRAAZ", "BLRAB", "BLRABZ"],
        Call(Register),
        Always,
    ),
    // RET, RETAA, RETAB, RETAASPPCR, RETABSPPCR: `BranchTo(target,
    // BranchType_RET, FALSE)` with any register (`ret x1` too).
    rule(
        "control/branch_reg",
        &["RET", "RETAA", "RETAB", "RETAASPPCR", "RETABSPPCR"],
        Return,
        Always,
    ),
    // RETAASPPC, RETABSPPC: return to the authenticated X[30]
    // (`BranchType_RET`); the label is the modifier's address, not a
    // target.
    rule("control/miscbranch", &[], Return, Always),
    // ERET, ERETAA, ERETAB: `AArch64.ExceptionReturn(target, SPSR_ELx)`.
    // DRPS: the return from debug state (UNDEFINED outside it). TEXIT
    // (FEAT_TEV): `AArch64.ExceptionReturn` from the TENTER exception.
    rule(
        "control/branch_reg",
        &["ERET", "ERETAA", "ERETAB", "DRPS", "TEXIT"],
        ExceptionReturn,
        Always,
    ),
    // SVC, HVC, SMC: `AArch64.CallSupervisor(imm16)`,
    // `AArch64.CallHypervisor(imm16)`, `AArch64.CallSecureMonitor(imm16)`;
    // TENTER (FEAT_TEV) takes an exception the same way. The handler
    // returns to the next instruction.
    rule(
        "control/exception",
        &["SVC", "HVC", "SMC", "TENTER"],
        SystemCall,
        Always,
    ),
    // BRK: `AArch64.SoftwareBreakpoint(imm16)`. HLT: `Halt(DebugHalt_HaltInstruction)`
    // when halting is allowed, else UNDEFINED; either way the instruction
    // does not complete.
    rule("control/exception", &["BRK", "HLT"], Trap, Always),
    // UDF: permanently UNDEFINED.
    rule("reserved/perm_undef", &["UDF"], Trap, Always),
    // FLT.<cond> (FEAT_CFLT): a fault exception if ConditionHolds(cond).
    rule("control/exception", &["FLT"], Trap, Flags),
    // CFLT<cc> (FEAT_CFLT): a fault exception if <cc> holds for the
    // comparison of X[t] with X[m] or the immediate, which is signed but
    // for the unsigned conditions (exarmo-aarch64's operand types, from
    // the pseudocode).
    rule(
        "control/compfault_imm",
        &[],
        Trap,
        Compare(Immediate::ByCondition),
    ),
    rule(
        "control/compfault_regs",
        &[],
        Trap,
        Compare(Immediate::ByCondition),
    ),
    // TFLTZ, TFLTNZ (FEAT_CFLT): a fault exception if X[t]<bit_pos> is 0,
    // or 1.
    rule("control/testfault", &["TFLTZ"], Trap, Bit(false)),
    rule("control/testfault", &["TFLTNZ"], Trap, Bit(true)),
    // DCPS1-3: change the exception level in debug state (UNDEFINED
    // outside it); in debug state instructions come from the debugger, so
    // there is no flow to follow.
    rule(
        "control/exception",
        &["DCPS1", "DCPS2", "DCPS3"],
        Next,
        Always,
    ),
    // TCHANGEB, TCHANGEF (FEAT_TEV): change the translation regime's
    // state; execution continues.
    rule("control/tchange_imm", &[], Next, Always),
    rule("control/tchange_reg", &[], Next, Always),
    // Hints (WFI and WFE wait for an interrupt or event and continue),
    // barriers, PSTATE and system register accesses,
    // system instructions (WFIT, WFET): execution continues.
    rule("control/hints", &[], Next, Always),
    rule("control/extendedhints", &[], Next, Always),
    rule("control/barriers", &[], Next, Always),
    rule("control/pstate", &[], Next, Always),
    rule("control/systeminstrs", &[], Next, Always),
    rule("control/systeminstrswithreg", &[], Next, Always),
    rule("control/systemmove", &[], Next, Always),
    rule("control/systemmovepr", &[], Next, Always),
    rule("control/syspairinstrs", &[], Next, Always),
    // CSEL, CSINC, CSINV, CSNEG: `if ConditionHolds(cond) then result =
    // operand1 else …`.
    rule("dpreg/condsel", &[], Next, Flags),
    // CCMP, CCMN: `if ConditionHolds(cond) then flags = compare else flags
    // = nzcv`.
    rule("dpreg/condcmp_imm", &[], Next, Flags),
    rule("dpreg/condcmp_reg", &[], Next, Flags),
    // FCSEL, FCCMP, FCCMPE: as CSEL and CCMP.
    rule("simd_dp/floatsel", &[], Next, Flags),
    rule("simd_dp/floatccmp", &[], Next, Flags),
];

/// Whether every encoding of `path` must match a rule.
fn classified(path: &str) -> bool {
    path.starts_with("control/") || path == "reserved/perm_undef"
}

/// The rule `encoding` (in group `path`) matches, if any; an error if it
/// matches more than one.
fn find(encoding: &Encoding<'_>, path: &str) -> Result<Option<(usize, &'static Rule)>> {
    let mnemonic = encoding.instruction.mnemonic().unwrap_or_default();
    let mut matches = RULES.iter().enumerate().filter(|(_, rule)| {
        rule.group == path && (rule.mnemonics.is_empty() || rule.mnemonics.contains(&mnemonic))
    });
    let found = matches.next();
    if matches.next().is_some() {
        return Err(format!("{}: more than one flow rule", encoding.name()).into());
    }
    Ok(found)
}

/// `(word >> start) & mask` for the encoding's field `name`.
fn field(encoding: &Encoding<'_>, name: &str) -> Result<TokenStream> {
    let (start, width) = encoding
        .field(name)
        .ok_or_else(|| format!("{}: no field {name}", encoding.name()))?;
    Ok(extract(start, width))
}

/// The fields `display` is encoded in, concatenated (first most
/// significant), and the total width.
fn display(encoding: &Encoding<'_>, display: &str) -> Result<(TokenStream, u32)> {
    let fields = encoding
        .instruction
        .encoded_in
        .get(display)
        .ok_or_else(|| format!("{}: {display} is not encoded", encoding.name()))?;
    let mut value = quote! { 0u32 };
    let mut total = 0;
    for name in fields {
        let (_, width) = encoding
            .field(name)
            .ok_or_else(|| format!("{}: no field {name}", encoding.name()))?;
        let bits = field(encoding, name)?;
        let shift = lit(width);
        value = if total == 0 {
            bits
        } else {
            quote! { ((#value) << #shift) | #bits }
        };
        total += width;
    }
    Ok((value, total))
}

/// The general register encoded in `register_field` (`Rt`, `Rm`), of the
/// class its display says: `<Wt>`, `<Xt|SP>`, or `<R><t>` sized by `b5`.
fn register(encoding: &Encoding<'_>, register_field: &str) -> Result<TokenStream> {
    let name = encoding.name();
    let (key, _) = encoding
        .instruction
        .encoded_in
        .iter()
        .find(|(_, fields)| fields.as_slice() == [register_field])
        .ok_or_else(|| format!("{name}: no display is encoded in {register_field}"))?;
    let number = field(encoding, register_field)?;
    let class = |class: &str| {
        let class = quote::format_ident!("{class}");
        quote! { Register::new(RegisterClass::#class, (#number) as u8) }
    };
    Ok(match key.as_str() {
        "<Wt>" | "<Wm>" => class("W"),
        "<Xt>" | "<Xm>" => class("X"),
        "<Wt|WSP>" | "<Wm|WSP>" => class("Wsp"),
        "<Xt|SP>" | "<Xm|SP>" => class("Xsp"),
        "<t>" => {
            let wide = field(encoding, "b5")?;
            let (x, w) = (class("X"), class("W"));
            quote! { if #wide == 1 { #x } else { #w } }
        }
        other => return Err(format!("{name}: register display {other}").into()),
    })
}

/// The condition named by the last two letters of the mnemonic (`CBHHI`:
/// `Hi`), as a `Condition` variant name.
fn mnemonic_condition(encoding: &Encoding<'_>) -> Result<&'static str> {
    let mnemonic = encoding.instruction.mnemonic().unwrap_or_default();
    let suffix = mnemonic
        .get(mnemonic.len().saturating_sub(2)..)
        .unwrap_or_default();
    Ok(match suffix {
        "EQ" => "Eq",
        "NE" => "Ne",
        "HS" => "Hs",
        "LO" => "Lo",
        "HI" => "Hi",
        "LS" => "Ls",
        "GE" => "Ge",
        "LT" => "Lt",
        "GT" => "Gt",
        "LE" => "Le",
        _ => return Err(format!("{}: no condition in {mnemonic}", encoding.name()).into()),
    })
}

/// `Some(Condition::…)` for the test, or `None` when there is none.
fn condition(encoding: &Encoding<'_>, test: Test) -> Result<Option<TokenStream>> {
    Ok(Some(match test {
        Always => return Ok(None),
        Flags => {
            let cond = field(encoding, "cond")?;
            quote! { Some(Condition::Flags(Cond::from_bits(#cond))) }
        }
        Zero(zero) => {
            let register = register(encoding, "Rt")?;
            quote! { Some(Condition::Zero { register: #register, zero: #zero }) }
        }
        Bit(set) => {
            let register = register(encoding, "Rt")?;
            let (bit, _) = display(encoding, "<imm>")?;
            quote! { Some(Condition::Bit { register: #register, bit: (#bit) as u8, set: #set }) }
        }
        Compare(immediate) => {
            let variant = mnemonic_condition(encoding)?;
            let cond = quote::format_ident!("{variant}");
            let left = register(encoding, "Rt")?;
            let right = if encoding.field("Rm").is_some() {
                let right = register(encoding, "Rm")?;
                quote! { CompareOperand::Register(#right) }
            } else {
                let (value, width) = display(encoding, "<imm>")?;
                let unsigned_condition = matches!(variant, "Hi" | "Lo" | "Hs" | "Ls");
                let value = if immediate == Immediate::ByCondition && !unsigned_condition {
                    sign_extend(&value, width)
                } else {
                    quote! { i64::from(#value) }
                };
                quote! { CompareOperand::Immediate(#value) }
            };
            quote! { Some(Condition::Compare { cond: Cond::#cond, left: #left, right: #right }) }
        }
    }))
}

/// The target of a transfer to `destination`.
fn target(encoding: &Encoding<'_>, destination: Destination) -> Result<TokenStream> {
    Ok(match destination {
        Register => quote! { Target::Indirect },
        Label => {
            let (value, width) = display(encoding, "<label>")?;
            let offset = sign_extend(&value, width);
            quote! { Target::Address(address.wrapping_add((#offset << 2).cast_unsigned())) }
        }
    })
}

/// Whether a test can fail.
enum Conditional {
    /// Never: the transfer always happens.
    Never,
    /// For every word.
    Always,
    /// When the boolean expression holds for the word.
    When(TokenStream),
}

/// Whether `test` can fail; `ConditionHolds` cannot for a `cond` of `111x`.
fn conditional(encoding: &Encoding<'_>, test: Test) -> Result<Conditional> {
    Ok(match test {
        Always => Conditional::Never,
        Flags => {
            let cond = field(encoding, "cond")?;
            Conditional::When(quote! { #cond >> 1 != 7 })
        }
        Zero(_) | Bit(_) | Compare(_) => Conditional::Always,
    })
}

/// The `Flow` expression of `encoding` under `rule`; `None` for `Next`.
fn flow(encoding: &Encoding<'_>, rule: &Rule) -> Result<Option<TokenStream>> {
    let name = encoding.name();
    let conditional = conditional(encoding, rule.test)?;
    let fixed = |flow: TokenStream| -> Result<TokenStream> {
        match conditional {
            Conditional::Never => Ok(flow),
            Conditional::Always | Conditional::When(_) => {
                Err(format!("{name}: a conditional {:?}", rule.transfer).into())
            }
        }
    };
    Ok(Some(match rule.transfer {
        Next => return Ok(None),
        Jump(destination) => {
            let target = target(encoding, destination)?;
            match &conditional {
                Conditional::Never => quote! { Flow::Jump(#target) },
                Conditional::Always => quote! { Flow::Branch(#target) },
                Conditional::When(may_fail) => quote! {
                    if #may_fail { Flow::Branch(#target) } else { Flow::Jump(#target) }
                },
            }
        }
        Call(destination) => {
            let target = target(encoding, destination)?;
            fixed(quote! { Flow::Call(#target) })?
        }
        Return => fixed(quote! { Flow::Return })?,
        ExceptionReturn => fixed(quote! { Flow::ExceptionReturn })?,
        SystemCall => fixed(quote! { Flow::SystemCall })?,
        Trap => match conditional {
            Conditional::Never => quote! { Flow::Trap { conditional: false } },
            Conditional::Always => quote! { Flow::Trap { conditional: true } },
            Conditional::When(may_fail) => quote! { Flow::Trap { conditional: #may_fail } },
        },
    }))
}

/// Match arms `A | B => code,` grouping the encodings with the same code,
/// in order of first appearance.
fn arms(entries: Vec<(TokenStream, TokenStream)>) -> Vec<TokenStream> {
    let mut grouped: Vec<(String, TokenStream, Vec<TokenStream>)> = Vec::new();
    for (variant, code) in entries {
        let key = code.to_string();
        match grouped.iter_mut().find(|(k, _, _)| *k == key) {
            Some((_, _, list)) => list.push(variant),
            None => grouped.push((key, code, vec![variant])),
        }
    }
    grouped
        .into_iter()
        .map(|(_, code, list)| quote! { #(Encoding::#list)|* => #code, })
        .collect()
}

/// Generates `flow.rs`; fails if a `control` encoding matches no rule, an
/// encoding more than one, or a rule none.
pub fn generate(encodings: &[Encoding<'_>]) -> Result<GeneratedFile> {
    let mut flows = Vec::new();
    let mut conditions = Vec::new();
    let mut used: BTreeMap<usize, usize> = BTreeMap::new();
    let mut unclassified = Vec::new();
    for encoding in encodings {
        let path: Vec<&str> = encoding.groups.iter().map(|g| g.name.as_str()).collect();
        let path = path.join("/");
        let Some((index, rule)) = find(encoding, &path)? else {
            if classified(&path) {
                unclassified.push(encoding.name());
            }
            continue;
        };
        *used.entry(index).or_default() += 1;
        let variant = encoding_ident(encoding.name())?;
        let variant = quote! { #variant };
        if let Some(code) = flow(encoding, rule)? {
            flows.push((variant.clone(), code));
        }
        if let Some(code) = condition(encoding, rule.test)? {
            conditions.push((variant, code));
        }
    }
    if !unclassified.is_empty() {
        return Err(format!("encodings without a flow rule: {}", unclassified.join(", ")).into());
    }
    let unused: Vec<String> = RULES
        .iter()
        .enumerate()
        .filter(|(index, _)| !used.contains_key(index))
        .map(|(_, rule)| format!("{} {:?}", rule.group, rule.mnemonics))
        .collect();
    if !unused.is_empty() {
        return Err(format!("flow rules matching no encoding: {}", unused.join("; ")).into());
    }
    // Every named mnemonic matches an encoding.
    for rule in RULES {
        for mnemonic in rule.mnemonics {
            let found = encodings.iter().any(|encoding| {
                encoding.instruction.mnemonic() == Some(mnemonic)
                    && encoding
                        .groups
                        .iter()
                        .map(|g| g.name.as_str())
                        .collect::<Vec<_>>()
                        .join("/")
                        == rule.group
            });
            if !found {
                return Err(format!("flow rule {}: no encoding {mnemonic}", rule.group).into());
            }
        }
    }
    let flow_arms = arms(flows);
    let condition_arms = arms(conditions);
    let tokens = quote! {
        use binbun_isa::{Flow, Target};

        use super::encoding::Encoding;
        use crate::flow::{CompareOperand, Condition};
        use crate::operand::{Condition as Cond, Register, RegisterClass};

        /// How the instruction `word` of `encoding`, at `address`,
        /// transfers control.
        #[inline]
        pub fn flow(encoding: Encoding, word: u32, address: u64) -> Flow {
            match encoding {
                #(#flow_arms)*
                _ => Flow::Next,
            }
        }

        /// The condition the instruction `word` of `encoding` tests.
        pub fn condition(encoding: Encoding, word: u32) -> Option<Condition> {
            match encoding {
                #(#condition_arms)*
                _ => None,
            }
        }
    };
    Ok(GeneratedFile {
        path: output("flow"),
        notice: AARCHMRS_NOTICE,
        docs: vec![
            "Control flow and conditions of the A64 encodings".to_owned(),
            "(`xtask/src/aarch64/flow.rs`).".to_owned(),
        ],
        tokens,
    })
}
