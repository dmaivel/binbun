//! binbun's answers in the notation of `tools/xed-oracle` (see its header
//! comment), so they compare with XED's as strings. Shared by the oracle
//! tests and the fuzz targets (`fuzz/`, which include this file by path).

use std::fmt::Write as _;

use binbun_x86::{
    Action, DecodeError, Instruction, Mode, Register, Value, Visibility, decode, decode_length,
};

/// The oracle's name for `mode`.
pub fn mode_tag(mode: Mode) -> &'static str {
    match mode {
        Mode::Real16 => "r16",
        Mode::Real32 => "r32",
        Mode::Bits16 => "16",
        Mode::Bits32 => "32",
        Mode::Bits64 => "64",
    }
}

/// The mode the oracle calls `tag`.
pub fn parse_mode(tag: &str) -> Option<Mode> {
    [
        Mode::Real16,
        Mode::Real32,
        Mode::Bits16,
        Mode::Bits32,
        Mode::Bits64,
    ]
    .into_iter()
    .find(|&mode| mode_tag(mode) == tag)
}

/// XED's name for our error.
pub fn xed_error(error: DecodeError) -> &'static str {
    match error {
        DecodeError::TooShort => "BUFFER_TOO_SHORT",
        DecodeError::TooLong => "INSTR_TOO_LONG",
        DecodeError::Invalid => "GENERAL_ERROR",
        DecodeError::InvalidMode => "INVALID_MODE",
        DecodeError::BadRegister => "BAD_REGISTER",
        DecodeError::BadLockPrefix => "BAD_LOCK_PREFIX",
        DecodeError::BadLegacyPrefix => "BAD_LEGACY_PREFIX",
        DecodeError::BadRexPrefix => "BAD_REX_PREFIX",
        DecodeError::BadMap => "BAD_MAP",
        DecodeError::BadEvexVPrime => "BAD_EVEX_V_PRIME",
        DecodeError::BadEvexZeroingWithoutMask => "BAD_EVEX_Z_NO_MASKING",
        DecodeError::BadEvexLength => "BAD_EVEX_LL",
        DecodeError::GatherRegisters => "GATHER_REGS",
        DecodeError::BadRegisterMatch => "BAD_REG_MATCH",
    }
}

/// The length decoder's answer: the length or XED's error name.
pub fn length(bytes: &[u8], mode: Mode) -> String {
    decode_length(bytes, mode).map_or_else(|e| xed_error(e).to_owned(), |n| n.to_string())
}

/// The full decode: `LENGTH ICLASS IFORM | OPERAND...`, or the error.
pub fn decoded(result: &Result<Instruction, DecodeError>) -> String {
    match result {
        Ok(instruction) => {
            let mut text = format!(
                "{} {} {} |",
                instruction.len(),
                instruction.mnemonic().as_str(),
                instruction.form().as_str()
            );
            for operand in instruction.operands() {
                write!(
                    text,
                    " {}:{}:{}={}",
                    operand.name.as_str(),
                    visibility(operand.visibility),
                    action(operand.action),
                    value(&operand.value)
                )
                .unwrap();
            }
            text
        }
        Err(error) => xed_error(*error).to_owned(),
    }
}

/// The oracle's whole answer for `bytes` at `address` (`oracle_answer`).
pub fn answer(mode: Mode, address: u64, bytes: &[u8]) -> String {
    let length = length(bytes, mode);
    let result = decode(bytes, mode);
    match &result {
        Ok(instruction) => format!(
            "{length} {}\t{}\t{}\t{}",
            decoded(&result),
            instruction.intel(address),
            flags(instruction),
            cpuid(instruction)
        ),
        Err(error) => format!("{length} {} - - |", xed_error(*error)),
    }
}

fn visibility(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Explicit => "EXPLICIT",
        Visibility::Implicit => "IMPLICIT",
        Visibility::Suppressed => "SUPPRESSED",
    }
}

fn action(action: Action) -> &'static str {
    match action {
        Action::Read => "R",
        Action::Write => "W",
        Action::ReadWrite => "RW",
        Action::ConditionalRead => "CR",
        Action::ConditionalWrite => "CW",
        Action::ConditionalReadWrite => "CRW",
        Action::ReadConditionalWrite => "RCW",
    }
}

/// XED's register name.
fn register(register: Option<Register>) -> String {
    register.map_or_else(|| "INVALID".to_owned(), |r| r.name().to_ascii_uppercase())
}

/// An operand value in the oracle's notation.
fn value(value: &Value) -> String {
    match *value {
        Value::Register(r) => register(r),
        Value::Memory(m) => format!(
            "{}:{}:{}:{}:{}:{}",
            register(m.segment),
            register(m.base),
            register(m.index),
            m.scale,
            m.displacement,
            m.size
        ),
        Value::Immediate { value, signed } => format!("{value:x}{}", if signed { "s" } else { "" }),
        Value::SecondImmediate(value) => format!("{value:x}"),
        Value::Relative(displacement) => displacement.to_string(),
        Value::Field(value) => value.to_string(),
    }
}

/// The flags column.
pub fn flags(instruction: &Instruction) -> String {
    instruction.flags().map_or_else(
        || "-".to_owned(),
        |f| {
            let effects: Vec<String> = f.effects.iter().map(ToString::to_string).collect();
            format!(
                "{:x}:{:x}:{:x}:{}:{}:{}",
                f.read.0,
                f.written.0,
                f.undefined.0,
                u8::from(f.may_write),
                u8::from(f.must_write),
                effects.join(",")
            )
        },
    )
}

/// The CPUID column.
pub fn cpuid(instruction: &Instruction) -> String {
    let groups: Vec<String> = instruction
        .isa_set()
        .cpuid()
        .iter()
        .map(|group| {
            let fields: Vec<String> = group
                .iter()
                .map(|f| {
                    format!(
                        "{:x}.{:x}.{}.{}:{}={}",
                        f.leaf,
                        f.subleaf,
                        f.register.as_str().to_ascii_uppercase(),
                        f.low,
                        f.high,
                        f.value
                    )
                })
                .collect();
            fields.join(",")
        })
        .collect();
    if groups.is_empty() {
        "-".to_owned()
    } else {
        groups.join("|")
    }
}
