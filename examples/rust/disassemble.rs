//! Disassembles a buffer of x86 machine code given in hexadecimal: each
//! instruction's address, bytes and text (Intel syntax, as XED writes it).
//! Bytes that are no instruction are shown as such and stepped over one at
//! a time, as a linear sweep does.
//!
//! With no bytes given it disassembles a small function of its own (a
//! prologue, a call, an epilogue) for the mode.
//!
//! ```text
//! cargo run -p binbun-x86 --example disassemble
//! cargo run -p binbun-x86 --example disassemble -- 55 4889e5 e800000000 c3
//! cargo run -p binbun-x86 --example disassemble -- --mode 32 --address 0x401000 8b442404 c3
//! ```

use std::env;
use std::process::ExitCode;

use binbun_x86::Instruction;
use binbun_x86::{Decoder, Mode};

const USAGE: &str = "usage: disassemble [--mode 64|32|16] [--address ADDRESS] [HEX...]";

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("disassemble: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (mut mode, mut address, mut hex) = (Mode::Bits64, 0x1000, String::new());
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                mode = match args.next().as_deref() {
                    Some("64") => Mode::Bits64,
                    Some("32") => Mode::Bits32,
                    Some("16") => Mode::Bits16,
                    _ => return Err(USAGE.to_owned()),
                }
            }
            "--address" => {
                let value = args.next().ok_or(USAGE)?;
                address = parse_address(&value)?;
            }
            _ => hex.push_str(&arg),
        }
    }
    let code = parse_hex(if hex.is_empty() { example(mode) } else { &hex })?;

    let decoded: Vec<_> = Decoder::new(&code, mode, address).collect();
    let longest = decoded
        .iter()
        .map(|(_, result)| result.as_ref().map_or(1, Instruction::len))
        .max()
        .unwrap_or(1);
    for (at, result) in decoded {
        let offset = usize::try_from(at - address).map_err(|e| e.to_string())?;
        let length = result.as_ref().map_or(1, Instruction::len);
        let bytes: Vec<String> = code
            .get(offset..offset + length)
            .unwrap_or_default()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let text = match result {
            Ok(instruction) => instruction.intel(at).to_string(),
            Err(error) => format!("(bad: {error})"),
        };
        println!(
            "{at:016x}  {:<width$} {text}",
            bytes.join(" "),
            width = longest * 3
        );
    }
    Ok(())
}

/// What is disassembled in `mode` when no bytes are given: push the frame
/// pointer, set it, call the next instruction, pop it, return.
const fn example(mode: Mode) -> &'static str {
    match mode {
        Mode::Bits64 => "554889e5e8000000005dc3",
        Mode::Bits32 | Mode::Real32 => "5589e5e8000000005dc3",
        Mode::Bits16 | Mode::Real16 => "5589e5e800005dc3",
    }
}

/// An address in hexadecimal (`0x401000`) or decimal.
fn parse_address(text: &str) -> Result<u64, String> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .map_err(|_| format!("{text} is not an address"))
}

/// Bytes written as hexadecimal digits, two per byte.
fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(format!(
            "{USAGE}\n(the bytes: hexadecimal digits, two per byte)"
        ));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("{text} is not hexadecimal"))
        })
        .collect()
}
