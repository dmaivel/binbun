//! Disassembles a buffer of machine code given in hexadecimal for x86 (64,
//! 32 or 16-bit) or AArch64 through one API (`binbun-disasm`): each
//! instruction's address, bytes, text, mnemonic, and the registers it
//! reads and writes. Bytes that are no instruction are shown as such and
//! skipped (one byte on x86, four on AArch64).
//!
//! With no bytes given it disassembles a small function of its own (a
//! prologue, a call, an epilogue) for the architecture.
//!
//! ```text
//! cargo run -p binbun-disasm --example decode_any
//! cargo run -p binbun-disasm --example decode_any -- --arch aarch64
//! cargo run -p binbun-disasm --example decode_any -- --arch x86-32 --address 0x400000 55 89e5 c3
//! ```

use std::env;
use std::process::ExitCode;

use binbun_disasm::{Arch, Decoder, Registers, x86};

const USAGE: &str =
    "usage: decode_any [--arch x86-64|x86-32|x86-16|aarch64] [--address ADDRESS] [HEX...]";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let (mut arch, mut address, mut hex) = (Arch::X86(x86::Mode::Bits64), 0x1000, String::new());
    while let Some(arg) = args.next() {
        let parsed = match arg.as_str() {
            "--arch" => args
                .next()
                .and_then(|name| parse_arch(&name))
                .map(|a| arch = a),
            "--address" => args
                .next()
                .and_then(|v| parse_address(&v))
                .map(|a| address = a),
            _ => {
                hex.push_str(&arg);
                Some(())
            }
        };
        if parsed.is_none() {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    }
    if hex.is_empty() {
        hex.push_str(example(arch));
    }
    let code: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|p| u8::from_str_radix(p, 16).ok())
        })
        .collect();
    let Some(code) = code.filter(|code| !code.is_empty() && hex.len() % 2 == 0) else {
        eprintln!("{USAGE}\n(the bytes: hexadecimal digits, two per byte)");
        return ExitCode::FAILURE;
    };

    let width = arch.max_length().min(8) * 3;
    for (at, decoded) in Decoder::new(arch, &code, address) {
        match decoded {
            Ok(insn) => {
                let bytes = hex_bytes(insn.bytes());
                let text = insn.to_string().replace('\t', " ");
                println!(
                    "{at:016x}  {bytes:<width$} {text:<28} {:<6} reads {}; writes {}",
                    insn.mnemonic(),
                    names(&insn.registers_read()),
                    names(&insn.registers_written()),
                );
            }
            Err(error) => {
                let start = usize::try_from(at.wrapping_sub(address)).unwrap_or(usize::MAX);
                let rest = code.get(start..).unwrap_or_default();
                let bytes = hex_bytes(rest.get(..arch.invalid_step()).unwrap_or(rest));
                println!("{at:016x}  {bytes:<width$} ({error})");
            }
        }
    }
    ExitCode::SUCCESS
}

/// What is disassembled when no bytes are given: push the frame pointer,
/// set it, call the next instruction, pop it, return.
fn example(arch: Arch) -> &'static str {
    match arch {
        Arch::X86(x86::Mode::Bits64) => "554889e5e8000000005dc3",
        Arch::X86(x86::Mode::Bits32 | x86::Mode::Real32) => "5589e5e8000000005dc3",
        Arch::X86(x86::Mode::Bits16 | x86::Mode::Real16) => "5589e5e800005dc3",
        Arch::AArch64 => "fd7bbfa9fd03009101000094fd7bc1a8c0035fd6",
    }
}

/// `registers` by name, `-` for none.
fn names(registers: &Registers) -> String {
    if registers.is_empty() {
        return "-".to_owned();
    }
    let names: Vec<String> = registers.iter().map(ToString::to_string).collect();
    names.join(" ")
}

/// `bytes` as hexadecimal pairs separated by spaces.
fn hex_bytes(bytes: &[u8]) -> String {
    let pairs: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    pairs.join(" ")
}

fn parse_arch(name: &str) -> Option<Arch> {
    Some(match name {
        "x86-64" => Arch::X86(x86::Mode::Bits64),
        "x86-32" => Arch::X86(x86::Mode::Bits32),
        "x86-16" => Arch::X86(x86::Mode::Bits16),
        "aarch64" => Arch::AArch64,
        _ => return None,
    })
}

/// An address in hexadecimal (`0x400000`) or decimal.
fn parse_address(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}
