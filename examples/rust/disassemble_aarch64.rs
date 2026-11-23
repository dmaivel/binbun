//! Disassembles a buffer of AArch64 machine code given in hexadecimal
//! (little-endian, as in memory): each instruction's address, word and
//! text (as LLVM writes it), with the registers it reads or writes without
//! naming them. Words that are no instruction are shown as such.
//!
//! With no bytes given it disassembles a small function of its own (a
//! prologue, a call, an epilogue).
//!
//! ```text
//! cargo run -p binbun-aarch64 --example disassemble_aarch64
//! cargo run -p binbun-aarch64 --example disassemble_aarch64 -- fd7bbfa9 fd030091 00000094 c0035fd6
//! cargo run -p binbun-aarch64 --example disassemble_aarch64 -- --address 0x400000 1f2003d5
//! ```

use std::env;
use std::fmt::Write as _;
use std::process::ExitCode;

use binbun_aarch64::Decoder;
use binbun_aarch64::operand::{Register, RegisterClass};

const USAGE: &str = "usage: disassemble_aarch64 [--address ADDRESS] [HEX...]";
/// What is disassembled when no bytes are given: `stp x29, x30, [sp,
/// #-0x10]!`, `mov x29, sp`, a `bl` to the next instruction, `ldp`, `ret`.
const EXAMPLE: &str = "fd7bbfa9fd03009101000094fd7bc1a8c0035fd6";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let (mut address, mut hex) = (0x1000, String::new());
    while let Some(arg) = args.next() {
        if arg == "--address" {
            let Some(value) = args.next().and_then(|v| parse_address(&v)) else {
                eprintln!("{USAGE}");
                return ExitCode::FAILURE;
            };
            address = value;
        } else {
            hex.push_str(&arg);
        }
    }
    if hex.is_empty() {
        hex.push_str(EXAMPLE);
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

    for (at, decoded) in Decoder::new(&code, address) {
        match decoded {
            Ok(instruction) => {
                let text = instruction.display(at).to_string().replace('\t', " ");
                let mut line = format!("{at:016x}  {:08x}  {text:<36}", instruction.word());
                let implicit = instruction.implicit();
                for (what, registers) in [("reads", implicit.reads), ("writes", implicit.writes)] {
                    if !registers.is_empty() {
                        let names: Vec<String> = registers.iter().copied().map(name).collect();
                        let _ = write!(line, " ; {what} {}", names.join(", "));
                    }
                }
                println!("{}", line.trim_end());
            }
            Err(error) => println!("{at:016x}  {:<8}  ({error})", "????????"),
        }
    }
    ExitCode::SUCCESS
}

/// How the text writes an implicit register: x30 (`bl`, `ret`), sp, x15 to
/// x17 (pointer authentication), ffr (SVE first-fault loads).
fn name(register: Register) -> String {
    match (register.class, register.number) {
        (RegisterClass::Xsp, 31) => "sp".to_owned(),
        (RegisterClass::X | RegisterClass::Xsp, n) => format!("x{n}"),
        (RegisterClass::Ffr, _) => "ffr".to_owned(),
        (class, n) => format!("{class:?}{n}").to_lowercase(),
    }
}

/// An address in hexadecimal (`0x400000`) or decimal.
fn parse_address(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}
