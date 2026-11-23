//! Finds the functions that call a function with a constant first
//! argument: for each call to it, the instructions before the call in its
//! block are decoded to what last set the argument's register (`mov` of an
//! immediate, `xor` of itself, an address computed by `lea` or `adr`);
//! pointers to strings are shown as the string. Reads only: nothing is
//! written. x86-64 (System V) and AArch64.
//!
//! With no arguments it finds the calls to exit in the checked-in test
//! program (`tests/fixtures/program-x86_64.elf`); give a path, and a
//! function (default exit), to run on your own binary.
//!
//! ```text
//! cargo run --release -p binbun --example calls_with_constant
//! cargo run --release -p binbun --example calls_with_constant -- /usr/bin/bash exit
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::references::Kind;
use binbun::strings::MIN_SCANNED;
use binbun_aarch64::Decoder as A64Decoder;
use binbun_aarch64::operand::{Operand, RegisterClass};
use binbun_isa::Instruction as _;
use binbun_loader::{Image, Machine};
use binbun_x86::{Decoder as X86Decoder, Mode, Value};

/// The binary run on when no file is given.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/program-x86_64.elf"
);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (path, callee) = match args.as_slice() {
        [] => (FIXTURE, "exit"),
        [path] => (path.as_str(), "exit"),
        [path, callee] => (path.as_str(), callee.as_str()),
        _ => {
            eprintln!("usage: calls_with_constant [FILE [FUNCTION]]");
            return ExitCode::FAILURE;
        }
    };
    match find(path, callee) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{path}: {message}");
            ExitCode::FAILURE
        }
    }
}

/// One line per call to `callee` in the binary at `path` passing a
/// constant first argument, then how many calls there are.
fn find(path: &str, callee: &str) -> Result<Vec<String>, String> {
    let data = fs::read(path).map_err(|error| error.to_string())?;
    let image = Image::parse(&data).map_err(|error| error.to_string())?;
    if !matches!(image.machine, Machine::X86_64 | Machine::Aarch64) {
        return Err("not x86-64 or AArch64".to_owned());
    }
    let database = Database::new(&image, Seeds::ALL).map_err(|error| error.to_string())?;
    // By the image's name for it: a symbol, or an import's PLT thunk.
    let entry = database
        .functions()
        .map(|(_, f)| f.entry)
        .find(|&entry| database.data_name(entry).as_deref() == Some(callee))
        .ok_or_else(|| format!("no function {callee}"))?;
    let strings = database.strings(MIN_SCANNED);
    let shown = |value: u64| match strings.iter().find(|s| s.address == value) {
        Some(string) => format!("{:?}", string.text),
        None => format!("{value:#x}"),
    };

    let calls: Vec<_> = database
        .references()
        .to(entry)
        .iter()
        .filter(|r| r.kind == Kind::Call)
        .collect();
    let mut lines = Vec::new();
    for call in &calls {
        let Some(function) = call.function.and_then(|id| database.function(id)) else {
            continue;
        };
        // The bytes from the start of the call's block to the call.
        let block = function
            .blocks
            .iter()
            .filter_map(|&b| database.program().blocks.get(b))
            .find(|b| (b.start..b.end).contains(&call.from));
        let code = block.and_then(|block| {
            let segment = image.segment(block.start)?;
            let offset = usize::try_from(block.start - segment.start).ok()?;
            let length = usize::try_from(call.from - block.start).ok()?;
            Some((block.start, segment.bytes.get(offset..offset + length)?))
        });
        let Some((start, code)) = code else {
            continue;
        };
        let value = if image.machine == Machine::Aarch64 {
            aarch64_constant(code, start)
        } else {
            x86_64_constant(code, start)
        };
        if let Some(value) = value {
            let name = database
                .data_name(function.entry)
                .unwrap_or_else(|| format!("sub_{:X}", function.entry));
            lines.push(format!(
                "{:#010x}  {name:<24} {callee}({})",
                call.from,
                shown(value)
            ));
        }
    }
    lines.push(format!(
        "{} of {} calls to {callee} pass a constant first argument",
        lines.len(),
        calls.len()
    ));
    Ok(lines)
}

/// The constant the last instruction of `code` (at `start`) setting `rdi`
/// puts there, if it is one.
fn x86_64_constant(code: &[u8], start: u64) -> Option<u64> {
    const RDI: [&str; 4] = ["rdi", "edi", "di", "dil"];
    let instructions: Vec<_> = X86Decoder::new(code, Mode::Bits64, start)
        .filter_map(|(address, decoded)| Some((address, decoded.ok()?)))
        .collect();
    for (address, instruction) in instructions.iter().rev() {
        let operands: Vec<_> = instruction.operands().collect();
        let writes_rdi = operands.iter().any(|operand| {
            matches!(operand.value, Value::Register(Some(r)) if RDI.contains(&r.name()))
                && operand.action.writes()
        });
        if !writes_rdi {
            continue;
        }
        let source = operands.get(1).map(|operand| operand.value);
        return match (instruction.mnemonic().as_str(), source) {
            ("MOV", Some(Value::Immediate { value, .. })) => Some(value),
            ("XOR", Some(source)) if Some(source) == operands.first().map(|o| o.value) => Some(0),
            ("LEA", _) => instruction.computed_address(*address),
            _ => None,
        };
    }
    None
}

/// The constant the last instruction of `code` (at `start`) setting `x0`
/// or `w0` puts there, if it is one.
fn aarch64_constant(code: &[u8], start: u64) -> Option<u64> {
    let instructions: Vec<_> = A64Decoder::new(code, start)
        .filter_map(|(address, decoded)| Some((address, decoded.ok()?)))
        .collect();
    for (address, instruction) in instructions.iter().rev() {
        let operands = instruction.operands();
        let writes_x0 = matches!(
            operands.as_slice().first(),
            Some(Operand::Register(r)) if r.number == 0 && matches!(r.class, RegisterClass::X | RegisterClass::W)
        ) && instruction
            .access()
            .as_slice()
            .first()
            .is_some_and(|a| a.writes());
        if !writes_x0 {
            continue;
        }
        return match (instruction.mnemonic(), operands.as_slice().get(1)) {
            // A negative constant as its two's complement bits.
            ("mov", Some(Operand::Immediate(immediate))) => Some(immediate.value),
            ("adr", _) => instruction.computed_address(*address),
            _ => None,
        };
    }
    None
}
