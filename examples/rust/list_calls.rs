//! Lists the calls in an executable's code section: each call's address,
//! its text, and where it goes (the name there, an import through its
//! slot, or "indirect"). The loader finds the section, the x86 or AArch64
//! decoder sweeps it, the engine names the targets (symbols, and import
//! thunks by their import). ELF or PE; x86-64, x86-32 or AArch64.
//!
//! With no file given it runs on the checked-in test program
//! (`tests/fixtures/program-x86_64.elf`); give a path to run on your own
//! binary.
//!
//! ```text
//! cargo run --release -p binbun --example list_calls
//! cargo run --release -p binbun --example list_calls -- /usr/bin/true
//! cargo run --release -p binbun --example list_calls -- program.exe .text
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun_aarch64::Decoder as A64Decoder;
use binbun_isa::{Flow, Target};
use binbun_loader::{Image, Machine};
use binbun_x86::{Decoder as X86Decoder, Mode};

/// The binary run on when no file is given.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/program-x86_64.elf"
);

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (path, section) = match args.as_slice() {
        [] => (FIXTURE, ".text"),
        [path] => (path.as_str(), ".text"),
        [path, section] => (path.as_str(), section.as_str()),
        _ => {
            eprintln!("usage: list_calls [FILE [SECTION]]");
            return ExitCode::FAILURE;
        }
    };
    match list_calls(path, section) {
        Ok(lines) => {
            println!("{} calls in {section} of {path}", lines.len());
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

/// One line per call in `wanted`, a code section of the file at `path`.
fn list_calls(path: &str, wanted: &str) -> Result<Vec<String>, String> {
    let data = fs::read(path).map_err(|error| error.to_string())?;
    let image = Image::parse(&data).map_err(|error| error.to_string())?;
    let section = image
        .sections
        .iter()
        .find(|s| s.name == wanted && image.is_code(s.start))
        .ok_or_else(|| format!("no code section {wanted}"))?;
    let segment = image
        .segment(section.start)
        .ok_or_else(|| format!("{wanted} is not mapped"))?;
    let offset = usize::try_from(section.start - segment.start).map_err(|e| e.to_string())?;
    let size = usize::try_from(section.size).map_err(|e| e.to_string())?;
    let code = segment
        .bytes
        .get(offset..offset + size)
        .ok_or_else(|| format!("{wanted} has no bytes in the file"))?;

    // Names for targets: a function's or import thunk's at an address, an
    // import's at its pointer slot.
    let database = Database::new(&image, Seeds::ALL).map_err(|error| error.to_string())?;
    let target = |target: Target| match target {
        Target::Address(address) => database
            .data_name(address)
            .unwrap_or_else(|| format!("{address:#x}")),
        Target::Pointer { address, .. } => image
            .imports
            .iter()
            .find(|import| import.slot == address)
            .map_or_else(
                || format!("*{address:#x}"),
                |import| format!("*{}", import.name),
            ),
        Target::Indirect => "indirect".to_owned(),
        Target::Far { selector, offset } => format!("{selector:#x}:{offset:#x}"),
    };

    let mut lines = Vec::new();
    let mut call = |address: u64, text: String, flow: Flow| {
        if let Flow::Call(to) = flow {
            lines.push(format!("{address:#010x}  {text:<40}  {}", target(to)));
        }
    };
    match image.machine {
        Machine::X86_64 | Machine::X86 => {
            let mode = if image.machine == Machine::X86_64 {
                Mode::Bits64
            } else {
                Mode::Bits32
            };
            for (address, decoded) in X86Decoder::new(code, mode, section.start) {
                if let Ok(instruction) = decoded {
                    call(
                        address,
                        instruction.intel(address).to_string(),
                        instruction.flow(address),
                    );
                }
            }
        }
        Machine::Aarch64 => {
            for (address, decoded) in A64Decoder::new(code, section.start) {
                if let Ok(instruction) = decoded {
                    let text = instruction.display(address).to_string().replace('\t', " ");
                    call(address, text, instruction.flow(address));
                }
            }
        }
        Machine::Arm | Machine::Other => {
            return Err("the code is neither x86 nor AArch64".to_owned());
        }
    }
    Ok(lines)
}
