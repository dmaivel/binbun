//! Shows what one x86-64 instruction does: its operands and whether it
//! reads or writes each, the registers it uses without naming them (the
//! operands its text does not show), what it does to each flag, and where
//! it branches.
//!
//! With no bytes given it shows `add qword ptr [rbx+0x10], rax`.
//!
//! ```text
//! cargo run -p binbun-x86 --example instruction_info
//! cargo run -p binbun-x86 --example instruction_info -- 48014310   # add qword ptr [rbx+0x10], rax
//! cargo run -p binbun-x86 --example instruction_info -- 55         # push rbp
//! ```

use std::env;
use std::fmt::Write as _;
use std::process::ExitCode;

use binbun_isa::{Flow, Target};
use binbun_x86::{Instruction, Mode, Value, Visibility, decode};

/// Where the example says the instruction is.
const ADDRESS: u64 = 0x1000;
/// What is shown when no bytes are given: `add qword ptr [rbx+0x10], rax`.
const EXAMPLE: &str = "48014310";

fn main() -> ExitCode {
    let mut hex: String = env::args().skip(1).collect();
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
    let Some(code) = code.filter(|code| !code.is_empty() && hex.len().is_multiple_of(2)) else {
        eprintln!("usage: instruction_info [HEX] (the instruction's bytes)");
        return ExitCode::FAILURE;
    };
    match decode(&code, Mode::Bits64) {
        Ok(instruction) => {
            print!("{}", describe(&instruction));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("instruction_info: {hex}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// What `instruction` (at [`ADDRESS`]) does, one fact per line.
fn describe(instruction: &Instruction) -> String {
    let mut out = format!(
        "{ADDRESS:#x}: {}\n  mnemonic {}, form {}, {} bytes\n  operands:\n",
        instruction.intel(ADDRESS),
        instruction.mnemonic().as_str(),
        instruction.form().as_str(),
        instruction.len()
    );
    let mut implicit = Vec::new();
    for (n, operand) in instruction.operands().enumerate() {
        let access = match (operand.action.reads(), operand.action.writes()) {
            (true, true) => "read/write",
            (true, false) => "read",
            (false, true) => "write",
            (false, false) => "-",
        };
        let value = match operand.value {
            Value::Register(register) => register.map_or("-", |r| r.name()).to_owned(),
            Value::Memory(memory) => format!(
                "[{}{:+#x}] ({} bytes)",
                memory.base.map_or("", |r| r.name()),
                memory.displacement,
                memory.size
            ),
            Value::Immediate { value, .. } | Value::Field(value) => format!("{value:#x}"),
            Value::SecondImmediate(value) => format!("{value:#x}"),
            Value::Relative(displacement) => {
                format!("{displacement:+#x} from the next instruction")
            }
        };
        let _ = writeln!(
            out,
            "    {n}  {:<6} {access:<10} {:>3} bits  {value}",
            operand.name.as_str(),
            instruction.operand_bits(n)
        );
        if operand.visibility == Visibility::Suppressed {
            implicit.push(format!("{value} ({access})"));
        }
    }
    let _ = writeln!(out, "  implicit: {}", or_none(&implicit.join(", ")));
    let effects: Vec<String> = instruction
        .flags()
        .map(|flags| flags.effects.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    let _ = writeln!(out, "  flags: {}", or_none(&effects.join(" ")));
    let _ = writeln!(out, "  branch: {}", branch(instruction.flow(ADDRESS)));
    out
}

/// `text`, or `-` if it is empty.
fn or_none(text: &str) -> &str {
    if text.is_empty() { "-" } else { text }
}

/// Where `flow` goes.
fn branch(flow: Flow) -> String {
    let target = |target: Target| match target {
        Target::Address(address) => format!("{address:#x}"),
        Target::Pointer { address, size } => format!("the {size}-byte pointer at {address:#x}"),
        Target::Indirect => "a computed address".to_owned(),
        Target::Far { selector, offset } => format!("{selector:#x}:{offset:#x}"),
    };
    match flow {
        Flow::Next => "none (falls through)".to_owned(),
        Flow::Jump(to) => format!("jump to {}", target(to)),
        Flow::Branch(to) => format!("conditional jump to {}", target(to)),
        Flow::Call(to) => format!("call to {}", target(to)),
        Flow::Return => "return".to_owned(),
        Flow::Trap { .. } => "trap".to_owned(),
        Flow::SystemCall => "system call".to_owned(),
        Flow::ExceptionReturn => "exception return".to_owned(),
        Flow::Halt => "halt".to_owned(),
    }
}
