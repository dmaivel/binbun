//! exarmo-aarch64 as a validity oracle for binbun's A64 decoder: for the
//! encodings LLVM 22 does not know (or wrongly rejects), which words Arm's
//! specification defines, from a decoder generated independently from the
//! same 2026-09 release of it.
//!
//! The line protocol of `tools/llvm-oracle`: reads lines `WORD [ADDRESS]`
//! from stdin, WORD being the 32-bit instruction word in hex (as a number:
//! `d503201f` is `nop`) and ADDRESS the optional hex address of the
//! instruction (default 0). Prints one line per input line: `invalid` if
//! exarmo does not decode the word, otherwise its text, followed by
//! `\t// CONSTRAINED UNPREDICTABLE` if exarmo marks the word CONSTRAINED
//! UNPREDICTABLE (should-be bits not as specified, overlapping registers).
//!
//! With `--flow`, each answer is instead exarmo's branch information at
//! the address: `invalid`, or `KIND CONDITIONAL TARGET`, KIND being
//! exarmo's `BranchKind` (`None`, `Direct`, `Indirect`, `DirectCall`,
//! `IndirectCall`, `Return`, `ExceptionReturn`, `SystemCall`, `Exception`,
//! `Halt`), CONDITIONAL `0` or `1`, TARGET the hex target or `-`. The
//! decoder's flow test compares its `flow` with it.
//!
//! With `--analysis`, each decoded word's line is instead what exarmo knows
//! of its accesses, as space-separated fields:
//!
//! - `F<r><w>`: the condition flags read and written (hex nibbles, N = 8,
//!   Z = 4, C = 2, V = 1).
//! - `K<kinds>`: one letter per operand of exarmo's operand view: `r`
//!   register, `l` list, `m` memory, `i` immediate, `f` float, `b` label,
//!   `s` system register, `o` system operation, `c` condition, `y` symbol,
//!   `z` ZA slice, `t` tile mask, `d` modifier, `x` other.
//! - `S<access>`: `R` or `W` if a system operation operand takes a general
//!   register and reads or writes it, `-` otherwise.
//! - `R<indices>` and `W<indices>`: the operands (comma-separated indices
//!   into the operand view, `-` for none) the ACLE intrinsics the
//!   instruction realises take as arguments and give as their result.
//! - `P<pointer>`: `L` if an intrinsic takes a read-only pointer (a load),
//!   `S` if a writable one (a store), `-` otherwise.
//!
//! Build with `scripts/exarmo-oracle.sh`.

use std::collections::BTreeSet;
use std::error::Error;
use std::io::{self, BufRead as _, BufWriter, Write as _};
use std::process::ExitCode;

use exarmo_aarch64::{
    Instruction, Operand, Output, RegisterAccess, RegisterUse, Source, decode_word,
};

/// Parses a line `WORD [ADDRESS]`.
fn parse(line: &str) -> Option<(u32, u64)> {
    let mut parts = line.split_whitespace();
    let word = u32::from_str_radix(parts.next()?, 16).ok()?;
    let address = match parts.next() {
        Some(address) => u64::from_str_radix(address, 16).ok()?,
        None => 0,
    };
    parts.next().is_none().then_some((word, address))
}

/// Writes exarmo's text of `instruction`.
fn text(out: &mut impl io::Write, instruction: Instruction, address: u64) -> io::Result<()> {
    if instruction.unpredictable() {
        writeln!(
            out,
            "{}\t// CONSTRAINED UNPREDICTABLE",
            instruction.at(address)
        )
    } else {
        writeln!(out, "{}", instruction.at(address))
    }
}

/// Writes exarmo's branch information for `instruction` at `address`.
fn flow(out: &mut impl io::Write, instruction: Instruction, address: u64) -> io::Result<()> {
    let branch = instruction.at(address).branch();
    write!(out, "{:?} {}", branch.kind, u8::from(branch.conditional))?;
    match branch.target {
        Some(target) => writeln!(out, " {target:x}"),
        None => writeln!(out, " -"),
    }
}

/// The letter of an operand's kind.
const fn kind(operand: &Operand) -> char {
    match operand {
        Operand::Reg(_) => 'r',
        Operand::List(_) => 'l',
        Operand::Mem(_) => 'm',
        Operand::Imm { .. } => 'i',
        Operand::FpImm { .. } => 'f',
        Operand::Label { .. } => 'b',
        Operand::SysReg(_) => 's',
        Operand::SysOp(_) => 'o',
        Operand::Cond(_) => 'c',
        Operand::Symbol(_) => 'y',
        Operand::ZaSlice(_) => 'z',
        Operand::TileMask(_) => 't',
        Operand::Modifier(_) => 'd',
        Operand::Other => 'x',
    }
}

/// Comma-separated indices, `-` for none.
fn indices(set: &BTreeSet<u8>) -> String {
    if set.is_empty() {
        return "-".to_owned();
    }
    set.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
}

/// The `--analysis` line of a decoded word.
fn analysis(instruction: &Instruction) -> String {
    let flags = instruction.flags();
    let operands = instruction.operands();
    let kinds: String = operands.as_slice().iter().map(kind).collect();
    let sysop = operands
        .as_slice()
        .iter()
        .find_map(|operand| match operand {
            Operand::SysOp(op) if op.def().reg_use != RegisterUse::None => {
                Some(match op.def().reg_access {
                    RegisterAccess::Read => 'R',
                    RegisterAccess::Write => 'W',
                })
            }
            _ => None,
        })
        .unwrap_or('-');
    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();
    let mut pointer = '-';
    for intrinsic in instruction.intrinsics() {
        let def = intrinsic.def();
        for (source, parameter) in intrinsic.arguments.iter().zip(def.parameters) {
            if let Source::Operand(index) = source {
                reads.insert(*index);
                let parameter = parameter.def();
                if parameter.pointer {
                    pointer = if parameter.readonly { 'L' } else { 'S' };
                }
            }
        }
        match intrinsic.result {
            Output::Operand(index) | Output::Element { operand: index, .. } => {
                writes.insert(index);
            }
            Output::None => {}
        }
    }
    format!(
        "F{:x}{:x} K{kinds} S{sysop} R{} W{} P{pointer}",
        flags.reads.0,
        flags.writes.0,
        indices(&reads),
        indices(&writes),
    )
}

/// Writes what exarmo knows of `instruction`'s accesses (`--analysis`).
fn accesses(out: &mut impl io::Write, instruction: Instruction, _address: u64) -> io::Result<()> {
    writeln!(out, "{}", analysis(&instruction))
}

fn run() -> Result<(), Box<dyn Error>> {
    let answer = match std::env::args().nth(1).as_deref() {
        None => text,
        Some("--flow") => flow,
        Some("--analysis") => accesses,
        Some(other) => return Err(format!("unknown argument {other}").into()),
    };
    let mut out = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line?;
        let Some((word, address)) = parse(&line) else {
            return Err(format!("bad input line: {line}").into());
        };
        match decode_word(word) {
            Ok(instruction) => answer(&mut out, instruction, address)?,
            Err(_) => writeln!(out, "invalid")?,
        }
    }
    out.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("exarmo-oracle: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
