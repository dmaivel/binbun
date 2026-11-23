//! Development tasks, run as `cargo xtask <task>`.
//!
//! - `codegen`: regenerate every checked-in generated source file (from
//!   XED's and AARCHMRS's data, and the L2 rewrite rules).
//! - `codegen --check`: fail if any generated file is out of date (for CI).
//! - `header`: regenerate the C API's generated header
//!   (`crates/binbun-capi/include/binbun/disasm_generated.h`) from the
//!   decoders as built, so after `codegen` when the decoder tables change.
//! - `header --check`: fail if it is out of date (for CI).

#![allow(
    clippy::too_many_lines,
    clippy::indexing_slicing,
    reason = "generators are long quote! templates over their own tables; a panic is a generator bug"
)]

mod aarch64;
mod codegen;
mod header;
mod lift;
mod naming;
mod rules;
mod x86;

use std::path::Path;
use std::process::ExitCode;

use codegen::Action;

/// Result type of every task.
type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let task = match *args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["codegen"] => Task::Codegen(Action::Write),
        ["codegen", "--check"] => Task::Codegen(Action::Check),
        ["header"] => Task::Header(Action::Write),
        ["header", "--check"] => Task::Header(Action::Check),
        _ => {
            eprintln!("usage: cargo xtask codegen [--check]\n       cargo xtask header [--check]");
            return ExitCode::FAILURE;
        }
    };
    match run(task) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// What to run.
#[derive(Debug, Clone, Copy)]
enum Task {
    Codegen(Action),
    Header(Action),
}

fn run(task: Task) -> Result<bool> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask is not inside the workspace")?;
    let action = match task {
        Task::Codegen(action) => action,
        Task::Header(action) => return header::run(root, action),
    };
    let mut files = x86::generate(root)?;
    files.extend(aarch64::generate(root)?);
    files.extend(rules::generate(root)?);
    codegen::emit(root, &files, action)
}
