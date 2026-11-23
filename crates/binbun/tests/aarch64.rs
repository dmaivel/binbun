//! AArch64 code in SSA form: the functions of the hand-assembled fixture
//! (`tests/fixtures/dozen-aarch64.s`, written only with the instructions
//! that have semantics) build and verify, and constant propagation, the
//! stack analysis and summaries see through them as AAPCS64 says; the
//! corpus functions made only of those instructions do the same (ignored:
//! `BINBUN_ARM64_CORPUS` names the corpus directory of
//! `scripts/aarch64-corpus.sh`).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;

use binbun::analysis::{Seeds, analyse, type_library};
use binbun::cfg::Program;
use binbun::lift::{Kind, decode_and_lift, lift_function};
use binbun::memory::ImageMemory;
use binbun::summary::{Summaries, summaries};
use binbun_aarch64_lift::AARCH64;
use binbun_aarch64_lift::registers::{SP, x};
use binbun_loader::{Image, SymbolKind};
use binbun_semantics::RegisterId;
use binbun_ssa::constant::{Constants, propagate};
use binbun_ssa::stack::Stack;
use binbun_ssa::summary::{Kept, Summary, summarize};
use binbun_ssa::text::print;
use binbun_ssa::verify::verify;
use binbun_ssa::{Function, Op, Terminator, Type};

fn fixture() -> Vec<u8> {
    let path = format!(
        "{}/../../tests/fixtures/dozen-aarch64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A function's L1 and what the analyses find in it.
struct Analysed {
    function: Function,
    constants: Constants,
    stack: Stack,
    summary: Option<Summary>,
}

fn analysed(image: &Image<'_>, program: &Program, entry: u64, summaries: &Summaries) -> Analysed {
    let id = program.function_at(entry).unwrap();
    let function = lift_function(image, program, id, summaries).unwrap();
    verify(&function, &AARCH64).unwrap();
    let constants = propagate(&function, &ImageMemory::new(image));
    let arguments: Vec<RegisterId> = (0..8).map(x).collect();
    let stack = Stack::new(&function, &AARCH64, &constants, SP, &arguments);
    let summary = summarize(&function, &AARCH64, &constants, &stack, SP);
    Analysed {
        function,
        constants,
        stack,
        summary,
    }
}

/// The fixture's functions by name, as its symbols give them.
fn functions<'a>(image: &'a Image<'_>) -> BTreeMap<&'a str, u64> {
    image
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
        .map(|symbol| (symbol.name.as_str(), symbol.address))
        .collect()
}

/// Stack offsets (from the entry stack pointer) of the loads and stores of
/// `analysed`, with their sizes and directions.
fn slots(analysed: &Analysed) -> Vec<(i64, u16, bool)> {
    let mut slots = Vec::new();
    for inst in &analysed.function.insts {
        let (address, bytes, store) = if let Op::Load { address, bytes, .. } = &inst.op {
            (*address, *bytes, false)
        } else if let Op::Store { address, value, .. } = &inst.op {
            let width = match analysed.function.ty(*value) {
                Some(Type::Bits(width)) => width,
                Some(Type::Memory) | None => 0,
            };
            (*address, width / 8, true)
        } else {
            continue;
        };
        if let Some(offset) = analysed.stack.offset(address) {
            slots.push((offset, bytes, store));
        }
    }
    slots.sort_unstable();
    slots
}

/// The constant values of `register` where the function returns.
fn returned(analysed: &Analysed, register: RegisterId) -> Vec<Option<u64>> {
    analysed
        .function
        .blocks
        .iter()
        .filter_map(|block| {
            let Terminator::Return { state, .. } = &block.terminator else {
                return None;
            };
            Some(
                analysed
                    .constants
                    .constant(state.registers[usize::from(register.0)])
                    .map(|bits| bits.low_u64()),
            )
        })
        .collect()
}

/// The registers a summary says change (the stack pointer's move is its
/// `stack`).
fn changed(summary: &Summary) -> Vec<&'static str> {
    summary
        .kept
        .iter()
        .enumerate()
        .filter(|&(i, &kept)| kept != Kept::Yes && i != usize::from(SP.0))
        .map(|(i, _)| AARCH64.registers[i].name)
        .collect()
}

#[test]
fn fixture_functions_build_and_verify() {
    let data = fixture();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let summaries = summaries(&image, &program);
    let names = functions(&image);
    assert_eq!(names.len(), 6, "{names:?}");
    for (name, &entry) in &names {
        let id = program
            .function_at(entry)
            .unwrap_or_else(|| panic!("{name}"));
        let function = lift_function(&image, &program, id, &summaries)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        verify(&function, &AARCH64).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    // Every function that returns has a summary: not `_start` (which never
    // returns) nor `tail_sum` (which leaves through a tail call).
    let mut summarized: Vec<u64> = summaries.keys().copied().collect();
    summarized.sort_unstable();
    let mut returning =
        ["leaf_sum", "saved_sum", "loop_sum", "table_entry"].map(|name| names[name]);
    returning.sort_unstable();
    assert_eq!(summarized, returning);
}

#[test]
fn a_frame_saves_and_restores_callee_saved_registers() {
    let data = fixture();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let summaries = summaries(&image, &program);
    let names = functions(&image);
    let saved_sum = analysed(&image, &program, names["saved_sum"], &summaries);
    // stp x29, x30, [sp, #-0x20]! and str x19, [sp, #0x10], read back by
    // ldr and ldp (a pair is an access per register).
    assert_eq!(
        slots(&saved_sum),
        [
            (-32, 8, false),
            (-32, 8, true),
            (-24, 8, false),
            (-24, 8, true),
            (-16, 8, false),
            (-16, 8, true)
        ]
    );
    let summary = saved_sum.summary.as_ref().unwrap();
    assert_eq!(summary.stack, 0);
    // x19, x29 and x30 come back from the frame; x0 is the result; the
    // call to leaf_sum changes only what its summary says (x0, btype).
    assert_eq!(changed(summary), ["x0", "btype"]);
}

#[test]
fn leaf_summaries_are_what_the_instructions_write() {
    let data = fixture();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let summaries = summaries(&image, &program);
    let names = functions(&image);
    let leaf = analysed(&image, &program, names["leaf_sum"], &summaries);
    assert_eq!(changed(leaf.summary.as_ref().unwrap()), ["x0", "btype"]);
    // The loop's flags and both registers change; the loop is a cycle of
    // blocks.
    let loop_sum = analysed(&image, &program, names["loop_sum"], &summaries);
    assert_eq!(
        changed(loop_sum.summary.as_ref().unwrap()),
        ["x0", "x1", "n", "z", "c", "v", "btype"]
    );
    // Some block is reached from a block at a later address (the loop's
    // `b.ne`).
    let address =
        |target: &binbun_ssa::ir::Target| loop_sum.function.block(target.block).unwrap().address;
    let back_edge = loop_sum.function.blocks.iter().any(|block| {
        block
            .terminator
            .targets()
            .any(|target| address(target) < block.address)
    });
    assert!(back_edge, "{}", print(&loop_sum.function, &AARCH64));
}

#[test]
fn constants_propagate_through_page_addresses_and_read_only_memory() {
    let data = fixture();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let summaries = summaries(&image, &program);
    let names = functions(&image);
    // adrp x8, table; ldr x0, [x8, :lo12:table + 8]; x0 << 2.
    let table_entry = analysed(&image, &program, names["table_entry"], &summaries);
    assert_eq!(returned(&table_entry, x(0)), [Some(0x2a << 2)]);
    // The return address is the caller's x30, not a constant.
    assert_eq!(returned(&table_entry, x(30)), [None]);
}

#[test]
fn a_tail_call_leaves_the_function() {
    let data = fixture();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let names = functions(&image);
    let tail = analysed(&image, &program, names["tail_sum"], &Summaries::new());
    let leaves: Vec<&Terminator> = tail
        .function
        .blocks
        .iter()
        .map(|block| &block.terminator)
        .filter(|terminator| matches!(terminator, Terminator::Leave { .. }))
        .collect();
    assert_eq!(leaves.len(), 1, "{}", print(&tail.function, &AARCH64));
}

/// A function's L1 text, the registers it returns constant, its stack
/// slots and its summary.
fn describe(analysed: &Analysed) -> String {
    let mut text = print(&analysed.function, &AARCH64);
    let constant: Vec<String> = AARCH64
        .registers
        .iter()
        .enumerate()
        .filter_map(|(i, info)| {
            let values = returned(analysed, RegisterId(u16::try_from(i).unwrap()));
            (!values.is_empty() && values.iter().all(Option::is_some))
                .then(|| format!("{}={values:x?}", info.name))
        })
        .collect();
    writeln!(text, "constant at returns: {constant:?}").unwrap();
    writeln!(
        text,
        "stack slots (offset, bytes, store): {:?}",
        slots(analysed)
    )
    .unwrap();
    match &analysed.summary {
        Some(summary) => writeln!(
            text,
            "summary: changes {:?}, stack {:+}",
            changed(summary),
            summary.stack
        )
        .unwrap(),
        None => writeln!(text, "no summary").unwrap(),
    }
    text
}

#[test]
#[ignore = "needs the AArch64 corpus (BINBUN_ARM64_CORPUS)"]
fn corpus_functions_made_of_the_dozen() {
    let corpus = std::env::var("BINBUN_ARM64_CORPUS").expect("BINBUN_ARM64_CORPUS");
    let shown: usize = std::env::var("BINBUN_SHOW")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    let mut total = 0;
    for file in [
        "elf/libc6/libc.so.6",
        "elf/bash/bash",
        "elf/libstdc++6/libstdc++.so.6.0.33",
        "elf/libssl3t64/libcrypto.so.3",
        "elf/busybox-static/busybox",
        "elf/coreutils/ls",
    ] {
        let path = format!("{corpus}/{file}");
        let Ok(data) = fs::read(&path) else {
            eprintln!("{path}: missing");
            continue;
        };
        let image = Image::parse(&data).unwrap();
        let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
        let summaries = summaries(&image, &program);
        let mut built = Vec::new();
        for (id, function) in &program.functions {
            let only_the_dozen = function.blocks.iter().all(|&block| {
                let block = program.blocks[block];
                (0..u64::from(block.instructions)).all(|k| {
                    decode_and_lift(&image, block.start + 4 * k)
                        .is_ok_and(|lifted| matches!(lifted.semantics, Ok((_, Kind::Semantics))))
                })
            });
            if !only_the_dozen {
                continue;
            }
            let Ok(lifted) = lift_function(&image, &program, id, &summaries) else {
                continue;
            };
            verify(&lifted, &AARCH64)
                .unwrap_or_else(|e| panic!("{path} {:#x}: {e}", function.entry));
            built.push(function.entry);
        }
        eprintln!(
            "{file}: {} of {} functions are made of the dozen; {} summaries",
            built.len(),
            program.functions.len(),
            summaries.len()
        );
        for &entry in built.iter().take(shown) {
            let name = image
                .symbols
                .iter()
                .find(|symbol| symbol.address == entry)
                .map_or("?", |symbol| symbol.name.as_str());
            let analysed = analysed(&image, &program, entry, &summaries);
            eprintln!("--- {file} {entry:#x} {name}\n{}", describe(&analysed));
        }
        total += built.len();
    }
    assert!(total > 0, "no corpus function is made of the dozen");
}
