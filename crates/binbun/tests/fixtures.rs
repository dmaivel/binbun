//! Loading, recovering and evaluating the checked-in fixtures
//! (`tests/fixtures`, from `program.c`): each function of the program is
//! found with the right blocks and fate, on ELF, PE32+ and PE32.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::analysis::{Seeds, analyse, type_library};
use binbun::cfg::{Destination, Exit, Program, Returns};
use binbun::eval::evaluate;
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The address of the function `name` (or its cdecl `_name`).
fn address(image: &Image<'_>, name: &str) -> u64 {
    image
        .symbols
        .iter()
        .find(|s| s.name == name || s.name.strip_prefix('_') == Some(name))
        .unwrap_or_else(|| panic!("no symbol {name}"))
        .address
}

fn function(program: &Program, entry: u64) -> &binbun::cfg::Function {
    &program.functions[program.function_at(entry).unwrap()]
}

/// What `program.c`'s functions must come out as, whatever the format.
fn check_program(name: &str) {
    let data = fixture(name);
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();

    let fail = address(&image, "fail");
    let checked = address(&image, "checked");
    for (function_name, returns) in [
        ("main", true),
        ("classify", true),
        ("fail", false),
        ("checked", true),
        ("loop_sum", true),
    ] {
        let entry = address(&image, function_name);
        assert_eq!(
            function(&program, entry).returns,
            returns,
            "{name}: {function_name}"
        );
    }

    // checked calls fail, which never returns: nothing after that call is
    // code of checked.
    let calls_to_fail: Vec<_> = function(&program, checked)
        .blocks
        .iter()
        .map(|&id| program.blocks[id])
        .filter(
            |b| matches!(b.exit, Exit::Call { callee: Destination::Address(a), .. } if a == fail),
        )
        .collect();
    assert_eq!(calls_to_fail.len(), 1, "{name}");
    let call = calls_to_fail[0];
    assert_eq!(
        call.exit,
        Exit::Call {
            callee: Destination::Address(fail),
            returns: Returns::No
        },
        "{name}"
    );
    assert!(
        function(&program, checked)
            .blocks
            .iter()
            .all(|&id| program.blocks[id].start != call.end),
        "{name}: the bytes after `call fail` are in checked"
    );

    // fail ends in a call of the imported exit, which never returns.
    let ends_in_exit = function(&program, fail).blocks.iter().any(|&id| {
        matches!(
            program.blocks[id].exit,
            Exit::Call {
                returns: Returns::No,
                ..
            }
        )
    });
    assert!(ends_in_exit, "{name}");

    // loop_sum's loop: some block branches back to an earlier block of it.
    let loop_sum = function(&program, address(&image, "loop_sum"));
    let backward = loop_sum.blocks.iter().any(|&id| {
        let block = program.blocks[id];
        program
            .successors(id)
            .any(|(_, target)| target <= block.start && target >= loop_sum.entry)
    });
    assert!(backward, "{name}: loop_sum has no loop");

    // Everything the file states is found, and the graph is consistent.
    let evaluation = evaluate(&image, &program);
    assert_eq!(
        evaluation.correct, evaluation.truth,
        "{name}: {evaluation:?}"
    );
    assert_eq!(evaluation.unexplained_overlaps, 0, "{name}");
    assert_eq!(evaluation.missing_targets, 0, "{name}");
    assert_eq!(evaluation.conflicts, 0, "{name}");
}

#[test]
fn recovers_the_elf_program() {
    check_program("program-x86_64.elf");
}

#[test]
fn recovers_the_pe32_plus_program() {
    check_program("program-x86_64.exe");
}

#[test]
fn recovers_the_pe32_program() {
    check_program("program-i686.exe");
}

/// The catch block of `guarded` (in `exceptions.cpp`) is reached only by
/// the unwinder: through its landing pad, it is in a function's blocks, and
/// it calls `puts` (through its PLT stub, which jumps to the import). A
/// landing pad of a part joined into its function (`risky`'s cold part) is
/// that function's.
#[test]
fn recovers_catch_blocks_through_landing_pads() {
    let data = fixture("exceptions-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let puts = image
        .imports
        .iter()
        .find(|i| i.name == "puts")
        .unwrap()
        .slot;
    let stubs: Vec<u64> = program
        .functions
        .values()
        .filter(|f| {
            f.blocks
                .iter()
                .any(|&id| program.blocks[id].exit == Exit::Jump(Destination::Import(puts)))
        })
        .map(|f| f.entry)
        .collect();
    assert!(!stubs.is_empty(), "no stub jumps to puts");
    for pad in &image.landing_pads {
        let owner = program
            .functions
            .values()
            .find(|f| f.entry == pad.function || f.parts.contains(&pad.function))
            .unwrap_or_else(|| panic!("no function has {:#x}", pad.function));
        assert!(
            owner
                .blocks
                .iter()
                .any(|&id| program.blocks[id].start == pad.address),
            "landing pad {pad:x?} is not in its function"
        );
        assert!(owner.landing_pads.contains(&pad.address), "{pad:x?}");
    }
    let calls_puts = program.functions.values().any(|f| {
        f.blocks.iter().any(|&id| {
            matches!(
                program.blocks[id].exit,
                Exit::Call { callee: Destination::Address(target), .. } if stubs.contains(&target)
            )
        })
    });
    assert!(
        calls_puts,
        "the catch block's call to puts was not recovered"
    );
    let evaluation = evaluate(&image, &program);
    assert_eq!(
        (evaluation.unexplained_overlaps, evaluation.missing_targets),
        (0, 0)
    );
}

/// From the entry point alone (as in a stripped binary), recovery follows
/// calls into the program's functions; on PE, main is reached through the
/// C runtime's startup code.
#[test]
fn finds_functions_from_the_entry_point_alone() {
    let data = fixture("program-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ENTRY, &type_library(&image).unwrap()).unwrap();
    for name in ["main", "loop_sum", "checked", "classify", "fail"] {
        assert!(
            program.function_at(address(&image, name)).is_some(),
            "{name} not found from the entry point"
        );
    }
}
