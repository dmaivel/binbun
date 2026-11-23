//! Computed jumps and calls resolved during AArch64 recovery, on the
//! hand-assembled fixture (`tests/fixtures/resolve-aarch64.s`, linked by
//! ld.lld against a stub library): PLT stubs become thunks to their
//! imports, so calls to `exit` through the PLT, a tail call to it and a
//! call to `abort` through the GOT do not return; switch tables of byte,
//! halfword and word offsets are proven from their guards, and one bounded
//! only by its index's width ends where the next table begins.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeMap;

use binbun::analysis::{Seeds, analyse, type_library};
use binbun::cfg::{Destination, Exit, Program, Returns, Table};
use binbun::eval::evaluate;
use binbun_loader::{Image, SymbolKind};

fn fixture() -> Vec<u8> {
    let path = format!(
        "{}/../../tests/fixtures/resolve-aarch64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn symbols<'a>(image: &'a Image<'_>) -> BTreeMap<&'a str, u64> {
    image
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
        .map(|symbol| (symbol.name.as_str(), symbol.address))
        .collect()
}

fn slot(image: &Image<'_>, name: &str) -> u64 {
    image
        .imports
        .iter()
        .find(|import| import.name == name)
        .unwrap_or_else(|| panic!("no import {name}"))
        .slot
}

fn returns(program: &Program, entry: u64) -> bool {
    program.functions[program.function_at(entry).unwrap()].returns
}

/// The table of the computed jump whose block ends at `end`.
fn table(program: &Program, end: u64) -> &Table {
    let block = program.block_containing(end - 4).unwrap();
    program
        .table(block)
        .unwrap_or_else(|| panic!("the jump ending at {end:#x} is not resolved"))
}

#[test]
fn plt_stubs_are_thunks_and_imports_that_never_return_end_their_callers() {
    let data = fixture();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let names = symbols(&image);
    assert_eq!(program.unresolved().count(), 0);
    assert_eq!(program.conflicts, []);

    // The thunk of each PLT stub: one block, a jump to the import.
    let thunk = |name: &str| {
        let slot = slot(&image, name);
        let (_, function) = program
            .functions
            .iter()
            .find(|(_, f)| {
                f.blocks.len() == 1
                    && program.blocks[f.blocks[0]].exit == Exit::Jump(Destination::Import(slot))
            })
            .unwrap_or_else(|| panic!("no thunk to {name}"));
        function.entry
    };
    let (exit, puts) = (thunk("exit"), thunk("puts"));
    assert!(!returns(&program, exit), "exit's thunk returns");
    assert!(returns(&program, puts), "puts' thunk does not return");
    assert_eq!(evaluate(&image, &program).thunks, 2);

    // `bl exit` at the end of _start: the `udf` after it is no code.
    let start = names["_start"];
    let call = program.block_containing(start + 0x2c).unwrap();
    assert_eq!(
        program.blocks[call].exit,
        Exit::Call {
            callee: Destination::Address(exit),
            returns: Returns::No
        }
    );
    assert!(program.block_at(start + 0x30).is_none(), "udf decoded");
    assert!(!returns(&program, start));

    // A tail call to exit through the PLT, and abort called through the
    // GOT: neither function returns, nor is got_abort's `ret` code.
    assert!(!returns(&program, names["tail_exit"]));
    let got_abort = names["got_abort"];
    assert_eq!(
        program.blocks[program.block_at(got_abort).unwrap()].exit,
        Exit::Call {
            callee: Destination::Import(slot(&image, "abort")),
            returns: Returns::No
        }
    );
    assert!(program.block_at(got_abort + 0xc).is_none(), "ret decoded");
    assert!(!returns(&program, got_abort));
    // guarded's default case calls puts and goes on.
    assert!(returns(&program, names["guarded"]));
}

#[test]
fn switch_tables_are_proven_by_their_guards_or_cut_where_the_next_table_starts() {
    let data = fixture();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let names = symbols(&image);
    let cases = |base: u64, offsets: &[u64]| -> Vec<u64> {
        offsets.iter().map(|&offset| base + offset).collect()
    };

    // Bytes from `b.hi`, halfwords from `b.ls`, words from `b.hs`: every
    // case, and only those, for every index the guard lets through.
    let guarded = names["guarded"] + 0x20;
    let found = table(&program, guarded);
    assert!(!found.inferred);
    assert_eq!(found.targets, cases(guarded, &[0, 8, 16, 24]));
    let halves = names["halves"] + 0x28;
    let found = table(&program, halves);
    assert!(!found.inferred);
    assert_eq!(found.targets, cases(halves, &[0, 4, 12, 20, 28]));
    let words = names["words"] + 0x1c;
    let found = table(&program, words);
    assert!(!found.inferred);
    assert_eq!(found.targets, cases(words, &[0, 8, 16]));

    // No guard: the loaded byte's width bounds the index. Read on, the
    // halfword table's first byte (1) would be the `ret` at base + 4; the
    // table ends where halves' `adrp`+`add` addresses the next table.
    let width = names["width"] + 0x1c;
    let found = table(&program, width);
    assert!(found.inferred);
    assert_eq!(found.targets, cases(width, &[0, 8, 16]));
    assert!(
        program.block_at(width + 4).is_none(),
        "base + 4 is a target"
    );
}
