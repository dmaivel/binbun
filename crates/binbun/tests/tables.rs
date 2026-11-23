//! Jump tables resolved during recovery: the PE fixture's (MinGW's runtime
//! has three switches compiled to tables of 32-bit offsets in `.rdata`),
//! and libc's whose end is inferred.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::analysis::{Seeds, analyse, type_library};
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn switch_tables_resolve_and_jumps_through_pointers_stay_unresolved() {
    let data = fixture("program-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    // The `jmp rax` of each switch, and how many cases it has.
    for (jump, cases) in [(0x1_4000_183f, 7), (0x1_4000_1f0f, 10), (0x1_4000_20ab, 10)] {
        let block = program.block_containing(jump).unwrap();
        let table = program
            .table(block)
            .unwrap_or_else(|| panic!("the jump at {jump:#x} is not resolved"));
        assert!(!table.inferred, "{jump:#x}: a guard bounds it");
        let table = &table.targets;
        assert!(
            !table.is_empty() && table.len() <= cases,
            "{jump:#x}: {} targets for {cases} cases",
            table.len()
        );
        let function = program
            .functions
            .values()
            .find(|f| f.blocks.contains(&block))
            .unwrap();
        for &target in table {
            let target_block = program
                .block_at(target)
                .unwrap_or_else(|| panic!("{jump:#x}: no block at target {target:#x}"));
            assert!(
                function.blocks.contains(&target_block),
                "{jump:#x}: target {target:#x} is not code of the same function"
            );
        }
    }
    // A tail call through a pointer read from memory: no table bounds it.
    let pointer = program.block_containing(0x1_4000_20e3).unwrap();
    assert!(program.table(pointer).is_none());
    assert!(program.unresolved().any(|(block, _)| block == pointer));
}

/// libc has switches whose index only its width bounds; the tables
/// inferred for them end before entries that would be read from the next
/// table (whose offsets, taken from the wrong base, land in the middle of
/// instructions): no recovered instructions overlap, and every target is
/// code of the jump's function.
#[test]
fn inferred_tables_end_where_the_table_does() {
    const LIBC: &str = "/usr/lib/libc.so.6";
    if !std::path::Path::new(LIBC).exists() {
        return;
    }
    let data = std::fs::read(LIBC).unwrap();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let mut inferred = 0;
    for (block, _) in program.blocks.iter() {
        let Some(table) = program.table(block).filter(|table| table.inferred) else {
            continue;
        };
        inferred += 1;
        let function = program
            .functions
            .values()
            .find(|f| f.blocks.contains(&block))
            .unwrap();
        for &target in &table.targets {
            let target = program.block_at(target).unwrap();
            assert!(function.blocks.contains(&target));
        }
    }
    assert!(inferred > 0, "no table was inferred");
    assert_eq!(program.conflicts, []);
}
