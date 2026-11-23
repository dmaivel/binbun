#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The interfaces of `msvc-x86_64.exe` (`tests/fixtures/msvc.c`, built by
//! MSVC: see `scripts/build-fixtures.sh`) against its PDB's signatures.

use std::collections::BTreeMap;
use std::fs;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::stream;
use binbun_loader::Image;

/// Each function's parameter count by its PDB: the `# args` of the
/// `LF_PROCEDURE` type of its `S_GPROC32` record, at the image base plus
/// its section's virtual address plus its offset. To regenerate, build the
/// fixture with its PDB (`scripts/build-fixtures.sh` keeps it in its
/// scratch directory), then read `llvm-pdbutil dump --section-headers`,
/// `llvm-pdbutil dump --types` and `llvm-pdbutil dump --symbols --modi=0`
/// of `msvc-x86_64.pdb`.
const PDB: [(u64, &str, usize); 18] = [
    (0x1_4000_1010, "__local_stdio_printf_options", 0),
    (0x1_4000_1020, "_vfprintf_l", 4),
    (0x1_4000_1060, "apply", 2),
    (0x1_4000_1080, "five", 5),
    (0x1_4000_10a0, "four", 4),
    (0x1_4000_10c0, "last_error", 0),
    (0x1_4000_10d0, "main", 2),
    (0x1_4000_1270, "measure", 2),
    (0x1_4000_1290, "mixed", 4),
    (0x1_4000_12c0, "one", 1),
    (0x1_4000_1330, "release", 1),
    (0x1_4000_1340, "release_second", 2),
    (0x1_4000_1350, "report", 3),
    (0x1_4000_1370, "six", 6),
    (0x1_4000_1390, "teb", 0),
    (0x1_4000_13a0, "three", 3),
    (0x1_4000_13b0, "two", 2),
    (0x1_4000_13d0, "zero", 0),
];
// Not compared:
// - `printf` (0x1400012d0, 1 parameter and `...`): a variadic definition,
//   whose `va_start` stores `rdx`, `r8` and `r9` in their home slots.

/// Every function's parameters are the PDB's: the thread pointer (`gs`)
/// and the floating-point control registers (`mxcsr`, the x87 control
/// word) are the environment, not parameters, and positions take an
/// integer or a vector register.
#[test]
fn parameters_are_the_pdbs() {
    let path = format!(
        "{}/../../tests/fixtures/msvc-x86_64.exe",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = fs::read(&path).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let mut parameters = BTreeMap::new();
    stream(
        &image,
        database.program(),
        database.summaries(),
        &database.callers(&[]),
        &[],
        |id, _, interfaces| {
            let entry = database.function(id).unwrap().entry;
            if let Some(interface) = interfaces.interfaces.get(&entry) {
                parameters.insert(entry, interface.parameters.len());
            }
        },
    );
    let found: Vec<(u64, &str, Option<usize>)> = PDB
        .iter()
        .map(|&(entry, name, _)| (entry, name, parameters.get(&entry).copied()))
        .collect();
    let expected: Vec<(u64, &str, Option<usize>)> = PDB
        .iter()
        .map(|&(entry, name, count)| (entry, name, Some(count)))
        .collect();
    assert_eq!(found, expected);
}
