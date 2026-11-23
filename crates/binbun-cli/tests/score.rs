#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The scorer on a fixture whose source is known (`program.c`), and the
//! lattice's distances.

use std::path::PathBuf;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun_cli::score::{Class, Setup, Shape, conservative, distance, score};
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name),
    )
    .unwrap()
}

/// `classify(int)`, `checked(int)`, `loop_sum(int)`, `fail(const char *)`
/// and `main(int, char **)`: every parameter the code reads maps to the L2
/// parameter in its register (`main`'s `argv` is never read, so L2 has no
/// parameter for it), and `fail` is the one returning nothing.
#[test]
fn program_parameters_map_by_register() {
    let data = fixture("program-x86_64.elf");
    let model = binbun_debuginfo::info::read(&fixture("program-x86_64.debug"), &data).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let report = score(&database, &model, &Setup::new(&database)).unwrap();
    assert_eq!((report.debug_functions, report.decompiled), (5, 5));
    assert_eq!(
        (
            report.parameters.truth,
            report.parameters.mapped,
            report.parameters.extra
        ),
        (6, 5, 0)
    );
    assert_eq!(report.by_location, 5);
    assert_eq!(
        (report.void_agree, report.void_missed, report.void_extra),
        (1, 0, 0)
    );
    // `fail`'s `message` is a pointer in both.
    assert_eq!(
        report.parameter_scores.confusion[&(Class::Pointer, Class::Pointer)],
        1
    );
}

/// `stacked-x86_64.elf` is `tests/fixtures/stacked.c`: `seventh` takes
/// its seventh parameter on the stack, which the DWARF states at the
/// canonical frame address, the L2 parameter's slot at the entry stack
/// pointer + 8: it maps there, not as an extra parameter (`main`'s `argv`
/// is never read, so L2 has no parameter for it).
#[test]
fn a_stack_parameter_maps_by_its_slot() {
    let data = fixture("stacked-x86_64.elf");
    let model = binbun_debuginfo::info::read(&fixture("stacked-x86_64.debug"), &data).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let report = score(&database, &model, &Setup::new(&database)).unwrap();
    assert_eq!(
        (
            report.parameters.truth,
            report.parameters.mapped,
            report.parameters.extra
        ),
        (9, 8, 0)
    );
}

#[test]
fn lattice_distances() {
    let shape = |class, bytes| Shape {
        class,
        bytes: Some(bytes),
        target: None,
        identity: None,
    };
    let int = shape(Class::Signed, 4);
    // bits(32) is int(32)'s grandparent: two edges, and conservative.
    assert_eq!(distance(&shape(Class::Bits, 4), &int), 2);
    assert!(conservative(&shape(Class::Bits, 4), &int));
    // int and uint meet at num: siblings.
    assert_eq!(distance(&shape(Class::Unsigned, 4), &int), 2);
    assert!(!conservative(&shape(Class::Unsigned, 4), &int));
    // int and float meet at bits: three edges.
    assert_eq!(distance(&shape(Class::Float, 4), &int), 3);
    // Another width meets only at the top.
    assert_eq!(distance(&shape(Class::Bits, 8), &int), 4);
    assert!(!conservative(&shape(Class::Bits, 8), &int));
    // A pointer to an int is below `void *`.
    let pointer = Shape {
        target: Some(Box::new(int)),
        ..shape(Class::Pointer, 8)
    };
    assert_eq!(distance(&shape(Class::Pointer, 8), &pointer), 1);
    assert!(conservative(&shape(Class::Pointer, 8), &pointer));
}
