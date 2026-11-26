#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The scorer on a fixture whose source is known (`program.c`), the
//! lattice's distances, and struct identities split and merged.

use std::path::PathBuf;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun_cli::score::{Class, Setup, Shape, Tally, conservative, distance, score};
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

/// `loop_sum`'s `sum` and `i` live in registers (`rbx`, `r12` across the
/// loop, by the DWARF's location lists), not on the stack: each maps to
/// the L2 local held in its register where the loop reads and assigns it,
/// one apiece, and both are 32-bit there (not the 64-bit locals held in
/// the same registers).
#[test]
fn register_locals_map_by_register_and_address() {
    let data = fixture("program-x86_64.elf");
    let model = binbun_debuginfo::info::read(&fixture("program-x86_64.debug"), &data).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let report = score(&database, &model, &Setup::new(&database)).unwrap();
    assert_eq!((report.registers.truth, report.registers.mapped), (2, 2));
    assert_eq!(report.register_shared, 0);
    assert_eq!(report.unmapped_locals, 0);
    let scores = &report.register_scores;
    assert_eq!((scores.mapped, scores.width), (2, 2));
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

/// Pointers to the source's `list` the decompiler types as pointers to
/// its `struct_a_1` and `struct_b_1` split `list`; `struct_b_1` also for
/// the source's `node` merges the two; a pointer to `node` typed `void *`
/// is neither.
#[test]
fn identities_split_and_merged() {
    let to = |name: &str| Shape {
        class: Class::Pointer,
        bytes: Some(8),
        target: Some(Box::new(Shape {
            class: Class::Struct,
            bytes: Some(16),
            target: None,
            identity: Some((name.to_owned(), 16)),
        })),
        identity: None,
    };
    let void = Shape {
        class: Class::Pointer,
        bytes: Some(8),
        target: None,
        identity: None,
    };
    let mut tally = Tally::default();
    for (inferred, truth) in [
        (to("struct_a_1"), to("list")),
        (to("struct_a_1"), to("list")),
        (to("struct_b_1"), to("list")),
        (to("struct_b_1"), to("node")),
        (void, to("node")),
    ] {
        tally.add(&inferred, &truth);
    }
    let errors = tally.identity_errors();
    assert_eq!((errors.sources, errors.decompiler), (2, 2));
    assert_eq!(
        errors.split,
        [(
            "list".to_owned(),
            vec!["struct_a_1".to_owned(), "struct_b_1".to_owned()]
        )]
    );
    assert_eq!(
        errors.merged,
        [(
            "struct_b_1".to_owned(),
            vec!["list".to_owned(), "node".to_owned()]
        )]
    );
    // Pairs: three pointers to `list` make three pairs, one of them (the
    // two `struct_a_1`s) under one name; two `struct_a_1`s and two
    // `struct_b_1`s make two pairs under one name, one of them (the
    // `struct_a_1`s) to one source struct.
    assert_eq!(
        (errors.same_source, errors.same_name, errors.both),
        (3, 2, 1)
    );
    // Five pointers to a named struct, four typed as one of the
    // decompiler's (the `void *` one not).
    assert_eq!((errors.named, errors.pointers), (4, 5));
}

/// A pointer to `lua_State` where a translation unit only declares it
/// (size 0) points to the one `lua_State` defined: two pointers the
/// decompiler types alike are one struct's, not a merge of two.
#[test]
fn a_declared_struct_is_its_definition() {
    let to = |name: &str, bytes: u64| Shape {
        class: Class::Pointer,
        bytes: Some(8),
        target: Some(Box::new(Shape {
            class: Class::Struct,
            bytes: Some(bytes),
            target: None,
            identity: Some((name.to_owned(), bytes)),
        })),
        identity: None,
    };
    let mut tally = Tally::default();
    tally.add(&to("struct_a_1", 8), &to("lua_State", 208));
    tally.add(&to("struct_a_1", 8), &to("lua_State", 0));
    let errors = tally.identity_errors();
    assert_eq!(errors.merged, []);
    assert_eq!(
        (
            errors.sources,
            errors.same_source,
            errors.same_name,
            errors.both
        ),
        (1, 1, 1, 1)
    );
}

/// A struct no translation unit defines (an opaque handle the library
/// casts to its own struct: `sqlite3_stmt` to `Vdbe`) judges no pair: its
/// pointers under the decompiler's name for `Vdbe` are not a merge.
#[test]
fn a_struct_no_unit_defines_is_left_out_of_the_pairs() {
    let to = |name: &str, bytes: u64| Shape {
        class: Class::Pointer,
        bytes: Some(8),
        target: Some(Box::new(Shape {
            class: Class::Struct,
            bytes: Some(bytes),
            target: None,
            identity: Some((name.to_owned(), bytes)),
        })),
        identity: None,
    };
    let mut tally = Tally::default();
    tally.add(&to("struct_v_1", 8), &to("Vdbe", 304));
    tally.add(&to("struct_v_1", 8), &to("Vdbe", 304));
    tally.add(&to("struct_v_1", 8), &to("sqlite3_stmt", 0));
    let errors = tally.identity_errors();
    assert_eq!(errors.merged, []);
    assert_eq!(
        (errors.sources, errors.same_name, errors.both, errors.opaque),
        (1, 1, 1, 1)
    );
    assert_eq!((errors.named, errors.pointers), (3, 3));
}
