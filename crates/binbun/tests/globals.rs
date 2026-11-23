//! A global's one type over the program and the references into each of
//! its fields (`Database::global_type`, `Database::global_fields`), on
//! `tests/fixtures/globals-x86_64.s`: a 24-byte global one function writes
//! field by field and others read, one of them with a load spanning two
//! fields; and on `tests/fixtures/pointers-x86_64.s`, globals holding an
//! array's address read through an index: a pointer to the pointers it
//! holds where they are pointers, one element apart (an offset computed
//! apart too, where it is a multiple of one).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::analysis::Seeds;
use binbun::{Database, GlobalField};
use binbun_ast::types::Type;
use binbun_decompile::typing::{FieldType, GlobalShape, GlobalSource};
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The address of symbol `name`.
fn symbol(database: &Database<'_>, name: &str) -> u64 {
    database
        .names()
        .iter()
        .find(|(_, n)| *n == name)
        .map_or_else(|| panic!("no symbol {name}"), |(&address, _)| address)
}

/// `record` is the struct `fill` shows (4-byte fields at 0 and 4, 8-byte
/// fields at 8 and 16), asked for at any of its bytes; each field counts
/// the references starting in it: `fill`'s store, `second`'s read at 4,
/// `last`'s two reads at 16, and `pair`'s 16-byte load at 8, which spans
/// the fields at 8 and 16 and counts only for the one it starts in.
#[test]
fn a_global_s_fields_count_the_references_starting_in_them() {
    let data = fixture("globals-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let record = symbol(&database, "record");

    let ty = database.global_type(record + 13).unwrap();
    assert_eq!((ty.start, ty.size, ty.named), (record, 24, true));
    assert!(matches!(ty.shape, GlobalShape::Struct(_)), "{:?}", ty.shape);
    assert_eq!(ty.source, GlobalSource::Table);

    let callers = database.callers(&[]);
    let fields = database.global_fields(&callers, &ty);
    let fields: Vec<(u64, u64, &str, usize)> = fields
        .iter()
        .map(|field| {
            let GlobalField {
                offset,
                bytes,
                name,
                references,
            } = field;
            (*offset, *bytes, name.as_str(), *references)
        })
        .collect();
    assert_eq!(
        fields,
        [
            (0, 4, "field_0", 1),
            (4, 4, "field_4", 2),
            (8, 8, "field_8", 2),
            (0x10, 8, "field_10", 3),
        ]
    );

    // Its last byte is in it; the next is the object after it (`copy`).
    assert_eq!(database.global_start(record + 23), record);
    assert_eq!(
        database.global_start(record + 24),
        symbol(&database, "copy")
    );
}

/// `names[i][0]` makes `names` a pointer to pointers to bytes, which C
/// indexes, as `stack[n - 1][0] + stack[n - 2][0]` does `stack`, though
/// the offset of `stack[n - 1]` is computed apart (`n * 8 - 8`, added
/// scaled by 1) and `stack[n - 2]` is 8 bytes below it; `pairs + 16·i`
/// read 8 bytes at a time is the first field of 16-byte elements,
/// `counts`' elements are written integers, `odd` is read 4 bytes past a
/// multiple of 8 and `skewed` at an element and 4 bytes past it: none is
/// one.
#[test]
fn a_global_indexed_as_an_array_of_pointers_points_to_them() {
    let data = fixture("pointers-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let shape = |name: &str| database.global_type(symbol(&database, name)).unwrap().shape;
    for name in ["names", "stack"] {
        assert_eq!(
            shape(name),
            GlobalShape::Value(FieldType::ScalarPointers(Some(Type::UInt(8)))),
            "{name}"
        );
    }
    for name in ["pairs", "counts", "odd", "skewed"] {
        assert!(
            !matches!(
                shape(name),
                GlobalShape::Value(FieldType::ScalarPointers(_) | FieldType::Pointers(_))
            ),
            "{name}: {:?}",
            shape(name)
        );
    }
}
