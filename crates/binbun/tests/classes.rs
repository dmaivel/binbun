#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! C++ classes from run-time type information, decompiled
//! (`tests/fixtures/classes.cpp`): the class table its virtual tables and
//! `type_info` objects give, and the structs and virtual calls it names.

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::classes::classes;
use binbun::decompile::Options;
use binbun_decompile::typing::Classes;
use binbun_loader::Image;

/// The fixture `name`'s bytes.
fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The index of the class named `name` in `classes`.
fn index(classes: &Classes, name: &str) -> usize {
    (0..classes.len())
        .find(|&index| classes.get(index).is_some_and(|class| class.name == name))
        .unwrap_or_else(|| panic!("no class {name}"))
}

/// Both compilers' images give the three classes; the derived ones have
/// their tables (the abstract base none: its constructor is inlined),
/// slots named by their methods' manglings, the base as their primary
/// base, and their join is the base; an override's `this` is its class.
#[test]
fn virtual_tables_and_type_info_give_the_classes() {
    for name in ["classes-gcc-x86_64.elf", "classes-clang-x86_64.elf"] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let classes = classes(&image);
        let shape = index(&classes, "Shape");
        let square = index(&classes, "Square");
        let rectangle = index(&classes, "Rectangle");
        assert_eq!(classes.len(), 3, "{name}");
        assert_eq!(classes.vtables(), 2, "{name}");
        assert!(classes.get(shape).unwrap().vtable.is_none(), "{name}");
        for derived in [square, rectangle] {
            let class = classes.get(derived).unwrap();
            assert_eq!(class.base, Some(shape), "{name}: {}", class.name);
            assert_eq!(class.slots.len(), 4, "{name}: {}", class.name);
            let names: Vec<Option<&str>> = (0..4).map(|k| classes.slot(derived, k)).collect();
            assert_eq!(
                names,
                [
                    Some("destructor"),
                    Some("deleting_destructor"),
                    Some("area"),
                    Some("name")
                ],
                "{name}: {}",
                class.name
            );
        }
        // The base takes the names its derived classes agree on.
        assert_eq!(classes.slot(shape, 3), Some("name"), "{name}");
        assert_eq!(classes.join(square, rectangle), Some(shape), "{name}");
        let area = image
            .symbols
            .iter()
            .find(|symbol| symbol.name == "_ZNK6Square4areaEv")
            .unwrap()
            .address;
        assert_eq!(classes.method(area), Some(square), "{name}");
    }
}

/// The C names the structs by class: `make` (which stores either derived
/// class's table) returns the base, `Square::area` takes `struct Square
/// *`, and `describe`'s virtual call reads its slot through the base's
/// table by the method's name.
#[test]
fn structs_and_virtual_calls_are_named_by_class() {
    let data = fixture("classes-clang-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    let text = |wanted: &str| {
        let id = database.find_function(wanted).unwrap();
        database
            .decompile(id, &options)
            .result
            .unwrap_or_else(|e| panic!("{wanted}: {e}"))
            .c
            .unwrap()
            .text
    };
    let make = text("make");
    assert!(make.contains("struct Shape *make("), "{make}");
    assert!(make.contains("->vptr = "), "{make}");
    let area = text("_ZNK6Square4areaEv");
    assert!(area.contains("(struct Square *a1)"), "{area}");
    let describe = text("describe");
    assert!(describe.contains("struct Shape_vtbl *vptr;"), "{describe}");
    assert!(describe.contains("a1->vptr->name"), "{describe}");
}
