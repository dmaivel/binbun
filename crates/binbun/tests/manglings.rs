#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Prototypes from manglings, decompiled (`tests/fixtures/mangled-aarch64.s`):
//! a pointer to a class is declared only a pointer, so the accesses
//! through it give its target (a synthesised struct with the field
//! accessed); a declared `void *` stays one.

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::Options;
use binbun_ast::types::{Evidence, Type};
use binbun_loader::Image;

/// The offset and width of a struct's last field.
type Last = Option<(u64, u16)>;

/// The first parameter of each function of the fixture named in `names`,
/// as decompiled: its type, the offset and width of the last field of the
/// struct it points to (if a pointer to a struct), and its evidence.
fn first_parameters(names: &[&str]) -> Vec<(Type, Last, Evidence)> {
    let path = format!(
        "{}/../../tests/fixtures/mangled-aarch64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let options = Options {
        style: None,
        ..Options::default()
    };
    names
        .iter()
        .map(|&name| {
            let id = database.find_function(name).unwrap();
            let l2 = database
                .decompile(id, &options)
                .result
                .unwrap_or_else(|e| panic!("{name}: {e}"))
                .l2;
            let variable = l2.var(l2.parameters[0]).unwrap();
            let ty = l2.types.get(variable.ty).unwrap().clone();
            let mut target = None;
            if let Type::Pointer(Some(pointee)) = ty
                && let Some(Type::Struct(aggregate)) = l2.types.get(pointee)
                && let Some(field) = aggregate.fields.last()
            {
                target = Some((field.offset, l2.types.value_width(field.ty).unwrap_or(0)));
            }
            (ty, target, variable.evidence)
        })
        .collect()
}

#[test]
fn a_pointer_to_a_class_takes_the_target_its_accesses_give() {
    let found = first_parameters(&["_Z6secondP4Node", "_ZNK4Node4sizeEv", "_Z6secondPv"]);
    // second(Node *): the load of 8 bytes at offset 8.
    assert!(
        matches!(
            found[0],
            (
                Type::Pointer(Some(_)),
                Some((8, 64)),
                Evidence::DeclaredPointer
            )
        ),
        "second(Node *): {:?}",
        found[0]
    );
    // Node::size() const: `this`, the load of 4 bytes at offset 4.
    assert!(
        matches!(
            found[1],
            (
                Type::Pointer(Some(_)),
                Some((4, 32)),
                Evidence::DeclaredPointer
            )
        ),
        "Node::size() const: {:?}",
        found[1]
    );
    // second(void *): declared `void *`, whatever the accesses.
    assert_eq!(
        found[2],
        (Type::Pointer(None), None, Evidence::Declared),
        "second(void *)"
    );
}
