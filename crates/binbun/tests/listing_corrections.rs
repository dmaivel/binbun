//! The user's corrections ([`binbun::corrections`]) on a fixture: what
//! recovery, the listing and the C make of each, and what is refused.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::cfg::Exit;
use binbun::corrections::{Bounds, Corrections, Data, Item, Unit};
use binbun::decompile::Options as DecompileOptions;
use binbun::listing::{Listing, Options, Span, SpanKind};
use binbun_loader::Image;

fn fixture() -> Vec<u8> {
    fixture_named("program-x86_64.elf")
}

fn fixture_named(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Calls `f` with the database recovered with `corrections` and its
/// listing.
fn with(corrections: Corrections, f: impl FnOnce(&Database<'_>, &Listing)) {
    with_on(&fixture(), corrections, f);
}

/// [`with`] on the file `data`.
fn with_on(data: &[u8], corrections: Corrections, f: impl FnOnce(&Database<'_>, &Listing)) {
    let image = Image::parse(data).unwrap();
    let db = Database::with_corrections(&image, Seeds::ALL, None, corrections).unwrap();
    let listing = Listing::build(&db, &Options::default());
    f(&db, &listing);
}

fn item(address: u64, item: Item) -> Corrections {
    let mut c = Corrections::default();
    c.set_item(address, Some(item));
    c
}

fn bounds(entry: u64, bounds: Bounds) -> Corrections {
    let mut c = Corrections::default();
    c.set_bounds(entry, Some(bounds));
    c
}

/// The first item with a byte at `address`.
fn span(listing: &Listing, address: u64) -> Span {
    listing.spans(address..address + 1)[0]
}

/// The text of the content line of the item at `address`.
fn text(db: &Database<'_>, listing: &Listing, address: u64) -> String {
    listing.render(db, listing.line_of(address)).text()
}

/// The C of the function at `entry`.
fn c(db: &Database<'_>, entry: u64) -> String {
    let options = DecompileOptions {
        style: Some("kr".to_owned()),
        ..DecompileOptions::default()
    };
    let output = db.decompile(db.function_at(entry).unwrap(), &options);
    output.result.unwrap().c.unwrap().text
}

#[test]
fn without_corrections_the_listing_is_the_same() {
    let data = fixture();
    let image = Image::parse(&data).unwrap();
    let plain = Database::new(&image, Seeds::ALL).unwrap();
    let corrected =
        Database::with_corrections(&image, Seeds::ALL, None, Corrections::default()).unwrap();
    let (a, b) = (
        Listing::build(&plain, &Options::default()),
        Listing::build(&corrected, &Options::default()),
    );
    assert_eq!(a.len(), b.len());
    for n in 0..a.len() {
        assert_eq!(a.render(&plain, n), b.render(&corrected, n), "line {n}");
    }
}

#[test]
fn code_made_in_padding_is_decoded_and_followed() {
    with(Corrections::default(), |_, listing| {
        assert_eq!(span(listing, 0x11a3).kind, SpanKind::Align);
    });
    with(item(0x11a3, Item::Code), |db, listing| {
        assert_eq!(
            span(listing, 0x11a3),
            Span {
                start: 0x11a3,
                end: 0x11a5,
                kind: SpanKind::Instruction { function: false }
            }
        );
        // Followed: the next instruction is recovered too, and no
        // function is made.
        assert!(db.program().block_containing(0x11a5).is_some());
        assert!(db.function_at(0x11a3).is_none());
    });
}

#[test]
fn a_function_made_has_its_header_and_its_c() {
    with(
        bounds(0x11a3, Bounds::Function { end: None }),
        |db, listing| {
            assert!(db.function_at(0x11a3).is_some());
            assert_eq!(
                span(listing, 0x11a3).kind,
                SpanKind::Instruction { function: true }
            );
            let header = listing.render(db, listing.line_of(0x11a3) - 1).text();
            assert!(header.contains("sub_11A3"), "{header}");
            // It falls into `fail`, which it tail-calls.
            let c = c(db, 0x11a3);
            assert!(c.contains("sub_11a3") && c.contains("fail("), "{c}");
        },
    );
}

#[test]
fn data_is_typed_by_width_and_as_an_array() {
    let word = Data {
        unit: Unit::Word,
        count: 1,
    };
    with(item(0x2000, Item::Data(word)), |db, listing| {
        assert_eq!(
            span(listing, 0x2000),
            Span {
                start: 0x2000,
                end: 0x2002,
                kind: SpanKind::Scalar { width: 2 }
            }
        );
        assert!(text(db, listing, 0x2000).contains("dw 1"));
    });
    let array = Data {
        unit: Unit::Word,
        count: 2,
    };
    with(item(0x2000, Item::Data(array)), |db, listing| {
        assert_eq!(
            span(listing, 0x2000),
            Span {
                start: 0x2000,
                end: 0x2004,
                kind: SpanKind::Values { width: 2 }
            }
        );
        let line = text(db, listing, 0x2000);
        assert!(line.contains("dw 1, 2"), "{line}");
    });
}

#[test]
fn an_array_is_named_by_its_unit_as_ida_names_it() {
    let array = |unit, count| Item::Data(Data { unit, count });
    // `qword_3FF0`, a GOT slot code reads, made an array: named by the
    // array's unit.
    with(Corrections::default(), |_, listing| {
        assert_eq!(listing.name(0x3ff0), Some("qword_3FF0"));
    });
    for (unit, count, name) in [
        (Unit::Dword, 4, "dword_3FF0"),
        (Unit::Byte, 16, "byte_3FF0"),
        (Unit::Word, 8, "word_3FF0"),
    ] {
        with(item(0x3ff0, array(unit, count)), |_, listing| {
            assert!(matches!(
                span(listing, 0x3ff0).kind,
                SpanKind::Values { .. }
            ));
            assert_eq!(listing.name(0x3ff0), Some(name));
        });
    }
    // Past the file's bytes (`.bss`): `record + 8`, which `fill` writes,
    // made an array of two qwords.
    let globals = fixture_named("globals-x86_64.elf");
    with_on(
        &globals,
        item(0x0020_21d8, array(Unit::Qword, 2)),
        |_, listing| {
            assert_eq!(span(listing, 0x0020_21d8).kind, SpanKind::Uninitialised);
            assert_eq!(listing.name(0x0020_21d8), Some("qword_2021D8"));
        },
    );
}

#[test]
fn a_string_undefined_is_bytes_and_made_again_is_a_string() {
    with(Corrections::default(), |_, listing| {
        assert_eq!(span(listing, 0x2004).kind, SpanKind::String { wide: false });
    });
    with(item(0x2004, Item::Undefined { size: 9 }), |db, listing| {
        let spans = listing.spans(0x2004..0x200d);
        assert!(
            spans
                .iter()
                .all(|s| !matches!(s.kind, SpanKind::String { .. })),
            "{spans:?}"
        );
        assert!(!text(db, listing, 0x2004).contains("negative"));
    });
    // `.rodata` is at its own address in the file.
    let data = fixture();
    let string = Data::string(0x2004, &data[0x2004..0x2011]).unwrap();
    assert_eq!(
        string,
        Data {
            unit: Unit::String,
            count: 9
        }
    );
    // A string where the bytes were undefined first.
    let mut c = item(0x2004, Item::Undefined { size: 9 });
    c.set_item(0x2004, Some(Item::Data(string)));
    with(c, |db, listing| {
        assert_eq!(
            span(listing, 0x2004),
            Span {
                start: 0x2004,
                end: 0x200d,
                kind: SpanKind::String { wide: false }
            }
        );
        assert_eq!(listing.name(0x2004), Some("aNegative"));
        assert!(text(db, listing, 0x2004).contains("'negative',0"));
    });
}

#[test]
fn an_instruction_undefined_ends_the_code_that_reaches_it() {
    with(item(0x11dd, Item::Undefined { size: 4 }), |db, listing| {
        let program = db.program();
        // The call's fallthrough decodes nothing there.
        let block = program.blocks[program.block_at(0x11dd).unwrap()];
        assert_eq!(
            (block.end, block.instructions, block.exit),
            (0x11dd, 0, Exit::Invalid)
        );
        assert!(!matches!(
            span(listing, 0x11dd).kind,
            SpanKind::Instruction { .. }
        ));
        // What only it led to is no function's code any more.
        assert_eq!(
            span(listing, 0x11e1).kind,
            SpanKind::Instruction { function: false }
        );
    });
}

#[test]
fn an_end_set_makes_what_follows_a_function_of_its_own() {
    with(
        bounds(0x11d0, Bounds::Function { end: Some(0x11e4) }),
        |db, listing| {
            let checked = db.function(db.function_at(0x11d0).unwrap()).unwrap();
            assert!(
                checked
                    .blocks
                    .iter()
                    .all(|&b| db.program().blocks[b].end <= 0x11e4)
            );
            assert!(db.function_at(0x11e4).is_some());
            assert_eq!(listing.function_of(0x11e4).map(|(_, e)| e), Some(0x11e4));
            // Its C calls the part split off.
            assert!(c(db, 0x11d0).contains("sub_11e4("));
        },
    );
}

#[test]
fn a_deleted_function_keeps_its_code_and_its_callers() {
    with(bounds(0x1190, Bounds::Deleted), |db, listing| {
        assert!(db.function_at(0x1190).is_none());
        assert_eq!(
            span(listing, 0x1190).kind,
            SpanKind::Instruction { function: false }
        );
        assert!(c(db, 0x11d0).contains("classify("));
    });
}

#[test]
fn corrections_that_cannot_apply_are_refused_with_the_reason() {
    with(Corrections::default(), |db, _| {
        assert_eq!(
            db.check_item(0x1191, Item::Code),
            Err("0x1191 is inside the instruction at 0x1190".to_owned())
        );
        assert_eq!(
            db.check_item(0x2004, Item::Code),
            Err("0x2004 is not in executable code".to_owned())
        );
        assert_eq!(
            db.check_bounds(0x11d0, Bounds::Function { end: Some(0x1200) }),
            Err("it would overlap the function at 0x11f0".to_owned())
        );
        assert_eq!(
            db.check_bounds(0x11d0, Bounds::Function { end: Some(0x11d5) }),
            Err("its end 0x11d5 is inside the instruction at 0x11d4".to_owned())
        );
        assert_eq!(
            db.check_bounds(0x11d4, Bounds::Deleted),
            Err("no function starts at 0x11d4".to_owned())
        );
        assert_eq!(db.check_item(0x11a3, Item::Code), Ok(()));
        assert_eq!(
            db.check_bounds(0x11d0, Bounds::Function { end: Some(0x11e4) }),
            Ok(())
        );
    });
}
