//! The user's corrections of recovery as the commands make them from the
//! listing and the hex view ([`Op`]: `C`, `U`, `D`, `A`, `*`, `P`, Edit
//! Function, Delete Function): what each makes of the corrections there
//! are, from the item at the cursor ([`plan`]), or why it cannot apply
//! there. Over a selection `U` undefines its
//! items, `C` makes code from its start where the user's items there
//! give way, `D` makes data items of one width across it, `*` offers as
//! many units as it holds and `P` a function ending at its end. The
//! engine checks the result again against the program as recovered
//! ([`binbun_session::Session::set_corrections`]).

use binbun::Database;
use binbun::cfg::{SeedKind, SeedKinds};
use binbun::corrections::{Bounds, Corrections, Data, Item, Unit};
use binbun::listing::{Listing, Span, SpanKind};

/// The most data items `D` makes across a selection.
pub const MOST_ITEMS: u64 = 4096;

/// A correction, as a command makes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Code from the cursor (`C`).
    Code,
    /// The item at the cursor undefined (`U`).
    Undefine,
    /// Data at the cursor, its width cycled: byte, word, dword, qword
    /// (`D`).
    Data,
    /// A string at the cursor, C or UTF-16 by what the bytes are (`A`).
    String,
    /// An array of this many of the item's units at the cursor (`*`).
    Array(u64),
    /// A function from the cursor (`P`).
    Function,
    /// The function holding the cursor ending at this address (Edit
    /// Function).
    End(u64),
    /// The function holding the cursor deleted.
    Delete,
}

/// What a correction needs to know at the cursor.
#[derive(Clone, Copy, Debug)]
pub struct At<'a> {
    /// The listing.
    pub listing: &'a Listing,
    /// The database it was built from.
    pub database: &'a Database<'a>,
    /// The cursor's address (the selection's first byte, if there is
    /// one).
    pub address: u64,
    /// The bytes selected, if any: from `address` to the end (excluded).
    pub selection: Option<u64>,
}

/// The corrections `op` at the cursor makes of `corrections`, or why it
/// cannot apply there.
///
/// # Errors
///
/// The reason, for the palette.
pub fn plan(op: Op, at: At<'_>, corrections: &Corrections) -> Result<Corrections, &'static str> {
    let mut out = corrections.clone();
    if let Some(end) = at.selection
        && plan_range(op, at, end, &mut out)?
    {
        return Ok(out);
    }
    let image = at.database.image();
    let address = at.address;
    let span = span_at(at.listing, address);
    // Where an item made at the cursor starts: the item's start, or the
    // cursor in bytes nothing typed.
    let start = match span {
        Some(span) if span.kind != SpanKind::Unexplored => span.start,
        Some(_) | None => address,
    };
    match op {
        Op::Code | Op::Function => {
            if !image.is_code(address) {
                return Err("not in executable code");
            }
            if let Some(span) = span
                && matches!(span.kind, SpanKind::Instruction { .. })
            {
                if span.start != address {
                    return Err("inside an instruction");
                }
                if op == Op::Code {
                    return Err("already code");
                }
            }
            if op == Op::Code {
                out.set_item(address, Some(Item::Code));
            } else {
                if at.database.function_at(address).is_some() {
                    return Err("a function starts here already");
                }
                out.set_bounds(address, Some(Bounds::Function { end: None }));
            }
        }
        Op::Undefine => {
            let span = span
                .filter(|span| span.kind != SpanKind::Unexplored)
                .ok_or("nothing to undefine")?;
            out.set_item(
                span.start,
                Some(Item::Undefined {
                    size: span.end - span.start,
                }),
            );
        }
        Op::Data => {
            let unit = data_unit(span)?;
            out.set_item(start, Some(Item::Data(Data { unit, count: 1 })));
        }
        Op::String => {
            // As far as a referred-to literal is read: the palette asks at
            // every frame.
            const MOST: usize = 1 << 16;
            let bytes = image
                .segment(start)
                .and_then(|segment| {
                    segment
                        .bytes
                        .get(usize::try_from(start - segment.start).ok()?..)
                })
                .unwrap_or_default();
            let bytes = bytes.get(..bytes.len().min(MOST)).unwrap_or_default();
            let string = Data::string(start, bytes).ok_or("no string here")?;
            out.set_item(start, Some(Item::Data(string)));
        }
        Op::Array(count) => {
            if count == 0 {
                return Err("an array of no elements");
            }
            let unit = array_unit(span.map(|span| span.kind))?;
            out.set_item(start, Some(Item::Data(Data { unit, count })));
        }
        Op::End(end) => {
            let (_, entry) = at.listing.function_of(address).ok_or("not in a function")?;
            if end <= entry {
                return Err("not after the function's start");
            }
            out.set_bounds(entry, Some(Bounds::Function { end: Some(end) }));
        }
        Op::Delete => {
            let (id, entry) = at.listing.function_of(address).ok_or("not in a function")?;
            // A function only the user made goes with the user's word.
            let mut user = SeedKinds::default();
            user.insert(SeedKind::User);
            let only_users = at.database.function(id).is_some_and(|f| f.seeds == user);
            out.set_bounds(entry, (!only_users).then_some(Bounds::Deleted));
        }
    }
    Ok(out)
}

/// The item holding `address` in `listing`, if one does.
fn span_at(listing: &Listing, address: u64) -> Option<Span> {
    listing
        .spans(address..address.saturating_add(1))
        .into_iter()
        .find(|span| span.start <= address && address < span.end)
}

/// The unit `D` gives the item `span`: its width cycled (a byte's for
/// bytes nothing types or anything else).
fn data_unit(span: Option<Span>) -> Result<Unit, &'static str> {
    Ok(match span.map(|span| span.kind) {
        Some(SpanKind::Import) => return Err("an import's slot"),
        Some(SpanKind::Scalar { width } | SpanKind::Values { width }) => unit_of(width).cycled(),
        Some(SpanKind::Pointer { .. }) => Unit::Qword.cycled(),
        Some(_) | None => Unit::Byte,
    })
}

/// `op` over the bytes selected, from `at.address` to `end` (excluded),
/// into `out`, where it takes a range (`U`, `C`, `D`, `P`); whether it
/// did.
fn plan_range(op: Op, at: At<'_>, end: u64, out: &mut Corrections) -> Result<bool, &'static str> {
    let start = at.address;
    let last = end.saturating_sub(1).max(start);
    let first = span_at(at.listing, start);
    match op {
        Op::Undefine => {
            // From the first item's start to past the last's.
            let from = first.map_or(start, |s| s.start.min(start));
            let to = span_at(at.listing, last).map_or(end, |s| s.end.max(end));
            if first.is_some_and(|s| s.kind == SpanKind::Unexplored && s.end >= to) {
                return Err("nothing to undefine");
            }
            out.set_item(from, Some(Item::Undefined { size: to - from }));
        }
        Op::Code => {
            if !at.database.image().is_code(start) {
                return Err("not in executable code");
            }
            if let Some(span) = first
                && matches!(span.kind, SpanKind::Instruction { .. })
                && span.start != start
            {
                return Err("inside an instruction");
            }
            // The user's items there give way to the code decoded from the
            // start.
            let mut given: Vec<u64> = out.items().range(start..end).map(|(&a, _)| a).collect();
            given.extend(out.holding(start).map(|(a, _)| a));
            let already = first.is_some_and(|s| matches!(s.kind, SpanKind::Instruction { .. }));
            if already && given.is_empty() {
                return Err("already code");
            }
            for address in given {
                out.set_item(address, None);
            }
            if !already {
                out.set_item(start, Some(Item::Code));
            }
        }
        Op::Data => {
            let unit = data_unit(first)?;
            let width = unit.width();
            let count = ((end - start) / width).max(1);
            if count > MOST_ITEMS {
                return Err("more than 4096 items");
            }
            for k in 0..count {
                let item = Item::Data(Data { unit, count: 1 });
                out.set_item(start + k * width, Some(item));
            }
        }
        Op::Function => {
            if !at.database.image().is_code(start) {
                return Err("not in executable code");
            }
            if at.database.function_at(start).is_some() {
                return Err("a function starts here already");
            }
            out.set_bounds(start, Some(Bounds::Function { end: Some(end) }));
        }
        Op::String | Op::Array(_) | Op::End(_) | Op::Delete => return Ok(false),
    }
    Ok(true)
}

/// The unit of values `width` bytes wide (a byte's if no scalar is).
fn unit_of(width: u8) -> Unit {
    match width {
        2 => Unit::Word,
        4 => Unit::Dword,
        8 => Unit::Qword,
        _ => Unit::Byte,
    }
}

/// The unit an array made of an item of `kind` repeats.
fn array_unit(kind: Option<SpanKind>) -> Result<Unit, &'static str> {
    match kind {
        Some(SpanKind::Instruction { .. }) => Err("code"),
        Some(SpanKind::Import) => Err("an import's slot"),
        Some(SpanKind::Scalar { width } | SpanKind::Values { width }) => Ok(unit_of(width)),
        Some(SpanKind::Pointer { .. }) => Ok(Unit::Qword),
        Some(SpanKind::String { wide: true }) => Ok(Unit::Utf16),
        Some(SpanKind::String { wide: false }) => Ok(Unit::String),
        Some(
            SpanKind::Fill { .. }
            | SpanKind::Uninitialised
            | SpanKind::Align
            | SpanKind::Table
            | SpanKind::Unexplored,
        )
        | None => Ok(Unit::Byte),
    }
}

/// The count `*` offers at the cursor: the item's own if it is an array,
/// else as many of its units as fit before the next item that is not
/// bytes nothing typed (at least one); over a selection, as many as it
/// holds.
pub fn array_count(at: At<'_>) -> u64 {
    let address = at.address;
    let Some(span) = span_at(at.listing, address) else {
        return 1;
    };
    let Ok(unit) = array_unit(Some(span.kind)) else {
        return 1;
    };
    let width = unit.width();
    if let Some(end) = at.selection {
        return ((end - address) / width).max(1);
    }
    let start = if span.kind == SpanKind::Unexplored {
        address
    } else {
        span.start
    };
    if matches!(span.kind, SpanKind::Values { .. } | SpanKind::String { .. }) {
        return ((span.end - span.start) / width).max(1);
    }
    let limit = at
        .database
        .image()
        .segment(start)
        .map_or(span.end, binbun_loader::Segment::end);
    // Far enough for a table of thousands, cheap on any listing.
    let window = start..limit.min(start.saturating_add(0x10000));
    let next = at
        .listing
        .spans(window)
        .into_iter()
        .find(|s| {
            s.start > start
                && !matches!(
                    s.kind,
                    SpanKind::Unexplored | SpanKind::Fill { .. } | SpanKind::Align
                )
        })
        .map_or(limit, |s| s.start);
    ((next - start) / width).max(1)
}

/// The function holding the cursor and where it ends now (past its last
/// block from its entry): what Edit Function offers.
pub fn function_end(at: At<'_>) -> Option<(u64, u64)> {
    let (id, entry) = at.listing.function_of(at.address)?;
    let program = at.database.program();
    let end = at
        .database
        .function(id)?
        .blocks
        .iter()
        .filter_map(|&b| program.blocks.get(b))
        .filter(|b| b.start >= entry)
        .map(|b| b.end)
        .max()?;
    Some((entry, end))
}

#[cfg(test)]
mod tests {
    use binbun::analysis::Seeds;
    use binbun::listing::Options;
    use binbun_loader::Image;

    use super::*;

    /// Calls `f` with the fixture's database recovered with `corrections`
    /// and its listing.
    fn with(corrections: Corrections, f: impl FnOnce(&Database<'_>, &Listing)) {
        let path = format!(
            "{}/../../tests/fixtures/program-x86_64.elf",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = std::fs::read(path).unwrap();
        let image = Image::parse(&data).unwrap();
        let database = Database::with_corrections(&image, Seeds::ALL, None, corrections).unwrap();
        let listing = Listing::build(&database, &Options::default());
        f(&database, &listing);
    }

    fn at<'a>(database: &'a Database<'a>, listing: &'a Listing, address: u64) -> At<'a> {
        At {
            listing,
            database,
            address,
            selection: None,
        }
    }

    /// The bytes `start..end` selected.
    fn over<'a>(
        database: &'a Database<'a>,
        listing: &'a Listing,
        (start, end): (u64, u64),
    ) -> At<'a> {
        At {
            selection: Some(end),
            ..at(database, listing, start)
        }
    }

    fn data(unit: Unit, count: u64) -> Item {
        Item::Data(Data { unit, count })
    }

    #[test]
    fn d_cycles_a_scalars_width_and_types_bytes_as_a_byte() {
        let none = Corrections::default();
        let mut word = Corrections::default();
        word.set_item(0x2000, Some(data(Unit::Word, 1)));
        with(none.clone(), |db, l| {
            // `_IO_stdin_used`: a dword the symbol sizes.
            let planned = plan(Op::Data, at(db, l, 0x2002), &none).unwrap();
            assert_eq!(planned.item(0x2000), Some(data(Unit::Qword, 1)));
        });
        with(word.clone(), |db, l| {
            let planned = plan(Op::Data, at(db, l, 0x2001), &word).unwrap();
            assert_eq!(planned.item(0x2000), Some(data(Unit::Dword, 1)));
            assert_eq!(planned.items().len(), 1);
        });
    }

    #[test]
    fn u_undefines_the_whole_item_and_a_then_finds_the_string() {
        let none = Corrections::default();
        with(none.clone(), |db, l| {
            let undefined = plan(Op::Undefine, at(db, l, 0x2006), &none).unwrap();
            assert_eq!(undefined.item(0x2004), Some(Item::Undefined { size: 9 }));
            // On an instruction: its bytes.
            let code = plan(Op::Undefine, at(db, l, 0x11dd), &none).unwrap();
            assert_eq!(code.item(0x11dd), Some(Item::Undefined { size: 4 }));
        });
        let mut undefined = Corrections::default();
        undefined.set_item(0x2004, Some(Item::Undefined { size: 9 }));
        with(undefined.clone(), |db, l| {
            let string = plan(Op::String, at(db, l, 0x2004), &undefined).unwrap();
            assert_eq!(string.item(0x2004), Some(data(Unit::String, 9)));
            assert_eq!(
                plan(Op::String, at(db, l, 0x2000), &undefined),
                Err("no string here")
            );
        });
    }

    #[test]
    fn code_and_functions_are_refused_where_they_cannot_start() {
        let none = Corrections::default();
        with(none.clone(), |db, l| {
            assert_eq!(
                plan(Op::Code, at(db, l, 0x1191), &none),
                Err("inside an instruction")
            );
            assert_eq!(
                plan(Op::Code, at(db, l, 0x1190), &none),
                Err("already code")
            );
            assert_eq!(
                plan(Op::Code, at(db, l, 0x2004), &none),
                Err("not in executable code")
            );
            assert_eq!(
                plan(Op::Function, at(db, l, 0x1190), &none),
                Err("a function starts here already")
            );
            let made = plan(Op::Function, at(db, l, 0x11a3), &none).unwrap();
            assert_eq!(made.bounds(0x11a3), Some(Bounds::Function { end: None }));
            let code = plan(Op::Code, at(db, l, 0x11a3), &none).unwrap();
            assert_eq!(code.item(0x11a3), Some(Item::Code));
        });
    }

    #[test]
    fn edit_function_offers_its_end_and_delete_drops_the_users_function() {
        let none = Corrections::default();
        with(none.clone(), |db, l| {
            assert_eq!(function_end(at(db, l, 0x11d6)), Some((0x11d0, 0x11f0)));
            let ended = plan(Op::End(0x11e4), at(db, l, 0x11d6), &none).unwrap();
            assert_eq!(
                ended.bounds(0x11d0),
                Some(Bounds::Function { end: Some(0x11e4) })
            );
            assert_eq!(
                plan(Op::End(0x11c0), at(db, l, 0x11d6), &none),
                Err("not after the function's start")
            );
            let deleted = plan(Op::Delete, at(db, l, 0x1193), &none).unwrap();
            assert_eq!(deleted.bounds(0x1190), Some(Bounds::Deleted));
        });
        let mut made = Corrections::default();
        made.set_bounds(0x11a3, Some(Bounds::Function { end: None }));
        with(made.clone(), |db, l| {
            let deleted = plan(Op::Delete, at(db, l, 0x11a3), &made).unwrap();
            assert!(deleted.is_empty());
        });
    }

    #[test]
    fn star_offers_the_units_up_to_the_next_item() {
        let mut undefined = Corrections::default();
        undefined.set_item(0x2000, Some(Item::Undefined { size: 4 }));
        with(undefined.clone(), |db, l| {
            // Bytes nothing types up to the string at 0x2004.
            assert_eq!(array_count(at(db, l, 0x2000)), 4);
            let array = plan(Op::Array(4), at(db, l, 0x2000), &undefined).unwrap();
            assert_eq!(array.item(0x2000), Some(data(Unit::Byte, 4)));
            assert_eq!(array.items().len(), 1);
            assert_eq!(
                plan(Op::Array(0), at(db, l, 0x2000), &undefined),
                Err("an array of no elements")
            );
            assert_eq!(
                plan(Op::Array(2), at(db, l, 0x1190), &undefined),
                Err("code")
            );
        });
    }

    #[test]
    fn u_over_a_selection_undefines_from_its_first_items_start_to_its_last_items_end() {
        let none = Corrections::default();
        with(none.clone(), |db, l| {
            // Into the dword at 0x2000, out of the string at 0x2004.
            let planned = plan(Op::Undefine, over(db, l, (0x2002, 0x2006)), &none).unwrap();
            assert_eq!(planned.item(0x2000), Some(Item::Undefined { size: 0xd }));
            assert_eq!(planned.items().len(), 1);
            // Part of one instruction: the whole of it.
            let planned = plan(Op::Undefine, over(db, l, (0x11dd, 0x11df)), &none).unwrap();
            assert_eq!(planned.item(0x11dd), Some(Item::Undefined { size: 4 }));
        });
    }

    #[test]
    fn d_over_a_selection_makes_items_of_one_width_across_it_and_star_counts_it() {
        let mut undefined = Corrections::default();
        undefined.set_item(0x2000, Some(Item::Undefined { size: 4 }));
        with(undefined.clone(), |db, l| {
            let bytes = plan(Op::Data, over(db, l, (0x2000, 0x2004)), &undefined).unwrap();
            let items: Vec<(u64, Item)> = bytes.items().iter().map(|(&a, &i)| (a, i)).collect();
            let byte = data(Unit::Byte, 1);
            assert_eq!(
                items,
                [
                    (0x2000, byte),
                    (0x2001, byte),
                    (0x2002, byte),
                    (0x2003, byte)
                ]
            );
            assert_eq!(
                plan(
                    Op::Data,
                    over(db, l, (0x2000, 0x2000 + MOST_ITEMS + 1)),
                    &undefined
                ),
                Err("more than 4096 items")
            );
            // `*` offers what the selection holds, not what fits.
            assert_eq!(array_count(at(db, l, 0x2000)), 4);
            assert_eq!(array_count(over(db, l, (0x2000, 0x2003))), 3);
        });
        let mut bytes = Corrections::default();
        bytes.set_item(0x2000, Some(data(Unit::Byte, 1)));
        bytes.set_item(0x2001, Some(data(Unit::Byte, 1)));
        with(bytes.clone(), |db, l| {
            // `D` again: the next width, from the first item's.
            let words = plan(Op::Data, over(db, l, (0x2000, 0x2004)), &bytes).unwrap();
            assert_eq!(words.item(0x2000), Some(data(Unit::Word, 1)));
            assert_eq!(words.item(0x2002), Some(data(Unit::Word, 1)));
            assert_eq!(words.items().len(), 2);
        });
    }

    #[test]
    fn c_over_a_selection_clears_the_users_items_in_it_and_p_ends_at_its_end() {
        let mut undefined = Corrections::default();
        undefined.set_item(0x11a8, Some(Item::Undefined { size: 2 }));
        with(undefined.clone(), |db, l| {
            // From bytes nothing types (0x11a5): code there, the user's
            // item in the selection gone.
            let code = plan(Op::Code, over(db, l, (0x11a5, 0x11b0)), &undefined).unwrap();
            assert_eq!(code.item(0x11a5), Some(Item::Code));
            assert_eq!(code.items().len(), 1);
            // From an instruction (0x11a3): only the user's item goes.
            let code = plan(Op::Code, over(db, l, (0x11a3, 0x11b0)), &undefined).unwrap();
            assert!(code.is_empty());
            assert_eq!(
                plan(
                    Op::Code,
                    over(db, l, (0x1190, 0x11a0)),
                    &Corrections::default()
                ),
                Err("already code")
            );
            assert_eq!(
                plan(Op::Code, over(db, l, (0x1191, 0x11a0)), &undefined),
                Err("inside an instruction")
            );
            assert_eq!(
                plan(Op::Code, over(db, l, (0x2000, 0x2004)), &undefined),
                Err("not in executable code")
            );
            let made = plan(Op::Function, over(db, l, (0x11a3, 0x11c0)), &undefined).unwrap();
            assert_eq!(
                made.bounds(0x11a3),
                Some(Bounds::Function { end: Some(0x11c0) })
            );
        });
    }
}
