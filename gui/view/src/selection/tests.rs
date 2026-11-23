use std::collections::BTreeMap;

use binbun::analysis::Seeds;
use binbun::cfg::FunctionId;
use binbun::corrections::Corrections;
use binbun::listing::Options;
use binbun_ast::ir::{Function as Ast, Node, VarId};
use binbun_ast::types::Types;
use binbun_loader::Image;
use binbun_print::document::TokenKind;
use binbun_semantics::core::Id as _;
use binbun_session::View;
use binbun_ssa::ir::Function as L1;

use super::*;
use crate::cdoc::CSpan;

/// `int64_t v1;` / `  v1 = v1 + a2;` / `return;`: the first line made
/// from 0x10, the second from 0x20 and 0x30, the last from 0x30 and 0x40.
fn document() -> CDocument {
    let text = "int64_t v1;\n  v1 = v1 + a2;\nreturn;".to_owned();
    let v1 = Some(Node::Var(VarId(0)));
    let spans = [
        (0..7, TokenKind::BuiltinType, None),
        (8..10, TokenKind::Local, v1),
        (10..11, TokenKind::Punctuation, None),
        (14..16, TokenKind::Local, v1),
        (17..18, TokenKind::Operator, None),
        (19..21, TokenKind::Local, v1),
        (22..23, TokenKind::Operator, None),
        (24..26, TokenKind::Parameter, Some(Node::Var(VarId(1)))),
        (26..27, TokenKind::Punctuation, None),
        (28..34, TokenKind::ControlKeyword, None),
        (34..35, TokenKind::Punctuation, None),
    ]
    .into_iter()
    .map(|(range, kind, node)| CSpan {
        range,
        kind,
        node,
        automatic: true,
        cast: false,
    })
    .collect();
    let l2 = Ast::new(0, Types::new(64));
    let mut doc = CDocument::from_parts(
        FunctionId::from_raw(0),
        0,
        View::Reading,
        text,
        spans,
        BTreeMap::new(),
        &l2,
        &L1::default(),
    );
    doc.lines[0].addresses = vec![0x10];
    doc.lines[1].addresses = vec![0x20, 0x30];
    doc.lines[2].addresses = vec![0x30, 0x40];
    doc
}

#[test]
fn a_drag_selects_lines_once_it_leaves_the_line_pressed() {
    let mut s = Lines::default();
    s.press(10, 3, false);
    // Still on the line pressed: a click, nothing selected.
    assert!(!s.drag(10));
    assert_eq!(s.range(10), None);
    // Up: the lines in order whichever way it goes.
    assert!(s.drag(7));
    assert_eq!(s.range(7), Some(7..=10));
    // Back on the line pressed: that line.
    assert!(s.drag(10));
    assert_eq!(s.range(10), Some(10..=10));
    s.release();
    // Released: moving the pointer selects nothing more.
    assert!(!s.drag(12));
    assert_eq!(s.range(10), Some(10..=10));
    // A plain click elsewhere drops it.
    s.press(20, 10, false);
    assert_eq!(s.range(20), None);
}

#[test]
fn shift_extends_lines_from_the_cursor_and_a_plain_move_or_escape_drops_them() {
    let mut s = Lines::default();
    // Shift+Down twice from line 5.
    let mut cursor = 5;
    for _ in 0..2 {
        s.leave(cursor, true);
        cursor += 1;
    }
    assert_eq!(s.range(cursor), Some(5..=7));
    // Shift+Up past the anchor: the selection turns over it.
    for _ in 0..4 {
        s.leave(cursor, true);
        cursor -= 1;
    }
    assert_eq!(s.range(cursor), Some(3..=5));
    // Shift+click: from the same anchor; a drag from there goes on.
    s.press(9, cursor, true);
    assert_eq!(s.range(9), Some(5..=9));
    assert!(s.drag(11));
    assert_eq!(s.range(11), Some(5..=11));
    s.release();
    // A move without Shift drops it.
    s.leave(11, false);
    assert_eq!(s.range(12), None);
    // Escape: whether there was one to drop.
    s.leave(12, true);
    assert!(s.clear());
    assert!(!s.clear());
    assert_eq!(s.range(12), None);
}

#[test]
fn characters_select_from_the_press_and_an_empty_selection_goes_on_release() {
    let mut s = Text::default();
    let at = TextPos::new;
    // A click: nothing selected, and after the release a cursor moved by
    // the sync group selects nothing.
    s.press(at(1, 4), at(0, 0), false);
    assert_eq!(s.range(at(1, 4)), None);
    s.release(at(1, 4));
    assert_eq!(s.range(at(2, 3)), None);
    // A drag back over a line: in order.
    s.press(at(1, 4), at(1, 4), false);
    assert_eq!(s.range(at(0, 8)), Some((at(0, 8), at(1, 4))));
    s.release(at(0, 8));
    // Shift+click extends from the anchor, not the cursor.
    s.press(at(2, 2), at(0, 8), true);
    assert_eq!(s.range(at(2, 2)), Some((at(1, 4), at(2, 2))));
    // A key without Shift drops it; Escape says whether it had any.
    s.leave(at(2, 2), false);
    assert!(!s.clear(at(2, 2)));
    s.leave(at(2, 2), true);
    assert!(s.clear(at(2, 5)));
}

#[test]
fn a_selection_touches_the_lines_it_has_characters_of() {
    let at = TextPos::new;
    let s = Text {
        anchor: Some(at(0, 3)),
        pressed: false,
    };
    // Ending at a line's start: not that line.
    assert_eq!(s.lines(at(2, 0)), Some(0..=1));
    assert_eq!(s.lines(at(2, 1)), Some(0..=2));
    assert_eq!(s.lines(at(0, 5)), Some(0..=0));
    assert_eq!(s.lines(at(0, 3)), None);
    // As drawn: the first line from its column, the lines between whole
    // with their line break, the last to its column; a column past a
    // line's end at it.
    let range = (at(0, 3), at(2, 2));
    assert_eq!(columns_on(range, 0, 11), Some((3, 12)));
    assert_eq!(columns_on(range, 1, 15), Some((0, 16)));
    assert_eq!(columns_on(range, 2, 7), Some((0, 2)));
    assert_eq!(columns_on(range, 3, 7), None);
    assert_eq!(columns_on((at(0, 20), at(1, 0)), 0, 11), Some((11, 12)));
    assert_eq!(columns_on((at(0, 20), at(1, 0)), 1, 11), None);
    assert_eq!(columns_on((at(0, 4), at(0, 40)), 0, 11), Some((4, 11)));
    // Its instructions, each once, for the provenance wash.
    let doc = document();
    assert_eq!(line_addresses(&doc, 1..=2), [0x20, 0x30, 0x40]);
    assert_eq!(line_addresses(&doc, 2..=9), Vec::<u64>::new());
}

#[test]
fn a_double_click_takes_the_token_and_a_triple_click_the_line() {
    let doc = document();
    let at = TextPos::new;
    // On a token: its characters.
    assert_eq!(c_token(&doc, at(1, 3)), (at(1, 2), at(1, 4)));
    assert_eq!(c_token(&doc, at(2, 0)), (at(2, 0), at(2, 6)));
    // Between tokens: the spaces there.
    assert_eq!(c_token(&doc, at(1, 0)), (at(1, 0), at(1, 2)));
    // Past the line's end: nothing.
    assert_eq!(c_token(&doc, at(0, 40)), (at(0, 11), at(0, 11)));
    // A line to the next one's start; the last to its end.
    assert_eq!(c_line(&doc, 1), (at(1, 0), at(2, 0)));
    assert_eq!(c_line(&doc, 2), (at(2, 0), at(2, 7)));
}

#[test]
fn copying_c_takes_the_characters_between_the_ends_across_lines() {
    let doc = document();
    let at = TextPos::new;
    assert_eq!(c_text(&doc, at(1, 2), at(1, 4)), "v1");
    assert_eq!(
        c_text(&doc, at(0, 8), at(2, 6)),
        "v1;\n  v1 = v1 + a2;\nreturn"
    );
    // A whole line with its line break.
    let (from, to) = c_line(&doc, 0);
    assert_eq!(c_text(&doc, from, to), "int64_t v1;\n");
    // Columns past a line's end are at it; lines past the last are none.
    assert_eq!(c_text(&doc, at(0, 9), at(1, 40)), "1;\n  v1 = v1 + a2;");
    assert_eq!(c_text(&doc, at(2, 0), at(7, 3)), "return;\n");
}

#[test]
fn listing_selections_copy_as_shown_and_cover_their_items_bytes() {
    let path = format!(
        "{}/../../tests/fixtures/program-x86_64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read(path).unwrap();
    let image = Image::parse(&data).unwrap();
    let db = Database::with_corrections(&image, Seeds::ALL, None, Corrections::default()).unwrap();
    let listing = Listing::build(&db, &Options::default());
    let overlay = Overlay::default();
    // The 4-byte instruction at 0x11dd and the next one.
    let n = listing.line_of(0x11dd);
    let next = listing.line_of(0x11e1);
    let shown = |n: u64| -> String {
        let rendered = listing.render(&db, n, &overlay);
        let text: String = rendered.tokens.iter().map(|t| t.text.as_str()).collect();
        text.trim_end().to_owned()
    };
    let copied = listing_text(&listing, &db, &overlay, n..=next);
    let expected: Vec<String> = (n..=next).map(shown).collect();
    assert_eq!(copied, expected.join("\n"));
    assert!(!copied.ends_with(char::is_whitespace));
    assert_eq!(listing_bytes(&listing, n..=n), Some((0x11dd, 0x11e1)));
    // A function's lines from its `proc`: its entry to its last
    // instruction's end; and back, from its entry's first line (the blank
    // and the banner over the `proc` are its entry's item's too).
    let lines = listing.function_lines(0x11d0).unwrap();
    let (first, last) = (lines.start, lines.end - 1);
    let (start, end) = listing_bytes(&listing, first..=last).unwrap();
    assert_eq!(start, 0x11d0);
    assert!(end > 0x11e1);
    let back = item_lines(&listing, start, end - 1);
    let address = |n: u64| listing.line(n).map(|l| l.address);
    assert!(*back.start() < first);
    assert_eq!(address(*back.start()), Some(0x11d0));
    assert_ne!(address(*back.start() - 1), Some(0x11d0));
    assert!(*back.end() >= last);
    assert_ne!(address(*back.end() + 1), address(*back.end()));
    // One instruction's item: its line alone.
    assert_eq!(item_lines(&listing, 0x11dd, 0x11e0), n..=n);
}
