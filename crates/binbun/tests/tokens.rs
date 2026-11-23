#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! What each token of the decompiled C is, for highlighting: its kind
//! from the L2 node and declaration it comes from, whether binbun made
//! its name up, and whether it is part of a cast.

use std::collections::BTreeSet;
use std::fs;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::Options;
use binbun_loader::Image;
use binbun_print::c;
use binbun_print::document::TokenKind::{
    self, BuiltinType, ControlKeyword, Field, Function, Global, Keyword, Local, Macro, Number,
    Operator, Parameter, Punctuation, String as Str, Type,
};
use binbun_print::layout::render_spans;
use binbun_print::style::Style;

/// A token as printed: its text, kind, and whether it is automatic and
/// part of a cast.
type Printed = (String, TokenKind, bool, bool);

/// The tokens of function `function` of fixture `name`, printed K&R.
fn tokens(name: &str, function: &str) -> Vec<Printed> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let data = fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = database.find_function(function).unwrap();
    let decompiled = database.decompile(id, &Options::default()).result.unwrap();
    let style = Style::preset("kr").unwrap();
    let declarations = database.declarations().unwrap();
    let printed = c::function(
        &decompiled.l2,
        declarations,
        &style,
        database.data(),
        c::Opaque::Calls,
    )
    .unwrap();
    let (text, spans) = render_spans(&printed.document, &style);
    spans
        .into_iter()
        .map(|span| {
            (
                text[span.range].to_owned(),
                span.kind,
                span.automatic,
                span.cast,
            )
        })
        .collect()
}

/// How every token spelled `text` is classified: its kind, and whether
/// it is automatic (outside casts).
fn classes(tokens: &[Printed], text: &str) -> BTreeSet<(TokenKind, bool)> {
    tokens
        .iter()
        .filter(|(t, _, _, cast)| t == text && !cast)
        .map(|&(_, kind, automatic, _)| (kind, automatic))
        .collect()
}

/// Asserts every token spelled as each of `expected` is of that kind and
/// automatic or not, and that there is one.
fn check(tokens: &[Printed], expected: &[(&str, TokenKind, bool)]) {
    for &(text, kind, automatic) in expected {
        assert_eq!(
            classes(tokens, text),
            BTreeSet::from([(kind, automatic)]),
            "{text}"
        );
    }
}

/// `checked` calls `classify` (named by its symbol) with its parameter
/// (named by binbun) and `fail` with a string; `loop_sum`'s counter and
/// result are named by inference, not made up.
#[test]
fn names_are_functions_parameters_and_locals_by_their_declarations() {
    let checked = tokens("program-x86_64.elf", "checked");
    check(
        &checked,
        &[
            ("checked", Function, false),
            ("classify", Function, false),
            ("fail", Function, false),
            ("a1", Parameter, true),
            ("if", ControlKeyword, false),
            ("return", ControlKeyword, false),
            ("#include", Keyword, false),
            ("\"negative\"", Str, false),
            ("\"binbun_defs.h\"", Str, false),
            ("2", Number, false),
            ("binbun_unreachable", Macro, false),
            ("int32_t", BuiltinType, false),
            ("void", BuiltinType, false),
        ],
    );
    let loop_sum = tokens("program-x86_64.elf", "loop_sum");
    check(
        &loop_sum,
        &[
            ("for", ControlKeyword, false),
            ("i", Local, false),
            ("result", Local, false),
            ("a1", Parameter, true),
        ],
    );
}

/// `_start` stores through a struct type synthesis laid out (its name and
/// fields made up), reads the import slot's global (named by its
/// symbol), and casts.
#[test]
fn globals_fields_and_casts_are_told_apart() {
    let start = tokens("program-x86_64.elf", "_start");
    check(
        &start,
        &[
            ("__libc_start_main_ptr", Global, false),
            ("v5", Local, true),
            ("frame_p0", Local, true),
            ("struct__start_1", Type, true),
            ("field_0", Field, true),
            ("field_8", Field, true),
            ("extern", Keyword, false),
            ("const", Keyword, false),
            ("binbun_check_canonical_stack", Macro, false),
            ("BINBUN_TRAP_PROTECTION", Macro, false),
            ("BINBUN_SYMBOL", Macro, false),
        ],
    );
    // `v5 = (binbun_i64_u *)((…`: the cast's parentheses and type name,
    // not the parentheses of what it casts.
    let at = start
        .windows(2)
        .position(|pair| pair[0].0 == "v5" && pair[1].0 == "=" && pair[1].1 == Operator)
        .unwrap();
    let cast: Vec<(&str, TokenKind, bool)> = start[at + 2..at + 7]
        .iter()
        .map(|(text, kind, _, cast)| (text.as_str(), *kind, *cast))
        .collect();
    assert_eq!(
        cast,
        [
            ("(", Operator, true),
            ("binbun_i64_u", Type, true),
            ("*", Operator, true),
            (")", Operator, true),
            ("(", Punctuation, false),
        ]
    );
    assert!(
        start
            .iter()
            .filter(|(_, kind, _, _)| kind.is_name())
            .all(|(_, _, _, cast)| !cast),
        "a name in a cast"
    );
}

/// `report` reads the thread's canary through glibc's `tcbhead_t` (its
/// name and fields declared, its padding made up) and passes its
/// `va_list` on.
#[test]
fn declared_structs_and_their_members_are_named() {
    let report = tokens("variadic-gcc-x86_64.elf", "report");
    check(
        &report,
        &[
            ("tcbhead_t", Type, false),
            ("stack_guard", Field, false),
            ("pad_8", Field, true),
            ("s", Parameter, false),
            ("format", Parameter, false),
            ("ap", Local, false),
            ("va_list", Type, false),
            ("va_start", Macro, false),
            ("binbun_tcb", Macro, false),
            ("vfprintf", Function, false),
            ("struct", Keyword, false),
        ],
    );
}

/// A stripped function and global are named by binbun: automatic.
#[test]
fn names_without_a_symbol_are_automatic() {
    let tokens = tokens("msvc-x86_64.exe", "0x1400012c0");
    check(
        &tokens,
        &[
            ("sub_1400012c0", Function, true),
            ("g_140005130", Global, true),
            ("a1", Parameter, true),
            ("3", Number, false),
        ],
    );
}
