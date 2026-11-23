#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Layout options change only whitespace; the presets look like their
//! namesakes.

mod common;

use binbun_ast::ir::{Callee, Function, Name, NameOrigin, Origin, Place, VarId, VarKind, Variable};
use binbun_ast::types::{Aggregate, Evidence, Field, Type, TypeId};
use binbun_print::c::{self, Printed};
use binbun_print::document::Document;
use binbun_print::layout::{render, render_items, render_spans};
use binbun_print::style::{BraceStyle, Indent, IntSpelling, Naming, SingleStatementBraces, Style};
use binbun_semantics::ir::{Binary, RegisterId};
use common::samples::{branches, calls, escapes, loops, memory, symbols, wide_literals};
use common::{Builder, DECLARATIONS, LLP64, LP64, Platform};

fn printed(f: &Function, style: &Style) -> Printed {
    c::function(f, &DECLARATIONS, style, &symbols, c::Opaque::Calls).unwrap()
}

/// `f` as C under `style` on a platform whose `long` is `long` bits.
fn on(f: &Function, style: &Style, long: u16) -> String {
    let printed = c::function(f, &DECLARATIONS, style, &Platform(long), c::Opaque::Calls).unwrap();
    render(&printed.document, style)
}

/// A local of type `ty` made from `origins`, named `name` if given.
fn local_from(b: &mut Builder, ty: TypeId, origins: Vec<Origin>, name: Option<&str>) -> VarId {
    b.f.add_var(Variable {
        kind: VarKind::Local,
        name: name.map(|name| Name::new(name, NameOrigin::Debug)),
        ty,
        evidence: Evidence::Default,
        origins,
    })
}

/// Under [`Naming::Registers`] the parameter is `arg1`, the two locals
/// held in `rdi` are `rdi_1` and `rdi_2`, the local of the stack slot
/// 0x58 below the entry stack pointer (alone there) `var_58`, a local
/// made from neither numbered as before, and a name of a variable's own
/// stays (and counts in no register's numbering); by default every name
/// is numbered.
#[test]
fn register_names_say_where_the_machine_code_kept_each_variable() {
    let mut b = Builder::new(0x1000, "kept");
    let int = b.int(64);
    b.f.returns = Some(int);
    let parameter = b.param(int);
    let held = local_from(&mut b, int, vec![Origin::Held(RegisterId(0))], None);
    let again = local_from(&mut b, int, vec![Origin::Held(RegisterId(0))], None);
    let slot = local_from(&mut b, int, vec![Origin::Slot(-0x58)], None);
    let other = local_from(&mut b, int, Vec::new(), None);
    let named = local_from(
        &mut b,
        int,
        vec![Origin::Held(RegisterId(0))],
        Some("count"),
    );
    let mut body = Vec::new();
    for (to, from) in [
        (held, parameter),
        (again, held),
        (slot, again),
        (other, slot),
        (named, other),
    ] {
        let read = b.read(from);
        let one = b.c(64, 1);
        let sum = b.bin(Binary::Add, read, one);
        body.push(b.assign(to, sum));
    }
    let result = b.read(named);
    body.push(b.ret(result));
    let f = b.done(body);
    let registers = on(&f, &Style::kr().with_naming(Naming::Registers), 64);
    for expected in [
        "kept(int64_t arg1)",
        "rdi_1 = arg1 + 1",
        "rdi_2 = rdi_1 + 1",
        "var_58 = rdi_2 + 1",
        " = var_58 + 1",
        "count = v",
    ] {
        assert!(
            registers.contains(expected),
            "{expected:?} in:\n{registers}"
        );
    }
    let numbered = on(&f, &Style::kr(), 64);
    assert!(numbered.contains("kept(int64_t a1)"), "{numbered}");
    for unexpected in ["arg1", "rdi", "var_58"] {
        assert!(
            !numbered.contains(unexpected),
            "{unexpected:?} in:\n{numbered}"
        );
    }
    assert!(numbered.contains("count = v"), "{numbered}");
}

fn strip(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// A random layout (presentation fixed: braces always, `int`).
fn random_style(seed: &mut u64) -> Style {
    let mut next = || {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    };
    let braces = [
        BraceStyle::Attach,
        BraceStyle::KernighanRitchie,
        BraceStyle::Linux,
        BraceStyle::Allman,
        BraceStyle::Gnu,
    ];
    Style::kr()
        .with_indent(if next() % 2 == 0 {
            Indent::Spaces
        } else {
            Indent::Tabs
        })
        .with_indent_width(u16::try_from(next() % 8).unwrap() + 1)
        .with_tab_width(u16::try_from(next() % 8).unwrap() + 1)
        .with_braces(braces[usize::try_from(next() % 5).unwrap()])
        .with_column_limit(u16::try_from(next() % 160).unwrap() + 10)
        .with_single_statement_braces(SingleStatementBraces::Always)
}

#[test]
fn layout_never_changes_the_tokens() {
    let mut seed = 0x2545_f491_4f6c_dd1d;
    let reference_style = Style::kr().with_single_statement_braces(SingleStatementBraces::Always);
    for f in [loops(), memory(), calls(), escapes(), branches()] {
        let document = printed(&f, &reference_style).document;
        let reference = strip(&render(&document, &reference_style));
        for _ in 0..200 {
            let style = random_style(&mut seed);
            let (text, spans) = render_spans(&document, &style);
            assert_eq!(strip(&text), reference, "{style:?}\n{text}");
            // Every span holds its token, and the spans hold all the
            // text but whitespace.
            let mut joined = String::new();
            for span in &spans {
                joined.push_str(&text[span.range.clone()]);
            }
            assert_eq!(strip(&joined), reference, "{style:?}");
            // Lines never end in whitespace.
            assert!(
                text.lines().all(|line| !line.ends_with([' ', '\t'])),
                "{style:?}\n{text}"
            );
            // The printer's tokens, in order, are the spans but braces.
            let tokens: Vec<&str> = document.tokens().iter().map(|t| t.text.as_str()).collect();
            let spanned: Vec<&str> = spans
                .iter()
                .map(|span| &text[span.range.clone()])
                .filter(|text| *text != "{" && *text != "}")
                .collect();
            assert_eq!(tokens, spanned, "{style:?}");
            // Each top-level item starts a line, after the items before
            // it laid out alone.
            let (whole, _, starts) = render_items(&document, &style);
            assert_eq!(whole, text);
            assert_eq!(starts.len(), document.items.len());
            for (n, &start) in starts.iter().enumerate() {
                let before = Document {
                    items: document.items[..n].to_vec(),
                };
                assert_eq!(render(&before, &style), text[..start], "{style:?}");
            }
        }
    }
}

#[test]
fn presets_look_like_their_namesakes() {
    let f = branches();
    let kr = render(&printed(&f, &Style::kr()).document, &Style::kr());
    // K&R: the function's brace on its own line, the others attached,
    // `} else`, four spaces; fixed-width types, as every preset.
    assert!(
        kr.contains("int64_t branches(int64_t a1, int64_t a2)\n{\n"),
        "{kr}"
    );
    assert!(kr.contains("    if (a1 < a2) {\n"), "{kr}");
    assert!(kr.contains("    } else if (a1 == a2)\n"), "{kr}");
    assert!(kr.contains("    do {\n"), "{kr}");
    assert!(kr.contains("    } while ((uint64_t)v2 < 10);\n"), "{kr}");
    let allman = render(&printed(&f, &Style::allman()).document, &Style::allman());
    // Allman: every brace on its own line, single statements braced.
    assert!(allman.contains("    if (a1 < a2)\n    {\n"), "{allman}");
    assert!(
        allman.contains("    }\n    else if (a1 == a2)\n    {\n"),
        "{allman}"
    );
    assert!(allman.contains("    do\n    {\n"), "{allman}");
    let llvm = render(&printed(&f, &Style::llvm()).document, &Style::llvm());
    // LLVM: attached braces, two spaces, fixed-width types.
    assert!(
        llvm.contains("int64_t branches(int64_t a1, int64_t a2) {\n"),
        "{llvm}"
    );
    assert!(llvm.contains("\n  if (a1 < a2) {\n"), "{llvm}");
    let linux = render(&printed(&f, &Style::linux()).document, &Style::linux());
    assert!(linux.contains("\n\tif (a1 < a2) {\n"), "{linux}");
    // Long lines are broken under the column limit where they can be.
    for (text, limit) in [(&kr, 80), (&allman, 100), (&llvm, 80), (&linux, 80)] {
        let longest = text
            .lines()
            .map(|line| line.replace('\t', "        ").chars().count())
            .max()
            .unwrap();
        assert!(longest <= limit, "{longest} > {limit}:\n{text}");
    }
}

#[test]
fn a_wrapped_parameter_list_is_indented() {
    // Six 64-bit parameters exceed 80 columns: each continuation line is
    // indented one level, never at the left margin (where it read as a
    // statement of the enclosing scope).
    let mut b = Builder::new(0x6000, "many");
    let int64 = b.int(64);
    let parameters: Vec<_> = (0..6).map(|_| b.param(int64)).collect();
    let first = b.read(parameters[0]);
    let ret = b.ret(first);
    b.f.returns = Some(int64);
    let f = b.done(vec![ret]);
    for style in [Style::kr(), Style::llvm(), Style::linux()] {
        let text = render(&printed(&f, &style).document, &style);
        let head: Vec<&str> = text
            .lines()
            .skip_while(|line| !line.contains("many("))
            .take_while(|line| !line.starts_with('{') && !line.ends_with('{'))
            .collect();
        assert!(head.len() > 1, "not wrapped:\n{text}");
        let indent = style.indent_width as usize;
        for line in &head[1..] {
            let leading = line.len() - line.trim_start().len();
            assert!(
                leading >= 1 && (line.starts_with('\t') || leading >= indent),
                "{line:?} not indented:\n{text}"
            );
        }
    }
}

#[test]
fn a_call_without_arguments_is_never_broken() {
    // Past the column limit, a call with arguments breaks inside its
    // parentheses; one without has nothing to break: `sub_9000()`, not
    // `sub_9000(`, a blank line and `)`.
    let mut b = Builder::new(0x6000, "caller");
    let int32 = b.int(32);
    let result = b.local(int32);
    let signature = b.code(Vec::new(), Some(int32), false);
    let call = b.call(
        Callee::Address(0x9000),
        Vec::new(),
        signature,
        vec![Place::Var(result)],
    );
    let read = b.read(result);
    let ret = b.ret(read);
    b.f.returns = Some(int32);
    let f = b.done(vec![call, ret]);
    let style = Style::kr().with_column_limit(10);
    let text = render(&printed(&f, &style).document, &style);
    assert!(text.contains("sub_9000()"), "{text}");
}

#[test]
fn a_constant_compared_with_a_variable_goes_on_the_right() {
    // L0 has only `<` and `<=`, so `x > 5` arrives as `5 < x`: printed with
    // the constant on the right and the operator mirrored, and every
    // operator keeps its meaning.
    let cases = [
        (Binary::SLt, "a1 > 5"),
        (Binary::SLe, "a1 >= 5"),
        (Binary::ULt, "a1 > 5"),
        (Binary::ULe, "a1 >= 5"),
        (Binary::Eq, "a1 == 5"),
        (Binary::Ne, "a1 != 5"),
    ];
    for (op, wanted) in cases {
        let mut b = Builder::new(0x6000, "compare");
        let int32 = b.int(32);
        let x = b.param(int32);
        let five = b.c(32, 5);
        let read = b.read(x);
        let condition = b.bin(op, five, read);
        let one = b.c(32, 1);
        let early = b.ret(one);
        let when = b.when(condition, vec![early]);
        let zero = b.c(32, 0);
        let last = b.ret(zero);
        b.f.returns = Some(int32);
        let f = b.done(vec![when, last]);
        let style = Style::kr();
        let text = render(&printed(&f, &style).document, &style);
        assert!(text.contains(wanted), "{op:?}: wanted `{wanted}`:\n{text}");
    }
}

#[test]
fn plain_types_spell_64_bits_as_the_data_model_does() {
    // LP64 (Linux, macOS): `long` is 64 bits.
    let f = branches();
    let plain = Style::kr().with_int_spelling(IntSpelling::Plain);
    let linux = on(&f, &plain, LP64);
    assert!(
        linux.contains("long branches(long a1, long a2)\n{\n"),
        "{linux}"
    );
    assert!(
        linux.contains("} while ((unsigned long)v2 < 10);"),
        "{linux}"
    );
    assert!(
        !linux.contains("long long") && !linux.contains("int64_t"),
        "{linux}"
    );
    // LLP64 (64-bit Windows): `long` is 32 bits, 64 are `long long`.
    let windows = on(&f, &plain, LLP64);
    assert!(
        windows.contains("long long branches(long long a1, long long a2)\n{\n"),
        "{windows}"
    );
    assert!(
        windows.contains("} while ((unsigned long long)v2 < 10);"),
        "{windows}"
    );
    // The image's data model changes nothing of the fixed-width spelling,
    // the default, but the suffix of a 64-bit literal.
    assert_eq!(Style::kr().int_spelling, IntSpelling::Fixed);
    let windows = on(&f, &Style::kr(), LLP64);
    assert!(windows.contains("a2 * 0xc83fb728LL;"), "{windows}");
    assert_eq!(on(&f, &Style::kr(), LP64), windows.replace("LL", "L"));
}

#[test]
fn literals_of_64_bits_are_suffixed_as_the_data_model_does() {
    // Must: a 64-bit literal is 64 bits under the image's own data model,
    // whichever spelling the types take: `UL` where `long` is 64 bits
    // (LP64), `ULL` where it is 32 (LLP64: `0xdeadUL << 40` would shift a
    // 32-bit `unsigned long` past its width); a 32-bit literal takes none.
    // (The signed `L` and `LL`: above, `branches`.)
    let f = wide_literals();
    for style in [
        Style::kr(),
        Style::kr().with_int_spelling(IntSpelling::Plain),
    ] {
        let linux = on(&f, &style, LP64);
        for wanted in ["0xdeadUL << 40", "0xffffffff00000000UL", "0x123456789UL"] {
            assert!(linux.contains(wanted), "{wanted}:\n{linux}");
        }
        assert!(!linux.contains("LL"), "{linux}");
        let windows = on(&f, &style, LLP64);
        for wanted in ["0xdeadULL << 40", "0xffffffff00000000ULL", "0x123456789ULL"] {
            assert!(windows.contains(wanted), "{wanted}:\n{windows}");
        }
        for text in [&linux, &windows] {
            assert!(text.contains("(a2 + 0x12345)"), "{text}");
        }
    }
}

/// A function of a parameter of each integer width and signedness, a
/// string (`char *`), a `bool`, a pointer to a struct whose name reads as
/// an integer type's, and a 128-bit integer, returning the 32-bit one.
fn every_width() -> Function {
    let mut b = Builder::new(0x6100, "widths");
    let integers: Vec<_> = [8, 16, 32]
        .into_iter()
        .flat_map(|width| [Type::Int(width), Type::UInt(width)])
        .map(|ty| b.ty(ty))
        .collect();
    let text = b.ty(Type::Char { signed: true });
    let string = b.ty(Type::Pointer(Some(text)));
    let truth = b.ty(Type::Bool(8));
    let int32 = b.int(32);
    let holder = b.ty(Type::Struct(Aggregate {
        name: Some("uint32_t_holder".into()),
        size: 4,
        fields: vec![Field {
            offset: 0,
            ty: int32,
            name: Some("int8_t_count".into()),
        }],
    }));
    let to_holder = b.ty(Type::Pointer(Some(holder)));
    let wide = b.uint(128);
    for ty in integers
        .iter()
        .copied()
        .chain([string, truth, to_holder, wide])
    {
        b.param(ty);
    }
    let held = b.read(b.f.parameters[8]);
    let field = b.load_at(held, 0, int32);
    let ret = b.ret(field);
    b.f.returns = Some(int32);
    b.done(vec![ret])
}

#[test]
fn plain_bytes_are_signed_or_unsigned_char_never_plain_char() {
    let plain = Style::kr().with_int_spelling(IntSpelling::Plain);
    for long in [LP64, LLP64] {
        let text = on(&every_width(), &plain, long);
        assert!(
            strip(&text).contains(&strip(
                "int widths(signed char a1, unsigned char a2, short a3, unsigned short a4, int a5, unsigned int a6,"
            )),
            "{text}"
        );
        // Plain `char` only where the binary's types say text.
        assert_eq!(
            text.matches("char ").count() - text.matches("signed char ").count(),
            1,
            "{text}"
        );
        assert!(text.contains("char *a7"), "{text}");
    }
}

#[test]
fn plain_types_leave_names_bool_text_and_wide_integers_alone() {
    // Must not: a struct's or field's name, `bool`, the text `char` and
    // `__int128` are not integer spellings, whatever they read like.
    let plain = Style::kr().with_int_spelling(IntSpelling::Plain);
    let fixed = on(&every_width(), &Style::kr(), LP64);
    let text = on(&every_width(), &plain, LP64);
    for kept in [
        "struct uint32_t_holder",
        "->int8_t_count",
        "bool a8",
        "char *a7",
        "unsigned __int128 a10",
    ] {
        assert!(fixed.contains(kept), "fixed: {kept}\n{fixed}");
        assert!(text.contains(kept), "plain: {kept}\n{text}");
    }
    assert!(text.contains("    int int8_t_count;\n"), "{text}");
    assert!(fixed.contains("    int32_t int8_t_count;\n"), "{fixed}");
}
