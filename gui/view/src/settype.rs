//! Set type (`Y`): the inline field over a type in the
//! C ([`TypeField`]): a variable's type on its declaration, a parameter's
//! in the signature (the prototype changes), a function's whole prototype
//! on its signature or declaration, a member's type on its line of the
//! struct's definition (from a use too: `p->name`); the C the session
//! reads from it
//! ([`TypeField::c`]), where an error the session reports falls in it
//! ([`TypeField::error_range`]), the name a type word declares (`Y` on
//! it types what `Y` on the name types: [`declared_name`]), and the type
//! names completing the word typed that fit what is typed
//! ([`completions`]).

use std::ops::Range;

use binbun_ast::ir::{Node, VarId};
use binbun_print::document::TokenKind;
use binbun_session::{CError, GlobalTyped, Typed, member_at};

use crate::cdoc::CDocument;

/// What a type field types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A variable, a global, a prototype.
    Typed(Typed),
    /// A member of a struct or union.
    Member {
        /// The struct's key (`struct pair`).
        key: String,
        /// The member's name.
        name: String,
    },
}

/// An inline field over a type in a C document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeField {
    /// What it types.
    pub subject: Subject,
    /// The line it is on.
    pub line: usize,
    /// The bytes of the document's text it stands over.
    pub range: Range<usize>,
    /// The type as printed (the field's text before an edit).
    pub original: String,
    /// The field's text.
    pub text: String,
    /// The C before the field's text the session reads.
    before: String,
    /// The C after it.
    after: String,
}

/// The characters that end a declaration's type before it (a parameter
/// list's `(`, a parameter's `,`) or its declarator after it.
const BEFORE: [char; 4] = ['(', ',', ';', '{'];
const AFTER: [char; 5] = [',', ')', ';', '=', '{'];
/// The keywords a declaration's type is written with.
const TYPE_KEYWORDS: [&str; 9] = [
    "struct", "union", "enum", "const", "volatile", "unsigned", "signed", "extern", "static",
];
/// What cannot stand between a declaration's type and its name.
const NOT_A_TYPE: [char; 9] = ['(', ')', ',', ';', '=', '{', '}', '[', ']'];

impl TypeField {
    /// The field over the type of the global `typed` in its declaration
    /// as the C prints it (`struct s current_user`, `uint32_t g_4010[4]`),
    /// where no C shows it (the hex view's structure tree): the type
    /// before the name, the rest of the declarator after it.
    pub fn global(typed: &GlobalTyped) -> Option<Self> {
        let c = typed.c.as_deref()?;
        let is_word = |ch: char| ch.is_alphanumeric() || ch == '_';
        let (at, _) = c.match_indices(typed.name.as_str()).find(|&(at, name)| {
            c.get(..at).is_some_and(|b| !b.ends_with(is_word))
                && c.get(at + name.len()..)
                    .is_some_and(|a| !a.starts_with(is_word))
        })?;
        let original = c.get(..at)?.trim_end().to_owned();
        Some(Self {
            subject: Subject::Typed(typed.typed()),
            line: 0,
            range: 0..original.len(),
            text: original.clone(),
            original,
            before: String::new(),
            after: format!(" {}", c.get(at..)?),
        })
    }

    /// The field over the type of variable `var` on its declaration (its
    /// first occurrence), typing `typed` (a global's or a variable's).
    pub fn variable(doc: &CDocument, var: VarId, typed: Typed) -> Option<Self> {
        let (line, name, type_start, after) = declaration(doc, var)?;
        let range = type_start..name.start;
        let original = doc.text.get(range)?.trim_end().to_owned();
        let name_text = doc.text.get(name.start..name.end)?;
        let suffix = doc.text.get(name.end..after)?;
        Some(Self {
            subject: Subject::Typed(typed),
            line,
            range: type_start..type_start + original.len(),
            text: original.clone(),
            original,
            before: String::new(),
            after: format!(" {name_text}{suffix}"),
        })
    }

    /// The field over the type of parameter `var` in the signature: what
    /// it types is the function's prototype (`typed`), the rest of the
    /// signature as printed.
    pub fn parameter(doc: &CDocument, var: VarId, typed: Typed) -> Option<Self> {
        let (line, name, type_start, _) = declaration(doc, var)?;
        let signature = prototype_text(doc, line)?;
        let line_start = doc.lines.get(line)?.range.start;
        let original = doc.text.get(type_start..name.start)?.trim_end().to_owned();
        let start = type_start - line_start;
        Some(Self {
            subject: Subject::Typed(typed),
            line,
            range: type_start..type_start + original.len(),
            text: original.clone(),
            before: signature.get(..start)?.to_owned(),
            after: signature.get(start + original.len()..)?.to_owned(),
            original,
        })
    }

    /// The field over the whole prototype on line `line` (the signature,
    /// or a callee's declaration), typing `typed`.
    pub fn prototype(doc: &CDocument, line: usize, typed: Typed) -> Option<Self> {
        let original = prototype_text(doc, line)?;
        let start = doc.lines.get(line)?.range.start;
        Some(Self {
            subject: Subject::Typed(typed),
            line,
            range: start..start + original.len(),
            text: original.clone(),
            original,
            before: String::new(),
            after: String::new(),
        })
    }

    /// The field over the type of the member span `s` of `doc` names (on
    /// its declaration's line of the struct's definition where `doc`
    /// prints it, else over the name), its struct's C being `c` (the
    /// struct as the session has it): the C read is the struct's, the
    /// member's type the field's text.
    pub fn member(doc: &CDocument, s: usize, c: &str) -> Option<Self> {
        let of = doc.member(s)?;
        let name = doc.span_text(s).to_owned();
        let at = member_at(c, &name)?;
        let original = c.get(at.ty.clone())?.to_owned();
        let (line, range) = match doc.member_declaration(of, &name) {
            Some(declared) => {
                let line = doc.line_of_span(declared)?;
                let start = doc.lines.get(line)?.range.start;
                let end = doc.spans.get(declared)?.range.start;
                let head = doc.text.get(start..end)?;
                let from = start + (head.len() - head.trim_start().len());
                let to = start + head.trim_end().len();
                (line, from..to.max(from))
            }
            None => (doc.line_of_span(s)?, doc.spans.get(s)?.range.clone()),
        };
        Some(Self {
            subject: Subject::Member {
                key: doc.struct_key(of)?,
                name,
            },
            line,
            range,
            text: original.clone(),
            original,
            before: c.get(..at.ty.start)?.to_owned(),
            after: format!(" {}", c.get(at.name.start..)?),
        })
    }

    /// The line of `doc` declaring the function named `name` (its
    /// signature, or a callee's declaration before it), if there is one.
    pub fn prototype_line(doc: &CDocument, name: &str) -> Option<usize> {
        let call = format!("{name}(");
        let signature = doc.body_start();
        (0..=signature).rev().find(|&n| {
            let text = doc.line_text(n);
            let words = text.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '('));
            (n == signature
                || text
                    .trim_end()
                    .split("/*")
                    .next()
                    .is_some_and(|t| t.trim_end().ends_with(';')))
                && words.into_iter().any(|word| word.starts_with(&call))
        })
    }

    /// The C the session reads: the field's text in its declaration.
    pub fn c(&self) -> String {
        format!("{}{}{}", self.before, self.text, self.after)
    }

    /// What to commit: the C, or `None` for an empty field (as analysis
    /// types it again).
    pub fn commit(&self) -> Option<String> {
        (!self.text.trim().is_empty()).then(|| self.c())
    }

    /// Whether the text differs from the type as printed.
    pub fn changed(&self) -> bool {
        self.text.trim() != self.original
    }

    /// The bytes of the field's text `error` (about [`Self::c`]) falls
    /// on, clamped to it (an error past it: its end).
    pub fn error_range(&self, error: &CError) -> Range<usize> {
        let clamp = |at: usize| at.saturating_sub(self.before.len()).min(self.text.len());
        let start = clamp(error.span.start);
        start..clamp(error.span.end).max(start)
    }
}

/// The span of the name the type word at span `s` of `doc` declares on
/// its line: a variable's declaration (`int32_t` of `int32_t v3;`, of a
/// parameter), a function's prototype (its return type). `None` for a
/// type word elsewhere (a cast, `sizeof`) or a span that is no type word.
pub fn declared_name(doc: &CDocument, s: usize) -> Option<usize> {
    let span = doc.spans.get(s)?;
    let word = doc.text.get(span.range.clone())?;
    let type_word =
        span.kind.is_type() || (span.kind == TokenKind::Keyword && TYPE_KEYWORDS.contains(&word));
    if !type_word {
        return None;
    }
    let line = doc.line_of_span(s)?;
    let end = doc.lines.get(line)?.range.end;
    let (at, name) = doc
        .spans
        .iter()
        .enumerate()
        .skip(s + 1)
        .take_while(|(_, n)| n.range.start < end)
        .find(|(_, n)| n.kind.is_name())?;
    if doc
        .text
        .get(span.range.end..name.range.start)?
        .contains(NOT_A_TYPE)
    {
        return None;
    }
    if let Some(Node::Var(var)) = name.node {
        return (doc.occurrences(Node::Var(var)).next() == Some(at)).then_some(at);
    }
    if doc.member(at).is_some() {
        return Some(at);
    }
    let function = doc.text.get(name.range.clone())?;
    let called = doc.text.get(name.range.end..)?.starts_with('(');
    (called && TypeField::prototype_line(doc, function) == Some(line)).then_some(at)
}

/// The declaration of `var` in `doc`: its line, its name's bytes, where
/// its type starts and where its declarator ends.
fn declaration(doc: &CDocument, var: VarId) -> Option<(usize, Range<usize>, usize, usize)> {
    let s = doc.occurrences(Node::Var(var)).next()?;
    let name = doc.spans.get(s)?.range.clone();
    let line = doc.line_of_span(s)?;
    let line_range = doc.lines.get(line)?.range.clone();
    let head = doc.text.get(line_range.start..name.start)?;
    let from = head.rfind(BEFORE).map_or(0, |at| at + 1);
    let mut type_start = line_range.start + from;
    let rest = doc.text.get(type_start..name.start)?;
    let skipped = rest.len() - rest.trim_start().len();
    type_start += skipped;
    for storage in ["extern ", "static "] {
        if doc.text.get(type_start..)?.starts_with(storage) {
            type_start += storage.len();
        }
    }
    let tail = doc.text.get(name.end..line_range.end)?;
    let after = name.end + tail.find(AFTER).unwrap_or(tail.len());
    Some((line, name, type_start, after))
}

/// Line `line`'s prototype: its text without a `{`, `;` or comment after
/// it.
fn prototype_text(doc: &CDocument, line: usize) -> Option<String> {
    let text = doc.line_text(line);
    let text = text.split("/*").next()?.trim_end();
    let text = text.strip_suffix('{').unwrap_or(text).trim_end();
    let text = text.strip_suffix(';').unwrap_or(text).trim_end();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The names (sorted) completing the word `text` ends in that fit: those
/// that start with it (a tag's with its keyword, `struct st` → `struct
/// stat`), the word itself left out, each as it completes the text if
/// `fits` takes the text completed so, else (a struct or union) as a
/// pointer to it if that fits (`struct stat *` for a register, which
/// holds no struct), else not at all; at most `limit`, `fits` asked at
/// most `tries` times.
pub fn completions(
    names: &[String],
    text: &str,
    limit: usize,
    tries: usize,
    mut fits: impl FnMut(&str) -> bool,
) -> Vec<String> {
    let Some(word) = last_word(text) else {
        return Vec::new();
    };
    let mut asked = 0;
    let mut ask = |c: &str| {
        asked += 1;
        asked <= tries && fits(c)
    };
    names
        .iter()
        .map(String::as_str)
        .filter(|name| name.starts_with(word) && *name != word)
        .filter_map(|name| {
            let completed = complete(text, name);
            if ask(&completed) {
                return Some(name.to_owned());
            }
            if !(name.starts_with("struct ") || name.starts_with("union ")) {
                return None;
            }
            let pointer = format!("{name} *");
            ask(&complete(text, &pointer)).then_some(pointer)
        })
        .take(limit)
        .collect()
}

/// `text` with the word it ends in replaced by `name`.
pub fn complete(text: &str, name: &str) -> String {
    let word = last_word(text).unwrap_or("");
    let keep = text.len() - word.len();
    format!("{}{name}", text.get(..keep).unwrap_or(""))
}

/// The word `text` ends in: an identifier, with a `struct`, `union` or
/// `enum` before it.
fn last_word(text: &str) -> Option<&str> {
    let ident = text
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_alphanumeric() || *c == '_')
        .last()
        .map(|(at, _)| at)?;
    let head = text.get(..ident)?;
    for keyword in ["struct ", "union ", "enum "] {
        if let Some(before) = head.strip_suffix(keyword)
            && before
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
        {
            return text.get(ident - keyword.len()..);
        }
    }
    text.get(ident..)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail loudly")]

    use std::collections::BTreeMap;

    use binbun::cfg::FunctionId;
    use binbun_ast::ir::{Function as Ast, Node, StmtId, VarId};
    use binbun_ast::types::Types;
    use binbun_decompile::typing::{GlobalShape, GlobalSource, GlobalType};
    use binbun_print::document::TokenKind;
    use binbun_semantics::core::Id as _;
    use binbun_session::{CError, GlobalTyped, Typed, Variable, View};
    use binbun_ssa::ir::Function as L1;
    use binbun_typeinfer::Strength;

    use super::{Subject, TypeField, complete, completions, declared_name};
    use crate::cdoc::{CDocument, CSpan};

    /// A callee's declaration, the signature with `a1` (var 0), a local
    /// `argv` (var 1), a global `table` (var 2) declared `extern`.
    fn document() -> CDocument {
        let text = "extern char *table[4]; /* 0x4010 */\n\
                    int32_t classify(int64_t); /* 0x1190 */\n\
                    int32_t loop_sum(int32_t a1)\n\
                    {\n    \
                    char **argv;\n\n    \
                    return classify(a1);\n\
                    }"
        .to_owned();
        let mut spans = Vec::new();
        let mut node = |word: &str, nth: usize, kind, var: Option<u32>| {
            let at = text.match_indices(word).nth(nth).unwrap().0;
            spans.push(CSpan {
                range: at..at + word.len(),
                kind,
                node: var.map(|v| Node::Var(VarId(v))),
                automatic: false,
                cast: false,
            });
        };
        node("table", 0, TokenKind::Global, Some(2));
        node("classify", 0, TokenKind::Function, None);
        node("loop_sum", 0, TokenKind::Function, None);
        node("a1", 0, TokenKind::Parameter, Some(0));
        node("argv", 0, TokenKind::Local, Some(1));
        node("return", 0, TokenKind::ControlKeyword, None);
        node("classify", 1, TokenKind::Function, None);
        node("a1", 1, TokenKind::Parameter, Some(0));
        node("char", 0, TokenKind::BuiltinType, None);
        node("char", 1, TokenKind::BuiltinType, None);
        node("int32_t", 0, TokenKind::BuiltinType, None);
        node("int32_t", 1, TokenKind::BuiltinType, None);
        node("int32_t", 2, TokenKind::BuiltinType, None);
        node("int64_t", 0, TokenKind::BuiltinType, None);
        spans.sort_by_key(|s| s.range.start);
        // A statement on the return line, so the signature is found.
        if let Some(ret) = spans
            .iter_mut()
            .find(|s| s.kind == TokenKind::ControlKeyword)
        {
            ret.node = Some(Node::Stmt(StmtId(0)));
        }
        CDocument::from_parts(
            FunctionId::from_raw(0),
            0x11f0,
            View::Exact,
            text,
            spans,
            BTreeMap::new(),
            &Ast::new(0x11f0, Types::new(64)),
            &L1::default(),
        )
    }

    fn variable(origins: &[&str]) -> Typed {
        Typed::Variable(Variable {
            function: 0x11f0,
            origins: origins.iter().map(|&o| o.to_owned()).collect(),
            ordinal: 0,
        })
    }

    #[test]
    fn a_variable_s_field_is_its_type_and_reads_with_its_declarator() {
        let doc = document();
        let local = TypeField::variable(&doc, VarId(1), variable(&["value 3"])).unwrap();
        assert_eq!(local.original, "char **");
        assert_eq!(doc.text.get(local.range.clone()), Some("char **"));
        assert_eq!(local.line, 4);
        let global = TypeField::variable(&doc, VarId(2), Typed::Global(0x4010)).unwrap();
        assert_eq!(global.original, "char *", "extern left out");
        let mut edited = global.clone();
        edited.text = "const char *".to_owned();
        assert_eq!(edited.c(), "const char * table[4]", "the array stays");
        assert!(edited.changed() && !global.changed());
        edited.text = "  ".to_owned();
        assert_eq!(edited.commit(), None, "empty: analysis's type again");
    }

    #[test]
    fn a_global_s_field_without_a_document_is_its_declaration_s_type() {
        let typed = |c: &str, name: &str| GlobalTyped {
            ty: GlobalType {
                start: 0x4010,
                size: 16,
                named: true,
                shape: GlobalShape::Declared,
                source: GlobalSource::Debug,
                strength: Strength(0),
                clues: Vec::new(),
                conflicts: 0,
            },
            name: name.to_owned(),
            c: Some(c.to_owned()),
            fields: Vec::new(),
        };
        let field = TypeField::global(&typed("uint32_t user_ids[4]", "user_ids")).unwrap();
        assert_eq!(field.subject, Subject::Typed(Typed::Global(0x4010)));
        assert_eq!(field.original, "uint32_t");
        let mut edited = field;
        edited.text = "int32_t".to_owned();
        assert_eq!(edited.c(), "int32_t user_ids[4]", "the array stays");
        // The name, not a type word it is part of.
        let field = TypeField::global(&typed("struct user_s user", "user")).unwrap();
        assert_eq!(field.original, "struct user_s");
        assert_eq!(field.c(), "struct user_s user");
    }

    #[test]
    fn a_parameter_s_field_types_the_whole_prototype() {
        let doc = document();
        let field = TypeField::parameter(&doc, VarId(0), Typed::Prototype(0x11f0)).unwrap();
        assert_eq!(field.original, "int32_t");
        assert_eq!(field.line, 2);
        let mut edited = field;
        edited.text = "unsigned".to_owned();
        assert_eq!(edited.c(), "int32_t loop_sum(unsigned a1)");
        // An error in the C maps to the field's bytes.
        let error = CError {
            message: "x".to_owned(),
            span: 17..25,
        };
        assert_eq!(edited.error_range(&error), 0..8);
        let past = CError {
            message: "x".to_owned(),
            span: 28..28,
        };
        assert_eq!(edited.error_range(&past), 8..8);
    }

    #[test]
    fn prototypes_are_found_by_name_without_their_comments() {
        let doc = document();
        assert_eq!(TypeField::prototype_line(&doc, "loop_sum"), Some(2));
        assert_eq!(TypeField::prototype_line(&doc, "classify"), Some(1));
        assert_eq!(TypeField::prototype_line(&doc, "class"), None);
        let callee = TypeField::prototype(&doc, 1, Typed::Prototype(0x1190)).unwrap();
        assert_eq!(callee.original, "int32_t classify(int64_t)");
        assert_eq!(callee.c(), callee.original);
        let own = TypeField::prototype(&doc, 2, Typed::Prototype(0x11f0)).unwrap();
        assert_eq!(own.original, "int32_t loop_sum(int32_t a1)");
    }

    #[test]
    fn a_declaration_s_type_word_names_what_it_declares() {
        let doc = document();
        let at = |word: &str, nth: usize| {
            let start = doc.text.match_indices(word).nth(nth).unwrap().0;
            doc.spans
                .iter()
                .position(|s| s.range.start == start)
                .unwrap()
        };
        // A local's, a global's (`extern` before it), a parameter's.
        assert_eq!(declared_name(&doc, at("char", 1)), Some(at("argv", 0)));
        assert_eq!(declared_name(&doc, at("char", 0)), Some(at("table", 0)));
        assert_eq!(declared_name(&doc, at("int32_t", 2)), Some(at("a1", 0)));
        // A return type: the function's prototype, its own or a callee's.
        assert_eq!(
            declared_name(&doc, at("int32_t", 1)),
            Some(at("loop_sum", 0))
        );
        assert_eq!(
            declared_name(&doc, at("int32_t", 0)),
            Some(at("classify", 0))
        );
        // A type naming nothing, a use, a word that is no type.
        assert_eq!(declared_name(&doc, at("int64_t", 0)), None);
        assert_eq!(declared_name(&doc, at("a1", 1)), None);
        assert_eq!(declared_name(&doc, at("return", 0)), None);
    }

    #[test]
    fn a_member_s_field_is_its_type_on_its_line_and_reads_as_the_struct() {
        use super::Subject;
        use binbun_ast::types::TypeId;
        let text = "struct pair {\n    char *first;\n};\nreturn p->first;".to_owned();
        let pair = Some(Node::Type(TypeId(3)));
        let span = |word: &str, nth: usize, kind, node| {
            let at = text.match_indices(word).nth(nth).unwrap().0;
            CSpan {
                range: at..at + word.len(),
                kind,
                node,
                automatic: false,
                cast: false,
            }
        };
        let spans = vec![
            span("struct", 0, TokenKind::Keyword, pair),
            span("pair", 0, TokenKind::Type, None),
            span("char", 0, TokenKind::BuiltinType, None),
            span("first", 0, TokenKind::Field, pair),
            span("return", 0, TokenKind::ControlKeyword, None),
            span("p", 1, TokenKind::Local, Some(Node::Var(VarId(0)))),
            span("->", 0, TokenKind::Operator, None),
            span("first", 1, TokenKind::Field, None),
        ];
        let mut doc = CDocument::from_parts(
            FunctionId::from_raw(0),
            0,
            View::Exact,
            text,
            spans,
            BTreeMap::new(),
            &Ast::new(0, Types::new(64)),
            &L1::default(),
        );
        doc.members = BTreeMap::from([(3, TypeId(3)), (7, TypeId(3))]);
        // The session's C of the struct (the user's spacing).
        let c = "struct pair { char *first; long n; };";
        // From the use: over the type on the definition's line.
        let mut field = TypeField::member(&doc, 7, c).unwrap();
        assert_eq!(
            field.subject,
            Subject::Member {
                key: "struct pair".to_owned(),
                name: "first".to_owned()
            }
        );
        assert_eq!((field.line, field.original.as_str()), (1, "char *"));
        assert_eq!(doc.text.get(field.range.clone()), Some("char *"));
        field.text = "uint64_t".to_owned();
        assert_eq!(field.c(), "struct pair { uint64_t first; long n; };");
        // An error on the type falls on the field's text.
        let error = CError {
            message: "x".to_owned(),
            span: 14..22,
        };
        assert_eq!(field.error_range(&error), 0..8);
        assert_eq!(TypeField::member(&doc, 5, c), None, "no member");
        assert_eq!(
            declared_name(&doc, 2),
            Some(3),
            "a member's type word types it"
        );
    }

    #[test]
    fn completion_takes_the_last_word_and_a_tag_s_keyword() {
        let names: Vec<String> = [
            "size_t",
            "ssize_t",
            "struct stat",
            "struct statfs",
            "uint32_t",
        ]
        .map(str::to_owned)
        .to_vec();
        let any = |_: &str| true;
        assert_eq!(
            completions(&names, "const s", 8, 64, any),
            ["size_t", "ssize_t", "struct stat", "struct statfs"]
        );
        assert_eq!(
            completions(&names, "struct stat", 8, 64, any),
            ["struct statfs"]
        );
        assert_eq!(
            completions(&names, "char *", 8, 64, any),
            Vec::<String>::new()
        );
        // A 64-bit register: no struct, a pointer to one; no 32-bit type.
        let register = |text: &str| {
            !(text.contains("uint32_t") || text.starts_with("struct") && !text.ends_with('*'))
        };
        assert_eq!(
            completions(&names, "s", 8, 64, register),
            ["size_t", "ssize_t", "struct stat *", "struct statfs *"]
        );
        assert_eq!(
            completions(&names, "u", 8, 64, register),
            Vec::<String>::new()
        );
        // At most `limit`, and `fits` asked at most `tries` times.
        assert_eq!(completions(&names, "s", 1, 64, register), ["size_t"]);
        assert_eq!(
            completions(&names, "s", 8, 3, register),
            ["size_t", "ssize_t"]
        );
        assert_eq!(complete("const s", "size_t"), "const size_t");
        assert_eq!(complete("struct st", "struct stat"), "struct stat");
        assert_eq!(complete("unsigned u", "uint32_t"), "unsigned uint32_t");
    }
}
