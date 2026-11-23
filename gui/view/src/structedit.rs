//! The struct editor (types edited as C): a struct or union as its C
//! definition ([`StructEdit`]),
//! checked as it is typed by the engine's C parser, with each member's
//! offset beside its line, the holes after members and the
//! struct's size ([`gutter`]); an enumeration so too, each constant's
//! value beside its line ([`enum_gutter`]); what it edits ([`StructTarget`]):
//! a synthesised struct of the program's table (the user's version
//! replaces it), a definition (the user's, or the type library's the
//! user's then replaces), or a new struct or enumeration.
//! Shown, not edited, it is [`Row`]s: its lines beside their offsets and
//! a row of `??` where bytes no member uses are ([`StructEdit::rows`]),
//! coloured by [`tokens`].

use std::ops::Range;

use binbun_ast::ir::Node;
use binbun_print::document::TokenKind;
use binbun_session::{CError, EnumLayout, StructLayout, StructMember, TypeLayout};

use crate::cdoc::CDocument;

/// What a struct editor edits.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StructTarget {
    /// A struct of the program's table of synthesised structs, by its
    /// identity: the function it is born in and its number there.
    Synthesised {
        /// The entry of the function it is born in.
        function: u64,
        /// Its number among the structs born there.
        k: u32,
    },
    /// A definition, by the key it defines (`struct pair`).
    Definition(String),
    /// A struct or enumeration not defined yet (numbered: each new one its
    /// own tab).
    New(u32),
}

/// A struct or enumeration as C being edited, with what the parser says
/// of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructEdit {
    /// What it edits.
    pub target: StructTarget,
    /// The C as last applied (or as opened).
    pub original: String,
    /// The C as typed.
    pub text: String,
    /// The layout of the C last read without an error (the offsets stay
    /// while the text is broken).
    pub layout: Option<TypeLayout>,
    /// Why the C as typed is refused, with the bytes at fault.
    pub error: Option<CError>,
}

impl StructEdit {
    /// An editor on `target`, defined as C `c`, checked as `checked`.
    pub fn new(target: StructTarget, c: String, checked: Result<TypeLayout, CError>) -> Self {
        let mut edit = Self {
            target,
            original: c.clone(),
            text: String::new(),
            layout: None,
            error: None,
        };
        edit.checked(c, checked);
        edit
    }

    /// The text is `text` now, and the parser says `checked` of it.
    pub fn checked(&mut self, text: String, checked: Result<TypeLayout, CError>) {
        self.text = text;
        match checked {
            Ok(layout) => {
                self.layout = Some(layout);
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    /// Whether the text differs from the C last applied.
    pub fn changed(&self) -> bool {
        self.text.trim() != self.original.trim()
    }

    /// The text is applied: what it edits is now `target` (a new struct,
    /// or a definition renamed, is the definition of its key).
    pub fn applied(&mut self, target: StructTarget) {
        self.original.clone_from(&self.text);
        self.target = target;
    }

    /// The gutter beside each line of the text ([`gutter`],
    /// [`enum_gutter`]).
    pub fn gutter(&self) -> Vec<Gutter> {
        match &self.layout {
            Some(TypeLayout::Record(layout)) => gutter(&self.text, layout),
            Some(TypeLayout::Enum(layout)) => enum_gutter(&self.text, layout),
            None => vec![Gutter::default(); line_count(&self.text)],
        }
    }

    /// The rows the text is shown in: each line beside its offset (an
    /// enumeration's constant's value; the size on the closing line), and
    /// after a member the bytes no member uses up to the next.
    pub fn rows(&self) -> Vec<Row> {
        let lines = match &self.layout {
            Some(TypeLayout::Record(layout)) => record_lines(&self.text, layout),
            Some(TypeLayout::Enum(layout)) => enum_gutter(&self.text, layout)
                .into_iter()
                .map(|g| Laid {
                    offset: g.offset,
                    hole: None,
                })
                .collect(),
            None => vec![Laid::default(); line_count(&self.text)],
        };
        let mut rows = Vec::with_capacity(lines.len());
        for (line, laid) in lines.into_iter().enumerate() {
            rows.push(Row::Line {
                line,
                offset: laid.offset,
            });
            if let Some((at, bits)) = laid.hole {
                rows.push(Row::Hole {
                    offset: bit_offset(at),
                    bits,
                });
            }
        }
        rows
    }

    /// The line the error is on.
    pub fn error_line(&self) -> Option<usize> {
        let error = self.error.as_ref()?;
        Some(position(&self.text, error.span.start).0)
    }

    /// The bytes of the text at fault, as the editor underlines them: the
    /// error's span, at least a character (after an empty span, or before
    /// it at a line's end, where something is missing). `None` without an
    /// error, or with no character on its line.
    pub fn error_bytes(&self) -> Option<Range<usize>> {
        let span = &self.error.as_ref()?.span;
        let text = self.text.as_str();
        let start = span.start.min(text.len());
        let end = span.end.clamp(start, text.len());
        if start < end {
            return text.get(start..end).map(|_| start..end);
        }
        if let Some(c) = text.get(start..)?.chars().next().filter(|&c| c != '\n') {
            return Some(start..start + c.len_utf8());
        }
        let before = text
            .get(..start)?
            .chars()
            .next_back()
            .filter(|&c| c != '\n')?;
        Some(start - before.len_utf8()..start)
    }
}

/// How many lines `text` has (an empty text one).
fn line_count(text: &str) -> usize {
    text.split('\n').count()
}

/// What the gutter shows beside one line of a struct's C (all in
/// hexadecimal).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gutter {
    /// The member's offset (a bit-field's bit after a dot: `0018.3`), or
    /// the struct's size on the line closing it.
    pub offset: Option<String>,
    /// The bytes no member uses after this one, before the next or the
    /// struct's end (`+4`; bits after a dot: `+3.5`).
    pub hole: Option<String>,
}

/// A row of a struct shown (not edited).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Row {
    /// Line `line` of the text, beside its offset ([`Gutter::offset`]).
    Line {
        /// The line.
        line: usize,
        /// What the gutter shows beside it.
        offset: Option<String>,
    },
    /// `bits` no member uses, from `offset` (as a member's is written).
    Hole {
        /// Where they start.
        offset: String,
        /// How many.
        bits: u64,
    },
}

impl Row {
    /// A hole's text: a `??` for each byte, eight at most (`…` after
    /// them for more); bits short of a byte counted (`3 bits`).
    pub fn hole_text(bits: u64) -> String {
        if !bits.is_multiple_of(8) {
            return format!("{bits} bits");
        }
        let bytes = bits / 8;
        let mut text = vec!["??"; usize::try_from(bytes.min(8)).unwrap_or(8)].join(" ");
        if bytes > 8 {
            text.push_str(" …");
        }
        text
    }
}

/// A member's place as the gutter writes it: the byte (`0018`), and the
/// bit after a dot where it starts inside one (`0018.3`).
fn bit_offset(bits: u64) -> String {
    match bits % 8 {
        0 => format!("{:04X}", bits / 8),
        bit => format!("{:04X}.{bit}", bits / 8),
    }
}

/// What a line of a struct's C stands for: its offset (the size on the
/// closing line), and the hole after the member it declares (where it
/// starts and how many bits, both in bits).
#[derive(Clone, Debug, Default)]
struct Laid {
    offset: Option<String>,
    hole: Option<(u64, u64)>,
}

/// For each line of `text`, what `layout` says of the member it declares
/// ([`Gutter`]), and the struct's size on the line closing it; nothing on
/// any other line. A member is found by its name, in order, among the
/// lines of the struct's own body; an anonymous struct or union member
/// on the line opening it.
pub fn gutter(text: &str, layout: &StructLayout) -> Vec<Gutter> {
    record_lines(text, layout)
        .into_iter()
        .map(|laid| Gutter {
            offset: laid.offset,
            hole: laid.hole.map(|(_, hole)| {
                if hole % 8 == 0 {
                    format!("+{:X}", hole / 8)
                } else {
                    format!("+{:X}.{}", hole / 8, hole % 8)
                }
            }),
        })
        .collect()
}

/// [`gutter`]'s lines, the holes where they start.
fn record_lines(text: &str, layout: &StructLayout) -> Vec<Laid> {
    let holes = holes(layout);
    let mut next = 0;
    let mut depth = 0usize;
    text.split('\n')
        .map(|line| {
            let code = line.split("//").next().unwrap_or(line).trim();
            let opens = code.matches('{').count();
            let closes = code.matches('}').count();
            let before = depth;
            depth = (depth + opens).saturating_sub(closes);
            if closes > 0 && before > 0 && depth == 0 {
                return Laid {
                    offset: Some(format!("{:04X}", layout.size)),
                    hole: None,
                };
            }
            let found = if before == 1 && depth > 1 {
                // An anonymous member opens here (a named one is found by
                // its name where it closes).
                layout
                    .members
                    .get(next)
                    .filter(|m| m.name.is_empty())
                    .map(|m| (next, m))
            } else if depth == 1 && before >= 1 {
                member_name(code).and_then(|name| {
                    layout
                        .members
                        .iter()
                        .enumerate()
                        .skip(next)
                        .find(|(_, m)| m.name == name)
                })
            } else {
                None
            };
            let Some((index, member)) = found else {
                return Laid::default();
            };
            next = index + 1;
            Laid {
                offset: Some(match member.bit_width {
                    Some(_) => format!("{:04X}.{}", member.bit_offset / 8, member.bit_offset % 8),
                    None => bit_offset(member.bit_offset),
                }),
                hole: holes.get(index).copied().flatten(),
            }
        })
        .collect()
}

/// For each member of `layout`, the bits no member uses after it, up to
/// the next member or (the last) the struct's end, as where they start
/// and how many; `None` where there are none, and for a union's members.
fn holes(layout: &StructLayout) -> Vec<Option<(u64, u64)>> {
    let mut holes = vec![None; layout.members.len()];
    if layout.key.starts_with("union ") {
        return holes;
    }
    let bits = |m: &StructMember| m.bit_width.map_or(m.size * 8, u64::from);
    // The end of the bits used so far, and the member that reaches it.
    let mut end: Option<(u64, usize)> = None;
    for (index, member) in layout.members.iter().enumerate() {
        if let Some((at, last)) = end
            && member.bit_offset > at
            && let Some(hole) = holes.get_mut(last)
        {
            *hole = Some((at, member.bit_offset - at));
        }
        let reach = member.bit_offset + bits(member);
        if end.is_none_or(|(at, _)| reach >= at) {
            end = Some((reach, index));
        }
    }
    if let Some((at, last)) = end
        && layout.size * 8 > at
        && let Some(hole) = holes.get_mut(last)
    {
        *hole = Some((at, layout.size * 8 - at));
    }
    holes
}

/// The name a member declaration (`int a : 3;`, `char *argv[2];`,
/// `int (*f)(int);`) declares: its declarator's identifier.
fn member_name(code: &str) -> Option<&str> {
    let code = code.strip_suffix(';')?.trim_end();
    if code.ends_with('}') || code.contains('{') {
        return None;
    }
    // A function pointer's name is in its first parentheses.
    let declarator = if let Some(at) = code.find("(*") {
        let inner = code.get(at + 2..)?;
        inner.get(..inner.find(')')?)?
    } else {
        let end = code.find(['[', ':']).unwrap_or(code.len());
        code.get(..end)?
    };
    let declarator = declarator.trim_end();
    let start = declarator
        .char_indices()
        .rev()
        .take_while(|&(_, c)| c.is_alphanumeric() || c == '_')
        .last()
        .map(|(at, _)| at)?;
    let name = declarator.get(start..)?;
    (!name.starts_with(|c: char| c.is_ascii_digit())).then_some(name)
}

/// For each line of `text`, the value `layout` gives the constant it
/// declares first (hexadecimal, as the struct's offsets), and the
/// enumeration's size in bytes on the line closing it; nothing on any
/// other line. Constants are found by name, in order.
pub fn enum_gutter(text: &str, layout: &EnumLayout) -> Vec<Gutter> {
    let mut next = 0;
    let mut depth = 0usize;
    text.split('\n')
        .map(|line| {
            let code = line.split("//").next().unwrap_or(line).trim();
            let before = depth;
            depth = (depth + code.matches('{').count()).saturating_sub(code.matches('}').count());
            if before > 0 && depth == 0 {
                return Gutter {
                    offset: Some(format!("{:04X}", layout.size)),
                    ..Gutter::default()
                };
            }
            let body = code.rsplit('{').next().unwrap_or(code);
            let first = body
                .split([',', '='])
                .next()
                .map(str::trim)
                .filter(|name| !name.is_empty());
            let found = (depth == 1).then_some(first).flatten().and_then(|name| {
                layout
                    .constants
                    .iter()
                    .enumerate()
                    .skip(next)
                    .find(|(_, (n, _))| n == name)
            });
            let Some((index, &(_, value))) = found else {
                return Gutter::default();
            };
            next = index + 1;
            let sign = if value < 0 { "-" } else { "" };
            Gutter {
                offset: Some(format!("{sign}{:X}", value.unsigned_abs())),
                ..Gutter::default()
            }
        })
        .collect()
}

/// C's keywords a type's definition writes: drawn as keywords.
const KEYWORDS: &[&str] = &[
    "struct", "union", "enum", "typedef", "const", "volatile", "restrict", "signed", "unsigned",
    "static", "extern", "register", "_Atomic", "_Alignas", "alignas",
];

/// The types C and its standard headers name, drawn as the C view draws
/// them (the fixed-width integers too).
const BUILTIN: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "_Bool", "bool", "__int128",
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
];

/// The tokens of a type's C (`text`, as the struct editor shows and edits
/// it), each with the kind the C view draws it as: keywords, builtin
/// types, the tag after `struct`, `union` or `enum` and other type names
/// as types, the name a member's declarator declares as a field (a
/// typedef's as a type), an enumeration's constants as macros, numbers,
/// comments, `__attribute__((…))` as a macro, operators and punctuation.
/// Whitespace is no token.
#[expect(clippy::too_many_lines, reason = "one lexer's states, in one loop")]
pub fn tokens(text: &str) -> Vec<(Range<usize>, TokenKind)> {
    let bytes = text.as_bytes();
    let mut out: Vec<(Range<usize>, TokenKind)> = Vec::new();
    // What each brace opened: an enumeration's body or not.
    let mut braces: Vec<bool> = Vec::new();
    // The declaration so far: whether it is a typedef, the identifiers
    // it has (by their index in `out`) that may be its declarator's name.
    let mut typedef = false;
    let mut names: Vec<usize> = Vec::new();
    // The keyword just read was `struct`, `union` or `enum` (its tag
    // next), `enum` itself (a brace after it opens a body of constants).
    let mut tag_next = false;
    let mut enum_next = false;
    // Parentheses inside `__attribute__((…))`; brackets open (an array's
    // length names no declarator).
    let mut attribute = 0usize;
    let mut brackets = 0usize;
    let mut at = 0;
    while let Some(&b) = bytes.get(at) {
        let start = at;
        if b.is_ascii_whitespace() {
            at += 1;
            continue;
        }
        if text.get(at..).is_some_and(|t| t.starts_with("//")) {
            at = text
                .get(at..)
                .and_then(|t| t.find('\n'))
                .map_or(text.len(), |n| at + n);
            out.push((start..at, TokenKind::Comment));
            continue;
        }
        if text.get(at..).is_some_and(|t| t.starts_with("/*")) {
            at = text
                .get(at + 2..)
                .and_then(|t| t.find("*/"))
                .map_or(text.len(), |n| at + 2 + n + 2);
            out.push((start..at, TokenKind::Comment));
            continue;
        }
        if b.is_ascii_digit() {
            while bytes
                .get(at)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                at += 1;
            }
            out.push((start..at, TokenKind::Number));
            continue;
        }
        if b == b'\'' || b == b'"' {
            at += 1;
            while let Some(&c) = bytes.get(at) {
                at += 1;
                if c == b'\\' {
                    at += 1;
                } else if c == b || c == b'\n' {
                    break;
                }
            }
            at = at.min(text.len());
            out.push((start..at, TokenKind::String));
            continue;
        }
        if b.is_ascii_alphabetic() || b == b'_' {
            while bytes
                .get(at)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                at += 1;
            }
            let word = text.get(start..at).unwrap_or_default();
            let in_enum = braces.last() == Some(&true);
            let kind = if attribute > 0 || word == "__attribute__" {
                TokenKind::Macro
            } else if tag_next {
                tag_next = false;
                TokenKind::Type
            } else if KEYWORDS.contains(&word) {
                tag_next = matches!(word, "struct" | "union" | "enum");
                enum_next = word == "enum";
                typedef |= word == "typedef";
                TokenKind::Keyword
            } else if BUILTIN.contains(&word) {
                TokenKind::BuiltinType
            } else if in_enum {
                // A constant, or a name in its value.
                TokenKind::Macro
            } else {
                if brackets == 0 {
                    names.push(out.len());
                }
                TokenKind::Type
            };
            out.push((start..at, kind));
            continue;
        }
        at += text
            .get(at..)
            .and_then(|t| t.chars().next())
            .map_or(1, char::len_utf8);
        tag_next = false;
        let kind = match b {
            b'{' => {
                braces.push(enum_next);
                enum_next = false;
                names.clear();
                TokenKind::Punctuation
            }
            b'}' => {
                braces.pop();
                TokenKind::Punctuation
            }
            b'(' if attribute > 0
                || out
                    .last()
                    .is_some_and(|(r, _)| text.get(r.clone()) == Some("__attribute__")) =>
            {
                attribute += 1;
                TokenKind::Punctuation
            }
            b')' if attribute > 0 => {
                attribute -= 1;
                TokenKind::Punctuation
            }
            b']' => {
                brackets = brackets.saturating_sub(1);
                TokenKind::Punctuation
            }
            // A declarator ends: its last name is what it declares.
            b';' | b',' | b'[' | b':' | b'=' | b')' if braces.last() != Some(&true) => {
                if let Some(&name) = names.last()
                    && let Some((_, kind)) = out.get_mut(name)
                {
                    *kind = if typedef && braces.is_empty() {
                        TokenKind::Type
                    } else {
                        TokenKind::Field
                    };
                }
                names.clear();
                if b == b';' && braces.is_empty() {
                    (typedef, enum_next) = (false, false);
                }
                if b == b'[' {
                    brackets += 1;
                }
                if matches!(b, b';' | b',' | b')' | b'[') {
                    TokenKind::Punctuation
                } else {
                    TokenKind::Operator
                }
            }
            b'[' => {
                brackets += 1;
                TokenKind::Punctuation
            }
            b';' | b',' | b'(' | b')' => TokenKind::Punctuation,
            _ => TokenKind::Operator,
        };
        out.push((start..at, kind));
    }
    out
}

/// The line and column (in characters) of byte `at` of `text`.
pub fn position(text: &str, at: usize) -> (usize, usize) {
    let at = at.min(text.len());
    let before = text.get(..at).unwrap_or(text);
    let line = before.matches('\n').count();
    let start = before.rfind('\n').map_or(0, |n| n + 1);
    (line, before.get(start..).map_or(0, |t| t.chars().count()))
}

/// The key of the struct or union C token `span` of `doc` is about: a
/// tag after `struct` or `union`, or the struct or union a variable's
/// declared type names (`struct pair *p`: `struct pair`).
pub fn struct_key(doc: &CDocument, span: usize) -> Option<String> {
    let tagged = |text: &str| -> Option<String> {
        let mut words = text
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty());
        while let Some(word) = words.next() {
            if matches!(word, "struct" | "union") {
                return words.next().map(|tag| format!("{word} {tag}"));
            }
        }
        None
    };
    if let Some(var) = doc.variable(span) {
        let declared = doc.occurrences(Node::Var(var)).next()?;
        let line = doc.line_of_span(declared)?;
        let name = doc.spans.get(declared)?.range.start;
        let start = doc.lines.get(line)?.range.start;
        return tagged(doc.text.get(start..name)?);
    }
    let previous = span.checked_sub(1)?;
    let keyword = doc.span_text(previous);
    matches!(keyword, "struct" | "union").then(|| format!("{keyword} {}", doc.span_text(span)))
}

/// The integer widths `D` cycles a member through (byte, word,
/// dword, qword), as C types.
const WIDTHS: [(u64, &str); 4] = [
    (1, "uint8_t"),
    (2, "uint16_t"),
    (4, "uint32_t"),
    (8, "uint64_t"),
];

/// The types `D` tries for a member of `size` bytes, in order: the widths
/// after its own, round to the start (a member of another size starts at
/// a byte); the first the struct's layout holds is taken.
pub fn next_widths(size: u64) -> Vec<&'static str> {
    let at = WIDTHS.iter().position(|&(bytes, _)| bytes == size);
    let start = at.map_or(0, |at| at + 1);
    (0..WIDTHS.len())
        .map(|k| (start + k) % WIDTHS.len())
        .filter(|&k| Some(k) != at)
        .filter_map(|k| WIDTHS.get(k).map(|&(_, ty)| ty))
        .collect()
}

/// A new struct's starting text: a name no type of `names` has
/// (`struct struct_1`, `struct struct_2`, …) and one member.
pub fn new_struct(names: &[String]) -> String {
    // One of the first `names.len() + 1` numbers is free.
    let name = (1..=names.len() + 1)
        .map(|n| format!("struct_{n}"))
        .find(|name| !names.iter().any(|known| *known == format!("struct {name}")))
        .unwrap_or_default();
    format!("struct {name} {{\n    int32_t field_0;\n}};")
}

/// A new enumeration's starting text: a tag no type of `names` has
/// (`enum enum_1`, …), its underlying type (`uint32_t`), one constant.
pub fn new_enum(names: &[String]) -> String {
    let name = (1..=names.len() + 1)
        .map(|n| format!("enum_{n}"))
        .find(|name| !names.iter().any(|known| *known == format!("enum {name}")))
        .unwrap_or_default();
    format!(
        "enum {name} : uint32_t {{\n    {}_0 = 0,\n}};",
        name.to_uppercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A struct `s` (a union `u` if `union`) of `size` bytes with
    /// `members`: name, offset in bits, size in bytes, bit-field width.
    fn laid_out(union: bool, size: u64, members: &[(&str, u64, u64, Option<u32>)]) -> StructLayout {
        StructLayout {
            key: if union { "union u" } else { "struct s" }.to_owned(),
            size,
            members: members
                .iter()
                .map(|&(name, bit_offset, size, bit_width)| StructMember {
                    name: name.to_owned(),
                    bit_offset,
                    size,
                    bit_width,
                })
                .collect(),
        }
    }

    fn layout(size: u64, members: &[(&str, u64, u64, Option<u32>)]) -> StructLayout {
        laid_out(false, size, members)
    }

    /// A gutter line: offset, hole.
    fn line(offset: &str, hole: &str) -> Gutter {
        let some = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        Gutter {
            offset: some(offset),
            hole: some(hole),
        }
    }

    #[test]
    fn the_gutter_puts_each_members_offset_and_hole_beside_its_line() {
        let text = "struct s {\n    char *argv[2];\n    int (*f)(int);\n\n    unsigned a : 3;\n    unsigned b : 5;\n    long z;\n    char c;\n};";
        let shown = gutter(
            text,
            &layout(
                0x30,
                &[
                    ("argv", 0, 16, None),
                    ("f", 128, 8, None),
                    ("a", 192, 4, Some(3)),
                    ("b", 195, 4, Some(5)),
                    ("z", 256, 8, None),
                    ("c", 320, 1, None),
                ],
            ),
        );
        assert_eq!(
            shown,
            [
                Gutter::default(),
                line("0000", ""),
                line("0010", ""),
                Gutter::default(),
                line("0018.0", ""),
                // The bit-fields end at bit 200; `z` starts at 256.
                line("0018.3", "+7"),
                line("0020", ""),
                // The tail padding up to the size.
                line("0028", "+7"),
                line("0030", ""),
            ]
        );
    }

    #[test]
    fn nested_members_are_found_on_their_own_lines_only() {
        // An anonymous union on the line opening it, a named struct where
        // it closes, the lines inside neither (the inner `x` is not the
        // struct's); only the struct's own closing line has its size.
        let text = "struct s {\n    char k;\n    union {\n        int x;\n        float y;\n    };\n    struct {\n        int x;\n    } inner;\n    int x;\n};";
        let shown = gutter(
            text,
            &layout(
                16,
                &[
                    ("k", 0, 1, None),
                    ("", 32, 4, None),
                    ("inner", 64, 4, None),
                    ("x", 96, 4, None),
                ],
            ),
        );
        let none = Gutter::default();
        assert_eq!(
            shown,
            [
                none.clone(),
                line("0000", "+3"),
                line("0004", ""),
                none.clone(),
                none.clone(),
                none.clone(),
                none.clone(),
                none,
                line("0008", ""),
                line("000C", ""),
                line("0010", ""),
            ]
        );
    }

    #[test]
    fn holes_count_bits_and_a_union_has_none() {
        // Five bits unused after a three-bit field, before a `char`.
        let text = "struct s {\n    unsigned a : 3;\n    char c;\n};";
        let shown = gutter(text, &layout(4, &[("a", 0, 4, Some(3)), ("c", 8, 1, None)]));
        assert_eq!(shown.get(1), Some(&line("0000.0", "+0.5")));
        assert_eq!(shown.get(2), Some(&line("0001", "+2")));
        // A union's members overlap: no holes, even short of its size.
        let text = "union u {\n    char a;\n    long b;\n};";
        let shown = gutter(
            text,
            &laid_out(true, 8, &[("a", 0, 1, None), ("b", 0, 8, None)]),
        );
        assert_eq!(
            shown,
            [
                Gutter::default(),
                line("0000", ""),
                line("0000", ""),
                line("0008", ""),
            ]
        );
    }

    #[test]
    fn shown_a_struct_has_its_unused_bytes_as_rows_where_they_are() {
        let text = "struct s {\n    char c;\n    unsigned a : 3;\n    long z;\n};";
        let edit = StructEdit::new(
            StructTarget::New(1),
            text.to_owned(),
            Ok(TypeLayout::Record(layout(
                0x20,
                &[("c", 0, 1, None), ("a", 8, 4, Some(3)), ("z", 128, 8, None)],
            ))),
        );
        let line = |line: usize, offset: &str| Row::Line {
            line,
            offset: (!offset.is_empty()).then(|| offset.to_owned()),
        };
        let hole = |offset: &str, bits| Row::Hole {
            offset: offset.to_owned(),
            bits,
        };
        assert_eq!(
            edit.rows(),
            [
                line(0, ""),
                line(1, "0000"),
                line(2, "0001.0"),
                // From bit 11 to `z` at 16 bytes.
                hole("0001.3", 117),
                line(3, "0010"),
                hole("0018", 64),
                line(4, "0020"),
            ]
        );
        assert_eq!(Row::hole_text(32), "?? ?? ?? ??");
        assert_eq!(Row::hole_text(8 * 12), "?? ?? ?? ?? ?? ?? ?? ?? …");
        assert_eq!(Row::hole_text(5), "5 bits");
    }

    /// `text`'s tokens as their texts and kinds.
    fn kinds(text: &str) -> Vec<(&str, TokenKind)> {
        tokens(text)
            .into_iter()
            .map(|(range, kind)| (&text[range], kind))
            .collect()
    }

    #[test]
    fn a_definitions_tokens_are_drawn_as_the_c_draws_them() {
        use TokenKind::{
            BuiltinType as B, Comment as C, Field as F, Keyword as K, Macro as M, Number as N,
            Operator as O, Punctuation as P, Type as T,
        };
        let text = "struct bin_tree_t {\n    struct bin_tree_t *parent; // up\n    Idx node_idx;\n    char name[LEN];\n    unsigned a : 3;\n    int (*f)(int);\n    struct { int x; } inner;\n} __attribute__((packed));";
        assert_eq!(
            kinds(text),
            [
                ("struct", K),
                ("bin_tree_t", T),
                ("{", P),
                ("struct", K),
                ("bin_tree_t", T),
                ("*", O),
                ("parent", F),
                (";", P),
                ("// up", C),
                ("Idx", T),
                ("node_idx", F),
                (";", P),
                ("char", B),
                ("name", F),
                ("[", P),
                // An array's length is no declarator.
                ("LEN", T),
                ("]", P),
                (";", P),
                ("unsigned", K),
                ("a", F),
                (":", O),
                ("3", N),
                (";", P),
                ("int", B),
                ("(", P),
                ("*", O),
                ("f", F),
                (")", P),
                ("(", P),
                ("int", B),
                (")", P),
                (";", P),
                // An anonymous struct: its members' types are no tag.
                ("struct", K),
                ("{", P),
                ("int", B),
                ("x", F),
                (";", P),
                ("}", P),
                ("inner", F),
                (";", P),
                ("}", P),
                ("__attribute__", M),
                ("(", P),
                ("(", P),
                ("packed", M),
                (")", P),
                (")", P),
                (";", P),
            ]
        );
        // A typedef names a type; an enumeration's constants are macros,
        // after its underlying type.
        let text = "typedef enum e : uint32_t {\n    A = 1,\n    B = A << 1,\n} e_t;";
        assert_eq!(
            kinds(text),
            [
                ("typedef", K),
                ("enum", K),
                ("e", T),
                (":", O),
                ("uint32_t", B),
                ("{", P),
                ("A", M),
                ("=", O),
                ("1", N),
                (",", P),
                ("B", M),
                ("=", O),
                ("A", M),
                ("<", O),
                ("<", O),
                ("1", N),
                (",", P),
                ("}", P),
                ("e_t", T),
                (";", P),
            ]
        );
    }

    #[test]
    fn an_error_is_placed_on_its_line_and_the_last_layout_stays() {
        let ok = layout(4, &[("a", 0, 4, None)]);
        let mut edit = StructEdit::new(
            StructTarget::New(1),
            "struct s {\n    int a;\n};".to_owned(),
            Ok(TypeLayout::Record(ok.clone())),
        );
        assert!(!edit.changed());
        let text = "struct s {\n    mystery a;\n};".to_owned();
        edit.checked(
            text,
            Err(CError {
                message: "unknown type mystery".to_owned(),
                span: 15..22,
            }),
        );
        assert!(edit.changed());
        assert_eq!(edit.error_line(), Some(1));
        assert_eq!(edit.error_bytes(), Some(15..22));
        assert_eq!(edit.layout, Some(TypeLayout::Record(ok)));
        // An empty span: the character after it is underlined.
        edit.error = Some(CError {
            message: "expected ;".to_owned(),
            span: 23..23,
        });
        assert_eq!(edit.error_bytes(), Some(23..24));
        // At the end of the text: on its last line, the character before
        // it underlined (the `;`).
        edit.error = Some(CError {
            message: "expected }".to_owned(),
            span: 28..28,
        });
        assert_eq!(edit.error_line(), Some(2));
        assert_eq!(edit.error_bytes(), Some(27..28));
        // At a line's end: the line's last character.
        edit.error = Some(CError {
            message: "expected }".to_owned(),
            span: 25..25,
        });
        assert_eq!(edit.error_bytes(), Some(24..25));
        edit.applied(StructTarget::Definition("struct s".to_owned()));
        assert!(!edit.changed());
    }

    #[test]
    fn d_cycles_through_the_widths_after_the_members_own() {
        assert_eq!(next_widths(1), ["uint16_t", "uint32_t", "uint64_t"]);
        assert_eq!(next_widths(4), ["uint64_t", "uint8_t", "uint16_t"]);
        assert_eq!(next_widths(8), ["uint8_t", "uint16_t", "uint32_t"]);
        // Another size (an array, a struct): from a byte up.
        assert_eq!(
            next_widths(16),
            ["uint8_t", "uint16_t", "uint32_t", "uint64_t"]
        );
    }

    #[test]
    fn a_new_struct_takes_a_free_name() {
        let names = vec!["struct struct_1".to_owned(), "int".to_owned()];
        assert!(new_struct(&names).starts_with("struct struct_2 {"));
        let names = vec!["enum enum_1".to_owned(), "enum enum_2".to_owned()];
        assert_eq!(
            new_enum(&names),
            "enum enum_3 : uint32_t {\n    ENUM_3_0 = 0,\n};"
        );
    }

    #[test]
    fn an_enumerations_gutter_has_each_constants_value_and_its_size() {
        let text = "typedef enum : int16_t {\n    BAD = -1,\n\n    OK, // the next\n    BIG = 0x7f00, MORE\n} status_t;";
        let layout = EnumLayout {
            key: "status_t".to_owned(),
            size: 2,
            flags: false,
            constants: vec![
                ("BAD".to_owned(), -1),
                ("OK".to_owned(), 0),
                ("BIG".to_owned(), 0x7f00),
                ("MORE".to_owned(), 0x7f01),
            ],
        };
        let edit = StructEdit::new(
            StructTarget::New(1),
            text.to_owned(),
            Ok(TypeLayout::Enum(layout)),
        );
        assert_eq!(
            edit.gutter(),
            [
                Gutter::default(),
                line("-1", ""),
                Gutter::default(),
                line("0", ""),
                // The first constant of a line.
                line("7F00", ""),
                line("0002", ""),
            ]
        );
    }
}
