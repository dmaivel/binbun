//! One member of a struct or union edited from its uses (`N`, `Y`, `D`
//! on `p->name`): where it is declared in the struct's C ([`member_at`]),
//! the C with it renamed or retyped ([`MemberEdit`], [`edited`]), and
//! whether the struct's layout still holds after it ([`holds`]): a
//! member edited in place moves no other member and keeps the struct's
//! size, a retype keeps the member's size (a resize, the GUI's `D`, may
//! change it within the bytes up to the next member).

use std::fmt::Write as _;
use std::ops::Range;

use crate::types::{StructLayout, StructMember};

/// A change to one member of a struct or union.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MemberEdit {
    /// Its name is this (a C identifier).
    Rename(String),
    /// Its type is this C type (`uint32_t`, `char *`), as wide as it was.
    Retype(String),
    /// Its type is this C type, of any width the layout holds (the GUI's
    /// `D`).
    Resize(String),
}

/// Where a member is declared in a struct's C (byte ranges of the C).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberAt {
    /// Its declaration, without the `;`.
    pub declaration: Range<usize>,
    /// Its type: the declaration up to its name (`char *` of
    /// `char *name[4]`), trailing spaces left out.
    pub ty: Range<usize>,
    /// Its name.
    pub name: Range<usize>,
}

/// The member declarations of the struct or union C `c` defines (the
/// last braced body at the top level), in order, each with its name's
/// bytes (`None`: an anonymous struct or union, or several declarators
/// on one declaration). Comments are skipped.
pub fn members(c: &str) -> Vec<(Range<usize>, Option<Range<usize>>)> {
    let code = uncommented(c);
    let bytes = code.as_bytes();
    // The last top-level body.
    let mut depth = 0usize;
    let mut body = None;
    let mut open = 0;
    for (at, &byte) in bytes.iter().enumerate() {
        match byte {
            b'{' => {
                if depth == 0 {
                    open = at + 1;
                }
                depth += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    body = Some(open..at);
                }
            }
            _ => {}
        }
    }
    let Some(body) = body else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut nesting = 0usize;
    let mut start = body.start;
    for at in body {
        match bytes.get(at) {
            Some(b'{' | b'(' | b'[') => nesting += 1,
            Some(b'}' | b')' | b']') => nesting = nesting.saturating_sub(1),
            Some(b';') if nesting == 0 => {
                if let Some(declaration) = trimmed(&code, start..at) {
                    let name = declared(&code, declaration.clone());
                    out.push((declaration, name));
                }
                start = at + 1;
            }
            _ => {}
        }
    }
    out
}

/// Member `member` of the struct or union C `c` defines, if it declares
/// one of that name.
pub fn member_at(c: &str, member: &str) -> Option<MemberAt> {
    let (declaration, name) = members(c)
        .into_iter()
        .find(|(_, name)| name.as_ref().and_then(|n| c.get(n.clone())) == Some(member))?;
    let name = name?;
    let head = c.get(declaration.start..name.start)?;
    // A function pointer's name is in parentheses (`int (*f)(int)`): its
    // type is what comes before them (the return type).
    let head = head.split('(').next().unwrap_or(head).trim_end();
    Some(MemberAt {
        ty: declaration.start..declaration.start + head.len(),
        declaration,
        name,
    })
}

/// `c` with member `member` changed as `edit` says, the rest of the text
/// as it was; with the bytes the change wrote. `None`: no such member.
pub fn edited(c: &str, member: &str, edit: &MemberEdit) -> Option<(String, Range<usize>)> {
    let at = member_at(c, member)?;
    let (range, text) = match edit {
        MemberEdit::Rename(name) => (at.name, name.trim().to_owned()),
        MemberEdit::Retype(ty) | MemberEdit::Resize(ty) => {
            let ty = ty.trim();
            // A pointer's `*` stays against the name, as the printer
            // writes it; any other type is spaced from it.
            let glue = if ty.ends_with('*') { "" } else { " " };
            (at.ty.start..at.name.start, format!("{ty}{glue}"))
        }
    };
    let mut out = String::with_capacity(c.len() + text.len());
    out.push_str(c.get(..range.start)?);
    out.push_str(&text);
    out.push_str(c.get(range.end..)?);
    let written = range.start..range.start + text.trim_end().len();
    Some((out, written))
}

/// Whether the layout `after` (of the struct's C with member `member`
/// edited as `edit` says) still holds the struct `before`: no other
/// member moves or goes, the size stays, the member keeps its size (but
/// for a resize, which may take the unused bytes before the next member,
/// padding arrays included: [`absorb_padding`]), and a new name is no
/// other member's.
///
/// # Errors
///
/// Why not, in words.
pub fn holds(
    before: &StructLayout,
    after: &StructLayout,
    member: &str,
    edit: &MemberEdit,
) -> Result<(), String> {
    let key = &before.key;
    let index = before
        .members
        .iter()
        .position(|m| m.name == member)
        .ok_or_else(|| format!("{key} has no member {member}"))?;
    let old = before
        .members
        .get(index)
        .ok_or_else(|| format!("{key} has no member {member}"))?;
    if after.key != *key {
        return Err(format!("the edit must keep {key}"));
    }
    let name = match edit {
        MemberEdit::Rename(name) => name.as_str(),
        MemberEdit::Retype(_) | MemberEdit::Resize(_) => member,
    };
    let mut named = after.members.iter().filter(|m| m.name == name);
    let (Some(new), None) = (named.next(), named.next()) else {
        return Err(format!("{key} has a member {name} already"));
    };
    let bits = |m: &StructMember| m.bit_width.map_or(m.size * 8, u64::from);
    if matches!(edit, MemberEdit::Retype(_)) && bits(new) != bits(old) {
        return Err(format!(
            "{member} is {} bytes; this type is {}",
            old.size, new.size
        ));
    }
    let padding = |m: &&StructMember| m.name.starts_with("pad_");
    let union = key.starts_with("union ");
    if !union
        && let Some(next) = before
            .members
            .iter()
            .skip(index + 1)
            .filter(|m| !padding(m))
            .find(|m| m.bit_offset > old.bit_offset)
        && old.bit_offset + bits(new) > next.bit_offset
    {
        return Err(format!(
            "{member} would overlap {} at {:#x}",
            next.name,
            next.bit_offset / 8
        ));
    }
    let kept = |layout: &StructLayout| layout.members.iter().filter(|m| !padding(m)).count();
    if kept(after) != kept(before) {
        return Err(format!("the edit must keep {key}'s members"));
    }
    for was in before.members.iter().filter(|m| !padding(m)) {
        let now = if was.name == member {
            Some(new)
        } else {
            after.members.iter().find(|m| m.name == was.name)
        };
        let Some(now) = now else {
            return Err(format!("the edit must keep {key}'s member {}", was.name));
        };
        if now.bit_offset != was.bit_offset {
            return Err(format!(
                "{} would move from {:#x} to {:#x}",
                was.name,
                was.bit_offset / 8,
                now.bit_offset / 8
            ));
        }
    }
    if after.size != before.size {
        return Err(format!(
            "{} would be {:#x} bytes, not {:#x}",
            key, after.size, before.size
        ));
    }
    Ok(())
}

/// `c` (the struct `before` lays out, with member `member` resized: its
/// size now `size` bytes) with the padding array after the member
/// (`uint8_t pad_4[4];`, as the C prints unused bytes) giving the member
/// the bytes it grew into: shortened and renamed for its new offset, or
/// left out where it is all taken. `None` where the member did not grow
/// into a padding array, or past it.
pub fn absorb_padding(c: &str, before: &StructLayout, member: &str, size: u64) -> Option<String> {
    let index = before.members.iter().position(|m| m.name == member)?;
    let old = before.members.get(index)?;
    let pad = before.members.get(index + 1)?;
    if !pad.name.starts_with("pad_") || old.bit_width.is_some() || pad.bit_offset % 8 != 0 {
        return None;
    }
    let end = old.bit_offset / 8 + size;
    let (pad_start, pad_end) = (pad.bit_offset / 8, pad.bit_offset / 8 + pad.size);
    if end <= pad_start || end > pad_end {
        return None;
    }
    let at = member_at(c, &pad.name)?;
    let mut out = String::with_capacity(c.len());
    if end == pad_end {
        // All taken: its line goes (the line before keeps its end).
        let semicolon = at.declaration.end + c.get(at.declaration.end..)?.find(';')? + 1;
        let line_start = c.get(..at.declaration.start)?.rfind('\n');
        let alone = line_start.is_some_and(|n| {
            c.get(n + 1..at.declaration.start)
                .is_some_and(|t| t.trim().is_empty())
        }) && c
            .get(semicolon..)?
            .split('\n')
            .next()
            .is_some_and(|t| t.trim().is_empty());
        let (from, to) = match line_start {
            Some(n) if alone => {
                let rest = c.get(semicolon..)?;
                (n, semicolon + rest.find('\n').unwrap_or(rest.len()))
            }
            Some(_) | None => (at.declaration.start, semicolon),
        };
        out.push_str(c.get(..from)?);
        out.push_str(c.get(to..)?);
    } else {
        let ty = c.get(at.declaration.start..at.name.start)?;
        out.push_str(c.get(..at.declaration.start)?);
        let _ = write!(out, "{ty}pad_{end:x}[{}]", pad_end - end);
        out.push_str(c.get(at.declaration.end..)?);
    }
    Some(out)
}

/// Whether `name` is a C identifier (ASCII letters, digits and `_`, not
/// starting with a digit).
pub(crate) fn is_identifier(name: &str) -> bool {
    name.starts_with(|c: char| c == '_' || c.is_ascii_alphabetic())
        && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// `c` with its comments' bytes blanked (positions kept).
fn uncommented(c: &str) -> String {
    let mut out = String::with_capacity(c.len());
    let mut rest = c;
    while !rest.is_empty() {
        let line = rest.find("//").map(|at| (at, false));
        let block = rest.find("/*").map(|at| (at, true));
        let Some((start, is_block)) = line.into_iter().chain(block).min() else {
            out.push_str(rest);
            break;
        };
        let end = if is_block {
            rest.get(start + 2..)
                .and_then(|t| t.find("*/"))
                .map_or(rest.len(), |n| start + 2 + n + 2)
        } else {
            rest.get(start..)
                .and_then(|t| t.find('\n'))
                .map_or(rest.len(), |n| start + n)
        };
        out.push_str(rest.get(..start).unwrap_or(""));
        let comment = rest.get(start..end).unwrap_or("");
        // Blanked byte for byte, so positions stay.
        for ch in comment.chars() {
            if ch == '\n' {
                out.push('\n');
            } else {
                out.extend(std::iter::repeat_n(' ', ch.len_utf8()));
            }
        }
        rest = rest.get(end..).unwrap_or("");
    }
    out
}

/// `range` of `code` without its leading and trailing whitespace; `None`
/// if nothing is left.
fn trimmed(code: &str, range: Range<usize>) -> Option<Range<usize>> {
    let text = code.get(range.clone())?;
    let start = range.start + (text.len() - text.trim_start().len());
    let end = range.end - (text.len() - text.trim_end().len());
    (start < end).then_some(start..end)
}

/// The name declaration `range` of `code` declares: its declarator's
/// identifier (a function pointer's in its first parentheses; before an
/// array's `[` or a bit-field's `:`), after the braces of a nested struct
/// or union; `None` for an anonymous one or several declarators.
fn declared(code: &str, range: Range<usize>) -> Option<Range<usize>> {
    let text = code.get(range.clone())?;
    let (offset, declarator) = if let Some(close) = text.rfind('}') {
        (close + 1, text.get(close + 1..)?)
    } else if let Some(at) = text.find("(*") {
        let inner = text.get(at + 2..)?;
        (at + 2, inner.get(..inner.find(')')?)?)
    } else {
        let end = text.find(['[', ':']).unwrap_or(text.len());
        (0, text.get(..end)?)
    };
    if declarator.contains(',') {
        return None;
    }
    let declarator = declarator.trim_end();
    let start = declarator
        .char_indices()
        .rev()
        .take_while(|&(_, c)| c.is_ascii_alphanumeric() || c == '_')
        .last()
        .map(|(at, _)| at)?;
    let name = declarator.get(start..)?;
    if name.starts_with(|c: char| c.is_ascii_digit())
        || matches!(name, "struct" | "union" | "enum")
        || start == 0 && !text.contains('}') && !text.contains("(*")
    {
        // A lone word declares nothing (a type with no name).
        return None;
    }
    let at = range.start + offset + start;
    Some(at..at + name.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAIR: &str = "struct pair {\n    char *first; // the key\n    int64_t second[2];\n    unsigned bits : 3;\n    int (*f)(int);\n    union {\n        int x;\n    };\n    struct {\n        int y;\n    } inner;\n};";

    fn names(c: &str) -> Vec<Option<&str>> {
        members(c)
            .into_iter()
            .map(|(_, name)| name.and_then(|n| c.get(n)))
            .collect()
    }

    #[test]
    fn members_are_found_by_their_declarators() {
        assert_eq!(
            names(PAIR),
            [
                Some("first"),
                Some("second"),
                Some("bits"),
                Some("f"),
                None,
                Some("inner")
            ]
        );
        // One line, as a user may write it; a comment's `;` is no member.
        assert_eq!(
            names("struct frame { void *top; /* a; b */ long argc; };"),
            [Some("top"), Some("argc")]
        );
        let at = member_at(PAIR, "second").unwrap();
        assert_eq!(PAIR.get(at.ty.clone()), Some("int64_t"));
        assert_eq!(PAIR.get(at.declaration), Some("int64_t second[2]"));
        let at = member_at(PAIR, "f").unwrap();
        assert_eq!(PAIR.get(at.ty), Some("int"));
        assert_eq!(member_at(PAIR, "x"), None, "not the struct's own");
        assert_eq!(member_at(PAIR, "y"), None);
    }

    #[test]
    fn an_edit_rewrites_only_the_members_bytes() {
        let c = "struct pair {\n    char *first;\n    int64_t second;\n};";
        let (renamed, at) = edited(c, "first", &MemberEdit::Rename("key".to_owned())).unwrap();
        assert_eq!(
            renamed,
            "struct pair {\n    char *key;\n    int64_t second;\n};"
        );
        assert_eq!(renamed.get(at), Some("key"));
        let (retyped, at) = edited(c, "first", &MemberEdit::Retype("uint64_t".to_owned())).unwrap();
        assert_eq!(
            retyped,
            "struct pair {\n    uint64_t first;\n    int64_t second;\n};"
        );
        assert_eq!(retyped.get(at), Some("uint64_t"));
        let (retyped, _) = edited(
            c,
            "second",
            &MemberEdit::Retype(" const char * ".to_owned()),
        )
        .unwrap();
        assert!(retyped.contains("    const char *second;"), "{retyped}");
        assert_eq!(
            edited(c, "third", &MemberEdit::Rename("x".to_owned())),
            None
        );
    }

    fn layout(size: u64, members: &[(&str, u64, u64)]) -> StructLayout {
        StructLayout {
            key: "struct pair".to_owned(),
            size,
            members: members
                .iter()
                .map(|&(name, offset, size)| StructMember {
                    name: name.to_owned(),
                    bit_offset: offset * 8,
                    size,
                    bit_width: None,
                })
                .collect(),
        }
    }

    #[test]
    fn a_layout_holds_only_where_nothing_else_moves() {
        let before = layout(16, &[("first", 0, 4), ("second", 8, 8)]);
        let retype = MemberEdit::Retype("float".to_owned());
        assert_eq!(holds(&before, &before.clone(), "first", &retype), Ok(()));
        // Another width: refused by Y, taken by D within the hole.
        let wider = layout(16, &[("first", 0, 8), ("second", 8, 8)]);
        assert!(holds(&before, &wider, "first", &retype).is_err());
        let resize = MemberEdit::Resize("int64_t".to_owned());
        assert_eq!(holds(&before, &wider, "first", &resize), Ok(()));
        // Past the next member: an overlap, whatever the parser made of it.
        let past = layout(24, &[("first", 0, 16), ("second", 16, 8)]);
        assert!(holds(&before, &past, "first", &resize).is_err_and(|why| why.contains("overlap")));
        // The last member grown into no hole: the struct would grow.
        let grown = layout(24, &[("first", 0, 4), ("second", 8, 16)]);
        let resize_last = MemberEdit::Resize("x".to_owned());
        assert!(holds(&before, &grown, "second", &resize_last).is_err());
        let renamed = layout(16, &[("second", 0, 4), ("second", 8, 8)]);
        let clash = MemberEdit::Rename("second".to_owned());
        assert!(holds(&before, &renamed, "first", &clash).is_err());
        let free = layout(16, &[("key", 0, 4), ("second", 8, 8)]);
        assert_eq!(
            holds(
                &before,
                &free,
                "first",
                &MemberEdit::Rename("key".to_owned())
            ),
            Ok(())
        );
        assert!(holds(&before, &before, "third", &retype).is_err());
    }

    #[test]
    fn a_member_grown_into_padding_takes_its_bytes() {
        let c = "struct s {\n    uint8_t a;\n    uint8_t pad_1[7];\n    int64_t b;\n};";
        let before = layout(16, &[("a", 0, 1), ("pad_1", 1, 7), ("b", 8, 8)]);
        // To 4 bytes: the padding is 3 bytes from 4.
        assert_eq!(
            absorb_padding(c, &before, "a", 4).as_deref(),
            Some("struct s {\n    uint8_t a;\n    uint8_t pad_4[4];\n    int64_t b;\n};")
        );
        // To 8: it is gone, its line with it.
        assert_eq!(
            absorb_padding(c, &before, "a", 8).as_deref(),
            Some("struct s {\n    uint8_t a;\n    int64_t b;\n};")
        );
        // Past it, not grown, no padding after: nothing to do.
        assert_eq!(absorb_padding(c, &before, "a", 9), None);
        assert_eq!(absorb_padding(c, &before, "a", 1), None);
        assert_eq!(absorb_padding(c, &before, "b", 16), None);
    }
}
