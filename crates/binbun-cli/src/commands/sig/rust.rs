//! Rust symbol names as paths without crate hashes, so that two builds of
//! the standard library (whose crates' disambiguators and legacy hashes
//! differ) name a function alike: `_RNvNtCs1234_4core3fmt5write` and
//! `_ZN4core3fmt5write17h0123456789abcdefE` are both `core::fmt::write`.
//! Used to score matches against a program's symbols; the text is a key,
//! close to what demanglers print but not meant to be read as theirs.
//!
//! v0 manglings (RFC 2603) are parsed in full, with crate disambiguators
//! and the instantiating crate left out (closure and shim numbers stay:
//! they are not hashes); legacy ones lose their `h…` hash component.

use core::fmt::Write as _;

/// The path of a Rust mangling (`_R…` or legacy `_ZN…E`) without crate
/// hashes; `None` if `name` is neither or does not parse.
pub fn path(name: &str) -> Option<String> {
    if let Some(v0) = name.strip_prefix("_R") {
        let mut parser = Parser {
            bytes: v0.as_bytes(),
            at: 0,
            depth: 0,
        };
        // An encoding version (decimal) may come first.
        while parser.peek().is_some_and(|b| b.is_ascii_digit()) {
            parser.at += 1;
        }
        let mut out = String::new();
        parser.path(&mut out)?;
        return Some(out);
    }
    legacy(name)
}

/// A legacy mangling's components joined by `::`, its hash left out.
fn legacy(name: &str) -> Option<String> {
    let mut rest = name
        .strip_prefix("_ZN")
        .or_else(|| name.strip_prefix("__ZN"))?;
    let mut parts: Vec<&str> = Vec::new();
    while !rest.starts_with('E') {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let length: usize = rest.get(..digits)?.parse().ok()?;
        let part = rest.get(digits..digits + length)?;
        parts.push(part);
        rest = rest.get(digits + length..)?;
    }
    if parts.last().is_some_and(|last| {
        last.len() == 17
            && last.starts_with('h')
            && last.bytes().skip(1).all(|b| b.is_ascii_hexdigit())
    }) {
        parts.pop();
    }
    Some(parts.join("::"))
}

/// The deepest nesting a mangling may have.
const DEPTH: u32 = 256;

struct Parser<'s> {
    bytes: &'s [u8],
    at: usize,
    depth: u32,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    fn eat(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        if found {
            self.at += 1;
        }
        found
    }

    /// `<base-62-number>`: `_` is 0, digits then `_` their value plus 1.
    fn base62(&mut self) -> Option<u64> {
        if self.eat(b'_') {
            return Some(0);
        }
        let mut value: u64 = 0;
        loop {
            let byte = self.next()?;
            let digit = match byte {
                b'_' => return value.checked_add(1),
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'z' => byte - b'a' + 10,
                b'A'..=b'Z' => byte - b'A' + 36,
                _ => return None,
            };
            value = value.checked_mul(62)?.checked_add(u64::from(digit))?;
        }
    }

    /// `[<tag> <base-62-number>]`: 0 if absent, else the number plus 1.
    fn optional(&mut self, tag: u8) -> Option<u64> {
        if self.eat(tag) {
            self.base62()?.checked_add(1)
        } else {
            Some(0)
        }
    }

    fn decimal(&mut self) -> Option<usize> {
        let start = self.at;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.at += 1;
        }
        core::str::from_utf8(self.bytes.get(start..self.at)?)
            .ok()?
            .parse()
            .ok()
    }

    /// `<undisambiguated-identifier>`: its text (punycode kept as is).
    fn identifier(&mut self) -> Option<String> {
        let punycode = self.eat(b'u');
        let length = self.decimal()?;
        self.eat(b'_');
        let text = self.bytes.get(self.at..self.at + length)?;
        self.at += length;
        let text = core::str::from_utf8(text).ok()?;
        Some(if punycode {
            format!("punycode{{{text}}}")
        } else {
            text.to_owned()
        })
    }

    /// Runs `parse` at the position a back reference names, then returns.
    fn backref(
        &mut self,
        out: &mut String,
        parse: fn(&mut Self, &mut String) -> Option<()>,
    ) -> Option<()> {
        let start = self.at - 1;
        let target = usize::try_from(self.base62()?).ok()?;
        if target >= start {
            return None;
        }
        let resume = self.at;
        self.at = target;
        parse(self, out)?;
        self.at = resume;
        Some(())
    }

    fn enter(&mut self) -> Option<()> {
        self.depth += 1;
        (self.depth < DEPTH).then_some(())
    }

    fn path(&mut self, out: &mut String) -> Option<()> {
        self.enter()?;
        match self.next()? {
            b'C' => {
                // A crate: its disambiguator is the hash left out.
                self.optional(b's')?;
                out.push_str(&self.identifier()?);
            }
            b'M' => {
                self.optional(b's')?;
                self.path(&mut String::new())?;
                out.push('<');
                self.ty(out)?;
                out.push('>');
            }
            b'X' => {
                self.optional(b's')?;
                self.path(&mut String::new())?;
                out.push('<');
                self.ty(out)?;
                out.push_str(" as ");
                self.path(out)?;
                out.push('>');
            }
            b'Y' => {
                out.push('<');
                self.ty(out)?;
                out.push_str(" as ");
                self.path(out)?;
                out.push('>');
            }
            b'N' => {
                let namespace = self.next()?;
                self.path(out)?;
                let number = self.optional(b's')?;
                let name = self.identifier()?;
                out.push_str("::");
                if namespace.is_ascii_uppercase() {
                    let kind = match namespace {
                        b'C' => "closure",
                        b'S' => "shim",
                        _ => "",
                    };
                    out.push('{');
                    out.push_str(kind);
                    if !name.is_empty() {
                        out.push(':');
                        out.push_str(&name);
                    }
                    let _ = write!(out, "#{number}}}");
                } else {
                    out.push_str(&name);
                }
            }
            b'I' => {
                self.path(out)?;
                out.push('<');
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        out.push_str(", ");
                    }
                    first = false;
                    self.generic(out)?;
                }
                out.push('>');
            }
            b'B' => self.backref(out, Self::path)?,
            _ => return None,
        }
        self.depth -= 1;
        Some(())
    }

    fn generic(&mut self, out: &mut String) -> Option<()> {
        if self.eat(b'L') {
            self.base62()?;
            out.push_str("'_");
            Some(())
        } else if self.eat(b'K') {
            self.constant(out)
        } else {
            self.ty(out)
        }
    }

    #[expect(clippy::too_many_lines, reason = "one arm per type production")]
    fn ty(&mut self, out: &mut String) -> Option<()> {
        self.enter()?;
        let tag = self.peek()?;
        let basic = match tag {
            b'a' => Some("i8"),
            b'b' => Some("bool"),
            b'c' => Some("char"),
            b'd' => Some("f64"),
            b'e' => Some("str"),
            b'f' => Some("f32"),
            b'h' => Some("u8"),
            b'i' => Some("isize"),
            b'j' => Some("usize"),
            b'l' => Some("i32"),
            b'm' => Some("u32"),
            b'n' => Some("i128"),
            b'o' => Some("u128"),
            b's' => Some("i16"),
            b't' => Some("u16"),
            b'u' => Some("()"),
            b'v' => Some("..."),
            b'x' => Some("i64"),
            b'y' => Some("u64"),
            b'z' => Some("!"),
            b'p' => Some("_"),
            _ => None,
        };
        if let Some(name) = basic {
            self.at += 1;
            out.push_str(name);
            self.depth -= 1;
            return Some(());
        }
        match tag {
            b'R' | b'Q' => {
                self.at += 1;
                if self.eat(b'L') {
                    self.base62()?;
                }
                out.push_str(if tag == b'R' { "&" } else { "&mut " });
                self.ty(out)?;
            }
            b'P' | b'O' => {
                self.at += 1;
                out.push_str(if tag == b'P' { "*const " } else { "*mut " });
                self.ty(out)?;
            }
            b'A' => {
                self.at += 1;
                out.push('[');
                self.ty(out)?;
                out.push_str("; ");
                self.constant(out)?;
                out.push(']');
            }
            b'S' => {
                self.at += 1;
                out.push('[');
                self.ty(out)?;
                out.push(']');
            }
            b'T' => {
                self.at += 1;
                out.push('(');
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        out.push_str(", ");
                    }
                    first = false;
                    self.ty(out)?;
                }
                out.push(')');
            }
            b'F' => {
                self.at += 1;
                self.optional(b'G')?;
                if self.eat(b'U') {
                    out.push_str("unsafe ");
                }
                if self.eat(b'K') {
                    if self.eat(b'C') {
                        out.push_str("extern \"C\" ");
                    } else {
                        let abi = self.identifier()?;
                        let _ = write!(out, "extern \"{abi}\" ");
                    }
                }
                out.push_str("fn(");
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        out.push_str(", ");
                    }
                    first = false;
                    self.ty(out)?;
                }
                out.push_str(") -> ");
                self.ty(out)?;
            }
            b'D' => {
                self.at += 1;
                self.optional(b'G')?;
                out.push_str("dyn ");
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        out.push_str(" + ");
                    }
                    first = false;
                    self.path(out)?;
                    while self.eat(b'p') {
                        let name = self.identifier()?;
                        let _ = write!(out, "<{name} = ");
                        self.ty(out)?;
                        out.push('>');
                    }
                }
                if self.eat(b'L') {
                    self.base62()?;
                }
            }
            b'B' => {
                self.at += 1;
                self.backref(out, Self::ty)?;
            }
            _ => self.path(out)?,
        }
        self.depth -= 1;
        Some(())
    }

    fn constant(&mut self, out: &mut String) -> Option<()> {
        self.enter()?;
        match self.next()? {
            b'p' => out.push('_'),
            b'B' => self.backref(out, Self::constant)?,
            b'R' | b'Q' => {
                out.push('&');
                self.constant(out)?;
            }
            b'A' | b'T' => {
                out.push('[');
                while !self.eat(b'E') {
                    self.constant(out)?;
                    out.push(',');
                }
                out.push(']');
            }
            tag if tag.is_ascii_lowercase() => {
                // An integer, bool or char: its hexadecimal digits.
                let negative = self.eat(b'n');
                if negative {
                    out.push('-');
                }
                out.push_str("0x");
                loop {
                    let byte = self.next()?;
                    if byte == b'_' {
                        break;
                    }
                    out.push(char::from(byte));
                }
            }
            _ => return None,
        }
        self.depth -= 1;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::path;

    #[test]
    fn crate_hashes_are_left_out() {
        // One function of two toolchains' standard libraries.
        assert_eq!(
            path("_RNvNtCs9k3SxhrAWiO_3std2io5stdin").as_deref(),
            Some("std::io::stdin")
        );
        assert_eq!(
            path("_RNvNtCsAbC123_3std2io5stdin"),
            path("_RNvNtCs9k3SxhrAWiO_3std2io5stdin")
        );
        assert_eq!(
            path("_ZN4core3fmt5write17h0123456789abcdefE").as_deref(),
            Some("core::fmt::write")
        );
        assert_eq!(path("memcpy"), None);
    }

    #[test]
    fn generics_and_back_references_parse() {
        let name = "_RINvMNtNtCs6i54tJFfzR_5alloc2io5errorNtNtNtCsgxBkk5gSRhY_4core2io5error5Error3newReECs9k3SxhrAWiO_3std";
        assert_eq!(
            path(name).as_deref(),
            Some("<core::io::error::Error>::new<&str>")
        );
        // The same with other crate disambiguators: back references are
        // positions, so they move with the disambiguators' lengths.
        let other = "_RINvMNtNtCs1_5alloc2io5errorNtNtNtCs2_4core2io5error5Error3newReECs3_3std";
        assert_eq!(path(other), path(name));
        let closure = "_RNCNvCs1_3foo3bar0B3_";
        assert_eq!(path(closure).as_deref(), Some("foo::bar::{closure#0}"));
    }
}
