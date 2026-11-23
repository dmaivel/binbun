//! Theme files: CSS in a strict subset, read without a browser's
//! leniency.
//!
//! A file is an optional `@import "<theme>";` first (its base theme,
//! overridden by what follows), then `:root { … }` blocks of custom
//! properties only (`--name: value;`). A value is one of: a hex colour
//! (3, 4, 6 or 8 digits), `rgb()`/`rgba()`, `hsl()`/`hsla()`, a named
//! colour, `transparent`, `var(--x)` with an optional fallback,
//! `color-mix(in srgb, …)`, a keyword or a quoted string. Anything else
//! is a [`Diagnostic`] naming the file, line and column; nothing is
//! skipped silently.
//!
//! [`parse`] reads one file into a [`Sheet`]; a [`Resolver`] evaluates the
//! properties of an import chain as CSS does: the last declaration wins,
//! `var()` is resolved late against the whole chain (an importing file
//! that redefines a palette variable recolours the base's roles that use
//! it), and a declaration that cannot be used falls back to the one it
//! overrides, after its error is reported.
//!
//! This module uses nothing but `std`: the fuzz target includes it by
//! path.

use std::collections::HashMap;
use std::fmt;

/// A problem in a theme file, where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// The file, as given to [`parse`].
    pub file: String,
    /// The line, from 1.
    pub line: u32,
    /// The column in characters, from 1.
    pub column: u32,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}",
            self.file, self.line, self.column, self.message
        )
    }
}

/// A place in a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pos {
    /// The line, from 1.
    pub line: u32,
    /// The column in characters, from 1.
    pub column: u32,
}

/// A token of the subset.
#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    /// A name directly followed by `(`.
    Function(String),
    Hash(String),
    Number(f64, Unit),
    Str(String),
    At(String),
    Comma,
    Slash,
    Colon,
    Semicolon,
    Close,
    LeftBrace,
    RightBrace,
    /// Any other character, kept so its place can be named.
    Delim(char),
}

/// A number's unit.
#[derive(Clone, Debug, PartialEq)]
enum Unit {
    None,
    Percent,
    Dimension(String),
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ident(name) => write!(f, "`{name}`"),
            Self::Function(name) => write!(f, "`{name}(`"),
            Self::Hash(name) => write!(f, "`#{name}`"),
            Self::Number(..) => f.write_str("a number"),
            Self::Str(_) => f.write_str("a string"),
            Self::At(name) => write!(f, "`@{name}`"),
            Self::Comma => f.write_str("`,`"),
            Self::Slash => f.write_str("`/`"),
            Self::Colon => f.write_str("`:`"),
            Self::Semicolon => f.write_str("`;`"),
            Self::Close => f.write_str("`)`"),
            Self::LeftBrace => f.write_str("`{`"),
            Self::RightBrace => f.write_str("`}`"),
            Self::Delim(c) => write!(f, "`{c}`"),
        }
    }
}

/// One `--name: value;` as written.
#[derive(Clone, Debug, PartialEq)]
struct Declaration {
    name: String,
    pos: Pos,
    value: Vec<(Tok, Pos)>,
}

/// One theme file, parsed.
#[derive(Clone, Debug, PartialEq)]
pub struct Sheet {
    /// The file, as given to [`parse`].
    pub file: String,
    /// The `@import`'s theme or file name, and where it is.
    pub import: Option<(String, Pos)>,
    declarations: Vec<Declaration>,
    /// What [`parse`] could not read.
    pub diagnostics: Vec<Diagnostic>,
}

impl Sheet {
    /// The custom properties the file declares, each once, in order.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = Vec::new();
        for d in &self.declarations {
            if !names.contains(&d.name.as_str()) {
                names.push(&d.name);
            }
        }
        names
    }

    fn error(&mut self, pos: Pos, message: impl Into<String>) {
        self.diagnostics.push(diagnostic(&self.file, pos, message));
    }
}

fn diagnostic(file: &str, pos: Pos, message: impl Into<String>) -> Diagnostic {
    Diagnostic {
        file: file.to_owned(),
        line: pos.line,
        column: pos.column,
        message: message.into(),
    }
}

/// Splits `text` into tokens, reporting what is not one.
struct Lexer<'a> {
    chars: Vec<char>,
    at: usize,
    pos: Pos,
    sheet: &'a mut Sheet,
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || !c.is_ascii()
}

fn is_name(c: char) -> bool {
    is_name_start(c) || c.is_ascii_digit() || c == '-'
}

impl Lexer<'_> {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.at += 1;
        if c == '\n' {
            self.pos.line = self.pos.line.saturating_add(1);
            self.pos.column = 1;
        } else {
            self.pos.column = self.pos.column.saturating_add(1);
        }
        Some(c)
    }

    fn name(&mut self) -> String {
        let mut name = String::new();
        while let Some(c) = self.peek(0).filter(|&c| is_name(c)) {
            name.push(c);
            self.bump();
        }
        name
    }

    /// Whether an identifier starts here: a name start, or `-` before a
    /// name start or another `-`.
    fn ident_starts(&self) -> bool {
        match self.peek(0) {
            Some('-') => self.peek(1).is_some_and(|c| is_name_start(c) || c == '-'),
            Some(c) => is_name_start(c),
            None => false,
        }
    }

    fn number_starts(&self) -> bool {
        let digit = |k| self.peek(k).is_some_and(|c: char| c.is_ascii_digit());
        match self.peek(0) {
            Some('+' | '-') => digit(1) || (self.peek(1) == Some('.') && digit(2)),
            Some('.') => digit(1),
            Some(c) => c.is_ascii_digit(),
            None => false,
        }
    }

    fn number(&mut self) -> Tok {
        let mut text = String::new();
        if let Some(sign) = self.peek(0).filter(|c| matches!(c, '+' | '-')) {
            text.push(sign);
            self.bump();
        }
        let digits = |lexer: &mut Self, text: &mut String| {
            while let Some(c) = lexer.peek(0).filter(char::is_ascii_digit) {
                text.push(c);
                lexer.bump();
            }
        };
        digits(self, &mut text);
        if self.peek(0) == Some('.') && self.peek(1).is_some_and(|c| c.is_ascii_digit()) {
            text.push('.');
            self.bump();
            digits(self, &mut text);
        }
        if matches!(self.peek(0), Some('e' | 'E'))
            && (self.peek(1).is_some_and(|c| c.is_ascii_digit())
                || (matches!(self.peek(1), Some('+' | '-'))
                    && self.peek(2).is_some_and(|c| c.is_ascii_digit())))
        {
            for _ in 0..2 {
                if let Some(c) = self.bump() {
                    text.push(c);
                }
            }
            digits(self, &mut text);
        }
        let value = text.parse::<f64>().unwrap_or(f64::NAN);
        let unit = if self.peek(0) == Some('%') {
            self.bump();
            Unit::Percent
        } else if self.ident_starts() {
            Unit::Dimension(self.name_with_dash())
        } else {
            Unit::None
        };
        Tok::Number(value, unit)
    }

    fn name_with_dash(&mut self) -> String {
        let mut name = String::new();
        while let Some(c) = self.peek(0).filter(|&c| c == '-') {
            name.push(c);
            self.bump();
        }
        name.push_str(&self.name());
        name
    }

    fn string(&mut self, quote: char, start: Pos) -> Option<Tok> {
        self.bump();
        let mut text = String::new();
        loop {
            match self.bump() {
                Some(c) if c == quote => return Some(Tok::Str(text)),
                Some('\\') => {
                    self.sheet
                        .error(start, "escapes in strings are not supported");
                    return None;
                }
                Some('\n') | None => {
                    self.sheet.error(start, "unterminated string");
                    return None;
                }
                Some(c) => text.push(c),
            }
        }
    }

    /// Skips whitespace and comments; false at an unterminated comment.
    fn skip_blank(&mut self) -> bool {
        loop {
            match (self.peek(0), self.peek(1)) {
                (Some(c), _) if c.is_whitespace() => {
                    self.bump();
                }
                (Some('/'), Some('*')) => {
                    let start = self.pos;
                    self.bump();
                    self.bump();
                    loop {
                        match (self.peek(0), self.peek(1)) {
                            (Some('*'), Some('/')) => {
                                self.bump();
                                self.bump();
                                break;
                            }
                            (Some(_), _) => {
                                self.bump();
                            }
                            (None, _) => {
                                self.sheet.error(start, "unterminated comment");
                                return false;
                            }
                        }
                    }
                }
                _ => return true,
            }
        }
    }

    fn tokens(mut self) -> Vec<(Tok, Pos)> {
        let mut out = Vec::new();
        while self.skip_blank() {
            let start = self.pos;
            let Some(c) = self.peek(0) else {
                break;
            };
            let tok = if self.number_starts() {
                self.number()
            } else if self.ident_starts() {
                let name = self.name_with_dash();
                if self.peek(0) == Some('(') {
                    self.bump();
                    Tok::Function(name)
                } else {
                    Tok::Ident(name)
                }
            } else {
                match c {
                    '"' | '\'' => match self.string(c, start) {
                        Some(tok) => tok,
                        None => continue,
                    },
                    '#' => {
                        self.bump();
                        Tok::Hash(self.name())
                    }
                    '@' => {
                        self.bump();
                        Tok::At(self.name_with_dash())
                    }
                    _ => {
                        self.bump();
                        match c {
                            ',' => Tok::Comma,
                            '/' => Tok::Slash,
                            ':' => Tok::Colon,
                            ';' => Tok::Semicolon,
                            ')' => Tok::Close,
                            '{' => Tok::LeftBrace,
                            '}' => Tok::RightBrace,
                            other => Tok::Delim(other),
                        }
                    }
                }
            };
            out.push((tok, start));
        }
        out
    }
}

/// Reads `text`, the file `file` (named in its diagnostics). Never fails:
/// what it cannot read is in [`Sheet::diagnostics`].
pub fn parse(file: &str, text: &str) -> Sheet {
    let mut sheet = Sheet {
        file: file.to_owned(),
        import: None,
        declarations: Vec::new(),
        diagnostics: Vec::new(),
    };
    let lexer = Lexer {
        chars: text.chars().collect(),
        at: 0,
        pos: Pos { line: 1, column: 1 },
        sheet: &mut sheet,
    };
    let tokens = lexer.tokens();
    Parser {
        tokens: &tokens,
        at: 0,
        sheet: &mut sheet,
    }
    .sheet();
    sheet
}

struct Parser<'a> {
    tokens: &'a [(Tok, Pos)],
    at: usize,
    sheet: &'a mut Sheet,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&(Tok, Pos)> {
        self.tokens.get(self.at)
    }

    fn end(&self) -> Pos {
        self.tokens
            .last()
            .map_or(Pos { line: 1, column: 1 }, |(_, p)| *p)
    }

    /// Skips past the end of the statement at the cursor: its `;`, or its
    /// `{ … }` block.
    fn skip_statement(&mut self) {
        let mut depth = 0usize;
        while let Some((tok, _)) = self.tokens.get(self.at) {
            self.at += 1;
            if *tok == Tok::Semicolon && depth == 0 {
                return;
            } else if *tok == Tok::LeftBrace {
                depth += 1;
            } else if *tok == Tok::RightBrace {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return;
                }
            }
        }
    }

    fn sheet(&mut self) {
        let mut seen_rule = false;
        while let Some((tok, pos)) = self.peek().cloned() {
            match tok {
                Tok::At(name) if name.eq_ignore_ascii_case("import") => {
                    self.at += 1;
                    self.import(pos, seen_rule);
                }
                Tok::At(name) => {
                    self.sheet
                        .error(pos, format!("`@{name}` is not supported; only `@import`"));
                    self.skip_statement();
                }
                Tok::Colon
                    if matches!(
                        self.tokens.get(self.at + 1),
                        Some((Tok::Ident(root), p))
                            if root.eq_ignore_ascii_case("root")
                                && p.line == pos.line
                                && p.column == pos.column.saturating_add(1)
                    ) && matches!(self.tokens.get(self.at + 2), Some((Tok::LeftBrace, _))) =>
                {
                    self.at += 3;
                    seen_rule = true;
                    self.block();
                }
                other @ (Tok::Ident(_)
                | Tok::Function(_)
                | Tok::Hash(_)
                | Tok::Number(..)
                | Tok::Str(_)
                | Tok::Comma
                | Tok::Slash
                | Tok::Colon
                | Tok::Semicolon
                | Tok::Close
                | Tok::LeftBrace
                | Tok::RightBrace
                | Tok::Delim(_)) => {
                    self.sheet.error(
                        pos,
                        format!(
                            "expected `:root {{`, found {other}; only `:root` blocks are allowed"
                        ),
                    );
                    self.skip_statement();
                }
            }
        }
    }

    fn import(&mut self, at: Pos, seen_rule: bool) {
        let name = match self.peek().cloned() {
            Some((Tok::Str(name), _)) => {
                self.at += 1;
                name
            }
            Some((other, pos)) => {
                self.sheet.error(
                    pos,
                    format!("expected the imported theme's name in quotes, found {other}"),
                );
                self.skip_statement();
                return;
            }
            None => {
                self.sheet
                    .error(at, "expected the imported theme's name in quotes");
                return;
            }
        };
        match self.peek() {
            Some((Tok::Semicolon, _)) => self.at += 1,
            Some((other, pos)) => {
                let (other, pos) = (other.clone(), *pos);
                self.sheet
                    .error(pos, format!("expected `;` after `@import`, found {other}"));
                self.skip_statement();
                return;
            }
            None => {
                let end = self.end();
                self.sheet.error(end, "expected `;` after `@import`");
                return;
            }
        }
        if seen_rule || self.sheet.import.is_some() {
            self.sheet.error(
                at,
                "`@import` must come first, once, before any `:root` block",
            );
        } else if name.trim().is_empty() {
            self.sheet.error(at, "`@import` names no theme");
        } else {
            self.sheet.import = Some((name, at));
        }
    }

    /// The declarations of a `:root` block, after its `{`.
    fn block(&mut self) {
        loop {
            let Some((tok, pos)) = self.peek().cloned() else {
                let end = self.end();
                self.sheet.error(end, "missing `}` at the end of the file");
                return;
            };
            match tok {
                Tok::RightBrace => {
                    self.at += 1;
                    return;
                }
                Tok::Semicolon => self.at += 1,
                Tok::Ident(name)
                    if name.starts_with("--")
                        && matches!(self.tokens.get(self.at + 1), Some((Tok::Colon, _))) =>
                {
                    self.at += 2;
                    if self.declaration(name, pos) {
                        return;
                    }
                }
                Tok::Ident(name) if !name.starts_with("--") => {
                    self.sheet.error(
                        pos,
                        format!(
                            "`{name}` is not a custom property; only `--name: value;` is allowed"
                        ),
                    );
                    if self.skip_declaration() {
                        return;
                    }
                }
                other @ (Tok::Ident(_)
                | Tok::Function(_)
                | Tok::Hash(_)
                | Tok::Number(..)
                | Tok::Str(_)
                | Tok::At(_)
                | Tok::Comma
                | Tok::Slash
                | Tok::Colon
                | Tok::Close
                | Tok::LeftBrace
                | Tok::Delim(_)) => {
                    self.sheet
                        .error(pos, format!("expected `--name: value;`, found {other}"));
                    if self.skip_declaration() {
                        return;
                    }
                }
            }
        }
    }

    /// Skips to the end of a declaration; true when that is the block's
    /// end (its `}` taken).
    fn skip_declaration(&mut self) -> bool {
        while let Some((tok, _)) = self.tokens.get(self.at) {
            self.at += 1;
            if *tok == Tok::Semicolon {
                return false;
            }
            if *tok == Tok::RightBrace {
                return true;
            }
        }
        false
    }

    /// A declaration's value, after its `:`; true when it ended the block.
    fn declaration(&mut self, name: String, pos: Pos) -> bool {
        let start = self.at;
        let mut closed = false;
        while let Some((tok, _)) = self.tokens.get(self.at) {
            if *tok == Tok::Semicolon {
                break;
            }
            if *tok == Tok::RightBrace {
                closed = true;
                break;
            }
            self.at += 1;
        }
        let value = self.tokens.get(start..self.at).unwrap_or_default().to_vec();
        if self.at < self.tokens.len() {
            self.at += 1;
        }
        if value.is_empty() {
            self.sheet.error(pos, format!("`{name}` has no value"));
        } else {
            self.sheet
                .declarations
                .push(Declaration { name, pos, value });
        }
        closed
    }
}

/// What a property must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A colour.
    Color,
    /// One of these keywords (compared ignoring ASCII case).
    Keyword(&'static [&'static str]),
    /// A quoted string.
    Text,
    /// A number from 0 to 1 (`0.7`, or `70%`).
    Fraction,
    /// Anything the subset can write (a palette variable).
    Any,
}

/// A resolved value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `0xRRGGBBAA`.
    Color(u32),
    /// A keyword, in lower case.
    Keyword(String),
    /// A quoted string's text.
    Text(String),
    /// A number; a percentage as a fraction (`70%` is 0.7).
    Number(f64),
}

/// A colour while it is computed: straight-alpha RGBA, each 0 to 1.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Rgba([f64; 4]);

impl Rgba {
    fn pack(self) -> u32 {
        let [r, g, b, a] = self.0;
        (byte(r) << 24) | (byte(g) << 16) | (byte(b) << 8) | byte(a)
    }

    fn unpack(c: u32) -> Self {
        let channel = |shift: u32| f64::from((c >> shift) & 0xff) / 255.0;
        Self([channel(24), channel(16), channel(8), channel(0)])
    }
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to 0..=255 first"
)]
fn byte(x: f64) -> u32 {
    let x = if x.is_nan() { 0.0 } else { x.clamp(0.0, 1.0) };
    (x * 255.0).round() as u32
}

/// Why a reference has no value.
enum Missing {
    Undefined,
    Invalid,
    Cycle,
    TooDeep,
}

/// How deep `var()` references and nested functions may go.
const MAX_DEPTH: usize = 32;

/// Evaluates the properties of an import chain, base first.
#[derive(Debug)]
pub struct Resolver<'a> {
    layers: &'a [Sheet],
    kind: fn(&str) -> Kind,
    memo: HashMap<String, Option<Value>>,
    active: Vec<String>,
    diagnostics: Vec<Diagnostic>,
}

/// An error at a place, before it is given its file.
type Fault = (Pos, String);

impl<'a> Resolver<'a> {
    /// A resolver over `layers` (the base theme first, the file itself
    /// last); `kind` says what each property must be.
    pub fn new(layers: &'a [Sheet], kind: fn(&str) -> Kind) -> Self {
        Self {
            layers,
            kind,
            memo: HashMap::new(),
            active: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    /// Property `name`'s value: its last usable declaration's, reporting
    /// each one after it that could not be used. `None` when it has none.
    pub fn get(&mut self, name: &str) -> Option<Value> {
        self.lookup(name).ok()
    }

    /// Resolves every declared property not resolved yet, so an unused
    /// palette variable's error is reported too, then gives the
    /// diagnostics: the files' own, then the resolver's.
    pub fn finish(mut self) -> Vec<Diagnostic> {
        let layers = self.layers;
        for sheet in layers {
            for name in sheet.names() {
                let _ = self.lookup(name);
            }
        }
        let mut all: Vec<Diagnostic> = layers
            .iter()
            .flat_map(|s| s.diagnostics.iter().cloned())
            .collect();
        all.append(&mut self.diagnostics);
        all
    }

    fn lookup(&mut self, name: &str) -> Result<Value, Missing> {
        if let Some(memo) = self.memo.get(name) {
            return memo.clone().ok_or(Missing::Invalid);
        }
        if self.active.iter().any(|a| a == name) {
            return Err(Missing::Cycle);
        }
        if self.active.len() >= MAX_DEPTH {
            return Err(Missing::TooDeep);
        }
        let layers = self.layers;
        let mut candidates = layers
            .iter()
            .rev()
            .flat_map(|sheet| {
                sheet
                    .declarations
                    .iter()
                    .rev()
                    .filter(move |d| d.name == name)
                    .map(move |d| (sheet.file.as_str(), d))
            })
            .peekable();
        if candidates.peek().is_none() {
            return Err(Missing::Undefined);
        }
        self.active.push(name.to_owned());
        let kind = (self.kind)(name);
        let mut found = None;
        for (file, declaration) in candidates {
            match self.declared(declaration, kind) {
                Ok(value) => {
                    found = Some(value);
                    break;
                }
                Err((pos, message)) => self.diagnostics.push(diagnostic(file, pos, message)),
            }
        }
        self.active.pop();
        self.memo.insert(name.to_owned(), found.clone());
        found.ok_or(Missing::Invalid)
    }

    /// One declaration's value, checked against `kind`.
    fn declared(&mut self, d: &Declaration, kind: Kind) -> Result<Value, Fault> {
        let mut at = 0;
        let value = self.component(&d.value, &mut at, 0)?;
        if let Some((tok, pos)) = d.value.get(at) {
            return Err((
                *pos,
                format!("unexpected {tok} after the value of `{}`", d.name),
            ));
        }
        let wrong = |expected: String| {
            let found = match &value {
                Value::Color(_) => "a colour".to_owned(),
                Value::Keyword(k) => format!("`{k}`"),
                Value::Text(_) => "a string".to_owned(),
                Value::Number(n) => format!("{n}"),
            };
            Err((
                d.pos,
                format!("`{}` must be {expected}, found {found}", d.name),
            ))
        };
        match (kind, &value) {
            (Kind::Any, _) | (Kind::Color, Value::Color(_)) | (Kind::Text, Value::Text(_)) => {
                Ok(value)
            }
            (Kind::Fraction, Value::Number(n)) if (0.0..=1.0).contains(n) => Ok(value),
            (Kind::Fraction, _) => wrong("a number from 0 to 1".to_owned()),
            (Kind::Keyword(names), Value::Keyword(k)) if names.contains(&k.as_str()) => Ok(value),
            (Kind::Color, _) => wrong("a colour".to_owned()),
            (Kind::Text, _) => wrong("a quoted string".to_owned()),
            (Kind::Keyword(names), _) => {
                let quoted: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
                wrong(format!("one of {}", quoted.join(", ")))
            }
        }
    }

    /// One value at `tokens[*at]`, moving `at` past it.
    fn component(
        &mut self,
        tokens: &[(Tok, Pos)],
        at: &mut usize,
        depth: usize,
    ) -> Result<Value, Fault> {
        let Some((tok, pos)) = tokens.get(*at).cloned() else {
            let end = tokens
                .last()
                .map_or(Pos { line: 1, column: 1 }, |(_, p)| *p);
            return Err((end, "expected a value".to_owned()));
        };
        if depth > MAX_DEPTH {
            return Err((pos, "the value is nested too deeply".to_owned()));
        }
        *at += 1;
        match tok {
            Tok::Hash(digits) => hex(&digits).map(Value::Color).ok_or_else(|| {
                (
                    pos,
                    format!("`#{digits}` is not a hex colour of 3, 4, 6 or 8 digits"),
                )
            }),
            Tok::Ident(name) => {
                let lower = name.to_ascii_lowercase();
                Ok(named(&lower).map_or(Value::Keyword(lower), Value::Color))
            }
            Tok::Str(text) => Ok(Value::Text(text)),
            Tok::Function(name) => {
                let lower = name.to_ascii_lowercase();
                let value = match lower.as_str() {
                    "var" => self.var(tokens, at, depth, pos)?,
                    "rgb" | "rgba" => Value::Color(rgb(tokens, at, pos)?.pack()),
                    "hsl" | "hsla" => Value::Color(hsl(tokens, at, pos)?.pack()),
                    "color-mix" => Value::Color(self.mix(tokens, at, depth, pos)?.pack()),
                    _ => {
                        return Err((pos, format!("`{name}()` is not supported")));
                    }
                };
                Ok(value)
            }
            Tok::Number(n, Unit::None) => Ok(Value::Number(n)),
            Tok::Number(n, Unit::Percent) => Ok(Value::Number(n / 100.0)),
            Tok::Number(_, Unit::Dimension(unit)) => {
                Err((pos, format!("`{unit}`: only plain numbers and percentages")))
            }
            other @ (Tok::At(_)
            | Tok::Comma
            | Tok::Slash
            | Tok::Colon
            | Tok::Semicolon
            | Tok::Close
            | Tok::LeftBrace
            | Tok::RightBrace
            | Tok::Delim(_)) => Err((pos, format!("expected a value, found {other}"))),
        }
    }

    fn var(
        &mut self,
        tokens: &[(Tok, Pos)],
        at: &mut usize,
        depth: usize,
        at_pos: Pos,
    ) -> Result<Value, Fault> {
        let (name, name_pos) = match tokens.get(*at) {
            Some((Tok::Ident(name), pos)) if name.starts_with("--") => (name.clone(), *pos),
            Some((other, pos)) => {
                return Err((*pos, format!("expected `--name` in `var()`, found {other}")));
            }
            None => return Err((at_pos, "unclosed `var(`".to_owned())),
        };
        *at += 1;
        let fallback = match tokens.get(*at) {
            Some((Tok::Comma, _)) => {
                *at += 1;
                Some(self.component(tokens, at, depth + 1)?)
            }
            _ => None,
        };
        close(tokens, at, at_pos, "var")?;
        match self.lookup(&name) {
            Ok(value) => Ok(value),
            Err(why) => fallback.ok_or_else(|| {
                let message = match why {
                    Missing::Undefined => format!("`{name}` is not defined"),
                    Missing::Invalid => format!("`{name}` has no usable value"),
                    Missing::Cycle => format!("`{name}` refers to itself"),
                    Missing::TooDeep => format!("`{name}`: too many nested `var()` references"),
                };
                (name_pos, message)
            }),
        }
    }

    fn color(
        &mut self,
        tokens: &[(Tok, Pos)],
        at: &mut usize,
        depth: usize,
    ) -> Result<Rgba, Fault> {
        let pos = tokens.get(*at).map(|(_, p)| *p);
        match self.component(tokens, at, depth + 1)? {
            Value::Color(c) => Ok(Rgba::unpack(c)),
            Value::Keyword(k) => Err((
                pos.unwrap_or(Pos { line: 1, column: 1 }),
                format!("`{k}` is not a colour"),
            )),
            Value::Text(_) => Err((
                pos.unwrap_or(Pos { line: 1, column: 1 }),
                "a string is not a colour".to_owned(),
            )),
            Value::Number(_) => Err((
                pos.unwrap_or(Pos { line: 1, column: 1 }),
                "a number is not a colour".to_owned(),
            )),
        }
    }

    /// `color-mix(in srgb, A p?, B q?)`, after `color-mix(`.
    fn mix(
        &mut self,
        tokens: &[(Tok, Pos)],
        at: &mut usize,
        depth: usize,
        at_pos: Pos,
    ) -> Result<Rgba, Fault> {
        match (tokens.get(*at), tokens.get(*at + 1)) {
            (Some((Tok::Ident(i), _)), Some((Tok::Ident(space), _)))
                if i.eq_ignore_ascii_case("in") && space.eq_ignore_ascii_case("srgb") =>
            {
                *at += 2;
            }
            (_, _) => {
                let pos = tokens.get(*at).map_or(at_pos, |(_, p)| *p);
                return Err((pos, "only `color-mix(in srgb, …)` is supported".to_owned()));
            }
        }
        let mut sides = [(Rgba([0.0; 4]), None::<f64>); 2];
        for side in &mut sides {
            expect(tokens, at, &Tok::Comma, at_pos, "`,`")?;
            let mut percent = percentage(tokens, at)?;
            let colour = self.color(tokens, at, depth)?;
            if percent.is_none() {
                percent = percentage(tokens, at)?;
            }
            *side = (colour, percent);
        }
        close(tokens, at, at_pos, "color-mix")?;
        let [(left, p), (right, q)] = sides;
        let (p, q) = match (p, q) {
            (None, None) => (0.5, 0.5),
            (Some(p), None) => (p, 1.0 - p),
            (None, Some(q)) => (1.0 - q, q),
            (Some(p), Some(q)) => (p, q),
        };
        let sum = p + q;
        if sum <= 0.0 {
            return Err((
                at_pos,
                "`color-mix()`'s percentages add up to zero".to_owned(),
            ));
        }
        let (p, q) = (p / sum, q / sum);
        let multiplier = sum.min(1.0);
        let [.., left_alpha] = left.0;
        let [.., right_alpha] = right.0;
        // Premultiplied, as CSS mixes.
        let alpha = left_alpha * p + right_alpha * q;
        let mut rgb = left.0.into_iter().zip(right.0).map(|(x, y)| {
            if alpha > 0.0 {
                (x * left_alpha * p + y * right_alpha * q) / alpha
            } else {
                0.0
            }
        });
        let mut next = || rgb.next().unwrap_or(0.0);
        Ok(Rgba([next(), next(), next(), alpha * multiplier]))
    }
}

/// A `0%`–`100%` at the cursor, as 0 to 1, if there is one.
fn percentage(tokens: &[(Tok, Pos)], at: &mut usize) -> Result<Option<f64>, Fault> {
    match tokens.get(*at) {
        Some((Tok::Number(n, Unit::Percent), pos)) => {
            if !(0.0..=100.0).contains(n) {
                return Err((
                    *pos,
                    "a `color-mix()` percentage must be from 0% to 100%".to_owned(),
                ));
            }
            *at += 1;
            Ok(Some(n / 100.0))
        }
        _ => Ok(None),
    }
}

fn expect(
    tokens: &[(Tok, Pos)],
    at: &mut usize,
    want: &Tok,
    at_pos: Pos,
    what: &str,
) -> Result<(), Fault> {
    match tokens.get(*at) {
        Some((tok, _)) if tok == want => {
            *at += 1;
            Ok(())
        }
        Some((other, pos)) => Err((*pos, format!("expected {what}, found {other}"))),
        None => Err((at_pos, format!("expected {what}"))),
    }
}

fn close(tokens: &[(Tok, Pos)], at: &mut usize, at_pos: Pos, function: &str) -> Result<(), Fault> {
    match tokens.get(*at) {
        Some((Tok::Close, _)) => {
            *at += 1;
            Ok(())
        }
        Some((other, pos)) => Err((
            *pos,
            format!("expected `)` to close `{function}(`, found {other}"),
        )),
        None => Err((at_pos, format!("unclosed `{function}(`"))),
    }
}

/// The numbers of `rgb()`/`hsl()` after the function's `(`: three or
/// four, comma-separated throughout or space-separated with `/` before
/// the alpha.
fn arguments(
    tokens: &[(Tok, Pos)],
    at: &mut usize,
    at_pos: Pos,
    function: &str,
) -> Result<Vec<(f64, Unit, Pos)>, Fault> {
    let mut out = Vec::new();
    let mut commas = None;
    loop {
        match tokens.get(*at) {
            Some((Tok::Number(n, unit), pos)) => {
                out.push((*n, unit.clone(), *pos));
                *at += 1;
            }
            Some((Tok::Close, _)) if out.len() >= 3 => {
                *at += 1;
                return Ok(out);
            }
            Some((other, pos)) => {
                return Err((
                    *pos,
                    format!("expected a number in `{function}()`, found {other}"),
                ));
            }
            None => return Err((at_pos, format!("unclosed `{function}(`"))),
        }
        let separator = tokens.get(*at).map(|(t, p)| (t.clone(), *p));
        match separator {
            Some((Tok::Close, _)) if out.len() >= 3 => {
                *at += 1;
                return Ok(out);
            }
            Some((Tok::Close, pos)) => {
                return Err((
                    pos,
                    format!(
                        "`{function}()` needs three values and an optional alpha, found {}",
                        out.len()
                    ),
                ));
            }
            Some((Tok::Comma, pos)) => {
                if commas == Some(false) || out.len() >= 4 {
                    return Err((pos, format!("unexpected `,` in `{function}()`")));
                }
                commas = Some(true);
                *at += 1;
            }
            Some((Tok::Slash, pos)) => {
                if commas == Some(true) || out.len() != 3 {
                    return Err((pos, format!("unexpected `/` in `{function}()`")));
                }
                *at += 1;
            }
            Some((Tok::Number(..), pos)) => {
                if commas == Some(true) || out.len() >= 3 {
                    return Err((pos, format!("unexpected number in `{function}()`")));
                }
                commas = Some(false);
            }
            Some((other, pos)) => {
                return Err((
                    pos,
                    format!("expected `,` or `)` in `{function}()`, found {other}"),
                ));
            }
            None => return Err((at_pos, format!("unclosed `{function}(`"))),
        }
        if out.len() > 4 {
            return Err((at_pos, format!("too many values in `{function}()`")));
        }
    }
}

fn alpha(argument: Option<&(f64, Unit, Pos)>, function: &str) -> Result<f64, Fault> {
    match argument {
        None => Ok(1.0),
        Some((n, Unit::None, _)) => Ok(n.clamp(0.0, 1.0)),
        Some((n, Unit::Percent, _)) => Ok((n / 100.0).clamp(0.0, 1.0)),
        Some((_, Unit::Dimension(unit), pos)) => {
            Err((*pos, format!("`{unit}` is not an alpha in `{function}()`")))
        }
    }
}

fn rgb(tokens: &[(Tok, Pos)], at: &mut usize, at_pos: Pos) -> Result<Rgba, Fault> {
    let args = arguments(tokens, at, at_pos, "rgb")?;
    let channel = |k: usize| match args.get(k) {
        Some((n, Unit::None, _)) => Ok((n / 255.0).clamp(0.0, 1.0)),
        Some((n, Unit::Percent, _)) => Ok((n / 100.0).clamp(0.0, 1.0)),
        Some((_, Unit::Dimension(unit), pos)) => {
            Err((*pos, format!("`{unit}` is not a channel in `rgb()`")))
        }
        None => Err((at_pos, "`rgb()` needs three channels".to_owned())),
    };
    Ok(Rgba([
        channel(0)?,
        channel(1)?,
        channel(2)?,
        alpha(args.get(3), "rgb")?,
    ]))
}

fn hsl(tokens: &[(Tok, Pos)], at: &mut usize, at_pos: Pos) -> Result<Rgba, Fault> {
    let args = arguments(tokens, at, at_pos, "hsl")?;
    let hue = match args.first() {
        Some((n, Unit::None, _)) => *n,
        Some((n, Unit::Dimension(unit), pos)) => match unit.to_ascii_lowercase().as_str() {
            "deg" => *n,
            "grad" => n * 0.9,
            "rad" => n.to_degrees(),
            "turn" => n * 360.0,
            _ => return Err((*pos, format!("`{unit}` is not an angle in `hsl()`"))),
        },
        Some((_, Unit::Percent, pos)) => {
            return Err((*pos, "a hue is an angle, not a percentage".to_owned()));
        }
        None => return Err((at_pos, "`hsl()` needs a hue".to_owned())),
    };
    let fraction = |k: usize| match args.get(k) {
        Some((n, Unit::None | Unit::Percent, _)) => Ok((n / 100.0).clamp(0.0, 1.0)),
        Some((_, Unit::Dimension(unit), pos)) => {
            Err((*pos, format!("`{unit}` is not a percentage in `hsl()`")))
        }
        None => Err((at_pos, "`hsl()` needs saturation and lightness".to_owned())),
    };
    let (saturation, lightness) = (fraction(1)?, fraction(2)?);
    let opacity = alpha(args.get(3), "hsl")?;
    let hue = if hue.is_finite() {
        hue.rem_euclid(360.0)
    } else {
        0.0
    };
    // CSS Color 4's `hslToRgb`.
    let channel = |n: f64| {
        let k = (n + hue / 30.0) % 12.0;
        let chroma = saturation * lightness.min(1.0 - lightness);
        lightness - chroma * (k - 3.0).min(9.0 - k).clamp(-1.0, 1.0)
    };
    Ok(Rgba([channel(0.0), channel(8.0), channel(4.0), opacity]))
}

/// `#rgb`, `#rgba`, `#rrggbb` or `#rrggbbaa` (without the `#`).
fn hex(digits: &str) -> Option<u32> {
    if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let value = u32::from_str_radix(digits, 16).ok()?;
    let double = |nibbles: u32, count: u32| {
        (0..count).rev().fold(0u32, |acc, k| {
            let n = (nibbles >> (k * 4)) & 0xf;
            (acc << 8) | (n << 4) | n
        })
    };
    match digits.len() {
        3 => Some((double(value, 3) << 8) | 0xff),
        4 => Some(double(value, 4)),
        6 => Some((value << 8) | 0xff),
        8 => Some(value),
        _ => None,
    }
}

/// A CSS named colour (lower case), `transparent` included.
fn named(name: &str) -> Option<u32> {
    if name == "transparent" {
        return Some(0);
    }
    NAMED
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()
        .and_then(|i| NAMED.get(i))
        .map(|(_, rgb)| (rgb << 8) | 0xff)
}

/// CSS Color 4's named colours, sorted.
#[expect(
    clippy::unreadable_literal,
    reason = "written as CSS writes them, six hex digits"
)]
const NAMED: &[(&str, u32)] = &[
    ("aliceblue", 0xf0f8ff),
    ("antiquewhite", 0xfaebd7),
    ("aqua", 0x00ffff),
    ("aquamarine", 0x7fffd4),
    ("azure", 0xf0ffff),
    ("beige", 0xf5f5dc),
    ("bisque", 0xffe4c4),
    ("black", 0x000000),
    ("blanchedalmond", 0xffebcd),
    ("blue", 0x0000ff),
    ("blueviolet", 0x8a2be2),
    ("brown", 0xa52a2a),
    ("burlywood", 0xdeb887),
    ("cadetblue", 0x5f9ea0),
    ("chartreuse", 0x7fff00),
    ("chocolate", 0xd2691e),
    ("coral", 0xff7f50),
    ("cornflowerblue", 0x6495ed),
    ("cornsilk", 0xfff8dc),
    ("crimson", 0xdc143c),
    ("cyan", 0x00ffff),
    ("darkblue", 0x00008b),
    ("darkcyan", 0x008b8b),
    ("darkgoldenrod", 0xb8860b),
    ("darkgray", 0xa9a9a9),
    ("darkgreen", 0x006400),
    ("darkgrey", 0xa9a9a9),
    ("darkkhaki", 0xbdb76b),
    ("darkmagenta", 0x8b008b),
    ("darkolivegreen", 0x556b2f),
    ("darkorange", 0xff8c00),
    ("darkorchid", 0x9932cc),
    ("darkred", 0x8b0000),
    ("darksalmon", 0xe9967a),
    ("darkseagreen", 0x8fbc8f),
    ("darkslateblue", 0x483d8b),
    ("darkslategray", 0x2f4f4f),
    ("darkslategrey", 0x2f4f4f),
    ("darkturquoise", 0x00ced1),
    ("darkviolet", 0x9400d3),
    ("deeppink", 0xff1493),
    ("deepskyblue", 0x00bfff),
    ("dimgray", 0x696969),
    ("dimgrey", 0x696969),
    ("dodgerblue", 0x1e90ff),
    ("firebrick", 0xb22222),
    ("floralwhite", 0xfffaf0),
    ("forestgreen", 0x228b22),
    ("fuchsia", 0xff00ff),
    ("gainsboro", 0xdcdcdc),
    ("ghostwhite", 0xf8f8ff),
    ("gold", 0xffd700),
    ("goldenrod", 0xdaa520),
    ("gray", 0x808080),
    ("green", 0x008000),
    ("greenyellow", 0xadff2f),
    ("grey", 0x808080),
    ("honeydew", 0xf0fff0),
    ("hotpink", 0xff69b4),
    ("indianred", 0xcd5c5c),
    ("indigo", 0x4b0082),
    ("ivory", 0xfffff0),
    ("khaki", 0xf0e68c),
    ("lavender", 0xe6e6fa),
    ("lavenderblush", 0xfff0f5),
    ("lawngreen", 0x7cfc00),
    ("lemonchiffon", 0xfffacd),
    ("lightblue", 0xadd8e6),
    ("lightcoral", 0xf08080),
    ("lightcyan", 0xe0ffff),
    ("lightgoldenrodyellow", 0xfafad2),
    ("lightgray", 0xd3d3d3),
    ("lightgreen", 0x90ee90),
    ("lightgrey", 0xd3d3d3),
    ("lightpink", 0xffb6c1),
    ("lightsalmon", 0xffa07a),
    ("lightseagreen", 0x20b2aa),
    ("lightskyblue", 0x87cefa),
    ("lightslategray", 0x778899),
    ("lightslategrey", 0x778899),
    ("lightsteelblue", 0xb0c4de),
    ("lightyellow", 0xffffe0),
    ("lime", 0x00ff00),
    ("limegreen", 0x32cd32),
    ("linen", 0xfaf0e6),
    ("magenta", 0xff00ff),
    ("maroon", 0x800000),
    ("mediumaquamarine", 0x66cdaa),
    ("mediumblue", 0x0000cd),
    ("mediumorchid", 0xba55d3),
    ("mediumpurple", 0x9370db),
    ("mediumseagreen", 0x3cb371),
    ("mediumslateblue", 0x7b68ee),
    ("mediumspringgreen", 0x00fa9a),
    ("mediumturquoise", 0x48d1cc),
    ("mediumvioletred", 0xc71585),
    ("midnightblue", 0x191970),
    ("mintcream", 0xf5fffa),
    ("mistyrose", 0xffe4e1),
    ("moccasin", 0xffe4b5),
    ("navajowhite", 0xffdead),
    ("navy", 0x000080),
    ("oldlace", 0xfdf5e6),
    ("olive", 0x808000),
    ("olivedrab", 0x6b8e23),
    ("orange", 0xffa500),
    ("orangered", 0xff4500),
    ("orchid", 0xda70d6),
    ("palegoldenrod", 0xeee8aa),
    ("palegreen", 0x98fb98),
    ("paleturquoise", 0xafeeee),
    ("palevioletred", 0xdb7093),
    ("papayawhip", 0xffefd5),
    ("peachpuff", 0xffdab9),
    ("peru", 0xcd853f),
    ("pink", 0xffc0cb),
    ("plum", 0xdda0dd),
    ("powderblue", 0xb0e0e6),
    ("purple", 0x800080),
    ("rebeccapurple", 0x663399),
    ("red", 0xff0000),
    ("rosybrown", 0xbc8f8f),
    ("royalblue", 0x4169e1),
    ("saddlebrown", 0x8b4513),
    ("salmon", 0xfa8072),
    ("sandybrown", 0xf4a460),
    ("seagreen", 0x2e8b57),
    ("seashell", 0xfff5ee),
    ("sienna", 0xa0522d),
    ("silver", 0xc0c0c0),
    ("skyblue", 0x87ceeb),
    ("slateblue", 0x6a5acd),
    ("slategray", 0x708090),
    ("slategrey", 0x708090),
    ("snow", 0xfffafa),
    ("springgreen", 0x00ff7f),
    ("steelblue", 0x4682b4),
    ("tan", 0xd2b48c),
    ("teal", 0x008080),
    ("thistle", 0xd8bfd8),
    ("tomato", 0xff6347),
    ("turquoise", 0x40e0d0),
    ("violet", 0xee82ee),
    ("wheat", 0xf5deb3),
    ("white", 0xffffff),
    ("whitesmoke", 0xf5f5f5),
    ("yellow", 0xffff00),
    ("yellowgreen", 0x9acd32),
];

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn kinds(name: &str) -> Kind {
        match name {
            "--name" => Kind::Text,
            "--appearance" => Kind::Keyword(&["dark", "light"]),
            "--any" => Kind::Any,
            "--alpha" => Kind::Fraction,
            _ => Kind::Color,
        }
    }

    /// The colour of `--c` in `text`, and every diagnostic.
    fn one(text: &str) -> (Option<Value>, Vec<String>) {
        let sheets = [parse("t.css", text)];
        let mut r = Resolver::new(&sheets, kinds);
        let value = r.get("--c");
        let diagnostics = r.finish().iter().map(ToString::to_string).collect();
        (value, diagnostics)
    }

    fn colour(value: &str) -> u32 {
        let (value, diagnostics) = one(&format!(":root {{ --c: {value}; }}"));
        assert!(diagnostics.is_empty(), "{value:?}: {diagnostics:?}");
        match value {
            Some(Value::Color(c)) => c,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn colour_syntaxes() {
        assert_eq!(colour("#abc"), 0xaabb_ccff);
        assert_eq!(colour("#abcd"), 0xaabb_ccdd);
        assert_eq!(colour("#A1B2C3"), 0xa1b2_c3ff);
        assert_eq!(colour("#a1b2c3d4"), 0xa1b2_c3d4);
        assert_eq!(colour("rgb(255 0 128)"), 0xff00_80ff);
        assert_eq!(colour("rgb(255, 0, 128)"), 0xff00_80ff);
        assert_eq!(colour("rgba(255, 0, 128, 0.5)"), 0xff00_8080);
        assert_eq!(colour("rgb(100% 0% 50% / 25%)"), 0xff00_8040);
        // Out of range clamps, as CSS does.
        assert_eq!(colour("rgb(300 -5 0)"), 0xff00_00ff);
        assert_eq!(colour("hsl(0 100% 50%)"), 0xff00_00ff);
        assert_eq!(colour("hsl(120deg, 100%, 25%)"), 0x0080_00ff);
        assert_eq!(colour("hsla(0.5turn 100% 50% / 0.5)"), 0x00ff_ff80);
        assert_eq!(colour("RebeccaPurple"), 0x6633_99ff);
        assert_eq!(colour("transparent"), 0);
    }

    #[test]
    fn color_mix_follows_the_spec() {
        assert_eq!(colour("color-mix(in srgb, red, blue)"), 0x8000_80ff);
        assert_eq!(colour("color-mix(in srgb, red 25%, blue)"), 0x4000_bfff);
        assert_eq!(colour("color-mix(in srgb, red, 75% blue)"), 0x4000_bfff);
        // Mixing with transparent keeps the colour and scales the alpha
        // (premultiplied).
        assert_eq!(
            colour("color-mix(in srgb, #74ade8 19%, transparent)"),
            0x74ad_e830
        );
        // Percentages under 100% in total scale the alpha.
        assert_eq!(colour("color-mix(in srgb, red 25%, blue 25%)"), 0x8000_8080);
        assert_eq!(
            colour("color-mix(in srgb, red 100%, blue 100%)"),
            0x8000_80ff
        );
    }

    #[test]
    fn var_resolves_late_across_the_import_chain() {
        let base = parse(
            "base.css",
            ":root { --blue: #0000ff; --c: var(--blue); --d: var(--missing, red); }",
        );
        let top = parse("top.css", "@import \"Base\";\n:root { --blue: #00ff00; }");
        assert_eq!(top.import.as_ref().map(|(n, _)| n.as_str()), Some("Base"));
        let layers = [base, top];
        let mut r = Resolver::new(&layers, kinds);
        assert_eq!(r.get("--c"), Some(Value::Color(0x00ff_00ff)));
        assert_eq!(r.get("--d"), Some(Value::Color(0xff00_00ff)));
        assert_eq!(r.finish(), Vec::new());
    }

    #[test]
    fn an_unusable_declaration_falls_back_to_the_one_it_overrides() {
        let base = parse("base.css", ":root { --c: #111111; }");
        let top = parse("top.css", "@import \"b\";\n:root {\n  --c: rgb(1 2);\n}");
        let layers = [base, top];
        let mut r = Resolver::new(&layers, kinds);
        assert_eq!(r.get("--c"), Some(Value::Color(0x1111_11ff)));
        let d = r.finish();
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(
            (d[0].file.as_str(), d[0].line, d[0].column),
            ("top.css", 3, 15)
        );
        assert!(d[0].message.contains("rgb"), "{}", d[0].message);
    }

    #[test]
    fn errors_name_file_line_and_column() {
        let cases: &[(&str, (u32, u32), &str)] = &[
            (":root { --c: #12345; }", (1, 14), "hex colour"),
            (":root {\n  color: red;\n}", (2, 3), "not a custom property"),
            ("body { --c: red; }", (1, 1), "only `:root`"),
            (":root { --c: red !important; }", (1, 18), "unexpected `!`"),
            (
                ":root { --c: lab(50 0 0); }",
                (1, 14),
                "`lab()` is not supported",
            ),
            (
                ":root { --c: color-mix(in oklch, red, blue); }",
                (1, 24),
                "in srgb",
            ),
            (
                ":root { --c: var(--nope); }",
                (1, 18),
                "`--nope` is not defined",
            ),
            (":root { --c: var(--c); }", (1, 18), "refers to itself"),
            (":root { --c: dark; }", (1, 9), "must be a colour"),
            (":root { --appearance: dim; }", (1, 9), "`dark`, `light`"),
            (":root { --name: red; }", (1, 9), "quoted string"),
            (
                ":root { --c: red; } @import \"x\";",
                (1, 21),
                "must come first",
            ),
            ("@media screen { }", (1, 1), "`@media` is not supported"),
            (":root { --c: red;", (1, 17), "missing `}`"),
            ("/* never closed", (1, 1), "unterminated comment"),
            (":root { --c: \"open; }", (1, 14), "unterminated string"),
            (":root { --c: ; }", (1, 9), "has no value"),
            (":root { --c: rgb(1, 2 3); }", (1, 23), "unexpected number"),
            (
                ":root { --c: color-mix(in srgb, red 0%, blue 0%); }",
                (1, 14),
                "zero",
            ),
            (
                ":root { --c: color-mix(in srgb, red 150%, blue); }",
                (1, 37),
                "0% to 100%",
            ),
        ];
        for &(text, (line, column), wanted) in cases {
            let (_, diagnostics) = one(text);
            let place = format!("t.css:{line}:{column}: ");
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.starts_with(&place) && d.contains(wanted)),
                "{text}: wanted {wanted:?} at {line}:{column}, got {diagnostics:?}"
            );
        }
    }

    #[test]
    fn every_named_colour_is_found() {
        for &(name, rgb) in NAMED {
            assert_eq!(named(name), Some((rgb << 8) | 0xff), "{name}");
        }
        assert_eq!(colour("YellowGreen"), 0x9acd_32ff);
        assert_eq!(named("bluish"), None);
    }

    #[test]
    fn unused_palette_errors_are_reported_and_later_rules_still_read() {
        let (value, diagnostics) = one(
            ":root { --unused: #zz; }\nbody { x: y; }\n:root { --c: var(--other); --other: navy; }",
        );
        assert_eq!(value, Some(Value::Color(0x0000_80ff)));
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
        assert!(diagnostics[0].starts_with("t.css:2:1:"), "{diagnostics:?}");
        assert!(diagnostics[1].starts_with("t.css:1:19:"), "{diagnostics:?}");
    }

    #[test]
    fn the_last_declaration_wins_within_a_file() {
        assert_eq!(colour("red; --c: blue"), 0x0000_ffff);
    }

    #[test]
    fn deep_nesting_and_long_chains_are_errors_not_overflows() {
        let deep = format!(
            ":root {{ --c: {}red{}; }}",
            "color-mix(in srgb, ".repeat(100),
            ", blue)".repeat(100)
        );
        let (value, diagnostics) = one(&deep);
        assert_eq!(value, None);
        assert!(
            diagnostics.iter().any(|d| d.contains("nested too deeply")),
            "{diagnostics:?}"
        );

        let mut chain = String::from(":root { --c: var(--v0);");
        for k in 0..200 {
            let _ = write!(chain, " --v{k}: var(--v{});", k + 1);
        }
        chain.push_str(" --v200: red; }");
        let (value, diagnostics) = one(&chain);
        assert_eq!(value, None);
        assert!(
            diagnostics.iter().any(|d| d.contains("too many nested")),
            "{diagnostics:?}"
        );
    }

    #[test]
    fn names_strings_and_keywords() {
        let fraction = |value: &str| {
            let sheets = [parse("t.css", &format!(":root {{ --alpha: {value}; }}"))];
            let mut r = Resolver::new(&sheets, kinds);
            let got = r.get("--alpha");
            (got, r.finish().len())
        };
        assert_eq!(fraction("0.7"), (Some(Value::Number(0.7)), 0));
        assert_eq!(fraction("60%"), (Some(Value::Number(0.6)), 0));
        assert_eq!(fraction("1"), (Some(Value::Number(1.0)), 0));
        // Out of range, a colour, a unit: errors, no value.
        assert_eq!(fraction("1.5"), (None, 1));
        assert_eq!(fraction("red"), (None, 1));
        assert_eq!(fraction("3px"), (None, 1));
        // A number is no colour.
        let (value, diagnostics) = one(":root { --c: color-mix(in srgb, 0.5, red); }");
        assert_eq!(value, None);
        assert!(
            diagnostics.iter().any(|d| d.contains("not a colour")),
            "{diagnostics:?}"
        );

        let sheets = [parse(
            "t.css",
            ":root { --name: 'Mine'; --appearance: LIGHT; --any: whatever; }",
        )];
        let mut r = Resolver::new(&sheets, kinds);
        assert_eq!(r.get("--name"), Some(Value::Text("Mine".to_owned())));
        assert_eq!(
            r.get("--appearance"),
            Some(Value::Keyword("light".to_owned()))
        );
        assert_eq!(r.get("--any"), Some(Value::Keyword("whatever".to_owned())));
        assert_eq!(r.finish(), Vec::new());
    }
}
