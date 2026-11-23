//! Python as the console colours it: a small tokenizer finding keywords,
//! builtins, the names a `def` or `class` makes and the names called,
//! decorators, strings (prefixes and triple quotes), numbers, comments,
//! operators and punctuation. Plain names are left to the text's colour.

use std::ops::Range;

/// What a token is, for its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A keyword of control flow (`if`, `for`, `return`...).
    ControlKeyword,
    /// Another keyword (`def`, `import`, `and`...).
    Keyword,
    /// `True`, `False`, `None`.
    Constant,
    /// A builtin function, type or exception (`len`, `int`, `ValueError`).
    Builtin,
    /// A function's name: defined (`def f`) or called (`f(`).
    Function,
    /// A class's name where `class` defines it.
    Class,
    /// A decorator (`@property`).
    Decorator,
    /// A string literal, its prefix and quotes included.
    String,
    /// A number literal.
    Number,
    /// A comment.
    Comment,
    /// An operator.
    Operator,
    /// Punctuation: brackets, commas, dots, colons, semicolons.
    Punctuation,
}

/// A token: its bytes in the text and its kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// Its bytes.
    pub range: Range<usize>,
    /// Its kind.
    pub kind: Kind,
}

const CONTROL: &[&str] = &[
    "if", "elif", "else", "for", "while", "break", "continue", "return", "try", "except",
    "finally", "raise", "with", "yield", "await", "async", "match", "case",
];

const KEYWORDS: &[&str] = &[
    "and", "as", "assert", "class", "def", "del", "from", "global", "import", "in", "is", "lambda",
    "nonlocal", "not", "or", "pass",
];

const CONSTANTS: &[&str] = &["True", "False", "None"];

const BUILTINS: &[&str] = &[
    "abs",
    "all",
    "any",
    "ascii",
    "bin",
    "bool",
    "breakpoint",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "compile",
    "complex",
    "delattr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "eval",
    "exec",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "help",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "locals",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "property",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
    "self",
    "cls",
    "Exception",
    "BaseException",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "EOFError",
    "ImportError",
    "IndexError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "NameError",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "RecursionError",
    "RuntimeError",
    "StopIteration",
    "SyntaxError",
    "SystemExit",
    "TimeoutError",
    "TypeError",
    "UnicodeError",
    "ValueError",
    "ZeroDivisionError",
    "NotImplemented",
    "Ellipsis",
];

/// The tokens of `code` that have a colour of their own, in order.
pub fn tokens(code: &str) -> Vec<Token> {
    let mut lexer = Lexer {
        code,
        at: 0,
        tokens: Vec::new(),
        defines: None,
    };
    lexer.run();
    lexer.tokens
}

struct Lexer<'a> {
    code: &'a str,
    at: usize,
    tokens: Vec<Token>,
    /// The name after `def` or `class` is what it defines.
    defines: Option<Kind>,
}

impl Lexer<'_> {
    fn peek(&self) -> Option<char> {
        self.code.get(self.at..)?.chars().next()
    }

    fn peek_at(&self, at: usize) -> Option<char> {
        self.code.get(at..)?.chars().next()
    }

    fn push(&mut self, start: usize, kind: Kind) {
        self.tokens.push(Token {
            range: start..self.at,
            kind,
        });
    }

    fn run(&mut self) {
        while let Some(c) = self.peek() {
            let start = self.at;
            if c == '#' {
                self.at = self.code[start..]
                    .find('\n')
                    .map_or(self.code.len(), |end| start + end);
                self.push(start, Kind::Comment);
            } else if let Some(quote_at) = self.string_start() {
                self.string(start, quote_at);
            } else if c.is_ascii_digit()
                || (c == '.' && self.peek_at(start + 1).is_some_and(|d| d.is_ascii_digit()))
            {
                self.number(start);
            } else if c == '_' || c.is_alphabetic() {
                self.name(start);
            } else if c == '@' && self.at_line_start(start) {
                self.at += 1;
                while let Some(n) = self.peek() {
                    if n == '_' || n == '.' || n.is_alphanumeric() {
                        self.at += n.len_utf8();
                    } else {
                        break;
                    }
                }
                self.push(start, Kind::Decorator);
            } else if "()[]{},;.:".contains(c) {
                self.at += 1;
                // `:=` and `->` are operators.
                if c == ':' && self.peek() == Some('=') {
                    self.at += 1;
                    self.push(start, Kind::Operator);
                } else {
                    self.push(start, Kind::Punctuation);
                }
            } else if "+-*/%=<>!&|^~@".contains(c) {
                self.at += 1;
                while self.peek().is_some_and(|n| "=<>*/>".contains(n)) {
                    self.at += 1;
                }
                self.push(start, Kind::Operator);
            } else {
                self.at += c.len_utf8();
            }
        }
    }

    /// Whether only spaces come before `at` on its line.
    fn at_line_start(&self, at: usize) -> bool {
        let line = self.code[..at].rfind('\n').map_or(0, |n| n + 1);
        self.code[line..at].trim().is_empty()
    }

    /// Where the quote is, if a string starts here (after its prefix).
    fn string_start(&self) -> Option<usize> {
        let rest = self.code.get(self.at..)?;
        let prefix = rest
            .chars()
            .take_while(|c| "rRbBuUfFtT".contains(*c))
            .take(3)
            .count();
        let after = rest.get(prefix..)?;
        if prefix <= 2 && (after.starts_with('"') || after.starts_with('\'')) {
            // A name like `bar"` cannot be: the prefix starts the word.
            let before = self.code[..self.at].chars().next_back();
            if prefix > 0 && before.is_some_and(|b| b == '_' || b.is_alphanumeric()) {
                return None;
            }
            Some(self.at + prefix)
        } else {
            None
        }
    }

    fn string(&mut self, start: usize, quote_at: usize) {
        let rest = &self.code[quote_at..];
        let quote = &rest[..1];
        let triple = rest.starts_with(&quote.repeat(3));
        let delimiter = if triple {
            quote.repeat(3)
        } else {
            quote.to_owned()
        };
        self.at = quote_at + delimiter.len();
        while let Some(c) = self.peek() {
            // A backslash keeps the next character in the string, raw
            // strings too (`r'\''` is one string).
            if c == '\\' {
                self.at += 1;
                if let Some(escaped) = self.peek() {
                    self.at += escaped.len_utf8();
                }
                continue;
            }
            if self.code[self.at..].starts_with(&delimiter) {
                self.at += delimiter.len();
                break;
            }
            if c == '\n' && !triple {
                break;
            }
            self.at += c.len_utf8();
        }
        self.push(start, Kind::String);
    }

    fn number(&mut self, start: usize) {
        let hex = self.code[start..].starts_with("0x") || self.code[start..].starts_with("0X");
        while let Some(c) = self.peek() {
            let exponent_sign =
                (c == '+' || c == '-') && !hex && self.code[..self.at].ends_with(['e', 'E']);
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || exponent_sign {
                self.at += 1;
            } else {
                break;
            }
        }
        self.push(start, Kind::Number);
    }

    fn name(&mut self, start: usize) {
        while let Some(c) = self.peek() {
            if c == '_' || c.is_alphanumeric() {
                self.at += c.len_utf8();
            } else {
                break;
            }
        }
        let word = &self.code[start..self.at];
        let after_dot = self.code[..start].trim_end().ends_with('.');
        let kind = if let Some(kind) = self.defines.take() {
            Some(kind)
        } else if after_dot {
            self.called().then_some(Kind::Function)
        } else if CONTROL.contains(&word) {
            Some(Kind::ControlKeyword)
        } else if KEYWORDS.contains(&word) {
            self.defines = match word {
                "def" => Some(Kind::Function),
                "class" => Some(Kind::Class),
                _ => None,
            };
            Some(Kind::Keyword)
        } else if CONSTANTS.contains(&word) {
            Some(Kind::Constant)
        } else if BUILTINS.contains(&word) {
            Some(Kind::Builtin)
        } else {
            self.called().then_some(Kind::Function)
        };
        if let Some(kind) = kind {
            self.push(start, kind);
        }
    }

    /// Whether a `(` follows the name just read (spaces apart).
    fn called(&self) -> bool {
        self.code[self.at..]
            .trim_start_matches([' ', '\t'])
            .starts_with('(')
    }
}

#[cfg(test)]
mod tests {
    use super::{Kind, tokens};

    fn kinds(code: &str) -> Vec<(&str, Kind)> {
        tokens(code)
            .into_iter()
            .map(|t| (&code[t.range], t.kind))
            .collect()
    }

    #[test]
    fn keywords_names_and_calls_take_their_kinds() {
        let code = "def f(x):\n    return len(x) if x is not None else db.functions.get_at(0x10)";
        let found = kinds(code);
        assert!(found.contains(&("def", Kind::Keyword)));
        assert!(found.contains(&("f", Kind::Function)));
        assert!(found.contains(&("return", Kind::ControlKeyword)));
        assert!(found.contains(&("len", Kind::Builtin)));
        assert!(found.contains(&("None", Kind::Constant)));
        assert!(found.contains(&("get_at", Kind::Function)));
        assert!(found.contains(&("0x10", Kind::Number)));
        // Plain names and attributes not called keep the text's colour.
        assert!(
            !found
                .iter()
                .any(|(text, _)| *text == "db" || *text == "functions")
        );
    }

    #[test]
    fn strings_comments_and_decorators_span_their_text() {
        let code = "@property\nclass A:  # a 'quoted' comment\n    s = rb'\\x00' + \"\"\"two\nlines\"\"\" + f\"{x}\"";
        let found = kinds(code);
        assert!(found.contains(&("@property", Kind::Decorator)));
        assert!(found.contains(&("A", Kind::Class)));
        assert!(found.contains(&("# a 'quoted' comment", Kind::Comment)));
        assert!(found.contains(&("rb'\\x00'", Kind::String)));
        assert!(found.contains(&("\"\"\"two\nlines\"\"\"", Kind::String)));
        assert!(found.contains(&("f\"{x}\"", Kind::String)));
    }

    #[test]
    fn unfinished_text_never_panics_and_numbers_keep_exponents() {
        for code in [
            "'abc",
            "\"\"\"open",
            "x = 1e-5 + 0x1f",
            "é = 'ü'",
            "@",
            "#",
            "f(",
            "1.",
        ] {
            let found = tokens(code);
            assert!(found.iter().all(|t| code.get(t.range.clone()).is_some()));
        }
        assert!(kinds("x = 1e-5").contains(&("1e-5", Kind::Number)));
        assert!(kinds("x = 0xe-1").contains(&("0xe", Kind::Number)));
    }
}
