use std::fmt;

/// A datafile that does not follow XED's grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// 1-based line number the problem was found on.
    pub line: u32,
    /// What is wrong.
    pub kind: ErrorKind,
}

impl Error {
    /// An error of `kind` at `line`.
    pub const fn new(line: u32, kind: ErrorKind) -> Self {
        Self { line, kind }
    }
}

/// The ways a datafile can be malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Content before the first `NAME()::` section header.
    OutsideSection,
    /// A section header that is not `NAME()::` or `TYPE NAME()::`.
    MalformedHeader,
    /// An instruction section line that is not `{`, `UDELETE : x` or `DELETE : x`.
    ExpectedRecord,
    /// A record line without a `KEY : value` colon.
    MissingColon,
    /// A record key with an empty value, or a value that starts with another colon.
    MalformedValue(String),
    /// A key that may appear only once per record appeared again.
    DuplicateKey(&'static str),
    /// A record ended without a required key.
    MissingKey(&'static str),
    /// An `OPERANDS` or `IFORM` line before any `PATTERN` line of its form.
    WithoutPattern(&'static str),
    /// A `PATTERN` that is not followed by an `OPERANDS` line.
    WithoutOperands,
    /// End of input inside a `{ … }` record.
    UnterminatedRecord,
    /// A value that should be a number is not.
    NotANumber(String),
    /// A line or token that does not follow its file's grammar; the text says how.
    Malformed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: ", self.line)?;
        match &self.kind {
            ErrorKind::OutsideSection => f.write_str("content before the first section header"),
            ErrorKind::MalformedHeader => {
                f.write_str("section header is not `NAME()::` or `TYPE NAME()::`")
            }
            ErrorKind::ExpectedRecord => {
                f.write_str("expected `{`, `UDELETE : name` or `DELETE : iclass`")
            }
            ErrorKind::MissingColon => f.write_str("expected `KEY : value`"),
            ErrorKind::MalformedValue(key) => write!(f, "malformed value for `{key}`"),
            ErrorKind::DuplicateKey(key) => write!(f, "`{key}` appears twice in one record"),
            ErrorKind::MissingKey(key) => write!(f, "record has no `{key}`"),
            ErrorKind::WithoutPattern(key) => write!(f, "`{key}` before its `PATTERN`"),
            ErrorKind::WithoutOperands => f.write_str("`PATTERN` without `OPERANDS`"),
            ErrorKind::UnterminatedRecord => f.write_str("record is not closed with `}`"),
            ErrorKind::NotANumber(text) => write!(f, "`{text}` is not a number"),
            ErrorKind::Malformed(what) => write!(f, "malformed {what}"),
        }
    }
}

impl std::error::Error for Error {}
