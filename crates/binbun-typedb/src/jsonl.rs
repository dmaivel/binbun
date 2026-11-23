//! The file format of type databases: JSON Lines. The first line is the
//! [`Header`]; every other line is one function or one named type, as
//! `{"function": {…}}`, `{"record": {…}}`, `{"enum": {…}}`,
//! `{"typedef": {…}}` or `{"opaque": {…}}`, sorted by that kind, then by
//! name (functions) or key (types). The same database always writes the
//! same bytes, so a regenerated file differs only where the declarations
//! do.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::database::{Database, Definition, Function, Header, SCHEMA_VERSION, TypeRef};
use crate::types::{Enum, Opaque, Record, Typedef};

/// One line after the header, as written.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum LineRef<'a> {
    Function(&'a Function),
    Enum(&'a Enum),
    Opaque(&'a Opaque),
    Record(&'a Record<TypeRef>),
    Typedef(&'a Typedef<TypeRef>),
}

/// One line after the header, as read.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Line {
    Function(Function),
    Enum(Enum),
    Opaque(Opaque),
    Record(Record<TypeRef>),
    Typedef(Typedef<TypeRef>),
}

/// The version field alone, read before the rest of the header, whose
/// shape another version may change.
#[derive(Deserialize)]
struct Version {
    binbun_typedb: u32,
}

/// `database` as JSON Lines, sorted.
///
/// # Errors
///
/// If serde fails to serialize a value (it does not for these types).
pub fn write(database: &Database) -> Result<String, serde_json::Error> {
    let mut lines: Vec<(u8, &str, &str, LineRef<'_>)> = database
        .functions
        .iter()
        .map(|function| {
            (
                0,
                function.name.as_str(),
                function.library.as_deref().unwrap_or(""),
                LineRef::Function(function),
            )
        })
        .chain(database.types.iter().map(|definition| {
            let line = match definition {
                Definition::Enum(definition) => (1, LineRef::Enum(definition)),
                Definition::Opaque(opaque) => (2, LineRef::Opaque(opaque)),
                Definition::Record(record) => (3, LineRef::Record(record)),
                Definition::Typedef(typedef) => (4, LineRef::Typedef(typedef)),
            };
            (line.0, definition.key(), "", line.1)
        }))
        .collect();
    lines.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
    let mut out = serde_json::to_string(&database.header)?;
    out.push('\n');
    for (_, _, _, line) in &lines {
        out.push_str(&serde_json::to_string(line)?);
        out.push('\n');
    }
    Ok(out)
}

/// Reads a database from JSON Lines. Blank lines are skipped.
///
/// # Errors
///
/// If the text has no header, its schema version is not
/// [`SCHEMA_VERSION`], or a line is not a header, function or type.
pub fn parse(text: &str) -> Result<Database, ParseError> {
    let mut lines = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .filter(|(_, line)| !line.trim().is_empty());
    let (number, first) = lines.next().ok_or(ParseError {
        line: 1,
        kind: ParseErrorKind::NoHeader,
    })?;
    let error = |line, kind| ParseError { line, kind };
    let header = header(first).map_err(|e| ParseError { line: number, ..e })?;
    let mut database = Database {
        header,
        functions: Vec::new(),
        types: Vec::new(),
    };
    for (number, line) in lines {
        match serde_json::from_str(line).map_err(|e| error(number, ParseErrorKind::Json(e)))? {
            Line::Function(function) => database.functions.push(function),
            Line::Enum(definition) => database.types.push(Definition::Enum(definition)),
            Line::Opaque(opaque) => database.types.push(Definition::Opaque(opaque)),
            Line::Record(record) => database.types.push(Definition::Record(record)),
            Line::Typedef(typedef) => database.types.push(Definition::Typedef(typedef)),
        }
    }
    Ok(database)
}

/// Reads a database's header, its first line.
///
/// # Errors
///
/// If its schema version is not [`SCHEMA_VERSION`], or it is not a header.
pub fn header(line: &str) -> Result<Header, ParseError> {
    let error = |kind| ParseError { line: 1, kind };
    let version: Version =
        serde_json::from_str(line).map_err(|e| error(ParseErrorKind::Json(e)))?;
    if version.binbun_typedb != SCHEMA_VERSION {
        return Err(error(ParseErrorKind::Version(version.binbun_typedb)));
    }
    serde_json::from_str(line).map_err(|e| error(ParseErrorKind::Json(e)))
}

/// Why a database file cannot be read.
#[derive(Debug)]
pub struct ParseError {
    /// The line (from 1).
    pub line: usize,
    /// What is wrong with it.
    pub kind: ParseErrorKind,
}

/// What is wrong with a line of a database file.
#[derive(Debug)]
pub enum ParseErrorKind {
    /// The file is empty.
    NoHeader,
    /// The header gives another schema version.
    Version(u32),
    /// The line is not valid JSON of the schema.
    Json(serde_json::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: ", self.line)?;
        match &self.kind {
            ParseErrorKind::NoHeader => write!(f, "no header"),
            ParseErrorKind::Version(found) => {
                write!(f, "schema version {found}, expected {SCHEMA_VERSION}")
            }
            ParseErrorKind::Json(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ParseError {}
