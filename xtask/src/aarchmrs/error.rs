//! Errors of reading the package.

use std::fmt;

/// A package that cannot be read or does not follow the schema this crate
/// models.
#[derive(Debug)]
pub enum Error {
    /// Reading the archive failed.
    Io(std::io::Error),
    /// A JSON file is not valid JSON or does not have the expected shape.
    Json {
        /// The file inside the archive.
        file: &'static str,
        /// What serde found.
        error: serde_json::Error,
    },
    /// The archive lacks one of the JSON files.
    MissingFile(&'static str),
    /// The archive has no A64 instruction set.
    MissingA64,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "reading the package: {error}"),
            Self::Json { file, error } => write!(f, "{file}: {error}"),
            Self::MissingFile(file) => write!(f, "the package has no {file}"),
            Self::MissingA64 => f.write_str("Instructions.json has no A64 instruction set"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json { error, .. } => Some(error),
            Self::MissingFile(_) | Self::MissingA64 => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
