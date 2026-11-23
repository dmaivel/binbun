//! Why a request failed ([`Fault`]): its kind, which a client raises as
//! its own exception (Python's `binbun._errors`), its message, and for
//! refused C the bytes at fault.

use std::fmt;
use std::ops::Range;

use binbun_session::Error;
use serde::{Deserialize, Serialize};

/// What kind of failure: one per Python exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultKind {
    /// Anything else (`BinbunError`).
    Binbun,
    /// The file cannot be read as an image (`OpenError`).
    Open,
    /// The project cannot be read or written (`ProjectError`).
    Project,
    /// The analysis did not reach the stage a read needs
    /// (`NotAnalysedError`).
    NotAnalysed,
    /// An address in no segment (`InvalidAddressError`).
    InvalidAddress,
    /// No function starts at the address (`NoFunctionError`).
    NoFunction,
    /// No such variable (`NoVariableError`).
    NoVariable,
    /// The analysis changed under an iterator or handle (`StaleError`).
    Stale,
    /// A handle's function is gone (`FunctionGoneError`).
    FunctionGone,
    /// The function does not decompile (`DecompileError`).
    Decompile,
    /// C refused (`CDeclarationError`, with the bytes at fault).
    CDeclaration,
    /// A correction of recovery cannot apply (`CorrectionError`).
    Correction,
    /// A transaction misused, or held by another (`TransactionError`).
    Transaction,
    /// A thread, post or suggestion cannot be written: none such,
    /// another's, not pending (`ConversationError`).
    Conversation,
    /// Writes refused: by the server, or by the share the session's
    /// journal is part of (`ReadOnlyError`).
    ReadOnly,
    /// A `timeout=` elapsed (`TimeoutError`).
    Timeout,
    /// Cancelled (`CancelledError`).
    Cancelled,
    /// The server lacks a capability (`CapabilityError`).
    Capability,
    /// No database, or several and none chosen (`AmbiguousError`).
    Ambiguous,
    /// A malformed or unexpected message (`ProtocolError`).
    Protocol,
    /// No protocol version both ends speak (`VersionError`).
    Version,
    /// The connection failed or was lost (`ConnectionError`).
    Connection,
    /// The user may not reach the server: its directory or socket is
    /// another's (`PermissionError`).
    Permission,
}

/// A failure: its kind and message; for C refused, the C and the bytes
/// of it at fault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fault {
    /// Its kind.
    pub kind: FaultKind,
    /// What went wrong.
    pub message: String,
    /// The bytes of [`Self::c`] at fault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<Range<usize>>,
    /// The C refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
}

impl Fault {
    /// A fault of `kind` saying `message`.
    pub fn new(kind: FaultKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            span: None,
            c: None,
        }
    }

    /// A session's `error`, its C (if C was refused) `c`.
    pub fn session(error: &Error, c: Option<&str>) -> Self {
        let kind = match error {
            Error::Project(_) => FaultKind::Project,
            Error::NoFunction(_) => FaultKind::NoFunction,
            Error::NotDecompiled(_) => FaultKind::Decompile,
            Error::NoVariable(_) => FaultKind::NoVariable,
            Error::NotAnalysed => FaultKind::NotAnalysed,
            Error::Type(_) => FaultKind::CDeclaration,
            Error::Correction(_) => FaultKind::Correction,
            Error::Transaction(_) => FaultKind::Transaction,
            Error::Conversation(_) => FaultKind::Conversation,
            Error::Refused(_) => FaultKind::ReadOnly,
        };
        let span = match error {
            Error::Type(refused) => Some(refused.span.clone()),
            Error::Project(_)
            | Error::NoFunction(_)
            | Error::NotDecompiled(_)
            | Error::NoVariable(_)
            | Error::NotAnalysed
            | Error::Correction(_)
            | Error::Transaction(_)
            | Error::Conversation(_)
            | Error::Refused(_) => None,
        };
        Self {
            kind,
            message: match error {
                Error::Type(refused) => refused.message.clone(),
                Error::Project(_)
                | Error::NoFunction(_)
                | Error::NotDecompiled(_)
                | Error::NoVariable(_)
                | Error::NotAnalysed
                | Error::Correction(_)
                | Error::Transaction(_)
                | Error::Conversation(_)
                | Error::Refused(_) => error.to_string(),
            },
            c: span.as_ref().and(c).map(str::to_owned),
            span,
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Fault {}
