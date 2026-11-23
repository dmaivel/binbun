//! JSON-RPC 2.0 messages ([`Message`]): a request (`id`, `method`,
//! `params`), its response (`id`, `result` or `error`), or a notification
//! (`method`, `params`, no `id`). A failure's `error.data` is a
//! [`Fault`], so a client raises what the server would have.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fault::{Fault, FaultKind};

/// JSON-RPC's error code for a message that is no JSON.
pub const PARSE_ERROR: i64 = -32_700;
/// … for JSON that is no request.
pub const INVALID_REQUEST: i64 = -32_600;
/// … for a method the server does not have.
pub const METHOD_NOT_FOUND: i64 = -32_601;
/// … for parameters a method does not take.
pub const INVALID_PARAMS: i64 = -32_602;
/// binbun's code for a request that failed: `data` is its [`Fault`].
pub const FAULT: i64 = -32_000;

/// A message's error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    /// JSON-RPC's code.
    pub code: i64,
    /// What went wrong.
    pub message: String,
    /// The fault, for binbun's own failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Fault>,
}

impl RpcError {
    /// The error carrying `fault`.
    pub fn fault(fault: Fault) -> Self {
        let code = match fault.kind {
            FaultKind::Protocol => INVALID_PARAMS,
            FaultKind::Binbun
            | FaultKind::Open
            | FaultKind::Project
            | FaultKind::NotAnalysed
            | FaultKind::InvalidAddress
            | FaultKind::NoFunction
            | FaultKind::NoVariable
            | FaultKind::Stale
            | FaultKind::FunctionGone
            | FaultKind::Decompile
            | FaultKind::CDeclaration
            | FaultKind::Correction
            | FaultKind::Transaction
            | FaultKind::Conversation
            | FaultKind::ReadOnly
            | FaultKind::Timeout
            | FaultKind::Cancelled
            | FaultKind::Capability
            | FaultKind::Ambiguous
            | FaultKind::Version
            | FaultKind::Connection
            | FaultKind::Permission => FAULT,
        };
        Self {
            code,
            message: fault.message.clone(),
            data: Some(fault),
        }
    }

    /// The fault a client raises for it.
    pub fn into_fault(self) -> Fault {
        self.data
            .unwrap_or_else(|| Fault::new(FaultKind::Protocol, self.message))
    }
}

/// A JSON-RPC 2.0 message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// `"2.0"`.
    pub jsonrpc: String,
    /// A request's or its response's number; none for a notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// A request's or notification's method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Its parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// A response's result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// A response's error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Message {
    fn new() -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: None,
            params: None,
            result: None,
            error: None,
        }
    }

    /// Request `id`: `method` with `params`.
    pub fn request(id: u64, method: &str, params: Value) -> Self {
        Self {
            id: Some(id),
            method: Some(method.to_owned()),
            params: Some(params),
            ..Self::new()
        }
    }

    /// A notification: `method` with `params`.
    pub fn notification(method: &str, params: Value) -> Self {
        Self {
            method: Some(method.to_owned()),
            params: Some(params),
            ..Self::new()
        }
    }

    /// The response to request `id`: `result` or `error`.
    pub fn response(id: Option<u64>, outcome: Result<Value, RpcError>) -> Self {
        let (result, error) = match outcome {
            Ok(result) => (Some(result), None),
            Err(error) => (None, Some(error)),
        };
        Self {
            id,
            result,
            error,
            ..Self::new()
        }
    }

    /// Whether it is a response (no method).
    pub const fn is_response(&self) -> bool {
        self.method.is_none()
    }

    /// It as JSON bytes.
    ///
    /// # Errors
    ///
    /// It cannot be (a map with keys that are not strings: never).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Fault> {
        serde_json::to_vec(self).map_err(|error| Fault::new(FaultKind::Protocol, error.to_string()))
    }

    /// The message `bytes` hold.
    ///
    /// # Errors
    ///
    /// They are no JSON-RPC 2.0 message.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RpcError> {
        let message: Self = serde_json::from_slice(bytes).map_err(|error| RpcError {
            code: PARSE_ERROR,
            message: error.to_string(),
            data: None,
        })?;
        if message.jsonrpc != "2.0" {
            return Err(RpcError {
                code: INVALID_REQUEST,
                message: format!("JSON-RPC {:?}, not 2.0", message.jsonrpc),
                data: None,
            });
        }
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{FAULT, Message, RpcError};
    use crate::fault::{Fault, FaultKind};

    #[test]
    fn messages_round_trip_and_faults_cross_whole() {
        let request = Message::request(7, "functions.page", json!({"cursor": 0}));
        let read = Message::from_bytes(&request.to_bytes().unwrap()).unwrap();
        assert_eq!(read, request);
        assert!(!read.is_response());
        let mut fault = Fault::new(FaultKind::CDeclaration, "expected `}`");
        fault.span = Some(10..10);
        fault.c = Some("struct x {".to_owned());
        let response = Message::response(Some(7), Err(RpcError::fault(fault.clone())));
        let read = Message::from_bytes(&response.to_bytes().unwrap()).unwrap();
        assert!(read.is_response());
        let error = read.error.unwrap();
        assert_eq!(error.code, FAULT);
        assert_eq!(error.into_fault(), fault);
        assert!(Message::from_bytes(br#"{"jsonrpc":"1.0","id":1}"#).is_err());
        assert!(Message::from_bytes(b"not json").is_err());
    }
}
