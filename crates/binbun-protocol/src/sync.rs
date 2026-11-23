//! The change log on the wire (`sync.changes_since`): a client following a
//! server's session sends how far it knows each chain ([`frontier`]) and
//! takes the signed changes it lacks ([`changes_since`]), each in its
//! canonical encoding in base64 ([`encode`], [`decode`]), checked again
//! where it is applied (`Session::receive`). The answer names what the
//! server's chains are of ([`binding`]), which the client's session
//! follows (`Session::follow`).

use std::fmt::Write as _;

use binbun_session::journal::{ChainId, Of, SignedChange};
use binbun_session::{Session, VersionVector};

use crate::base64;
use crate::fault::{Fault, FaultKind};
use crate::messages::{Binding, Known};

/// How far `session` tells each chain, as the wire's list.
pub fn frontier(session: &Session) -> Vec<Known> {
    session
        .tips_after(None, usize::MAX)
        .into_iter()
        .map(|tip| Known {
            chain: tip.chain.to_string(),
            seq: tip.seq,
        })
        .collect()
}

/// The version vector `known` says.
///
/// # Errors
///
/// A chain is no 16 bytes of hexadecimal ([`FaultKind::Protocol`]).
pub fn vector(known: &[Known]) -> Result<VersionVector, Fault> {
    known
        .iter()
        .map(|known| {
            let bytes = unhex(&known.chain)
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                .ok_or_else(|| {
                    Fault::new(
                        FaultKind::Protocol,
                        format!("not a chain: {:?}", known.chain),
                    )
                })?;
            Ok((ChainId(bytes), known.seq))
        })
        .collect()
}

/// The changes `session` tells past `known`, chain by chain in order
/// (a chain `known` does not name: from its start).
pub fn changes_since(session: &Session, known: &VersionVector) -> Vec<SignedChange> {
    session
        .tips_after(None, usize::MAX)
        .into_iter()
        .filter(|tip| known.get(&tip.chain).is_none_or(|&seq| seq < tip.seq))
        .flat_map(|tip| {
            let after = known.get(&tip.chain).copied().unwrap_or(0);
            session.changes_after(tip.chain, after, usize::MAX, usize::MAX)
        })
        .collect()
}

/// What `session`'s chains are of, as sent.
pub fn binding(session: &Session) -> Binding {
    match session.binding() {
        Of::Binary { sha256, slice } => Binding {
            sha256: Some(hex(&sha256)),
            slice,
        },
        Of::Set => Binding {
            sha256: None,
            slice: None,
        },
    }
}

/// The binding `binding` says.
///
/// # Errors
///
/// Its digest is no 32 bytes of hexadecimal ([`FaultKind::Protocol`]).
pub fn of(binding: &Binding) -> Result<Of, Fault> {
    let Some(sha256) = &binding.sha256 else {
        return Ok(Of::Set);
    };
    let sha256 = unhex(sha256)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| Fault::new(FaultKind::Protocol, format!("not a SHA-256: {sha256:?}")))?;
    Ok(Of::Binary {
        sha256,
        slice: binding.slice.clone(),
    })
}

/// `change` as sent: its canonical encoding, in base64.
pub fn encode(change: &SignedChange) -> String {
    base64::encode(&change.encode())
}

/// The change `text` sends.
///
/// # Errors
///
/// It is no base64, or no change ([`FaultKind::Protocol`]).
pub fn decode(text: &str) -> Result<SignedChange, Fault> {
    let bytes = base64::decode(text)
        .map_err(|why| Fault::new(FaultKind::Protocol, format!("a change: {why}")))?;
    SignedChange::parse(&bytes)
        .map_err(|why| Fault::new(FaultKind::Protocol, format!("a change: {why}")))
}

/// `bytes` in lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The bytes hexadecimal `text` writes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            text.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use binbun_session::VersionVector;
    use binbun_session::journal::{ChainId, Of};

    use super::{decode, of, vector};
    use crate::fault::FaultKind;
    use crate::messages::{Binding, Known};

    #[test]
    fn frontiers_and_bindings_read_back_as_sent_and_bad_ones_are_refused() {
        let mut known = VersionVector::new();
        known.insert(ChainId([0xab; 16]), 7);
        known.insert(ChainId([0x01; 16]), 1);
        let wire: Vec<Known> = known
            .iter()
            .map(|(chain, &seq)| Known {
                chain: chain.to_string(),
                seq,
            })
            .collect();
        assert_eq!(vector(&wire).unwrap(), known);
        let mut bad = wire;
        bad[0].chain.pop();
        assert_eq!(vector(&bad).unwrap_err().kind, FaultKind::Protocol);
        bad[0].chain = "zz".repeat(16);
        assert_eq!(vector(&bad).unwrap_err().kind, FaultKind::Protocol);
        assert_eq!(decode("not base64!").unwrap_err().kind, FaultKind::Protocol);
        assert_eq!(decode("AAAA").unwrap_err().kind, FaultKind::Protocol);
        let binding = Binding {
            sha256: Some("ab".repeat(32)),
            slice: Some("arm64".to_owned()),
        };
        assert_eq!(
            of(&binding).unwrap(),
            Of::Binary {
                sha256: [0xab; 32],
                slice: Some("arm64".to_owned()),
            }
        );
        let short = Binding {
            sha256: Some("ab".repeat(31)),
            slice: None,
        };
        assert_eq!(of(&short).unwrap_err().kind, FaultKind::Protocol);
    }
}
