//! What another party wrote on the sync lane (`binbun_sync::Sync`), and
//! the canonical layouts it carries: envelopes (`Envelope::parse`), heads,
//! signed heads and fork proofs (the journal's parsers). The first byte
//! chooses which. Decoding must hold no more than a fixed multiple of the
//! input's bytes (`common/within.rs`); a message that reads is written
//! back and reads as itself, and an envelope's parts lie within it.

#![no_main]

#[path = "common/within.rs"]
mod within;

use binbun_session::journal::{ForkProof, Head, SignedHead};
use binbun_sync::{Envelope, Sync};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some((which, bytes)) = input.split_first() else {
        return;
    };
    match which % 5 {
        0 => {
            if let Ok(message) = within::within(bytes, Sync::decode) {
                let written = message.encode().expect("no longer than a frame");
                assert_eq!(Sync::decode(&written).ok(), Some(message));
            }
        }
        1 => {
            let parts = within::within(bytes, |bytes| {
                Envelope::parse(bytes).map(|envelope| {
                    (envelope.signed_head().len(), envelope.ciphertext().len(), envelope.bytes().len())
                })
            });
            if let Some((head, ciphertext, length)) = parts {
                assert!(head + ciphertext < length);
                assert_eq!(length, bytes.len());
            }
        }
        2 => {
            if let Ok(head) = within::within(bytes, Head::parse) {
                assert_eq!(&*head.bytes(), bytes);
            }
        }
        3 => {
            if let Ok(head) = within::within(bytes, SignedHead::parse) {
                assert_eq!(&*head.bytes(), bytes);
            }
        }
        _ => {
            if let Ok(proof) = within::within(bytes, ForkProof::parse) {
                assert_eq!(&*proof.bytes(), bytes);
            }
        }
    }
});
