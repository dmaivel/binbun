//! The control lane's decoder (`binbun_collab::wire::decode` of a
//! `Control`) on arbitrary frames: the first frame a host reads from
//! anyone who dials. Decoding must hold no more than a fixed multiple of
//! the frame's bytes (`common/within.rs`), and what reads is written back
//! within its frame's limit and reads as itself.

#![no_main]

#[path = "common/within.rs"]
mod within;

use binbun_collab::wire::{self, Control};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|frame: &[u8]| {
    if let Ok(control) = within::within(frame, wire::decode::<Control>) {
        let bytes = wire::encode(&control).expect("what reads is written within its frame");
        assert_eq!(wire::decode::<Control>(&bytes).ok(), Some(control));
    }
});
