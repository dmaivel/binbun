//! The live lane's decoders on arbitrary bytes, the first byte choosing
//! which: a live frame (`wire::LiveFrame`), what a live frame holds once
//! opened (`live::Said`), a presence datagram's plaintext
//! (`live::Presence`). Decoding must hold no more than a fixed multiple
//! of the input's bytes (`common/within.rs`), and what reads is written
//! back and reads as itself.

#![no_main]

#[path = "common/within.rs"]
mod within;

use binbun_collab::bounded::{self, Bounds};
use binbun_collab::live::{Presence, Said};
use binbun_collab::wire::{self, LiveFrame};
use libfuzzer_sys::fuzz_target;
use serde::Serialize;

/// `bytes` read as a `T`, within the allocation bound, and written back.
fn round_trip<T: Bounds + Serialize + PartialEq + std::fmt::Debug>(bytes: &[u8]) {
    if let Ok(value) = within::within(bytes, bounded::decode::<T>) {
        let written = bounded::encode(&value, bytes.len()).expect("no longer than what was read");
        assert_eq!(bounded::decode::<T>(&written).ok(), Some(value));
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((which, bytes)) = input.split_first() else {
        return;
    };
    match which % 3 {
        0 => {
            if let Ok(frame) = within::within(bytes, wire::decode::<LiveFrame>) {
                let written = wire::encode(&frame).expect("within its frame");
                assert_eq!(wire::decode::<LiveFrame>(&written).ok(), Some(frame));
            }
        }
        1 => round_trip::<Said>(bytes),
        _ => round_trip::<Presence>(bytes),
    }
});
