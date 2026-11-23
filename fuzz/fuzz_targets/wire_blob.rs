//! The blob lane's decoders on arbitrary bytes, the first byte choosing
//! which: an ask (`wire::BlobAsk`), an answer (`wire::BlobAnswer`), a list
//! of offers once opened (`blobs::decode_offers`). Decoding must hold no
//! more than a fixed multiple of the input's bytes (`common/within.rs`);
//! an ask or an answer that reads is written back within its frame and
//! reads as itself.

#![no_main]

#[path = "common/within.rs"]
mod within;

use binbun_collab::blobs;
use binbun_collab::wire::{self, BlobAnswer, BlobAsk};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some((which, bytes)) = input.split_first() else {
        return;
    };
    match which % 3 {
        0 => {
            if let Ok(ask) = within::within(bytes, wire::decode::<BlobAsk>) {
                let written = wire::encode(&ask).expect("within its frame");
                assert_eq!(wire::decode::<BlobAsk>(&written).ok(), Some(ask));
            }
        }
        1 => {
            if let Ok(answer) = within::within(bytes, wire::decode::<BlobAnswer>) {
                let written = wire::encode(&answer).expect("within its frame");
                assert_eq!(wire::decode::<BlobAnswer>(&written).ok(), Some(answer));
            }
        }
        _ => {
            let _ = within::within(bytes, blobs::decode_offers);
        }
    }
});
