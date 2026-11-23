//! What another party wrote that is read off the lanes' messages: a
//! membership record as signed (`membership::SignedRecord`) and its
//! contents (`membership::Record`), the binary a record seals once opened
//! (`membership::Binary`), and the texts people pass by hand (a join
//! ticket, an identity card). The first byte chooses which. Decoding must
//! hold no more than a fixed multiple of the input's bytes
//! (`common/within.rs`), and a record that reads is written back and
//! reads as itself.

#![no_main]

#[path = "common/within.rs"]
mod within;

use binbun_collab::bounded::{self, Bounds};
use binbun_collab::membership::{Binary, Record, SignedRecord};
use binbun_collab::ticket::{Card, JoinTicket};
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
    match which % 5 {
        0 => round_trip::<SignedRecord>(bytes),
        1 => round_trip::<Record>(bytes),
        2 => round_trip::<Binary>(bytes),
        3 => {
            let _ = within::within(bytes, |bytes| {
                std::str::from_utf8(bytes).map(str::parse::<JoinTicket>)
            });
        }
        _ => {
            let _ = within::within(bytes, |bytes| {
                std::str::from_utf8(bytes).map(str::parse::<Card>)
            });
        }
    }
});
