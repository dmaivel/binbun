#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
//! What encoding and decoding allocate, measured by an allocator that
//! refuses (and so aborts the test) past a limit set around each call.
//! One test, so no other runs beside it.

use std::alloc::System;

use binbun_bounded::{Bounded, Bytes, Error, PREALLOC, Text, decode, encode};
use cap::Cap;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, usize::MAX);

/// Room for what the test harness allocates meanwhile.
const SLACK: usize = 16 << 10;

/// `call`'s result, the process aborted if it holds more than `bytes`
/// of heap at once beyond what was held before.
fn within<R>(bytes: usize, call: impl FnOnce() -> R) -> R {
    ALLOCATOR
        .set_limit(ALLOCATOR.allocated() + bytes + SLACK)
        .unwrap();
    let result = call();
    ALLOCATOR.set_limit(usize::MAX).unwrap();
    result
}

/// `length`'s varint, then `body`.
fn declared(length: usize, body: &[u8]) -> Vec<u8> {
    let mut bytes = postcard::to_allocvec(&length).unwrap();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn neither_encoding_nor_decoding_allocates_past_its_bound() {
    // An encode past its limit fails before its buffer passes the limit:
    // 8 MiB within 64 KiB.
    let big = Bytes::<{ 8 << 20 }>::try_from(vec![1; 8 << 20]).unwrap();
    let encoded = within(64 << 10, || encode(&big, 64 << 10));
    assert_eq!(encoded, Err(Error::TooLarge(64 << 10)));

    // A list declaring a billion items, of a bound of a billion, in a
    // few bytes: no more than the reservation before items arrive.
    let lie = declared(1 << 30, &[1, 2, 3]);
    let read = within(PREALLOC, || decode::<Bounded<u64, { 1 << 30 }>>(&lie));
    assert!(read.is_err());
    let read = within(PREALLOC, || {
        decode::<Bounded<Text<{ 1 << 20 }>, { 1 << 30 }>>(&lie)
    });
    assert!(read.is_err());
    // Bytes declaring a gigabyte: refused before anything is reserved.
    let read = within(0, || {
        decode::<Bytes<{ 1 << 30 }>>(&declared(1 << 30, &[0; 8]))
    });
    assert!(read.is_err());
}
