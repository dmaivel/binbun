#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
//! What reading an exported project allocates, measured by an allocator
//! that refuses (and so aborts the test) past a limit set around each
//! call. One test, so no other runs beside it.

mod common;

use std::alloc::System;
use std::fs::File;

use binbun_session::project::{Bundle, MAX_BUNDLE};
use cap::Cap;
use common::Scratch;

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

#[test]
fn an_overlong_exported_project_is_refused_before_it_is_read() {
    let dir = Scratch::new("bounds-bundle");
    let path = dir.join("big.binbun");
    // Sparse: nothing written, a byte longer than the bound.
    File::create(&path)
        .unwrap()
        .set_len(MAX_BUNDLE + 1)
        .unwrap();
    assert!(within(64 << 10, || Bundle::read(&path)).is_err());
}
