#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
//! What reading a pasted ticket or identity card allocates, measured by an
//! allocator that refuses (and so aborts the test) past a limit set
//! around each call. One test, so no other runs beside it.

use std::alloc::System;

use binbun_collab::ticket::{Card, JoinTicket};
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

#[test]
fn an_overlong_ticket_or_card_is_refused_before_it_is_copied_or_decoded() {
    // Correctly prefixed, 64 MiB of base32 after: refused within 16 KiB.
    let body = "a".repeat(64 << 20);
    let ticket = format!("binbun{body}");
    assert!(within(16 << 10, || ticket.parse::<JoinTicket>()).is_err());
    let card = format!("binbunid{body}");
    assert!(within(16 << 10, || card.parse::<Card>()).is_err());
}
