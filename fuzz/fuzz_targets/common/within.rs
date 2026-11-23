//! The wire targets' allocation bound: an allocator that tracks live heap
//! bytes and refuses past a limit set around each decode, so a decode
//! that holds more than a fixed multiple of its input aborts the target
//! (libFuzzer reports the input).

use std::alloc::System;

use cap::Cap;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, usize::MAX);

/// The bytes a decode may hold per byte of its input.
const PER_BYTE: usize = 16;

/// The bytes a decode may hold whatever its input: what bounded lists
/// reserve before their items come (4 KiB each, a few nested), and the
/// small fixed parts of what is decoded.
const BASE: usize = 64 << 10;

/// `decode(input)`, the process aborted if it holds more than
/// `PER_BYTE` times the input's bytes and `BASE` more at once.
pub fn within<R>(input: &[u8], decode: impl FnOnce(&[u8]) -> R) -> R {
    let before = ALLOCATOR.allocated();
    let limit = before
        .saturating_add(input.len().saturating_mul(PER_BYTE))
        .saturating_add(BASE);
    // Above what is held, so it is taken.
    let _ = ALLOCATOR.set_limit(limit);
    let decoded = decode(input);
    let _ = ALLOCATOR.set_limit(usize::MAX);
    decoded
}
