//! Three answers on fuzzer-chosen bytes. binbun's decoder (with the 64-bit
//! fast path) against its reference decoder alone (`decode_reference`): the
//! instruction or error, and the flow-only decode, must be identical. Then
//! binbun against XED: the length decoder, the full decode with operands,
//! the Intel text, the flags and the CPUID bits must all match
//! (`notation::answer` against `oracle_answer`).
//!
//! Input: a selector byte, then (if its top bit is set) an 8-byte
//! little-endian address, then up to 15 instruction bytes. The selector's
//! low three bits pick the mode.

#![no_main]

#[path = "../../crates/binbun-x86/tests/support/notation.rs"]
#[expect(
    dead_code,
    reason = "shared with the oracle tests, which use all of it"
)]
mod notation;

use binbun_isa::FlowStep;
use binbun_x86::{MAX_LENGTH, Mode, decode, decode_flow, decode_reference};
use libfuzzer_sys::fuzz_target;

const MODES: [Mode; 5] = [
    Mode::Bits64,
    Mode::Bits32,
    Mode::Bits16,
    Mode::Real16,
    Mode::Real32,
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let mode = MODES[usize::from(selector & 7) % MODES.len()];
    let (address, bytes) = if selector & 0x80 == 0 {
        (0, rest)
    } else {
        let Some((address, bytes)) = rest.split_first_chunk::<8>() else {
            return;
        };
        (u64::from_le_bytes(*address), bytes)
    };
    let bytes = &bytes[..bytes.len().min(MAX_LENGTH)];
    if bytes.is_empty() {
        return;
    }
    let reference = decode_reference(bytes, mode);
    let tag = notation::mode_tag(mode);
    assert_eq!(
        decode(bytes, mode),
        reference,
        "fast path, {tag} {address:x} {bytes:02x?}"
    );
    assert_eq!(
        decode_flow(bytes, mode, address),
        reference.map(|i| FlowStep::of(&i, address)),
        "flow-only, {tag} {address:x} {bytes:02x?}"
    );
    let ours = notation::answer(mode, address, bytes);
    let theirs = xed::answer(tag, address, bytes);
    assert_eq!(ours, theirs, "{tag} {address:x} {bytes:02x?}");
});

mod xed {
    #![allow(unsafe_code)]

    use std::ffi::{CStr, CString, c_char, c_int};
    use std::sync::Once;

    unsafe extern "C" {
        fn oracle_init();
        fn oracle_answer(
            mode: *const c_char,
            address: u64,
            bytes: *const u8,
            length: u32,
            buffer: *mut c_char,
            capacity: usize,
        ) -> c_int;
    }

    /// XED's answer, as `tools/xed-oracle` prints it after the input.
    pub fn answer(mode: &str, address: u64, bytes: &[u8]) -> String {
        static INIT: Once = Once::new();
        // SAFETY: initialises XED's static tables; no preconditions.
        INIT.call_once(|| unsafe { oracle_init() });
        let mode = CString::new(mode).expect("mode tags have no NUL");
        let mut buffer = vec![0_u8; 8192];
        let length = u32::try_from(bytes.len()).expect("at most 15 bytes");
        // SAFETY: `mode` is NUL-terminated, `bytes` valid for `length`
        // bytes, and `buffer` for `buffer.len()`; the C side writes a
        // NUL-terminated string within it.
        let status = unsafe {
            oracle_answer(
                mode.as_ptr(),
                address,
                bytes.as_ptr(),
                length,
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
            )
        };
        assert_eq!(status, 0, "the oracle answered");
        let text = CStr::from_bytes_until_nul(&buffer).expect("the answer ends in NUL");
        text.to_str().expect("XED answers in ASCII").to_owned()
    }
}
