//! The streaming decoder: addresses, resynchronisation after errors, and
//! repositioning.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use binbun_x86::{DecodeError, Decoder, Mode};

/// `(address, Intel text or error)` for each item.
fn sweep(decoder: Decoder<'_>) -> Vec<(u64, String)> {
    decoder
        .map(|(address, result)| {
            let text = result.map_or_else(|e| format!("{e:?}"), |i| i.intel(address).to_string());
            (address, text)
        })
        .collect()
}

#[test]
fn decodes_in_sequence_with_addresses() {
    // push rbp; mov rbp, rsp; call 0x1000 (rel to next); leave; ret
    let code = [
        0x55, 0x48, 0x89, 0xe5, 0xe8, 0xf7, 0x0f, 0x00, 0x00, 0xc9, 0xc3,
    ];
    let items = sweep(Decoder::new(&code, Mode::Bits64, 0x400));
    assert_eq!(
        items,
        [
            (0x400, "push rbp".to_owned()),
            (0x401, "mov rbp, rsp".to_owned()),
            (0x404, "call 0x1400".to_owned()),
            (0x409, "leave ".to_owned()),
            (0x40a, "ret ".to_owned()),
        ]
    );
}

#[test]
fn decodes_endbr_as_cet_processors_run_it() {
    // F3 0F 1E FA/FB are ENDBR64/ENDBR32 (XED with CET, every x86-64
    // processor since 2020); without F3 the same bytes stay reserved NOPs.
    let code = [
        0xf3, 0x0f, 0x1e, 0xfa, 0xf3, 0x0f, 0x1e, 0xfb, 0x0f, 0x1e, 0xfa,
    ];
    let items = sweep(Decoder::new(&code, Mode::Bits64, 0));
    assert_eq!(
        items,
        [
            (0, "endbr64".to_owned()),
            (4, "endbr32".to_owned()),
            (8, "nop edx, edi".to_owned()),
        ]
    );
}

#[test]
fn skips_one_byte_after_an_error() {
    // 0x06 (push es) has no 64-bit encoding; then nop; then a truncated
    // `mov eax, imm32`, after which the decoder retries at `01`: an `add`
    // missing its ModRM.
    let code = [0x06, 0x90, 0xb8, 0x01];
    let mut decoder = Decoder::new(&code, Mode::Bits64, 0);
    let results: Vec<(u64, Result<usize, DecodeError>)> = decoder
        .by_ref()
        .map(|(address, result)| (address, result.map(|i| i.len())))
        .collect();
    assert_eq!(
        results,
        [
            (0, Err(DecodeError::Invalid)),
            (1, Ok(1)),
            (2, Err(DecodeError::TooShort)),
            (3, Err(DecodeError::TooShort)),
        ]
    );
    assert!(decoder.next().is_none());
}

#[test]
fn repositions_and_reports_remaining_bytes() {
    let code = [0x90, 0x90, 0xc3];
    let mut decoder = Decoder::new(&code, Mode::Bits32, 0x7000);
    decoder.set_offset(2);
    assert_eq!((decoder.offset(), decoder.address()), (2, 0x7002));
    assert_eq!(decoder.remaining(), [0xc3]);
    assert_eq!(
        decoder.next().map(|(a, r)| (a, r.unwrap().len())),
        Some((0x7002, 1))
    );
    assert!(decoder.next().is_none());
    decoder.set_offset(10);
    assert!(decoder.remaining().is_empty() && decoder.next().is_none());
}
