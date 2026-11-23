# Fuzzing

Eight targets, built with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). `RUSTC_BOOTSTRAP=1` lets the repository's pinned stable toolchain accept the coverage flags cargo-fuzz passes (a nightly toolchain works too); `-s none` skips AddressSanitizer, which safe Rust does not need.

## differential

`differential` decodes fuzzer-chosen bytes three ways in the same process and requires identical answers. binbun's decoder, with its 64-bit fast path, must equal its reference decoder alone (`decode_reference`, feature `internal-reference`): the same instruction or error, and the same flow-only decode. Then binbun must equal Intel XED: length, full decode with operands, Intel text, flags and CPUID bits, in the notation of `tools/xed-oracle` (binbun's side is `crates/binbun-x86/tests/support/notation.rs`).

It needs a built XED checkout (one where `python3 mfile.py` has run), linked with feature `xed`:

```sh
cd fuzz
XED_DIR=/path/to/xed RUSTC_BOOTSTRAP=1 cargo fuzz run -s none --features xed differential -- -max_len=24 -jobs=4 -workers=4
```

## capi

`capi` calls the C API's entry points (`crates/binbun-capi`) on fuzzer-chosen bytes: the first byte picks the x86 mode or AArch64 and the buffer capacities, the rest is code. It checks what the header promises: statuses, text within `BINBUN_*_MAX_TEXT` and NUL-terminated however short the buffer, tokens within `BINBUN_*_MAX_TOKENS` that cover the text and name real operands, the sweep covering the buffer. AddressSanitizer is worth keeping here, since the library writes into caller buffers:

```sh
cd fuzz
RUSTC_BOOTSTRAP=1 cargo fuzz run capi -- -max_len=32 -jobs=4 -workers=4
```

## theme_css

`theme_css` reads fuzzer-chosen text as a GUI theme file (`gui/view/src/theme_css.rs`, included by path: it uses only `std`, so the GUI's workspace is not built). User themes are files the GUI reads, so parsing and resolving must neither panic nor recurse without bound. It checks that every problem is placed inside the text, that resolving is deterministic and unchanged by an identical file over it, and that a resolved colour written back as hex reads as itself:

```sh
cd fuzz
RUSTC_BOOTSTRAP=1 cargo fuzz run -s none theme_css -- -max_len=4096 -jobs=4 -workers=4
```

## wire_control, wire_live, wire_blob, wire_records

Collaboration's decoders of what another party wrote (`crates/binbun-collab`, through `binbun-bounded`), one target per lane: the control lane's frames (`wire_control`); the live lane's frames, what they hold once opened and presence datagrams (`wire_live`); the blob lane's asks, answers and opened lists of offers (`wire_blob`); membership records, the binary a record seals, join tickets and identity cards (`wire_records`). The first byte of the input picks the decoder where a target has several. Each decode runs under an allocator limited to 16 times the input's bytes and 64 KiB more of live heap (`fuzz_targets/common/within.rs`): a decode that holds more aborts, and libFuzzer keeps the input. What reads must be written back within its frame and read as itself.

```sh
cd fuzz
RUSTC_BOOTSTRAP=1 cargo fuzz run -s none wire_control -- -max_len=16384 -jobs=4 -workers=4
```

## wire_sync

The sync lane's messages (`binbun_sync::Sync`, `crates/binbun-sync`) and the canonical layouts they carry: envelopes (`binbun_sync::Envelope::parse`), and the journal's heads, signed heads and fork proofs (`Head::parse`, `SignedHead::parse`, `ForkProof::parse`). The first byte picks which; each runs under the allocation bound of the other wire targets. A message that reads must be written back within a frame and read as itself; a layout that parses must be written back as the same bytes.

```sh
cd fuzz
RUSTC_BOOTSTRAP=1 cargo fuzz run -s none wire_sync -- -max_len=65536 -jobs=4 -workers=4
```

## Release smoke run

Before a release every target runs for five minutes under AddressSanitizer (cargo-fuzz's default; leak detection on), one process each from an empty corpus, with a fixed seed. Toolchain: the pinned 1.99.0 with `RUSTC_BOOTSTRAP=1` (a nightly older than the workspace's `rust-version` cannot build it), cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13. XED for `differential` is built by `scripts/ci/build-xed.sh`. Building into `/tmp` keeps the build off the disk:

```sh
scripts/ci/build-xed.sh /tmp/smoke/xed-build
cd fuzz
export RUSTC_BOOTSTRAP=1 XED_DIR=/tmp/smoke/xed-build/xed
cargo fuzz build --target-dir /tmp/smoke/target
cargo fuzz build --target-dir /tmp/smoke/target --features xed differential
bin=/tmp/smoke/target/x86_64-unknown-linux-gnu/release
mkdir -p /tmp/smoke/corpus/wire_sync /tmp/smoke/artifacts/wire_sync
$bin/wire_sync /tmp/smoke/corpus/wire_sync -seed=20261120 -max_total_time=300 \
    -max_len=65536 -print_final_stats=1 -artifact_prefix=/tmp/smoke/artifacts/wire_sync/
```

and likewise for each target with its `-max_len` from above (the other wire targets 16384); `differential` also reads `fuzz/corpus/differential` as a second corpus. Start the targets from a small shell (`bash -c`): libFuzzer measures peak RSS with `getrusage`, which on Linux keeps the launching process's peak across `exec`, so a target started straight from a large process reports out-of-memory at once.

Run of 2026-11-20 (commit `8a3ca12`), seed 20261120, 300 s each:

| Target | Runs | Corpus at the end | Peak RSS | Result |
|---|---|---|---|---|
| `capi` | 680,239 | 21,561 | 1027 MB | clean |
| `differential` | 884,614 | 32,881 | 760 MB | clean |
| `theme_css` | 1,401,857 | 1,094 | 571 MB | clean |
| `wire_control` | 26,503,310 | 342 | 558 MB | clean |
| `wire_live` | 16,286,894 | 728 | 557 MB | clean |
| `wire_blob` | 25,923,920 | 377 | 526 MB | clean |
| `wire_records` | 5,202,609 | 717 | 591 MB | clean |
| `wire_sync` | 7,079,981 | 825 | 611 MB | clean |

No crash, leak or allocation-bound abort. The kept corpora reach every decoder each target chooses between, the opened bodies included (`Said`, `Presence`, opened offer lists, the binary a record seals).
