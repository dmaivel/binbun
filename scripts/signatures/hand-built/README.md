# Signature packs made by hand

The packs of Microsoft's libraries, which a script cannot download and
which take too long to make in CI. Each is made by hand by its script in
`scripts/signatures/` from libraries pinned there by SHA-256, committed
here, and added by every release to the packs it builds
(`scripts/signatures/packs.sh --hand-built`, run by
`.github/workflows/signatures.yml`): a pack is installed only if its
SHA-256 is the one `SHA256SUMS` lists, and the release's `PROVENANCE`
lists it with the script that made it.

The packs hold recordings of the functions' behaviour (identities from
their lifted code, the results of running them on chosen inputs) and a
hash of each function's bytes with relocated fields zeroed (128 bits of
BLAKE3, as byte-pattern signatures match), never Microsoft's code; each
pack's header says where it came from
(`binbun sig show PACK`).

| Pack | What | Made by | SHA-256 | Size |
| --- | --- | --- | --- | --- |
| `msvc-crt-14.51.36231.jsonl.zst` | The /MT static runtime of MSVC 14.51.36231 and the Universal CRT of Windows SDK 10.0.26100.0 (`libcmt.lib`, `libvcruntime.lib`, `libucrt.lib`, `libcpmt.lib`): 11,227 functions | `scripts/signatures/msvc.sh --binbun BIN --vs ROOT` (hours) | `c624d217ad6a60abf6c00daff3f6db9d2c106b7bbf2a05f9201a3085fae2073b` | 3,140,803 bytes |
| `wdk-km-10.0.28000.0.jsonl.zst` | The static libraries drivers link from the Windows Driver Kit 10.0.28000.0 (kernel C runtime, GS cookie and control-flow guard support in both builds, `ntstrsafe`, `wdmsec`, KMDF 1.35's entry stub and others): 886 functions | `scripts/signatures/kernel.sh --binbun BIN --wdk ROOT` (half a minute) | `c3428cf136fbdc952dd42e86473039861d410e67134702cbae1c37d543a1f303` | 343,106 bytes |

Both were made on 2026-11-14 by binbun builds of identity version 2 (the
headers' `identity`) and compressed by zstd 1.5.7 (`zstd -19
--single-thread`, as `packs.sh` compresses); the same libraries, binbun
and zstd give the same bytes (the kernel pack was made three times, by
two builds of binbun, to the same SHA-256; the MSVC pack's text
compressed again gives its SHA-256). Making a pack again: run its script
with `--out` here and replace its line in `SHA256SUMS`
(`sha256sum *.jsonl.zst > SHA256SUMS`). A change to binbun's identities
(a new identity version) needs both made again.
