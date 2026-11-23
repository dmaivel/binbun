+++
title = "C, C++ and Rust libraries"
weight = 100
+++

The C API is the disassembler API, not the whole interactive analysis engine. It decodes x86 instructions in 16-, 32- and 64-bit modes and AArch64 A64 instructions. Use [Python](@/docs/python.md) or the Rust engine for functions, projects and decompilation.

## C

The release library is `libbinbun`, available as shared and static libraries with headers and pkg-config metadata (`binbun`). Include `binbun/binbun.h`, or `binbun/disasm.h` for the disassemblers alone; both include `binbun/core.h`, the version, statuses and strings every part of the library shares. The [C reference](@/docs/reference/c.md) is generated from the headers and gives each function's ownership, status and buffer contract.

A typical x86 decode allocates a `binbun_x86_instruction` in caller-owned storage and passes it, a mode and a byte buffer to `binbun_x86_decode_bytes`. Read the instruction only after `BINBUN_STATUS_OK`. Accessors return its length, mnemonic, form, operands, flags and control flow. Formatting takes an address separately, because a decoded instruction does not own one.

`binbun_x86_decoder_init` and `binbun_x86_decoder_next` perform a linear sweep over a buffer. The input must remain readable. An invalid decode advances one byte to resynchronise; end of input is a distinct status. This is a decoder, not function recovery: data bytes can happen to decode as instructions.

The AArch64 API follows the same caller-owned model with architecture-specific storage and accessors. Do not pass one architecture's storage to the other, or persist opaque storage across processes or library versions.

### One decoder for both architectures

`binbun_decode` (or `binbun_decoder_init` and `binbun_decoder_next`) takes the architecture as an argument: `BINBUN_ARCH_X86` with a mode, or `BINBUN_ARCH_AARCH64` with mode 0. Nothing is guessed from the bytes. It writes a `binbun_instruction`, which holds its address and bytes. The accessors return what both decoders share: the mnemonic the text writes (`movsb` for `rep movsb`), the text, the control flow, and the registers the decoder says the instruction may read and write. Each `binbun_register` has a kind and its architecture's fields, and `binbun_register_name` writes its name. Condition flags are left out. `binbun_instruction_as_x86` and `binbun_instruction_as_aarch64` return the native instruction inside the same storage, so every `binbun_x86_*` or `binbun_aarch64_*` function can read its operands, flags and tokens. This is the C side of the Rust crate `binbun-disasm` and of the Python package's `binbun.Decoder`.

## Ownership and failures

The library does not allocate, call callbacks or maintain global mutable state. Independent decodes may run on different threads. Do not mutate an instruction while another thread reads it, and use a decoder from one thread at a time.

Decode writes the output only on success. Invalid encodings, truncated input, invalid arguments and internal failures have distinct statuses. Uninitialised opaque storage is not a valid instruction object.

Text functions take a caller buffer and capacity, NUL-terminate when capacity permits, and return the full length excluding the NUL. A returned length at least as large as the capacity means truncation. The header's maximum text and token constants give sufficient bounds. Array accessors return the total number of elements even when the supplied capacity is smaller.

A `binbun_str` is a length and pointer, not a NUL-terminated C string. Its data remains owned by the loaded library. Numeric instruction IDs are version-specific; use names when writing a durable interchange format. Compare the library version and opaque-storage size with the header when loading a library separately.

## C++

`binbun/disasm.hpp` (with `binbun/core.hpp`) is a header-only C++17 wrapper over the same library. It provides range-based decoding and optional results without exceptions. It does not add a second engine or different instruction semantics. `binbun::Decoder` and `binbun::Instruction` decode either architecture, chosen by `binbun::Arch::x86(mode)` or `binbun::Arch::aarch64()`. The [repository examples](https://github.com/dmaivel/binbun/tree/main/examples) include C and C++ decoding and call-listing programs.

## Rust

The decoder crates work without the application. Their documentation is on docs.rs:

- [`binbun-disasm`](https://docs.rs/binbun-disasm) decodes either architecture through one API.
- [`binbun-x86`](https://docs.rs/binbun-x86) provides the x86 decoder and Intel-syntax formatting.
- [`binbun-aarch64`](https://docs.rs/binbun-aarch64) provides the A64 decoder.
- [`binbun-isa`](https://docs.rs/binbun-isa) defines shared instruction and control-flow interfaces.
- [`binbun`](https://docs.rs/binbun) is the analysis engine for loaded binaries, function recovery, references and decompilation.

Decoder coverage is broader than decompiler semantics. An instruction can decode correctly while its function cannot be decompiled.
