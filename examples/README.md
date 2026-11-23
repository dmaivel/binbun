# Examples

Each is a small real task, readable in a minute, with a header saying what it shows and how to run it. Every one runs with no arguments: the decoder examples on bytes of their own, the engine examples on the checked-in test program (`tests/fixtures/program-x86_64.elf`, found from the example's own file, or for Rust from its crate's); give them bytes, or a path and a function, to run them on yours. Every one runs in a test, with no arguments and against the fixtures (`tests/fixtures/`), its output checked: Python's and Rust's by `python/tests/test_examples.py` (`scripts/python-tests.sh` builds the Rust examples), C's and C++'s by `crates/binbun-capi/tests/examples.rs`.

## Python (`pip install binbun`)

Decoders, no database:

- `python/quick_start.py`: decode a few bytes of x86-64 through `binbun.disassemble`, the same call for AArch64, and print each instruction at its address. `python quick_start.py`
- `python/disassemble.py`: a buffer's instructions with addresses and bytes, x86 (64/32/16) or AArch64. `python disassemble.py`, `python disassemble.py --arch aarch64`, `python disassemble.py 55 4889e5 c3`
- `python/decode_any.py`: one decoder for both architectures (`binbun.disassemble`): each instruction's text, mnemonic and the registers it reads and writes, x86 (64/32/16) or AArch64. `python decode_any.py`, `python decode_any.py --arch aarch64`, `python decode_any.py --arch x86-32 55 89e5 c3`
- `python/instruction_info.py`: one instruction's operands with read/write access, implicit registers, flags, branch. `python instruction_info.py`, `python instruction_info.py 55`
- `python/color_tokens.py`: instructions coloured by token kind, ANSI or HTML. `python color_tokens.py`, `python color_tokens.py --arch aarch64 200440f9`
- `python/list_calls.py`: sweep an executable's `.text` (`sweep()`, columns) and list its calls with their targets. `python list_calls.py`, `python list_calls.py /usr/bin/true`

Engine (`binbun.open`):

- `python/decompiler_quick_start.py`: open the test program, decompile `classify`, print its C and the instructions its `return` line came from. `python decompiler_quick_start.py`
- `python/list_functions.py`: open a binary, list its functions with size, blocks and callers. `python list_functions.py`, `python list_functions.py /usr/bin/true`
- `python/xrefs.py`: references to a function or address (default `main`), and from a function. `python xrefs.py`, `python xrefs.py /usr/bin/true main`
- `python/decompile.py`: a function's C (default `main`) with, after each line, the instructions it came from. `python decompile.py`, `python decompile.py /usr/bin/true main`
- `python/decompile_all.py`: every function's C on all cores, printed or into one file, failures listed. `python decompile_all.py`, `python decompile_all.py /usr/bin/bash bash.c`
- `python/verify.py`: check the C against the machine code, count the verdicts. `python verify.py`, `python verify.py /usr/bin/true`
- `python/calls_with_constant.py`: calls to a function (default `exit`) passing a constant argument (strings shown), read-only. `python calls_with_constant.py`, `python calls_with_constant.py /usr/bin/bash exit`

Writes (`with db.transaction(...)`, `db.undo()`):

- `python/rename_in_transaction.py`: rename a function (default `loop_sum`) and its first parameter and comment its entry in one transaction, print its C before and after, undo the whole step and check the C is back; nothing is saved. `python rename_in_transaction.py`, `python rename_in_transaction.py /usr/bin/true main`

## Rust

- `rust/quick_start.rs`: decode a few bytes of x86-64 through `binbun-disasm`, the same API for AArch64. `cargo run -p binbun-disasm --example quick_start`
- `rust/disassemble.rs`: x86 bytes with addresses, bytes and text. `cargo run -p binbun-x86 --example disassemble`, `cargo run -p binbun-x86 --example disassemble -- 55 4889e5 c3`
- `rust/instruction_info.rs`: one x86 instruction's operands, access, implicit operands, flag effects, branch. `cargo run -p binbun-x86 --example instruction_info`, `cargo run -p binbun-x86 --example instruction_info -- 55`
- `rust/disassemble_aarch64.rs`: AArch64 words with implicit registers. `cargo run -p binbun-aarch64 --example disassemble_aarch64`, `cargo run -p binbun-aarch64 --example disassemble_aarch64 -- fd7bbfa9 c0035fd6`
- `rust/decode_any.rs`: one decoder API for both architectures (`binbun-disasm`), printing what `python/decode_any.py` prints. `cargo run -p binbun-disasm --example decode_any`, `cargo run -p binbun-disasm --example decode_any -- --arch aarch64`
- `rust/color_tokens.rs`: AArch64 text coloured through a token `Sink`. `cargo run -p binbun-aarch64 --example color_tokens`, `cargo run -p binbun-aarch64 --example color_tokens -- 200440f9`
- `rust/list_calls.rs`: sweep an executable's `.text` and list its calls, named by the engine. `cargo run --release -p binbun --example list_calls`, `cargo run --release -p binbun --example list_calls -- /usr/bin/true`
- `rust/list_functions.rs`: open a binary, list its functions. `cargo run --release -p binbun --example list_functions`, `cargo run --release -p binbun --example list_functions -- /usr/bin/true`
- `rust/xrefs.rs`: references to and from a function (default `main`) or address. `cargo run --release -p binbun --example xrefs`, `cargo run --release -p binbun --example xrefs -- /usr/bin/true main`
- `rust/decompile.rs`: one function's C (default `main`), as `binbun decompile` prints it. `cargo run --release -p binbun --example decompile`, `cargo run --release -p binbun --example decompile -- /usr/bin/true main`
- `rust/decompiler_quick_start.rs`: the test program's `classify` through a session, its C and the instructions its `return` line came from, as `python/decompiler_quick_start.py`. `cargo run --release -p binbun-session --example decompiler_quick_start`
- `rust/provenance.rs`: a function's C (default `main`) through a session, each line with its instructions. `cargo run --release -p binbun-session --example provenance`, `cargo run --release -p binbun-session --example provenance -- /usr/bin/true main`
- `rust/verify.rs`: every function's C checked on all cores, the verdicts counted. `cargo run --release -p binbun --example verify`, `cargo run --release -p binbun --example verify -- /usr/bin/true`
- `rust/calls_with_constant.rs`: calls to a function (default `exit`) with a constant first argument, read-only. `cargo run --release -p binbun --example calls_with_constant`, `cargo run --release -p binbun --example calls_with_constant -- /usr/bin/bash exit`

## C (`libbinbun`, `crates/binbun-capi/include/binbun/disasm.h`)

Build: `cargo build --release -p binbun-capi`, which names the library `libbinbun_capi` (a release's is `libbinbun`), then `cc -std=c11 -I crates/binbun-capi/include examples/c/NAME.c -L target/release -lbinbun_capi -Wl,-rpath,target/release -o NAME`.
On Windows, in a Visual Studio developer prompt: `cl /std:c11 /I crates\binbun-capi\include examples\c\NAME.c /link /LIBPATH:target\release binbun_capi.dll.lib`, with `target\release\binbun_capi.dll` copied beside `NAME.exe`.

- `c/quick_start.c`: decode a few bytes of x86-64. `./quick_start`
- `c/disassemble.c`: a buffer's instructions with addresses and bytes, x86 or AArch64. `./disassemble`, `./disassemble --arch aarch64 fd7bbfa9 c0035fd6`
- `c/decode_any.c`: one decoder for both architectures (`binbun_decoder`), printing what `rust/decode_any.rs` prints. `./decode_any`, `./decode_any --arch aarch64`, `./decode_any --arch x86-32 --address 0x400000 55 89e5 c3`
- `c/instruction_info.c`: one instruction's operands with access, implicit registers, flags, memory, branch. `./instruction_info`, `./instruction_info --aarch64 c0035fd6`
- `c/color_tokens.c`: instructions coloured from the token API. `./color_tokens`, `./color_tokens --aarch64 200440f9`
- `c/list_calls.c`: read a 64-bit ELF's `.text` by hand and list its calls, named by its symbols; with no file, the test program, found from the path the source was compiled from (run it from where you compiled it). `./list_calls`, `./list_calls /usr/bin/true`

## C++ (`binbun/disasm.hpp`)

Build as C, with `c++ -std=c++17` (MSVC: `cl /std:c++17 /EHsc`).

- `cpp/quick_start.cpp`: decode a few bytes of x86-64 with range-for. `./quick_start`
- `cpp/disassemble.cpp`: a file or hex buffer's instructions with addresses and bytes, x86 or AArch64. `./disassemble`, `./disassemble --arch aarch64 fd7bbfa9 c0035fd6`
- `cpp/decode_any.cpp`: one decoder for both architectures (`binbun::Decoder`, range-for), printing what `rust/decode_any.rs` prints. `./decode_any`, `./decode_any --arch aarch64`
- `cpp/instruction_info.cpp`: one instruction's operands, implicit registers, flags, memory and branch, through the wrapper's accessors. `./instruction_info`, `./instruction_info --aarch64 c0035fd6`
- `cpp/color_tokens.cpp`: instructions coloured from the wrapper's tokens, each a `std::string_view`. `./color_tokens`, `./color_tokens --aarch64 200440f9`
- `cpp/list_calls.cpp`: a 64-bit ELF's `.text` read by hand, bounds checked, and its calls listed through one generic lambda over both decoders; with no file, the test program, as `c/list_calls.c`. `./list_calls`, `./list_calls /usr/bin/true`

## What a processor decides

Not run by the tests: it needs a hybrid Intel processor (performance and efficiency cores), `cc` and `taskset`.

- `undefined/run.sh`: two eight-instruction programs. `lie.s` sets OF by an overflowing `imul r8, r8`, which the architecture defines, so it always prints `0xbeef`; a decompiler that treats a multiply's flags as undefined shows `0xDEAD`, binbun prints `printf("%#llx\n", 0xbeef)`. `twin.s` multiplies by zero (`imul r8, rcx`) and branches on ZF, which a multiply leaves undefined: on an i9-14900F it prints `0xdead` on a P-core (Raptor Cove clears ZF) and `0xbeef` on an E-core (Gracemont sets it when the product is zero); binbun prints `binbun_undefined_bool() ? 0xbeef : 0xdeadL`, and `binbun verify --compare intel-raptor-cove,intel-gracemont` says which core gives which and by what rule. `sh undefined/run.sh`, `sh undefined/run.sh 0 16` (a P-core and an E-core)
