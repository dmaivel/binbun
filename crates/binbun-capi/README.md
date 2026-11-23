# binbun-capi

`libbinbun`: binbun's C API, for C and C++. So far it is the x86 and AArch64 disassemblers of [binbun](https://binbun.org): C headers (`binbun/binbun.h` includes them all: `binbun/core.h`, what every part shares, and `binbun/disasm.h`), header-only C++ wrappers and pkg-config metadata (`binbun`). Every [release](https://github.com/dmaivel/binbun/releases) has the shared and static libraries with their headers; this crate builds them with [cargo-c](https://github.com/lu-zero/cargo-c) (`cargo cinstall`).

```c
#include <inttypes.h>
#include <stdio.h>
#include <binbun/binbun.h>

int main(void) {
    const uint8_t code[] = {0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3};

    binbun_decoder dec;
    binbun_decoder_init(&dec, BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64,
                        code, sizeof code, 0x401000);

    binbun_instruction insn;
    uint64_t addr;
    char text[BINBUN_MAX_TEXT + 1];
    while (binbun_decoder_next(&dec, &insn, &addr) == BINBUN_STATUS_OK) {
        binbun_instruction_text(&insn, BINBUN_TEXT_DEFAULT, text, sizeof text);
        printf("%#" PRIx64 "  %s\n", addr, text);
    }
}
```

`binbun_decode` and `binbun_decoder_init` decode either architecture through one API, the architecture chosen by the caller (`BINBUN_ARCH_X86` in a mode, as above, or `BINBUN_ARCH_AARCH64`), as the Rust crate [`binbun-disasm`](https://crates.io/crates/binbun-disasm) does: each instruction's address, bytes, mnemonic, text, control flow and the registers it reads and writes, and the native instruction (`binbun_x86_*`, `binbun_aarch64_*`) for the rest.

The [C API documentation](https://binbun.org/docs/c-api/) gives each function's ownership, status and buffer contract.

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option.
