# binbun-disasm

The x86 and AArch64 disassemblers of [binbun](https://binbun.org) through one API: decode, print and inspect instructions (operands, the registers they read and write, control flow) the same way for either architecture. For everything one architecture's decoder offers, use [`binbun-x86`](https://crates.io/crates/binbun-x86) or [`binbun-aarch64`](https://crates.io/crates/binbun-aarch64).

```rust
use binbun_disasm::{Arch, Decoder, x86};

let code = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
for (address, decoded) in Decoder::new(Arch::X86(x86::Mode::Bits64), &code, 0x40_1000) {
    if let Ok(insn) = decoded {
        println!("{address:#x}  {insn}");
    }
}
```

The features `x86` and `aarch64` (both on by default) choose the architectures. More examples are in the [repository](https://github.com/dmaivel/binbun/tree/main/examples/rust).

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option.
