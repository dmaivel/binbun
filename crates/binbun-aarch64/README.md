# binbun-aarch64

An AArch64 (A64) instruction decoder, generated from Arm's machine-readable specification: operands, implicit registers, control flow, and text as LLVM writes it. It is the AArch64 disassembler of [binbun](https://binbun.org), usable on its own.

```rust
use binbun_aarch64::Decoder;

// stp x29, x30, [sp, #-0x10]! and ret, little-endian as in memory.
let code = [0xfd, 0x7b, 0xbf, 0xa9, 0xc0, 0x03, 0x5f, 0xd6];
for (address, decoded) in Decoder::new(&code, 0x1000) {
    match decoded {
        Ok(insn) => println!("{address:#x}  {}", insn.display(address)),
        Err(error) => println!("{address:#x}  ({error})"),
    }
}
```

For x86 and AArch64 through one API, see [`binbun-disasm`](https://crates.io/crates/binbun-disasm). More examples are in the [repository](https://github.com/dmaivel/binbun/tree/main/examples/rust).

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option, except the code generated from Arm's A-profile Machine Readable Specification, which is under Arm's BSD 3-Clause licence (`NOTICE-AARCHMRS.html`).
