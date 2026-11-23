# binbun-x86

An x86 and x86-64 instruction decoder, generated from Intel XED's datafiles: 16-, 32- and 64-bit modes, operands with their access, implicit registers, flag effects, control flow, and Intel-syntax text. It is the x86 disassembler of [binbun](https://binbun.org), usable on its own.

```rust
use binbun_x86::{Decoder, Mode};

let code = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];
for (address, decoded) in Decoder::new(&code, Mode::Bits64, 0x40_1000) {
    match decoded {
        Ok(insn) => println!("{address:#x}  {}", insn.intel(address)),
        Err(error) => println!("{address:#x}  (bad: {error})"),
    }
}
```

For x86 and AArch64 through one API, see [`binbun-disasm`](https://crates.io/crates/binbun-disasm). More examples are in the [repository](https://github.com/dmaivel/binbun/tree/main/examples/rust).

Licensed under either of [Apache License, Version 2.0](https://github.com/dmaivel/binbun/blob/main/LICENSE-APACHE) or [MIT license](https://github.com/dmaivel/binbun/blob/main/LICENSE-MIT) at your option, except the code generated from Intel XED, which is under XED's Apache License, Version 2.0 (`LICENSE-XED`).
