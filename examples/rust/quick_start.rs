//! Quick start: decode a few bytes of x86-64 machine code and print each
//! instruction at its address. No file, no database: the decoder alone,
//! through `binbun-disasm`, the same API for AArch64
//! (`Arch::Aarch64`).
//!
//! ```text
//! cargo run -p binbun-disasm --example quick_start
//! ```

use binbun_disasm::{Arch, Decoder, x86};

fn main() {
    let code = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];

    for (address, decoded) in Decoder::new(Arch::X86(x86::Mode::Bits64), &code, 0x40_1000) {
        if let Ok(insn) = decoded {
            println!("{address:#x}  {insn}");
        }
    }
}
