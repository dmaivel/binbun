use binbun_disasm::{Arch, Decoder, x86};

fn main() {
    let code = [0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];

    for (address, decoded) in Decoder::new(Arch::X86(x86::Mode::Bits64), &code, 0x40_1000) {
        if let Ok(insn) = decoded {
            println!("{address:#x}  {insn}");
        }
    }
}
