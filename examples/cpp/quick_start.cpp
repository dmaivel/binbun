// Quick start: decode a few bytes of x86-64 machine code with the C++
// wrapper (binbun/disasm.hpp) and print each instruction at its address,
// through the decoder for either architecture, the same for AArch64
// (Arch::aarch64()).
//
//   cargo build --release -p binbun-capi
//   c++ -std=c++17 -I crates/binbun-capi/include examples/cpp/quick_start.cpp
//       -L target/release -lbinbun_capi -Wl,-rpath,target/release -o quick_start   (one line)
//   ./quick_start
#include <array>
#include <cstdint>
#include <iostream>
#include <binbun/disasm.hpp>

int main() {
    const std::array<std::uint8_t, 8> code = {0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3};

    using namespace binbun;
    for (const auto &d : Decoder(Arch::x86(x86::Mode::Bits64), code, 0x401000)) {
        if (d.ok()) {
            std::cout << std::hex << "0x" << d.address << "  " << d.instruction.text() << '\n';
        }
    }
}
