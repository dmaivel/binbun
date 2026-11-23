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
