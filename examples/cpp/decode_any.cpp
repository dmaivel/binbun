// Disassemble a buffer of machine code given in hexadecimal on the command
// line for x86 (64, 32 or 16-bit) or AArch64 through one decoder
// (binbun::Decoder, range-for): each instruction's address, bytes, text,
// mnemonic, and the registers it reads and writes. Bytes that are no
// instruction are shown with the reason and stepped over (one byte on x86,
// four on AArch64). What one architecture alone has (operands, flags) is the
// native instruction's: instruction.as_x86() or instruction.as_aarch64().
//
// With no bytes given it disassembles a small function of its own (a
// prologue, a call, an epilogue) for the architecture. It prints what
// examples/rust/decode_any.rs prints.
//
//   ./decode_any
//   ./decode_any --arch aarch64
//   ./decode_any --arch x86-32 --address 0x400000 55 89e5 c3
//
// Build as examples/cpp/quick_start.cpp says.
#include <binbun/disasm.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

int usage() {
    std::fputs("usage: decode_any [--arch x86-64|x86-32|x86-16|aarch64] [--address ADDRESS] [HEX...]\n", stderr);
    return 1;
}

// The architecture `name` names, and what is disassembled when no bytes are
// given: push the frame pointer, set it, call the next instruction, pop it,
// return.
std::optional<std::pair<binbun::Arch, std::string>> arch_named(const std::string &name) {
    using binbun::Arch;
    using binbun::x86::Mode;
    if (name == "x86-64") return std::pair{Arch::x86(Mode::Bits64), std::string("554889e5e8000000005dc3")};
    if (name == "x86-32") return std::pair{Arch::x86(Mode::Bits32), std::string("5589e5e8000000005dc3")};
    if (name == "x86-16") return std::pair{Arch::x86(Mode::Bits16), std::string("5589e5e800005dc3")};
    if (name == "aarch64") {
        return std::pair{Arch::aarch64(), std::string("fd7bbfa9fd03009101000094fd7bc1a8c0035fd6")};
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> parse_hex(const std::string &hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::size_t used = 0;
        unsigned long byte = 0;
        try {
            byte = std::stoul(hex.substr(i, 2), &used, 16);
        } catch (const std::exception &) {
            return std::nullopt;
        }
        if (used != 2) return std::nullopt;
        bytes.push_back(static_cast<std::uint8_t>(byte));
    }
    return bytes;
}

// The address and `length` bytes at `bytes`, padded to `width` characters
// (longer instructions push the rest right).
void print_start(std::uint64_t address, const std::uint8_t *bytes, std::size_t length, std::size_t width) {
    std::string shown;
    for (std::size_t i = 0; i < length; i++) {
        char pair[4];
        std::snprintf(pair, sizeof pair, i == 0 ? "%02x" : " %02x", bytes[i]);
        shown += pair;
    }
    shown.resize(std::max(shown.size(), width), ' ');
    std::printf("%016llx  %s ", static_cast<unsigned long long>(address), shown.c_str());
}

// The registers by name, `-` for none.
std::string names(const binbun::Registers &registers) {
    std::string joined;
    for (const binbun_register &reg : registers) {
        joined += (joined.empty() ? "" : " ") + binbun::register_name(reg);
    }
    return joined.empty() ? "-" : joined;
}

}  // namespace

int main(int argc, char **argv) {
    std::string name = "x86-64", hex;
    std::uint64_t base = 0x1000;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--arch" && i + 1 < argc) {
            name = argv[++i];
        } else if (arg == "--address" && i + 1 < argc) {
            base = std::stoull(argv[++i], nullptr, 0);
        } else {
            hex += arg;
        }
    }
    auto arch = arch_named(name);
    if (!arch) {
        std::fprintf(stderr, "decode_any: unknown architecture %s\n", name.c_str());
        return usage();
    }
    auto code = parse_hex(hex.empty() ? arch->second : hex);
    if (!code) {
        std::fprintf(stderr, "decode_any: %s: not hexadecimal bytes\n", hex.c_str());
        return usage();
    }

    // Eight bytes of x86 or one AArch64 word before the text.
    bool aarch64 = arch->first == binbun::Arch::aarch64();
    std::size_t width = (aarch64 ? 4 : 8) * 3;
    for (const auto &decoded : binbun::Decoder(arch->first, *code, base)) {
        if (!decoded.ok()) {
            // What the decoder stepped over: a byte on x86, four on AArch64.
            std::size_t offset = static_cast<std::size_t>(decoded.address - base);
            std::size_t step = std::min<std::size_t>(aarch64 ? 4 : 1, code->size() - offset);
            print_start(decoded.address, code->data() + offset, step, width);
            std::printf("(%s)\n", std::string(binbun::status_name(decoded.status)).c_str());
            continue;
        }
        const binbun::Instruction &instruction = decoded.instruction;
        std::string text = instruction.text();
        std::replace(text.begin(), text.end(), '\t', ' ');
        std::string mnemonic(instruction.mnemonic());
        print_start(decoded.address, instruction.bytes(), instruction.length(), width);
        std::printf("%-28s %-6s reads %s; writes %s\n", text.c_str(), mnemonic.c_str(),
                    names(instruction.registers_read()).c_str(), names(instruction.registers_written()).c_str());
    }
    return 0;
}
