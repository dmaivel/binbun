// Disassemble a file of raw machine code, or bytes in hexadecimal on the
// command line: each instruction's address, bytes and text, x86-64, x86-32
// or AArch64, with range-for over the C++ wrapper's decoders. Bytes that
// are no instruction are shown with the reason.
//
// With no bytes given it disassembles a small function of its own (a
// prologue, a call, an epilogue) for the architecture.
//
//   ./disassemble
//   ./disassemble 55 4889e5 e800000000 c3
//   ./disassemble --arch aarch64 --address 0x1000 fd7bbfa9 fd030091 c0035fd6
//   ./disassemble --arch x86-32 --file code.bin
//
// Build as examples/cpp/quick_start.cpp says.
#include <binbun/disasm.hpp>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

namespace {

int usage() {
    std::fputs("usage: disassemble [--arch x86-64|x86-32|aarch64] [--address ADDRESS] [--file FILE | HEX...]\n",
               stderr);
    return 1;
}

// What is disassembled when no bytes are given: push the frame pointer, set
// it, call the next instruction, pop it, return.
std::string example(const std::string &arch) {
    if (arch == "aarch64") return "fd7bbfa9fd03009101000094fd7bc1a8c0035fd6";
    if (arch == "x86-32") return "5589e5e8000000005dc3";
    return "554889e5e8000000005dc3";
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

// One line: address, the `length` bytes at `bytes` (padded to `width`), text.
void print_line(std::uint64_t address, const std::uint8_t *bytes, std::size_t length, std::size_t width,
                const std::string &text) {
    std::printf("%016llx  ", static_cast<unsigned long long>(address));
    for (std::size_t i = 0; i < width || i < length; i++) {
        if (i < length) {
            std::printf("%02x ", bytes[i]);
        } else {
            std::fputs("   ", stdout);
        }
    }
    std::printf("%s\n", text.c_str());
}

std::string bad(binbun_status status) { return "(bad: " + std::string(binbun::status_name(status)) + ")"; }

}  // namespace

int main(int argc, char **argv) {
    std::string arch = "x86-64", hex, file;
    std::uint64_t base = 0x1000;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--arch" && i + 1 < argc) {
            arch = argv[++i];
        } else if (arg == "--address" && i + 1 < argc) {
            base = std::stoull(argv[++i], nullptr, 0);
        } else if (arg == "--file" && i + 1 < argc) {
            file = argv[++i];
        } else {
            hex += arg;
        }
    }
    std::vector<std::uint8_t> code;
    if (!file.empty()) {
        std::ifstream in(file, std::ios::binary);
        if (!in) {
            std::fprintf(stderr, "disassemble: cannot open %s\n", file.c_str());
            return 1;
        }
        code.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    } else if (auto bytes = parse_hex(hex.empty() ? example(arch) : hex)) {
        code = *bytes;
    } else {
        std::fprintf(stderr, "disassemble: %s: not hexadecimal bytes\n", hex.c_str());
        return usage();
    }
    if (code.empty()) return usage();

    if (arch == "x86-64" || arch == "x86-32") {
        auto mode = arch == "x86-64" ? binbun::x86::Mode::Bits64 : binbun::x86::Mode::Bits32;
        for (const auto &decoded : binbun::x86::Decoder(mode, code, base)) {
            const std::uint8_t *bytes = code.data() + (decoded.address - base);
            if (decoded.ok()) {
                print_line(decoded.address, bytes, decoded.instruction.length(), 8,
                           decoded.instruction.text(decoded.address));
            } else {
                print_line(decoded.address, bytes, 1, 8, bad(decoded.status));
            }
        }
    } else if (arch == "aarch64") {
        for (const auto &decoded : binbun::aarch64::Decoder(code, base)) {
            std::size_t offset = static_cast<std::size_t>(decoded.address - base);
            std::size_t length = std::min<std::size_t>(4, code.size() - offset);
            std::string text = decoded.ok() ? decoded.instruction.text(decoded.address) : bad(decoded.status);
            if (auto tab = text.find('\t'); tab != std::string::npos) text[tab] = ' ';
            print_line(decoded.address, code.data() + offset, length, 4, text);
        }
    } else {
        std::fprintf(stderr, "disassemble: unknown architecture %s\n", arch.c_str());
        return usage();
    }
    return 0;
}
