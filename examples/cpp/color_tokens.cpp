// Print instructions coloured by what each piece of text is (mnemonic,
// register, number, address...), as a listing view colours them, from the
// tokens the C++ wrapper gives (Instruction::tokens, range-for over them,
// each token's text a std::string_view). x86-64 or AArch64.
//
// With no bytes given it colours a load, a call and a return.
//
//   ./color_tokens
//   ./color_tokens 488b4310 e800000000 c3
//   ./color_tokens --aarch64 200440f9 00000094
//
// Build as examples/cpp/quick_start.cpp says.
#include <binbun/disasm.hpp>

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Bytes written as hexadecimal digits, two per byte, or nullopt.
std::optional<std::vector<std::uint8_t>> parse_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::uint8_t byte = 0;
        auto [end, error] = std::from_chars(hex.data() + i, hex.data() + i + 2, byte, 16);
        if (error != std::errc() || end != hex.data() + i + 2) return std::nullopt;
        bytes.push_back(byte);
    }
    return bytes;
}

// An ANSI colour per binbun_token_kind; empty leaves the token plain.
std::string_view colour(std::uint8_t kind) {
    switch (kind) {
    case BINBUN_TOKEN_MNEMONIC: return "1;34";
    case BINBUN_TOKEN_PREFIX: return "34";
    case BINBUN_TOKEN_REGISTER: return "32";
    case BINBUN_TOKEN_IMMEDIATE:
    case BINBUN_TOKEN_INTEGER:
    case BINBUN_TOKEN_FLOAT:
    case BINBUN_TOKEN_DISPLACEMENT: return "33";
    case BINBUN_TOKEN_ADDRESS: return "35";
    case BINBUN_TOKEN_SYMBOL: return "36";
    default: return {};
    }
}

// `address` as the line starts with it.
std::string at(std::uint64_t address) {
    char text[32];
    std::snprintf(text, sizeof text, "0x%08llx  ", static_cast<unsigned long long>(address));
    return text;
}

// One line: the address, then each token of `tokens`, coloured.
template <class Tokens>
void print(std::uint64_t address, const Tokens &tokens) {
    std::cout << at(address);
    for (const binbun_token &token : tokens) {
        std::string_view sgr = colour(token.kind);
        if (token.kind == BINBUN_TOKEN_WHITESPACE) {
            std::cout << ' ';  // AArch64 puts a tab after the mnemonic
        } else if (!sgr.empty()) {
            std::cout << "\x1b[" << sgr << 'm' << tokens.text(token) << "\x1b[0m";
        } else {
            std::cout << tokens.text(token);
        }
    }
    std::cout << '\n';
}

// Every instruction `decoder` sweeps, coloured.
template <class Decoder>
void colour_all(const Decoder &decoder) {
    for (const auto &decoded : decoder) {
        if (decoded.ok()) {
            print(decoded.address, decoded.instruction.tokens(decoded.address));
        } else {
            std::cout << at(decoded.address) << "(bad)\n";
        }
    }
}

}  // namespace

int main(int argc, char **argv) {
    std::vector<std::string_view> args(argv + 1, argv + argc);
    bool aarch64 = !args.empty() && args.front() == "--aarch64";
    std::string hex;
    for (std::size_t i = aarch64 ? 1 : 0; i < args.size(); i++) hex += args[i];
    if (hex.empty()) hex = aarch64 ? "200440f900000094c0035fd6" : "488b4310e800000000c3";  // a load, a call, a return
    auto code = parse_hex(hex);
    if (!code || code->empty()) {
        std::cerr << "usage: color_tokens [--aarch64] [HEX...]\n";
        return 1;
    }
    if (aarch64) {
        colour_all(binbun::aarch64::Decoder(*code, 0x1000));
    } else {
        colour_all(binbun::x86::Decoder(binbun::x86::Mode::Bits64, *code, 0x1000));
    }
    return 0;
}
