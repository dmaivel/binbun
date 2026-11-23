// The C++ wrapper: `disasm_test_cpp <x86-64|x86-32|aarch64> <address> <file>`
// sweeps the code in <file> with binbun::x86::Decoder or
// binbun::aarch64::Decoder (range-for) and prints, per instruction, the
// notation tests/capi.rs prints from the Rust API; binbun::Instruction and
// binbun::Decoder, for either architecture, must agree with them. Built by
// tests/capi.rs with -Wall -Wextra -Werror -std=c++17.
#include <binbun/disasm.hpp>

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

[[noreturn]] void fail(const std::string &message) {
    std::fprintf(stderr, "disasm_test_cpp: %s\n", message.c_str());
    std::exit(1);
}

void require(bool condition, const char *what) {
    if (!condition) fail(what);
}

void print_branch(const binbun_branch &branch) {
    std::printf(" branch=%u%s/%u/%" PRIx64, branch.kind, branch.conditional ? "?" : "", branch.target_kind,
                branch.target);
}

// The tokens, which together are the text.
template <class Tokens>
void check_tokens(const Tokens &tokens, std::string_view text) {
    std::string joined;
    for (const binbun_token &token : tokens) {
        joined += tokens.text(token);
    }
    require(tokens.text() == text && joined == text, "tokens are the text");
}

// The instruction at `address`, `offset` bytes into `code`, decoded for
// either architecture: the native instruction's length and text, its
// registers named.
binbun::Instruction either(binbun::Arch arch, const std::vector<std::uint8_t> &code, std::size_t offset,
                           std::uint64_t address, std::uint8_t length, const std::string &text) {
    auto instruction = binbun::Instruction::decode(arch, code.data() + offset, code.size() - offset, address);
    require(instruction && instruction->arch() == arch && instruction->address() == address, "either decodes");
    require(instruction->length() == length && instruction->text() == text, "either agrees with the native");
    for (const binbun_register &reg : instruction->registers_read()) {
        require(!binbun::register_name(reg).empty(), "registers read are named");
    }
    for (const binbun_register &reg : instruction->registers_written()) {
        require(!binbun::register_name(reg).empty(), "registers written are named");
    }
    return *instruction;
}

// The addresses of the instructions binbun::Decoder finds in `code`.
std::vector<std::uint64_t> sweep(binbun::Arch arch, std::uint64_t address, const std::vector<std::uint8_t> &code) {
    binbun::Decoder decoder(arch, code, address);
    require(decoder.status() == BINBUN_STATUS_OK, "decoder starts");
    std::vector<std::uint64_t> found;
    for (const auto &decoded : decoder) {
        if (decoded.ok()) {
            require(decoded.instruction.address() == decoded.address, "sweep address");
            found.push_back(decoded.address);
        }
    }
    return found;
}

void dump_x86(binbun::x86::Mode mode, std::uint64_t address, const std::vector<std::uint8_t> &code) {
    binbun::x86::Decoder decoder(mode, code, address);
    require(decoder.status() == BINBUN_STATUS_OK, "decoder starts");
    std::vector<std::uint64_t> found;
    for (const auto &decoded : decoder) {
        if (!decoded.ok()) {
            std::printf("@%" PRIx64 " %d\n", decoded.address, decoded.status);
            continue;
        }
        const binbun::x86::Instruction &instruction = decoded.instruction;
        std::string text = instruction.text(decoded.address);
        std::string_view mnemonic = instruction.mnemonic_name();
        std::printf("@%" PRIx64 " len=%u mnem=%.*s ops=%zu text=%s", decoded.address, instruction.length(),
                    static_cast<int>(mnemonic.size()), mnemonic.data(), instruction.operands().size(), text.c_str());
        print_branch(instruction.branch(decoded.address));
        std::printf("\n");
        check_tokens(instruction.tokens(decoded.address), text);
        // Decoding the bytes again gives the same instruction.
        std::size_t offset = static_cast<std::size_t>(decoded.address - address);
        auto again = binbun::x86::Instruction::decode(mode, code.data() + offset, code.size() - offset);
        require(again && again->form() == instruction.form(), "decode agrees with the sweep");
        auto any = either(binbun::Arch::x86(mode), code, offset, decoded.address, instruction.length(), text);
        require(any.as_x86() && any.as_x86()->form() == instruction.form() && !any.as_aarch64(), "native x86");
        found.push_back(decoded.address);
    }
    require(sweep(binbun::Arch::x86(mode), address, code) == found, "the sweeps agree");
}

void dump_aarch64(std::uint64_t address, const std::vector<std::uint8_t> &code) {
    binbun::aarch64::Decoder decoder(code, address);
    require(decoder.status() == BINBUN_STATUS_OK, "decoder starts");
    std::vector<std::uint64_t> found;
    for (const auto &decoded : decoder) {
        if (!decoded.ok()) {
            std::printf("@%" PRIx64 " %d\n", decoded.address, decoded.status);
            continue;
        }
        const binbun::aarch64::Instruction &instruction = decoded.instruction;
        std::string text = instruction.text(decoded.address);
        std::string_view mnemonic = instruction.mnemonic();
        std::string_view encoding = instruction.encoding_name();
        std::printf("@%" PRIx64 " word=%08x mnem=%.*s enc=%.*s ops=%zu text=%s", decoded.address, instruction.word(),
                    static_cast<int>(mnemonic.size()), mnemonic.data(), static_cast<int>(encoding.size()),
                    encoding.data(), instruction.operands().size(), text.c_str());
        print_branch(instruction.branch(decoded.address));
        std::printf("\n");
        check_tokens(instruction.tokens(decoded.address), text);
        auto again = binbun::aarch64::Instruction::decode(instruction.word());
        require(again && again->encoding() == instruction.encoding(), "decode agrees with the sweep");
        std::size_t offset = static_cast<std::size_t>(decoded.address - address);
        auto any = either(binbun::Arch::aarch64(), code, offset, decoded.address, instruction.length(), text);
        require(any.as_aarch64() && any.as_aarch64()->word() == instruction.word() && !any.as_x86(), "native A64");
        found.push_back(decoded.address);
    }
    require(sweep(binbun::Arch::aarch64(), address, code) == found, "the sweeps agree");
}

}  // namespace

int main(int argc, char **argv) {
    if (binbun::version() != BINBUN_VERSION) fail("library version differs from the header's");
    if (argc != 4) fail("usage: disasm_test_cpp <x86-64|x86-32|aarch64> <address> <file>");
    std::string arch = argv[1];
    std::uint64_t address = std::strtoull(argv[2], nullptr, 16);
    std::ifstream file(argv[3], std::ios::binary);
    if (!file) fail("cannot open the file");
    std::vector<std::uint8_t> code((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (arch == "x86-64") {
        dump_x86(binbun::x86::Mode::Bits64, address, code);
    } else if (arch == "x86-32") {
        dump_x86(binbun::x86::Mode::Bits32, address, code);
    } else if (arch == "aarch64") {
        dump_aarch64(address, code);
    } else {
        fail("unknown architecture");
    }
    return 0;
}
