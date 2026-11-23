// Show what one instruction does: its operands and whether it reads or
// writes each, the registers it uses without naming them, the flags it
// reads and writes, the memory it accesses and where it branches. x86-64 or
// AArch64, through the C++ wrapper's Instruction::decode, operands(),
// flags(), branch(), memory() and implicit_reads()/implicit_writes().
//
// With no bytes given it shows add qword ptr [rbx+0x10], rax (x86-64) or
// stp x29, x30, [sp, #-0x10]! (AArch64).
//
//   ./instruction_info
//   ./instruction_info 48014310                 # add qword ptr [rbx+0x10], rax
//   ./instruction_info --aarch64 c0035fd6       # ret: reads x30
//
// Build as examples/cpp/quick_start.cpp says.
#include <binbun/disasm.hpp>

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::uint64_t address = 0x1000;

constexpr std::string_view access_names[] = {"-", "read", "write", "read/write"};

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

std::string hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

// The names of the flags of `names` set in `flags`, or "-".
template <class Names>
std::string flag_names(std::uint32_t flags, const Names &names) {
    std::string out;
    for (const auto &[bit, name] : names) {
        if (flags & bit) out += (out.empty() ? "" : " ") + std::string(name);
    }
    return out.empty() ? "-" : out;
}

std::string branch(const binbun_branch &b) {
    constexpr std::string_view kinds[] = {"none", "jump", "call", "return", "trap", "system call", "exception return",
                                          "halt"};
    std::string out(b.kind < std::size(kinds) ? kinds[b.kind] : "?");
    if (b.target_kind == BINBUN_TARGET_ADDRESS) out += " to " + hex(b.target);
    return out;
}

std::string x86_register(binbun_x86_register reg) { return std::string(binbun::x86::register_name(reg)); }

int x86_info(const std::vector<std::uint8_t> &code) {
    binbun_status status = BINBUN_STATUS_OK;
    auto instruction = binbun::x86::Instruction::decode(binbun::x86::Mode::Bits64, code.data(), code.size(), &status);
    if (!instruction) {
        std::cerr << "instruction_info: " << binbun::status_name(status) << '\n';
        return 1;
    }
    std::cout << hex(address) << ": " << instruction->text(address) << "\n  mnemonic " << instruction->mnemonic_name()
              << ", length " << unsigned(instruction->length()) << "\n  operands:\n";
    std::size_t n = 0;
    for (const binbun_x86_operand &op : instruction->operands()) {
        std::string value;
        switch (op.kind) {
        case BINBUN_X86_OPERAND_REGISTER:
            value = x86_register(op.reg);
            break;
        case BINBUN_X86_OPERAND_MEMORY: {
            value = "[";
            if (op.base) value += x86_register(op.base);
            if (op.index) value += "+" + x86_register(op.index) + "*" + std::to_string(op.scale);
            std::uint64_t magnitude = std::uint64_t(op.displacement);
            if (op.displacement < 0) magnitude = 0 - magnitude;
            value += (op.displacement < 0 ? "-" : "+") + hex(magnitude) + "] (" + std::to_string(op.memory_size) +
                     " bytes)";
            break;
        }
        case BINBUN_X86_OPERAND_RELATIVE:
            value = std::to_string(op.displacement) + " from the next instruction";
            break;
        default:
            value = hex(op.value);
        }
        if (op.visibility == BINBUN_X86_VISIBILITY_SUPPRESSED) value += " (implicit)";
        std::cout << "    " << n++ << "  " << std::left << std::setw(10) << access_names[op.access & 3] << ' '
                  << std::right << std::setw(3) << unsigned(op.bits) << " bits  " << value << '\n';
    }
    constexpr std::pair<std::uint32_t, std::string_view> flags[] = {
        {BINBUN_X86_FLAG_CF, "cf"}, {BINBUN_X86_FLAG_PF, "pf"}, {BINBUN_X86_FLAG_AF, "af"},
        {BINBUN_X86_FLAG_ZF, "zf"}, {BINBUN_X86_FLAG_SF, "sf"}, {BINBUN_X86_FLAG_TF, "tf"},
        {BINBUN_X86_FLAG_IF, "if"}, {BINBUN_X86_FLAG_DF, "df"}, {BINBUN_X86_FLAG_OF, "of"}};
    binbun_x86_flag_effect effect = instruction->flags();
    std::cout << "  flags read: " << flag_names(effect.read, flags) << "; written: " << flag_names(effect.written, flags)
              << "\n  branch: " << branch(instruction->branch(address)) << '\n';
    return 0;
}

std::string a64_register(const binbun_aarch64_register &r) {
    constexpr std::string_view classes[] = {"",  "w", "x", "w", "x", "b",  "h",  "s", "d",
                                            "q", "v", "z", "p", "pn", "zt", "c", "ffr"};
    bool general = r.class_ == BINBUN_AARCH64_REG_X || r.class_ == BINBUN_AARCH64_REG_W;
    bool stack = r.class_ == BINBUN_AARCH64_REG_XSP || r.class_ == BINBUN_AARCH64_REG_WSP;
    bool x = r.class_ == BINBUN_AARCH64_REG_X || r.class_ == BINBUN_AARCH64_REG_XSP;
    if (r.number == 31 && stack) return x ? "sp" : "wsp";
    if (r.number == 31 && general) return x ? "xzr" : "wzr";
    if (r.class_ == BINBUN_AARCH64_REG_FFR) return "ffr";
    return std::string(r.class_ < std::size(classes) ? classes[r.class_] : "?") + std::to_string(r.number);
}

std::string a64_registers(const binbun::aarch64::Registers &registers) {
    std::string out;
    for (const binbun_aarch64_register &r : registers) out += (out.empty() ? "" : " ") + a64_register(r);
    return out.empty() ? "-" : out;
}

int aarch64_info(const std::vector<std::uint8_t> &code) {
    binbun_status status = BINBUN_STATUS_OK;
    auto instruction = binbun::aarch64::Instruction::decode(code.data(), code.size(), &status);
    if (!instruction) {
        std::cerr << "instruction_info: " << binbun::status_name(status) << '\n';
        return 1;
    }
    std::string text = instruction->text(address);
    if (auto tab = text.find('\t'); tab != std::string::npos) text[tab] = ' ';
    std::cout << hex(address) << ": " << text << "\n  encoding " << instruction->encoding_name() << "\n  operands:\n";
    std::size_t n = 0;
    for (const binbun_aarch64_operand &op : instruction->operands()) {
        std::string value;
        switch (op.kind) {
        case BINBUN_AARCH64_OPERAND_REGISTER:
        case BINBUN_AARCH64_OPERAND_WRITEBACK:
            value = a64_register(op.detail.reg);
            break;
        case BINBUN_AARCH64_OPERAND_MEMORY:
            value = "memory at [" + a64_register(op.detail.memory.base) +
                    (op.detail.memory.writeback ? ", written back]" : "]");
            break;
        case BINBUN_AARCH64_OPERAND_IMMEDIATE:
            value = "immediate " + hex(op.detail.immediate.value);
            break;
        case BINBUN_AARCH64_OPERAND_LABEL:
            value = "label " + std::to_string(op.detail.label.offset);
            break;
        default:
            value = "(operand kind " + std::to_string(op.kind) + ")";
        }
        std::cout << "    " << n++ << "  " << std::left << std::setw(10) << access_names[op.access & 3] << ' '
                  << value << '\n';
    }
    std::cout << "  implicit reads: " << a64_registers(instruction->implicit_reads())
              << "; writes: " << a64_registers(instruction->implicit_writes()) << '\n';
    if (auto memory = instruction->memory()) {
        constexpr std::string_view kinds[] = {"",         "load", "store",    "atomic",   "exclusive load",
                                              "exclusive store", "prefetch", "copy", "tag load", "tag store"};
        std::cout << "  memory: " << (memory->kind < std::size(kinds) ? kinds[memory->kind] : "?") << " of "
                  << memory->size << " bytes\n";
    }
    constexpr std::pair<std::uint32_t, std::string_view> flags[] = {
        {BINBUN_AARCH64_FLAG_N, "n"}, {BINBUN_AARCH64_FLAG_Z, "z"}, {BINBUN_AARCH64_FLAG_C, "c"},
        {BINBUN_AARCH64_FLAG_V, "v"}};
    binbun_aarch64_flag_effect effect = instruction->flags();
    std::cout << "  flags read: " << flag_names(effect.read, flags) << "; written: " << flag_names(effect.written, flags)
              << "\n  branch: " << branch(instruction->branch(address)) << '\n';
    return 0;
}

}  // namespace

int main(int argc, char **argv) {
    std::vector<std::string_view> args(argv + 1, argv + argc);
    bool aarch64 = !args.empty() && args.front() == "--aarch64";
    std::string hex_bytes;
    for (std::size_t i = aarch64 ? 1 : 0; i < args.size(); i++) hex_bytes += args[i];
    if (hex_bytes.empty()) hex_bytes = aarch64 ? "fd7bbfa9" : "48014310";  // no bytes given: an example
    auto code = parse_hex(hex_bytes);
    if (!code || code->empty()) {
        std::cerr << "usage: instruction_info [--aarch64] [HEX]\n";
        return 1;
    }
    return aarch64 ? aarch64_info(*code) : x86_info(*code);
}
