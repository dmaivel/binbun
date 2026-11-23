// List the calls in a 64-bit ELF executable's .text (x86-64 or AArch64):
// each call's address, its text, and where it goes, named by the ELF's
// symbols where one starts there. The ELF is read here, by hand, bounds
// checked: the C++ wrapper only decodes. One sweep serves both
// architectures, through a generic lambda over the wrapper's decoders.
//
// With no file given it reads the checked-in test program
// (tests/fixtures/program-x86_64.elf), found from this source file's path
// as it was compiled; give a path to run on your own binary.
//
//   ./list_calls
//   ./list_calls /usr/bin/true
//
// Build as examples/cpp/quick_start.cpp says.
#include <binbun/disasm.hpp>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::uint16_t em_x86_64 = 62;
constexpr std::uint16_t em_aarch64 = 183;
constexpr std::uint32_t sht_symtab = 2;
constexpr std::uint32_t sht_nobits = 8;
constexpr std::uint32_t sht_dynsym = 11;
constexpr std::uint8_t stt_func = 2;

struct Section {
    std::string_view name;
    std::uint32_t type = 0;
    std::uint32_t link = 0;
    std::uint64_t address = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    // Whether its bytes are all in the file (or it has none there).
    bool in_file = false;
};

// A 64-bit little-endian ELF file, read whole: its machine, its sections
// and the names of its function symbols.
class Elf {
public:
    // `data` as an ELF, or nullopt if it is not a 64-bit little-endian one.
    static std::optional<Elf> parse(std::vector<std::uint8_t> data) {
        if (data.size() < 64 || std::memcmp(data.data(), "\x7f" "ELF", 4) != 0 || data[4] != 2 || data[5] != 1) {
            return std::nullopt;
        }
        Elf elf(std::move(data));
        std::uint64_t table = elf.field(40, 8);
        std::uint64_t count = elf.field(60, 2);
        for (std::uint64_t i = 0; i < count; i++) {
            std::uint64_t at = table + i * 64;
            Section section;
            section.type = static_cast<std::uint32_t>(elf.field(at + 4, 4));
            section.address = elf.field(at + 16, 8);
            section.offset = elf.field(at + 24, 8);
            section.size = elf.field(at + 32, 8);
            section.link = static_cast<std::uint32_t>(elf.field(at + 40, 4));
            section.in_file = section.type == sht_nobits || elf.inside(section.offset, section.size);
            elf.sections_.push_back(section);
        }
        std::uint64_t names = elf.field(62, 2);
        for (std::uint64_t i = 0; i < count && names < count; i++) {
            elf.sections_[i].name = elf.string(elf.sections_[names], elf.field(table + i * 64, 4));
        }
        return elf;
    }

    std::uint16_t machine() const noexcept { return static_cast<std::uint16_t>(field(18, 2)); }
    const std::vector<Section> &sections() const noexcept { return sections_; }
    const std::uint8_t *bytes(const Section &section) const noexcept { return data_.data() + section.offset; }

    // The name of a function symbol at `address`, or nullopt.
    std::optional<std::string_view> symbol_at(std::uint64_t address) const {
        for (const Section &table : sections_) {
            if ((table.type != sht_symtab && table.type != sht_dynsym) || !table.in_file ||
                table.link >= sections_.size()) {
                continue;
            }
            const Section &strings = sections_[table.link];
            for (std::uint64_t at = table.offset; at + 24 <= table.offset + table.size; at += 24) {
                bool function = (data_[at + 4] & 0xf) == stt_func;
                std::uint64_t name = field(at, 4);
                if (function && name != 0 && field(at + 8, 8) == address) {
                    std::string_view text = string(strings, name);
                    if (!text.empty()) return text;
                }
            }
        }
        return std::nullopt;
    }

private:
    explicit Elf(std::vector<std::uint8_t> data) : data_(std::move(data)) {}

    bool inside(std::uint64_t offset, std::uint64_t size) const noexcept {
        return offset <= data_.size() && data_.size() - offset >= size;
    }

    // The little-endian field of `size` bytes at `offset`; 0 past the end.
    std::uint64_t field(std::uint64_t offset, unsigned size) const noexcept {
        if (!inside(offset, size)) return 0;
        std::uint64_t value = 0;
        for (unsigned i = size; i > 0; i--) value = value << 8 | data_[offset + i - 1];
        return value;
    }

    // The NUL-terminated string at `offset` of `table`; empty if there is none.
    std::string_view string(const Section &table, std::uint64_t offset) const noexcept {
        if (!table.in_file || table.type == sht_nobits || offset >= table.size) return {};
        const char *start = reinterpret_cast<const char *>(data_.data() + table.offset + offset);
        const void *end = std::memchr(start, 0, table.size - offset);
        return end == nullptr ? std::string_view() : std::string_view(start, static_cast<const char *>(end) - start);
    }

    std::vector<std::uint8_t> data_;
    std::vector<Section> sections_;
};

// Where `branch` goes.
std::string describe(const Elf &elf, const binbun_branch &branch) {
    char text[64];
    switch (branch.target_kind) {
    case BINBUN_TARGET_ADDRESS:
        if (auto name = elf.symbol_at(branch.target)) return std::string(*name);
        std::snprintf(text, sizeof text, "0x%" PRIx64, branch.target);
        return text;
    case BINBUN_TARGET_POINTER:
        std::snprintf(text, sizeof text, "*0x%" PRIx64 " (through a pointer)", branch.target);
        return text;
    default:
        return "indirect";
    }
}

// The file at `path` whole, or nullopt (errno says why).
std::optional<std::vector<std::uint8_t>> read(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

int main(int argc, char **argv) {
    if (argc > 2) {
        std::fputs("usage: list_calls [ELF]\n", stderr);
        return 1;
    }
    // The test program, two directories up from this file's.
    std::string_view source = __FILE__;
#ifdef _WIN32
    std::size_t slash = source.find_last_of("/\\");
#else
    std::size_t slash = source.rfind('/');
#endif
    std::string path = argc == 2 ? std::string(argv[1])
                                 : std::string(source.substr(0, slash == std::string_view::npos ? 0 : slash + 1)) +
                                       "../../tests/fixtures/program-x86_64.elf";

    auto data = read(path);
    if (!data) {
        std::fprintf(stderr, "%s: %s\n", path.c_str(), std::strerror(errno));
        return 1;
    }
    auto elf = Elf::parse(std::move(*data));
    if (!elf) {
        std::fprintf(stderr, "%s: not a 64-bit little-endian ELF file\n", path.c_str());
        return 1;
    }
    if (elf->machine() != em_x86_64 && elf->machine() != em_aarch64) {
        std::fprintf(stderr, "%s: machine %u is neither x86-64 nor AArch64\n", path.c_str(), elf->machine());
        return 1;
    }
    for (const Section &text : elf->sections()) {
        if (text.name != ".text" || !text.in_file || text.type == sht_nobits) continue;
        std::printf("calls in .text of %s:\n", path.c_str());
        std::size_t calls = 0;
        // Either architecture's decoder: their Decoded share their shape.
        auto list = [&](const auto &decoder) {
            for (const auto &decoded : decoder) {
                if (!decoded.ok()) continue;
                binbun_branch branch = decoded.instruction.branch(decoded.address);
                if (branch.kind != BINBUN_BRANCH_CALL) continue;
                std::string shown = decoded.instruction.text(decoded.address);
                if (auto tab = shown.find('\t'); tab != std::string::npos) shown[tab] = ' ';  // AArch64's
                std::printf("0x%08" PRIx64 "  %-40s  %s\n", decoded.address, shown.c_str(),
                            describe(*elf, branch).c_str());
                calls++;
            }
        };
        if (elf->machine() == em_x86_64) {
            list(binbun::x86::Decoder(binbun::x86::Mode::Bits64, elf->bytes(text), text.size, text.address));
        } else {
            list(binbun::aarch64::Decoder(elf->bytes(text), text.size, text.address));
        }
        std::printf("%zu calls\n", calls);
        return 0;
    }
    std::fprintf(stderr, "%s: no .text section\n", path.c_str());
    return 1;
}
