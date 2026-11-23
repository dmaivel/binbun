// binbun/disasm.hpp: a header-only C++17 wrapper over binbun/disasm.h
// (with binbun/core.hpp's strings, status names and version).
//
// Value types over the C API's storage, a decoder to iterate over a buffer
// of code with range-for, and text as std::string or std::string_view into
// your buffer. Nothing here throws but std::string's allocation; failures
// are statuses or empty std::optionals, as in the C API, whose conventions
// (thread safety, ids, buffer sizes) hold here too.
//
//     for (auto& decoded : binbun::x86::Decoder(binbun::x86::Mode::Bits64, code, size, 0x1000)) {
//         if (decoded.ok()) {
//             std::cout << decoded.instruction.text(decoded.address) << '\n';
//         }
//     }
//
// binbun::Decoder and binbun::Instruction do the same for either
// architecture, chosen by a binbun::Arch.
#ifndef BINBUN_DISASM_HPP
#define BINBUN_DISASM_HPP

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include "core.hpp"
#include "disasm.h"

namespace binbun {

// An instruction's text as tokens, in buffers of the largest size any
// instruction needs (MaxText and MaxTokens of its architecture).
template <std::size_t MaxText, std::size_t MaxTokens>
struct Tokens {
    char buffer[MaxText + 1] = {};
    binbun_token items[MaxTokens] = {};
    std::size_t count = 0;
    std::size_t length = 0;

    std::string_view text() const noexcept { return {buffer, length}; }
    // The text of `token`.
    std::string_view text(const binbun_token &token) const noexcept {
        return text().substr(token.offset, token.length);
    }
    const binbun_token *begin() const noexcept { return items; }
    const binbun_token *end() const noexcept { return items + count; }
};

// Up to N items the library writes: operands, registers.
template <class Item, std::size_t N>
struct List {
    static constexpr std::size_t capacity = N;
    Item items[N] = {};
    std::size_t count = 0;

    const Item *begin() const noexcept { return items; }
    const Item *end() const noexcept { return items + count; }
    std::size_t size() const noexcept { return count; }
    bool empty() const noexcept { return count == 0; }
    const Item &operator[](std::size_t i) const noexcept { return items[i]; }
};

// Up to N operands.
template <class Operand, std::size_t N>
using Operands = List<Operand, N>;

// One step of a sweep: where, what the decode came to, and the instruction
// when the status is BINBUN_STATUS_OK.
template <class Instruction>
struct Decoded {
    std::uint64_t address = 0;
    binbun_status status = BINBUN_STATUS_END;
    Instruction instruction;

    bool ok() const noexcept { return status == BINBUN_STATUS_OK; }
};

namespace detail {

// An input iterator over a C decoder: `Raw` the decoder, `Next` its next
// function.
template <class Raw, class Instruction, binbun_status (*Next)(Raw *, decltype(Instruction().raw()), std::uint64_t *)>
class Sweep {
public:
    class iterator {
    public:
        using iterator_category = std::input_iterator_tag;
        using value_type = Decoded<Instruction>;
        using difference_type = std::ptrdiff_t;
        using pointer = const value_type *;
        using reference = const value_type &;

        iterator() = default;
        explicit iterator(Raw raw) noexcept : raw_(raw), done_(false) { advance(); }

        reference operator*() const noexcept { return current_; }
        pointer operator->() const noexcept { return &current_; }
        iterator &operator++() noexcept {
            advance();
            return *this;
        }
        // Iterators are equal when both are at the end.
        bool operator==(const iterator &other) const noexcept { return done_ && other.done_; }
        bool operator!=(const iterator &other) const noexcept { return !(*this == other); }

    private:
        void advance() noexcept {
            current_.status = Next(&raw_, current_.instruction.raw(), &current_.address);
            done_ = current_.status == BINBUN_STATUS_END || current_.status == BINBUN_STATUS_NULL_POINTER ||
                    current_.status == BINBUN_STATUS_BAD_ARGUMENT || current_.status == BINBUN_STATUS_FAILED;
        }

        Raw raw_{};
        value_type current_{};
        bool done_ = true;
    };

    iterator begin() const noexcept { return iterator(raw_); }
    iterator end() const noexcept { return iterator(); }

    // The C decoder, to read or set its offset.
    Raw &raw() noexcept { return raw_; }

protected:
    Raw raw_{};
};

}  // namespace detail

namespace x86 {

enum class Mode : binbun_x86_mode {
    Real16 = BINBUN_X86_MODE_REAL16,
    Real32 = BINBUN_X86_MODE_REAL32,
    Bits16 = BINBUN_X86_MODE_BITS16,
    Bits32 = BINBUN_X86_MODE_BITS32,
    Bits64 = BINBUN_X86_MODE_BITS64,
};

using Tokens = binbun::Tokens<BINBUN_X86_MAX_TEXT, BINBUN_X86_MAX_TOKENS>;
using Operands = binbun::Operands<binbun_x86_operand, BINBUN_X86_MAX_OPERANDS>;

// A decoded x86 instruction (or none, as default-constructed).
class Instruction {
public:
    Instruction() noexcept : raw_{} {}

    // Decodes the instruction at the start of `bytes`; `*status` (if not
    // null) says why there is none.
    static std::optional<Instruction> decode(Mode mode, const std::uint8_t *bytes, std::size_t size,
                                             binbun_status *status = nullptr) noexcept {
        Instruction instruction;
        binbun_status result =
            binbun_x86_decode_bytes(static_cast<binbun_x86_mode>(mode), bytes, size, &instruction.raw_);
        if (status != nullptr) {
            *status = result;
        }
        if (result != BINBUN_STATUS_OK) {
            return std::nullopt;
        }
        return instruction;
    }

    std::uint8_t length() const noexcept { return binbun_x86_instruction_length(&raw_); }
    binbun_x86_mnemonic mnemonic() const noexcept { return binbun_x86_instruction_mnemonic(&raw_); }
    std::string_view mnemonic_name() const noexcept { return view(binbun_x86_mnemonic_name(mnemonic())); }
    binbun_x86_form form() const noexcept { return binbun_x86_instruction_form(&raw_); }
    std::string_view form_name() const noexcept { return view(binbun_x86_form_name(form())); }
    binbun_x86_category category() const noexcept { return binbun_x86_instruction_category(&raw_); }
    binbun_x86_extension extension() const noexcept { return binbun_x86_instruction_extension(&raw_); }
    binbun_x86_isa_set isa_set() const noexcept { return binbun_x86_instruction_isa_set(&raw_); }
    binbun_x86_encoding encoding() const noexcept { return binbun_x86_instruction_encoding(&raw_); }
    binbun_x86_condition condition() const noexcept { return binbun_x86_instruction_condition(&raw_); }
    std::uint32_t operand_width() const noexcept { return binbun_x86_instruction_operand_width(&raw_); }
    std::uint32_t address_width() const noexcept { return binbun_x86_instruction_address_width(&raw_); }
    std::uint32_t stack_address_width() const noexcept {
        return binbun_x86_instruction_stack_address_width(&raw_);
    }
    binbun_branch branch(std::uint64_t address) const noexcept {
        return binbun_x86_instruction_branch(&raw_, address);
    }
    std::optional<std::uint64_t> computed_address(std::uint64_t address) const noexcept {
        std::uint64_t computed = 0;
        if (!binbun_x86_instruction_computed_address(&raw_, address, &computed)) {
            return std::nullopt;
        }
        return computed;
    }
    binbun_x86_flag_effect flags() const noexcept { return binbun_x86_instruction_flags(&raw_); }

    Operands operands() const noexcept {
        Operands operands;
        operands.count = binbun_x86_instruction_operands(&raw_, operands.items, BINBUN_X86_MAX_OPERANDS);
        return operands;
    }

    // The text at `address`, in `buffer`.
    std::string_view text(std::uint64_t address, char (&buffer)[BINBUN_X86_MAX_TEXT + 1]) const noexcept {
        std::size_t length = binbun_x86_instruction_text(&raw_, address, BINBUN_TEXT_DEFAULT, buffer, sizeof buffer);
        return {buffer, length < sizeof buffer ? length : 0};
    }
    // The text at `address`.
    std::string text(std::uint64_t address) const {
        char buffer[BINBUN_X86_MAX_TEXT + 1];
        return std::string(text(address, buffer));
    }
    Tokens tokens(std::uint64_t address) const noexcept {
        Tokens tokens;
        binbun_text_size size = binbun_x86_instruction_tokens(&raw_, address, BINBUN_TEXT_DEFAULT, tokens.buffer,
                                                              sizeof tokens.buffer, tokens.items,
                                                              BINBUN_X86_MAX_TOKENS);
        tokens.count = size.tokens;
        tokens.length = size.length;
        return tokens;
    }

    const binbun_x86_instruction *raw() const noexcept { return &raw_; }
    binbun_x86_instruction *raw() noexcept { return &raw_; }

private:
    binbun_x86_instruction raw_;
};

// A linear sweep over a buffer of code: range-for gives a Decoded per
// instruction (or per byte that starts none). The buffer must outlive it.
class Decoder : public detail::Sweep<binbun_x86_decoder, Instruction, binbun_x86_decoder_next> {
public:
    Decoder(Mode mode, const std::uint8_t *bytes, std::size_t size, std::uint64_t address) noexcept {
        status_ = binbun_x86_decoder_init(&raw_, static_cast<binbun_x86_mode>(mode), bytes, size, address);
    }
    // Over a contiguous container of bytes (std::vector<uint8_t>,
    // std::array, std::string_view of bytes...).
    template <class Bytes>
    Decoder(Mode mode, const Bytes &bytes, std::uint64_t address) noexcept
        : Decoder(mode, reinterpret_cast<const std::uint8_t *>(std::data(bytes)),
                  std::size(bytes) * sizeof *std::data(bytes), address) {}

    // BINBUN_STATUS_OK, or why the decoder could not start (it then yields
    // nothing).
    binbun_status status() const noexcept { return status_; }

private:
    binbun_status status_;
};

inline std::string_view register_name(binbun_x86_register reg) noexcept { return view(binbun_x86_register_name(reg)); }

inline std::optional<binbun_x86_register_info> register_info(binbun_x86_register reg) noexcept {
    binbun_x86_register_info info{};
    if (!binbun_x86_register_describe(reg, &info)) {
        return std::nullopt;
    }
    return info;
}

}  // namespace x86

namespace aarch64 {

using Tokens = binbun::Tokens<BINBUN_AARCH64_MAX_TEXT, BINBUN_AARCH64_MAX_TOKENS>;
using Operands = binbun::Operands<binbun_aarch64_operand, BINBUN_AARCH64_MAX_OPERANDS>;
// Registers an instruction uses without naming them: 8, more than any
// instruction has.
using Registers = binbun::List<binbun_aarch64_register, 8>;

// A decoded A64 instruction (or none, as default-constructed).
class Instruction {
public:
    Instruction() noexcept : raw_{} {}

    static std::optional<Instruction> decode(std::uint32_t word, binbun_status *status = nullptr) noexcept {
        Instruction instruction;
        binbun_status result = binbun_aarch64_decode_word(word, &instruction.raw_);
        if (status != nullptr) {
            *status = result;
        }
        if (result != BINBUN_STATUS_OK) {
            return std::nullopt;
        }
        return instruction;
    }

    static std::optional<Instruction> decode(const std::uint8_t *bytes, std::size_t size,
                                             binbun_status *status = nullptr) noexcept {
        Instruction instruction;
        binbun_status result = binbun_aarch64_decode_bytes(bytes, size, &instruction.raw_);
        if (status != nullptr) {
            *status = result;
        }
        if (result != BINBUN_STATUS_OK) {
            return std::nullopt;
        }
        return instruction;
    }

    std::uint32_t word() const noexcept { return binbun_aarch64_instruction_word(&raw_); }
    std::uint8_t length() const noexcept { return binbun_aarch64_instruction_length(&raw_); }
    binbun_aarch64_encoding encoding() const noexcept { return binbun_aarch64_instruction_encoding(&raw_); }
    std::string_view encoding_name() const noexcept { return view(binbun_aarch64_encoding_name(encoding())); }
    std::string_view mnemonic() const noexcept { return view(binbun_aarch64_instruction_mnemonic(&raw_)); }
    binbun_branch branch(std::uint64_t address) const noexcept {
        return binbun_aarch64_instruction_branch(&raw_, address);
    }
    std::optional<std::uint64_t> computed_address(std::uint64_t address) const noexcept {
        std::uint64_t computed = 0;
        if (!binbun_aarch64_instruction_computed_address(&raw_, address, &computed)) {
            return std::nullopt;
        }
        return computed;
    }
    std::optional<binbun_aarch64_condition> condition() const noexcept {
        binbun_aarch64_condition condition{};
        if (!binbun_aarch64_instruction_condition(&raw_, &condition)) {
            return std::nullopt;
        }
        return condition;
    }
    binbun_aarch64_flag_effect flags() const noexcept { return binbun_aarch64_instruction_flags(&raw_); }
    std::optional<binbun_aarch64_memory_access> memory() const noexcept {
        binbun_aarch64_memory_access access{};
        if (!binbun_aarch64_instruction_memory(&raw_, &access)) {
            return std::nullopt;
        }
        return access;
    }

    Operands operands() const noexcept {
        Operands operands;
        operands.count = binbun_aarch64_instruction_operands(&raw_, operands.items, BINBUN_AARCH64_MAX_OPERANDS);
        return operands;
    }

    // The registers it reads, or writes, without naming them (x30 of `bl`
    // and `ret`, x16 and x17 of `pacia1716`, FFR).
    Registers implicit_reads() const noexcept {
        Registers registers;
        std::size_t count = binbun_aarch64_instruction_implicit_reads(&raw_, registers.items, Registers::capacity);
        registers.count = count < Registers::capacity ? count : Registers::capacity;
        return registers;
    }
    Registers implicit_writes() const noexcept {
        Registers registers;
        std::size_t count = binbun_aarch64_instruction_implicit_writes(&raw_, registers.items, Registers::capacity);
        registers.count = count < Registers::capacity ? count : Registers::capacity;
        return registers;
    }

    std::string_view text(std::uint64_t address, char (&buffer)[BINBUN_AARCH64_MAX_TEXT + 1],
                          std::uint32_t options = BINBUN_TEXT_DEFAULT) const noexcept {
        std::size_t length = binbun_aarch64_instruction_text(&raw_, address, options, buffer, sizeof buffer);
        return {buffer, length < sizeof buffer ? length : 0};
    }
    std::string text(std::uint64_t address, std::uint32_t options = BINBUN_TEXT_DEFAULT) const {
        char buffer[BINBUN_AARCH64_MAX_TEXT + 1];
        return std::string(text(address, buffer, options));
    }
    Tokens tokens(std::uint64_t address, std::uint32_t options = BINBUN_TEXT_DEFAULT) const noexcept {
        Tokens tokens;
        binbun_text_size size = binbun_aarch64_instruction_tokens(&raw_, address, options, tokens.buffer,
                                                                  sizeof tokens.buffer, tokens.items,
                                                                  BINBUN_AARCH64_MAX_TOKENS);
        tokens.count = size.tokens;
        tokens.length = size.length;
        return tokens;
    }

    const binbun_aarch64_instruction *raw() const noexcept { return &raw_; }
    binbun_aarch64_instruction *raw() noexcept { return &raw_; }

private:
    binbun_aarch64_instruction raw_;
};

// A linear sweep over a buffer of code, 4 bytes at a time.
class Decoder : public detail::Sweep<binbun_aarch64_decoder, Instruction, binbun_aarch64_decoder_next> {
public:
    Decoder(const std::uint8_t *bytes, std::size_t size, std::uint64_t address) noexcept {
        status_ = binbun_aarch64_decoder_init(&raw_, bytes, size, address);
    }
    template <class Bytes>
    Decoder(const Bytes &bytes, std::uint64_t address) noexcept
        : Decoder(reinterpret_cast<const std::uint8_t *>(std::data(bytes)), std::size(bytes) * sizeof *std::data(bytes),
                  address) {}

    binbun_status status() const noexcept { return status_; }

private:
    binbun_status status_;
};

}  // namespace aarch64

// The architecture to decode for, with x86's mode: Arch::x86(x86::Mode::Bits64)
// or Arch::aarch64().
struct Arch {
    binbun_arch arch;
    // For x86, a binbun_x86_mode; for AArch64, 0.
    binbun_x86_mode mode;

    static constexpr Arch x86(::binbun::x86::Mode mode) noexcept {
        return Arch{BINBUN_ARCH_X86, static_cast<binbun_x86_mode>(mode)};
    }
    static constexpr Arch aarch64() noexcept { return Arch{BINBUN_ARCH_AARCH64, 0}; }

    constexpr bool operator==(const Arch &other) const noexcept {
        return arch == other.arch && mode == other.mode;
    }
    constexpr bool operator!=(const Arch &other) const noexcept { return !(*this == other); }
};

// The registers an instruction reads, or writes.
using Registers = List<binbun_register, BINBUN_MAX_REGISTERS>;

// A decoded instruction of either architecture (or none, as
// default-constructed), bound to its address, with its bytes.
class Instruction {
public:
    Instruction() noexcept : raw_{} {}

    // Decodes the instruction at the start of `bytes`, which is at
    // `address`; `*status` (if not null) says why there is none.
    static std::optional<Instruction> decode(Arch arch, const std::uint8_t *bytes, std::size_t size,
                                             std::uint64_t address, binbun_status *status = nullptr) noexcept {
        Instruction instruction;
        binbun_status result = binbun_decode(arch.arch, arch.mode, bytes, size, address, &instruction.raw_);
        if (status != nullptr) {
            *status = result;
        }
        if (result != BINBUN_STATUS_OK) {
            return std::nullopt;
        }
        return instruction;
    }

    Arch arch() const noexcept { return Arch{binbun_instruction_arch(&raw_), binbun_instruction_mode(&raw_)}; }
    std::uint64_t address() const noexcept { return binbun_instruction_address(&raw_); }
    std::uint8_t length() const noexcept { return binbun_instruction_length(&raw_); }
    // The bytes it was decoded from, length() of them, in this object.
    const std::uint8_t *bytes() const noexcept { return binbun_instruction_bytes(&raw_); }
    std::string_view mnemonic() const noexcept { return view(binbun_instruction_mnemonic(&raw_)); }
    binbun_branch branch() const noexcept { return binbun_instruction_branch(&raw_); }

    // The text, in `buffer`; `options` as the native text's (x86 has none).
    std::string_view text(char (&buffer)[BINBUN_MAX_TEXT + 1],
                          std::uint32_t options = BINBUN_TEXT_DEFAULT) const noexcept {
        std::size_t length = binbun_instruction_text(&raw_, options, buffer, sizeof buffer);
        return {buffer, length < sizeof buffer ? length : 0};
    }
    std::string text(std::uint32_t options = BINBUN_TEXT_DEFAULT) const {
        char buffer[BINBUN_MAX_TEXT + 1];
        return std::string(text(buffer, options));
    }

    Registers registers_read() const noexcept {
        Registers registers;
        std::size_t count = binbun_instruction_registers_read(&raw_, registers.items, Registers::capacity);
        registers.count = count < Registers::capacity ? count : Registers::capacity;
        return registers;
    }
    Registers registers_written() const noexcept {
        Registers registers;
        std::size_t count = binbun_instruction_registers_written(&raw_, registers.items, Registers::capacity);
        registers.count = count < Registers::capacity ? count : Registers::capacity;
        return registers;
    }

    // The native instruction, a copy, for what one architecture alone has
    // (operands, flags, tokens); empty for the other architecture.
    std::optional<x86::Instruction> as_x86() const noexcept {
        const binbun_x86_instruction *native = binbun_instruction_as_x86(&raw_);
        if (native == nullptr) {
            return std::nullopt;
        }
        x86::Instruction instruction;
        *instruction.raw() = *native;
        return instruction;
    }
    std::optional<aarch64::Instruction> as_aarch64() const noexcept {
        const binbun_aarch64_instruction *native = binbun_instruction_as_aarch64(&raw_);
        if (native == nullptr) {
            return std::nullopt;
        }
        aarch64::Instruction instruction;
        *instruction.raw() = *native;
        return instruction;
    }

    const binbun_instruction *raw() const noexcept { return &raw_; }
    binbun_instruction *raw() noexcept { return &raw_; }

private:
    binbun_instruction raw_;
};

// A linear sweep over a buffer of code for an architecture: range-for gives
// a Decoded per instruction (or per step over bytes that are none: one byte
// on x86, four on AArch64). The buffer must outlive it.
class Decoder : public detail::Sweep<binbun_decoder, Instruction, binbun_decoder_next> {
public:
    Decoder(Arch arch, const std::uint8_t *bytes, std::size_t size, std::uint64_t address) noexcept {
        status_ = binbun_decoder_init(&raw_, arch.arch, arch.mode, bytes, size, address);
    }
    template <class Bytes>
    Decoder(Arch arch, const Bytes &bytes, std::uint64_t address) noexcept
        : Decoder(arch, reinterpret_cast<const std::uint8_t *>(std::data(bytes)),
                  std::size(bytes) * sizeof *std::data(bytes), address) {}

    // BINBUN_STATUS_OK, or why the decoder could not start (it then yields
    // nothing).
    binbun_status status() const noexcept { return status_; }

private:
    binbun_status status_;
};

// The register's name as its architecture writes it (`rax`, `x0`,
// `TPIDR_EL0`); empty if it names none.
inline std::string register_name(const binbun_register &reg) {
    char buffer[BINBUN_MAX_REGISTER_NAME + 1];
    std::size_t length = binbun_register_name(&reg, buffer, sizeof buffer);
    return std::string(buffer, length < sizeof buffer ? length : 0);
}

}  // namespace binbun

#endif
