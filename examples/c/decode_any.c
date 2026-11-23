/* Disassemble a buffer of machine code given in hexadecimal on the command
 * line for x86 (64, 32 or 16-bit) or AArch64 through one decoder
 * (binbun_decoder): each instruction's address, bytes, text, mnemonic, and
 * the registers it reads and writes. Bytes that are no instruction are shown
 * with the reason and stepped over (one byte on x86, four on AArch64). What
 * one architecture alone has (operands, flags) is the native instruction's:
 * binbun_instruction_as_x86 or binbun_instruction_as_aarch64.
 *
 * With no bytes given it disassembles a small function of its own (a
 * prologue, a call, an epilogue) for the architecture. It prints what
 * examples/rust/decode_any.rs prints.
 *
 *   ./decode_any
 *   ./decode_any --arch aarch64
 *   ./decode_any --arch x86-32 --address 0x400000 55 89e5 c3
 *
 * Build as examples/c/quick_start.c says.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <binbun/disasm.h>

#define MAX_CODE 4096

/* The architectures by name, and what is disassembled when no bytes are
 * given: push the frame pointer, set it, call the next instruction, pop it,
 * return. */
static const struct {
    const char *name, *hex;
    binbun_arch arch;
    binbun_x86_mode mode;
} archs[] = {
    {"x86-64", "554889e5e8000000005dc3", BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64},
    {"x86-32", "5589e5e8000000005dc3", BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS32},
    {"x86-16", "5589e5e800005dc3", BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS16},
    {"aarch64", "fd7bbfa9fd03009101000094fd7bc1a8c0035fd6", BINBUN_ARCH_AARCH64, 0},
};

static int usage(void) {
    fputs("usage: decode_any [--arch x86-64|x86-32|x86-16|aarch64] [--address ADDRESS] [HEX...]\n", stderr);
    return 1;
}

/* Appends the bytes `hex` writes to `code`; false if it is not hexadecimal
 * pairs or does not fit. */
static int parse_hex(const char *hex, uint8_t *code, size_t *size) {
    size_t length = strlen(hex);
    if (length % 2 != 0) return 0;
    for (size_t i = 0; i < length; i += 2) {
        char pair[3] = {hex[i], hex[i + 1], 0};
        char *end;
        unsigned long byte = strtoul(pair, &end, 16);
        if (*end != 0 || *size == MAX_CODE) return 0;
        code[(*size)++] = (uint8_t)byte;
    }
    return 1;
}

/* The address and `length` bytes from `bytes`, padded to `width`
 * characters (longer instructions push the rest right). */
static void print_start(uint64_t address, const uint8_t *bytes, size_t length, size_t width) {
    printf("%016" PRIx64 "  ", address);
    size_t written = 0;
    for (size_t i = 0; i < length; i++) {
        written += (size_t)printf(i == 0 ? "%02x" : " %02x", bytes[i]);
    }
    for (; written < width; written++) putchar(' ');
    putchar(' ');
}

/* The registers by name, `-` for none. */
static void print_registers(const binbun_register *registers, size_t count) {
    if (count == 0) {
        putchar('-');
        return;
    }
    for (size_t i = 0; i < count; i++) {
        char name[BINBUN_MAX_REGISTER_NAME + 1];
        binbun_register_name(&registers[i], name, sizeof name);
        printf(i == 0 ? "%s" : " %s", name);
    }
}

int main(int argc, char **argv) {
    const char *name = "x86-64";
    uint64_t address = 0x1000;
    static uint8_t code[MAX_CODE];
    size_t size = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--arch") == 0 && i + 1 < argc) {
            name = argv[++i];
        } else if (strcmp(argv[i], "--address") == 0 && i + 1 < argc) {
            address = strtoull(argv[++i], NULL, 0);
        } else if (!parse_hex(argv[i], code, &size)) {
            fprintf(stderr, "decode_any: %s: not hexadecimal bytes\n", argv[i]);
            return usage();
        }
    }
    size_t which = 0;
    while (which < sizeof archs / sizeof archs[0] && strcmp(name, archs[which].name) != 0) which++;
    if (which == sizeof archs / sizeof archs[0]) {
        fprintf(stderr, "decode_any: unknown architecture %s\n", name);
        return usage();
    }
    binbun_arch arch = archs[which].arch;
    if (size == 0) parse_hex(archs[which].hex, code, &size);

    binbun_decoder decoder;
    if (binbun_decoder_init(&decoder, arch, archs[which].mode, code, size, address) != BINBUN_STATUS_OK) {
        return usage();
    }
    /* Eight bytes of x86 or one AArch64 word before the text. */
    size_t width = (arch == BINBUN_ARCH_AARCH64 ? 4 : 8) * 3;
    binbun_instruction instruction;
    uint64_t at;
    binbun_status status;
    while ((status = binbun_decoder_next(&decoder, &instruction, &at)) != BINBUN_STATUS_END) {
        if (status != BINBUN_STATUS_OK) {
            /* What the decoder stepped over: a byte on x86, four on AArch64. */
            size_t offset = (size_t)(at - address), left = size - offset;
            size_t step = arch == BINBUN_ARCH_AARCH64 ? 4 : 1;
            print_start(at, code + offset, left < step ? left : step, width);
            binbun_str why = binbun_status_name(status);
            printf("(%.*s)\n", (int)why.length, why.data);
            continue;
        }
        char text[BINBUN_MAX_TEXT + 1];
        binbun_instruction_text(&instruction, BINBUN_TEXT_DEFAULT, text, sizeof text);
        for (char *tab = strchr(text, '\t'); tab != NULL; tab = strchr(tab, '\t')) *tab = ' ';
        binbun_str mnemonic = binbun_instruction_mnemonic(&instruction);
        print_start(at, binbun_instruction_bytes(&instruction), binbun_instruction_length(&instruction), width);
        printf("%-28s %-6.*s reads ", text, (int)mnemonic.length, mnemonic.data);
        binbun_register registers[BINBUN_MAX_REGISTERS];
        print_registers(registers, binbun_instruction_registers_read(&instruction, registers, BINBUN_MAX_REGISTERS));
        fputs("; writes ", stdout);
        print_registers(registers,
                        binbun_instruction_registers_written(&instruction, registers, BINBUN_MAX_REGISTERS));
        putchar('\n');
    }
    return 0;
}
