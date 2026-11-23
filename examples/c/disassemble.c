/* Disassemble a buffer of machine code given in hexadecimal on the command
 * line: each instruction's address, bytes and text, x86 (64, 32 or 16-bit)
 * or AArch64. Bytes that are no instruction are shown with the reason and
 * stepped over (one byte on x86, four on AArch64), as a linear sweep does.
 *
 * With no bytes given it disassembles a small function of its own (a
 * prologue, a call, an epilogue) for the architecture.
 *
 *   ./disassemble
 *   ./disassemble 55 4889e5 e800000000 c3
 *   ./disassemble --arch aarch64 --address 0x1000 fd7bbfa9 fd030091 c0035fd6
 *
 * Build as examples/c/quick_start.c says.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <binbun/disasm.h>

#define MAX_CODE 4096

/* What is disassembled when no bytes are given: push the frame pointer, set
 * it, call the next instruction, pop it, return. */
static const struct {
    const char *arch, *hex;
} examples[] = {
    {"x86-64", "554889e5e8000000005dc3"},
    {"x86-32", "5589e5e8000000005dc3"},
    {"x86-16", "5589e5e800005dc3"},
    {"aarch64", "fd7bbfa9fd03009101000094fd7bc1a8c0035fd6"},
};

static int usage(void) {
    fputs("usage: disassemble [--arch x86-64|x86-32|x86-16|aarch64] [--address ADDRESS] [HEX...]\n", stderr);
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

/* One line: the address, `length` bytes from `bytes` padded to `width`
 * bytes (longer instructions push the text right), the text. */
static void print_line(uint64_t address, const uint8_t *bytes, size_t length, size_t width, const char *text) {
    printf("%016" PRIx64 "  ", address);
    for (size_t i = 0; i < width || i < length; i++) {
        if (i < length) {
            printf("%02x ", bytes[i]);
        } else {
            fputs("   ", stdout);
        }
    }
    printf("%s\n", text);
}

static void disassemble_x86(binbun_x86_mode mode, const uint8_t *code, size_t size, uint64_t base) {
    binbun_x86_decoder decoder;
    binbun_x86_decoder_init(&decoder, mode, code, size, base);
    binbun_x86_instruction instruction;
    uint64_t address;
    binbun_status status;
    while ((status = binbun_x86_decoder_next(&decoder, &instruction, &address)) != BINBUN_STATUS_END) {
        const uint8_t *bytes = code + (address - base);
        char text[BINBUN_X86_MAX_TEXT + 1];
        if (status == BINBUN_STATUS_OK) {
            binbun_x86_instruction_text(&instruction, address, BINBUN_TEXT_DEFAULT, text, sizeof text);
            print_line(address, bytes, binbun_x86_instruction_length(&instruction), 8, text);
        } else {
            binbun_str why = binbun_status_name(status);
            snprintf(text, sizeof text, "(bad: %.*s)", (int)why.length, why.data);
            print_line(address, bytes, 1, 8, text);
        }
    }
}

static void disassemble_aarch64(const uint8_t *code, size_t size, uint64_t base) {
    binbun_aarch64_decoder decoder;
    binbun_aarch64_decoder_init(&decoder, code, size, base);
    binbun_aarch64_instruction instruction;
    uint64_t address;
    binbun_status status;
    while ((status = binbun_aarch64_decoder_next(&decoder, &instruction, &address)) != BINBUN_STATUS_END) {
        const uint8_t *bytes = code + (address - base);
        size_t length = size - (size_t)(address - base) < 4 ? size - (size_t)(address - base) : 4;
        char text[BINBUN_AARCH64_MAX_TEXT + 1];
        if (status == BINBUN_STATUS_OK) {
            binbun_aarch64_instruction_text(&instruction, address, BINBUN_TEXT_DEFAULT, text, sizeof text);
            char *tab = strchr(text, '\t'); /* LLVM puts a tab after the mnemonic */
            if (tab != NULL) *tab = ' ';
        } else {
            binbun_str why = binbun_status_name(status);
            snprintf(text, sizeof text, "(bad: %.*s)", (int)why.length, why.data);
        }
        print_line(address, bytes, length, 4, text);
    }
}

int main(int argc, char **argv) {
    const char *arch = "x86-64";
    uint64_t address = 0x1000;
    static uint8_t code[MAX_CODE];
    size_t size = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--arch") == 0 && i + 1 < argc) {
            arch = argv[++i];
        } else if (strcmp(argv[i], "--address") == 0 && i + 1 < argc) {
            address = strtoull(argv[++i], NULL, 0);
        } else if (!parse_hex(argv[i], code, &size)) {
            fprintf(stderr, "disassemble: %s: not hexadecimal bytes\n", argv[i]);
            return usage();
        }
    }
    for (size_t i = 0; size == 0 && i < sizeof examples / sizeof examples[0]; i++) {
        if (strcmp(arch, examples[i].arch) == 0) parse_hex(examples[i].hex, code, &size);
    }
    if (size == 0) return usage();

    if (strcmp(arch, "x86-64") == 0) {
        disassemble_x86(BINBUN_X86_MODE_BITS64, code, size, address);
    } else if (strcmp(arch, "x86-32") == 0) {
        disassemble_x86(BINBUN_X86_MODE_BITS32, code, size, address);
    } else if (strcmp(arch, "x86-16") == 0) {
        disassemble_x86(BINBUN_X86_MODE_BITS16, code, size, address);
    } else if (strcmp(arch, "aarch64") == 0) {
        disassemble_aarch64(code, size, address);
    } else {
        fprintf(stderr, "disassemble: unknown architecture %s\n", arch);
        return usage();
    }
    return 0;
}
