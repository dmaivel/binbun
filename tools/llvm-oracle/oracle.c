/* LLVM's AArch64 disassembler as a test oracle for binbun's A64 decoder.
 *
 * The disassembler is LLVM's C API with every feature enabled:
 * LLVMCreateDisasmCPUFeatures("aarch64-linux-gnu", "generic", "+all"), with
 * hexadecimal immediates. The plain LLVMCreateDisasm would reject SVE, SME,
 * PAC and LSE and print `paciasp` as `hint #25`.
 *
 * Line mode (default): reads lines `WORD [ADDRESS]` from stdin, WORD being
 * the 32-bit instruction word in hex (as a number, not as bytes: `d503201f`
 * is `nop`) and ADDRESS the optional hex address of the instruction (default
 * 0). Prints one line per input line: `invalid` if LLVM does not decode the
 * word, otherwise LLVM's text without its leading tab (the tab between the
 * mnemonic and the operands is kept). Soft failures (LLVM's name for
 * should-be bits not as specified) count as decoded, as they do in
 * LLVMDisasmInstruction.
 *
 * Bitmap mode: `llvm-oracle --bitmap START COUNT` (START in hex, COUNT in
 * decimal, a multiple of 8) writes COUNT / 8 bytes to stdout: bit i of byte
 * i / 8 (least significant first) is set if the word START + i decodes. For
 * sweeps of the whole word space, where text is not needed.
 *
 * Build with scripts/llvm-oracle.sh.
 */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>

static LLVMDisasmContextRef create(void) {
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAArch64TargetMC();
    LLVMInitializeAArch64Disassembler();
    LLVMDisasmContextRef context =
        LLVMCreateDisasmCPUFeatures("aarch64-linux-gnu", "generic", "+all", NULL, 0, NULL, NULL);
    if (context && !LLVMSetDisasmOptions(context, LLVMDisassembler_Option_PrintImmHex)) {
        LLVMDisasmDispose(context);
        context = NULL;
    }
    return context;
}

/* Decodes WORD at ADDRESS into TEXT; returns whether LLVM decoded it. */
static int disassemble(LLVMDisasmContextRef context, uint32_t word, uint64_t address, char* text,
                       size_t size) {
    uint8_t bytes[4] = {(uint8_t)word, (uint8_t)(word >> 8), (uint8_t)(word >> 16),
                        (uint8_t)(word >> 24)};
    return LLVMDisasmInstruction(context, bytes, sizeof bytes, address, text, size) == sizeof bytes;
}

static int lines(LLVMDisasmContextRef context) {
    char* line = NULL;
    size_t capacity = 0;
    char text[512];
    while (getline(&line, &capacity, stdin) != -1) {
        char* end;
        unsigned long long word = strtoull(line, &end, 16);
        if (end == line || word > UINT32_MAX) {
            fprintf(stderr, "llvm-oracle: bad input line: %s", line);
            free(line);
            return 1;
        }
        unsigned long long address = strtoull(end, NULL, 16);
        if (disassemble(context, (uint32_t)word, address, text, sizeof text)) {
            const char* start = text;
            while (*start == '\t' || *start == ' ') start++;
            printf("%s\n", start);
        } else {
            printf("invalid\n");
        }
    }
    free(line);
    return fflush(stdout) != 0;
}

static int bitmap(LLVMDisasmContextRef context, const char* start_text, const char* count_text) {
    unsigned long long start = strtoull(start_text, NULL, 16);
    unsigned long long count = strtoull(count_text, NULL, 10);
    if (count % 8 != 0 || start + count > (1ULL << 32)) {
        fprintf(stderr, "llvm-oracle: bad range %s %s\n", start_text, count_text);
        return 1;
    }
    char text[512];
    unsigned char chunk[4096];
    size_t filled = 0;
    for (unsigned long long i = 0; i < count; i += 8) {
        unsigned char byte = 0;
        for (unsigned bit = 0; bit < 8; bit++) {
            if (disassemble(context, (uint32_t)(start + i + bit), 0, text, sizeof text)) {
                byte |= (unsigned char)(1u << bit);
            }
        }
        chunk[filled++] = byte;
        if (filled == sizeof chunk) {
            if (fwrite(chunk, 1, filled, stdout) != filled) return 1;
            filled = 0;
        }
    }
    if (fwrite(chunk, 1, filled, stdout) != filled) return 1;
    return fflush(stdout) != 0;
}

int main(int argc, char** argv) {
    LLVMDisasmContextRef context = create();
    if (!context) {
        fprintf(stderr, "llvm-oracle: cannot create the AArch64 disassembler\n");
        return 1;
    }
    int status;
    if (argc == 4 && !strcmp(argv[1], "--bitmap")) {
        status = bitmap(context, argv[2], argv[3]);
    } else if (argc == 1) {
        status = lines(context);
    } else {
        fprintf(stderr, "usage: llvm-oracle [--bitmap START COUNT] < words\n");
        status = 2;
    }
    LLVMDisasmDispose(context);
    return status;
}
