/* Print instructions coloured by what each piece of text is (mnemonic,
 * register, number, address...), as a listing view colours them, from the
 * tokens the C API writes alongside the text. x86-64 or AArch64.
 *
 * With no bytes given it colours a load, a call and a return.
 *
 *   ./color_tokens
 *   ./color_tokens 488b4310 e800000000 c3
 *   ./color_tokens --aarch64 200440f9 00000094
 *
 * Build as examples/c/quick_start.c says.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <binbun/disasm.h>

/* Appends the bytes `hex` writes to `code`, which holds `size` of
 * `capacity`; returns the new size. */
static size_t append_hex(const char *hex, uint8_t *code, size_t size, size_t capacity) {
    for (const char *p = hex; p[0] && p[1] && size < capacity; p += 2) {
        char pair[3] = {p[0], p[1], 0};
        code[size++] = (uint8_t)strtoul(pair, NULL, 16);
    }
    return size;
}

/* An ANSI colour per binbun_token_kind; NULL leaves the token plain. */
static const char *colour(uint8_t kind) {
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
    default: return NULL;
    }
}

/* Prints `count` tokens of `text`, coloured. */
static void print_tokens(uint64_t address, const char *text, const binbun_token *tokens, size_t count) {
    printf("0x%08" PRIx64 "  ", address);
    for (size_t i = 0; i < count; i++) {
        const char *sgr = colour(tokens[i].kind);
        const char *piece = text + tokens[i].offset;
        int length = (int)tokens[i].length;
        if (tokens[i].kind == BINBUN_TOKEN_WHITESPACE) {
            fputc(' ', stdout); /* AArch64 puts a tab after the mnemonic */
        } else if (sgr != NULL) {
            printf("\x1b[%sm%.*s\x1b[0m", sgr, length, piece);
        } else {
            printf("%.*s", length, piece);
        }
    }
    printf("\n");
}

int main(int argc, char **argv) {
    int aarch64 = argc > 1 && strcmp(argv[1], "--aarch64") == 0;
    uint8_t code[256];
    size_t size = 0;
    for (int i = 1 + aarch64; i < argc; i++) size = append_hex(argv[i], code, size, sizeof code);
    if (argc == 1 + aarch64) {
        /* No bytes given: a load, a call, a return. */
        size = append_hex(aarch64 ? "200440f900000094c0035fd6" : "488b4310e800000000c3", code, 0, sizeof code);
    }
    if (size == 0) {
        fputs("usage: color_tokens [--aarch64] [HEX...]\n", stderr);
        return 1;
    }

    char text[BINBUN_X86_MAX_TEXT + 1];
    binbun_token tokens[BINBUN_X86_MAX_TOKENS];
    uint64_t address;
    binbun_status status;
    if (aarch64) {
        binbun_aarch64_decoder decoder;
        binbun_aarch64_instruction inst;
        binbun_aarch64_decoder_init(&decoder, code, size, 0x1000);
        while ((status = binbun_aarch64_decoder_next(&decoder, &inst, &address)) != BINBUN_STATUS_END) {
            if (status != BINBUN_STATUS_OK) {
                printf("0x%08" PRIx64 "  (bad)\n", address);
                continue;
            }
            binbun_text_size written = binbun_aarch64_instruction_tokens(
                &inst, address, BINBUN_TEXT_DEFAULT, text, sizeof text, tokens, BINBUN_X86_MAX_TOKENS);
            print_tokens(address, text, tokens, written.tokens);
        }
    } else {
        binbun_x86_decoder decoder;
        binbun_x86_instruction inst;
        binbun_x86_decoder_init(&decoder, BINBUN_X86_MODE_BITS64, code, size, 0x1000);
        while ((status = binbun_x86_decoder_next(&decoder, &inst, &address)) != BINBUN_STATUS_END) {
            if (status != BINBUN_STATUS_OK) {
                printf("0x%08" PRIx64 "  (bad)\n", address);
                continue;
            }
            binbun_text_size written = binbun_x86_instruction_tokens(&inst, address, BINBUN_TEXT_DEFAULT, text,
                                                                     sizeof text, tokens, BINBUN_X86_MAX_TOKENS);
            print_tokens(address, text, tokens, written.tokens);
        }
    }
    return 0;
}
