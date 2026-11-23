/* List the calls in a 64-bit ELF executable's .text (x86-64 or AArch64):
 * each call's address, its text, and where it goes, named by the ELF's
 * symbols where one starts there. The ELF is read here, by hand: the C API
 * only decodes.
 *
 * With no file given it reads the checked-in test program
 * (tests/fixtures/program-x86_64.elf), found from this source file's path
 * as it was compiled; give a path to run on your own binary.
 *
 *   ./list_calls
 *   ./list_calls /usr/bin/true
 *
 * Build as examples/c/quick_start.c says.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <binbun/disasm.h>

#define EM_X86_64 62
#define EM_AARCH64 183
#define SHT_SYMTAB 2
#define SHT_DYNSYM 11
#define STT_FUNC 2

/* What ends a directory in a path: on Windows `\` too. */
#ifdef _WIN32
#define SEPARATORS "/\\"
#else
#define SEPARATORS "/"
#endif

/* Little-endian fields of the file, which `elf_valid` bounds. */
static uint64_t field(const uint8_t *at, int size) {
    uint64_t value = 0;
    for (int i = size - 1; i >= 0; i--) value = value << 8 | at[i];
    return value;
}

typedef struct elf {
    const uint8_t *data;
    size_t size;
    uint16_t machine;
    uint64_t shoff;
    uint16_t shnum, shstrndx;
} elf;

typedef struct section {
    const char *name;
    uint32_t type, link;
    uint64_t address, offset, size;
} section;

/* Section `index`; false if it is outside the file. */
static int elf_section(const elf *e, size_t index, section *out) {
    uint64_t at = e->shoff + index * 64;
    if (index >= e->shnum || at + 64 > e->size) return 0;
    const uint8_t *h = e->data + at;
    out->type = (uint32_t)field(h + 4, 4);
    out->address = field(h + 16, 8);
    out->offset = field(h + 24, 8);
    out->size = field(h + 32, 8);
    out->link = (uint32_t)field(h + 40, 4);
    out->name = "";
    section names;
    if (index != e->shstrndx && elf_section(e, e->shstrndx, &names) && names.offset + names.size <= e->size) {
        uint64_t name = field(h, 4);
        if (name < names.size && memchr(e->data + names.offset + name, 0, names.size - name) != NULL) {
            out->name = (const char *)e->data + names.offset + name;
        }
    }
    return out->type == 8 /* SHT_NOBITS */ || out->offset + out->size <= e->size;
}

/* The name of a function symbol at `address` in the symbol tables, or NULL. */
static const char *symbol_at(const elf *e, uint64_t address) {
    for (size_t i = 0; i < e->shnum; i++) {
        section table, strings;
        if (!elf_section(e, i, &table) || (table.type != SHT_SYMTAB && table.type != SHT_DYNSYM)) continue;
        if (!elf_section(e, table.link, &strings)) continue;
        for (uint64_t at = table.offset; at + 24 <= table.offset + table.size; at += 24) {
            const uint8_t *symbol = e->data + at;
            uint64_t name = field(symbol, 4);
            if ((symbol[4] & 0xf) == STT_FUNC && field(symbol + 8, 8) == address && name != 0 &&
                name < strings.size && memchr(e->data + strings.offset + name, 0, strings.size - name) != NULL) {
                return (const char *)e->data + strings.offset + name;
            }
        }
    }
    return NULL;
}

/* Where `branch` goes, in `out`. */
static void describe_target(const elf *e, binbun_branch branch, char *out, size_t size) {
    const char *name = NULL;
    switch (branch.target_kind) {
    case BINBUN_TARGET_ADDRESS:
        name = symbol_at(e, branch.target);
        if (name != NULL) {
            snprintf(out, size, "%s", name);
        } else {
            snprintf(out, size, "0x%" PRIx64, branch.target);
        }
        break;
    case BINBUN_TARGET_POINTER:
        snprintf(out, size, "*0x%" PRIx64 " (through a pointer)", branch.target);
        break;
    default:
        snprintf(out, size, "indirect");
    }
}

/* One line per call in `code` at `base`; how many there are. */
static size_t list_calls(const elf *e, const uint8_t *code, size_t size, uint64_t base) {
    size_t calls = 0;
    uint64_t address;
    binbun_status status;
    char text[BINBUN_X86_MAX_TEXT + 1], target[256];
    if (e->machine == EM_X86_64) {
        binbun_x86_decoder decoder;
        binbun_x86_instruction instruction;
        binbun_x86_decoder_init(&decoder, BINBUN_X86_MODE_BITS64, code, size, base);
        while ((status = binbun_x86_decoder_next(&decoder, &instruction, &address)) != BINBUN_STATUS_END) {
            if (status != BINBUN_STATUS_OK) continue;
            binbun_branch branch = binbun_x86_instruction_branch(&instruction, address);
            if (branch.kind != BINBUN_BRANCH_CALL) continue;
            binbun_x86_instruction_text(&instruction, address, BINBUN_TEXT_DEFAULT, text, sizeof text);
            describe_target(e, branch, target, sizeof target);
            printf("0x%08" PRIx64 "  %-40s  %s\n", address, text, target);
            calls++;
        }
    } else {
        binbun_aarch64_decoder decoder;
        binbun_aarch64_instruction instruction;
        binbun_aarch64_decoder_init(&decoder, code, size, base);
        while ((status = binbun_aarch64_decoder_next(&decoder, &instruction, &address)) != BINBUN_STATUS_END) {
            if (status != BINBUN_STATUS_OK) continue;
            binbun_branch branch = binbun_aarch64_instruction_branch(&instruction, address);
            if (branch.kind != BINBUN_BRANCH_CALL) continue;
            binbun_aarch64_instruction_text(&instruction, address, BINBUN_TEXT_DEFAULT, text, sizeof text);
            char *tab = strchr(text, '\t');
            if (tab != NULL) *tab = ' ';
            describe_target(e, branch, target, sizeof target);
            printf("0x%08" PRIx64 "  %-40s  %s\n", address, text, target);
            calls++;
        }
    }
    return calls;
}

int main(int argc, char **argv) {
    if (argc > 2) {
        fputs("usage: list_calls [ELF]\n", stderr);
        return 1;
    }
    /* The test program, two directories up from this file's. */
    char fixture[4096];
    int dir = 0;
    for (const char *at = __FILE__; (at = strpbrk(at, SEPARATORS)) != NULL; at++) {
        dir = (int)(at - __FILE__ + 1);
    }
    snprintf(fixture, sizeof fixture, "%.*s../../tests/fixtures/program-x86_64.elf", dir, __FILE__);
    const char *path = argc == 2 ? argv[1] : fixture;

    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return 1;
    }
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    rewind(file);
    uint8_t *data = length > 0 ? malloc((size_t)length) : NULL;
    size_t size = data != NULL ? fread(data, 1, (size_t)length, file) : 0;
    fclose(file);
    if (data == NULL || size != (size_t)length) {
        fprintf(stderr, "%s: cannot read the file\n", path);
        free(data);
        return 1;
    }

    elf e = {data, size, 0, 0, 0, 0};
    if (size < 64 || memcmp(data, "\x7f" "ELF", 4) != 0 || data[4] != 2 || data[5] != 1) {
        fprintf(stderr, "%s: not a 64-bit little-endian ELF file\n", path);
        free(data);
        return 1;
    }
    e.machine = (uint16_t)field(data + 18, 2);
    e.shoff = field(data + 40, 8);
    e.shnum = (uint16_t)field(data + 60, 2);
    e.shstrndx = (uint16_t)field(data + 62, 2);
    if (e.machine != EM_X86_64 && e.machine != EM_AARCH64) {
        fprintf(stderr, "%s: machine %u is neither x86-64 nor AArch64\n", path, e.machine);
        free(data);
        return 1;
    }
    for (size_t i = 0; i < e.shnum; i++) {
        section text;
        if (elf_section(&e, i, &text) && strcmp(text.name, ".text") == 0) {
            printf("calls in .text of %s:\n", path);
            size_t calls = list_calls(&e, data + text.offset, (size_t)text.size, text.address);
            printf("%zu calls\n", calls);
            free(data);
            return 0;
        }
    }
    fprintf(stderr, "%s: no .text section\n", path);
    free(data);
    return 1;
}
