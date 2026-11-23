/*
 * Calls one function of a static x86-64 ELF fixture natively, on this
 * processor, for the profile test (crates/binbun-cli/tests/profiles.rs):
 *
 *   fixture-call FILE FUNCTION < inputs
 *
 * Each input line is two hexadecimal numbers, the first two arguments
 * (rdi, rsi); each output line is the function's return value (eax) in
 * hexadecimal. The function's bytes (from the symbol table) are copied to
 * an executable page and called there, so it must not refer to anything
 * by address (the fixture's leaf functions do not). The caller pins it to
 * a CPU (taskset): affinity is inherited.
 *
 * Built by scripts/fixture-call.sh. Linux x86-64 only.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static void fail(const char *what) {
    fprintf(stderr, "fixture-call: %s\n", what);
    exit(1);
}

static unsigned char *slurp(const char *path, size_t *size) {
    FILE *file = fopen(path, "rb");
    if (!file) fail("cannot open the file");
    if (fseek(file, 0, SEEK_END) != 0) fail("cannot seek");
    long length = ftell(file);
    if (length <= 0) fail("empty file");
    rewind(file);
    unsigned char *data = malloc((size_t)length);
    if (!data || fread(data, 1, (size_t)length, file) != (size_t)length) fail("cannot read");
    fclose(file);
    *size = (size_t)length;
    return data;
}

/* The bytes of symbol `name` in the ELF `data`: where they start in the
 * file and how many. */
static const unsigned char *function(const unsigned char *data, size_t size, const char *name,
                                     size_t *bytes) {
    if (size < sizeof(Elf64_Ehdr) || memcmp(data, ELFMAG, SELFMAG) != 0) fail("not ELF");
    const Elf64_Ehdr *header = (const Elf64_Ehdr *)data;
    if (header->e_ident[EI_CLASS] != ELFCLASS64 || header->e_machine != EM_X86_64)
        fail("not x86-64 ELF");
    if (header->e_shoff + (size_t)header->e_shnum * sizeof(Elf64_Shdr) > size)
        fail("bad section table");
    const Elf64_Shdr *sections = (const Elf64_Shdr *)(data + header->e_shoff);
    for (int i = 0; i < header->e_shnum; i++) {
        if (sections[i].sh_type != SHT_SYMTAB) continue;
        const Elf64_Shdr *strings = &sections[sections[i].sh_link];
        const Elf64_Sym *symbols = (const Elf64_Sym *)(data + sections[i].sh_offset);
        size_t count = sections[i].sh_size / sizeof(Elf64_Sym);
        for (size_t k = 0; k < count; k++) {
            const char *symbol = (const char *)(data + strings->sh_offset + symbols[k].st_name);
            if (strcmp(symbol, name) != 0 || symbols[k].st_shndx == SHN_UNDEF) continue;
            const Elf64_Shdr *home = &sections[symbols[k].st_shndx];
            size_t offset = home->sh_offset + (symbols[k].st_value - home->sh_addr);
            if (offset + symbols[k].st_size > size || symbols[k].st_size == 0)
                fail("bad symbol");
            *bytes = symbols[k].st_size;
            return data + offset;
        }
    }
    fail("no such function");
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) fail("usage: fixture-call FILE FUNCTION < inputs");
    size_t size, bytes;
    unsigned char *data = slurp(argv[1], &size);
    const unsigned char *code = function(data, size, argv[2], &bytes);
    void *page = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) fail("cannot map");
    memcpy(page, code, bytes);
    if (mprotect(page, bytes, PROT_READ | PROT_EXEC) != 0) fail("cannot make it executable");
    uint32_t (*call)(uint64_t, uint64_t);
    memcpy(&call, &page, sizeof call);
    uint64_t rdi, rsi;
    while (scanf("%" SCNx64 " %" SCNx64, &rdi, &rsi) == 2) {
        printf("%" PRIx32 "\n", call(rdi, rsi));
    }
    return 0;
}
