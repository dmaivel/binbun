/* Show what one instruction does: its operands and whether it reads or
 * writes each, the registers it uses without naming them, the flags it
 * reads and writes, and where it branches. x86-64 or AArch64.
 *
 * With no bytes given it shows add qword ptr [rbx+0x10], rax (x86-64) or
 * stp x29, x30, [sp, #-0x10]! (AArch64).
 *
 *   ./instruction_info
 *   ./instruction_info 48014310                 # add qword ptr [rbx+0x10], rax
 *   ./instruction_info --aarch64 fd7bbfa9       # stp x29, x30, [sp, #-0x10]!
 *
 * Build as examples/c/quick_start.c says.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <binbun/disasm.h>

#define ADDRESS 0x1000

static const char *const access_names[] = {"-", "read", "write", "read/write"};

/* Appends the bytes `hex` writes to `code`, which holds `size` of
 * `capacity`; returns the new size. */
static size_t append_hex(const char *hex, uint8_t *code, size_t size, size_t capacity) {
    for (const char *p = hex; p[0] && p[1] && size < capacity; p += 2) {
        char pair[3] = {p[0], p[1], 0};
        code[size++] = (uint8_t)strtoul(pair, NULL, 16);
    }
    return size;
}

/* The names of the x86 flags set in `flags`, into `out`. */
static const char *x86_flags(uint32_t flags, char *out, size_t size) {
    static const struct {
        uint32_t bit;
        const char *name;
    } names[] = {{BINBUN_X86_FLAG_CF, "cf"}, {BINBUN_X86_FLAG_PF, "pf"}, {BINBUN_X86_FLAG_AF, "af"},
                 {BINBUN_X86_FLAG_ZF, "zf"}, {BINBUN_X86_FLAG_SF, "sf"}, {BINBUN_X86_FLAG_TF, "tf"},
                 {BINBUN_X86_FLAG_IF, "if"}, {BINBUN_X86_FLAG_DF, "df"}, {BINBUN_X86_FLAG_OF, "of"}};
    out[0] = 0;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (flags & names[i].bit) {
            strncat(out, out[0] ? " " : "", size - strlen(out) - 1);
            strncat(out, names[i].name, size - strlen(out) - 1);
        }
    }
    return out[0] ? out : "-";
}

static void x86_register(binbun_x86_register reg) {
    binbun_str name = binbun_x86_register_name(reg);
    printf("%.*s", (int)name.length, name.data);
}

static int x86_info(const uint8_t *code, size_t size) {
    binbun_x86_instruction inst;
    binbun_status status = binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, code, size, &inst);
    if (status != BINBUN_STATUS_OK) {
        binbun_str why = binbun_status_name(status);
        fprintf(stderr, "instruction_info: %.*s\n", (int)why.length, why.data);
        return 1;
    }
    char text[BINBUN_X86_MAX_TEXT + 1];
    binbun_x86_instruction_text(&inst, ADDRESS, BINBUN_TEXT_DEFAULT, text, sizeof text);
    binbun_str mnemonic = binbun_x86_mnemonic_name(binbun_x86_instruction_mnemonic(&inst));
    printf("0x%x: %s\n  mnemonic %.*s, length %u\n  operands:\n", ADDRESS, text, (int)mnemonic.length,
           mnemonic.data, binbun_x86_instruction_length(&inst));

    binbun_x86_operand operands[BINBUN_X86_MAX_OPERANDS];
    size_t count = binbun_x86_instruction_operands(&inst, operands, BINBUN_X86_MAX_OPERANDS);
    for (size_t i = 0; i < count; i++) {
        const binbun_x86_operand *op = &operands[i];
        const char *shown = op->visibility == BINBUN_X86_VISIBILITY_SUPPRESSED ? " (implicit)" : "";
        printf("    %zu  %-10s %3u bits  ", i, access_names[op->access & 3], op->bits);
        switch (op->kind) {
        case BINBUN_X86_OPERAND_REGISTER:
            x86_register(op->reg);
            break;
        case BINBUN_X86_OPERAND_MEMORY:
            printf("[");
            if (op->base) x86_register(op->base);
            if (op->index) {
                printf("+");
                x86_register(op->index);
                printf("*%u", op->scale);
            }
            printf("%s0x%" PRIx64 "] (%u bytes)", op->displacement < 0 ? "-" : "+",
                   op->displacement < 0 ? 0 - (uint64_t)op->displacement : (uint64_t)op->displacement,
                   op->memory_size);
            break;
        case BINBUN_X86_OPERAND_RELATIVE:
            printf("%+" PRId64 " from the next instruction", op->displacement);
            break;
        default:
            printf("0x%" PRIx64, op->value);
        }
        printf("%s\n", shown);
    }

    binbun_x86_flag_effect flags = binbun_x86_instruction_flags(&inst);
    char read[64], written[64];
    printf("  flags read: %s; written: %s\n", x86_flags(flags.read, read, sizeof read),
           x86_flags(flags.written, written, sizeof written));
    binbun_branch branch = binbun_x86_instruction_branch(&inst, ADDRESS);
    static const char *const kinds[] = {"none", "jump", "call", "return", "trap", "system call", "exception return", "halt"};
    printf("  branch: %s", kinds[branch.kind]);
    if (branch.target_kind == BINBUN_TARGET_ADDRESS) printf(" to 0x%" PRIx64, branch.target);
    printf("\n");
    return 0;
}

static void a64_register(binbun_aarch64_register r) {
    static const char *const classes[] = {"",  "w", "x", "w", "x", "b", "h", "s",  "d",
                                          "q", "v", "z", "p", "pn", "zt", "c", "ffr"};
    if (r.number == 31 && (r.class_ == BINBUN_AARCH64_REG_XSP || r.class_ == BINBUN_AARCH64_REG_WSP)) {
        printf(r.class_ == BINBUN_AARCH64_REG_XSP ? "sp" : "wsp");
    } else if (r.number == 31 && (r.class_ == BINBUN_AARCH64_REG_X || r.class_ == BINBUN_AARCH64_REG_W)) {
        printf(r.class_ == BINBUN_AARCH64_REG_X ? "xzr" : "wzr");
    } else {
        printf("%s%u", r.class_ <= BINBUN_AARCH64_REG_FFR ? classes[r.class_] : "?", r.number);
    }
}

static int aarch64_info(const uint8_t *code, size_t size) {
    binbun_aarch64_instruction inst;
    binbun_status status = binbun_aarch64_decode_bytes(code, size, &inst);
    if (status != BINBUN_STATUS_OK) {
        binbun_str why = binbun_status_name(status);
        fprintf(stderr, "instruction_info: %.*s\n", (int)why.length, why.data);
        return 1;
    }
    char text[BINBUN_AARCH64_MAX_TEXT + 1];
    binbun_aarch64_instruction_text(&inst, ADDRESS, BINBUN_TEXT_DEFAULT, text, sizeof text);
    char *tab = strchr(text, '\t');
    if (tab != NULL) *tab = ' ';
    binbun_str encoding = binbun_aarch64_encoding_name(binbun_aarch64_instruction_encoding(&inst));
    printf("0x%x: %s\n  encoding %.*s\n  operands:\n", ADDRESS, text, (int)encoding.length, encoding.data);

    binbun_aarch64_operand operands[BINBUN_AARCH64_MAX_OPERANDS];
    size_t count = binbun_aarch64_instruction_operands(&inst, operands, BINBUN_AARCH64_MAX_OPERANDS);
    for (size_t i = 0; i < count; i++) {
        const binbun_aarch64_operand *op = &operands[i];
        printf("    %zu  %-10s ", i, access_names[op->access & 3]);
        switch (op->kind) {
        case BINBUN_AARCH64_OPERAND_REGISTER:
        case BINBUN_AARCH64_OPERAND_WRITEBACK:
            a64_register(op->detail.reg);
            break;
        case BINBUN_AARCH64_OPERAND_MEMORY:
            printf("memory at [");
            a64_register(op->detail.memory.base);
            printf("%s]", op->detail.memory.writeback ? ", written back" : "");
            break;
        case BINBUN_AARCH64_OPERAND_IMMEDIATE:
            printf("immediate 0x%" PRIx64, op->detail.immediate.value);
            break;
        case BINBUN_AARCH64_OPERAND_LABEL:
            printf("label %+" PRId64, op->detail.label.offset);
            break;
        default:
            printf("(operand kind %u)", op->kind);
        }
        printf("\n");
    }
    binbun_aarch64_register implicit[8];
    size_t reads = binbun_aarch64_instruction_implicit_reads(&inst, implicit, 8);
    printf("  implicit reads:");
    for (size_t i = 0; i < reads && i < 8; i++) {
        printf(" ");
        a64_register(implicit[i]);
    }
    size_t writes = binbun_aarch64_instruction_implicit_writes(&inst, implicit, 8);
    printf(reads ? "; writes:" : " -; writes:");
    for (size_t i = 0; i < writes && i < 8; i++) {
        printf(" ");
        a64_register(implicit[i]);
    }
    printf(writes ? "\n" : " -\n");
    binbun_aarch64_memory_access memory;
    if (binbun_aarch64_instruction_memory(&inst, &memory)) {
        static const char *const kinds[] = {"", "load", "store", "atomic", "exclusive load", "exclusive store",
                                            "prefetch", "copy", "tag load", "tag store"};
        printf("  memory: %s of %u bytes\n", memory.kind <= 9 ? kinds[memory.kind] : "?", memory.size);
    }
    binbun_aarch64_flag_effect flags = binbun_aarch64_instruction_flags(&inst);
    printf("  flags read: 0x%x; written: 0x%x (NZCV)\n", flags.read, flags.written);
    return 0;
}

int main(int argc, char **argv) {
    int aarch64 = argc > 1 && strcmp(argv[1], "--aarch64") == 0;
    uint8_t code[16];
    size_t size = 0;
    for (int i = 1 + aarch64; i < argc; i++) size = append_hex(argv[i], code, size, sizeof code);
    if (argc == 1 + aarch64) size = append_hex(aarch64 ? "fd7bbfa9" : "48014310", code, 0, sizeof code);
    if (size == 0) {
        fputs("usage: instruction_info [--aarch64] [HEX]\n", stderr);
        return 1;
    }
    return aarch64 ? aarch64_info(code, size) : x86_info(code, size);
}
