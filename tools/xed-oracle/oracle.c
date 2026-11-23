/* XED as a test oracle for binbun's x86 decoder.
 *
 * Reads lines `MODE ADDRESS HEX` from stdin, where MODE is 16, 32, 64, r16
 * or r32 (real mode with 16- or 32-bit code), ADDRESS is the hex runtime
 * address of the instruction and HEX up to 15 instruction bytes, and prints
 * one line per input: the input, a space, and the answer
 *
 *     ILD_LENGTH|ILD_ERROR DECODE_LENGTH|DECODE_ERROR ICLASS IFORM | OPERAND...<TAB>TEXT<TAB>FLAGS<TAB>CPUID
 *
 * ILD columns come from xed_ild_decode (length decoder only); the rest from
 * xed_decode. ICLASS and IFORM are `-` when decoding fails, and the operand
 * list and the tab-separated columns are then absent. TEXT is
 * xed_format_context's Intel syntax at ADDRESS (no symbols), `-` if
 * formatting fails. Each operand is `NAME:VISIBILITY:ACTION=VALUE`:
 *
 *   registers (REGn, BASEn, INDEX, SEGn)  the register, e.g. RAX
 *   MEM0, MEM1, AGEN                      SEG:BASE:INDEX:SCALE:DISP:BYTES
 *   IMM0                                  hex value, `s` suffix if signed
 *   IMM1                                  hex value
 *   RELBR                                 signed decimal displacement
 *   anything else                         the field's value, decimal
 *
 * FLAGS and CPUID are described at print_flags and print_cpuid.
 *
 * Built as a program by scripts/xed-oracle.sh; with ORACLE_LIBRARY defined,
 * only oracle_init and oracle_answer are compiled, for in-process use (the
 * fuzz targets).
 */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "xed/xed-interface.h"

/* Sets up xedd for MODE; returns 0 for an unknown mode. */
static int set_mode(xed_decoded_inst_t* xedd, const char* mode) {
    xed_decoded_inst_zero(xedd);
    if (!strcmp(mode, "16")) {
        xed_decoded_inst_set_mode(xedd, XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b);
    } else if (!strcmp(mode, "32")) {
        xed_decoded_inst_set_mode(xedd, XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b);
    } else if (!strcmp(mode, "64")) {
        xed_decoded_inst_set_mode(xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    } else if (!strcmp(mode, "r16")) {
        xed_decoded_inst_set_mode(xedd, XED_MACHINE_MODE_REAL_16, XED_ADDRESS_WIDTH_16b);
    } else if (!strcmp(mode, "r32")) {
        xed_decoded_inst_set_mode(xedd, XED_MACHINE_MODE_REAL_32, XED_ADDRESS_WIDTH_32b);
    } else {
        return 0;
    }
    /* The dual encodings as the xed command (and binbun) decode them:
     * PAUSE, TZCNT and LZCNT rather than NOP, BSF and BSR; with CET,
     * ENDBR64 and ENDBR32 rather than reserved NOPs. */
    xed3_operand_set_p4(xedd, 1);
    xed3_operand_set_tzcnt(xedd, 1);
    xed3_operand_set_lzcnt(xedd, 1);
    xed3_operand_set_cet(xedd, 1);
    return 1;
}

static int is_register_operand(xed_operand_enum_t name) {
    return xed_operand_is_register(name) || name == XED_OPERAND_BASE0 || name == XED_OPERAND_BASE1 ||
           name == XED_OPERAND_INDEX || name == XED_OPERAND_SEG0 || name == XED_OPERAND_SEG1;
}

static void print_operands(FILE* out, const xed_decoded_inst_t* xedd) {
    const xed_inst_t* inst = xed_decoded_inst_inst(xedd);
    unsigned count = xed_inst_noperands(inst);
    for (unsigned i = 0; i < count; i++) {
        const xed_operand_t* op = xed_inst_operand(inst, i);
        xed_operand_enum_t name = xed_operand_name(op);
        fprintf(out, " %s:%s:%s=", xed_operand_enum_t2str(name),
                xed_operand_visibility_enum_t2str(xed_operand_operand_visibility(op)),
                xed_operand_action_enum_t2str(xed_operand_rw(op)));
        if (is_register_operand(name)) {
            fprintf(out, "%s", xed_reg_enum_t2str(xed_decoded_inst_get_reg(xedd, name)));
        } else if (name == XED_OPERAND_MEM0 || name == XED_OPERAND_MEM1 || name == XED_OPERAND_AGEN) {
            unsigned m = name == XED_OPERAND_MEM1 ? 1 : 0;
            fprintf(out, "%s:%s:%s:%u:%" PRId64 ":%u",
                    xed_reg_enum_t2str(xed_decoded_inst_get_seg_reg(xedd, m)),
                    xed_reg_enum_t2str(xed_decoded_inst_get_base_reg(xedd, m)),
                    xed_reg_enum_t2str(xed_decoded_inst_get_index_reg(xedd, m)),
                    xed_decoded_inst_get_scale(xedd, m), xed_decoded_inst_get_memory_displacement(xedd, m),
                    xed_decoded_inst_get_memory_operand_length(xedd, m));
        } else if (name == XED_OPERAND_IMM0) {
            fprintf(out, "%" PRIx64 "%s", xed_decoded_inst_get_unsigned_immediate(xedd),
                    xed_decoded_inst_get_immediate_is_signed(xedd) ? "s" : "");
        } else if (name == XED_OPERAND_IMM1) {
            fprintf(out, "%x", (unsigned)xed_decoded_inst_get_second_immediate(xedd));
        } else if (name == XED_OPERAND_RELBR) {
            fprintf(out, "%" PRId64, xed_decoded_inst_get_branch_displacement(xedd));
        } else {
            uint64_t value = 0;
            xed3_get_generic_operand(xedd, name, &value);
            fprintf(out, "%" PRIu64, value);
        }
    }
}

/* The flags column: `-` when the instruction has no flags information,
 * else READ:WRITTEN:UNDEFINED (flag sets, hex), MAY:MUST, and the flag
 * actions as `flag-action` joined by `,`. */
static void print_flags(FILE* out, const xed_decoded_inst_t* xedd) {
    const xed_simple_flag_t* flags = xed_decoded_inst_get_rflags_info(xedd);
    if (!flags) {
        fprintf(out, "\t-");
        return;
    }
    fprintf(out, "\t%x:%x:%x:%d:%d:", xed_simple_flag_get_read_flag_set(flags)->flat,
            xed_simple_flag_get_written_flag_set(flags)->flat,
            xed_simple_flag_get_undefined_flag_set(flags)->flat, xed_simple_flag_get_may_write(flags),
            xed_simple_flag_get_must_write(flags));
    unsigned count = xed_simple_flag_get_nflags(flags);
    for (unsigned i = 0; i < count; i++) {
        char action[64];
        xed_flag_action_print(xed_simple_flag_get_flag_action(flags, i), action, sizeof action);
        fprintf(out, "%s%s", i ? "," : "", action);
    }
}

/* The CPUID column: the isa set's CPUID groups joined by `|` (any one
 * suffices), each its records joined by `,` (all needed) as
 * LEAF.SUBLEAF.REG.START:END=VALUE (hex leaf and subleaf); `-` for none. */
static void print_cpuid(FILE* out, xed_isa_set_enum_t isa_set) {
    fprintf(out, "\t");
    int any = 0;
    for (unsigned g = 0; g < XED_MAX_CPUID_GROUPS_PER_ISA_SET; g++) {
        xed_cpuid_group_enum_t group = xed_get_cpuid_group_enum_for_isa_set(isa_set, g);
        if (group == XED_CPUID_GROUP_INVALID) break;
        int records = 0;
        for (unsigned r = 0; r < XED_MAX_CPUID_RECS_PER_GROUP; r++) {
            xed_cpuid_rec_enum_t id = xed_get_cpuid_rec_enum_for_group(group, r);
            xed_cpuid_rec_t rec;
            if (id == XED_CPUID_REC_INVALID || !xed_get_cpuid_rec(id, &rec)) break;
            fprintf(out, "%s%s%x.%x.%s.%u:%u=%u", records ? "," : "", !records && any ? "|" : "",
                    rec.leaf, rec.subleaf, xed_reg_enum_t2str(rec.reg), rec.bit_start, rec.bit_end,
                    rec.value);
            records++;
        }
        if (records) any = 1;
    }
    if (!any) fprintf(out, "-");
}

void oracle_init(void) { xed_tables_init(); }

/* Writes the answer for LENGTH bytes at ADDRESS in MODE to OUT (no newline,
 * NUL-terminated). Returns 0 on success, -1 for an unknown mode or when
 * the answer does not fit. */
int oracle_answer(const char* mode, uint64_t address, const unsigned char* bytes, unsigned length,
                  char* buffer, size_t capacity) {
    xed_decoded_inst_t xedd;
    if (!set_mode(&xedd, mode)) return -1;
    FILE* out = fmemopen(buffer, capacity, "w");
    if (!out) return -1;
    setvbuf(out, NULL, _IONBF, 0);

    xed_error_enum_t error = xed_ild_decode(&xedd, bytes, length);
    if (error == XED_ERROR_NONE) fprintf(out, "%u ", xed_decoded_inst_get_length(&xedd));
    else fprintf(out, "%s ", xed_error_enum_t2str(error));

    set_mode(&xedd, mode);
    error = xed_decode(&xedd, bytes, length);
    if (error == XED_ERROR_NONE) {
        fprintf(out, "%u %s %s |", xed_decoded_inst_get_length(&xedd),
                xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&xedd)),
                xed_iform_enum_t2str(xed_decoded_inst_get_iform_enum(&xedd)));
        print_operands(out, &xedd);
        char text[256];
        if (xed_format_context(XED_SYNTAX_INTEL, &xedd, text, sizeof text, address, 0, 0)) {
            fprintf(out, "\t%s", text);
        } else {
            fprintf(out, "\t-");
        }
        print_flags(out, &xedd);
        print_cpuid(out, xed_decoded_inst_get_isa_set(&xedd));
    } else {
        fprintf(out, "%s - - |", xed_error_enum_t2str(error));
    }
    long written = ftell(out);
    fclose(out);
    return written >= 0 && (size_t)written + 1 < capacity ? 0 : -1;
}

#ifndef ORACLE_LIBRARY
static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(void) {
    char line[256];
    static char answer[8192];
    oracle_init();
    while (fgets(line, sizeof line, stdin)) {
        char mode[8] = {0}, hex[128] = {0};
        uint64_t address = 0;
        if (sscanf(line, "%7s %" SCNx64 " %127s", mode, &address, hex) != 3) continue;
        unsigned char bytes[15];
        unsigned length = 0;
        for (size_t i = 0; hex[i] && hex[i + 1] && length < sizeof bytes; i += 2) {
            int hi = hex_value(hex[i]), lo = hex_value(hex[i + 1]);
            if (hi < 0 || lo < 0) break;
            bytes[length++] = (unsigned char)(hi * 16 + lo);
        }
        if (oracle_answer(mode, address, bytes, length, answer, sizeof answer)) {
            fprintf(stderr, "no answer for: %s", line);
            return 1;
        }
        printf("%s %" PRIx64 " %s %s\n", mode, address, hex, answer);
    }
    return 0;
}
#endif
