/* The C API from C: `disasm_test dump <x86-64|x86-32|aarch64> <address> <file>`
 * sweeps the code in <file> (at <address>, hex) and prints every
 * instruction in the notation tests/capi.rs prints from the Rust API, so the
 * two can be compared; `disasm_test any ...` does so through the decoder for
 * either architecture (binbun_decoder); `disasm_test check` exercises the
 * API's contract (statuses, null pointers, short buffers, storage). All exit
 * non-zero on the first violation. Built by tests/capi.rs with -Wall -Wextra
 * -Werror -std=c11. */
#include <binbun/binbun.h>

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The layout the header describes, on 64-bit targets: what the library's
 * own assertions pin on its side. */
#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFFu
_Static_assert(sizeof(binbun_str) == 16, "binbun_str");
_Static_assert(sizeof(binbun_branch) == 16 && _Alignof(binbun_branch) == 8, "binbun_branch");
_Static_assert(sizeof(binbun_token) == 24 && _Alignof(binbun_token) == 8, "binbun_token");
_Static_assert(sizeof(binbun_text_size) == 16, "binbun_text_size");
_Static_assert(sizeof(binbun_x86_instruction) == 192 && _Alignof(binbun_x86_instruction) == 8, "x86 storage");
_Static_assert(sizeof(binbun_x86_decoder) == 40, "binbun_x86_decoder");
_Static_assert(sizeof(binbun_x86_operand) == 40 && _Alignof(binbun_x86_operand) == 8, "binbun_x86_operand");
_Static_assert(sizeof(binbun_x86_flag_effect) == 16, "binbun_x86_flag_effect");
_Static_assert(sizeof(binbun_x86_register_info) == 12, "binbun_x86_register_info");
_Static_assert(sizeof(binbun_aarch64_instruction) == 32, "aarch64 storage");
_Static_assert(sizeof(binbun_aarch64_decoder) == 32, "binbun_aarch64_decoder");
_Static_assert(sizeof(binbun_aarch64_register) == 8, "binbun_aarch64_register");
_Static_assert(sizeof(binbun_aarch64_condition) == 32, "binbun_aarch64_condition");
_Static_assert(sizeof(binbun_aarch64_flag_effect) == 4, "binbun_aarch64_flag_effect");
_Static_assert(sizeof(binbun_aarch64_memory_access) == 8, "binbun_aarch64_memory_access");
_Static_assert(sizeof(binbun_aarch64_register_list) == 16, "binbun_aarch64_register_list");
_Static_assert(sizeof(binbun_aarch64_immediate) == 16, "binbun_aarch64_immediate");
_Static_assert(sizeof(binbun_aarch64_float) == 16, "binbun_aarch64_float");
_Static_assert(sizeof(binbun_aarch64_shift) == 8, "binbun_aarch64_shift");
_Static_assert(sizeof(binbun_aarch64_extend) == 8, "binbun_aarch64_extend");
_Static_assert(sizeof(binbun_aarch64_memory) == 32, "binbun_aarch64_memory");
_Static_assert(sizeof(binbun_aarch64_label) == 16, "binbun_aarch64_label");
_Static_assert(sizeof(binbun_aarch64_system_register) == 24, "binbun_aarch64_system_register");
_Static_assert(sizeof(binbun_aarch64_named) == 24, "binbun_aarch64_named");
_Static_assert(sizeof(binbun_aarch64_za) == 16, "binbun_aarch64_za");
_Static_assert(sizeof(binbun_aarch64_za_list) == 24, "binbun_aarch64_za_list");
_Static_assert(sizeof(binbun_aarch64_indexed_register) == 24, "binbun_aarch64_indexed_register");
_Static_assert(sizeof(binbun_aarch64_operand) == 40 && _Alignof(binbun_aarch64_operand) == 8,
               "binbun_aarch64_operand");
_Static_assert(sizeof(binbun_instruction) == 256 && _Alignof(binbun_instruction) == 8, "storage");
_Static_assert(sizeof(binbun_decoder) == 40, "binbun_decoder");
_Static_assert(sizeof(binbun_register) == 24 && _Alignof(binbun_register) == 8, "binbun_register");
#endif

static void fail(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    fputs("disasm_test: ", stderr);
    vfprintf(stderr, format, arguments);
    fputc('\n', stderr);
    va_end(arguments);
    exit(1);
}

#define REQUIRE(condition)                                                                  \
    do {                                                                                    \
        if (!(condition)) fail("%s:%d: %s", __FILE__, __LINE__, #condition);                \
    } while (0)

static int str_is(binbun_str s, const char *text) {
    return s.length == strlen(text) && memcmp(s.data, text, s.length) == 0;
}

static int str_equal(binbun_str a, binbun_str b) {
    return a.length == b.length && memcmp(a.data, b.data, a.length) == 0;
}

static const char *status_symbol(binbun_status status) {
    switch (status) {
    case BINBUN_STATUS_OK: return "OK";
    case BINBUN_STATUS_END: return "END";
    case BINBUN_STATUS_TRUNCATED: return "TRUNCATED";
    case BINBUN_STATUS_NULL_POINTER: return "NULL_POINTER";
    case BINBUN_STATUS_BAD_ARGUMENT: return "BAD_ARGUMENT";
    case BINBUN_STATUS_FAILED: return "FAILED";
    case BINBUN_STATUS_INVALID: return "INVALID";
    case BINBUN_STATUS_X86_TOO_LONG: return "X86_TOO_LONG";
    case BINBUN_STATUS_X86_INVALID_MODE: return "X86_INVALID_MODE";
    case BINBUN_STATUS_X86_BAD_REGISTER: return "X86_BAD_REGISTER";
    case BINBUN_STATUS_X86_BAD_LOCK_PREFIX: return "X86_BAD_LOCK_PREFIX";
    case BINBUN_STATUS_X86_BAD_LEGACY_PREFIX: return "X86_BAD_LEGACY_PREFIX";
    case BINBUN_STATUS_X86_BAD_REX_PREFIX: return "X86_BAD_REX_PREFIX";
    case BINBUN_STATUS_X86_BAD_MAP: return "X86_BAD_MAP";
    case BINBUN_STATUS_X86_BAD_EVEX_V_PRIME: return "X86_BAD_EVEX_V_PRIME";
    case BINBUN_STATUS_X86_BAD_EVEX_ZEROING: return "X86_BAD_EVEX_ZEROING";
    case BINBUN_STATUS_X86_BAD_EVEX_LENGTH: return "X86_BAD_EVEX_LENGTH";
    case BINBUN_STATUS_X86_GATHER_REGISTERS: return "X86_GATHER_REGISTERS";
    case BINBUN_STATUS_X86_BAD_REGISTER_MATCH: return "X86_BAD_REGISTER_MATCH";
    case BINBUN_STATUS_AARCH64_UNALLOCATED: return "AARCH64_UNALLOCATED";
    case BINBUN_STATUS_AARCH64_UNDEFINED: return "AARCH64_UNDEFINED";
    case BINBUN_STATUS_AARCH64_UNPREDICTABLE: return "AARCH64_UNPREDICTABLE";
    default: return "?";
    }
}

static void print_branch(binbun_branch branch) {
    static const char *const kinds[] = {"none", "jump", "call", "return", "trap", "syscall", "eret", "halt"};
    REQUIRE(branch.kind <= BINBUN_BRANCH_HALT);
    printf(" branch=%s%s fall=%d target=", kinds[branch.kind], branch.conditional ? "?" : "", branch.falls_through);
    switch (branch.target_kind) {
    case BINBUN_TARGET_NONE: printf("none"); break;
    case BINBUN_TARGET_ADDRESS: printf("address:%" PRIx64, branch.target); break;
    case BINBUN_TARGET_POINTER: printf("pointer:%" PRIx64 "/%u", branch.target, branch.pointer_size); break;
    case BINBUN_TARGET_INDIRECT: printf("indirect"); break;
    case BINBUN_TARGET_FAR: printf("far:%x:%" PRIx64, branch.selector, branch.target); break;
    default: fail("target kind %u", branch.target_kind);
    }
    printf("\n");
}

static void print_computed(bool computed, uint64_t address) {
    if (computed) {
        printf(" computed=%" PRIx64 "\n", address);
    }
}

/* The tokens of an instruction whose text is `text`, `length` bytes, and
 * which has `operands` operands: together they are the text, and every
 * token that is part of an operand names one there is. */
static void check_tokens(const char *text, size_t length, size_t max_text, size_t max_tokens, const binbun_token *tokens,
                         binbun_text_size size, const char *tokens_text, size_t operands, int aarch64) {
    REQUIRE(size.length == length && length <= max_text);
    REQUIRE(size.tokens > 0 && size.tokens <= max_tokens);
    REQUIRE(strcmp(text, tokens_text) == 0);
    size_t offset = 0, separators = 0, registers = 0, owned = 0;
    for (size_t i = 0; i < size.tokens; i++) {
        const binbun_token *token = &tokens[i];
        if (token->offset != offset || token->length == 0) fail("token %zu of `%s` at %u", i, text, token->offset);
        offset += token->length;
        REQUIRE(token->kind <= BINBUN_TOKEN_WHITESPACE);
        REQUIRE(token->operand == BINBUN_TOKEN_NO_OPERAND || token->operand < operands);
        if (token->kind == BINBUN_TOKEN_SEPARATOR) {
            separators++;
            REQUIRE(token->operand == BINBUN_TOKEN_NO_OPERAND && token->length == 2);
        }
        if (token->kind == BINBUN_TOKEN_REGISTER) {
            registers++;
            owned += token->operand != BINBUN_TOKEN_NO_OPERAND;
        }
    }
    REQUIRE(offset == length);
    REQUIRE(tokens[0].kind == BINBUN_TOKEN_MNEMONIC || tokens[0].kind == BINBUN_TOKEN_PREFIX);
    if (owned != registers) fail("registers of `%s` without an operand", text);
    if (aarch64 && separators != (operands ? operands - 1 : 0)) fail("separators of `%s`", text);
}

/* ---------------------------------------------------------------------- x86 */

static const char *x86_condition(binbun_x86_condition condition) {
    static const char *const names[] = {
        "-",  "o",   "no", "b",  "nb", "z",     "nz",   "be",         "nbe",  "s",         "ns",           "p",
        "np", "l",   "nl", "le", "nle", "false", "true", "count_zero", "loop", "loop_zero", "loop_not_zero",
        "transaction_abort"};
    REQUIRE(condition <= BINBUN_X86_CONDITION_TRANSACTION_ABORT);
    return names[condition];
}

static const char *x86_field(binbun_x86_operand_field field) {
    static const char *const names[] = {"",      "REG0",  "REG1", "REG2", "REG3", "REG4", "REG5",
                                        "REG6",  "REG7",  "REG8", "REG9", "BASE0", "BASE1", "MEM0",
                                        "MEM1",  "AGEN",  "IMM0", "IMM1", "RELBR", "ABSBR", "PTR"};
    REQUIRE(field >= BINBUN_X86_FIELD_REG0 && field <= BINBUN_X86_FIELD_PTR);
    return names[field];
}

static void print_x86_register(const char *label, binbun_x86_register reg) {
    binbun_str name = binbun_x86_register_name(reg);
    if (reg == BINBUN_X86_REG_NONE) {
        REQUIRE(name.length == 0);
        printf(" %s=-", label);
    } else {
        REQUIRE(name.length > 0);
        printf(" %s=%.*s", label, (int)name.length, name.data);
    }
}

static void print_x86_operand(const binbun_x86_operand *op) {
    static const char *const kinds[] = {"", "register", "memory", "immediate", "second", "relative", "field"};
    static const char *const visibilities[] = {"", "explicit", "implicit", "suppressed"};
    static const char *const actions[] = {"", "r", "w", "rw", "cr", "cw", "crw", "rcw"};
    static const char *const accesses[] = {"-", "r", "w", "rw"};
    REQUIRE(op->kind >= BINBUN_X86_OPERAND_REGISTER && op->kind <= BINBUN_X86_OPERAND_FIELD);
    REQUIRE(op->visibility >= BINBUN_X86_VISIBILITY_EXPLICIT && op->visibility <= BINBUN_X86_VISIBILITY_SUPPRESSED);
    REQUIRE(op->action >= BINBUN_X86_ACTION_READ && op->action <= BINBUN_X86_ACTION_READ_CONDITIONAL_WRITE);
    REQUIRE(op->access <= (BINBUN_ACCESS_READ | BINBUN_ACCESS_WRITE));
    printf(" op=%s field=%s vis=%s act=%s acc=%s bits=%u", kinds[op->kind], x86_field(op->field),
           visibilities[op->visibility], actions[op->action], accesses[op->access], op->bits);
    switch (op->kind) {
    case BINBUN_X86_OPERAND_REGISTER: print_x86_register("reg", op->reg); break;
    case BINBUN_X86_OPERAND_MEMORY:
        print_x86_register("seg", op->segment);
        print_x86_register("base", op->base);
        print_x86_register("index", op->index);
        printf(" scale=%u disp=%" PRId64 " size=%u", op->scale, op->displacement, op->memory_size);
        break;
    case BINBUN_X86_OPERAND_IMMEDIATE: printf(" value=%" PRIx64 " signed=%d", op->value, op->signed_immediate); break;
    case BINBUN_X86_OPERAND_SECOND_IMMEDIATE:
    case BINBUN_X86_OPERAND_FIELD: printf(" value=%" PRIx64, op->value); break;
    case BINBUN_X86_OPERAND_RELATIVE: printf(" disp=%" PRId64, op->displacement); break;
    default: break;
    }
    printf("\n");
}

static void print_x86(binbun_x86_mode mode, const binbun_x86_instruction *inst, const uint8_t *bytes, size_t left,
                      uint64_t address) {
    static const char *const encodings[] = {"", "legacy", "vex", "evex", "xop"};
    uint8_t length = binbun_x86_instruction_length(inst);
    REQUIRE(length >= 1 && length <= BINBUN_X86_MAX_LENGTH && length <= left);

    /* The other ways to decode the same bytes agree. */
    size_t only_length = 0;
    REQUIRE(binbun_x86_decode_length(mode, bytes, left, &only_length) == BINBUN_STATUS_OK && only_length == length);
    binbun_x86_instruction again;
    REQUIRE(binbun_x86_decode_bytes(mode, bytes, left, &again) == BINBUN_STATUS_OK);
    REQUIRE(binbun_x86_instruction_form(&again) == binbun_x86_instruction_form(inst));

    binbun_str mnemonic = binbun_x86_mnemonic_name(binbun_x86_instruction_mnemonic(inst));
    binbun_str form = binbun_x86_form_name(binbun_x86_instruction_form(inst));
    binbun_str category = binbun_x86_category_name(binbun_x86_instruction_category(inst));
    binbun_str extension = binbun_x86_extension_name(binbun_x86_instruction_extension(inst));
    binbun_str isa_set = binbun_x86_isa_set_name(binbun_x86_instruction_isa_set(inst));
    binbun_x86_encoding encoding = binbun_x86_instruction_encoding(inst);
    REQUIRE(encoding >= BINBUN_X86_ENCODING_LEGACY && encoding <= BINBUN_X86_ENCODING_XOP);
    REQUIRE(binbun_x86_mnemonic_from_name(mnemonic.data, mnemonic.length) == binbun_x86_instruction_mnemonic(inst));
    REQUIRE(binbun_x86_form_from_name(form.data, form.length) == binbun_x86_instruction_form(inst));
    printf("@%" PRIx64 " len=%u mnem=%.*s form=%.*s cat=%.*s ext=%.*s isa=%.*s enc=%s cond=%s w=%u,%u,%u\n", address,
           length, (int)mnemonic.length, mnemonic.data, (int)form.length, form.data, (int)category.length,
           category.data, (int)extension.length, extension.data, (int)isa_set.length, isa_set.data,
           encodings[encoding], x86_condition(binbun_x86_instruction_condition(inst)),
           binbun_x86_instruction_operand_width(inst), binbun_x86_instruction_address_width(inst),
           binbun_x86_instruction_stack_address_width(inst));

    char text[BINBUN_X86_MAX_TEXT + 1];
    size_t text_length = binbun_x86_instruction_text(inst, address, BINBUN_TEXT_DEFAULT, text, sizeof text);
    REQUIRE(text_length > 0 && text_length <= BINBUN_X86_MAX_TEXT && strlen(text) == text_length);
    printf(" text=%s\n", text);
    print_branch(binbun_x86_instruction_branch(inst, address));
    uint64_t computed = 0;
    bool has_computed = binbun_x86_instruction_computed_address(inst, address, &computed);
    print_computed(has_computed, computed);
    binbun_x86_flag_effect flags = binbun_x86_instruction_flags(inst);
    printf(" flags=%x,%x,%x,%d,%d\n", flags.read, flags.written, flags.undefined, flags.may_write, flags.must_write);

    binbun_x86_operand operands[BINBUN_X86_MAX_OPERANDS];
    size_t count = binbun_x86_instruction_operands(inst, operands, BINBUN_X86_MAX_OPERANDS);
    REQUIRE(count <= BINBUN_X86_MAX_OPERANDS);
    for (size_t i = 0; i < count; i++) {
        print_x86_operand(&operands[i]);
    }

    char tokens_text[BINBUN_X86_MAX_TEXT + 1];
    binbun_token tokens[BINBUN_X86_MAX_TOKENS];
    binbun_text_size size = binbun_x86_instruction_tokens(inst, address, BINBUN_TEXT_DEFAULT, tokens_text,
                                                          sizeof tokens_text, tokens, BINBUN_X86_MAX_TOKENS);
    check_tokens(text, text_length, BINBUN_X86_MAX_TEXT, BINBUN_X86_MAX_TOKENS, tokens, size, tokens_text, count, 0);
}

static void dump_x86(binbun_x86_mode mode, uint64_t address, const uint8_t *bytes, size_t length) {
    binbun_x86_decoder decoder;
    REQUIRE(binbun_x86_decoder_init(&decoder, mode, bytes, length, address) == BINBUN_STATUS_OK);
    binbun_x86_instruction inst;
    uint64_t at = 0;
    binbun_status status;
    while ((status = binbun_x86_decoder_next(&decoder, &inst, &at)) != BINBUN_STATUS_END) {
        if (status == BINBUN_STATUS_OK) {
            size_t offset = (size_t)(at - address);
            print_x86(mode, &inst, bytes + offset, length - offset, at);
        } else {
            REQUIRE(BINBUN_STATUS_IS_INVALID(status) || status == BINBUN_STATUS_TRUNCATED);
            printf("@%" PRIx64 " %s\n", at, status_symbol(status));
        }
    }
}

/* ------------------------------------------------------------------ AArch64 */

static const char *const cond_names[] = {"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                                         "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
static const char *const radixes[] = {"", "hex", "dec", "padded"};

static void print_a64_register(const char *label, binbun_aarch64_register reg) {
    static const char *const classes[] = {"", "w", "x", "wsp", "xsp", "b", "h", "s", "d",
                                          "q", "v", "z", "p",   "pn",  "zt", "c", "ffr"};
    static const char *const elements[] = {"-", "b", "h", "s", "d", "q"};
    static const char *const predications[] = {"-", "z", "m"};
    REQUIRE(reg.class_ >= BINBUN_AARCH64_REG_W && reg.class_ <= BINBUN_AARCH64_REG_FFR);
    REQUIRE(reg.element <= BINBUN_AARCH64_ELEMENT_Q && reg.predication <= BINBUN_AARCH64_PREDICATION_MERGING);
    printf(" %s=%s%u/%u%s/", label, classes[reg.class_], reg.number, reg.lanes, elements[reg.element]);
    if (reg.has_index) {
        printf("%u", reg.index);
    } else {
        printf("-");
    }
    printf("/%s", predications[reg.predication]);
}

static void print_a64_za(binbun_aarch64_za za) {
    static const char *const elements[] = {"-", "b", "h", "s", "d", "q"};
    static const char *const directions[] = {"-", "h", "v"};
    REQUIRE(za.element <= BINBUN_AARCH64_ELEMENT_Q && za.direction <= BINBUN_AARCH64_SLICE_VERTICAL);
    printf(" za=");
    if (za.has_tile) {
        printf("%u", za.tile);
    } else {
        printf("-");
    }
    printf("/%s/%s", elements[za.element], directions[za.direction]);
    if (za.has_slice) {
        printf("/w%u+%u", za.slice_index, za.slice_offset);
        if (za.has_last) printf(":%u", za.slice_last);
        printf("x%u", za.group);
    }
}

static void print_a64_operand(const binbun_aarch64_operand *op) {
    static const char *const kinds[] = {"",      "register", "list",  "immediate", "float", "shift",
                                        "extend", "memory",  "writeback", "label", "condition", "sysreg",
                                        "named", "za",       "za_list", "table_slice", "indexed"};
    static const char *const accesses[] = {"-", "r", "w", "rw"};
    static const char *const shifts[] = {"", "lsl", "lsr", "asr", "ror", "msl", "mul"};
    static const char *const extends[] = {"", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};
    static const char *const names[] = {"", "prefetch", "barrier", "bti", "pstate", "pattern", "sysop", "keyword"};
    REQUIRE(op->kind >= BINBUN_AARCH64_OPERAND_REGISTER && op->kind <= BINBUN_AARCH64_OPERAND_INDEXED_REGISTER);
    REQUIRE(op->access <= (BINBUN_ACCESS_READ | BINBUN_ACCESS_WRITE));
    printf(" op=%s acc=%s", kinds[op->kind], accesses[op->access]);
    switch (op->kind) {
    case BINBUN_AARCH64_OPERAND_REGISTER:
    case BINBUN_AARCH64_OPERAND_WRITEBACK: print_a64_register("reg", op->detail.reg); break;
    case BINBUN_AARCH64_OPERAND_LIST:
        print_a64_register("first", op->detail.list.first);
        REQUIRE(op->detail.list.style == BINBUN_AARCH64_LIST_COMMAS || op->detail.list.style == BINBUN_AARCH64_LIST_RANGE);
        printf(" count=%u stride=%u style=%s", op->detail.list.count, op->detail.list.stride,
               op->detail.list.style == BINBUN_AARCH64_LIST_COMMAS ? "commas" : "range");
        break;
    case BINBUN_AARCH64_OPERAND_IMMEDIATE:
        REQUIRE(op->detail.immediate.radix >= BINBUN_AARCH64_RADIX_HEX && op->detail.immediate.radix <= BINBUN_AARCH64_RADIX_PADDED_HEX);
        printf(" value=%" PRIx64 " signed=%d radix=%s", op->detail.immediate.value, op->detail.immediate.is_signed,
               radixes[op->detail.immediate.radix]);
        break;
    case BINBUN_AARCH64_OPERAND_FLOAT: {
        uint64_t bits;
        memcpy(&bits, &op->detail.float_.value, sizeof bits);
        printf(" bits=%016" PRIx64 " exact=%d", bits, op->detail.float_.exact);
        break;
    }
    case BINBUN_AARCH64_OPERAND_SHIFT:
        REQUIRE(op->detail.shift.kind >= BINBUN_AARCH64_SHIFT_LSL && op->detail.shift.kind <= BINBUN_AARCH64_SHIFT_MUL);
        printf(" %s=%u", shifts[op->detail.shift.kind], op->detail.shift.amount);
        break;
    case BINBUN_AARCH64_OPERAND_EXTEND:
        REQUIRE(op->detail.extend.kind >= BINBUN_AARCH64_EXTEND_UXTB && op->detail.extend.kind <= BINBUN_AARCH64_EXTEND_SXTX);
        printf(" %s", extends[op->detail.extend.kind]);
        if (op->detail.extend.has_amount) printf("=%u", op->detail.extend.amount);
        break;
    case BINBUN_AARCH64_OPERAND_MEMORY: {
        const binbun_aarch64_memory *m = &op->detail.memory;
        static const char *const writebacks[] = {"none", "pre", "post"};
        REQUIRE(m->writeback <= BINBUN_AARCH64_WRITEBACK_POST);
        print_a64_register("base", m->base);
        switch (m->offset_kind) {
        case BINBUN_AARCH64_OFFSET_NONE: printf(" offset=none"); break;
        case BINBUN_AARCH64_OFFSET_IMMEDIATE:
            REQUIRE(m->offset_radix >= BINBUN_AARCH64_RADIX_HEX && m->offset_radix <= BINBUN_AARCH64_RADIX_PADDED_HEX);
            printf(" offset=%" PRId64 " signed=%d radix=%s", m->offset, m->offset_signed, radixes[m->offset_radix]);
            break;
        case BINBUN_AARCH64_OFFSET_REGISTER:
            print_a64_register("index", m->index);
            if (m->modifier == BINBUN_AARCH64_MODIFIER_SHIFT) {
                REQUIRE(m->modifier_kind >= BINBUN_AARCH64_SHIFT_LSL && m->modifier_kind <= BINBUN_AARCH64_SHIFT_MUL);
                printf(" %s=%u", shifts[m->modifier_kind], m->modifier_amount);
            } else if (m->modifier == BINBUN_AARCH64_MODIFIER_EXTEND) {
                REQUIRE(m->modifier_kind >= BINBUN_AARCH64_EXTEND_UXTB && m->modifier_kind <= BINBUN_AARCH64_EXTEND_SXTX);
                printf(" %s", extends[m->modifier_kind]);
                if (m->modifier_has_amount) printf("=%u", m->modifier_amount);
            } else {
                REQUIRE(m->modifier == BINBUN_AARCH64_MODIFIER_NONE);
            }
            break;
        case BINBUN_AARCH64_OFFSET_VECTOR_LENGTH: printf(" offset=%" PRId64 "vl", m->offset); break;
        default: fail("offset kind %u", m->offset_kind);
        }
        printf(" wb=%s", writebacks[m->writeback]);
        break;
    }
    case BINBUN_AARCH64_OPERAND_LABEL:
        REQUIRE(op->detail.label.base == BINBUN_AARCH64_LABEL_INSTRUCTION || op->detail.label.base == BINBUN_AARCH64_LABEL_PAGE);
        REQUIRE(op->detail.label.radix >= BINBUN_AARCH64_RADIX_HEX && op->detail.label.radix <= BINBUN_AARCH64_RADIX_PADDED_HEX);
        printf(" offset=%" PRId64 " base=%s radix=%s", op->detail.label.offset,
               op->detail.label.base == BINBUN_AARCH64_LABEL_PAGE ? "page" : "pc", radixes[op->detail.label.radix]);
        break;
    case BINBUN_AARCH64_OPERAND_CONDITION:
        REQUIRE(op->detail.condition <= BINBUN_AARCH64_COND_NV);
        printf(" cond=%s", cond_names[op->detail.condition]);
        break;
    case BINBUN_AARCH64_OPERAND_SYSTEM_REGISTER:
        REQUIRE(op->detail.system_register.has_name == (op->detail.system_register.name.length > 0));
        printf(" sysreg=%x/%.*s", op->detail.system_register.encoding, (int)op->detail.system_register.name.length,
               op->detail.system_register.name.data);
        break;
    case BINBUN_AARCH64_OPERAND_NAMED:
        REQUIRE(op->detail.named.kind >= BINBUN_AARCH64_NAME_PREFETCH && op->detail.named.kind <= BINBUN_AARCH64_NAME_KEYWORD);
        printf(" %s=%.*s", names[op->detail.named.kind], (int)op->detail.named.name.length, op->detail.named.name.data);
        break;
    case BINBUN_AARCH64_OPERAND_ZA: print_a64_za(op->detail.za); break;
    case BINBUN_AARCH64_OPERAND_ZA_LIST:
        if (op->detail.za_list.kind == BINBUN_AARCH64_ZA_LIST_TILES) {
            printf(" tiles=%x", op->detail.za_list.tiles);
        } else {
            REQUIRE(op->detail.za_list.kind == BINBUN_AARCH64_ZA_LIST_SLICE);
            print_a64_za(op->detail.za_list.za);
        }
        break;
    case BINBUN_AARCH64_OPERAND_TABLE_SLICE: printf(" slice=%u", op->detail.table_slice); break;
    case BINBUN_AARCH64_OPERAND_INDEXED_REGISTER:
        print_a64_register("reg", op->detail.indexed_register.reg);
        print_a64_register("index", op->detail.indexed_register.index);
        printf(" offset=%u", op->detail.indexed_register.offset);
        break;
    default: break;
    }
    printf("\n");
}

static void print_a64_registers(const char *label, const binbun_aarch64_register *registers, size_t count) {
    printf(" %s:", label);
    for (size_t i = 0; i < count; i++) {
        print_a64_register("r", registers[i]);
    }
    printf("\n");
}

static void print_a64(const binbun_aarch64_instruction *inst, uint64_t address) {
    static const char *const memory_kinds[] = {"",      "load",     "store", "atomic",   "load_exclusive",
                                               "store_exclusive", "prefetch", "copy", "load_tag", "store_tag"};
    uint32_t word = binbun_aarch64_instruction_word(inst);
    binbun_aarch64_instruction again;
    REQUIRE(binbun_aarch64_decode_word(word, &again) == BINBUN_STATUS_OK);
    REQUIRE(binbun_aarch64_instruction_encoding(&again) == binbun_aarch64_instruction_encoding(inst));
    REQUIRE(binbun_aarch64_instruction_length(inst) == BINBUN_AARCH64_LENGTH);
    binbun_str encoding = binbun_aarch64_encoding_name(binbun_aarch64_instruction_encoding(inst));
    REQUIRE(binbun_aarch64_encoding_from_name(encoding.data, encoding.length) == binbun_aarch64_instruction_encoding(inst));
    binbun_str base = binbun_aarch64_encoding_mnemonic(binbun_aarch64_instruction_encoding(inst));
    binbun_str mnemonic = binbun_aarch64_instruction_mnemonic(inst);
    printf("@%" PRIx64 " word=%08x enc=%.*s base=%.*s mnem=%.*s\n", address, word, (int)encoding.length, encoding.data,
           (int)base.length, base.data, (int)mnemonic.length, mnemonic.data);

    char text[BINBUN_AARCH64_MAX_TEXT + 1];
    size_t text_length = binbun_aarch64_instruction_text(inst, address, BINBUN_TEXT_DEFAULT, text, sizeof text);
    REQUIRE(text_length > 0 && text_length <= BINBUN_AARCH64_MAX_TEXT && strlen(text) == text_length);
    printf(" text=%s\n", text);
    char relative[BINBUN_AARCH64_MAX_TEXT + 1];
    REQUIRE(binbun_aarch64_instruction_text(inst, address, BINBUN_TEXT_RELATIVE_LABELS, relative, sizeof relative) > 0);
    printf(" relative=%s\n", relative);
    print_branch(binbun_aarch64_instruction_branch(inst, address));
    uint64_t computed = 0;
    bool has_computed = binbun_aarch64_instruction_computed_address(inst, address, &computed);
    print_computed(has_computed, computed);

    binbun_aarch64_condition condition;
    if (binbun_aarch64_instruction_condition(inst, &condition)) {
        REQUIRE(condition.cond <= BINBUN_AARCH64_COND_NV);
        switch (condition.kind) {
        case BINBUN_AARCH64_CONDITION_FLAGS: printf(" cond=flags:%s", cond_names[condition.cond]); break;
        case BINBUN_AARCH64_CONDITION_ZERO:
            printf(" cond=zero:%d", condition.sense);
            print_a64_register("reg", condition.reg);
            break;
        case BINBUN_AARCH64_CONDITION_BIT:
            printf(" cond=bit:%u:%d", condition.bit, condition.sense);
            print_a64_register("reg", condition.reg);
            break;
        case BINBUN_AARCH64_CONDITION_COMPARE:
            printf(" cond=compare:%s", cond_names[condition.cond]);
            print_a64_register("reg", condition.reg);
            if (condition.right_kind == BINBUN_AARCH64_COMPARE_REGISTER) {
                print_a64_register("right", condition.right_register);
            } else {
                REQUIRE(condition.right_kind == BINBUN_AARCH64_COMPARE_IMMEDIATE);
                printf(" right=%" PRId64, condition.right_immediate);
            }
            break;
        default: fail("condition kind %u", condition.kind);
        }
        printf("\n");
    }
    binbun_aarch64_flag_effect flags = binbun_aarch64_instruction_flags(inst);
    REQUIRE(flags.read <= 0xF && flags.written <= 0xF);
    printf(" flags=%x,%x\n", flags.read, flags.written);
    binbun_aarch64_memory_access memory;
    if (binbun_aarch64_instruction_memory(inst, &memory)) {
        REQUIRE(memory.kind >= BINBUN_AARCH64_MEMORY_LOAD && memory.kind <= BINBUN_AARCH64_MEMORY_STORE_TAG);
        printf(" memory=%s/%u\n", memory_kinds[memory.kind], memory.size);
    }
    binbun_aarch64_register implicit[8];
    size_t reads = binbun_aarch64_instruction_implicit_reads(inst, implicit, 8);
    REQUIRE(reads <= 8);
    if (reads) print_a64_registers("reads", implicit, reads);
    size_t writes = binbun_aarch64_instruction_implicit_writes(inst, implicit, 8);
    REQUIRE(writes <= 8);
    if (writes) print_a64_registers("writes", implicit, writes);

    binbun_aarch64_operand operands[BINBUN_AARCH64_MAX_OPERANDS];
    size_t count = binbun_aarch64_instruction_operands(inst, operands, BINBUN_AARCH64_MAX_OPERANDS);
    REQUIRE(count <= BINBUN_AARCH64_MAX_OPERANDS);
    for (size_t i = 0; i < count; i++) {
        print_a64_operand(&operands[i]);
    }

    char tokens_text[BINBUN_AARCH64_MAX_TEXT + 1];
    binbun_token tokens[BINBUN_AARCH64_MAX_TOKENS];
    binbun_text_size size = binbun_aarch64_instruction_tokens(inst, address, BINBUN_TEXT_DEFAULT, tokens_text,
                                                              sizeof tokens_text, tokens, BINBUN_AARCH64_MAX_TOKENS);
    check_tokens(text, text_length, BINBUN_AARCH64_MAX_TEXT, BINBUN_AARCH64_MAX_TOKENS, tokens, size, tokens_text,
                 count, 1);
}

static void dump_a64(uint64_t address, const uint8_t *bytes, size_t length) {
    binbun_aarch64_decoder decoder;
    REQUIRE(binbun_aarch64_decoder_init(&decoder, bytes, length, address) == BINBUN_STATUS_OK);
    binbun_aarch64_instruction inst;
    uint64_t at = 0;
    binbun_status status;
    while ((status = binbun_aarch64_decoder_next(&decoder, &inst, &at)) != BINBUN_STATUS_END) {
        if (status == BINBUN_STATUS_OK) {
            print_a64(&inst, at);
        } else {
            REQUIRE(BINBUN_STATUS_IS_INVALID(status) || status == BINBUN_STATUS_TRUNCATED);
            printf("@%" PRIx64 " %s\n", at, status_symbol(status));
        }
    }
}

/* ------------------------------------------------------- either architecture */

/* ` <label>` and the `count` registers in `registers` by name (` -` for
 * none), each checked against what its kind says. */
static void print_registers(const char *label, const binbun_register *registers, size_t count) {
    REQUIRE(count <= BINBUN_MAX_REGISTERS);
    printf(" %s", label);
    if (count == 0) printf(" -");
    for (size_t i = 0; i < count; i++) {
        const binbun_register *reg = &registers[i];
        char name[BINBUN_MAX_REGISTER_NAME + 1];
        size_t length = binbun_register_name(reg, name, sizeof name);
        REQUIRE(length > 0 && length <= BINBUN_MAX_REGISTER_NAME);
        switch (reg->kind) {
        case BINBUN_REGISTER_X86:
            REQUIRE(str_is(binbun_x86_register_name(reg->value), name));
            REQUIRE(reg->class_ == 0 && reg->number == 0 && !reg->has_tile && !reg->has_name);
            break;
        case BINBUN_REGISTER_AARCH64:
            REQUIRE(reg->class_ >= BINBUN_AARCH64_REG_W && reg->class_ <= BINBUN_AARCH64_REG_FFR);
            REQUIRE(reg->value == 0 && !reg->has_tile && !reg->has_name);
            break;
        case BINBUN_REGISTER_AARCH64_ZA:
            REQUIRE(reg->class_ == 0 && reg->value == 0 && !reg->has_name);
            REQUIRE(reg->has_tile || (reg->number == 0 && reg->element == 0));
            break;
        case BINBUN_REGISTER_AARCH64_SYSTEM:
            REQUIRE(reg->has_name ? str_is(reg->name, name) : reg->name.length == 0);
            break;
        default: fail("register kind %u", reg->kind);
        }
        printf(" %s", name);
    }
}

/* One instruction through the decoder for either architecture, checked
 * against its native instruction. */
static void print_any(const binbun_instruction *inst, uint64_t at) {
    REQUIRE(binbun_instruction_address(inst) == at);
    uint8_t length = binbun_instruction_length(inst);
    const uint8_t *bytes = binbun_instruction_bytes(inst);
    REQUIRE(length >= 1 && length <= BINBUN_MAX_LENGTH && bytes != NULL);
    printf("@%" PRIx64 " ", at);
    for (uint8_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    binbun_str mnemonic = binbun_instruction_mnemonic(inst);
    char text[BINBUN_MAX_TEXT + 1], native[BINBUN_MAX_TEXT + 1];
    size_t text_length = binbun_instruction_text(inst, BINBUN_TEXT_DEFAULT, text, sizeof text);
    REQUIRE(text_length > 0 && text_length <= BINBUN_MAX_TEXT);
    printf(" mnem=%.*s text=%s", (int)mnemonic.length, mnemonic.data, text);
    const binbun_x86_instruction *x86 = binbun_instruction_as_x86(inst);
    const binbun_aarch64_instruction *a64 = binbun_instruction_as_aarch64(inst);
    if (binbun_instruction_arch(inst) == BINBUN_ARCH_X86) {
        REQUIRE(x86 != NULL && a64 == NULL && binbun_instruction_mode(inst) != 0);
        REQUIRE(binbun_x86_instruction_length(x86) == length);
        REQUIRE(binbun_x86_instruction_text(x86, at, BINBUN_TEXT_DEFAULT, native, sizeof native) == text_length);
    } else {
        REQUIRE(binbun_instruction_arch(inst) == BINBUN_ARCH_AARCH64);
        REQUIRE(a64 != NULL && x86 == NULL && binbun_instruction_mode(inst) == 0);
        REQUIRE(binbun_aarch64_instruction_length(a64) == length);
        REQUIRE(str_equal(binbun_aarch64_instruction_mnemonic(a64), mnemonic));
        REQUIRE(binbun_aarch64_instruction_text(a64, at, BINBUN_TEXT_DEFAULT, native, sizeof native) == text_length);
    }
    REQUIRE(strcmp(text, native) == 0);
    binbun_register registers[BINBUN_MAX_REGISTERS];
    print_registers("reads", registers, binbun_instruction_registers_read(inst, registers, BINBUN_MAX_REGISTERS));
    print_registers("; writes", registers,
                    binbun_instruction_registers_written(inst, registers, BINBUN_MAX_REGISTERS));
    print_branch(binbun_instruction_branch(inst));
}

static void dump_any(binbun_arch arch, binbun_x86_mode mode, uint64_t address, const uint8_t *bytes,
                     size_t length) {
    binbun_decoder decoder;
    REQUIRE(binbun_decoder_init(&decoder, arch, mode, bytes, length, address) == BINBUN_STATUS_OK);
    binbun_instruction inst;
    uint64_t at = 0;
    binbun_status status;
    while ((status = binbun_decoder_next(&decoder, &inst, &at)) != BINBUN_STATUS_END) {
        if (status == BINBUN_STATUS_OK) {
            print_any(&inst, at);
        } else {
            REQUIRE(BINBUN_STATUS_IS_INVALID(status) || status == BINBUN_STATUS_TRUNCATED);
            printf("@%" PRIx64 " %s\n", at, status_symbol(status));
        }
    }
}

/* -------------------------------------------------------------------- check */

static void check_x86(void) {
    /* lock add dword ptr [rax+rbx*4-0x10], 0x5 */
    static const uint8_t add[] = {0xf0, 0x83, 0x44, 0x98, 0xf0, 0x05};
    static const char add_text[] = "lock add dword ptr [rax+rbx*4-0x10], 0x5";
    binbun_x86_instruction inst, untouched;
    memset(&untouched, 0xa5, sizeof untouched);

    /* Storage: the library writes no more than the header's struct holds. */
    REQUIRE(binbun_x86_instruction_size() <= sizeof(binbun_x86_instruction));

    /* Every shorter buffer is truncated, and `out` is left alone. */
    for (size_t n = 0; n < sizeof add; n++) {
        inst = untouched;
        REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, add, n, &inst) == BINBUN_STATUS_TRUNCATED);
        REQUIRE(memcmp(&inst, &untouched, sizeof inst) == 0);
        size_t length = 99;
        REQUIRE(binbun_x86_decode_length(BINBUN_X86_MODE_BITS64, add, n, &length) == BINBUN_STATUS_TRUNCATED);
        REQUIRE(length == 99);
    }
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, add, sizeof add, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_x86_instruction_mnemonic(&inst) == BINBUN_X86_MNEMONIC_ADD_LOCK);
    REQUIRE(str_is(binbun_x86_mnemonic_name(BINBUN_X86_MNEMONIC_ADD_LOCK), "ADD_LOCK"));
    REQUIRE(str_is(binbun_x86_register_name(BINBUN_X86_REG_RAX), "rax"));
    REQUIRE(binbun_x86_register_from_name("rbx", 3) == BINBUN_X86_REG_RBX);
    binbun_x86_register_info info;
    REQUIRE(binbun_x86_register_describe(BINBUN_X86_REG_AH, &info));
    REQUIRE(info.class_ == BINBUN_X86_REGISTER_CLASS_GPR && info.full == BINBUN_X86_REG_RAX && info.offset == 8 &&
            info.width == 8);
    REQUIRE(!binbun_x86_register_describe(BINBUN_X86_REG_NONE, &info));
    REQUIRE(!binbun_x86_register_describe(BINBUN_X86_REG_COUNT + 1, &info));

    /* Copies of the storage are instructions too. */
    binbun_x86_instruction copy = inst;

    /* Text: the whole length whatever the capacity, NUL-terminated where
     * there is room. */
    char text[64];
    size_t length = strlen(add_text);
    REQUIRE(binbun_x86_instruction_text(&copy, 0, BINBUN_TEXT_DEFAULT, NULL, 0) == length);
    memset(text, 'x', sizeof text);
    REQUIRE(binbun_x86_instruction_text(&copy, 0, BINBUN_TEXT_DEFAULT, text, 0) == length && text[0] == 'x');
    REQUIRE(binbun_x86_instruction_text(&copy, 0, BINBUN_TEXT_DEFAULT, text, 1) == length && text[0] == '\0');
    REQUIRE(binbun_x86_instruction_text(&copy, 0, BINBUN_TEXT_DEFAULT, text, 9) == length);
    REQUIRE(strcmp(text, "lock add") == 0);
    REQUIRE(binbun_x86_instruction_text(&copy, 0, BINBUN_TEXT_DEFAULT, text, length) == length);
    REQUIRE(strlen(text) == length - 1);
    REQUIRE(binbun_x86_instruction_text(&copy, 0, BINBUN_TEXT_DEFAULT, text, length + 1) == length);
    REQUIRE(strcmp(text, add_text) == 0);
    REQUIRE(binbun_x86_instruction_text(&copy, 0, BINBUN_TEXT_RELATIVE_LABELS, text, sizeof text) == 0);

    /* Tokens: all counted, those that fit written. */
    binbun_token tokens[4];
    binbun_text_size size = binbun_x86_instruction_tokens(&copy, 0, BINBUN_TEXT_DEFAULT, text, 5, tokens, 4);
    REQUIRE(size.length == length && size.tokens > 4 && strcmp(text, "lock") == 0);
    REQUIRE(tokens[0].kind == BINBUN_TOKEN_PREFIX && tokens[0].offset == 0 && tokens[0].length == 4);
    REQUIRE(tokens[2].kind == BINBUN_TOKEN_MNEMONIC && tokens[2].offset == 5 && tokens[2].length == 3);
    size = binbun_x86_instruction_tokens(&copy, 0, BINBUN_TEXT_DEFAULT, NULL, 0, NULL, 0);
    REQUIRE(size.length == length && size.tokens > 4);

    /* Operands: all counted, those that fit written. */
    binbun_x86_operand operand;
    size_t operands = binbun_x86_instruction_operands(&copy, &operand, 1);
    REQUIRE(operands >= 2 && operand.kind == BINBUN_X86_OPERAND_MEMORY && operand.base == BINBUN_X86_REG_RAX &&
            operand.index == BINBUN_X86_REG_RBX && operand.scale == 4 && operand.displacement == -16 &&
            operand.memory_size == 4 && operand.access == (BINBUN_ACCESS_READ | BINBUN_ACCESS_WRITE));
    REQUIRE(binbun_x86_instruction_operands(&copy, NULL, 0) == operands);

    /* Control flow at an address: call rel32 and jmp [rip+0x10]. */
    static const uint8_t call[] = {0xe8, 0x10, 0x00, 0x00, 0x00};
    static const uint8_t jump[] = {0xff, 0x25, 0x10, 0x00, 0x00, 0x00};
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, call, sizeof call, &inst) == BINBUN_STATUS_OK);
    binbun_branch branch = binbun_x86_instruction_branch(&inst, 0x1000);
    REQUIRE(branch.kind == BINBUN_BRANCH_CALL && !branch.conditional && branch.falls_through &&
            branch.target_kind == BINBUN_TARGET_ADDRESS && branch.target == 0x1015);
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, jump, sizeof jump, &inst) == BINBUN_STATUS_OK);
    branch = binbun_x86_instruction_branch(&inst, 0x1000);
    REQUIRE(branch.kind == BINBUN_BRANCH_JUMP && !branch.falls_through && branch.target_kind == BINBUN_TARGET_POINTER &&
            branch.target == 0x1016 && branch.pointer_size == 8);

    /* Invalid bytes: why, by status. */
    static const uint8_t push_es[] = {0x06};
    static const uint8_t lock_nop[] = {0xf0, 0x90};
    static const uint8_t too_long[] = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                       0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90};
    REQUIRE(BINBUN_STATUS_IS_INVALID(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, push_es, 1, &inst)));
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS32, push_es, 1, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, lock_nop, 2, &inst) == BINBUN_STATUS_X86_BAD_LOCK_PREFIX);
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, too_long, sizeof too_long, &inst) ==
            BINBUN_STATUS_X86_TOO_LONG);
    REQUIRE(binbun_status_name(BINBUN_STATUS_X86_BAD_LOCK_PREFIX).length > 0);
    REQUIRE(binbun_status_name(1000).length == 0);

    /* Null pointers and bad arguments. */
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, add, sizeof add, NULL) == BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, NULL, 4, &inst) == BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, NULL, 0, &inst) == BINBUN_STATUS_TRUNCATED);
    REQUIRE(binbun_x86_decode_bytes(0, add, sizeof add, &inst) == BINBUN_STATUS_BAD_ARGUMENT);
    REQUIRE(binbun_x86_decode_bytes(99, add, sizeof add, &inst) == BINBUN_STATUS_BAD_ARGUMENT);
    REQUIRE(binbun_x86_decode_length(BINBUN_X86_MODE_BITS64, add, sizeof add, NULL) == BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_x86_instruction_length(NULL) == 0);
    REQUIRE(binbun_x86_instruction_mnemonic(NULL) == BINBUN_X86_MNEMONIC_NONE);
    REQUIRE(binbun_x86_instruction_text(NULL, 0, BINBUN_TEXT_DEFAULT, text, sizeof text) == 0);
    size = binbun_x86_instruction_tokens(NULL, 0, BINBUN_TEXT_DEFAULT, text, sizeof text, tokens, 4);
    REQUIRE(size.length == 0 && size.tokens == 0);
    REQUIRE(binbun_x86_instruction_operands(NULL, &operand, 1) == 0);
    REQUIRE(binbun_x86_instruction_branch(NULL, 0).kind == BINBUN_BRANCH_NONE);
    REQUIRE(!binbun_x86_instruction_computed_address(NULL, 0, NULL));
    REQUIRE(binbun_x86_mnemonic_from_name(NULL, 3) == BINBUN_X86_MNEMONIC_NONE);
    REQUIRE(binbun_x86_mnemonic_name(BINBUN_X86_MNEMONIC_COUNT + 1).length == 0);

    /* Zeroed storage, and storage holding an AArch64 instruction, hold no
     * x86 instruction. */
    binbun_x86_instruction zeroed;
    memset(&zeroed, 0, sizeof zeroed);
    REQUIRE(binbun_x86_instruction_length(&zeroed) == 0);
    REQUIRE(binbun_x86_instruction_text(&zeroed, 0, BINBUN_TEXT_DEFAULT, text, sizeof text) == 0);
    binbun_x86_instruction other;
    memset(&other, 0, sizeof other);
    REQUIRE(binbun_aarch64_decode_word(0xd65f03c0, (binbun_aarch64_instruction *)&other) == BINBUN_STATUS_OK);
    REQUIRE(binbun_x86_instruction_length(&other) == 0);

    /* The decoder: addresses, a byte on after invalid bytes, then END. */
    static const uint8_t sweep[] = {0x06, 0xc3, 0x48};
    binbun_x86_decoder decoder;
    REQUIRE(binbun_x86_decoder_init(NULL, BINBUN_X86_MODE_BITS64, sweep, 3, 0) == BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_x86_decoder_init(&decoder, 7, sweep, 3, 0) == BINBUN_STATUS_BAD_ARGUMENT);
    REQUIRE(binbun_x86_decoder_init(&decoder, BINBUN_X86_MODE_BITS64, sweep, sizeof sweep, 0x400) == BINBUN_STATUS_OK);
    uint64_t at = 0;
    REQUIRE(BINBUN_STATUS_IS_INVALID(binbun_x86_decoder_next(&decoder, &inst, &at)) && at == 0x400);
    REQUIRE(binbun_x86_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_OK && at == 0x401);
    REQUIRE(binbun_x86_instruction_branch(&inst, at).kind == BINBUN_BRANCH_RETURN);
    REQUIRE(binbun_x86_decoder_next(&decoder, &inst, NULL) == BINBUN_STATUS_TRUNCATED);
    REQUIRE(binbun_x86_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_END);
    REQUIRE(binbun_x86_decoder_next(NULL, &inst, &at) == BINBUN_STATUS_NULL_POINTER);
    decoder.offset = 1;
    REQUIRE(binbun_x86_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_OK && at == 0x401);
}

static void check_aarch64(void) {
    /* ldr x0, [x1, #0x8] */
    static const uint8_t ldr[] = {0x20, 0x04, 0x40, 0xf9};
    binbun_aarch64_instruction inst, untouched;
    memset(&untouched, 0x5a, sizeof untouched);
    REQUIRE(binbun_aarch64_instruction_size() <= sizeof(binbun_aarch64_instruction));
    for (size_t n = 0; n < sizeof ldr; n++) {
        inst = untouched;
        REQUIRE(binbun_aarch64_decode_bytes(ldr, n, &inst) == BINBUN_STATUS_TRUNCATED);
        REQUIRE(memcmp(&inst, &untouched, sizeof inst) == 0);
    }
    REQUIRE(binbun_aarch64_decode_bytes(ldr, sizeof ldr, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_aarch64_instruction_encoding(&inst) == BINBUN_AARCH64_ENC_LDR_64_ldst_pos);
    REQUIRE(str_is(binbun_aarch64_instruction_mnemonic(&inst), "ldr"));
    char text[32];
    REQUIRE(binbun_aarch64_instruction_text(&inst, 0, BINBUN_TEXT_DEFAULT, text, sizeof text) == 18);
    REQUIRE(strcmp(text, "ldr\tx0, [x1, #0x8]") == 0);
    REQUIRE(binbun_aarch64_instruction_text(&inst, 0, 0x80, text, sizeof text) == 0);
    binbun_aarch64_memory_access memory;
    REQUIRE(binbun_aarch64_instruction_memory(&inst, &memory));
    REQUIRE(memory.kind == BINBUN_AARCH64_MEMORY_LOAD && memory.size == 8);

    /* b 0x1040, and as an offset. */
    REQUIRE(binbun_aarch64_decode_word(0x14000010, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_aarch64_instruction_text(&inst, 0x1000, BINBUN_TEXT_DEFAULT, text, sizeof text) == 8);
    REQUIRE(strcmp(text, "b\t0x1040") == 0);
    REQUIRE(binbun_aarch64_instruction_text(&inst, 0x1000, BINBUN_TEXT_RELATIVE_LABELS, text, sizeof text) == 7);
    REQUIRE(strcmp(text, "b\t#0x40") == 0);
    binbun_branch branch = binbun_aarch64_instruction_branch(&inst, 0x1000);
    REQUIRE(branch.kind == BINBUN_BRANCH_JUMP && !branch.conditional && branch.target == 0x1040);

    /* cbz x1, +8: a conditional jump testing a register. */
    REQUIRE(binbun_aarch64_decode_word(0xb4000041, &inst) == BINBUN_STATUS_OK);
    branch = binbun_aarch64_instruction_branch(&inst, 0x1000);
    REQUIRE(branch.kind == BINBUN_BRANCH_JUMP && branch.conditional && branch.falls_through && branch.target == 0x1008);
    binbun_aarch64_condition condition;
    REQUIRE(binbun_aarch64_instruction_condition(&inst, &condition));
    REQUIRE(condition.kind == BINBUN_AARCH64_CONDITION_ZERO && condition.sense &&
            condition.reg.class_ == BINBUN_AARCH64_REG_X && condition.reg.number == 1);

    /* bl: x30 written implicitly. */
    REQUIRE(binbun_aarch64_decode_word(0x94000000, &inst) == BINBUN_STATUS_OK);
    binbun_aarch64_register written[2];
    REQUIRE(binbun_aarch64_instruction_implicit_writes(&inst, written, 2) == 1);
    REQUIRE(written[0].class_ == BINBUN_AARCH64_REG_X && written[0].number == 30);

    /* Invalid words. */
    REQUIRE(binbun_aarch64_decode_word(0x00000000, &inst) == BINBUN_STATUS_OK); /* udf #0 */
    REQUIRE(BINBUN_STATUS_IS_INVALID(binbun_aarch64_decode_word(0xffffffff, &inst)));
    REQUIRE(binbun_aarch64_decode_word(0x0bc20020, &inst) == BINBUN_STATUS_AARCH64_UNDEFINED);

    /* Null pointers. */
    REQUIRE(binbun_aarch64_decode_word(0xd65f03c0, NULL) == BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_aarch64_decode_bytes(NULL, 4, &inst) == BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_aarch64_instruction_word(NULL) == 0);
    REQUIRE(binbun_aarch64_instruction_mnemonic(NULL).length == 0);
    REQUIRE(!binbun_aarch64_instruction_condition(NULL, &condition));
    REQUIRE(binbun_aarch64_instruction_operands(NULL, NULL, 0) == 0);
    REQUIRE(binbun_aarch64_encoding_name(BINBUN_AARCH64_ENC_COUNT + 1).length == 0);

    /* Storage holding an x86 instruction holds no AArch64 one. */
    binbun_x86_instruction x86;
    static const uint8_t ret[] = {0xc3};
    REQUIRE(binbun_x86_decode_bytes(BINBUN_X86_MODE_BITS64, ret, 1, &x86) == BINBUN_STATUS_OK);
    REQUIRE(binbun_aarch64_instruction_word((const binbun_aarch64_instruction *)&x86) == 0);

    /* The decoder: a short last piece is truncated. */
    static const uint8_t sweep[] = {0xc0, 0x03, 0x5f, 0xd6, 0xff, 0xff, 0xff, 0xff, 0x1f};
    binbun_aarch64_decoder decoder;
    REQUIRE(binbun_aarch64_decoder_init(&decoder, sweep, sizeof sweep, 0x2000) == BINBUN_STATUS_OK);
    uint64_t at = 0;
    REQUIRE(binbun_aarch64_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_OK && at == 0x2000);
    REQUIRE(BINBUN_STATUS_IS_INVALID(binbun_aarch64_decoder_next(&decoder, &inst, &at)) && at == 0x2004);
    REQUIRE(binbun_aarch64_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_TRUNCATED && at == 0x2008);
    REQUIRE(binbun_aarch64_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_END);
}

/* The name binbun_register_name writes for `reg`, in `name`. */
static const char *register_name(binbun_register reg, char (*name)[BINBUN_MAX_REGISTER_NAME + 1]) {
    size_t length = binbun_register_name(&reg, *name, sizeof *name);
    REQUIRE(length <= BINBUN_MAX_REGISTER_NAME);
    return *name;
}

/* Arguments refused, storage that holds no instruction, sweeps. */
static void check_any_contract(void) {
    static const uint8_t push[] = {0x55};
    binbun_instruction inst, untouched;
    memset(&untouched, 0xa5, sizeof untouched);
    REQUIRE(binbun_instruction_size() <= sizeof(binbun_instruction));

    /* `out` is left alone when the decode fails. */
    inst = untouched;
    REQUIRE(binbun_decode(BINBUN_ARCH_X86, 0, push, 1, 0, &inst) == BINBUN_STATUS_BAD_ARGUMENT);
    REQUIRE(binbun_decode(BINBUN_ARCH_AARCH64, BINBUN_X86_MODE_BITS64, push, 1, 0, &inst) ==
            BINBUN_STATUS_BAD_ARGUMENT);
    REQUIRE(binbun_decode(0, 0, push, 1, 0, &inst) == BINBUN_STATUS_BAD_ARGUMENT);
    REQUIRE(binbun_decode(3, 0, push, 1, 0, &inst) == BINBUN_STATUS_BAD_ARGUMENT);
    REQUIRE(binbun_decode(BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64, NULL, 1, 0, &inst) == BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_decode(BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64, push, 1, 0, NULL) == BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_decode(BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64, push, 0, 0, &inst) == BINBUN_STATUS_TRUNCATED);
    REQUIRE(binbun_decode(BINBUN_ARCH_AARCH64, 0, push, 1, 0, &inst) == BINBUN_STATUS_TRUNCATED);
    REQUIRE(memcmp(&inst, &untouched, sizeof inst) == 0);

    /* Zeroed storage holds no instruction. */
    memset(&inst, 0, sizeof inst);
    char text[BINBUN_MAX_TEXT + 1];
    binbun_register registers[BINBUN_MAX_REGISTERS];
    REQUIRE(binbun_instruction_arch(&inst) == 0 && binbun_instruction_mode(&inst) == 0);
    REQUIRE(binbun_instruction_length(&inst) == 0 && binbun_instruction_bytes(&inst) == NULL);
    REQUIRE(binbun_instruction_mnemonic(&inst).length == 0);
    REQUIRE(binbun_instruction_text(&inst, BINBUN_TEXT_DEFAULT, text, sizeof text) == 0);
    REQUIRE(binbun_instruction_registers_read(&inst, registers, BINBUN_MAX_REGISTERS) == 0);
    REQUIRE(binbun_instruction_branch(&inst).kind == BINBUN_BRANCH_NONE);
    REQUIRE(binbun_instruction_as_x86(&inst) == NULL && binbun_instruction_as_aarch64(&inst) == NULL);
    REQUIRE(binbun_instruction_arch(NULL) == 0 && binbun_instruction_as_x86(NULL) == NULL);

    /* Sweeps: one byte on after bytes that are no x86 instruction, four on
     * AArch64, where a short last piece is truncated. */
    static const uint8_t x86[] = {0x06, 0xc3};
    static const uint8_t a64[] = {0xc0, 0x03, 0x5f, 0xd6, 0x00, 0x00};
    binbun_decoder decoder;
    uint64_t at = 0;
    REQUIRE(binbun_decoder_init(NULL, BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64, x86, 2, 0) ==
            BINBUN_STATUS_NULL_POINTER);
    REQUIRE(binbun_decoder_init(&decoder, BINBUN_ARCH_AARCH64, BINBUN_X86_MODE_BITS64, a64, 6, 0) ==
            BINBUN_STATUS_BAD_ARGUMENT);
    REQUIRE(binbun_decoder_init(&decoder, BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64, x86, 2, 0x1000) ==
            BINBUN_STATUS_OK);
    REQUIRE(BINBUN_STATUS_IS_INVALID(binbun_decoder_next(&decoder, &inst, &at)) && at == 0x1000);
    REQUIRE(binbun_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_OK && at == 0x1001);
    REQUIRE(str_is(binbun_instruction_mnemonic(&inst), "ret") && binbun_instruction_address(&inst) == 0x1001);
    REQUIRE(binbun_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_END);
    REQUIRE(binbun_decoder_init(&decoder, BINBUN_ARCH_AARCH64, 0, a64, 6, 0x2000) == BINBUN_STATUS_OK);
    REQUIRE(binbun_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_OK && at == 0x2000);
    REQUIRE(binbun_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_TRUNCATED && at == 0x2004);
    REQUIRE(binbun_decoder_next(&decoder, &inst, &at) == BINBUN_STATUS_END);
}

static void check_any_x86(void) {
    static const uint8_t push[] = {0x55};
    binbun_instruction inst;
    char text[BINBUN_MAX_TEXT + 1], name[BINBUN_MAX_REGISTER_NAME + 1];
    binbun_register registers[BINBUN_MAX_REGISTERS];

    REQUIRE(binbun_decode(BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64, push, 1, 0x1000, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_instruction_arch(&inst) == BINBUN_ARCH_X86);
    REQUIRE(binbun_instruction_mode(&inst) == BINBUN_X86_MODE_BITS64);
    REQUIRE(binbun_instruction_address(&inst) == 0x1000 && binbun_instruction_length(&inst) == 1);
    REQUIRE(binbun_instruction_bytes(&inst)[0] == 0x55);
    REQUIRE(str_is(binbun_instruction_mnemonic(&inst), "push"));
    REQUIRE(binbun_instruction_text(&inst, BINBUN_TEXT_DEFAULT, text, sizeof text) == 8);
    REQUIRE(strcmp(text, "push rbp") == 0);
    REQUIRE(binbun_instruction_text(&inst, BINBUN_TEXT_DEFAULT, text, 4) == 8 && strcmp(text, "pus") == 0);
    /* x86 text has no options. */
    REQUIRE(binbun_instruction_text(&inst, BINBUN_TEXT_RELATIVE_LABELS, text, sizeof text) == 0);

    /* push rbp reads rbp first and writes rsp alone. */
    size_t reads = binbun_instruction_registers_read(&inst, registers, BINBUN_MAX_REGISTERS);
    REQUIRE(reads >= 2 && registers[0].kind == BINBUN_REGISTER_X86 && registers[0].value == BINBUN_X86_REG_RBP);
    REQUIRE(binbun_instruction_registers_written(&inst, registers, BINBUN_MAX_REGISTERS) == 1);
    REQUIRE(registers[0].value == BINBUN_X86_REG_RSP);
    REQUIRE(binbun_register_name(&registers[0], name, sizeof name) == 3 && strcmp(name, "rsp") == 0);
    REQUIRE(binbun_register_name(&registers[0], name, 2) == 3 && strcmp(name, "r") == 0);
    REQUIRE(binbun_register_name(NULL, name, sizeof name) == 0);
    /* A short array: as many as fit, and how many there are. */
    registers[1].kind = 0xee;
    REQUIRE(binbun_instruction_registers_read(&inst, registers, 1) == reads && registers[1].kind == 0xee);
    REQUIRE(binbun_instruction_branch(&inst).kind == BINBUN_BRANCH_NONE);

    /* The native instruction, in the same storage, and only through it: the
     * x86 functions refuse the storage itself. */
    const binbun_x86_instruction *native = binbun_instruction_as_x86(&inst);
    REQUIRE(native != NULL && binbun_instruction_as_aarch64(&inst) == NULL);
    REQUIRE((const void *)native > (const void *)&inst && (const void *)(native + 1) <= (const void *)(&inst + 1));
    REQUIRE(binbun_x86_instruction_mnemonic(native) == BINBUN_X86_MNEMONIC_PUSH);
    REQUIRE(binbun_x86_instruction_length((const binbun_x86_instruction *)(const void *)&inst) == 0);
    /* A copy is the same instruction. */
    binbun_instruction copy = inst;
    REQUIRE(str_is(binbun_instruction_mnemonic(&copy), "push"));
    REQUIRE(binbun_x86_instruction_mnemonic(binbun_instruction_as_x86(&copy)) == BINBUN_X86_MNEMONIC_PUSH);

    /* call in 32-bit mode, at 0x400000; push bp in 16-bit mode. */
    static const uint8_t call[] = {0xe8, 0x00, 0x00, 0x00, 0x00};
    REQUIRE(binbun_decode(BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS32, call, sizeof call, 0x400000, &inst) ==
            BINBUN_STATUS_OK);
    binbun_branch branch = binbun_instruction_branch(&inst);
    REQUIRE(branch.kind == BINBUN_BRANCH_CALL && branch.target_kind == BINBUN_TARGET_ADDRESS);
    REQUIRE(branch.target == 0x400005 && branch.falls_through);
    REQUIRE(binbun_decode(BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS16, push, 1, 0, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_instruction_mode(&inst) == BINBUN_X86_MODE_BITS16);
    REQUIRE(binbun_instruction_text(&inst, BINBUN_TEXT_DEFAULT, text, sizeof text) == 7);
    REQUIRE(strcmp(text, "push bp") == 0);
}

static void check_any_aarch64(void) {
    /* stp x29, x30, [sp, #-0x10]! */
    static const uint8_t stp[] = {0xfd, 0x7b, 0xbf, 0xa9};
    binbun_instruction inst;
    char text[BINBUN_MAX_TEXT + 1], native[BINBUN_MAX_TEXT + 1], name[BINBUN_MAX_REGISTER_NAME + 1];
    binbun_register registers[BINBUN_MAX_REGISTERS];

    REQUIRE(binbun_decode(BINBUN_ARCH_AARCH64, 0, stp, sizeof stp, 0x2000, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_instruction_arch(&inst) == BINBUN_ARCH_AARCH64 && binbun_instruction_mode(&inst) == 0);
    REQUIRE(binbun_instruction_length(&inst) == 4 && memcmp(binbun_instruction_bytes(&inst), stp, 4) == 0);
    REQUIRE(str_is(binbun_instruction_mnemonic(&inst), "stp"));
    REQUIRE(binbun_instruction_text(&inst, BINBUN_TEXT_DEFAULT, text, sizeof text) == 27);
    REQUIRE(strcmp(text, "stp\tx29, x30, [sp, #-0x10]!") == 0);
    REQUIRE(binbun_instruction_registers_read(&inst, registers, BINBUN_MAX_REGISTERS) == 3);
    REQUIRE(registers[0].kind == BINBUN_REGISTER_AARCH64 && registers[0].class_ == BINBUN_AARCH64_REG_X);
    REQUIRE(registers[0].number == 29 && strcmp(register_name(registers[0], &name), "x29") == 0);
    REQUIRE(registers[2].class_ == BINBUN_AARCH64_REG_XSP && registers[2].number == 31);
    REQUIRE(strcmp(register_name(registers[2], &name), "sp") == 0);
    REQUIRE(binbun_instruction_registers_written(&inst, registers, BINBUN_MAX_REGISTERS) == 1);
    REQUIRE(strcmp(register_name(registers[0], &name), "sp") == 0);
    REQUIRE(binbun_instruction_as_aarch64(&inst) != NULL && binbun_instruction_as_x86(&inst) == NULL);
    REQUIRE(binbun_aarch64_instruction_word(binbun_instruction_as_aarch64(&inst)) == 0xa9bf7bfd);

    /* b 0x2040, and as an offset, as the native text writes it. */
    static const uint8_t b[] = {0x10, 0x00, 0x00, 0x14};
    REQUIRE(binbun_decode(BINBUN_ARCH_AARCH64, 0, b, sizeof b, 0x2000, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_instruction_text(&inst, BINBUN_TEXT_DEFAULT, text, sizeof text) == 8);
    REQUIRE(strcmp(text, "b\t0x2040") == 0);
    size_t relative = binbun_instruction_text(&inst, BINBUN_TEXT_RELATIVE_LABELS, text, sizeof text);
    REQUIRE(relative > 0 && relative == binbun_aarch64_instruction_text(binbun_instruction_as_aarch64(&inst), 0x2000,
                                                                       BINBUN_TEXT_RELATIVE_LABELS, native,
                                                                       sizeof native));
    REQUIRE(strcmp(text, native) == 0 && strcmp(text, "b\t0x2040") != 0);
    REQUIRE(binbun_instruction_text(&inst, 0x80, text, sizeof text) == 0);
    binbun_branch branch = binbun_instruction_branch(&inst);
    REQUIRE(branch.kind == BINBUN_BRANCH_JUMP && branch.target == 0x2040 && !branch.falls_through);

    /* mrs x0, tpidr_el0: the system register by encoding and name. */
    static const uint8_t mrs[] = {0x40, 0xd0, 0x3b, 0xd5};
    REQUIRE(binbun_decode(BINBUN_ARCH_AARCH64, 0, mrs, sizeof mrs, 0, &inst) == BINBUN_STATUS_OK);
    REQUIRE(binbun_instruction_registers_read(&inst, registers, BINBUN_MAX_REGISTERS) == 1);
    binbun_register system = registers[0];
    REQUIRE(system.kind == BINBUN_REGISTER_AARCH64_SYSTEM && system.has_name && system.value == 0xde82);
    REQUIRE(str_is(system.name, "TPIDR_EL0") && strcmp(register_name(system, &name), "TPIDR_EL0") == 0);
    REQUIRE(binbun_instruction_registers_written(&inst, registers, BINBUN_MAX_REGISTERS) == 1);
    REQUIRE(strcmp(register_name(registers[0], &name), "x0") == 0);

    /* Names from the fields alone: a system register without its name, ZA,
     * and fields that name no register. */
    binbun_register reg;
    memset(&reg, 0, sizeof reg);
    reg.kind = BINBUN_REGISTER_AARCH64_SYSTEM;
    reg.value = 0xde82;
    REQUIRE(strcmp(register_name(reg, &name), "S3_3_C13_C0_2") == 0);
    memset(&reg, 0, sizeof reg);
    reg.kind = BINBUN_REGISTER_AARCH64_ZA;
    REQUIRE(strcmp(register_name(reg, &name), "za") == 0);
    reg.has_tile = true;
    reg.number = 1;
    reg.element = BINBUN_AARCH64_ELEMENT_D;
    REQUIRE(strcmp(register_name(reg, &name), "za1.d") == 0);
    reg.element = 9;
    REQUIRE(binbun_register_name(&reg, name, sizeof name) == 0);
    memset(&reg, 0, sizeof reg);
    reg.kind = BINBUN_REGISTER_AARCH64;
    reg.class_ = 99;
    REQUIRE(binbun_register_name(&reg, name, sizeof name) == 0);
    reg.kind = 0;
    REQUIRE(binbun_register_name(&reg, name, sizeof name) == 0);
}

static uint8_t *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) fail("cannot open %s", path);
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *bytes = malloc(size > 0 ? (size_t)size : 1);
    REQUIRE(bytes != NULL);
    if (fread(bytes, 1, (size_t)size, file) != (size_t)size) fail("cannot read %s", path);
    fclose(file);
    *length = (size_t)size;
    return bytes;
}

/* The longest text and the most tokens of the words `first` to `last`, at
 * an address whose labels have the most digits: `<length> <word> <tokens>
 * <word>`. */
static void bounds_aarch64(uint32_t first, uint32_t last) {
    const uint64_t address = 0x8000000000000000u;
    size_t most_text = 0, most_tokens = 0;
    uint32_t text_word = 0, tokens_word = 0;
    char text[BINBUN_AARCH64_MAX_TEXT + 1];
    binbun_token tokens[BINBUN_AARCH64_MAX_TOKENS];
    binbun_aarch64_instruction inst;
    for (uint64_t word = first; word <= last; word++) {
        if (binbun_aarch64_decode_word((uint32_t)word, &inst) != BINBUN_STATUS_OK) continue;
        binbun_text_size size = binbun_aarch64_instruction_tokens(&inst, address, BINBUN_TEXT_DEFAULT, text,
                                                                  sizeof text, tokens, BINBUN_AARCH64_MAX_TOKENS);
        REQUIRE(size.length > 0);
        if (size.length > most_text) {
            most_text = size.length;
            text_word = (uint32_t)word;
        }
        if (size.tokens > most_tokens) {
            most_tokens = size.tokens;
            tokens_word = (uint32_t)word;
        }
    }
    printf("%zu %08x %zu %08x\n", most_text, text_word, most_tokens, tokens_word);
}

/* The longest text and the most tokens of the x86 code in `bytes`, decoded
 * at every offset (not only at instruction boundaries), at an address whose
 * targets have the most digits: `<length> <offset> <tokens> <offset>`. */
static void bounds_x86(binbun_x86_mode mode, const uint8_t *bytes, size_t length) {
    const uint64_t address = 0x8000000000000000u;
    size_t most_text = 0, most_tokens = 0, text_offset = 0, tokens_offset = 0;
    char text[BINBUN_X86_MAX_TEXT + 1];
    binbun_token tokens[BINBUN_X86_MAX_TOKENS];
    binbun_x86_instruction inst;
    for (size_t offset = 0; offset < length; offset++) {
        if (binbun_x86_decode_bytes(mode, bytes + offset, length - offset, &inst) != BINBUN_STATUS_OK) continue;
        binbun_text_size size = binbun_x86_instruction_tokens(&inst, address, BINBUN_TEXT_DEFAULT, text, sizeof text,
                                                              tokens, BINBUN_X86_MAX_TOKENS);
        REQUIRE(size.length > 0);
        if (size.length > most_text) {
            most_text = size.length;
            text_offset = offset;
        }
        if (size.tokens > most_tokens) {
            most_tokens = size.tokens;
            tokens_offset = offset;
        }
    }
    printf("%zu %zx %zu %zx\n", most_text, text_offset, most_tokens, tokens_offset);
}

int main(int argc, char **argv) {
    if (binbun_version() != BINBUN_VERSION) fail("library version differs from the header's");
    /* Another part's statuses (from 64) are not the disassemblers'. */
    if (BINBUN_STATUS_IS_INVALID(64) || !BINBUN_STATUS_IS_INVALID(63)) fail("BINBUN_STATUS_IS_INVALID's range");
    if (argc == 2 && strcmp(argv[1], "check") == 0) {
        check_x86();
        check_aarch64();
        check_any_contract();
        check_any_x86();
        check_any_aarch64();
        puts("ok");
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "bounds-aarch64") == 0) {
        bounds_aarch64((uint32_t)strtoul(argv[2], NULL, 16), (uint32_t)strtoul(argv[3], NULL, 16));
        return 0;
    }
    int any = argc == 5 && strcmp(argv[1], "any") == 0;
    if (argc != 5 || (!any && strcmp(argv[1], "dump") != 0)) {
        fail("usage: disasm_test check | <dump|any> <x86-64|x86-32|aarch64> <address> <file>");
    }
    uint64_t address = strtoull(argv[3], NULL, 16);
    size_t length = 0;
    uint8_t *bytes = read_file(argv[4], &length);
    if (any && strcmp(argv[2], "x86-64") == 0) {
        dump_any(BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64, address, bytes, length);
    } else if (any && strcmp(argv[2], "x86-32") == 0) {
        dump_any(BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS32, address, bytes, length);
    } else if (any && strcmp(argv[2], "aarch64") == 0) {
        dump_any(BINBUN_ARCH_AARCH64, 0, address, bytes, length);
    } else if (any) {
        fail("unknown architecture %s", argv[2]);
    } else if (strcmp(argv[2], "x86-64") == 0) {
        dump_x86(BINBUN_X86_MODE_BITS64, address, bytes, length);
    } else if (strcmp(argv[2], "x86-32") == 0) {
        dump_x86(BINBUN_X86_MODE_BITS32, address, bytes, length);
    } else if (strcmp(argv[2], "aarch64") == 0) {
        dump_a64(address, bytes, length);
    } else if (strcmp(argv[2], "bounds-x86-64") == 0) {
        bounds_x86(BINBUN_X86_MODE_BITS64, bytes, length);
    } else if (strcmp(argv[2], "bounds-x86-32") == 0) {
        bounds_x86(BINBUN_X86_MODE_BITS32, bytes, length);
    } else {
        fail("unknown architecture %s", argv[2]);
    }
    free(bytes);
    return 0;
}
