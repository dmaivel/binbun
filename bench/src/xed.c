/* Linear sweep with Intel XED, in C so XED pays no per-instruction FFI cost. */
#include <stddef.h>
#include <stdint.h>

#include "xed/xed-interface.h"

void binbun_bench_xed_init(void) { xed_tables_init(); }

/* Where the flow task's results go, so that they are computed. */
static volatile uint64_t binbun_bench_xed_sink;

/* task: 0 = length only (xed_ild_decode), 1 = full decode (xed_decode),
 * 2 = decode and format as Intel syntax, 3 = decode and the flow: category
 * and the target of a relative branch. Undecodable bytes are skipped one at
 * a time and counted in *invalid. Returns the number of instructions. */
uint64_t binbun_bench_xed_sweep(const uint8_t* code, size_t len, uint64_t ip, int task,
                                uint64_t* invalid) {
    xed_state_t state;
    xed_state_init2(&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    xed_decoded_inst_t xedd;
    char text[256];
    size_t offset = 0;
    uint64_t count = 0, skipped = 0;
    while (offset < len) {
        size_t left = len - offset;
        unsigned avail = left > 15 ? 15 : (unsigned)left;
        xed_decoded_inst_zero_set_mode(&xedd, &state);
        xed_error_enum_t error = task == 0 ? xed_ild_decode(&xedd, code + offset, avail)
                                           : xed_decode(&xedd, code + offset, avail);
        if (error != XED_ERROR_NONE) {
            offset++;
            skipped++;
            continue;
        }
        if (task == 2)
            xed_format_context(XED_SYNTAX_INTEL, &xedd, text, sizeof text, ip + offset, 0, 0);
        if (task == 3) {
            uint64_t next = ip + offset + xed_decoded_inst_get_length(&xedd);
            xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);
            uint64_t target = 0;
            if (xed_operand_values_has_branch_displacement(&xedd))
                target = next + (uint64_t)xed_decoded_inst_get_branch_displacement(&xedd);
            binbun_bench_xed_sink += (uint64_t)category + target;
        }
        offset += xed_decoded_inst_get_length(&xedd);
        count++;
    }
    *invalid = skipped;
    return count;
}
