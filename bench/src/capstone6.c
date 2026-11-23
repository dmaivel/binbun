/* Linear sweep of AArch64 code with Capstone 6 (the "next" branch, whose
 * AArch64 module is generated from LLVM), in C: there is no Rust binding for
 * it. build.rs links it so that its symbols cannot clash with the Capstone 5
 * that the `capstone` crate links. Capstone always prints the instruction;
 * the decode task also fills in the operand details. */
#include <stddef.h>
#include <stdint.h>

#include <capstone/capstone.h>

/* [0]: detail off, [1]: detail on. */
static csh handles[2];
static cs_insn* instructions[2];

int binbun_bench_cs6_init(void) {
    for (int detail = 0; detail < 2; detail++) {
        if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &handles[detail]) != CS_ERR_OK)
            return 0;
        if (detail && cs_option(handles[detail], CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return 0;
        instructions[detail] = cs_malloc(handles[detail]);
        if (!instructions[detail]) return 0;
    }
    return 1;
}

/* Skips one 4-byte word where nothing decodes; `invalid` counts words. */
uint64_t binbun_bench_cs6_sweep(const uint8_t* code, size_t len, uint64_t ip, int detail,
                                uint64_t* invalid) {
    csh handle = handles[detail != 0];
    cs_insn* instruction = instructions[detail != 0];
    uint64_t count = 0, skipped = 0;
    while (len >= 4) {
        if (cs_disasm_iter(handle, &code, &len, &ip, instruction)) {
            count++;
            continue;
        }
        code += 4;
        len -= 4;
        ip += 4;
        skipped++;
    }
    *invalid = skipped;
    return count;
}
