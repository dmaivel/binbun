/* Linear sweep of AArch64 code with LLVM's MC disassembler through its C API,
 * like llvm.c for x86-64. With the default features LLVM rejects SVE, SME,
 * pointer authentication and more, so every extension is enabled ("+all", as
 * llvm-objdump does for AArch64). The C API always prints the instruction,
 * so only the decode + format task applies. */
#include <stddef.h>
#include <stdint.h>

#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>

static LLVMDisasmContextRef context;

int binbun_bench_llvm_a64_init(void) {
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAArch64TargetMC();
    LLVMInitializeAArch64Disassembler();
    context = LLVMCreateDisasmCPUFeatures("aarch64-linux-gnu", "generic", "+all", NULL, 0, NULL,
                                          NULL);
    if (!context) return 0;
    /* Hexadecimal immediates, like every other contender. */
    LLVMSetDisasmOptions(context, LLVMDisassembler_Option_PrintImmHex);
    return 1;
}

/* Skips one 4-byte word where nothing decodes; `invalid` counts words. */
uint64_t binbun_bench_llvm_a64_sweep(const uint8_t* code, size_t len, uint64_t ip,
                                     uint64_t* invalid) {
    char text[256];
    size_t offset = 0;
    uint64_t count = 0, skipped = 0;
    while (len - offset >= 4) {
        size_t length = LLVMDisasmInstruction(context, (uint8_t*)code + offset, 4, ip + offset,
                                              text, sizeof text);
        if (length == 0) {
            offset += 4;
            skipped++;
            continue;
        }
        offset += length;
        count++;
    }
    *invalid = skipped;
    return count;
}
