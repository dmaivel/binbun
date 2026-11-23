/* Linear sweep with LLVM's MC disassembler through its C API, in C so LLVM
 * pays no per-instruction FFI cost. The C API always prints the instruction,
 * so only the decode + format task applies. */
#include <stddef.h>
#include <stdint.h>

#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>

static LLVMDisasmContextRef context;

int binbun_bench_llvm_init(void) {
    LLVMInitializeX86TargetInfo();
    LLVMInitializeX86TargetMC();
    LLVMInitializeX86Disassembler();
    context = LLVMCreateDisasm("x86_64-unknown-linux-gnu", NULL, 0, NULL, NULL);
    if (!context) return 0;
    /* Intel syntax, like every other contender's formatter. */
    LLVMSetDisasmOptions(context, LLVMDisassembler_Option_AsmPrinterVariant);
    return 1;
}

uint64_t binbun_bench_llvm_sweep(const uint8_t* code, size_t len, uint64_t ip, uint64_t* invalid) {
    char text[256];
    size_t offset = 0;
    uint64_t count = 0, skipped = 0;
    while (offset < len) {
        size_t length = LLVMDisasmInstruction(context, (uint8_t*)code + offset, len - offset,
                                              ip + offset, text, sizeof text);
        if (length == 0) {
            offset++;
            skipped++;
            continue;
        }
        offset += length;
        count++;
    }
    *invalid = skipped;
    return count;
}
