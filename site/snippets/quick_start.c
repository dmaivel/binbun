#include <inttypes.h>
#include <stdio.h>
#include <binbun/disasm.h>

int main(void) {
    const uint8_t code[] = {0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3};

    binbun_decoder dec;
    binbun_decoder_init(&dec, BINBUN_ARCH_X86, BINBUN_X86_MODE_BITS64,
                        code, sizeof code, 0x401000);

    binbun_instruction insn;
    uint64_t addr;
    char text[BINBUN_MAX_TEXT + 1];
    while (binbun_decoder_next(&dec, &insn, &addr) == BINBUN_STATUS_OK) {
        binbun_instruction_text(&insn, BINBUN_TEXT_DEFAULT, text, sizeof text);
        printf("%#" PRIx64 "  %s\n", addr, text);
    }
}
