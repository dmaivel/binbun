/* The source of chained-x86_64.exe, built by scripts/build-fixtures.sh:
   code split off a function as MSVC's profile-guided hot and cold
   splitting leaves it, with x64 `.pdata` entries whose unwind information
   chains to the function's own, in both forms: `cold1`'s information
   holds `main`'s runtime function entry after its (no) unwind codes;
   `cold2`'s unwind RVA is odd, pointing at `main`'s `.pdata` entry
   itself. Keep in sync with crates/binbun-loader/tests/load.rs. */

    .text
    .globl main
main:
    test %ecx, %ecx
    jne cold1
    cmp $1, %ecx
    je cold2
    xor %eax, %eax
back:
    ret
main_end:

    .p2align 4
cold1:
    mov $1, %eax
    jmp back
cold1_end:
cold2:
    mov $2, %eax
    jmp back
cold2_end:

    .section .xdata, "dr"
    .p2align 2
main_unwind:
    .byte 1, 0, 0, 0
cold1_unwind:
    /* Version 1, UNW_FLAG_CHAININFO; no prologue, no codes, no frame
       register; then the chained entry. */
    .byte 0x21, 0, 0, 0
    .rva main, main_end, main_unwind

    .section .pdata, "dr"
    .p2align 2
main_entry:
    .rva main, main_end, main_unwind
    .rva cold1, cold1_end, cold1_unwind
    .rva cold2, cold2_end
    .rva main_entry + 1
