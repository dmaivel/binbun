/* A library's exit for the session's signature tests
   (crates/binbun-session/tests/signatures.rs): it never returns (the
   exit_group system call does not), though its code ends in a return,
   so only its declaration says so. Its object, sigs-exit-gcc.o, is a
   pack's input; linked into sigs-app-gcc.elf. Built by
   scripts/build-fixtures.sh. */

void exit(int code)
{
    __asm__ volatile("syscall" : : "a"(231), "D"(code) : "rcx", "r11", "memory");
}
