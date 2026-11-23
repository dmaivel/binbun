/* The source of x87-x86_64.elf, built by scripts/build-fixtures.sh: an
   exception raised through the x87 environment, as libgcc's
   __sfp_handle_exceptions raises its soft-float ones (`fnstenv` stores
   the tag word, which reads the eight x87 registers where in use; then
   the flag set, `fldenv`, `fwait`). Keep in sync with
   crates/binbun/tests/decompile.rs. */

struct environment {
    unsigned short control, unused1, status, unused2, tags, unused3;
    unsigned int ip;
    unsigned short cs, opcode;
    unsigned int dp;
    unsigned short ds, unused4;
};

/* Raises the x87 exceptions of the status word bits in `flags`. */
__attribute__((noinline)) void raised(int flags)
{
    if (flags & 0x3f) {
        struct environment env;
        __asm__ volatile("fnstenv %0" : "=m"(env));
        env.status |= (unsigned short)(flags & 0x3f);
        __asm__ volatile("fldenv %0\n\tfwait" : : "m"(env));
    }
}

int main(int argc, char **argv)
{
    (void)argv;
    raised(argc & 0x20);
    return 0;
}
