/* A double kept across a call to an import: `scaled` needs its argument
 * after calling libc's `strtod`, so AArch64 compilers keep it in d8, a
 * register AAPCS64's callee keeps (the low 64 bits of v8-v15), saved and
 * restored in the prologue and epilogue. `rescaled` keeps its own across
 * a call to `scaled`, which saves and restores d8 as a double: the call
 * gives back d8's low 64 bits. See scripts/build-fixtures.sh. */
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) double scaled(double x, const char *text) { return strtod(text, NULL) * x; }

__attribute__((noinline)) double rescaled(double x, const char *text) { return scaled(x + 1.0, text) * x; }

int main(int argc, char **argv)
{
    printf("%f\n", rescaled(argc + 0.25, argv[0]));
    return 0;
}
