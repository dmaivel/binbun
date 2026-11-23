/* The source of ifunc-x86_64.elf, built by scripts/build-fixtures.sh: an
   executable that defines `strlen` as an IFUNC (its resolver picks the
   implementation when the image is loaded) and exports it, and calls it:
   the call goes through a slot an IRELATIVE relocation fills with what
   the resolver returns. Keep it in sync with
   crates/binbun/tests/decompile.rs. */

#include <stddef.h>

static size_t length(const char *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

static size_t (*resolve_strlen(void))(const char *)
{
    return length;
}

size_t strlen(const char *s) __attribute__((ifunc("resolve_strlen")));

/* Calls strlen with the string alone; rsi to r9 are as its caller left
   them. */
__attribute__((noinline)) size_t twice(const char *s)
{
    return strlen(s) * 2;
}

int main(int argc, char **argv)
{
    return argc > 1 ? (int)twice(argv[1]) : 0;
}
