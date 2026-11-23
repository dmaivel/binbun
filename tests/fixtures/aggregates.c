/* The source of aggregates-x86_64.elf, built by scripts/build-fixtures.sh:
   calls of library functions that return a struct by value. Keep it in
   sync with crates/binbun/tests/decompile.rs. */

#include <inttypes.h>
#include <malloc.h>
#include <stdlib.h>

/* `imaxdiv_t` is two 64-bit integers: returned in `rax` and `rdx`. */
__attribute__((noinline)) long quot_plus_rem(long a, long b)
{
    imaxdiv_t r = imaxdiv(a, b);
    return r.quot * 10 + r.rem;
}

/* `struct mallinfo2` is 80 bytes: returned in memory, whose address the
   caller passes first. */
__attribute__((noinline)) size_t used(void)
{
    struct mallinfo2 m = mallinfo2();
    return m.uordblks + m.fordblks;
}

int main(int argc, char **argv)
{
    (void)argv;
    return (int)(quot_plus_rem(17, argc + 4) + (long)used());
}
