/* The source of bits-x86_64.elf, built by scripts/build-fixtures.sh: bit
   counts of a value tested first, as C23's stdc_bit_floor is in glibc.
   GCC makes `__builtin_clz` a `bsr`, which leaves its destination as it
   was for a zero source; the test before it rules that case out. Keep it
   in sync with crates/binbun/tests/decompile.rs. */

/* The largest power of two not above `x`, 0 for 0. */
__attribute__((noinline)) unsigned floor_pow2(unsigned char x)
{
    return x ? 0x80000000u >> __builtin_clz(x) : 0;
}

/* How many bits `x` takes, 0 for 0 (C23's stdc_bit_width): GCC tests the
   source after the `bsr` and picks with a conditional move. */
__attribute__((noinline)) unsigned bit_width(unsigned x)
{
    return x ? 32 - __builtin_clz(x) : x;
}

int main(int argc, char **argv)
{
    (void)argv;
    return (int)(floor_pow2((unsigned char)argc) + bit_width((unsigned)argc));
}
