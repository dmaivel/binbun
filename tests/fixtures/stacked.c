/* The source of stacked-x86_64.elf and its type oracle
   stacked-x86_64.debug, built by scripts/build-fixtures.sh: a function
   whose seventh parameter is on the stack (System V x86-64 passes six in
   registers). Keep in sync with crates/binbun-cli/tests/score.rs. */

__attribute__((noinline)) long seventh(long a, long b, long c, long d, long e, long f, long g)
{
    return a + b + c + d + e + f + g;
}

int main(int argc, char **argv)
{
    (void)argv;
    return (int)seventh(argc, 2, 3, 4, 5, 6, argc);
}
