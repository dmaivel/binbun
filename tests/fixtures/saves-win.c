/* The source of saves-x86_64.exe, built by scripts/build-fixtures.sh:
   a double kept across a call in xmm6, which the Microsoft x64
   convention makes callee-saved, so the function saves and restores the
   caller's xmm6. Keep in sync with crates/binbun/tests/decompile.rs. */

/* noipa: GCC would otherwise see `halve` leaves xmm1 alone and keep `x`
   there. */
__attribute__((noipa)) double halve(double x)
{
    return x / 2;
}

/* `x` lives in xmm6 across the call. */
__attribute__((noinline)) double scaled(double x)
{
    double half = halve(x);
    return half * x;
}

int main(int argc, char **argv)
{
    (void)argv;
    return (int)scaled((double)argc);
}
