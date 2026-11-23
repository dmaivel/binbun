/* The source of callbacks-x86_64.elf, built by scripts/build-fixtures.sh:
   calls through pointers whose callee's parameters nothing states. Keep
   in sync with crates/binbun/tests/decompile.rs. */

/* Sets the call's first argument and leaves rdx..r9 as its callers left
   them. */
__attribute__((noinline)) int apply(int (*f)(int), int x)
{
    return f(x) + 1;
}

long (*volatile hook)(long, long);

/* Hands its own arguments on through a pointer, setting none: what it
   passes is what its callers left. No call of the program is seen. */
__attribute__((noinline)) long relay(long a, long b)
{
    return hook(a, b);
}

static int twice(int x)
{
    return 2 * x;
}

int main(int argc, char **argv)
{
    (void)argv;
    return apply(twice, argc);
}
