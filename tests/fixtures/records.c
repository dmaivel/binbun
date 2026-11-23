/* The source of records-x86_64.elf and records-x86_64.debug, built by
   scripts/build-fixtures.sh: functions that take and return structs by
   value, whose debug information states them so. Keep it in sync with
   crates/binbun/tests/debug.rs. */

#include <stdio.h>

/* Two eightbytes of integers: two integer registers. */
struct pair {
    long a;
    long b;
};

/* Four: memory. */
struct wide {
    long v[4];
};

/* A `double` and an integer: a vector register and an integer one. */
struct mixed {
    double d;
    long n;
};

/* `p` in `rdi` and `rsi`, `k` in `rdx`. */
__attribute__((noinline)) long sum(struct pair p, long k)
{
    return p.a + p.b * k;
}

/* Returned in `rax` and `rdx`. */
__attribute__((noinline)) struct pair swap(struct pair p)
{
    struct pair r = { p.b, p.a };
    return r;
}

/* Returned in memory: its address in `rdi`, `x` in `rsi`. */
__attribute__((noinline)) struct wide fill(long x)
{
    struct wide w = { { x, x + 1, x + 2, x + 3 } };
    return w;
}

/* `w` on the stack, `k` in `rdi`. */
__attribute__((noinline)) long last(struct wide w, long k)
{
    return w.v[3] + k;
}

/* `m.d` in `xmm0`, `m.n` in `rdi`. */
__attribute__((noinline)) double weigh(struct mixed m)
{
    return m.d * (double)m.n;
}

int main(int argc, char **argv)
{
    (void)argv;
    struct pair p = swap((struct pair){ argc, 2 });
    struct wide w = fill(sum(p, 3));
    struct mixed m = { 1.5, last(w, argc) };
    printf("%f\n", weigh(m));
    return 0;
}
