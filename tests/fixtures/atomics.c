/* C11 atomic operations as GCC compiles them for x86-64: one locked
 * instruction each (`lock xadd`, `xchg`, `lock cmpxchg`, `lock add`,
 * `lock or`, `lock bts`, `lock dec`), and a compare-and-exchange loop
 * where no instruction gives the old value (`fetch_or` returning it).
 * See scripts/build-fixtures.sh. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>

__attribute__((noinline)) int fetch_add(atomic_int *counter, int amount)
{
    return atomic_fetch_add(counter, amount);
}

__attribute__((noinline)) long exchange(atomic_long *cell, long value)
{
    return atomic_exchange(cell, value);
}

__attribute__((noinline)) bool compare_exchange(atomic_int *cell, int *expected, int desired)
{
    return atomic_compare_exchange_strong(cell, expected, desired);
}

__attribute__((noinline)) void increment(atomic_long *counter) { atomic_fetch_add(counter, 3); }

__attribute__((noinline)) void set_bits(atomic_int *flags, int mask) { atomic_fetch_or(flags, mask); }

__attribute__((noinline)) int fetch_or(atomic_int *flags, int mask)
{
    return atomic_fetch_or(flags, mask);
}

__attribute__((noinline)) bool try_lock(atomic_int *lock) { return atomic_exchange(lock, 1) == 0; }

__attribute__((noinline)) bool test_and_set(atomic_long *flags)
{
    return atomic_fetch_or(flags, 4) & 4;
}

__attribute__((noinline)) bool release(atomic_int *references)
{
    return atomic_fetch_sub(references, 1) == 1;
}

int main(int argc, char **argv)
{
    atomic_int counter = argc;
    atomic_long cell = argc;
    int expected = 1;
    int a = fetch_add(&counter, 5);
    long b = exchange(&cell, 9);
    bool c = compare_exchange(&counter, &expected, 7);
    increment(&cell);
    set_bits(&counter, 16);
    int d = fetch_or(&counter, 32);
    bool e = try_lock(&counter);
    bool f = test_and_set(&cell);
    bool g = release(&counter);
    printf("%d %ld %d %d %d %d %d %d %ld %d\n", a, b, c, d, e, f, g, (int)counter, (long)cell,
           expected);
    return argv[0] == 0;
}
