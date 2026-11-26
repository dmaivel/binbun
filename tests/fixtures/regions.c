/* The source of regions-x86_64.elf, built by scripts/build-fixtures.sh:
   structs on the stack passed by address, to a library function that
   declares their type and to functions of the program that do not. Keep
   it in sync with crates/binbun/tests/decompile.rs. */

#include <stddef.h>
#include <sys/time.h>

/* `out = a - b`. */
__attribute__((noinline)) void difference(struct timeval *out, const struct timeval *a,
                                          const struct timeval *b)
{
    out->tv_sec = a->tv_sec - b->tv_sec;
    out->tv_usec = a->tv_usec - b->tv_usec;
    if (out->tv_usec < 0) {
        out->tv_usec += 1000000;
        out->tv_sec--;
    }
}

/* Whole milliseconds. */
__attribute__((noinline)) long milliseconds(const struct timeval *t)
{
    return t->tv_sec * 1000 + t->tv_usec / 1000;
}

int main(void)
{
    struct timeval before, after, spent;
    gettimeofday(&before, NULL);
    gettimeofday(&after, NULL);
    difference(&spent, &after, &before);
    return (int)milliseconds(&spent);
}
