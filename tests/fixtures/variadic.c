/* Variadic definitions: va_arg walked inline (integers, doubles, both),
 * a va_list passed on (with its format, which is then the function's own;
 * with the format changed; twice), named arguments of both classes and on
 * the stack, and fixed functions of the same shapes. See
 * scripts/build-fixtures.sh. */
#include <stdarg.h>
#include <stdio.h>

__attribute__((noinline)) long sum(int count, ...)
{
    va_list ap;
    long total = 0;
    va_start(ap, count);
    for (int i = 0; i < count; i++)
        total += va_arg(ap, long);
    va_end(ap);
    return total;
}

__attribute__((noinline)) double mean(int count, ...)
{
    va_list ap;
    double total = 0;
    va_start(ap, count);
    for (int i = 0; i < count; i++)
        total += va_arg(ap, double);
    va_end(ap);
    return count > 0 ? total / count : 0;
}

__attribute__((noinline)) double scaled(double scale, int count, ...)
{
    va_list ap;
    double total = 0;
    va_start(ap, count);
    for (int i = 0; i < count; i++)
        total += scale * va_arg(ap, int);
    va_end(ap);
    return total;
}

__attribute__((noinline)) int report(FILE *out, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int written = vfprintf(out, format, ap);
    va_end(ap);
    return written;
}

/* The format vfprintf reads is not the one the caller passed. */
__attribute__((noinline)) int skipped(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int written = vfprintf(stderr, format + 1, ap);
    va_end(ap);
    return written;
}

/* One va_list passed to two calls (C11 7.16p3 leaves it indeterminate
 * after the first: the second goes on where the first stopped). */
__attribute__((noinline)) int twice(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int written = vfprintf(stderr, format, ap);
    written += vfprintf(stdout, format, ap);
    va_end(ap);
    return written;
}

__attribute__((noinline)) long many(long a, long b, long c, long d, long e, long f, long g, ...)
{
    va_list ap;
    va_start(ap, g);
    long next = va_arg(ap, long);
    va_end(ap);
    return a + b + c + d + e + f + g + next;
}

/* Integers only, as glibc's __libc_message_impl: GCC saves no vector
 * register and leaves fp_offset unset; with the frame pointer (as
 * distributions build glibc), the callee-saved registers it pushes for
 * the loop lie just above the integer registers' save area. */
__attribute__((noinline, optimize("no-omit-frame-pointer"))) long lengths(const char *prefix,
                                                                          const char *first, ...)
{
    va_list ap;
    long total = 0, count = 0, longest = 0;
    va_start(ap, first);
    for (const char *s = first; s; s = va_arg(ap, const char *)) {
        long n = puts(s) + (long)prefix[count & 1];
        total += n;
        longest = n > longest ? n : longest;
        count++;
    }
    va_end(ap);
    return total * count + longest;
}

__attribute__((noinline)) long fixed(long a, long b, long *out)
{
    long local[2] = {a, b};
    *out = local[0] * local[1];
    return local[a & 1];
}

int main(int argc, char **argv)
{
    long product;
    long total = sum(3, (long)argc, 2L, 3L) + many(1, 2, 3, 4, 5, 6, 7, 8L);
    double average = mean(2, 1.5, (double)argc) + scaled(0.5, 2, argc, 4);
    report(stdout, "%s %ld %f\n", argv[0], total + fixed(argc, 3, &product), average);
    skipped("-%s %d\n", argv[0], argc);
    twice("%s %d\n", argv[0], argc);
    lengths("ab", argv[0], "x", (char *)0);
    return (int)product;
}
