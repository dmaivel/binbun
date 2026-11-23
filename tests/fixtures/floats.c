/* Scalar floating point as compilers emit it for SSE: arithmetic,
 * conversions both ways, comparisons by `ucomisd` and each condition code
 * of its flags, the sign changed with a mask, a square root, a value
 * returned where it was found, a sum kept in a register over a loop, a
 * value loaded and returned, the largest of an array, and two that return
 * nothing though they leave a double in the register: one copied from
 * memory to memory, one scaled in place. `shifted` returns a float it
 * makes of an exponent it keeps in an integer register on every path, as
 * glibc's `scalbnf` does: only its caller shows which register it returns
 * in. `forwarded` leaves for `root` and `wrapped` returns what `product`
 * gave it after more work: each returns its callee's double.
 * See scripts/build-fixtures.sh. */
#include <math.h>
#include <stdio.h>

__attribute__((noinline)) double product(double a, double b) { return a * b; }

__attribute__((noinline)) float total(float a, float b) { return a + b; }

__attribute__((noinline)) double halved(int count) { return count * 0.5; }

__attribute__((noinline)) int truncated(double x) { return (int)x; }

__attribute__((noinline)) long nearest(double x) { return lrint(x); }

__attribute__((noinline)) float narrowed(double x) { return (float)x; }

__attribute__((noinline)) int below(double a, double b) { return a < b; }

__attribute__((noinline)) int differs(double a, double b) { return a != b; }

__attribute__((noinline)) int same(float a, float b) { return a == b; }

__attribute__((noinline)) int unordered(double a, double b) { return isunordered(a, b); }

__attribute__((noinline)) double negated(double x) { return -x; }

__attribute__((noinline)) float magnitude(float x) { return fabsf(x); }

__attribute__((noinline)) double root(double x) { return sqrt(x); }

__attribute__((noinline)) double polynomial(double x) { return 3.0 * x * x - 2.5 * x + 0.125; }

/* The first argument is returned where the caller left it. */
__attribute__((noinline)) double smaller(double a, double b) { return a < b ? a : b + 1.0; }

__attribute__((noinline)) double summed(const double *values, int count)
{
    double sum = 0;
    for (int i = 0; i < count; i++)
        sum += values[i];
    return sum;
}

__attribute__((noinline)) double loaded(const double *from) { return *from; }

__attribute__((noinline)) double largest(const double *values, int count)
{
    double most = values[0];
    for (int i = 1; i < count; i++)
        if (values[i] > most)
            most = values[i];
    return most;
}

__attribute__((noinline)) void copied(double *to, const double *from) { *to = *from; }

__attribute__((noinline)) void scaled(double *values, int count, double by)
{
    for (int i = 0; i < count; i++)
        values[i] *= by;
}

__attribute__((noinline)) float shifted(float x, int by)
{
    union {
        float value;
        unsigned bits;
    } parts = {x};
    int exponent = (parts.bits >> 23) & 0xff;
    if (exponent == 0xff)
        return x + x;
    exponent += by;
    if (exponent > 254)
        return x * 1e30f;
    parts.bits = (parts.bits & 0x807fffffu) | ((unsigned)exponent << 23);
    return parts.value;
}

__attribute__((noinline)) double forwarded(double x) { return root(x + 1.0); }

__attribute__((noinline)) double wrapped(double x, int *calls)
{
    double twice = product(x, 2.0);
    ++*calls;
    return twice;
}

int main(int argc, char **argv)
{
    double values[3] = {argc, 2.5, -1.0};
    double other[1];
    int calls = 0;
    double x = argc + 0.25;
    printf("%f %f %f %d %ld %f\n", product(x, 3.0), (double)total((float)x, 1.5f), halved(argc),
           truncated(x), nearest(x), (double)narrowed(x));
    printf("%d %d %d %d\n", below(x, 2.0), differs(x, 1.25), same((float)x, 1.25f),
           unordered(x, 0.0 / (argc - 1)));
    printf("%f %f %f %f %f %f\n", negated(x), (double)magnitude((float)-x), root(x), polynomial(x),
           smaller(x, 1.0), summed(values, 3));
    copied(other, values);
    scaled(values, 3, 0.5);
    printf("%f %f %f %f\n", loaded(values), largest(values, 3), other[0],
           (double)shifted((float)x, argc));
    printf("%f %f %d\n", forwarded(x), wrapped(x, &calls), calls);
    return argv[0] == 0;
}
