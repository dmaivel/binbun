/* Known signatures under the Microsoft x64 convention, built with MSVC
 * (cl /O2 /MD /Zi: see scripts/build-fixtures.sh): functions of 0 to 6
 * integer and floating-point parameters, a variadic call, a call through
 * a function pointer, a tail call to an import, an adapter that moves an
 * argument before its tail call, and reads of the thread's TEB. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define NOINLINE __declspec(noinline)

volatile int sink;

NOINLINE int zero(void) { return sink + 1; }

NOINLINE int one(int a) { return a * 3 + sink; }

NOINLINE long long two(long long a, int b) { return a - b * sink; }

NOINLINE int three(int a, int b, int c) { return a * b + c; }

NOINLINE double four(int a, double b, int c, double d) { return a * b + c * d; }

NOINLINE long long five(int a, int b, int c, int d, int e) {
    return (long long)a * b + (long long)c * d + e;
}

NOINLINE double six(double a, double b, double c, double d, double e, double f) {
    return a * b + c * d + e * f;
}

NOINLINE float mixed(float a, int b, float c, const char *d) { return a * b + c + d[0]; }

/* A variadic call. */
NOINLINE int report(const char *name, int value, double ratio) {
    return printf("%s %d %.2f\n", name, value, ratio);
}

/* A call through a function pointer. */
NOINLINE int apply(int (*f)(int), int x) { return f(x) + 1; }

/* A tail call to an import (`jmp [__imp_free]`). */
NOINLINE void release(void *p) { free(p); }

/* An adapter: moves its second argument into the first one's register,
 * then tail-calls the import. */
NOINLINE void release_second(void *unused, void *p) {
    (void)unused;
    free(p);
}

NOINLINE size_t measure(const char *s, size_t extra) { return strlen(s) + extra; }

/* The thread's TEB: its address (`gs:[0x30]`), and its LastErrorValue
 * (at 0x68 in the x64 TEB) read through it. */
NOINLINE void *teb(void) { return NtCurrentTeb(); }

NOINLINE unsigned long last_error(void) {
    return *(unsigned long *)((char *)NtCurrentTeb() + 0x68);
}

int main(int argc, char **argv) {
    sink = argc;
    int total = zero() + one(argc) + (int)two(argc, 2) + three(argc, 2, 3);
    total += (int)four(argc, 1.5, 2, 2.5) + (int)five(1, 2, 3, argc, 5);
    total += (int)six(1, 2, 3, 4, 5, argc) + (int)mixed(1.5f, argc, 2.5f, argv[0]);
    total += apply(one, argc) + (int)measure(argv[0], 4);
    total += teb() != NULL;
    SetLastError(7);
    total += (int)last_error();
    release(malloc(16));
    release_second(NULL, malloc(32));
    return report(argv[0], total, total / 3.0) > 0 ? 0 : 1;
}
