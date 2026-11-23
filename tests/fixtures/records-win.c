/* The source of records-x86_64.exe and records-x86_64.pdb, built by
   scripts/build-fixtures.sh with MSVC: functions that take and return
   structs by value under the Microsoft x64 convention, whose debug
   information states them so. Keep it in sync with
   crates/binbun/tests/debug.rs. */

#include <stdio.h>
#include <windows.h>

/* Sixteen bytes: passed as a pointer to a copy, returned in memory. */
struct pair {
    long long a;
    long long b;
};

/* Eight: passed and returned as a 64-bit integer. */
struct dims {
    int x;
    int y;
};

/* A pointer to `p` in `rcx`, `k` in `rdx`. */
__declspec(noinline) long long sum(struct pair p, long long k)
{
    return p.a + p.b * k;
}

/* The result's address in `rcx`, a pointer to `p` in `rdx`. */
__declspec(noinline) struct pair swap(struct pair p)
{
    struct pair r = { p.b, p.a };
    return r;
}

/* `s` in `rcx`, `k` in `edx`. */
__declspec(noinline) int area(struct dims s, int k)
{
    return s.x * s.y + k;
}

/* `s` in `rcx`, the result in `rax`. */
__declspec(noinline) struct dims twice(struct dims s)
{
    struct dims r = { s.x * 2, s.y * 2 };
    return r;
}

/* `COORD` is four bytes: the 32-bit integer in `edx`. */
__declspec(noinline) int place(HANDLE out, short x, short y)
{
    COORD at = { x, y };
    return SetConsoleCursorPosition(out, at);
}

int main(int argc, char **argv)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    struct pair p = { argc, 5 };
    struct pair q = swap(p);
    struct dims s = { argc + 2, 7 };
    struct dims t = twice(s);
    (void)argv;
    printf("%lld %lld %d %d %d\n", sum(q, 3), q.a, area(t, argc), place(out, (short)argc, 2), t.y);
    return 0;
}
