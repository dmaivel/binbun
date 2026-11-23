/* The source of aggregates-x86_64.exe, built by scripts/build-fixtures.sh:
   calls of functions that take or return a struct by value under the
   Microsoft x64 convention. Keep it in sync with
   crates/binbun/tests/decompile.rs. */

#include <stdlib.h>
#include <windows.h>

/* `COORD` is two 16-bit integers: passed as the 32-bit integer they make,
   in the second argument's register. */
__attribute__((noinline)) int place(HANDLE out, short x, short y)
{
    COORD at = { x, y };
    return SetConsoleCursorPosition(out, at);
}

/* Returned as that integer, in `eax`. */
__attribute__((noinline)) int widest(HANDLE out)
{
    COORD size = GetLargestConsoleWindowSize(out);
    return size.X * size.Y;
}

/* `lldiv_t` is two 64-bit integers: returned in memory, whose address is
   the first argument, before the two declared ones. */
__attribute__((noinline)) long long both(long long a, long long b)
{
    lldiv_t r = lldiv(a, b);
    return r.quot + r.rem;
}

int main(int argc, char **argv)
{
    (void)argv;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    return place(out, (short)argc, 2) + widest(out) + (int)both(argc, 3);
}
