/* A small library for the signature tests (crates/binbun/tests/signatures.rs):
   look-alike pairs told apart only by some inputs, a string function that
   reads a word at a time past the terminator (as musl's does), a pair no
   input tells apart, one with a string literal, and one that dispatches by
   processor. Built by scripts/build-fixtures.sh in several ways. */

#include <stddef.h>
#include <stdint.h>

typedef size_t __attribute__((__may_alias__)) word;
#define ALIGN (sizeof(size_t))
#define ONES ((size_t)-1 / UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX / 2 + 1))
#define HASZERO(x) (((x) - ONES) & ~(x) & HIGHS)
#define UCHAR_MAX 255

char *stpcpy(char *restrict d, const char *restrict s)
{
    word *wd;
    const word *ws;
    if ((uintptr_t)s % ALIGN == (uintptr_t)d % ALIGN) {
        for (; (uintptr_t)s % ALIGN; s++, d++)
            if (!(*d = *s))
                return d;
        wd = (void *)d;
        ws = (const void *)s;
        for (; !HASZERO(*ws); *wd++ = *ws++)
            ;
        d = (void *)wd;
        s = (const void *)ws;
    }
    for (; (*d = *s); s++, d++)
        ;
    return d;
}

char *strcpy(char *restrict dest, const char *restrict src)
{
    stpcpy(dest, src);
    return dest;
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;
    for (; n; n--)
        *d++ = *s++;
    return dest;
}

void *memmove(void *dest, const void *src, size_t n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;
    if (d == s)
        return d;
    if (d < s) {
        for (; n; n--)
            *d++ = *s++;
    } else {
        while (n)
            n--, d[n] = s[n];
    }
    return dest;
}

char *strchrnul(const char *s, int c)
{
    c = (unsigned char)c;
    if (!c) {
        while (*s)
            s++;
        return (char *)s;
    }
    for (; *s && *(unsigned char *)s != c; s++)
        ;
    return (char *)s;
}

char *strchr(const char *s, int c)
{
    char *r = strchrnul(s, c);
    return *(unsigned char *)r == (unsigned char)c ? r : 0;
}

int tolower(int c)
{
    if ((unsigned)c - 'A' < 26)
        return c | 32;
    return c;
}

int tolower_l(int c, void *locale)
{
    (void)locale;
    if ((unsigned)c - 'A' < 26)
        return c | 32;
    return c;
}

long labs(long a)
{
    return a > 0 ? a : -a;
}

int abs(int a)
{
    return a > 0 ? a : -a;
}

const char *sig_error(int code)
{
    switch (code) {
    case 0:
        return "no error";
    case 1:
        return "operation not permitted";
    case 2:
        return "no such file or directory";
    default:
        return "unknown error";
    }
}

unsigned long sig_hash(const char *s)
{
    unsigned long h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h ^ 0x9e3779b97f4a7c15UL;
}

int sig_has_avx(void)
{
    unsigned a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    return (c >> 28) & 1 ? (int)sig_hash("avx") : 0;
}

/* The entry of the linked builds. */
void _start(void)
{
    static char buffer[64];
    strcpy(buffer, sig_error(2));
    memmove(buffer + 1, buffer, 8);
    __builtin_trap();
}
