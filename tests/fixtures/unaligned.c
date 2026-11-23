/* Accesses at addresses of no alignment: each function reads and writes
 * through fixed-size memcpy, which GCC compiles to the machine's plain
 * loads and stores, and is called with addresses 0 to 4 bytes into a
 * buffer. `twice` writes a word through each of two addresses that may
 * overlap in part, then reads the first: 257 where the second is one byte
 * on. `links` does the same with a pointer, `halves` with a 16-bit and a
 * 64-bit value, `second` with a struct's field. See
 * scripts/build-fixtures.sh. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct pair {
    int32_t first;
    int64_t second;
};

__attribute__((noinline)) int32_t twice(void *a, void *b)
{
    int32_t one = 1, out;
    memcpy(a, &one, sizeof one);
    memcpy(b, &one, sizeof one);
    memcpy(&out, a, sizeof out);
    return out;
}

__attribute__((noinline)) void *links(void *a, void *b, void *link)
{
    void *out;
    memcpy(a, &link, sizeof link);
    memcpy(b, &link, sizeof link);
    memcpy(&out, a, sizeof out);
    return out;
}

__attribute__((noinline)) uint64_t halves(void *a, void *b, uint16_t half)
{
    uint64_t wide = 0x0101010101010101u, out;
    memcpy(a, &wide, sizeof wide);
    memcpy(b, &half, sizeof half);
    memcpy(&out, a, sizeof out);
    return out;
}

__attribute__((noinline)) int64_t second(void *a, void *b)
{
    struct pair one = {1, 1}, out;
    memcpy((char *)a + 8, &one.second, sizeof one.second);
    memcpy((char *)b + 8, &one.second, sizeof one.second);
    memcpy(&out.second, (char *)a + 8, sizeof out.second);
    return out.second;
}

__attribute__((noinline)) uint32_t get32(const void *from)
{
    uint32_t out;
    memcpy(&out, from, sizeof out);
    return __builtin_bswap32(out);
}

int main(void)
{
    static unsigned char buffer[64];
    for (int offset = 0; offset <= 4; offset++) {
        memset(buffer, 0, sizeof buffer);
        printf("%d: %d", offset, twice(buffer + 8, buffer + 8 + offset));
        memset(buffer, 0, sizeof buffer);
        printf(" %p", links(buffer + 8, buffer + 8 + offset, (void *)0x0101010101010101));
        memset(buffer, 0, sizeof buffer);
        printf(" %llx", (unsigned long long)halves(buffer + 8, buffer + 8 + offset, 0xffff));
        memset(buffer, 0, sizeof buffer);
        printf(" %lld", (long long)second(buffer + 8, buffer + 8 + offset));
        buffer[offset + 3] = 0x98;
        printf(" %x\n", get32(buffer + offset));
    }
    return 0;
}
