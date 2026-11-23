/* Loops GCC vectorises with AVX2 (-O3 -mavx2): 256-bit loads, stores,
 * lane-wise arithmetic, comparisons, blends, reductions and their 128-bit
 * and scalar remainders. Each is a leaf, so a test can run its decompiled
 * C against this source. */

#include <stddef.h>
#include <stdint.h>

uint32_t sum_bytes(const uint8_t *p, size_t n) {
    uint32_t sum = 0;
    for (size_t i = 0; i < n; i++)
        sum += p[i];
    return sum;
}

void add_arrays(int32_t *restrict d, const int32_t *restrict a, const int32_t *restrict b,
                size_t n) {
    for (size_t i = 0; i < n; i++)
        d[i] = a[i] + b[i];
}

size_t count_byte(const uint8_t *p, size_t n, uint8_t c) {
    size_t count = 0;
    for (size_t i = 0; i < n; i++)
        count += p[i] == c;
    return count;
}

void max_bytes(uint8_t *restrict d, const uint8_t *restrict a, const uint8_t *restrict b,
               size_t n) {
    for (size_t i = 0; i < n; i++)
        d[i] = a[i] > b[i] ? a[i] : b[i];
}

void xor_bytes(uint8_t *restrict d, const uint8_t *restrict s, size_t n, uint8_t key) {
    for (size_t i = 0; i < n; i++)
        d[i] = s[i] ^ key;
}

void mix_words(uint32_t *restrict d, const uint32_t *restrict a, size_t n) {
    for (size_t i = 0; i < n; i++)
        d[i] = (a[i] >> 3) ^ (a[i] << 5) ^ 0x9e3779b9u;
}

int32_t max_int(const int32_t *a, size_t n) {
    int32_t best = INT32_MIN;
    for (size_t i = 0; i < n; i++)
        best = a[i] > best ? a[i] : best;
    return best;
}

void ramp_words(uint64_t *d, size_t n, uint64_t start) {
    for (size_t i = 0; i < n; i++)
        d[i] = start + i;
}

void clamp_shorts(int16_t *restrict d, const int16_t *restrict a, size_t n, int16_t limit) {
    for (size_t i = 0; i < n; i++)
        d[i] = a[i] < -limit ? -limit : a[i] > limit ? limit : a[i];
}

void widen_bytes(uint16_t *restrict d, const uint8_t *restrict a, size_t n) {
    for (size_t i = 0; i < n; i++)
        d[i] = (uint16_t)(a[i] * 3);
}

int main(void) {
    return 0;
}
