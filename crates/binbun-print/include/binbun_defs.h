/* binbun_defs.h: the helpers C written by binbun calls.
 *
 * C11 for GCC and Clang, any target. Compile the output with
 *     -fwrapv -fno-strict-aliasing
 * so signed overflow wraps and type punning through pointers is defined
 * (and link with -lm: the float roundings may call floor, ceil, trunc).
 *
 * Each helper is a static inline function with L0's exact meaning (every
 * operation total: shifts past the width give 0 or the sign, division by
 * zero gives all ones, counts of zeros of 0 give the width). A short name
 * dispatches on the operand's type with _Generic: rotl(x, n) on a uint32_t
 * is the 32-bit rotation. Macros only where no function can do it (that
 * dispatch, escapes with any number of operands, and the canonical-address
 * checks, which take an integer, a data or a code pointer alike).
 *
 * Define BINBUN_HOOKS before including it to receive traps and escapes in
 * binbun_hook_trap and binbun_hook_escape (a test harness's), instead of
 * trapping.
 */
#ifndef BINBUN_DEFS_H
#define BINBUN_DEFS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__GNUC__)
#error "binbun_defs.h needs GCC or Clang"
#endif

/* The prototypes binbun writes for library functions (memcpy, strlen)
 * carry the types the decompiler recovered, not the library's (no const,
 * its own integer types): ABI-compatible, but compilers warn that they
 * redeclare their builtins (Clang also that the builtin's header is not
 * included: vfprintf's is <stdio.h>), and that the address of a global
 * declared const (one in read-only data) passed to them, or kept in a
 * variable of a recovered pointer type, discards the qualifier. Those
 * warnings are off for the output. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wincompatible-library-redeclaration"
#pragma clang diagnostic ignored "-Wbuiltin-requires-header"
#pragma clang diagnostic ignored "-Wincompatible-pointer-types-discards-qualifiers"
#else
#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#endif

/* A variadic call whose format string is not parsed (not constant, or a
 * conversion the decompiler refuses) passes every argument register the
 * caller may have set, each as wide as its register; and integers print by
 * width, so a parsed %lld passes an int64_t, which is `long` under LP64:
 * the compilers' format checks would flag either. Those warnings are off
 * for the output too. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wformat"
#else
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#endif

typedef __int128 binbun_i128;
typedef unsigned __int128 binbun_u128;

/* The scalar types, of alignment 1: what the program's pointers point to
 * (binbun_i32_u *p). The machine's loads and stores ask no alignment of an
 * address, and the program need not give any: a parser reads a 32-bit
 * field wherever it lies in a packet. C's int32_t * promises a multiple of
 * 4, and compilers use the promise: given two of them, GCC takes the two
 * objects to be the same or apart, never to overlap in part, and answers
 * a load after two stores of one value without reading; through an
 * unsigned __int128 * compilers load and store with aligned vector
 * instructions, which fault where the address is not a multiple of 16, as
 * the machine's movdqu need not be. Pointers and enumerations pointed to
 * get such a typedef in the output itself (struct_node_p_u), and its
 * structs are packed. */
typedef int16_t binbun_i16_u __attribute__((aligned(1)));
typedef uint16_t binbun_u16_u __attribute__((aligned(1)));
typedef int32_t binbun_i32_u __attribute__((aligned(1)));
typedef uint32_t binbun_u32_u __attribute__((aligned(1)));
typedef int64_t binbun_i64_u __attribute__((aligned(1)));
typedef uint64_t binbun_u64_u __attribute__((aligned(1)));
typedef __int128 binbun_i128_u __attribute__((aligned(1)));
typedef unsigned __int128 binbun_u128_u __attribute__((aligned(1)));
typedef float binbun_f32_u __attribute__((aligned(1)));
typedef double binbun_f64_u __attribute__((aligned(1)));
#ifdef __FLT16_MAX__
typedef _Float16 binbun_f16_u __attribute__((aligned(1)));
#endif
/* The address of a field of a packed struct (&p->f) becomes such a
 * pointer, which asks no alignment of it; Clang warns that it may be
 * unaligned wherever one is taken. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#endif

/* System V x86-64's va_list is an array of one struct __va_list_tag, the
 * compiler's own type, which C cannot name: a struct declared with that
 * tag is another type. binbun_va_tag is the compiler's, for the pointers
 * into a va_list kept outside a parameter list (in one, binbun writes
 * them va_list). */
#if defined(__x86_64__) && !defined(_WIN32) && !defined(__CYGWIN__)
typedef __typeof__(**(va_list *)0) binbun_va_tag;
#endif

/* After va_start in a function that reads its va_list by its fields
 * (ap->gp_offset, ap->reg_save_area: a va_arg the compiler expanded in
 * place is such reads and arithmetic). GCC's va_start saves only the
 * registers and sets only the fields the va_arg uses it finds need, and
 * finds none in such a function: it left reg_save_area unset and saved no
 * register. This gives the list to code the compiler cannot see into, so
 * that it fills all of it. */
#define binbun_va_walk(ap) __asm__ volatile("" : : "r"(ap) : "memory")

/* A declaration linked to the symbol `name` rather than its C name (a
 * symbol that is not a C identifier, or a second prototype for one
 * function): int foo_cold(int) BINBUN_SYMBOL("foo.cold"); */
#define BINBUN_STRING_(x) #x
#define BINBUN_STRING(x) BINBUN_STRING_(x)
#define BINBUN_SYMBOL(name) __asm__(BINBUN_STRING(__USER_LABEL_PREFIX__) name)

/* The width of `long`: 64 bits (LP64: Linux, macOS) or 32 (LLP64:
 * 64-bit Windows). */
#if __SIZEOF_LONG__ == 8
#define BINBUN_LONG_BITS 64
#else
#define BINBUN_LONG_BITS 32
#endif
#define BINBUN_CAT_(a, b) a##b
#define BINBUN_CAT(a, b) BINBUN_CAT_(a, b)

/* Dispatch on the type of x over the unsigned widths. The associations
 * are C's standard integer types, which every <stdint.h> typedef is one
 * of on any target (uint64_t is `unsigned long` on Linux, `unsigned long
 * long` on Windows): so x may be spelled either way. */
#define BINBUN_UNSIGNED(x, name)                                              \
    _Generic((x), unsigned char: name##8, unsigned short: name##16,           \
             unsigned int: name##32,                                          \
             unsigned long: BINBUN_CAT(name, BINBUN_LONG_BITS),               \
             unsigned long long: name##64, binbun_u128: name##128)
/* Dispatch on the type of x over the signed widths. */
#define BINBUN_SIGNED(x, name)                                                \
    _Generic((x), signed char: name##8, short: name##16, int: name##32,       \
             long: BINBUN_CAT(name, BINBUN_LONG_BITS), long long: name##64,  \
             binbun_i128: name##128)
/* Dispatch on the type of x between up to 64 bits and 128. */
#define BINBUN_WIDE(x, name)                                                  \
    _Generic((x), unsigned char: name##64, unsigned short: name##64,          \
             unsigned int: name##64, unsigned long: name##64,                 \
             unsigned long long: name##64, binbun_u128: name##128)

/* Defines a helper `name` for each width W as body (with T the unsigned
 * type, S the signed one). */
#define BINBUN_EACH(define)                                                   \
    define(8, uint8_t, int8_t) define(16, uint16_t, int16_t)                  \
    define(32, uint32_t, int32_t) define(64, uint64_t, int64_t)               \
    define(128, binbun_u128, binbun_i128)

/* ---- Counts and byte order ------------------------------------------- */

static inline unsigned binbun_popcount_u128(binbun_u128 x) {
    return (unsigned)__builtin_popcountll((uint64_t)x) +
           (unsigned)__builtin_popcountll((uint64_t)(x >> 64));
}

static inline unsigned binbun_clz_u128(binbun_u128 x) {
    uint64_t high = (uint64_t)(x >> 64), low = (uint64_t)x;
    if (high != 0)
        return (unsigned)__builtin_clzll(high);
    return low != 0 ? 64u + (unsigned)__builtin_clzll(low) : 128u;
}

static inline unsigned binbun_ctz_u128(binbun_u128 x) {
    uint64_t high = (uint64_t)(x >> 64), low = (uint64_t)x;
    if (low != 0)
        return (unsigned)__builtin_ctzll(low);
    return high != 0 ? 64u + (unsigned)__builtin_ctzll(high) : 128u;
}

#define BINBUN_COUNTS(W, T, S)                                                \
    /* Number of 1 bits. */                                                   \
    static inline T binbun_popcount##W(T x) {                                 \
        return (T)binbun_popcount_u128(x);                                    \
    }                                                                         \
    /* Number of 0 bits above the highest 1 bit; W for 0. */                  \
    static inline T binbun_clz##W(T x) {                                      \
        return (T)(binbun_clz_u128(x) - (128u - (W)));                        \
    }                                                                         \
    /* Number of 0 bits below the lowest 1 bit; W for 0. */                   \
    static inline T binbun_ctz##W(T x) {                                      \
        return x == 0 ? (T)(W) : (T)binbun_ctz_u128(x);                       \
    }
BINBUN_EACH(BINBUN_COUNTS)

#define popcount(x) BINBUN_UNSIGNED((x), binbun_popcount)(x)
#define clz(x) BINBUN_UNSIGNED((x), binbun_clz)(x)
#define ctz(x) BINBUN_UNSIGNED((x), binbun_ctz)(x)

/* For a value of `width` bits (below 64 or 128) zero-extended in x: its
 * leading and trailing zeros within those bits. */
static inline uint64_t binbun_clz_n64(uint64_t x, unsigned width) {
    return x == 0 ? width : (uint64_t)__builtin_clzll(x) - (64u - width);
}
static inline binbun_u128 binbun_clz_n128(binbun_u128 x, unsigned width) {
    return binbun_clz_u128(x) - (128u - width);
}
static inline uint64_t binbun_ctz_n64(uint64_t x, unsigned width) {
    return x == 0 ? width : (uint64_t)__builtin_ctzll(x);
}
static inline binbun_u128 binbun_ctz_n128(binbun_u128 x, unsigned width) {
    return x == 0 ? width : binbun_ctz_u128(x);
}
#define clz_n(x, width)                                                       \
    BINBUN_WIDE((x), binbun_clz_n)(x, width)
#define ctz_n(x, width)                                                       \
    BINBUN_WIDE((x), binbun_ctz_n)(x, width)

/* Whether the low 8 bits of x have an even number of 1 bits (x86's parity
 * flag). */
static inline bool even_parity8(uint64_t x) {
    return (__builtin_popcount((unsigned)(x & 0xff)) & 1) == 0;
}

static inline uint8_t binbun_bswap8(uint8_t x) { return x; }
static inline uint16_t binbun_bswap16(uint16_t x) { return __builtin_bswap16(x); }
static inline uint32_t binbun_bswap32(uint32_t x) { return __builtin_bswap32(x); }
static inline uint64_t binbun_bswap64(uint64_t x) { return __builtin_bswap64(x); }
static inline binbun_u128 binbun_bswap128(binbun_u128 x) {
    return (binbun_u128)__builtin_bswap64((uint64_t)x) << 64 |
           __builtin_bswap64((uint64_t)(x >> 64));
}
/* The bytes of x in reverse order. */
#define bswap(x) BINBUN_UNSIGNED((x), binbun_bswap)(x)

/* ---- Shifts and rotations --------------------------------------------- */

#define BINBUN_SHIFTS(W, T, S)                                                \
    /* x shifted left by n; 0 from n = W on. */                               \
    static inline T binbun_shl##W(T x, T n) {                                 \
        return n >= (W) ? (T)0 : (T)(x << n);                                 \
    }                                                                         \
    /* x shifted right by n, logically; 0 from n = W on. */                   \
    static inline T binbun_lshr##W(T x, T n) {                                \
        return n >= (W) ? (T)0 : (T)(x >> n);                                 \
    }                                                                         \
    /* x shifted right by n, arithmetically; the sign from n = W on. */       \
    static inline S binbun_ashr##W(S x, T n) {                                \
        return n >= (W) ? (S)(x < 0 ? -1 : 0) : (S)(x >> n);                  \
    }                                                                         \
    /* x rotated left by n modulo W. */                                       \
    static inline T binbun_rotl##W(T x, T n) {                                \
        unsigned k = (unsigned)(n % (W));                                     \
        return k == 0 ? x : (T)(x << k | x >> ((W) - k));                     \
    }                                                                         \
    /* x rotated right by n modulo W. */                                      \
    static inline T binbun_rotr##W(T x, T n) {                                \
        unsigned k = (unsigned)(n % (W));                                     \
        return k == 0 ? x : (T)(x >> k | x << ((W) - k));                     \
    }
BINBUN_EACH(BINBUN_SHIFTS)

/* Shifts by a count not known to be below the width (n is converted to x's
 * type: only its value matters). */
#define shl(x, n) BINBUN_UNSIGNED((x), binbun_shl)(x, n)
#define lshr(x, n) BINBUN_UNSIGNED((x), binbun_lshr)(x, n)
#define ashr(x, n) BINBUN_SIGNED((x), binbun_ashr)(x, n)
#define rotl(x, n) BINBUN_UNSIGNED((x), binbun_rotl)(x, n)
#define rotr(x, n) BINBUN_UNSIGNED((x), binbun_rotr)(x, n)

/* Rotations of a value of `width` bits (below 64 or 128) zero-extended in
 * x; the result is zero-extended too. */
static inline uint64_t binbun_rotl_n64(uint64_t x, uint64_t n, unsigned width) {
    unsigned k = (unsigned)(n % width);
    uint64_t mask = ((uint64_t)1 << width) - 1;
    return k == 0 ? x : ((x << k) | (x >> (width - k))) & mask;
}
static inline binbun_u128 binbun_rotl_n128(binbun_u128 x, binbun_u128 n, unsigned width) {
    unsigned k = (unsigned)(n % width);
    binbun_u128 mask = ((binbun_u128)1 << width) - 1;
    return k == 0 ? x : ((x << k) | (x >> (width - k))) & mask;
}
static inline uint64_t binbun_rotr_n64(uint64_t x, uint64_t n, unsigned width) {
    unsigned k = (unsigned)(n % width);
    return binbun_rotl_n64(x, k == 0 ? 0 : width - k, width);
}
static inline binbun_u128 binbun_rotr_n128(binbun_u128 x, binbun_u128 n, unsigned width) {
    unsigned k = (unsigned)(n % width);
    return binbun_rotl_n128(x, k == 0 ? 0 : width - k, width);
}
#define rotl_n(x, n, width)                                                   \
    BINBUN_WIDE((x), binbun_rotl_n)(x, n, width)
#define rotr_n(x, n, width)                                                   \
    BINBUN_WIDE((x), binbun_rotr_n)(x, n, width)

/* The low `width` bits of x (below 64 or 128) sign-extended. */
static inline int64_t binbun_sext_n64(uint64_t x, unsigned width) {
    uint64_t sign = (uint64_t)1 << (width - 1);
    return (int64_t)(((x & ((sign << 1) - 1)) ^ sign) - sign);
}
static inline binbun_i128 binbun_sext_n128(binbun_u128 x, unsigned width) {
    binbun_u128 sign = (binbun_u128)1 << (width - 1);
    return (binbun_i128)(((x & ((sign << 1) - 1)) ^ sign) - sign);
}
#define sext_n(x, width)                                                      \
    BINBUN_WIDE((x), binbun_sext_n)(x, width)

/* ---- Parts of values ---------------------------------------------------- */

/* Bits 0-7, 0-15, 0-31 and 8-15 of x (x86's al, ax, eax and ah). */
static inline uint8_t low8(uint64_t x) { return (uint8_t)x; }
static inline uint16_t low16(uint64_t x) { return (uint16_t)x; }
static inline uint32_t low32(uint64_t x) { return (uint32_t)x; }
static inline uint8_t high8(uint64_t x) { return (uint8_t)(x >> 8); }

/* ---- Carries, borrows and overflows ------------------------------------ */

#define BINBUN_FLAGS(W, T, S)                                                 \
    /* The carry out of a + b + c (the carry of a + b, or of that + c). */    \
    static inline bool binbun_add_carry##W(T a, T b, T c) {                   \
        T sum;                                                                \
        bool first = __builtin_add_overflow(a, b, &sum);                      \
        bool second = __builtin_add_overflow(sum, c, &sum);                   \
        return first | second;                                                \
    }                                                                         \
    /* Whether a + b + c overflows as a signed sum (a and b of one sign,      \
     * the sum of the other). */                                              \
    static inline bool binbun_add_overflow##W(T a, T b, T c) {                \
        T sum = (T)(a + b + c);                                               \
        return (S)(~(a ^ b) & (a ^ sum)) < 0;                                 \
    }                                                                         \
    /* The borrow out of a - b - c: whether a < b + c, exactly. */            \
    static inline bool binbun_sub_borrow##W(T a, T b, T c) {                  \
        T subtrahend;                                                         \
        bool over = __builtin_add_overflow(b, c, &subtrahend);                \
        return over | (a < subtrahend);                                       \
    }                                                                         \
    /* Whether a - b - c overflows as a signed difference (a and b of         \
     * different signs, the result of b's). */                                \
    static inline bool binbun_sub_overflow##W(T a, T b, T c) {                \
        T difference = (T)(a - b - c);                                        \
        return (S)((a ^ b) & (a ^ difference)) < 0;                           \
    }                                                                         \
    /* Bit 4 of a ^ b ^ c (x86's auxiliary carry). */                         \
    static inline bool binbun_nibble_carry##W(T a, T b, T c) {                \
        return ((a ^ b ^ c) >> 4 & 1) != 0;                                   \
    }
BINBUN_EACH(BINBUN_FLAGS)

#define add_carry(a, b, c) BINBUN_UNSIGNED((a), binbun_add_carry)(a, b, c)
#define add_overflow(a, b, c) BINBUN_UNSIGNED((a), binbun_add_overflow)(a, b, c)
#define sub_borrow(a, b, c) BINBUN_UNSIGNED((a), binbun_sub_borrow)(a, b, c)
#define sub_overflow(a, b, c) BINBUN_UNSIGNED((a), binbun_sub_overflow)(a, b, c)
#define nibble_carry(a, b, c) BINBUN_UNSIGNED((a), binbun_nibble_carry)(a, b, c)

/* ---- Multiplication and division --------------------------------------- */

/* The high half of the double-width product, unsigned and signed. */
static inline uint8_t binbun_umulh8(uint8_t a, uint8_t b) { return (uint8_t)((unsigned)a * b >> 8); }
static inline uint16_t binbun_umulh16(uint16_t a, uint16_t b) { return (uint16_t)((uint32_t)a * b >> 16); }
static inline uint32_t binbun_umulh32(uint32_t a, uint32_t b) { return (uint32_t)((uint64_t)a * b >> 32); }
static inline uint64_t binbun_umulh64(uint64_t a, uint64_t b) { return (uint64_t)((binbun_u128)a * b >> 64); }
static inline int8_t binbun_smulh8(int8_t a, int8_t b) { return (int8_t)(a * b >> 8); }
static inline int16_t binbun_smulh16(int16_t a, int16_t b) { return (int16_t)((int32_t)a * b >> 16); }
static inline int32_t binbun_smulh32(int32_t a, int32_t b) { return (int32_t)((int64_t)a * b >> 32); }
static inline int64_t binbun_smulh64(int64_t a, int64_t b) { return (int64_t)((binbun_i128)a * b >> 64); }
#define umulh(a, b)                                                           \
    _Generic((a), unsigned char: binbun_umulh8, unsigned short: binbun_umulh16, \
             unsigned int: binbun_umulh32,                                    \
             unsigned long: BINBUN_CAT(binbun_umulh, BINBUN_LONG_BITS),       \
             unsigned long long: binbun_umulh64)(a, b)
#define smulh(a, b)                                                           \
    _Generic((a), signed char: binbun_smulh8, short: binbun_smulh16,          \
             int: binbun_smulh32,                                             \
             long: BINBUN_CAT(binbun_smulh, BINBUN_LONG_BITS),                \
             long long: binbun_smulh64)(a, b)

#define BINBUN_DIVISION(W, T, S)                                              \
    /* a / b, unsigned; all ones for b = 0. */                                \
    static inline T binbun_udiv##W(T a, T b) {                                \
        return b == 0 ? (T)~(T)0 : (T)(a / b);                                \
    }                                                                         \
    /* a % b, unsigned; a for b = 0. */                                       \
    static inline T binbun_urem##W(T a, T b) {                                \
        return b == 0 ? a : (T)(a % b);                                       \
    }                                                                         \
    /* a / b, signed, truncated; -1 for b = 0, a for the most negative a      \
     * divided by -1. */                                                      \
    static inline S binbun_sdiv##W(S a, S b) {                                \
        if (b == 0)                                                           \
            return (S)-1;                                                     \
        if (b == -1)                                                          \
            return (S)(0 - (T)a);                                             \
        return (S)(a / b);                                                    \
    }                                                                         \
    /* a % b, signed, with a's sign; a for b = 0, 0 for b = -1. */            \
    static inline S binbun_srem##W(S a, S b) {                                \
        if (b == 0)                                                           \
            return a;                                                         \
        if (b == -1)                                                          \
            return 0;                                                         \
        return (S)(a % b);                                                    \
    }
BINBUN_EACH(BINBUN_DIVISION)

/* Divisions by a divisor not known to be safe (x86 checks and traps before
 * dividing; L0's division is total). */
#define udiv(a, b) BINBUN_UNSIGNED((a), binbun_udiv)(a, b)
#define urem(a, b) BINBUN_UNSIGNED((a), binbun_urem)(a, b)
#define sdiv(a, b) BINBUN_SIGNED((a), binbun_sdiv)(a, b)
#define srem(a, b) BINBUN_SIGNED((a), binbun_srem)(a, b)

/* ---- Floating point -------------------------------------------------------- */

/* The bits of an integer as a float, and back. */
static inline float as_f32(uint32_t bits) { float x; __builtin_memcpy(&x, &bits, 4); return x; }
static inline double as_f64(uint64_t bits) { double x; __builtin_memcpy(&x, &bits, 8); return x; }
static inline uint32_t f32_bits(float x) { uint32_t bits; __builtin_memcpy(&bits, &x, 4); return bits; }
static inline uint64_t f64_bits(double x) { uint64_t bits; __builtin_memcpy(&bits, &x, 8); return bits; }

/* a compared with b: less 1, equal 2, greater 4, unordered 8. Quietly: C's
 * < and > are the signalling comparisons, which set the invalid flag for
 * a quiet NaN (and trap where the program unmasked it). */
static inline uint8_t binbun_fcmp64(double a, double b) {
    return __builtin_isless(a, b) ? 1 : a == b ? 2 : __builtin_isgreater(a, b) ? 4 : 8;
}
static inline uint8_t binbun_fcmp32(float a, float b) { return binbun_fcmp64(a, b); }
#define fcmp(a, b) _Generic((a), float: binbun_fcmp32, double: binbun_fcmp64)(a, b)

/* x rounded as L0's rounding operand says: 0 to nearest (ties to even, in
 * the default floating-point environment), 1 down, 2 up, 3 toward zero. */
static inline double binbun_round(double x, int rounding) {
    switch (rounding) {
    case 1: return __builtin_floor(x);
    case 2: return __builtin_ceil(x);
    case 3: return __builtin_trunc(x);
    default: return __builtin_rint(x);
    }
}
/* The same for a float (exact: an integral float is a float). */
static inline float binbun_roundf(float x, int rounding) {
    return (float)binbun_round(x, rounding);
}

/* x rounded, as a `width`-bit (at most 64) signed or unsigned integer; 0
 * if it is NaN or out of range. */
static inline int64_t float_to_sint(double x, unsigned width, int rounding) {
    double r = binbun_round(x, rounding);
    double limit = __builtin_ldexp(1.0, (int)width - 1);
    return r >= -limit && r < limit ? (int64_t)r : 0;
}
static inline uint64_t float_to_uint(double x, unsigned width, int rounding) {
    double r = binbun_round(x, rounding);
    double limit = __builtin_ldexp(1.0, (int)width);
    return r >= 0 && r < limit ? (uint64_t)r : 0;
}

/* ---- Vectors (SIMD) ------------------------------------------------------- */

/* SIMD values are the compilers' vector extensions: u8x16 is 16 lanes of
 * uint8_t (128 bits), i32x8 is 8 lanes of int32_t, f64x4 4 doubles, u128x2
 * two 128-bit halves; a 256- or 512-bit value with no lanes known is u64x4
 * or u64x8 (values of up to 128 bits stay integers). The operators work
 * lane by lane with L0's meaning: + - * wrap, a comparison gives each lane
 * 0 or -1 (all ones), and a shift's count is below the lane's width. v[k]
 * is lane k (lane 0 the lowest bits); a cast between two types of the same
 * size, vectors or an integer, keeps the bits; __builtin_convertvector
 * converts lane by lane (zero or sign extension, truncation).
 *
 * Each type is aligned(1), as the compilers' own __m256i_u: no layout or
 * access assumes alignment, so *(u64x4 *)p is an unaligned load from any
 * address and a struct holds one at any offset. A vector parameter or
 * result is passed in vector registers where the target has them (AVX
 * for 256 bits, AVX-512 for 512), as the binary, whose code needs them
 * anyway, passed it; GCC's warning that the ABI differs without them is
 * off. */
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wpsabi"
#endif
#define BINBUN_VECTOR(name, T, bytes)                                         \
    typedef T name __attribute__((vector_size(bytes), aligned(1)));
#define BINBUN_VECTORS(bytes, n8, n16)                                        \
    BINBUN_VECTOR(u8x##n8, uint8_t, bytes)                                    \
    BINBUN_VECTOR(i8x##n8, int8_t, bytes)                                     \
    BINBUN_VECTOR(u16x##n16, uint16_t, bytes)                                 \
    BINBUN_VECTOR(i16x##n16, int16_t, bytes)
BINBUN_VECTORS(4, 4, 2)
BINBUN_VECTORS(8, 8, 4)
BINBUN_VECTOR(u32x2, uint32_t, 8)
BINBUN_VECTOR(i32x2, int32_t, 8)
BINBUN_VECTOR(f32x2, float, 8)
BINBUN_VECTORS(16, 16, 8)
BINBUN_VECTOR(u32x4, uint32_t, 16)
BINBUN_VECTOR(i32x4, int32_t, 16)
BINBUN_VECTOR(u64x2, uint64_t, 16)
BINBUN_VECTOR(i64x2, int64_t, 16)
BINBUN_VECTOR(f32x4, float, 16)
BINBUN_VECTOR(f64x2, double, 16)
BINBUN_VECTORS(32, 32, 16)
BINBUN_VECTOR(u32x8, uint32_t, 32)
BINBUN_VECTOR(i32x8, int32_t, 32)
BINBUN_VECTOR(u64x4, uint64_t, 32)
BINBUN_VECTOR(i64x4, int64_t, 32)
BINBUN_VECTOR(u128x2, binbun_u128, 32)
BINBUN_VECTOR(i128x2, binbun_i128, 32)
BINBUN_VECTOR(f32x8, float, 32)
BINBUN_VECTOR(f64x4, double, 32)
BINBUN_VECTORS(64, 64, 32)
BINBUN_VECTOR(u32x16, uint32_t, 64)
BINBUN_VECTOR(i32x16, int32_t, 64)
BINBUN_VECTOR(u64x8, uint64_t, 64)
BINBUN_VECTOR(i64x8, int64_t, 64)
BINBUN_VECTOR(u128x4, binbun_u128, 64)
BINBUN_VECTOR(i128x4, binbun_i128, 64)
BINBUN_VECTOR(f32x16, float, 64)
BINBUN_VECTOR(f64x8, double, 64)

/* The helpers below take vectors of any of these types (and the types the
 * compilers give comparisons, which differ between them: Clang's lanes of
 * 8 bits are `char`): macros, each argument evaluated once. */

/* A vector of type T with x (converted to the lane's type) in every lane. */
#define splat(T, x) ((T){0} + (__typeof__(((T){0})[0]))(x))

/* The lowest bit of each lane of m as an integer, lane i at bit i: L0's
 * lanes of one bit, from a comparison's 0 or -1 lanes (or 0 or 1). */
#define mask_bits(m)                                                          \
    __extension__({                                                           \
        __auto_type binbun_mask_ = (m);                                       \
        uint64_t binbun_bits_ = 0;                                            \
        for (unsigned binbun_i_ = 0;                                          \
             binbun_i_ < sizeof binbun_mask_ / sizeof binbun_mask_[0];        \
             binbun_i_++)                                                     \
            binbun_bits_ |= (uint64_t)(binbun_mask_[binbun_i_] & 1)           \
                            << binbun_i_;                                     \
        binbun_bits_;                                                         \
    })

/* A vector of type T (signed lanes) whose lane i is -1 where bit i of bits
 * is set, else 0: mask_bits undone. */
#define lanes_from_bits(T, bits)                                              \
    __extension__({                                                           \
        uint64_t binbun_bits_ = (bits);                                       \
        T binbun_lanes_;                                                      \
        for (unsigned binbun_i_ = 0;                                          \
             binbun_i_ < sizeof binbun_lanes_ / sizeof binbun_lanes_[0];      \
             binbun_i_++)                                                     \
            binbun_lanes_[binbun_i_] =                                        \
                -(__typeof__(binbun_lanes_[0]))((binbun_bits_ >> binbun_i_) & 1); \
        binbun_lanes_;                                                        \
    })

/* Each lane of a where the lane of m is all ones, of b where it is 0 (m a
 * comparison's lanes, as wide as a's; a and b of one integer type). */
#define blend(m, a, b)                                                        \
    __extension__({                                                           \
        __auto_type binbun_a_ = (a);                                          \
        __typeof__(binbun_a_) binbun_b_ = (b);                                \
        __typeof__(binbun_a_) binbun_m_ = (__typeof__(binbun_a_))(m);         \
        (binbun_a_ & binbun_m_) | (binbun_b_ & ~binbun_m_);                   \
    })

/* Lane-wise shifts of v by the lanes of n (a vector of v's size and lane
 * count), L0's meaning: from the lane's width on, 0 (shl_lanes, lshr_lanes
 * of unsigned lanes) or the sign (ashr_lanes of signed lanes). */
#define BINBUN_LANE_SHIFT(v, n, shift)                                        \
    __extension__({                                                           \
        __auto_type binbun_v_ = (v);                                          \
        __typeof__(binbun_v_) binbun_n_ = (__typeof__(binbun_v_))(n);         \
        const __typeof__(binbun_v_[0]) binbun_low_ =                          \
            (__typeof__(binbun_v_[0]))(sizeof binbun_v_[0] * 8 - 1);          \
        const __typeof__(binbun_v_[0]) binbun_high_ =                         \
            (__typeof__(binbun_v_[0]))~binbun_low_;                           \
        __typeof__(binbun_v_) binbun_past_ =                                  \
            (__typeof__(binbun_v_))((binbun_n_ & binbun_high_) != 0);         \
        shift;                                                                \
    })
#define shl_lanes(v, n)                                                       \
    BINBUN_LANE_SHIFT(v, n,                                                   \
                      (binbun_v_ << (binbun_n_ & binbun_low_)) & ~binbun_past_)
#define lshr_lanes(v, n)                                                      \
    BINBUN_LANE_SHIFT(v, n,                                                   \
                      (binbun_v_ >> (binbun_n_ & binbun_low_)) & ~binbun_past_)
#define ashr_lanes(v, n)                                                      \
    BINBUN_LANE_SHIFT(v, n,                                                   \
                      binbun_v_ >> ((binbun_n_ & binbun_low_) |               \
                                    (binbun_past_ & binbun_low_)))

/* ---- Traps and what C cannot say ------------------------------------------ */

/* Why the machine traps: L0's traps, and code that is never reached. */
enum {
    BINBUN_UNREACHABLE = -1,
    BINBUN_TRAP_DIVIDE = 0,
    BINBUN_TRAP_INVALID_INSTRUCTION = 1,
    BINBUN_TRAP_BREAKPOINT = 2,
    BINBUN_TRAP_PROTECTION = 3,
    BINBUN_TRAP_STACK = 4,
    BINBUN_TRAP_FLOATING_POINT = 5,
    BINBUN_TRAP_AUTHENTICATION = 6,
    BINBUN_TRAP_ALIGNMENT = 7,
    /* A software interrupt (binbun_interrupt): this plus its vector. */
    BINBUN_TRAP_INTERRUPT = 0x100
};

/* What C cannot say. */
enum {
    BINBUN_UNRESOLVED_JUMP = 0,
    BINBUN_FOREIGN_JUMP = 1,
    BINBUN_OVERLAPPING_CODE = 2,
    BINBUN_NON_STANDARD_CALL = 3,
    BINBUN_STACK_TRICK = 4,
    BINBUN_SYSTEM_CALL = 5
};

#ifdef BINBUN_HOOKS
_Noreturn void binbun_hook_trap(int kind);
uint64_t binbun_hook_escape(int kind, size_t count, const uint64_t *operands);
#endif

/* The machine traps (kind: BINBUN_TRAP_...). */
static inline _Noreturn void binbun_trap(int kind) {
#ifdef BINBUN_HOOKS
    binbun_hook_trap(kind);
#else
    (void)kind;
    __builtin_trap();
#endif
}

/* Control never gets here (after a call that does not return). */
static inline _Noreturn void binbun_unreachable(void) { binbun_trap(BINBUN_UNREACHABLE); }

/* A software interrupt (x86 `int vector`): control passes to the handler
 * of the vector, which the platform defines; Windows' vector 0x29 is
 * __fastfail, which ends the process. */
static inline _Noreturn void binbun_interrupt(int vector) {
    binbun_trap(BINBUN_TRAP_INTERRUPT + vector);
}

/* x86-64's check of an address (L0's before each access through a pointer
 * and each indirect jump or call): the machine traps with #GP
 * (binbun_check_canonical) or, for an address based on rsp or rbp, #SS
 * (binbun_check_canonical_stack) unless the 64 bits of p are a canonical
 * 48-bit address (bits 63 to 47 all equal). p is any scalar (an integer,
 * a data or a code pointer), evaluated once; the statement is exactly
 *     if ((uint64_t)sext_n((uint64_t)p, 48) != (uint64_t)p)
 *         binbun_trap(BINBUN_TRAP_PROTECTION);
 * (BINBUN_TRAP_STACK for the second). */
#define binbun_check_canonical(p)                                             \
    BINBUN_CHECK_CANONICAL((p), BINBUN_TRAP_PROTECTION)
#define binbun_check_canonical_stack(p)                                       \
    BINBUN_CHECK_CANONICAL((p), BINBUN_TRAP_STACK)
#define BINBUN_CHECK_CANONICAL(p, kind)                                       \
    do {                                                                      \
        uint64_t binbun_address_ = (uint64_t)(p);                             \
        if ((uint64_t)binbun_sext_n64(binbun_address_, 48) != binbun_address_) \
            binbun_trap(kind);                                                \
    } while (0)

/* ---- C++ exceptions -------------------------------------------------------- */

/* BINBUN_TRY { body } BINBUN_CATCH(std::exception) { handler } ...: the
 * body runs; an exception unwinding out of one of its calls would enter
 * the first handler that matches (C cannot throw, so none ever runs, but
 * they compile and are type-checked). The argument names the caught type
 * as C++ does and is dropped. A BINBUN_CLEANUP or BINBUN_UNEXPECTED(types)
 * handler propagates the exception at its end (destructors of locals; a
 * dynamic exception specification); a BINBUN_LANDING handler is a landing
 * pad whose clauses were not recognised, which reads the runtime's raw
 * state. `else if (0)` lets any number of handlers chain. */
#define BINBUN_TRY if (1)
#define BINBUN_CATCH(...) else if (0)
#define BINBUN_CATCH_ALL else if (0)
#define BINBUN_CLEANUP else if (0)
#define BINBUN_UNEXPECTED(...) else if (0)
#define BINBUN_LANDING else if (0)

/* In a handler: the exception object (what __cxa_begin_catch takes), and
 * which clause of the runtime's table matched (the Itanium C++ ABI's
 * selector). */
static inline void *binbun_exception(void) { binbun_unreachable(); }
static inline intptr_t binbun_selector(void) { binbun_unreachable(); }

/* ---- Structured exception handling (Microsoft x64) ------------------------ */

/* BINBUN_SEH_TRY { body } BINBUN_EXCEPT(1) { handler }: MSVC's __try {
 * body } __except (1) { handler }: the handler runs when an exception (a
 * fault, RaiseException) reaches it and the filter takes it; with GCC and
 * Clang, which have no __try, the body runs and the handler never does,
 * as for BINBUN_TRY. BINBUN_EXCEPT_FUNCLET(address) names a filter
 * expression by the address of its funclet (the code that evaluates it).
 * In the handler, binbun_exception_code() is GetExceptionCode().
 * BINBUN_FINALLY { handler } is a __finally block as the runtime runs it
 * when an exception unwinds out of the body (its funclet's code; MSVC
 * compiles the way out without an exception apart, and that code follows
 * the try), in which binbun_abnormal_termination() is
 * AbnormalTermination(). */
#define BINBUN_SEH_TRY if (1)
#define BINBUN_EXCEPT(...) else if (0)
#define BINBUN_EXCEPT_FUNCLET(...) else if (0)
#define BINBUN_FINALLY else if (0)
static inline uint32_t binbun_exception_code(void) { binbun_unreachable(); }
static inline int32_t binbun_abnormal_termination(void) { binbun_unreachable(); }

/* The results of the last escape after the first (which it returns). */
static _Thread_local uint64_t binbun_results[8];
static inline uint64_t binbun_result(size_t index) {
    return index < 8 ? binbun_results[index] : 0;
}

/* A system call: operands[0] the number, then the arguments, in the
 * convention's registers (Linux: rax, rdi, rsi, rdx, r10, r8, r9 on
 * x86-64; x8, x0-x5 on AArch64). */
static inline uint64_t binbun_system_call(size_t count, const uint64_t *operands) {
    uint64_t v[7] = {0};
    for (size_t i = 0; i < count && i < 7; i++)
        v[i] = operands[i];
#if defined(__x86_64__)
    register uint64_t rax __asm__("rax") = v[0];
    register uint64_t rdi __asm__("rdi") = v[1];
    register uint64_t rsi __asm__("rsi") = v[2];
    register uint64_t rdx __asm__("rdx") = v[3];
    register uint64_t r10 __asm__("r10") = v[4];
    register uint64_t r8 __asm__("r8") = v[5];
    register uint64_t r9 __asm__("r9") = v[6];
    __asm__ volatile("syscall"
                     : "+r"(rax)
                     : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return rax;
#elif defined(__aarch64__)
    register uint64_t x8 __asm__("x8") = v[0];
    register uint64_t x0 __asm__("x0") = v[1];
    register uint64_t x1 __asm__("x1") = v[2];
    register uint64_t x2 __asm__("x2") = v[3];
    register uint64_t x3 __asm__("x3") = v[4];
    register uint64_t x4 __asm__("x4") = v[5];
    register uint64_t x5 __asm__("x5") = v[6];
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
#else
    __builtin_trap();
#endif
}

/* An escape of `kind` (BINBUN_...) with its operands' values: a system
 * call is made; anything else traps. Returns the first result. */
static inline uint64_t binbun_escape(int kind, size_t count, const uint64_t *operands) {
#ifdef BINBUN_HOOKS
    return binbun_hook_escape(kind, count, operands);
#else
    if (kind == BINBUN_SYSTEM_CALL)
        return binbun_system_call(count, operands);
    __builtin_trap();
#endif
}

/* An escape that does not come back (a jump). */
static inline _Noreturn void binbun_escape_jump(int kind, size_t count, const uint64_t *operands) {
    (void)binbun_escape(kind, count, operands);
    __builtin_trap();
}

/* ---- The thread pointer ------------------------------------------------------ */

/* ELF platforms: __builtin_thread_pointer(), the TLS ABI's thread pointer
 * (on x86-64 it reads %fs:0, where the ABI keeps the thread control
 * block's own address): a compiler builtin, on x86 from GCC 11. */

/* x86-64 glibc: the thread pointer as a pointer to its thread control
 * block, tcbhead_t (the output defines the struct with the fields it
 * reads: stack_guard at 0x28, the stack protector's canary). Defined
 * where the compiler has the builtin, an AArch64 host's too (a Mac's):
 * there an x86-64 program's C compiles, though the host's thread pointer
 * is not the program's. Not on Windows, whose compilers have no such
 * builtin and whose threads have no tcbhead_t (their TEB is below). */
#if (defined(__x86_64__) || defined(__aarch64__)) && !defined(_WIN32)
struct tcbhead_t;
static inline struct tcbhead_t *binbun_tcb(void) {
    return (struct tcbhead_t *)__builtin_thread_pointer();
}
#endif

/* Windows x64: the thread's TEB is in gs. Microsoft's intrinsics read and
 * write at an offset in it (__readgsqword(0x30)), and NtCurrentTeb()
 * gives its address (the TEB's NT_TIB.Self field, at 0x30). Defined here
 * for GCC and Clang, as mingw-w64's <intrin.h> does, but where Clang has
 * the intrinsics itself (Microsoft mode), which <intrin.h> declares. Each
 * access is one segment-relative mov, ordered with other memory accesses
 * (the TEB is ordinary memory too). */
#if defined(__x86_64__)
#define BINBUN_GS(size, T)                                                    \
    static inline T __readgs##size(unsigned long offset) {                    \
        T value;                                                              \
        __asm__ volatile("mov %%gs:(%1), %0" : "=q"(value) : "r"(offset)      \
                         : "memory");                                         \
        return value;                                                         \
    }                                                                         \
    static inline void __writegs##size(unsigned long offset, T value) {       \
        __asm__ volatile("mov %0, %%gs:(%1)" : : "q"(value), "r"(offset)      \
                         : "memory");                                         \
    }
#if defined(__has_builtin)
#if __has_builtin(__readgsqword)
#define BINBUN_GS_BUILTINS 1
#endif
#endif
#if defined(BINBUN_GS_BUILTINS)
#include <intrin.h>
#else
BINBUN_GS(byte, uint8_t)
BINBUN_GS(word, uint16_t)
BINBUN_GS(dword, uint32_t)
BINBUN_GS(qword, uint64_t)
#endif
/* As winnt.h declares it: a pointer to the TEB (the output defines struct
 * _TEB, phnt's, with the fields it reads). */
struct _TEB;
static inline struct _TEB *NtCurrentTeb(void) {
    return (struct _TEB *)(uintptr_t)__readgsqword(0x30);
}
/* Kernel mode: gs holds the processor's control region instead, and
 * KeGetPcr() gives its address (the KPCR's Self field, at 0x18), as the
 * WDK's wdm.h defines it. */
struct _KPCR;
static inline struct _KPCR *KeGetPcr(void) {
    return (struct _KPCR *)(uintptr_t)__readgsqword(0x18);
}
#endif

/* Windows ARM64: the platform register x18 holds the thread's TEB (in
 * kernel mode the processor's KPCR), which winnt.h's NtCurrentTeb() and
 * wdm.h's KeGetPcr() read (__getReg(18)); memory relative to it is
 * ordinary memory, reached through the pointer. */
#if defined(__aarch64__)
struct _TEB;
static inline struct _TEB *NtCurrentTeb(void) {
    struct _TEB *teb;
    __asm__("mov %0, x18" : "=r"(teb));
    return teb;
}
struct _KPCR;
static inline struct _KPCR *KeGetPcr(void) {
    struct _KPCR *pcr;
    __asm__("mov %0, x18" : "=r"(pcr));
    return pcr;
}
#endif

/* ---- The floating-point control registers ------------------------------------- */

/* A function that keeps the floating-point controls its caller set (the
 * conventions make them callee-saved) reads them, and the status flags
 * the caller left, from the register at entry: binbun_read_<register>(),
 * read once into a local first thing. x86-64: MXCSR (stmxcsr) and the x87
 * control word (fnstcw); AArch64: FPCR's architected (low 32) bits. On
 * another architecture they trap, like a system call. */
static inline uint32_t binbun_read_mxcsr(void) {
#if defined(__x86_64__)
    uint32_t value;
    __asm__ volatile("stmxcsr %0" : "=m"(value));
    return value;
#else
    __builtin_trap();
#endif
}
static inline uint16_t binbun_read_fcw(void) {
#if defined(__x86_64__)
    uint16_t value;
    __asm__ volatile("fnstcw %0" : "=m"(value));
    return value;
#else
    __builtin_trap();
#endif
}
static inline uint32_t binbun_read_fpcr(void) {
#if defined(__aarch64__)
    uint64_t value;
    __asm__ volatile("mrs %0, fpcr" : "=r"(value));
    return (uint32_t)value;
#else
    __builtin_trap();
#endif
}

/* ---- Floating point under the program's rounding, and its exceptions ----------- */

/* An instruction of the machine's, run for its result under a rounding
 * the program chose or for the exceptions it raises: MXCSR is set to that
 * rounding (L0's 0 to nearest, 1 down, 2 up, 3 toward zero, which is the
 * register's own encoding) with every exception masked and no flag set,
 * the instruction runs, the flags it left are read and MXCSR is put back
 * with those flags set too, as the instruction would have left it (the
 * function reads the register once, at entry, so this changes nothing it
 * computes; a caller that tests the flags afterwards finds them).
 * The flags are IEEE's five as L0 numbers them: invalid 1, division by
 * zero 2, overflow 4, underflow 8, inexact 16 (the machine's
 * denormal-operand flag is not one of them: the program's own code tells
 * it from the operands). A NaN result is L0's default NaN: which NaN the
 * machine gives is the program's code around the operation too. The
 * instruction is written out, so that a compiler, which does not know the
 * register changed, neither moves nor folds it. On another architecture
 * they trap, like the readers above. */
#if defined(__x86_64__)
static inline void binbun_load_mxcsr(uint32_t value) {
    __asm__ volatile("ldmxcsr %0" : : "m"(value));
}
#define BINBUN_FLOAT_RUN(rounding, flags, ...)                                \
    do {                                                                      \
        uint32_t binbun_kept = binbun_read_mxcsr();                           \
        binbun_load_mxcsr(0x1f80u | ((uint32_t)(rounding) & 3u) << 13);       \
        __asm__ volatile(__VA_ARGS__);                                        \
        uint32_t binbun_left = binbun_read_mxcsr();                           \
        binbun_load_mxcsr(binbun_kept | (binbun_left & 0x3fu));               \
        *(flags) = (uint8_t)((binbun_left & 1u) | (binbun_left >> 2 & 0xfu) << 1); \
    } while (0)
#else
#define BINBUN_FLOAT_RUN(rounding, flags, ...)                                \
    do {                                                                      \
        *(flags) = (uint8_t)(rounding);                                       \
        __builtin_trap();                                                     \
    } while (0)
#endif

/* By the bits: a comparison would raise flags of its own in the caller's
 * register. A NaN as the default one; whether one of a and b is a zero
 * and the other an infinity. */
static inline float binbun_fnan32(float x) {
    return (f32_bits(x) & 0x7fffffffu) > 0x7f800000u ? as_f32(0x7fc00000u) : x;
}
static inline double binbun_fnan64(double x) {
    return (f64_bits(x) & 0x7fffffffffffffffu) > 0x7ff0000000000000u
               ? as_f64(0x7ff8000000000000u)
               : x;
}
static inline bool binbun_fzero_infinity32(float a, float b) {
    uint32_t x = f32_bits(a) & 0x7fffffffu, y = f32_bits(b) & 0x7fffffffu;
    return (x == 0 && y == 0x7f800000u) || (x == 0x7f800000u && y == 0);
}
static inline bool binbun_fzero_infinity64(double a, double b) {
    uint64_t x = f64_bits(a) & 0x7fffffffffffffffu;
    uint64_t y = f64_bits(b) & 0x7fffffffffffffffu;
    return (x == 0 && y == 0x7ff0000000000000u) ||
           (x == 0x7ff0000000000000u && y == 0);
}

/* Each operation is three functions: the one that runs it and gives its
 * flags too (binbun_f<op>_run<W>, W the operand's width), its result
 * (binbun_f<op><W>) and its flags (binbun_f<op>_status<W>). */

/* a op b, of type T. */
#define BINBUN_FLOAT_BINARY(op, W, T, instruction)                            \
    static inline T binbun_f##op##_run##W(T a, T b, int rounding,             \
                                          uint8_t *flags) {                   \
        T r = a;                                                              \
        (void)b;                                                              \
        BINBUN_FLOAT_RUN(rounding, flags,                                     \
                         instruction " {%1, %0|%0, %1}" : "+x"(r) : "xm"(b)); \
        return binbun_fnan##W(r);                                             \
    }                                                                         \
    static inline T binbun_f##op##W(T a, T b, int rounding) {                 \
        uint8_t flags;                                                        \
        return binbun_f##op##_run##W(a, b, rounding, &flags);                 \
    }                                                                         \
    static inline uint8_t binbun_f##op##_status##W(T a, T b, int rounding) {  \
        uint8_t flags;                                                        \
        (void)binbun_f##op##_run##W(a, b, rounding, &flags);                  \
        return flags;                                                         \
    }
BINBUN_FLOAT_BINARY(add, 32, float, "addss")
BINBUN_FLOAT_BINARY(add, 64, double, "addsd")
BINBUN_FLOAT_BINARY(sub, 32, float, "subss")
BINBUN_FLOAT_BINARY(sub, 64, double, "subsd")
BINBUN_FLOAT_BINARY(mul, 32, float, "mulss")
BINBUN_FLOAT_BINARY(mul, 64, double, "mulsd")
BINBUN_FLOAT_BINARY(div, 32, float, "divss")
BINBUN_FLOAT_BINARY(div, 64, double, "divsd")

/* An operation on one operand of type A (in a register of class `from`)
 * giving an R (in one of class `to`), finished by `finish`. */
#define BINBUN_FLOAT_UNARY(op, W, R, A, to, from, finish, instruction)        \
    static inline R binbun_f##op##_run##W(A a, int rounding, uint8_t *flags) { \
        R r = 0;                                                              \
        (void)a;                                                              \
        BINBUN_FLOAT_RUN(rounding, flags, instruction : to(r) : from(a));     \
        return finish(r);                                                     \
    }                                                                         \
    static inline R binbun_f##op##W(A a, int rounding) {                      \
        uint8_t flags;                                                        \
        return binbun_f##op##_run##W(a, rounding, &flags);                    \
    }                                                                         \
    static inline uint8_t binbun_f##op##_status##W(A a, int rounding) {       \
        uint8_t flags;                                                        \
        (void)binbun_f##op##_run##W(a, rounding, &flags);                     \
        return flags;                                                         \
    }
#define BINBUN_FLOAT_AS_IS(x) (x)
BINBUN_FLOAT_UNARY(sqrt, 32, float, float, "=x", "xm", binbun_fnan32,
                   "sqrtss {%1, %0|%0, %1}")
BINBUN_FLOAT_UNARY(sqrt, 64, double, double, "=x", "xm", binbun_fnan64,
                   "sqrtsd {%1, %0|%0, %1}")
/* To an integral value, as the register's rounding says (SSE4.1). */
BINBUN_FLOAT_UNARY(round, 32, float, float, "=x", "xm", binbun_fnan32,
                   "roundss {$4, %1, %0|%0, %1, 4}")
BINBUN_FLOAT_UNARY(round, 64, double, double, "=x", "xm", binbun_fnan64,
                   "roundsd {$4, %1, %0|%0, %1, 4}")
/* To the other format. */
BINBUN_FLOAT_UNARY(convert, 32, double, float, "=x", "xm", binbun_fnan64,
                   "cvtss2sd {%1, %0|%0, %1}")
BINBUN_FLOAT_UNARY(convert, 64, float, double, "=x", "xm", binbun_fnan32,
                   "cvtsd2ss {%1, %0|%0, %1}")
/* A signed integer of W bits as a float (f32) or a double (f64). */
BINBUN_FLOAT_UNARY(32_from_sint, 32, float, int32_t, "=x", "r",
                   BINBUN_FLOAT_AS_IS, "cvtsi2ss {%1, %0|%0, %1}")
BINBUN_FLOAT_UNARY(32_from_sint, 64, float, int64_t, "=x", "r",
                   BINBUN_FLOAT_AS_IS, "cvtsi2ss {%1, %0|%0, %1}")
BINBUN_FLOAT_UNARY(64_from_sint, 32, double, int32_t, "=x", "r",
                   BINBUN_FLOAT_AS_IS, "cvtsi2sd {%1, %0|%0, %1}")
BINBUN_FLOAT_UNARY(64_from_sint, 64, double, int64_t, "=x", "r",
                   BINBUN_FLOAT_AS_IS, "cvtsi2sd {%1, %0|%0, %1}")
/* A float (W 32) or a double (64) as a signed integer of 32 or 64 bits:
 * the machine's own conversion, whose result where it is invalid is not
 * L0's, so only the flags of these are used (float_to_sint gives the
 * value). */
BINBUN_FLOAT_UNARY(to_sint32, 32, int32_t, float, "=r", "xm",
                   BINBUN_FLOAT_AS_IS, "cvtss2si {%1, %0|%0, %1}")
BINBUN_FLOAT_UNARY(to_sint32, 64, int32_t, double, "=r", "xm",
                   BINBUN_FLOAT_AS_IS, "cvtsd2si {%1, %0|%0, %1}")
BINBUN_FLOAT_UNARY(to_sint64, 32, int64_t, float, "=r", "xm",
                   BINBUN_FLOAT_AS_IS, "cvtss2si {%1, %0|%0, %1}")
BINBUN_FLOAT_UNARY(to_sint64, 64, int64_t, double, "=r", "xm",
                   BINBUN_FLOAT_AS_IS, "cvtsd2si {%1, %0|%0, %1}")

/* a * b + c, rounded once (FMA3). Zero times infinity is invalid in L0
 * whatever c is; the machine does not say so where c is a quiet NaN. */
#define BINBUN_FLOAT_FMA(W, T, instruction)                                   \
    static inline T binbun_ffma_run##W(T a, T b, T c, int rounding,           \
                                       uint8_t *flags) {                      \
        T r = c;                                                              \
        (void)a, (void)b;                                                     \
        BINBUN_FLOAT_RUN(rounding, flags,                                     \
                         instruction " {%2, %1, %0|%0, %1, %2}"               \
                         : "+x"(r) : "x"(a), "xm"(b));                        \
        if (binbun_fzero_infinity##W(a, b))                                   \
            *flags |= 1;                                                      \
        return binbun_fnan##W(r);                                             \
    }                                                                         \
    static inline T binbun_ffma##W(T a, T b, T c, int rounding) {             \
        uint8_t flags;                                                        \
        return binbun_ffma_run##W(a, b, c, rounding, &flags);                 \
    }                                                                         \
    static inline uint8_t binbun_ffma_status##W(T a, T b, T c, int rounding) { \
        uint8_t flags;                                                        \
        (void)binbun_ffma_run##W(a, b, c, rounding, &flags);                  \
        return flags;                                                         \
    }
BINBUN_FLOAT_FMA(32, float, "vfmadd231ss")
BINBUN_FLOAT_FMA(64, double, "vfmadd231sd")

/* The flags of comparing a with b: invalid for a signalling NaN, and in
 * the signalling comparison for any NaN. */
#define BINBUN_FLOAT_COMPARE(name, W, T, instruction)                         \
    static inline uint8_t binbun_f##name##_status##W(T a, T b) {              \
        uint8_t flags;                                                        \
        (void)a, (void)b;                                                     \
        BINBUN_FLOAT_RUN(0, &flags,                                           \
                         instruction " {%1, %0|%0, %1}"                       \
                         : : "x"(a), "xm"(b) : "cc");                         \
        return flags;                                                         \
    }
BINBUN_FLOAT_COMPARE(compare, 32, float, "ucomiss")
BINBUN_FLOAT_COMPARE(compare, 64, double, "ucomisd")
BINBUN_FLOAT_COMPARE(compare_signaling, 32, float, "comiss")
BINBUN_FLOAT_COMPARE(compare_signaling, 64, double, "comisd")

/* The operations by their operands' types: float_add(a, b, rounding) is
 * the sum, float_add_status(a, b, rounding) its flags. */
#define BINBUN_FLOAT(x, name) _Generic((x), float: name##32, double: name##64)
#define BINBUN_SINT(x, name)                                                  \
    _Generic((x), int: name##32,                                              \
             long: BINBUN_CAT(name, BINBUN_LONG_BITS), long long: name##64)
#define float_add(a, b, r) BINBUN_FLOAT((a), binbun_fadd)(a, b, r)
#define float_sub(a, b, r) BINBUN_FLOAT((a), binbun_fsub)(a, b, r)
#define float_mul(a, b, r) BINBUN_FLOAT((a), binbun_fmul)(a, b, r)
#define float_div(a, b, r) BINBUN_FLOAT((a), binbun_fdiv)(a, b, r)
#define float_sqrt(a, r) BINBUN_FLOAT((a), binbun_fsqrt)(a, r)
#define float_fma(a, b, c, r) BINBUN_FLOAT((a), binbun_ffma)(a, b, c, r)
#define float_convert(a, r) BINBUN_FLOAT((a), binbun_fconvert)(a, r)
#define f32_from_sint(a, r) BINBUN_SINT((a), binbun_f32_from_sint)(a, r)
#define f64_from_sint(a, r) BINBUN_SINT((a), binbun_f64_from_sint)(a, r)
#define float_add_status(a, b, r) BINBUN_FLOAT((a), binbun_fadd_status)(a, b, r)
#define float_sub_status(a, b, r) BINBUN_FLOAT((a), binbun_fsub_status)(a, b, r)
#define float_mul_status(a, b, r) BINBUN_FLOAT((a), binbun_fmul_status)(a, b, r)
#define float_div_status(a, b, r) BINBUN_FLOAT((a), binbun_fdiv_status)(a, b, r)
#define float_sqrt_status(a, r) BINBUN_FLOAT((a), binbun_fsqrt_status)(a, r)
#define float_fma_status(a, b, c, r)                                          \
    BINBUN_FLOAT((a), binbun_ffma_status)(a, b, c, r)
#define float_round_status(a, r) BINBUN_FLOAT((a), binbun_fround_status)(a, r)
#define float_convert_status(a, r)                                            \
    BINBUN_FLOAT((a), binbun_fconvert_status)(a, r)
#define f32_from_sint_status(a, r)                                            \
    BINBUN_SINT((a), binbun_f32_from_sint_status)(a, r)
#define f64_from_sint_status(a, r)                                            \
    BINBUN_SINT((a), binbun_f64_from_sint_status)(a, r)
#define float_to_sint32_status(a, r)                                          \
    BINBUN_FLOAT((a), binbun_fto_sint32_status)(a, r)
#define float_to_sint64_status(a, r)                                          \
    BINBUN_FLOAT((a), binbun_fto_sint64_status)(a, r)
#define float_compare_status(a, b)                                            \
    BINBUN_FLOAT((a), binbun_fcompare_status)(a, b)
#define float_compare_signaling_status(a, b)                                  \
    BINBUN_FLOAT((a), binbun_fcompare_signaling_status)(a, b)

/* The number of operands and a pointer to them, from a list that may be
 * empty. */
#define BINBUN_OPERANDS(...)                                                  \
    (sizeof((const uint64_t[]){0, __VA_ARGS__}) / sizeof(uint64_t) - 1),      \
        ((const uint64_t[]){0, __VA_ARGS__} + 1)

/* A computed jump whose targets are not known (operand: the address). */
#define binbun_unresolved_jump(...)                                           \
    binbun_escape_jump(BINBUN_UNRESOLVED_JUMP, BINBUN_OPERANDS(__VA_ARGS__))
/* A jump into another function's body (operand: the address). */
#define binbun_foreign_jump(...)                                              \
    binbun_escape_jump(BINBUN_FOREIGN_JUMP, BINBUN_OPERANDS(__VA_ARGS__))
/* Code that overlaps other code (operand: the address it runs at). */
#define binbun_overlapping_code(...)                                          \
    binbun_escape_jump(BINBUN_OVERLAPPING_CODE, BINBUN_OPERANDS(__VA_ARGS__))
/* A call no C convention makes (operands: the target, then the values). */
#define binbun_non_standard_call(...)                                         \
    binbun_escape(BINBUN_NON_STANDARD_CALL, BINBUN_OPERANDS(__VA_ARGS__))
/* Stack use the stack analysis cannot follow (operands: the values). */
#define binbun_stack_trick(...)                                               \
    binbun_escape(BINBUN_STACK_TRICK, BINBUN_OPERANDS(__VA_ARGS__))
/* A system call (operands: the number, then the arguments). */
#define binbun_syscall(...)                                                   \
    binbun_escape(BINBUN_SYSTEM_CALL, BINBUN_OPERANDS(__VA_ARGS__))

/* The memory accesses of an atomic read-modify-write the decompiler did
 * not turn into one C operation: each access is atomic (sequentially
 * consistent), the group is not. */
#define BINBUN_ATOMIC(W, T, S)                                                \
    static inline T binbun_atomic_load##W(void *address) {                    \
        return __atomic_load_n((T *)address, __ATOMIC_SEQ_CST);               \
    }                                                                         \
    static inline void binbun_atomic_store##W(void *address, T value) {       \
        __atomic_store_n((T *)address, value, __ATOMIC_SEQ_CST);              \
    }
BINBUN_EACH(BINBUN_ATOMIC)

/* An atomic read-modify-write, one operation as the locked instruction it
 * was (sequentially consistent): the memory at address read, changed and
 * written back, and the value read given. A compare-and-exchange stores
 * desired where it reads expected. */
#define BINBUN_ATOMIC_FETCH(W, T, name)                                       \
    static inline T binbun_atomic_##name##W(void *address, T value) {         \
        return __atomic_##name((T *)address, value, __ATOMIC_SEQ_CST);        \
    }
#define BINBUN_ATOMIC_UPDATE(W, T, S)                                         \
    static inline T binbun_atomic_exchange##W(void *address, T value) {       \
        return __atomic_exchange_n((T *)address, value, __ATOMIC_SEQ_CST);    \
    }                                                                         \
    BINBUN_ATOMIC_FETCH(W, T, fetch_add)                                      \
    BINBUN_ATOMIC_FETCH(W, T, fetch_sub)                                      \
    BINBUN_ATOMIC_FETCH(W, T, fetch_and)                                      \
    BINBUN_ATOMIC_FETCH(W, T, fetch_or)                                       \
    BINBUN_ATOMIC_FETCH(W, T, fetch_xor)                                      \
    static inline T binbun_atomic_compare_exchange##W(void *address,          \
                                                      T expected, T desired) { \
        __atomic_compare_exchange_n((T *)address, &expected, desired, 0,      \
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);      \
        return expected;                                                      \
    }
BINBUN_EACH(BINBUN_ATOMIC_UPDATE)

/* ---- Instructions without semantics ------------------------------------------ */

/* An instruction binbun has no semantics for, by its text (as the listing
 * shows it): unlifted("kmovd eax, k1") where the code after it reads
 * nothing it writes, v = unlifted_u32("kmovd eax, k1") where it reads one
 * value, unlifted("vcomisd xmm16, xmm17", &t0, &t1) where several (each
 * output's address). The C compiles but does not compute it: to the
 * compiler, what it gives is unknown (an empty asm writes it) and memory
 * may change (a memory clobber), so nothing is folded across it. */
static inline void unlifted(const char *instruction, ...) {
    va_list outputs;
    va_start(outputs, instruction);
    __asm__ volatile("" : : "r"(instruction), "r"(&outputs) : "memory");
    va_end(outputs);
}
static inline bool unlifted_bool(const char *instruction) {
    bool value;
    __asm__ volatile("" : "=m"(value) : "r"(instruction) : "memory");
    return value;
}
#define BINBUN_UNLIFTED(W, T, S)                                              \
    static inline T unlifted_u##W(const char *instruction) {                  \
        T value;                                                              \
        __asm__ volatile("" : "=m"(value) : "r"(instruction) : "memory");     \
        return value;                                                         \
    }
BINBUN_EACH(BINBUN_UNLIFTED)
BINBUN_UNLIFTED(256, u64x4, u64x4)
BINBUN_UNLIFTED(512, u64x8, u64x8)

/* ---- Values the architecture leaves undefined ----------------------------- */

/* A value an instruction leaves undefined (SHRD's OF and AF, BSF's
 * destination of a zero source), which processors set differently: AMD,
 * Intel's P-cores and its E-cores do not agree. binbun_undefined_bool() for
 * a flag, binbun_undefined_u32() for 32 bits (a narrower value in the next
 * width up, only its low bits meaningful). The C compiles, but the value is
 * unknown to the compiler (an empty asm writes it), and each call is its own
 * (volatile): nothing is folded from it, no branch on it is dropped. */
static inline bool binbun_undefined_bool(void) {
    bool value;
    __asm__ volatile("" : "=m"(value));
    return value;
}
#define BINBUN_UNDEFINED(W, T, S)                                             \
    static inline T binbun_undefined_u##W(void) {                             \
        T value;                                                              \
        __asm__ volatile("" : "=m"(value));                                  \
        return value;                                                         \
    }
BINBUN_EACH(BINBUN_UNDEFINED)
BINBUN_UNDEFINED(256, u64x4, u64x4)
BINBUN_UNDEFINED(512, u64x8, u64x8)

#endif /* BINBUN_DEFS_H */
