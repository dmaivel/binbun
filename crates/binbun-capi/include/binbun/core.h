/* binbun/core.h: what every part of binbun's C API (libbinbun) shares: the
 * library's version, the status a call returns, and the string the library
 * returns. Included by each part's header (binbun/disasm.h); include
 * binbun/binbun.h for all of them.
 *
 * Conventions every part keeps (each part's header adds its own):
 *
 * - Every function catches internal failures (Rust panics) rather than
 *   letting them leave the library: a function returning a status returns
 *   BINBUN_STATUS_FAILED, the others their documented failure value (0, an
 *   empty string, false). This needs the library built with
 *   `panic = "unwind"`, the default.
 * - A status has one meaning across the library. Values 0 to 15 are the
 *   ones below, about the call; each part defines its own in a range of its
 *   own (the disassemblers' 16 to 63, in binbun/disasm.h).
 * - Within one major version, minor and patch versions only add functions,
 *   statuses and enumerators: the ABI stays the same.
 */
#ifndef BINBUN_CORE_H
#define BINBUN_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------
 * Version
 * ---------------------------------------------------------------------- */

#define BINBUN_VERSION_MAJOR 0
#define BINBUN_VERSION_MINOR 1
#define BINBUN_VERSION_PATCH 0
/* The version this header describes, major << 16 | minor << 8 | patch. */
#define BINBUN_VERSION ((BINBUN_VERSION_MAJOR << 16) | (BINBUN_VERSION_MINOR << 8) | BINBUN_VERSION_PATCH)

/* The version of the library loaded, to compare with BINBUN_VERSION: the
 * ABI is the same within one major version. */
uint32_t binbun_version(void);

/* Marks a function kept under a former name. */
#if defined(__GNUC__) || defined(__clang__)
#define BINBUN_DEPRECATED(message) __attribute__((deprecated(message)))
#elif defined(_MSC_VER)
#define BINBUN_DEPRECATED(message) __declspec(deprecated(message))
#else
#define BINBUN_DEPRECATED(message)
#endif

/* ------------------------------------------------------------------------
 * Status
 * ---------------------------------------------------------------------- */

/* What a call came to: one of the values below, or one of a part's own
 * (binbun/disasm.h's from 16). */
typedef int32_t binbun_status;
enum {
    /* Done. */
    BINBUN_STATUS_OK = 0,
    /* An iteration has nothing left (a decoder no bytes); nothing was
     * written. */
    BINBUN_STATUS_END = 1,
    /* The input ends before what it holds does (bytes before the end of an
     * instruction). */
    BINBUN_STATUS_TRUNCATED = 2,
    /* A pointer the call needs is null. */
    BINBUN_STATUS_NULL_POINTER = 3,
    /* An argument has no meaning: an unknown mode, misaligned storage. */
    BINBUN_STATUS_BAD_ARGUMENT = 4,
    /* The library failed internally (a bug); nothing was written. */
    BINBUN_STATUS_FAILED = 5,
};

/* A string that is not NUL-terminated: `length` bytes at `data`, which is
 * never null. */
typedef struct binbun_str {
    const char *data;
    size_t length;
} binbun_str;

/* What a status means, in a few words; empty for a number that is none. */
binbun_str binbun_status_name(binbun_status status);

#ifdef __cplusplus
}
#endif

#endif /* BINBUN_CORE_H */
