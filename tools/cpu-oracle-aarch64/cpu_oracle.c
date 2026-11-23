/* This machine's CPU as a test oracle for binbun's AArch64 lifter.
 *
 * Runs one instruction at a time from a given state and reports the state
 * after it, or the fault it raised. Linux AArch64 user mode (natively, or
 * under qemu-aarch64). Reads one case per line from stdin and prints
 * exactly one line per input line, in order, flushed per line; all numbers
 * are lowercase hex without 0x:
 *
 *     case CODE-ADDRESS WORD [NAME=VALUE ...] [mem=ADDRESS:BYTES ...]
 *
 * WORD (the 32-bit instruction word, up to 8 hex digits, as Arm writes it)
 * is placed little-endian at CODE-ADDRESS (a multiple of 4), on a page
 * mapped read+exec for the case whose other bytes are 0. NAME is one of x0
 * ... x30, sp, nzcv (the flags N Z C V as bits 3 to 0) or btype (PSTATE.BTYPE,
 * 0 to 3); unlisted registers start as 0. Each mem= maps the pages
 * containing ADDRESS..ADDRESS+len read-write (other bytes 0) and fills them
 * with BYTES; regions may share pages, also with the code (such pages are
 * read-write-exec, and the word wins where they overlap).
 *
 * Floating-point state: NAME may also be v0 ... v31 (128 bits, up to 32
 * hex digits), fpcr or fpsr. If a line names any of them, the case runs
 * with all of this state, the unnamed parts 0, and the answer reports it
 * (FP below); otherwise the state is as the process has it and is not
 * reported. FPCR and FPSR bits the processor does not implement read back
 * as 0. Answers:
 *
 * System state: NAME may also be tpidr_el0 (the thread pointer), dit, ssbs
 * or tco (PSTATE bits, 0 or 1). If a line names any of them, the case runs
 * with all of them (unnamed ones 0) and the answer reports them and
 * tpidrro_el0 (SYS below: tpidr_el0=HEX tpidrro_el0=HEX dit=HEX ssbs=HEX
 * tco=HEX, after btype); otherwise the thread pointer is the process's and
 * the PSTATE bits as the process has them, not reported.
 *
 *     ok pc=HEX x0=HEX ... x30=HEX sp=HEX nzcv=HEX btype=HEX [SYS] [FP] [mem=ADDRESS:BYTES ...]
 *     fault SIGNAL code=SI_CODE addr=SI_ADDR pc=HEX ... btype=HEX [SYS] [FP] [mem=...]
 *     skip REASON
 *     error REASON
 *
 * Registers are always pc x0 ... x30 sp nzcv btype; mem= lists every input
 * region, same address and length, with its contents afterwards. FP is
 * v0=HEX ... v31=HEX fpcr=HEX fpsr=HEX. `ok`: the instruction completed and
 * pc is where execution continues. `fault` is SIGSEGV, SIGBUS, SIGFPE,
 * SIGILL or SIGTRAP raised by the instruction itself, with the state the
 * kernel reports in the signal context (pc = CODE-ADDRESS); SI_CODE is the
 * siginfo si_code (hex, `-` prefixed if negative), SI_ADDR the si_addr (the
 * kernel clears the tag byte of a data fault address). `skip`: a page
 * cannot be mapped (already in use in the process, below mmap_min_addr, not
 * a user address), the instruction branched to itself (it would run
 * forever), branched into the oracle's own code or the vDSO, ran more than
 * itself (see below), the case ran longer than a second, the instruction
 * ended the process, or a floating-point case finds no FP/SIMD record (or a
 * streaming-mode SVE one) in the signal frame. `error`: a malformed line.
 *
 * How: each case runs in a forked child, which maps the pages, installs
 * handlers on an alternate signal stack and raises SIGUSR1. That handler
 * writes the case's registers into its ucontext (pc = CODE-ADDRESS, NZCV
 * and BTYPE into pstate, the vector state into the frame's FP/SIMD record,
 * and into the low 128 bits of the SVE record's Z registers, the rest
 * zeroed, when the frame holds them, so that the V registers are right
 * whichever record sigreturn restores last), so
 * returning from it (sigreturn) loads the state and executes the
 * instruction. The handler also writes the case's FPCR with MSR, as
 * sigreturn then restores it: qemu-aarch64 fixes FPCR.NEP's merging and
 * FPCR.AH's negations when it translates, from flags MSR FPCR recomputes
 * and sigreturn does not. AArch64 has no single-step a user process can set on
 * itself, so the end of the instruction is found by the next fetch
 * trapping at once: the code page's other words are 0 (UDF #0, always
 * undefined: SIGILL), any other page the case maps is not executable
 * (SIGSEGV), and a misaligned pc raises SIGBUS (PC alignment fault). A trap
 * at a pc other than CODE-ADDRESS is that next fetch, so the instruction
 * completed and its registers are in the signal context: `ok` with that
 * pc. A signal at CODE-ADDRESS is the instruction's own fault. A trap
 * elsewhere that is not such a fetch (a word from mem= on the code page
 * ran, or the instruction stored a defined instruction there) answers
 * `skip`. The oracle's own code and the vDSO are executable too: a pc in
 * one (found from /proc/self/maps before the case is mapped) answers
 * `skip`. A branch to itself would loop: after 100 ms of CPU time
 * (ITIMER_VIRTUAL) the case answers `skip`. An instruction that enters the
 * kernel (svc) runs the system call with the case's registers.
 *
 * Linux runs EL0 with SCTLR_EL1.SA0 set, so a load or store with the stack
 * pointer as base and sp not a multiple of 16 is SIGBUS (BUS_ADRALN) on
 * hardware; qemu-aarch64 does not check SP alignment and runs it. qemu also
 * reports si_addr 0 for an address outside the virtual address range
 * (bit 55 set), and only a processor with FEAT_BTI keeps BTYPE.
 *
 * Built by scripts/cpu-oracle-aarch64.sh. tools/cpu-oracle-aarch64/smoke.txt
 * holds sample cases: add (shifted register, 64 and 32 bits), subs
 * (immediate, 64 and 32 bits, shifted), cmp, orr (ror), mov, ldr and str
 * (unsigned offset), stp (pre-index, sp), ldp (post-index, sp), adrp, b,
 * bl, b.cond taken and not, cbz (64 and 32 bits, taken and not), ret (to
 * an unmapped address, a misaligned one, a tagged one: the tag byte is
 * ignored), a load from an unmapped address, a load with sp misaligned
 * and aligned, b to itself, br (BTYPE 1), BTYPE 3 cleared by add, msr
 * tpidr_el0, fadd with fp state, brk, udf, a misaligned code address, a
 * bad word, a bad nzcv, an unmappable address, stp with sp misaligned, a
 * load through a tagged pointer, one outside the address range, a store
 * straddling into an unmapped page (the store does not happen), a load
 * from the code page, fadd rounding toward zero (FPSR.IXC), br x16.
 * `qemu-aarch64 -cpu max target/cpu-oracle-aarch64 < smoke.txt` answers
 * smoke.expected; on hardware (Linux EL0) the two cases with a misaligned
 * sp (ldr x0, [sp], stp ... [sp, #-16]!) answer `fault SIGBUS code=1
 * addr=SP` instead, the load outside the address range has addr set, and
 * without FEAT_BTI the br cases report btype=0.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "cpu_oracle.c is for AArch64 Linux"
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define TIMEOUT_MS 1000
/* CPU time after which a running case is taken to loop. */
#define LOOP_US 100000

/* Signal frame records (the kernel's uapi asm/sigcontext.h): each starts
 * with a 32-bit magic and a 32-bit size; magic 0 ends the list. (libc
 * headers may define the kernel's names for these, so they are renamed.) */
#define RECORD_FPSIMD 0x46508001u
#define RECORD_SVE 0x53564501u
#define RECORD_EXTRA 0x45585401u
/* fpsimd_context: fpsr, fpcr, then v0-v31. */
#define FPSIMD_FPSR 8
#define FPSIMD_FPCR 12
#define FPSIMD_V 16
/* sve_context: vl (bytes), flags; Z registers from 16 if the size says. */
#define SVE_VL 8
#define SVE_FLAGS 10
#define SVE_FLAG_SM 1
#define SVE_REGS 16
/* extra_context: datap, the address where the records continue. */
#define EXTRA_DATAP 8

#define PSTATE_NZCV_SHIFT 28
#define PSTATE_BTYPE_SHIFT 10
#define PSTATE_DIT_SHIFT 24
#define PSTATE_SSBS_SHIFT 12
#define PSTATE_TCO_SHIFT 25

#define NX 31 /* x0-x30 */
#define NV 32 /* v0-v31 */
#define MAX_EXEC 64

/* Input values: x0-x30, then these; from TPIDR on, the system state. */
enum { SP = NX, NZCV, BTYPE, TPIDR, DIT, SSBS, TCO, NVALUES };
static const uint64_t value_limit[NVALUES - NX] = {UINT64_MAX, 0xf, 3, UINT64_MAX, 1, 1, 1};
static const char* const value_name[NVALUES - NX] = {"sp", "nzcv", "btype", "tpidr_el0", "dit", "ssbs", "tco"};

/* FP input slots: v0-v31, then fpcr and fpsr. */
enum { FPCR = NV, FPSR, NFP_NAMES };

struct region {
    uint64_t addr;
    size_t len;
    unsigned char* bytes;
};

/* Vector registers as little-endian byte arrays. */
struct fp_state {
    unsigned char v[NV][16];
    uint32_t fpcr, fpsr;
};

struct oracle_case {
    uint64_t code_addr;
    uint32_t word;
    uint64_t value[NVALUES];
    int has_fp; /* a floating-point name was given: load and report fp */
    int has_sys; /* a system state name was given: load and report it */
    struct fp_state fp;
    struct region* mem;
    size_t nmem;
};

/* ---- Parsing (parent) ---- */

static int hex_digit(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_u64(const char* s, uint64_t* out) {
    size_t n = strlen(s);
    if (n == 0 || n > 16) return 0;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        int d = hex_digit((unsigned char)s[i]);
        if (d < 0) return 0;
        v = v << 4 | (uint64_t)d;
    }
    *out = v;
    return 1;
}

/* Parses hex pairs into out (room for max bytes); returns the count, 0 if bad. */
static size_t parse_bytes(const char* s, unsigned char* out, size_t max) {
    size_t n = strlen(s);
    if (n == 0 || n % 2 || n / 2 > max) return 0;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_digit((unsigned char)s[2 * i]), lo = hex_digit((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return n / 2;
}

/* Parses up to 2 * n hex digits into out, n bytes little-endian. */
static int parse_wide(const char* s, unsigned char* out, size_t n) {
    size_t len = strlen(s);
    if (len == 0 || len > 2 * n) return 0;
    memset(out, 0, n);
    for (size_t k = 0; k < len; k++) {
        int d = hex_digit((unsigned char)s[len - 1 - k]);
        if (d < 0) return 0;
        out[k / 2] |= (unsigned char)(d << (4 * (k % 2)));
    }
    return 1;
}

static int fail(char* err, size_t size, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, size, fmt, ap);
    va_end(ap);
    return 0;
}

/* The number after `prefix` in name if it is decimal without leading
 * zeros and below count; -1 otherwise. */
static int numbered(const char* name, const char* prefix, int count) {
    size_t len = strlen(prefix);
    if (strncmp(name, prefix, len)) return -1;
    const char* digits = name + len;
    if (digits[0] < '0' || digits[0] > '9' || (digits[0] == '0' && digits[1])) return -1;
    int n = 0;
    for (const char* p = digits; *p; p++) {
        if (*p < '0' || *p > '9' || (n = n * 10 + (*p - '0')) >= count) return -1;
    }
    return n;
}

/* An input register name's index in oracle_case.value, -1 if none. */
static int value_slot(const char* name) {
    int x = numbered(name, "x", NX);
    if (x >= 0) return x;
    for (int i = 0; i < NVALUES - NX; i++)
        if (!strcmp(name, value_name[i])) return NX + i;
    return -1;
}

/* An FP input name's slot, -1 if none. */
static int fp_slot(const char* name) {
    if (!strcmp(name, "fpcr")) return FPCR;
    if (!strcmp(name, "fpsr")) return FPSR;
    return numbered(name, "v", NV);
}

static void free_case(struct oracle_case* c) {
    for (size_t i = 0; i < c->nmem; i++) free(c->mem[i].bytes);
    free(c->mem);
    c->mem = NULL;
    c->nmem = 0;
}

/* Parses mem=ADDRESS:BYTES (value, modified in place) into c. */
static int parse_mem(char* value, struct oracle_case* c, char* err, size_t size) {
    char* colon = strchr(value, ':');
    if (!colon) return fail(err, size, "expected mem=address:bytes: %s", value);
    *colon = 0;
    struct region r = {0};
    size_t hex = strlen(colon + 1);
    if (!parse_u64(value, &r.addr)) return fail(err, size, "bad mem address: %s", value);
    if (!(r.bytes = malloc(hex / 2 + 1))) return fail(err, size, "out of memory");
    if (!(r.len = parse_bytes(colon + 1, r.bytes, hex / 2))) {
        free(r.bytes);
        return fail(err, size, "bad mem bytes at %s", value);
    }
    struct region* grown = realloc(c->mem, (c->nmem + 1) * sizeof *grown);
    if (!grown) {
        free(r.bytes);
        return fail(err, size, "out of memory");
    }
    c->mem = grown;
    c->mem[c->nmem++] = r;
    return 1;
}

/* Parses an input line (modified in place) into c; on failure, writes the
 * reason to err and returns 0. c must be freed with free_case either way. */
static int parse_case(char* line, struct oracle_case* c, char* err, size_t size) {
    memset(c, 0, sizeof *c);
    unsigned char seen[NVALUES] = {0};
    unsigned char seen_fp[NFP_NAMES] = {0};
    char* save;
    char* tok = strtok_r(line, " \t", &save);
    if (!tok || strcmp(tok, "case")) return fail(err, size, "expected `case`");
    tok = strtok_r(NULL, " \t", &save);
    if (!tok || !parse_u64(tok, &c->code_addr)) return fail(err, size, "bad code address: %s", tok ? tok : "");
    if (c->code_addr & 3) return fail(err, size, "code address not a multiple of 4: %s", tok);
    tok = strtok_r(NULL, " \t", &save);
    uint64_t word;
    if (!tok || strlen(tok) > 8 || !parse_u64(tok, &word)) return fail(err, size, "bad word: %s", tok ? tok : "");
    c->word = (uint32_t)word;
    while ((tok = strtok_r(NULL, " \t", &save))) {
        char* eq = strchr(tok, '=');
        if (!eq) return fail(err, size, "expected name=value: %s", tok);
        *eq = 0;
        char* value = eq + 1;
        if (!strcmp(tok, "mem")) {
            if (!parse_mem(value, c, err, size)) return 0;
            continue;
        }
        int slot = fp_slot(tok);
        if (slot >= 0) {
            if (seen_fp[slot]) return fail(err, size, "register given twice: %s", tok);
            seen_fp[slot] = 1;
            c->has_fp = 1;
            uint64_t v;
            if (slot < NV) {
                if (!parse_wide(value, c->fp.v[slot], sizeof c->fp.v[slot]))
                    return fail(err, size, "bad value for %s: %s", tok, value);
            } else if (!parse_u64(value, &v) || v > 0xffffffffu) {
                return fail(err, size, "bad value for %s: %s", tok, value);
            } else if (slot == FPCR) {
                c->fp.fpcr = (uint32_t)v;
            } else {
                c->fp.fpsr = (uint32_t)v;
            }
            continue;
        }
        int i = value_slot(tok);
        if (i < 0) return fail(err, size, "unknown register: %s", tok);
        if (seen[i]) return fail(err, size, "register given twice: %s", tok);
        seen[i] = 1;
        if (i >= TPIDR) c->has_sys = 1;
        if (!parse_u64(value, &c->value[i]) || (i >= NX && c->value[i] > value_limit[i - NX]))
            return fail(err, size, "bad value for %s: %s", tok, value);
    }
    return 1;
}

/* ---- Running a case (child) ---- */

static const struct oracle_case* current;
static int result_fd;
static uint64_t tpidr;
static uint64_t code_start, code_end; /* the code's page */
static struct span {
    uint64_t start, end;
} exec_spans[MAX_EXEC]; /* the process's executable mappings before the case */
static size_t nexec;
static char* out_buf;
static size_t out_len, out_cap;
static char altstack[1 << 16] __attribute__((aligned(16)));

/* Everything below up to run_child runs in signal handlers: no stdio, no
 * malloc, libc only through syscall(). Built without stack protector, as
 * the canary is read through tpidr_el0, which the instruction may have
 * changed (msr tpidr_el0), and with general registers only, as the
 * instruction may have changed FPCR. */

static void put(const char* s) {
    while (*s && out_len < out_cap) out_buf[out_len++] = *s++;
}

static void put_hex(uint64_t v) {
    char digits[17];
    int n = 0;
    do {
        digits[n++] = "0123456789abcdef"[v & 15];
        v >>= 4;
    } while (v);
    while (n && out_len < out_cap) out_buf[out_len++] = digits[--n];
}

/* A number below 100 in decimal. */
static void put_dec(unsigned v) {
    if (v >= 10) put_hex(v / 10);
    put_hex(v % 10);
}

static void put_bytes(const unsigned char* p, size_t n) {
    for (size_t i = 0; i < n && out_len + 2 <= out_cap; i++) {
        out_buf[out_len++] = "0123456789abcdef"[p[i] >> 4];
        out_buf[out_len++] = "0123456789abcdef"[p[i] & 15];
    }
}

/* A little-endian number of n bytes, as put_hex prints numbers. */
static void put_wide(const unsigned char* p, size_t n) {
    while (n > 1 && !p[n - 1]) n--;
    put_hex(p[n - 1]);
    while (--n) put_bytes(p + n - 1, 1);
}

/* ` NAME[INDEX]=` with INDEX decimal, left out if negative. */
static void put_name(const char* name, int index) {
    put(" ");
    put(name);
    if (index >= 0) put_dec((unsigned)index);
    put("=");
}

/* Writes the answer and ends the child. */
static _Noreturn void finish(void) {
    for (size_t done = 0; done < out_len;) {
        long n = syscall(SYS_write, result_fd, out_buf + done, out_len - done);
        if (n <= 0) break;
        done += (size_t)n;
    }
    syscall(SYS_exit_group, 0);
    __builtin_unreachable();
}

static uint64_t get_le(const unsigned char* p, int n) {
    uint64_t v = 0;
    while (n--) v = v << 8 | p[n];
    return v;
}

static void set_le(unsigned char* p, uint64_t v, int n) {
    for (int i = 0; i < n; i++, v >>= 8) p[i] = (unsigned char)v;
}

/* The signal frame record with `magic`, NULL if absent; records continue
 * where an extra_context points. */
static unsigned char* frame_record(ucontext_t* uc, uint32_t magic) {
    unsigned char* p = (unsigned char*)&uc->uc_mcontext.__reserved;
    for (int n = 0; n < 64; n++) {
        uint32_t m = (uint32_t)get_le(p, 4), size = (uint32_t)get_le(p + 4, 4);
        if (m == magic) return p;
        if (m == 0 || size < 8) return NULL;
        p = m == RECORD_EXTRA ? (unsigned char*)(uintptr_t)get_le(p + EXTRA_DATAP, 8) : p + size;
    }
    return NULL;
}

static _Noreturn void skip_now(const char* reason) {
    put("skip ");
    put(reason);
    put("\n");
    finish();
}

/* Writes the case's fp state into the frame, for sigreturn to load. */
static void load_fp(ucontext_t* uc) {
    unsigned char* fp = frame_record(uc, RECORD_FPSIMD);
    if (!fp) skip_now("the signal frame has no FP/SIMD record");
    set_le(fp + FPSIMD_FPSR, current->fp.fpsr, 4);
    set_le(fp + FPSIMD_FPCR, current->fp.fpcr, 4);
    for (int i = 0; i < NV; i++) __builtin_memcpy(fp + FPSIMD_V + 16 * i, current->fp.v[i], 16);
    unsigned char* sve = frame_record(uc, RECORD_SVE);
    if (!sve || get_le(sve + 4, 4) <= SVE_REGS) return;
    if (get_le(sve + SVE_FLAGS, 2) & SVE_FLAG_SM) skip_now("the signal frame is in streaming mode");
    size_t vl = (size_t)get_le(sve + SVE_VL, 2);
    for (int i = 0; i < NV; i++) {
        unsigned char* z = sve + SVE_REGS + (size_t)i * vl;
        __builtin_memcpy(z, current->fp.v[i], 16);
        __builtin_memset(z + 16, 0, vl - 16);
    }
}

/* Prints the fp state in answer order. */
static void put_fp(ucontext_t* uc) {
    unsigned char* fp = frame_record(uc, RECORD_FPSIMD);
    if (!fp) skip_now("the signal frame has no FP/SIMD record");
    for (int i = 0; i < NV; i++) {
        put_name("v", i);
        put_wide(fp + FPSIMD_V + 16 * i, 16);
    }
    put_name("fpcr", -1);
    put_hex(get_le(fp + FPSIMD_FPCR, 4));
    put_name("fpsr", -1);
    put_hex(get_le(fp + FPSIMD_FPSR, 4));
}

static const char* signal_name(int sig) {
    switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGILL: return "SIGILL";
    default: return "SIGTRAP";
    }
}

/* Loads the case's state: returning from this handler runs the instruction. */
static void on_start(int sig, siginfo_t* si, void* ctx) {
    (void)sig;
    (void)si;
    ucontext_t* uc = ctx;
    for (int i = 0; i < NX; i++) uc->uc_mcontext.regs[i] = current->value[i];
    uc->uc_mcontext.sp = current->value[SP];
    uc->uc_mcontext.pc = current->code_addr;
    uint64_t pstate = uc->uc_mcontext.pstate;
    pstate &= ~(0xfull << PSTATE_NZCV_SHIFT | 3ull << PSTATE_BTYPE_SHIFT);
    pstate |= current->value[NZCV] << PSTATE_NZCV_SHIFT | current->value[BTYPE] << PSTATE_BTYPE_SHIFT;
    if (current->has_sys) {
        pstate &= ~(1ull << PSTATE_DIT_SHIFT | 1ull << PSTATE_SSBS_SHIFT | 1ull << PSTATE_TCO_SHIFT);
        pstate |= current->value[DIT] << PSTATE_DIT_SHIFT | current->value[SSBS] << PSTATE_SSBS_SHIFT |
                  current->value[TCO] << PSTATE_TCO_SHIFT;
    }
    uc->uc_mcontext.pstate = pstate;
    if (current->has_fp) {
        load_fp(uc);
        /* For qemu-aarch64's translation flags (see How, above). */
        __asm__ volatile("msr fpcr, %0" ::"r"((uint64_t)current->fp.fpcr));
    }
    sigemptyset(&uc->uc_sigmask);
    /* A branch to itself runs until this expires. */
    struct itimerval loop = {.it_value = {.tv_sec = 0, .tv_usec = LOOP_US}};
    syscall(SYS_setitimer, ITIMER_VIRTUAL, &loop, NULL);
    /* Last: nothing in the oracle uses the thread pointer until on_result
     * restores it. */
    if (current->has_sys) __asm__ volatile("msr tpidr_el0, %0" ::"r"(current->value[TPIDR]));
}

static int in_exec_span(uint64_t pc) {
    for (size_t i = 0; i < nexec; i++)
        if (exec_spans[i].start <= pc && pc < exec_spans[i].end) return 1;
    return 0;
}

/* Whether the signal is the fetch after the instruction trapping at pc: a
 * UDF #0 (zero word) on the code page, or a fetch fault or PC alignment
 * fault at pc (si_addr may have lost the tag byte). */
static int next_fetch(int sig, const siginfo_t* si, uint64_t pc) {
    if (sig == SIGILL)
        return pc >= code_start && pc < code_end && !(pc & 3) && !*(const volatile uint32_t*)(uintptr_t)pc;
    return (sig == SIGSEGV || sig == SIGBUS) && !((((uintptr_t)si->si_addr ^ pc) << 8));
}

/* Reports the state after the instruction or its fault. */
static void on_result(int sig, siginfo_t* si, void* ctx) {
    /* The instruction may have changed the thread pointer; libc needs it. */
    uint64_t case_tpidr, case_tpidrro;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(case_tpidr));
    __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(case_tpidrro));
    __asm__ volatile("msr tpidr_el0, %0" ::"r"(tpidr));
    ucontext_t* uc = ctx;
    uint64_t pc = uc->uc_mcontext.pc;
    if (in_exec_span(pc)) skip_now("the instruction branched into the oracle's own code");
    if (sig == SIGVTALRM) skip_now(pc == current->code_addr ? "the instruction branches to itself" : "timeout");
    if (pc == current->code_addr) {
        put("fault ");
        put(signal_name(sig));
        put(" code=");
        if (si->si_code < 0) put("-");
        put_hex(si->si_code < 0 ? -(int64_t)si->si_code : si->si_code);
        put(" addr=");
        put_hex((uintptr_t)si->si_addr);
    } else if (next_fetch(sig, si, pc)) {
        put("ok");
    } else {
        put("skip more than one instruction ran: ");
        put(signal_name(sig));
        put(" at ");
        put_hex(pc);
        put("\n");
        finish();
    }
    put_name("pc", -1);
    put_hex(pc);
    for (int i = 0; i < NX; i++) {
        put_name("x", i);
        put_hex(uc->uc_mcontext.regs[i]);
    }
    put_name("sp", -1);
    put_hex(uc->uc_mcontext.sp);
    put_name("nzcv", -1);
    put_hex(uc->uc_mcontext.pstate >> PSTATE_NZCV_SHIFT & 0xf);
    put_name("btype", -1);
    put_hex(uc->uc_mcontext.pstate >> PSTATE_BTYPE_SHIFT & 3);
    if (current->has_sys) {
        put_name("tpidr_el0", -1);
        put_hex(case_tpidr);
        put_name("tpidrro_el0", -1);
        put_hex(case_tpidrro);
        put_name("dit", -1);
        put_hex(uc->uc_mcontext.pstate >> PSTATE_DIT_SHIFT & 1);
        put_name("ssbs", -1);
        put_hex(uc->uc_mcontext.pstate >> PSTATE_SSBS_SHIFT & 1);
        put_name("tco", -1);
        put_hex(uc->uc_mcontext.pstate >> PSTATE_TCO_SHIFT & 1);
    }
    if (current->has_fp) put_fp(uc);
    for (size_t i = 0; i < current->nmem; i++) {
        put(" mem=");
        put_hex(current->mem[i].addr);
        put(":");
        put_bytes((const unsigned char*)(uintptr_t)current->mem[i].addr, current->mem[i].len);
    }
    put("\n");
    finish();
}

static _Noreturn void child_answer(const char* fmt, ...) {
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line - 1, fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if ((size_t)n > sizeof line - 2) n = sizeof line - 2;
    line[n++] = '\n';
    for (int done = 0; done < n;) {
        ssize_t w = write(result_fd, line + done, (size_t)(n - done));
        if (w <= 0) break;
        done += (int)w;
    }
    _exit(0);
}

/* Records the process's executable mappings (its code, the vDSO). */
static void find_exec_spans(void) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) child_answer("skip cannot read /proc/self/maps: %s", strerror(errno));
    char line[512];
    while (fgets(line, sizeof line, maps)) {
        unsigned long long start, end;
        char perms[5];
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) != 3 || perms[2] != 'x') continue;
        if (nexec == MAX_EXEC) child_answer("skip too many executable mappings");
        exec_spans[nexec++] = (struct span){start, end};
    }
    fclose(maps);
}

/* Page-aligned [start, end) of the pages holding [addr, addr+len). */
static int page_span(uint64_t addr, size_t len, uint64_t page, struct span* s) {
    uint64_t last = addr + len - 1;
    if (last < addr) return 0;
    s->start = addr & ~(page - 1);
    s->end = (last & ~(page - 1)) + page;
    return s->end != 0;
}

static int span_order(const void* a, const void* b) {
    uint64_t x = ((const struct span*)a)->start, y = ((const struct span*)b)->start;
    return x < y ? -1 : x > y;
}

/* Maps every page the case needs and fills it; answers `skip` if it cannot. */
static void map_case(const struct oracle_case* c) {
    uint64_t page = (uint64_t)sysconf(_SC_PAGESIZE);
    size_t nspans = c->nmem + 1;
    struct span* spans = malloc(nspans * sizeof *spans);
    if (!spans) child_answer("skip out of memory");
    if (!page_span(c->code_addr, 4, page, &spans[0])) child_answer("skip address not usable: %" PRIx64, c->code_addr);
    for (size_t i = 0; i < c->nmem; i++)
        if (!page_span(c->mem[i].addr, c->mem[i].len, page, &spans[i + 1]))
            child_answer("skip address not usable: %" PRIx64, c->mem[i].addr);
    code_start = spans[0].start;
    code_end = spans[0].end;
    qsort(spans, nspans, sizeof *spans, span_order);
    uint64_t mapped_end = 0;
    for (size_t i = 0; i < nspans; i++) {
        uint64_t p = spans[i].start > mapped_end ? spans[i].start : mapped_end;
        for (; p < spans[i].end; p += page) {
            void* want = (void*)(uintptr_t)p;
            void* got = mmap(want, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                             -1, 0);
            if (got == want) continue;
            if (got != MAP_FAILED || errno == EEXIST) child_answer("skip address in use: %" PRIx64, p);
            if (errno == EPERM || errno == EACCES) child_answer("skip address below mmap_min_addr: %" PRIx64, p);
            if (errno == ENOMEM || errno == EINVAL) child_answer("skip address not usable: %" PRIx64, p);
            child_answer("skip cannot map %" PRIx64 ": %s", p, strerror(errno));
        }
        if (spans[i].end > mapped_end) mapped_end = spans[i].end;
    }
    for (size_t i = 0; i < c->nmem; i++) memcpy((void*)(uintptr_t)c->mem[i].addr, c->mem[i].bytes, c->mem[i].len);
    unsigned char word[4];
    set_le(word, c->word, 4);
    memcpy((void*)(uintptr_t)c->code_addr, word, 4);
    int prot = PROT_READ | PROT_EXEC;
    for (size_t i = 0; i < c->nmem; i++) {
        struct span s = {0, 0};
        if (page_span(c->mem[i].addr, c->mem[i].len, page, &s) && s.start < code_end && code_start < s.end)
            prot |= PROT_WRITE;
    }
    if (mprotect((void*)(uintptr_t)code_start, page, prot))
        child_answer("skip mprotect %" PRIx64 ": %s", code_start, strerror(errno));
    /* The instruction cache need not see what was written as data. */
    __builtin___clear_cache((char*)(uintptr_t)code_start, (char*)(uintptr_t)code_end);
    free(spans);
}

static _Noreturn void run_child(const struct oracle_case* c, int fd) {
    current = c;
    result_fd = fd;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tpidr));
    find_exec_spans();
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack};
    if (sigaltstack(&ss, NULL)) child_answer("skip sigaltstack: %s", strerror(errno));
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&sa.sa_mask);
    sa.sa_sigaction = on_result;
    static const int results[] = {SIGTRAP, SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGVTALRM};
    for (size_t i = 0; i < sizeof results / sizeof results[0]; i++)
        if (sigaction(results[i], &sa, NULL)) child_answer("skip sigaction: %s", strerror(errno));
    sa.sa_sigaction = on_start;
    if (sigaction(SIGUSR1, &sa, NULL)) child_answer("skip sigaction: %s", strerror(errno));

    map_case(c);
    out_cap = 4096;
    for (size_t i = 0; i < c->nmem; i++) out_cap += 32 + 2 * c->mem[i].len;
    if (!(out_buf = malloc(out_cap))) child_answer("skip out of memory");

    raise(SIGUSR1);
    child_answer("skip internal error: the state was not loaded");
}

/* ---- Driving the child (parent) ---- */

static long elapsed_ms(const struct timespec* start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000 + (now.tv_nsec - start->tv_nsec) / 1000000;
}

/* Runs c in a child and prints its answer line. */
static void answer(const struct oracle_case* c) {
    int fds[2];
    if (pipe(fds)) {
        printf("skip pipe: %s\n", strerror(errno));
        return;
    }
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        printf("skip fork: %s\n", strerror(errno));
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0) {
        close(fds[0]);
        run_child(c, fds[1]);
    }
    close(fds[1]);

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char* buf = NULL;
    size_t len = 0, cap = 0;
    int timed_out = 0;
    for (;;) {
        long left = TIMEOUT_MS - elapsed_ms(&start);
        struct pollfd pfd = {.fd = fds[0], .events = POLLIN};
        int r = left > 0 ? poll(&pfd, 1, (int)left) : 0;
        if (r < 0 && errno == EINTR) continue;
        if (r == 0) timed_out = 1;
        if (r <= 0) break;
        if (len == cap) {
            char* grown = realloc(buf, cap = cap ? 2 * cap : 4096);
            if (!grown) break;
            buf = grown;
        }
        ssize_t n = read(fds[0], buf + len, cap - len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        len += (size_t)n;
    }
    close(fds[0]);

    if (timed_out) kill(pid, SIGKILL);
    int status = 0;
    for (;;) {
        pid_t done = waitpid(pid, &status, timed_out ? 0 : WNOHANG);
        if (done == pid || (done < 0 && errno != EINTR)) break;
        if (done != 0) continue;
        if (elapsed_ms(&start) >= TIMEOUT_MS) {
            timed_out = 1;
            kill(pid, SIGKILL);
        } else {
            nanosleep(&(struct timespec){.tv_nsec = 1000000}, NULL);
        }
    }
    if (timed_out) {
        printf("skip timeout\n");
    } else if (len && buf[len - 1] == '\n' && memchr(buf, '\n', len) == buf + len - 1) {
        fwrite(buf, 1, len, stdout);
    } else if (WIFSIGNALED(status)) {
        printf("skip no result: killed by signal %d\n", WTERMSIG(status));
    } else {
        printf("skip no result: exited with status %d\n", WEXITSTATUS(status));
    }
    free(buf);
}

int main(void) {
    char* line = NULL;
    size_t size = 0;
    ssize_t n;
    while ((n = getline(&line, &size, stdin)) != -1) {
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        struct oracle_case c;
        char err[256];
        if (parse_case(line, &c, err, sizeof err)) {
            answer(&c);
        } else {
            printf("error %s\n", err);
        }
        free_case(&c);
        fflush(stdout);
    }
    free(line);
    return 0;
}
