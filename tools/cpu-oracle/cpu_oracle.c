/* This machine's CPU as a test oracle for binbun's x86 lifter.
 *
 * Runs one instruction at a time from a given state and reports the state
 * after it, or the fault it raised. Linux x86-64 only. Reads one case per
 * line from stdin and prints exactly one line per input line, in order,
 * flushed per line; all numbers are lowercase hex without 0x:
 *
 *     case CODE-ADDRESS CODE-BYTES [NAME=VALUE ...] [mem=ADDRESS:BYTES ...]
 *
 * CODE-BYTES (1 to 15 bytes, as hex pairs) are placed at CODE-ADDRESS, on
 * pages mapped read+exec for the case. NAME is one of rax rbx rcx rdx rsi
 * rdi rbp rsp r8 ... r15 rflags; unlisted registers start as 0, rflags as 2.
 * rflags may not set TF, IF, IOPL, NT, RF, VM, AC, VIF, VIP or a reserved
 * bit (ID is allowed; bit 1 is always set). Each mem= maps the pages
 * containing ADDRESS..ADDRESS+len read-write (other bytes 0) and fills them
 * with BYTES; regions may share pages, also with the code (such pages are
 * read-write-exec, and the code bytes win where they overlap). Answers:
 *
 * Floating-point state: NAME may also be ymm0 ... ymm15 (the 256-bit value,
 * up to 64 hex digits), mxcsr, fcw, fsw (the whole x87 status word, TOP
 * and C0-C3 included), ftw (the abridged tag word as FXSAVE stores it: bit
 * i set if physical register i is in use) or fpr0 ... fpr7 (the PHYSICAL
 * x87 registers, not the stack: st(i) is fpr((TOP + i) mod 8); 80 bits, up
 * to 20 hex digits). If a line names any of them, the case runs with all
 * of this state, the unnamed parts as ymm 0, mxcsr 1f80, fcw 37f, fsw 0,
 * ftw 0, fpr 0 (the x87 instruction and data pointers are 0), and the
 * answer reports it (FP below); otherwise the state is as the process has
 * it and is not reported. mxcsr may not set bits outside the processor's
 * MXCSR_MASK. Answers:
 *
 *     ok rip=HEX rax=HEX ... r15=HEX rflags=HEX [FP] [mem=ADDRESS:BYTES ...]
 *     fault SIGNAL code=SI_CODE addr=SI_ADDR rip=HEX ... rflags=HEX [FP] [mem=...]
 *     skip REASON
 *     error REASON
 *
 * Registers are always rip rax rbx rcx rdx rsi rdi rbp rsp r8 ... r15 rflags,
 * with TF and RF cleared in rflags (IF is set, as always in user mode); mem=
 * lists every input region, same address and length, with its contents
 * afterwards. FP is ymm0=HEX ... ymm15=HEX mxcsr=HEX fcw=HEX fsw=HEX
 * ftw=HEX fpr0=HEX ... fpr7=HEX, named as in the input. `fault` is SIGSEGV,
 * SIGBUS, SIGFPE, SIGILL or SIGTRAP (not the single-step trap, e.g. int3)
 * with the state the kernel reports in the signal context; SI_CODE is the
 * siginfo si_code (hex, `-` prefixed if negative: 80 is SI_KERNEL). `skip`:
 * a page cannot be mapped (already in use in the process, below
 * mmap_min_addr, not a user address), the case ran longer than a second,
 * the instruction ended the process, or a floating-point case finds no AVX
 * state in the signal frame. `error`: a malformed line. Unmasked
 * SSE exceptions (#XM) and pending unmasked x87 exceptions (#MF, raised by
 * the next waiting x87 instruction) are SIGFPE with FPE_FLTDIV (3), FLTOVF,
 * FLTUND, FLTRES, FLTINV or FLTSUB (8); the kernel picks the code from the
 * unmasked exception flags, sticky ones included. Integer divide errors are
 * FPE_INTDIV (1).
 *
 * How: each case runs in a forked child, which maps the pages, installs
 * handlers on an alternate signal stack and raises SIGUSR1. That handler
 * writes the case's registers into its ucontext, with rip = CODE-ADDRESS and
 * TF set, so returning from it (sigreturn) loads the state and executes one
 * instruction, after which the single-step trap (or a fault) arrives; its
 * handler prints the state from its ucontext. The floating-point state goes
 * through the frame's FXSAVE area (uc_mcontext.fpregs) and the XSAVE
 * extension after it (FP_XSTATE_MAGIC1 in its software bytes; XSTATE_BV
 * x87, SSE and AVX bits set; ymm upper halves in the AVX component at
 * CPUID.(0xd,2).EBX), with FXSAVE's stack order converted from and to
 * physical registers; reading it back, a component whose XSTATE_BV bit is
 * clear is in its initial state. Segment registers and fs/gs bases are as
 * the process has them. TF is really set while
 * the instruction runs, so pushf stores it, and an instruction that enters
 * the kernel (syscall, int 80) runs the next instruction too before trapping.
 *
 * Built by scripts/cpu-oracle.sh. tools/cpu-oracle/smoke.txt holds sample
 * cases (add, push into memory, jmp to an unmapped address, div by zero, a
 * load from an unmapped address, int3, an instruction straddling two pages,
 * ID OF DF SF ZF AF PF CF kept, a forbidden flag (TF), an unmappable
 * address, a malformed line, a nop; then floating point: addps (lanes 1 2
 * 3 4 plus 1, the upper ymm half kept), vaddps ymm (1 + 2 in all eight
 * lanes), fld1 (TOP 0 to 7, 1.0 in fpr7, tagged), fadd st(0), st(1) with
 * TOP 3 (fpr3 = 1 + 2), ldmxcsr from memory, divss by zero with ZM clear
 * (#XM: SIGFPE FPE_FLTDIV, ZE set, xmm0 unchanged), an mxcsr outside
 * MXCSR_MASK, a nop keeping ymm15's top bit and fpr7 (st(0) at TOP 7),
 * fninit (control, status and tags reset, registers kept), vzeroupper);
 * `target/cpu-oracle < tools/cpu-oracle/smoke.txt` answers:
 *
 *     ok rip=100000003 rax=0 rbx=1 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=257
 *     ok rip=100000001 rax=0 rbx=1122334455667788 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=200000008 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 mem=200000000:00000000000000008877665544332211
 *     ok rip=123456789000 rax=123456789000 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202
 *     fault SIGFPE code=1 addr=100000000 rip=100000000 rax=1 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202
 *     fault SIGSEGV code=1 addr=300000000 rip=100000000 rax=0 rbx=300000000 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202
 *     fault SIGTRAP code=80 addr=0 rip=100000001 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202
 *     ok rip=100001001 rax=0 rbx=1 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=257
 *     ok rip=100000001 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=200ed7
 *     error rflags sets bits that cannot be controlled: 100
 *     skip address below mmap_min_addr: 1000
 *     error bad code bytes: zz
 *     ok rip=100000001 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202
 *     ok rip=100000003 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=1111111122222222333333334444444440a00000408000004040000040000000 ymm1=3f8000003f8000003f8000003f800000 ymm2=0 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=0 mxcsr=1f80 fcw=37f fsw=0 ftw=0 fpr0=0 fpr1=0 fpr2=0 fpr3=0 fpr4=0 fpr5=0 fpr6=0 fpr7=0
 *     ok rip=100000004 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=4040000040400000404000004040000040400000404000004040000040400000 ymm1=3f8000003f8000003f8000003f8000003f8000003f8000003f8000003f800000 ymm2=4000000040000000400000004000000040000000400000004000000040000000 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=0 mxcsr=1f80 fcw=37f fsw=0 ftw=0 fpr0=0 fpr1=0 fpr2=0 fpr3=0 fpr4=0 fpr5=0 fpr6=0 fpr7=0
 *     ok rip=100000002 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=0 ymm1=0 ymm2=0 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=0 mxcsr=1f80 fcw=37f fsw=3800 ftw=80 fpr0=0 fpr1=0 fpr2=0 fpr3=0 fpr4=0 fpr5=0 fpr6=0 fpr7=3fff8000000000000000
 *     ok rip=100000002 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=0 ymm1=0 ymm2=0 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=0 mxcsr=1f80 fcw=37f fsw=1800 ftw=18 fpr0=0 fpr1=0 fpr2=0 fpr3=4000c000000000000000 fpr4=40008000000000000000 fpr5=0 fpr6=0 fpr7=0
 *     ok rip=100000003 rax=200000000 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=0 ymm1=0 ymm2=0 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=0 mxcsr=7fc0 fcw=37f fsw=0 ftw=0 fpr0=0 fpr1=0 fpr2=0 fpr3=0 fpr4=0 fpr5=0 fpr6=0 fpr7=0 mem=200000000:c07f0000
 *     fault SIGFPE code=3 addr=100000000 rip=100000000 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=3f800000 ymm1=0 ymm2=0 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=0 mxcsr=1d84 fcw=37f fsw=0 ftw=0 fpr0=0 fpr1=0 fpr2=0 fpr3=0 fpr4=0 fpr5=0 fpr6=0 fpr7=0
 *     error mxcsr sets bits outside MXCSR_MASK (ffff): 10000
 *     ok rip=100000001 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=0 ymm1=0 ymm2=0 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=8000000000000000000000000000000000000000000000000000000000000001 mxcsr=1f80 fcw=37f fsw=3800 ftw=80 fpr0=0 fpr1=0 fpr2=0 fpr3=0 fpr4=0 fpr5=0 fpr6=0 fpr7=1
 *     ok rip=100000002 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=0 ymm1=0 ymm2=0 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=0 mxcsr=1f80 fcw=37f fsw=0 ftw=0 fpr0=0 fpr1=0 fpr2=0 fpr3=0 fpr4=0 fpr5=0 fpr6=0 fpr7=1
 *     ok rip=100000003 rax=0 rbx=0 rcx=0 rdx=0 rsi=0 rdi=0 rbp=0 rsp=0 r8=0 r9=0 r10=0 r11=0 r12=0 r13=0 r14=0 r15=0 rflags=202 ymm0=0 ymm1=0 ymm2=0 ymm3=0 ymm4=0 ymm5=0 ymm6=0 ymm7=0 ymm8=0 ymm9=0 ymm10=0 ymm11=0 ymm12=0 ymm13=0 ymm14=0 ymm15=1 mxcsr=1f80 fcw=37f fsw=0 ftw=0 fpr0=0 fpr1=0 fpr2=0 fpr3=0 fpr4=0 fpr5=0 fpr6=0 fpr7=0
 */
#define _GNU_SOURCE
#include <asm/prctl.h>
#include <cpuid.h>
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
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define FLAG_TF (1ull << 8)
#define FLAG_RF (1ull << 16)
#define FLAG_AC (1ull << 18)
#define FLAG_ID (1ull << 21)
/* TF IF IOPL NT RF VM AC VIF VIP, and the reserved bits 3, 5, 15, 22-63. */
#define FLAGS_FORBIDDEN (0x1f7300ull | (1ull << 3) | (1ull << 5) | (1ull << 15) | ~0x3fffffull)

#define TIMEOUT_MS 1000

/* The FXSAVE area (uc_mcontext.fpregs) in the signal frame: offsets. */
#define FX_FCW 0
#define FX_FSW 2
#define FX_FTW 4
#define FX_FOP 6
#define FX_FIP 8
#define FX_FDP 16
#define FX_MXCSR 24
#define FX_MXCSR_MASK 28
#define FX_ST 32   /* ST(i) at FX_ST + 16 * i: 80 bits, then 6 reserved bytes */
#define FX_XMM 160 /* xmm i at FX_XMM + 16 * i */
/* The kernel's software bytes at 464 (struct _fpx_sw_bytes): magic1,
 * extended_size, xfeatures. FP_XSTATE_MAGIC1 there: the frame was saved
 * with XSAVE (standard format), its header at 512. */
#define FX_SW_MAGIC1 464
#define FX_SW_EXTENDED_SIZE 468
#define FX_SW_XFEATURES 472
#ifndef FP_XSTATE_MAGIC1
#define FP_XSTATE_MAGIC1 0x46505853u
#endif
#define XSAVE_HEADER 512 /* XSTATE_BV, the first 8 bytes */
/* XSTATE_BV bits: x87, SSE, AVX (upper halves of ymm). */
#define XSTATE_X87_SSE_AVX 7ull

#define NYMM 16
#define NFPR 8

/* MXCSR bits the processor accepts (FXSAVE's MXCSR_MASK, or ffbf if 0). */
static uint32_t mxcsr_mask;
/* Offset of the AVX component in a standard-format XSAVE area
 * (CPUID.(0xd,2).EBX); 0 if the OS has not enabled AVX. */
static uint32_t avx_offset;

/* The registers, in output order. Input names are the entries with `input`
 * set; the value comes from (and goes to) gregs[greg] of the ucontext. */
static const struct reg {
    const char* name;
    int greg;
    int input;
} regs[] = {
    {"rip", REG_RIP, 0}, {"rax", REG_RAX, 1}, {"rbx", REG_RBX, 1}, {"rcx", REG_RCX, 1},
    {"rdx", REG_RDX, 1}, {"rsi", REG_RSI, 1}, {"rdi", REG_RDI, 1}, {"rbp", REG_RBP, 1},
    {"rsp", REG_RSP, 1}, {"r8", REG_R8, 1},   {"r9", REG_R9, 1},   {"r10", REG_R10, 1},
    {"r11", REG_R11, 1}, {"r12", REG_R12, 1}, {"r13", REG_R13, 1}, {"r14", REG_R14, 1},
    {"r15", REG_R15, 1}, {"rflags", REG_EFL, 1},
};
#define NREGS (sizeof regs / sizeof regs[0])
#define RIP 0
#define RFLAGS (NREGS - 1)

struct region {
    uint64_t addr;
    size_t len;
    unsigned char* bytes;
};

/* Vector, MXCSR and x87 state; numbers are little-endian byte arrays. */
struct fp_state {
    unsigned char ymm[NYMM][32];
    uint32_t mxcsr;
    uint16_t fcw, fsw; /* fsw: the whole status word, TOP and C0-C3 included */
    uint8_t ftw;       /* abridged: bit i set if physical register i is in use */
    unsigned char fpr[NFPR][10]; /* physical registers, not stack order */
};

struct oracle_case {
    uint64_t code_addr;
    unsigned char code[15];
    size_t code_len;
    uint64_t value[NREGS]; /* indexed like regs; the rip slot is unused */
    int has_fp;            /* a floating-point name was given: load and report fp */
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

static int fail(char* err, size_t size, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, size, fmt, ap);
    va_end(ap);
    return 0;
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

/* An fp input name's slot for duplicate detection: ymm0-15 are 0-15,
 * fpr0-7 16-23, then mxcsr fcw fsw ftw; -1 if name is not one. */
#define NFP_NAMES (NYMM + NFPR + 4)
static int fp_slot(const char* name) {
    static const char* const scalars[] = {"mxcsr", "fcw", "fsw", "ftw"};
    for (int i = 0; i < 4; i++)
        if (!strcmp(name, scalars[i])) return NYMM + NFPR + i;
    int base, count;
    const char* digits;
    if (!strncmp(name, "ymm", 3)) {
        base = 0, count = NYMM, digits = name + 3;
    } else if (!strncmp(name, "fpr", 3)) {
        base = NYMM, count = NFPR, digits = name + 3;
    } else {
        return -1;
    }
    /* Decimal, no leading zeros. */
    if (digits[0] < '0' || digits[0] > '9' || (digits[0] == '0' && digits[1])) return -1;
    int n = 0;
    for (const char* p = digits; *p; p++) {
        if (*p < '0' || *p > '9' || (n = n * 10 + (*p - '0')) >= count) return -1;
    }
    return base + n;
}

/* Sets fp slot `slot` (see fp_slot) from value; 0 with err set if bad. */
static int parse_fp(struct fp_state* fp, int slot, const char* name, const char* value, char* err, size_t size) {
    if (slot < NYMM) {
        if (!parse_wide(value, fp->ymm[slot], sizeof fp->ymm[slot]))
            return fail(err, size, "bad value for %s: %s", name, value);
        return 1;
    }
    if (slot < NYMM + NFPR) {
        if (!parse_wide(value, fp->fpr[slot - NYMM], sizeof fp->fpr[0]))
            return fail(err, size, "bad value for %s: %s", name, value);
        return 1;
    }
    static const uint64_t limits[] = {0xffffffff, 0xffff, 0xffff, 0xff};
    uint64_t v;
    if (!parse_u64(value, &v) || v > limits[slot - NYMM - NFPR])
        return fail(err, size, "bad value for %s: %s", name, value);
    switch (slot - NYMM - NFPR) {
    case 0:
        if (v & ~(uint64_t)mxcsr_mask)
            return fail(err, size, "mxcsr sets bits outside MXCSR_MASK (%" PRIx32 "): %" PRIx64, mxcsr_mask,
                        v & ~(uint64_t)mxcsr_mask);
        fp->mxcsr = (uint32_t)v;
        break;
    case 1: fp->fcw = (uint16_t)v; break;
    case 2: fp->fsw = (uint16_t)v; break;
    default: fp->ftw = (uint8_t)v; break;
    }
    return 1;
}

static void free_case(struct oracle_case* c) {
    for (size_t i = 0; i < c->nmem; i++) free(c->mem[i].bytes);
    free(c->mem);
    c->mem = NULL;
    c->nmem = 0;
}

/* Parses an input line (modified in place) into c; on failure, writes the
 * reason to err and returns 0. c must be freed with free_case either way. */
static int parse_case(char* line, struct oracle_case* c, char* err, size_t size) {
    memset(c, 0, sizeof *c);
    c->value[RFLAGS] = 2;
    c->fp.mxcsr = 0x1f80;
    c->fp.fcw = 0x37f;
    unsigned char seen[NREGS] = {0};
    unsigned char seen_fp[NFP_NAMES] = {0};
    char* save;
    char* tok = strtok_r(line, " \t", &save);
    if (!tok || strcmp(tok, "case")) return fail(err, size, "expected `case`");
    tok = strtok_r(NULL, " \t", &save);
    if (!tok || !parse_u64(tok, &c->code_addr)) return fail(err, size, "bad code address: %s", tok ? tok : "");
    tok = strtok_r(NULL, " \t", &save);
    if (!tok || !(c->code_len = parse_bytes(tok, c->code, sizeof c->code)))
        return fail(err, size, "bad code bytes: %s", tok ? tok : "");
    while ((tok = strtok_r(NULL, " \t", &save))) {
        char* eq = strchr(tok, '=');
        if (!eq) return fail(err, size, "expected name=value: %s", tok);
        *eq = 0;
        char* value = eq + 1;
        if (!strcmp(tok, "mem")) {
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
            continue;
        }
        int slot = fp_slot(tok);
        if (slot >= 0) {
            if (seen_fp[slot]) return fail(err, size, "register given twice: %s", tok);
            seen_fp[slot] = 1;
            c->has_fp = 1;
            if (!parse_fp(&c->fp, slot, tok, value, err, size)) return 0;
            continue;
        }
        size_t i = 0;
        while (i < NREGS && !(regs[i].input && !strcmp(regs[i].name, tok))) i++;
        if (i == NREGS) return fail(err, size, "unknown register: %s", tok);
        if (seen[i]) return fail(err, size, "register given twice: %s", tok);
        seen[i] = 1;
        if (!parse_u64(value, &c->value[i])) return fail(err, size, "bad value for %s: %s", tok, value);
    }
    uint64_t forbidden = c->value[RFLAGS] & FLAGS_FORBIDDEN;
    if (forbidden) return fail(err, size, "rflags sets bits that cannot be controlled: %" PRIx64, forbidden);
    c->value[RFLAGS] |= 2;
    return 1;
}

/* ---- Running a case (child) ---- */

static const struct oracle_case* current;
static int result_fd;
static unsigned long fs_base;
static char* out_buf;
static size_t out_len, out_cap;
static char altstack[1 << 16];

/* Everything below up to run_child runs in signal handlers: no stdio, no
 * malloc, and libc only through syscall(), whose PLT entry run_child has
 * already resolved. Built without stack protector, as the canary is read
 * through fs, which the instruction may have changed (wrfsbase). */

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

/* The AVX component (upper halves of ymm0-15) of a signal frame's FXSAVE
 * area fx, or NULL if the kernel did not save it with XSAVE or AVX is off. */
static unsigned char* frame_avx(unsigned char* fx) {
    if (get_le(fx + FX_SW_MAGIC1, 4) != FP_XSTATE_MAGIC1 || !avx_offset) return NULL;
    if (!(get_le(fx + FX_SW_XFEATURES, 8) & 4) || get_le(fx + FX_SW_EXTENDED_SIZE, 4) < avx_offset + 256ull)
        return NULL;
    return fx + avx_offset;
}

/* Writes the case's fp state into the frame (fx: its FXSAVE area), for
 * sigreturn to load with XRSTOR. */
static void load_fp(unsigned char* fx) {
    unsigned char* avx = frame_avx(fx);
    if (!avx) {
        put("skip the signal frame has no AVX state\n");
        finish();
    }
    const struct fp_state* fp = &current->fp;
    set_le(fx + FX_FCW, fp->fcw, 2);
    set_le(fx + FX_FSW, fp->fsw, 2);
    set_le(fx + FX_FTW, fp->ftw, 2);
    set_le(fx + FX_FOP, 0, 2);
    set_le(fx + FX_FIP, 0, 8);
    set_le(fx + FX_FDP, 0, 8);
    set_le(fx + FX_MXCSR, fp->mxcsr, 4);
    unsigned top = fp->fsw >> 11 & 7;
    for (unsigned i = 0; i < NFPR; i++) {
        __builtin_memcpy(fx + FX_ST + 16 * i, fp->fpr[(top + i) & 7], 10);
        __builtin_memset(fx + FX_ST + 16 * i + 10, 0, 6);
    }
    for (unsigned i = 0; i < NYMM; i++) {
        __builtin_memcpy(fx + FX_XMM + 16 * i, fp->ymm[i], 16);
        __builtin_memcpy(avx + 16 * i, fp->ymm[i] + 16, 16);
    }
    set_le(fx + XSAVE_HEADER, get_le(fx + XSAVE_HEADER, 8) | XSTATE_X87_SSE_AVX, 8);
}

/* Reads the fp state from a signal frame's FXSAVE area: a component whose
 * XSTATE_BV bit is clear is in its initial state. fp must be all zeros. */
static void read_fp(unsigned char* fx, struct fp_state* fp) {
    unsigned char* avx = frame_avx(fx);
    uint64_t bv = get_le(fx + FX_SW_MAGIC1, 4) == FP_XSTATE_MAGIC1 ? get_le(fx + XSAVE_HEADER, 8) : 3;
    fp->mxcsr = (uint32_t)get_le(fx + FX_MXCSR, 4);
    fp->fcw = 0x37f;
    if (bv & 1) {
        fp->fcw = (uint16_t)get_le(fx + FX_FCW, 2);
        fp->fsw = (uint16_t)get_le(fx + FX_FSW, 2);
        fp->ftw = fx[FX_FTW];
        unsigned top = fp->fsw >> 11 & 7;
        for (unsigned i = 0; i < NFPR; i++) __builtin_memcpy(fp->fpr[(top + i) & 7], fx + FX_ST + 16 * i, 10);
    }
    for (unsigned i = 0; i < NYMM; i++) {
        if (bv & 2) __builtin_memcpy(fp->ymm[i], fx + FX_XMM + 16 * i, 16);
        if (avx && (bv & 4)) __builtin_memcpy(fp->ymm[i] + 16, avx + 16 * i, 16);
    }
}

static void put_named(const char* name, int index, const unsigned char* p, size_t n) {
    put(" ");
    put(name);
    if (index >= 10) put("1"); /* decimal: indexes are below 20 */
    if (index >= 0) put_hex((uint64_t)index % 10);
    put("=");
    put_wide(p, n);
}

/* Prints the fp state in answer order. */
static void put_fp(const struct fp_state* fp) {
    unsigned char word[4];
    for (int i = 0; i < NYMM; i++) put_named("ymm", i, fp->ymm[i], 32);
    set_le(word, fp->mxcsr, 4);
    put_named("mxcsr", -1, word, 4);
    set_le(word, fp->fcw, 2);
    put_named("fcw", -1, word, 2);
    set_le(word, fp->fsw, 2);
    put_named("fsw", -1, word, 2);
    put_named("ftw", -1, &fp->ftw, 1);
    for (int i = 0; i < NFPR; i++) put_named("fpr", i, fp->fpr[i], 10);
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
    for (size_t i = 0; i < NREGS; i++)
        if (regs[i].input) uc->uc_mcontext.gregs[regs[i].greg] = (greg_t)current->value[i];
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)current->code_addr;
    uc->uc_mcontext.gregs[REG_EFL] = (greg_t)(current->value[RFLAGS] | FLAG_TF);
    if (current->has_fp) load_fp((unsigned char*)uc->uc_mcontext.fpregs);
    sigemptyset(&uc->uc_sigmask);
    /* sigreturn takes ID from the flags at the rt_sigreturn syscall, not
     * from the ucontext, so set it here; nothing on the way changes it. */
    uint64_t flags = __builtin_ia32_readeflags_u64();
    __builtin_ia32_writeeflags_u64((flags & ~FLAG_ID) | (current->value[RFLAGS] & FLAG_ID));
}

/* Reports the state after the instruction (single-step trap) or its fault. */
static void on_result(int sig, siginfo_t* si, void* ctx) {
    const ucontext_t* uc = ctx;
    const greg_t* gregs = uc->uc_mcontext.gregs;
    /* The instruction may have set AC (popf; Linux runs with CR0.AM) or
     * changed the fs base; undo both before running C and libc code. */
    __builtin_ia32_writeeflags_u64(__builtin_ia32_readeflags_u64() & ~FLAG_AC);
    syscall(SYS_arch_prctl, ARCH_SET_FS, fs_base);
    if (sig == SIGTRAP && si->si_code == TRAP_TRACE) {
        put("ok");
    } else {
        put("fault ");
        put(signal_name(sig));
        put(" code=");
        if (si->si_code < 0) put("-");
        put_hex(si->si_code < 0 ? -(int64_t)si->si_code : si->si_code);
        put(" addr=");
        put_hex((uintptr_t)si->si_addr);
    }
    for (size_t i = 0; i < NREGS; i++) {
        uint64_t v = (uint64_t)gregs[regs[i].greg];
        if (i == RFLAGS) v &= ~(FLAG_TF | FLAG_RF);
        put(" ");
        put(regs[i].name);
        put("=");
        put_hex(v);
    }
    if (current->has_fp) {
        /* Zero-initialized, as read_fp wants: this handler runs once. */
        static struct fp_state after;
        read_fp((unsigned char*)uc->uc_mcontext.fpregs, &after);
        put_fp(&after);
    }
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

/* Page-aligned [start, end) of the pages holding [addr, addr+len). */
struct span {
    uint64_t start, end;
};

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
    if (!page_span(c->code_addr, c->code_len, page, &spans[0]))
        child_answer("skip address not usable: %" PRIx64, c->code_addr);
    for (size_t i = 0; i < c->nmem; i++)
        if (!page_span(c->mem[i].addr, c->mem[i].len, page, &spans[i + 1]))
            child_answer("skip address not usable: %" PRIx64, c->mem[i].addr);
    struct span code = spans[0];
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
    memcpy((void*)(uintptr_t)c->code_addr, c->code, c->code_len);
    for (uint64_t p = code.start; p < code.end; p += page) {
        int prot = PROT_READ | PROT_EXEC;
        for (size_t i = 0; i < c->nmem; i++) {
            struct span s = {0, 0};
            if (page_span(c->mem[i].addr, c->mem[i].len, page, &s) && s.start <= p && p < s.end) prot |= PROT_WRITE;
        }
        if (mprotect((void*)(uintptr_t)p, page, prot)) child_answer("skip mprotect %" PRIx64 ": %s", p, strerror(errno));
    }
    free(spans);
}

static _Noreturn void run_child(const struct oracle_case* c, int fd) {
    current = c;
    result_fd = fd;
    if (syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base)) child_answer("skip arch_prctl: %s", strerror(errno));
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof altstack};
    if (sigaltstack(&ss, NULL)) child_answer("skip sigaltstack: %s", strerror(errno));
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&sa.sa_mask);
    sa.sa_sigaction = on_result;
    static const int results[] = {SIGTRAP, SIGSEGV, SIGBUS, SIGFPE, SIGILL};
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

/* Finds MXCSR_MASK and where XSAVE puts the AVX state. */
static void init_cpu(void) {
    static unsigned char fx[512] __attribute__((aligned(16)));
    __asm__ volatile("fxsave64 %0" : "=m"(fx));
    mxcsr_mask = (uint32_t)(fx[FX_MXCSR_MASK] | fx[FX_MXCSR_MASK + 1] << 8 | fx[FX_MXCSR_MASK + 2] << 16 |
                            (uint32_t)fx[FX_MXCSR_MASK + 3] << 24);
    if (!mxcsr_mask) mxcsr_mask = 0xffbf;
    unsigned a, b, c, d;
    /* AVX needs OSXSAVE (CPUID.1:ECX.27) and XCR0's SSE and AVX bits. */
    if (__get_cpuid_max(0, NULL) < 0xd || !__get_cpuid(1, &a, &b, &c, &d) || !(c >> 27 & 1)) return;
    unsigned xcr0, xcr0_high;
    __asm__ volatile("xgetbv" : "=a"(xcr0), "=d"(xcr0_high) : "c"(0));
    if ((xcr0 & 6) != 6) return;
    __cpuid_count(0xd, 2, a, b, c, d);
    avx_offset = b;
}

int main(void) {
    char* line = NULL;
    size_t size = 0;
    ssize_t n;
    init_cpu();
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
