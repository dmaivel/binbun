/* The source of futex-x86_64.elf, built by scripts/build-fixtures.sh:
   functions that call the kernel's futex with the `syscall` instruction,
   as a C library's lock code does, setting only the arguments their
   operation reads (FUTEX_WAIT four, FUTEX_WAKE three) and leaving the
   other argument registers as their callers did. Keep it in sync with
   crates/binbun/tests/decompile.rs. */

#include <stdatomic.h>

#define SYS_futex 202
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE_PRIVATE 129
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE_FLAG 128

/* Waits while the word is 2: futex(word, FUTEX_WAIT_PRIVATE, 2, NULL). */
__attribute__((noinline)) long wait_on(int *word)
{
    register long timeout __asm__("r10") = 0;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "0"((long)SYS_futex), "D"(word), "S"((long)FUTEX_WAIT_PRIVATE),
                       "d"(2L), "r"(timeout)
                     : "rcx", "r11", "memory");
    return result;
}

/* Wakes one waiter: futex(word, FUTEX_WAKE_PRIVATE, 1). */
__attribute__((noinline)) long wake_one(int *word)
{
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "0"((long)SYS_futex), "D"(word), "S"((long)FUTEX_WAKE_PRIVATE),
                       "d"(1L)
                     : "rcx", "r11", "memory");
    return result;
}

/* Wakes one waiter, private or shared as `private` says (its
   FUTEX_PRIVATE_FLAG bit): the operation's command is known, its flag
   not. */
__attribute__((noinline)) long wake_kind(int *word, int private)
{
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "0"((long)SYS_futex), "D"(word),
                       "S"((long)(FUTEX_WAKE | (private & FUTEX_PRIVATE_FLAG))), "d"(1L)
                     : "rcx", "r11", "memory");
    return result;
}

/* Wakes one waiter as glibc's __lll_lock_wake does: `private` is 0 or
   FUTEX_PRIVATE_FLAG, xor-ed into FUTEX_WAKE_PRIVATE, so the operation's
   command is FUTEX_WAKE only if `private` has no other bit set, which
   only its callers show. */
__attribute__((noinline)) long wake_shared(int *word, int private)
{
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "0"((long)SYS_futex), "D"(word),
                       "S"((long)(private ^ FUTEX_WAKE_PRIVATE)), "d"(1L)
                     : "rcx", "r11", "memory");
    return result;
}

/* Takes the lock, waiting while another holds it. */
__attribute__((noinline)) void lock(atomic_int *word)
{
    int expected = 0;
    while (!atomic_compare_exchange_strong(word, &expected, 2)) {
        wait_on((int *)word);
        expected = 0;
    }
}

atomic_int word;

int main(void)
{
    lock(&word);
    atomic_store(&word, 0);
    return (int)(wake_one((int *)&word) + wake_kind((int *)&word, 0) +
                 wake_shared((int *)&word, 0));
}
