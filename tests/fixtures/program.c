/* The source of the checked-in test binaries in this directory, built by
 * scripts/build-fixtures.sh. Each function exercises something the loader
 * or the CFG recovery must get right; keep them in sync with the tests. */
#include <stdio.h>
#include <stdlib.h>

/* A dense switch: compiled to a jump table (an indirect jump). */
__attribute__((noinline)) int classify(int x) {
    switch (x) {
    case 0: return 10;
    case 1: return 21;
    case 2: return 32;
    case 3: return 43;
    case 4: return 54;
    case 5: return 65;
    case 6: return 76;
    default: return -1;
    }
}

/* Never returns: it ends in a call to the imported `exit`. */
__attribute__((noinline, noreturn)) void fail(const char *message) {
    puts(message);
    exit(2);
}

/* Calls a function that never returns: nothing follows that call. */
__attribute__((noinline)) int checked(int x) {
    if (x < 0)
        fail("negative");
    return classify(x) * 2;
}

/* A loop with a call in its body. */
__attribute__((noinline)) int loop_sum(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++)
        sum += checked(i % 7);
    return sum;
}

int main(int argc, char **argv) {
    (void)argv;
    printf("%d\n", loop_sum(argc + 5));
    return 0;
}
