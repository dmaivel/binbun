/* Two compilation units (with units-b.c): functions defined in each, one
   calling across. */
#include <stdio.h>

int scale(int x);
int offset(int x);

__attribute__((noinline)) static int twice(int x) { return 2 * x; }

int main(int argc, char **argv) {
    (void)argv;
    printf("%d\n", twice(scale(argc)) + offset(argc));
    return 0;
}
