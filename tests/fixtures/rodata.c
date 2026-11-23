/* Read-only data in the executable segment: linked with
   -z noseparate-code, as Debian's arm64 binaries are, `.rodata` shares the
   R+X segment with `.text`. The data holds pointers to both: to strings in
   `.rodata` (`names`) and to functions (`operations`). */
#include <stdio.h>

static const char *names[] = {"zero", "one", "two"};

static int twice(int x) { return 2 * x; }
static int square(int x) { return x * x; }
int (*operations[])(int) = {twice, square};

int main(int argc, char **argv) {
    (void)argv;
    printf("%s %d\n", names[argc % 3], operations[argc & 1](argc));
    return 0;
}
