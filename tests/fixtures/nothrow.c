/* The source of nothrow-x86_64.elf, built by scripts/build-fixtures.sh
   with -fexceptions: a cleanup (`release`) whose landing pad the exception
   table gives a range covering the calls of `found`, among them one of
   `strchr`, which the C library declares never to throw (between calls
   of `puts`, which may). Keep in sync with crates/binbun/tests/lower.rs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void release(char **copy)
{
    free(*copy);
}

/* Where `c` is in `s`, after printing it; 0 if it is not there. */
__attribute__((noinline)) size_t found(const char *s, int c)
{
    char *copy __attribute__((cleanup(release))) = strdup(s);
    puts(copy);
    char *at = strchr(copy, c);
    puts(at ? at : "");
    return at ? (size_t)(at - copy) : 0;
}

int main(int argc, char **argv)
{
    return (int)found(argc > 1 ? argv[1] : "binbun", 'b');
}
