/* The source of forwarded-x86_64.elf and forwarded-x86_64.so, built by
   scripts/build-fixtures.sh: calls that leave argument registers as the
   caller found them, to variadic library functions after the named
   arguments and through a pointer; in the shared object, the calls of
   its own exported functions go through their PLT stubs. Keep it in sync
   with crates/binbun/tests/decompile.rs. */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* Two arguments: `rdx` holds whatever `main`'s caller left there. */
__attribute__((noinline)) int check_tty(void)
{
    int fd = open("/dev/tty", O_RDWR | O_NONBLOCK);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

/* Three arguments: the mode is this function's own third, passed on in
   place. */
__attribute__((noinline)) int wrap_open(const char *path, int flags, mode_t mode)
{
    return open(path, flags, mode);
}

/* Passes its own third on to `wrap_open` in turn. */
__attribute__((noinline)) int wrap_twice(const char *path, int flags, mode_t mode)
{
    puts(path);
    return wrap_open(path, flags, mode);
}

/* Two arguments, passed on through a pointer: `rdx` to `r9` are whatever
   the caller left. */
void (*on_error)(const char *message, int code);

__attribute__((noinline)) void report(const char *message, int code)
{
    on_error(message, code);
}

int main(int argc, char **argv)
{
    (void)argc;
    int result = check_tty() + wrap_twice(argv[0], O_CREAT | O_WRONLY, 0644);
    report("done", result);
    return result;
}
