/* The source of cycles-x86_64.elf, built by scripts/build-fixtures.sh: a
   loop entered at two places (`goto` into its second half), so the
   registers it carries unchanged reach each of its joins from the other
   as well as from outside, and a stack protector, whose check reads the
   thread pointer at the exit. Keep it in sync with
   crates/binbun/tests/decompile.rs. */

#include <string.h>

/* Copies the fields of `s` before `;` into `out`, skipping those between
   `,` and the next `;`; a field starting `x` starts the skipping. */
__attribute__((noinline)) int scan(const char *s, char *out)
{
    char buf[64];
    int i = 0;
    if (*s == 'x')
        goto skipping;
copying:
    while (*s && *s != ';') {
        buf[i++ & 63] = *s++;
        if (*s == ',')
            goto skipping;
    }
    if (!*s)
        goto done;
    s++;
skipping:
    while (*s && *s != ';') {
        if (*s == '!')
            goto copying;
        s++;
    }
    if (*s) {
        s++;
        goto copying;
    }
done:
    memcpy(out, buf, sizeof buf);
    return i;
}

int main(int argc, char **argv)
{
    char out[64];
    return argc > 1 ? scan(argv[1], out) : 0;
}
