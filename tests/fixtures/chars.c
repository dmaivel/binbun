/* Bytes used as text, and bytes that are not: a path's first characters
 * tested, separators counted along a string, an option's letter switched
 * on, a line's newline replaced by a NUL; and a flag byte tested for one
 * value that happens to be a character's code, and bytes tested for
 * values no character has. See scripts/build-fixtures.sh. */
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) int absolute(const char *path)
{
    return path[0] == '/' || (path[0] == '.' && path[1] == '/');
}

__attribute__((noinline)) int separators(const char *text)
{
    int count = 0;
    for (; *text; text++)
        if (*text == ',' || *text == ';')
            count++;
    return count;
}

__attribute__((noinline)) int option(const char *argument)
{
    switch (argument[1]) {
    case 'a':
        return 1;
    case 'h':
        return 2;
    case 'v':
        return 3;
    case 'x':
        return 5;
    default:
        return 0;
    }
}

__attribute__((noinline)) void chomp(char *line)
{
    char *end = strchr(line, '\n');
    if (end)
        *end = '\0';
}

__attribute__((noinline)) int flagged(const unsigned char *flags) { return flags[0] == 64; }

__attribute__((noinline)) int marked(const unsigned char *bytes)
{
    return bytes[0] == 0xff || bytes[0] == 0x80;
}

int main(int argc, char **argv)
{
    char line[16] = "a,b;c\n";
    unsigned char bytes[2] = {(unsigned char)argc, 0x80};
    chomp(line);
    printf("%d %d %d %s %d %d\n", absolute(argv[0]), separators(line),
           option(argc > 1 ? argv[1] : "-h"), line, flagged(bytes), marked(bytes + 1));
    return 0;
}
