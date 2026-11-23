/* The signatures evaluation's word count (scripts/signatures/corpus.sh):
 * lines, words and bytes of each file or standard input, as wc prints
 * them, using a little of most of the C library (stdio, string, ctype,
 * stdlib, errno, locale). */
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct counts {
    unsigned long lines, words, bytes;
};

static int count(FILE *file, struct counts *counts)
{
    char buffer[4096];
    size_t got;
    int in_word = 0;
    while ((got = fread(buffer, 1, sizeof buffer, file)) > 0) {
        counts->bytes += got;
        for (size_t i = 0; i < got; i++) {
            unsigned char c = (unsigned char)buffer[i];
            if (c == '\n')
                counts->lines++;
            if (isspace(c)) {
                in_word = 0;
            } else if (!in_word) {
                in_word = 1;
                counts->words++;
            }
        }
    }
    return ferror(file) ? -1 : 0;
}

static void show(const struct counts *counts, const char *name)
{
    char line[128];
    snprintf(line, sizeof line, "%7lu %7lu %7lu", counts->lines, counts->words, counts->bytes);
    if (name)
        printf("%s %s\n", line, name);
    else
        puts(line);
}

int main(int argc, char **argv)
{
    struct counts total = {0, 0, 0};
    int status = 0;
    setlocale(LC_ALL, "");
    if (argc < 2) {
        struct counts counts = {0, 0, 0};
        if (count(stdin, &counts) != 0) {
            fprintf(stderr, "wc: %s\n", strerror(errno));
            return 1;
        }
        show(&counts, NULL);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        struct counts counts = {0, 0, 0};
        FILE *file = strcmp(argv[i], "-") == 0 ? stdin : fopen(argv[i], "rb");
        if (!file) {
            fprintf(stderr, "wc: %s: %s\n", argv[i], strerror(errno));
            status = 1;
            continue;
        }
        if (count(file, &counts) != 0) {
            fprintf(stderr, "wc: %s: %s\n", argv[i], strerror(errno));
            status = 1;
        }
        if (file != stdin)
            fclose(file);
        show(&counts, argv[i]);
        total.lines += counts.lines;
        total.words += counts.words;
        total.bytes += counts.bytes;
    }
    if (argc > 2)
        show(&total, "total");
    return status ? EXIT_FAILURE : EXIT_SUCCESS;
}
