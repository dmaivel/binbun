/* The source of objects-gcc-x86_64.elf (-O2) and
   objects-gcc-O0-x86_64.elf (-O0), built by scripts/build-fixtures.sh:
   one object's fields, set through a pointer kept in a frame slot (-O0
   reloads it at each use), a pointer field returned only where it is
   null, an array field indexed where its bound is checked, and a
   function reading only two fields of an object its caller makes. Keep
   it in sync with crates/binbun/tests/decompile.rs. */

#include <stdlib.h>
#include <string.h>

struct var {
    char *name;
    char *value;
    long size;
    struct var *next;
    int flags;
};

static struct var *table;

struct shape {
    int rank;
    int dims[3];
    long count;
};

/* Each field of a new object, through its pointer. */
__attribute__((noinline)) struct var *make(char *name, char *value, int flags)
{
    struct var *v = malloc(sizeof *v);
    v->name = name;
    v->value = value;
    v->size = (long)strlen(value);
    v->next = table;
    v->flags = flags;
    table = v;
    return v;
}

/* The variable named `name`, if one is. */
__attribute__((noinline)) struct var *find(const char *name)
{
    for (struct var *v = table; v != 0; v = v->next)
        if (strcmp(v->name, name) == 0)
            return v;
    return 0;
}

/* The variable `v` refers to (its value names it), else `v`: its value,
   tested null, is what it returns where it is null. */
__attribute__((noinline)) struct var *resolve(struct var *v)
{
    if ((v->flags & 8) == 0)
        return v;
    char *target = v->value;
    if (target == 0)
        return (struct var *)target;
    struct var *found = find(target);
    return found != 0 ? found : v;
}

/* The product of the first `rank` of `dims`, where `rank` is at most
   their number: each read of `dims[i]` stays in the array. */
__attribute__((noinline)) long elements(struct shape *s)
{
    int rank = s->rank;
    if (rank < 0 || rank > 3)
        return -1;
    long n = 1;
    for (int i = 0; i < rank; i++)
        n *= s->dims[i];
    s->count = n;
    return n;
}

/* Two of a variable's fields: as much of `struct var` as it shows. */
__attribute__((noinline)) int describe(struct var *v)
{
    return (int)(strlen(v->name) + strlen(v->value));
}

/* A variable `make` makes, described: one object. */
__attribute__((noinline)) int made(char *name)
{
    struct var *v = make(name, name, 1);
    return describe(v);
}

/* The same with `rank` unchecked: `dims[i]` may be past the array (the
   bytes of `count`), so no subscript says it. */
__attribute__((noinline)) long unchecked(struct shape *s, int rank)
{
    long n = 1;
    for (int i = 0; i < rank; i++)
        n *= s->dims[i];
    s->count = n;
    return n;
}

int main(int argc, char **argv)
{
    struct var *v = make(argv[0], argc > 1 ? argv[1] : "", argc);
    struct shape s = { argc, { 2, 3, 4 }, 0 };
    return resolve(v)->flags + (int)elements(&s) + (int)unchecked(&s, argc) + made(argv[0]);
}
