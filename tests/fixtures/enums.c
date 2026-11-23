/* Values of enumerations kept in variables: the test declares, as the
   user would, `enum status status(void)` and `enum other other(void)`
   (here they return `int`), and the callers keep, compare and switch on
   what they return. `mixed` keeps values of both enumerations in one
   variable, `stepped` a status or a product. */
#define NOINLINE __attribute__((noinline))

volatile int sink;

NOINLINE int status(void) { return sink; }
NOINLINE int other(void) { return sink + 1; }
NOINLINE void idle(void) { sink = 10; }
NOINLINE void busy(void) { sink = 20; }
NOINLINE void gone(void) { sink = 40; }

/* A status kept and compared twice. */
NOINLINE int compared(void) {
    int s = status();
    if (s == 3)
        return 10;
    sink = s;
    if (s == 5)
        return 20;
    return 0;
}

/* A switch on a status. */
NOINLINE void switched(void) {
    switch (status()) {
    case 1: idle(); break;
    case 2: busy(); break;
    case 4: gone(); break;
    default: sink = 0; break;
    }
}

/* A status or an other in one variable. */
NOINLINE int mixed(int which) {
    int s = which ? status() : other();
    if (s == 3)
        return 10;
    sink = s;
    if (s == 5)
        return 20;
    return 0;
}

/* A status, or a product, in one variable. */
NOINLINE int stepped(int step) {
    int s = status();
    if (step)
        s = sink * step;
    if (s == 3)
        return 10;
    sink = s;
    if (s == 5)
        return 20;
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    switched();
    return compared() + mixed(argc) + stepped(argc);
}
