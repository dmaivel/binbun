/* A program for the session's signature tests
   (crates/binbun-session/tests/signatures.rs), linked static with sigs.c
   and sigs-exit.c into sigs-app-gcc.elf, entered at app_start and
   stripped. exit is declared without noreturn, so fatal keeps code after
   its call: it returns only while exit is not known not to. Built by
   scripts/build-fixtures.sh. */

void exit(int code);
unsigned long sig_hash(const char *s);

static volatile int seen;

__attribute__((noipa)) void fatal(int code)
{
    exit(code);
    seen = code;
}

void app_start(void)
{
    static volatile unsigned long sink;
    sink = sig_hash("app");
    fatal(3);
}
