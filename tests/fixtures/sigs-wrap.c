/* The second object of sigs-gcc.a (crates/binbun/tests/signatures.rs):
   forwarders (a call that is the whole function, compiled to a jump) and
   an identical definition of sig_hash in another object. Linked with
   sigs.c into sigs-wrap-gcc.elf, entered at wrap_start and stripped:
   there tolower and sig_hash are reached only through the forwarders'
   jumps, so recovery first takes each forwarder and its callee as one
   function. Built by scripts/build-fixtures.sh. */

unsigned long sig_hash(const char *s);
int tolower(int c);

__attribute__((noipa)) unsigned long hash_of(const char *s)
{
    return sig_hash(s);
}

__attribute__((noipa)) int lower(int c)
{
    return tolower(c);
}

/* sig_hash's definition again. */
__attribute__((noipa)) unsigned long sig_hash_copy(const char *s)
{
    unsigned long h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h ^ 0x9e3779b97f4a7c15UL;
}

void wrap_start(void)
{
    static volatile unsigned long sink;
    sink = hash_of("wrap");
    sink = (unsigned long)lower('Q');
    sink = sig_hash_copy("copy");
    __builtin_trap();
}
