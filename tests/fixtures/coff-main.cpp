// coff-x86_64.exe: coff-x86_64.lib's functions linked into a program
// without the C runtime (cl /O2 /GS-, link /NODEFAULTLIB /ENTRY:entry
// /MAP), against coff-imports.lib: the program the library's pack names
// (crates/binbun/tests/signatures.rs), its map file the answers.

extern "C" int use_a(int);
extern "C" int use_b(int);
extern "C" int classify(int);
extern "C" int bump(void);
extern "C" int call_import(int);
extern "C" int guarded_store(int *);
extern "C" int weigh(unsigned);

// What the C runtime would define: the TLS index the loader sets, and
// the exception handler `__try` names.
extern "C" unsigned long _tls_index = 0;
extern "C" int __C_specific_handler(void *, void *, void *, void *) { return 1; }

extern "C" int entry(void)
{
    int value = 0;
    int total = use_a(1) + use_b(2) + classify(3) + bump() + call_import(4);
    total += guarded_store(&value) + weigh(5);
    return total + value;
}
