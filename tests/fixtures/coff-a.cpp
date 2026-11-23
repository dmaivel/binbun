// COFF objects for the relocatable loader (crates/binbun-loader/tests/coff.rs)
// and `sig make` from a .lib (crates/binbun/tests/signatures.rs): built with
// MSVC's cl /O2 /Gy and lib (scripts/build-fixtures.sh).

#include "coff.h"

// A function in a DLL: called through `__imp_imported`.
extern "C" __declspec(dllimport) int imported(int);

// Thread-local: `.tls$`, `_tls_index`, `SECREL`.
__declspec(thread) int counter = 7;

// No object defines `hook`: it is `default_hook`, as the directive says.
extern "C" int hook(int);
#pragma comment(linker, "/alternatename:hook=default_hook")

extern "C" int default_hook(int x) { return x * 3; }

extern "C" int use_a(int x) { return twice(x) + 1; }

// A dense switch: a jump table of offsets from `__ImageBase` (`ADDR32NB`).
extern "C" int classify(int x)
{
    switch (x) {
    case 0: return 11;
    case 1: return hook(x) + 13;
    case 2: return 17 * x;
    case 3: return x ^ 0x55;
    case 4: return imported(x);
    case 5: return twice(x) - 4;
    case 6: return 23;
    default: return -1;
    }
}

extern "C" int bump(void) { return ++counter; }

extern "C" int call_import(int x) { return imported(x) + 1; }

// `__try`/`__except`: `.pdata` and `.xdata` naming __C_specific_handler.
extern "C" int guarded_store(int *p)
{
    __try {
        *p = 1;
    } __except (1) {
        return -1;
    }
    return 0;
}
