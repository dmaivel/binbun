// The COFF fixtures' shared definitions (coff-a.cpp, coff-b.cpp).

// Not inlined, defined in both objects: a COMDAT section in each, of which
// a linker keeps the first.
__declspec(noinline) inline int twice(int x) { return 2 * x + (x >> 3); }
