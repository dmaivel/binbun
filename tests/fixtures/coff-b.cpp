// The second COFF object of coff-x86_64.lib (see coff-a.cpp).

#include "coff.h"

extern "C" int use_b(int x) { return twice(x) - 1; }

// Read-only data another object's code does not see: a table indexed.
static const unsigned char weights[8] = {3, 1, 4, 1, 5, 9, 2, 6};

extern "C" int weigh(unsigned x) { return weights[x & 7] + use_b(static_cast<int>(x)); }
