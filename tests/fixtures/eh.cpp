// C++ exception handling under MSVC (cl /O2 /EHsc /MD /Zi: see
// scripts/build-fixtures.sh), the shapes of handlers.cpp: catches by
// type, several, catch (...), rethrow, nested, cleanup only, in a loop,
// one function each (extern "C" for plain names). Built twice: with the
// default __CxxFrameHandler4 tables (eh-x86_64.exe) and with
// __CxxFrameHandler3's (/d2FH4-, eh-fh3-x86_64.exe).
#include <cstdio>
#include <stdexcept>

#define NOINLINE __declspec(noinline)

struct Error {
    int code;
};

// Counts the live guards: a local with a destructor, which an unwind
// funclet runs when an exception unwinds through its scope.
struct Guard {
    int *counter;
    explicit Guard(int *c) : counter(c) { ++*counter; }
    ~Guard() { --*counter; }
};

int live;

extern "C" {

NOINLINE int step(int x) {
    if (x < 0)
        throw Error{x};
    if (x > 100)
        throw std::runtime_error("too big");
    if (x == 42)
        throw 42;
    return x + 1;
}

NOINLINE void note(const char *what) { std::puts(what); }

// Catch by type.
NOINLINE int by_type(int x) {
    try {
        return step(x);
    } catch (const Error &e) {
        return e.code;
    }
}

// Several catches, tried in order.
NOINLINE int several(int x) {
    try {
        return step(x);
    } catch (const Error &e) {
        return e.code;
    } catch (const std::exception &e) {
        note(e.what());
        return -1;
    } catch (int code) {
        return code;
    }
}

// Any exception.
NOINLINE int any(int x) {
    try {
        return step(x);
    } catch (...) {
        return 0;
    }
}

// A handler that throws the exception on.
NOINLINE int rethrow(int x) {
    try {
        return step(x);
    } catch (const Error &) {
        note("error");
        throw;
    }
}

// A try inside a try.
NOINLINE int nested(int x) {
    try {
        int y = step(x);
        try {
            y = step(y);
        } catch (const Error &e) {
            y = e.code;
        }
        return step(y);
    } catch (const std::exception &e) {
        note(e.what());
        return -2;
    }
}

// No handler: the guard's destructor runs as the exception unwinds.
NOINLINE int cleanup(int x) {
    Guard guard(&live);
    return step(x) + step(x + 1);
}

// A handler in a loop.
NOINLINE int loop(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        try {
            total += step(i);
        } catch (const Error &e) {
            total -= e.code;
        }
    }
    return total;
}
}

int main(int argc, char **) {
    int inputs[] = {argc, -argc, 200, 42};
    for (int x : inputs) {
        std::printf("%d: by_type %d several %d any %d nested %d loop %d\n", x,
                    x == 200 || x == 42 ? 0 : by_type(x), several(x), any(x),
                    x < 0 || x == 42 ? 0 : nested(x),
                    loop(x < 0 ? 3 : x % 50));
        try {
            std::printf("rethrow %d\n", rethrow(x));
        } catch (const Error &e) {
            std::printf("rethrown %d\n", e.code);
        } catch (...) {
            std::printf("rethrown other\n");
        }
        try {
            std::printf("cleanup %d live %d\n", cleanup(x), live);
        } catch (...) {
            std::printf("cleanup threw, live %d\n", live);
        }
    }
    return 0;
}
