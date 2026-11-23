// The source of handlers-gcc-x86_64.elf and handlers-clang-x86_64.elf,
// built by scripts/build-fixtures.sh with G++ and Clang: the shapes of C++
// exception handling a decompiler meets, one function each (extern "C"
// for plain names). The two compilers lay out landing pads and test the
// selector differently.
#include <cstdio>
#include <stdexcept>

struct Error {
    int code;
};

// Counts the live guards: a local with a destructor, which a cleanup
// landing pad runs when an exception unwinds through its scope.
struct Guard {
    int *counter;
    explicit Guard(int *c) : counter(c) { ++*counter; }
    ~Guard() { --*counter; }
};

int live;

extern "C" {

__attribute__((noinline)) int step(int x) {
    if (x < 0)
        throw Error{x};
    if (x > 100)
        throw std::runtime_error("too big");
    if (x == 42)
        throw 42;
    return x + 1;
}

__attribute__((noinline)) void note(const char *what) {
    std::puts(what);
}

// Catch by type.
__attribute__((noinline)) int by_type(int x) {
    try {
        return step(x);
    } catch (const Error &e) {
        return e.code;
    }
}

// Several catches, tried in order.
__attribute__((noinline)) int several(int x) {
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
__attribute__((noinline)) int any(int x) {
    try {
        return step(x);
    } catch (...) {
        return 0;
    }
}

// A handler that throws the exception on.
__attribute__((noinline)) int rethrow(int x) {
    try {
        return step(x);
    } catch (const Error &) {
        note("error");
        throw;
    }
}

// A try inside a try.
__attribute__((noinline)) int nested(int x) {
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
__attribute__((noinline)) int cleanup(int x) {
    Guard guard(&live);
    return step(x) + step(x + 1);
}

// A handler in a loop.
__attribute__((noinline)) int loop(int n) {
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
    return by_type(argc) + several(argc) + any(argc) + rethrow(argc) + nested(argc) +
           cleanup(argc) + loop(argc);
}
