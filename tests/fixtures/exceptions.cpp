// The source of the exception-handling test binaries in this directory,
// built by scripts/build-fixtures.sh: `guarded`'s catch block is reached
// only by the unwinder, through the landing pad in its exception table.
#include <cstdio>
#include <stdexcept>

__attribute__((noinline)) int risky(int x) {
    if (x > 3)
        throw std::runtime_error("too big");
    return x * 2;
}

__attribute__((noinline)) int guarded(int x) {
    try {
        return risky(x);
    } catch (const std::exception &e) {
        std::puts(e.what());
        return -1;
    }
}

int main(int argc, char **) {
    return guarded(argc) > 0 ? 0 : 1;
}
