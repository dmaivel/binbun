// The source of classes-gcc-x86_64.elf and classes-clang-x86_64.elf, built
// by scripts/build-fixtures.sh with G++ and Clang: classes with virtual
// methods (a base class, two derived classes), their constructors storing
// vtable addresses, and virtual calls through a base pointer (extern "C"
// for plain names where a function is not a method).
#include <cstdio>
#include <cstdlib>

struct Shape {
    int sides;
    explicit Shape(int n) : sides(n) {}
    virtual ~Shape() {}
    virtual long area() const = 0;
    virtual const char *name() const { return "shape"; }
};

struct Square : Shape {
    long side;
    explicit Square(long s) : Shape(4), side(s) {}
    long area() const override { return side * side; }
    const char *name() const override { return "square"; }
};

struct Rectangle : Shape {
    long width;
    long height;
    Rectangle(long w, long h) : Shape(4), width(w), height(h) {}
    long area() const override { return width * height; }
};

extern "C" {

// Makes a shape the caller cannot see the class of.
__attribute__((noinline)) Shape *make(int kind, long a, long b) {
    if (kind == 0)
        return new Square(a);
    return new Rectangle(a, b);
}

// Virtual calls through a base pointer (neither a tail call).
__attribute__((noinline)) long describe(const Shape *s) {
    std::printf("%s with %d sides\n", s->name(), s->sides);
    return s->area() + s->sides;
}

// A virtual destructor called through a base pointer (a tail call).
__attribute__((noinline)) void destroy(Shape *s) {
    delete s;
}

}

int main(int argc, char **argv) {
    long a = argc > 1 ? std::atol(argv[1]) : 3;
    Shape *s = make(argc & 1, a, a + 1);
    long area = describe(s);
    destroy(s);
    return (int)(area & 0x7f);
}
