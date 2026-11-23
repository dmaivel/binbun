// The source of mangled-aarch64.elf, built by scripts/build-fixtures.sh:
// AArch64 functions whose Itanium manglings state their parameters (on
// AArch64 every one is placed), each loading through a pointer parameter.
// A pointer to a class is only a pointer: the load decides its target.
// Keep them in sync with crates/binbun/tests/manglings.rs.

    .text
    .globl _start
    .type _start, %function
_start:
    bl      _Z6secondP4Node
    bl      _Z6secondPv
    bl      _ZNK4Node4sizeEv
1:  b       1b
    .size _start, . - _start

// second(Node *node): node's 8 bytes at offset 8.
    .globl _Z6secondP4Node
    .type _Z6secondP4Node, %function
_Z6secondP4Node:
    ldr     x0, [x0, #8]
    ret
    .size _Z6secondP4Node, . - _Z6secondP4Node

// second(void *p): the same load, through a declared void *.
    .globl _Z6secondPv
    .type _Z6secondPv, %function
_Z6secondPv:
    ldr     x0, [x0, #8]
    ret
    .size _Z6secondPv, . - _Z6secondPv

// Node::size() const: this's 4 bytes at offset 4.
    .globl _ZNK4Node4sizeEv
    .type _ZNK4Node4sizeEv, %function
_ZNK4Node4sizeEv:
    ldr     w0, [x0, #4]
    ret
    .size _ZNK4Node4sizeEv, . - _ZNK4Node4sizeEv
