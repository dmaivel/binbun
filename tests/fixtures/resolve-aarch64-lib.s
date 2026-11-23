// A stand-in for libc, which scripts/build-fixtures.sh links
// resolve-aarch64.elf against (and then deletes): the imports it names.

    .text
    .globl exit
    .type exit, %function
exit:
    b       exit
    .size exit, . - exit

    .globl abort
    .type abort, %function
abort:
    b       abort
    .size abort, . - abort

    .globl puts
    .type puts, %function
puts:
    ret
    .size puts, . - puts
