#!/bin/sh
# Rebuilds the test binaries in tests/fixtures from program.c:
#
#   program-x86_64.elf   GCC, -O2, PIE, symbols and .eh_frame kept
#   program-x86_64.exe   MinGW-w64, -O2, PE32+, symbols and .pdata kept
#   program-i686.exe     MinGW-w64, -O2, PE32
#
# and from stacked.c:
#
#   stacked-x86_64.elf   GCC, -O2, PIE: a seventh parameter, on the stack
#
# and from callbacks.c:
#
#   callbacks-x86_64.elf  GCC, -O2, PIE: calls through pointers, one
#                         setting an argument, one setting none
#
# and from exceptions.cpp:
#
#   exceptions-x86_64.elf  G++, -O2, PIE: a catch block reached only through
#                          its landing pad
#
# and from handlers.cpp:
#
#   handlers-gcc-x86_64.elf, handlers-clang-x86_64.elf  G++ and Clang, -O2,
#                          PIE: catches by type, several, catch (...),
#                          rethrow, nested, cleanup only, in a loop
#
# and from classes.cpp:
#
#   classes-gcc-x86_64.elf, classes-clang-x86_64.elf  G++ and Clang, -O2,
#                          PIE: a base class with virtual methods, two
#                          derived classes, virtual calls through a base
#                          pointer (C++ classes from RTTI and vtables)
#
# and from rodata.c:
#
#   rodata-x86_64.elf  GCC, -O2, PIE, -z noseparate-code: .rodata in the
#                      executable segment, as Debian links for arm64
#
# and from variadic.c:
#
#   variadic-gcc-x86_64.elf, variadic-clang-x86_64.elf  GCC and Clang, -O2,
#                      PIE; variadic-x86_64.exe  MinGW-w64, -O2, PE32+;
#                      variadic-clang-aarch64.elf  Clang (zig cc) for
#                      AArch64 Linux, -O2: variadic definitions (System V,
#                      Microsoft x64 and AAPCS64)
#   variadic-gcc-O0-x86_64.elf  GCC, -O0, PIE: every local in the frame
#                      beside the register save area and the va_list
#
# and from objects.c:
#
#   objects-gcc-O0-x86_64.elf  GCC, -O0, PIE: one object's fields set
#                      through a pointer reloaded from its frame slot
#   objects-gcc-x86_64.elf  GCC, -O2, PIE: a pointer field returned
#                      only where it is null
#
# and from floats.c:
#
#   floats-x86_64.elf  GCC, -O2, PIE: scalar floating point in SSE
#                      registers (arithmetic, conversions, comparisons,
#                      signs, a sum over a loop)
#   floats-aarch64.elf Clang (zig cc) for AArch64 Linux, -O2: the same in
#                      SIMD&FP registers
#
# and from kept-float.c:
#
#   kept-float-aarch64.elf  Clang (zig cc) for AArch64 Linux, -O2;
#                      kept-float-x86_64.exe  MinGW-w64, -O2, PE32+: a
#                      double kept across a call of an import in d8 and
#                      xmm6, whose low bits the callee keeps
#
# and from simd.c:
#
#   simd-avx2-x86_64.elf  GCC, -O3 -mavx2, PIE: loops vectorised with
#                      256-bit AVX2 (values wider than 128 bits in C)
#
# and from atomics.c:
#
#   atomics-x86_64.elf  GCC, -O2, PIE: C11 atomic operations, each one
#                      locked instruction (and one compare-and-exchange
#                      loop)
#
# and from enums.c:
#
#   enums-x86_64.elf   GCC, -O2, PIE: values a callee returns kept,
#                      compared and switched on (the test declares the
#                      callees to return enumerations)
#
# and from chars.c:
#
#   chars-x86_64.elf   GCC, -O2, PIE: bytes used as text (compared with
#                      characters, a newline stored) and bytes that are
#                      not
#
# and from unaligned.c:
#
#   unaligned-x86_64.elf  GCC, -O2, PIE: loads and stores at addresses of
#                      no alignment (fixed-size memcpy), through two
#                      addresses that may overlap in part
#
# and from aggregates.c:
#
#   aggregates-x86_64.elf  GCC, -O2, PIE: calls of library functions that
#                      return a struct by value, in two registers
#                      (`imaxdiv`) and in memory (`mallinfo2`)
#
# and from forwarded.c:
#
#   forwarded-x86_64.elf  GCC, -O2, PIE: calls of `open` with two and
#                      with three arguments, the third the caller's own
#                      passed on in place, and a call through a pointer
#   forwarded-x86_64.so  GCC, -O2, -fPIC -shared: the same, its calls of
#                      its own exported functions through their PLT stubs
#
# and from cycles.c:
#
#   cycles-x86_64.elf  GCC, -O2, -fstack-protector-all: a loop entered at
#                      two places, the thread pointer read at the exit
#
# and from bits.c:
#
#   bits-x86_64.elf    GCC, -O2: `bsr` on a value tested for zero first
#
# and from x87.c:
#
#   x87-x86_64.elf     GCC, -O2: `fnstenv`, `fldenv`, `fwait`
#
# and from nothrow.c:
#
#   nothrow-x86_64.elf GCC, -O2 -fexceptions -fno-builtin: a call of
#                      `strchr` (never throws) in a cleanup's range
#
# and from ifunc.c:
#
#   ifunc-x86_64.elf   GCC, -O2, -fno-builtin, -rdynamic: an exported
#                      indirect function (`strlen`) called through its
#                      IRELATIVE slot
#
# and from futex.c:
#
#   futex-x86_64.elf   GCC, -O2: calls of the kernel's futex with the
#                      `syscall` instruction, only the arguments the
#                      operation reads set
#
# and from chained.s:
#
#   chained-x86_64.exe     MinGW-w64 as and ld, PE32+: code split off a
#                          function, x64 `.pdata` entries chained to its
#                          own (both forms of the chain)
#
# and from aggregates-win.c:
#
#   aggregates-x86_64.exe  MinGW-w64, -O2, PE32+: calls of functions that
#                      take a struct by value in a register (`COORD`),
#                      return one in `eax`, and return one in memory
#                      (`lldiv`)
#
# and from saves-win.c:
#
#   saves-x86_64.exe  MinGW-w64, -O2, PE32+: a function that saves and
#                     restores the callee-saved `xmm6`
#
# and from records.c:
#
#   records-x86_64.elf, records-x86_64.debug  GCC, -O2 -g, PIE, the DWARF
#                      apart: functions that take and return structs by
#                      value (in two registers, in a vector and an
#                      integer register, in memory)
#
# and from dozen-aarch64.s:
#
#   dozen-aarch64.elf  clang (AArch64 assembler) and ld.lld, static, symbols
#                      kept: functions made only of the instructions
#                      binbun-aarch64-lift has semantics for
#
# and from opaque-aarch64.s and opaque-x86_64.s:
#
#   opaque-aarch64.elf, opaque-x86_64.elf  clang and ld.lld, static: frame
#                      pointers passed through instructions without
#                      semantics
#
# and from kept-x86_64.s:
#
#   kept-x86_64.elf  clang and ld.lld, static: a callee-saved register
#                    saved and read on a path that did not assign it, a
#                    caller passing its own on, and one read unsaved
#
# and from undefined-x86_64.s:
#
#   undefined-x86_64.elf  clang and ld.lld, static: flags SHRD leaves
#                      undefined read by a branch, SETO and LAHF
#
# and from resolve-aarch64.s:
#
#   resolve-aarch64.elf  clang and ld.lld, dynamic, linked against a stub
#                      library (resolve-aarch64-lib.s, deleted after the
#                      link): PLT and GOT calls to imports, switch tables
#
# and from mangled-aarch64.s:
#
#   mangled-aarch64.elf  clang and ld.lld, static: functions with Itanium
#                      manglings loading through pointer parameters
#
# and from globals-x86_64.s:
#
#   globals-x86_64.elf  clang and ld.lld, static: a global struct written
#                      field by field and read in parts
#
# and from pointers-x86_64.s:
#
#   pointers-x86_64.elf  clang and ld.lld, static: globals holding an
#                      array's address, read through an index: of
#                      pointers, of 16-byte elements, of pointers an
#                      integer is stored into, of pointers read at an
#                      offset computed apart (`n * 8 - 8`), and two read
#                      off their elements
#
# and from interfaces-x86_64.s:
#
#   interfaces-x86_64.elf  clang and ld.lld, static: functions whose
#                      parameters are what their code reads (a register's
#                      bits an `and` masks off, stack arguments after
#                      ones not read), and a conditional move from memory
#
# and from textstrings-x86_64.s:
#
#   textstrings-x86_64.elf  clang and ld.lld, static: a narrow and a wide
#                      string in .text after the code, and code, whose
#                      addresses only `lea` takes
#
# and from sigs.c (the library signature tests; freestanding, no unwind
# tables, GCC's loop idioms off so its loops stay loops):
#
#   sigs-gcc.a         GCC -O2, an archive of its object and sigs-wrap.c's
#                      (forwarders, an identical definition)
#   sigs-gcc-r8.o, sigs-gcc-r1011.o
#                      the same with r8 (r10 and r11) fixed: another
#                      register allocation
#   sigs-gcc-blocks.o  the same with -freorder-blocks-algorithm=simple:
#                      another block layout
#   sigs-gcc-pie.o     the same, -fPIE
#   sigs-gcc-lo.elf, sigs-gcc-hi.elf
#                      the same linked static at 0x400000 and 0x12340000
#   sigs-clang.o       Clang -O2
#   sigs-wrap-gcc.elf  sigs.c and sigs-wrap.c linked static, entered at
#                      wrap_start: read without its symbols, callees are
#                      reached only through forwarders' jumps
#   sigs-exit-gcc.o    sigs-exit.c: a library's exit (never returns)
#   sigs-app-gcc.elf   sigs.c, sigs-exit.c and sigs-app.c linked static,
#                      entered at app_start, stripped: a program whose
#                      library functions signatures name in a session
#
# Needs cc, c++, x86_64-w64-mingw32-gcc, i686-w64-mingw32-gcc, clang,
# clang++, ld.lld, llvm-objcopy and zig (its `zig cc`, for AArch64 Linux
# with glibc).
# The outputs are checked in, so tests do not need these tools.
#
# and, when MSVC's cl is on PATH (msvc-wine's wrappers, run under Wine),
# from msvc.c:
#
#   msvc-x86_64.exe  MSVC x64, /O2 /MD /Zi, reproducible (/Brepro): built in
#                    a scratch directory, so its PDB (the signature
#                    oracle: llvm-pdbutil dump --symbols --modi=0 and
#                    --types) is checked in beside it (msvc-x86_64.pdb,
#                    binbun_debuginfo::info's PDB oracle)
#   records-x86_64.exe, records-x86_64.pdb  MSVC x64, the same way, from
#                    records-win.c: functions that take and return
#                    structs by value (as an integer, as a pointer to a
#                    copy, in memory)
#   teb-x86_64.exe   MSVC x64, /O2 /MD, reproducible, from teb.c: walks
#                    from the TEB to the loader's module list
#   teb-aarch64.exe  MSVC ARM64 (msvc-wine's arm64 wrappers beside cl's
#                    directory), /O2 /MD, linked with ntdll.lib,
#                    reproducible, from teb.c: the same walks from x18's
#                    TEB, and a call of ntdll.dll's
#                    NtQueryInformationProcess
#   seh-x86_64.exe   MSVC x64, /O2 /MD /Zi, reproducible, from seh.c:
#                    __try/__except (a filter expression, and
#                    EXCEPTION_EXECUTE_HANDLER), __try/__finally, nested
#                    (__C_specific_handler's scope tables), PDB kept
#   eh-x86_64.exe, eh-fh3-x86_64.exe
#                    MSVC x64, /O2 /EHs /MD /Zi, reproducible, from eh.cpp:
#                    C++ try/catch (by type, several, catch (...),
#                    rethrow, nested, cleanup only, in a loop), with the
#                    default __CxxFrameHandler4 tables and with
#                    __CxxFrameHandler3's (/d2FH4-), PDBs kept. /EHs, not
#                    /EHsc: the functions are extern "C" (plain names),
#                    which /EHc assumes never throw
#
#                    seh-x86_64.stdout and eh-x86_64.stdout: what they
#                    print when run without arguments (WINEDEBUG=-all
#                    wine; the two eh builds print the same)
#   coff-x86_64.lib  MSVC x64 objects (cl /c /O2 /Gy /GS- /Brepro) of
#                    coff-a.cpp and coff-b.cpp in a lib archive: a COMDAT
#                    function both define, /alternatename, a dllimport
#                    call, a thread-local, a jump table from __ImageBase,
#                    __try (the COFF loader and sig make's tests)
#   coff-imports.lib an import library (lib /def:coff-imports.def)
#   coff-x86_64.exe, coff-x86_64.map
#                    coff-main.cpp linked with both (no C runtime:
#                    /NODEFAULTLIB /ENTRY:entry), with link's map file
#                    (the names sig match is scored against)
#
# and, on Windows with the WDK (not this script: msvc-wine has no WDK),
# from driver.c by scripts/build-driver-fixture.bat:
#
#   driver-x86_64.sys  MSVC x64 with the WDK's kernel-mode flags for a WDM
#                    driver's Debug configuration, reproducible: wide and
#                    narrow string literals in .text (-cbstring), kernel
#                    imports, a gs-relative read; its PDB kept
#                    (driver-x86_64.pdb)
#
# and the type oracle of the ELF fixtures built from C and C++ (binbun_debuginfo::info):
#
#   program-x86_64.debug, rodata-x86_64.debug, exceptions-x86_64.debug,
#   handlers-gcc-x86_64.debug, handlers-clang-x86_64.debug,
#   stacked-x86_64.debug
#                    the same compilations with -g, objcopy
#                    --only-keep-debug: -g does not change the code, so the
#                    DWARF describes the -g0 binaries' addresses (only the
#                    build IDs differ)
#
# and from units-a.c and units-b.c:
#
#   units-x86_64.elf, units-x86_64.debug
#                    GCC, -O2 -g, PIE, two compilation units (the build
#                    directory mapped to /src): the DWARF split off with
#                    objcopy --only-keep-debug, the binary stripped of it
#                    and linked to it (--add-gnu-debuglink; one build ID)
#
# and, run on a Mac as `scripts/build-fixtures.sh macos` (Xcode's clang,
# ld, lipo, dsymutil and strip; only these are built then), from
# program.c and exceptions.cpp:
#
#   program-universal.macho
#                    clang -O2, universal: x86_64 for macOS 10.15
#                    (LC_DYLD_INFO_ONLY's bind and rebase opcodes, lazy
#                    binds through __la_symbol_ptr), arm64 for macOS 13
#                    (chained fixups, DYLD_CHAINED_PTR_64) and arm64e
#                    for macOS 13 (chained fixups with authenticated
#                    pointers, __auth_stubs and __auth_got); built with
#                    -g, then its debug symbols stripped (strip -S) after
#                    dsymutil gathered them into
#   program-universal.macho.dSYM
#                    its dSYM bundle (one DWARF file of the three slices,
#                    matched by UUID; the build directory mapped to `.`;
#                    dsymutil's Relocations directory left out)
#   exceptions-universal.macho
#                    clang++ -O2, x86_64 and arm64e: the LSDA reached
#                    through __unwind_info
set -eu

dir=$(cd "$(dirname "$0")/../tests/fixtures" && pwd)
cd "$dir"
# Debug information names the directory it was compiled in: every -g
# compile here names it /src, never the build machine's path.
map="-ffile-prefix-map=$dir=/src"
# zig cc compiles glibc's start files (start.S, init.c) with debug
# information whatever -g says, naming this directory; the fixtures it
# builds keep none, and keep their symbols (zig's own --strip-debug drops
# them too). The first argument is the output.
zig_aarch64() {
    out=$1
    shift
    zig cc -target aarch64-linux-gnu -o "$out" "$@"
    llvm-objcopy --strip-debug "$out"
}

if [ "${1:-}" = macos ]; then
    scratch=$(mktemp -d)
    cp program.c exceptions.cpp "$scratch"
    (
        cd "$scratch"
        for spec in "x86_64 10.15" "arm64 13.0" "arm64e 13.0"; do
            set -- $spec
            flags="-arch $1 -mmacosx-version-min=$2 -O2"
            # shellcheck disable=SC2086
            clang $flags -g -fdebug-prefix-map="$PWD=." -c -o "program-$1.o" program.c
            # shellcheck disable=SC2086
            clang $flags -o "program-$1" "program-$1.o"
            if [ "$1" != arm64 ]; then
                # shellcheck disable=SC2086
                clang++ $flags -g0 -o "exceptions-$1" exceptions.cpp
            fi
        done
        lipo -create -output program-universal.macho program-x86_64 program-arm64 program-arm64e
        dsymutil program-universal.macho -o program-universal.macho.dSYM
        rm -r program-universal.macho.dSYM/Contents/Resources/Relocations
        strip -S program-universal.macho
        lipo -create -output exceptions-universal.macho exceptions-x86_64 exceptions-arm64e
    )
    rm -rf program-universal.macho.dSYM
    cp -R "$scratch/program-universal.macho" "$scratch/program-universal.macho.dSYM" \
        "$scratch/exceptions-universal.macho" .
    rm -r "$scratch"
    ls -lR program-universal.macho program-universal.macho.dSYM exceptions-universal.macho
    exit
fi

cc -O2 -g0 -o program-x86_64.elf program.c
cc -O2 -g0 -o stacked-x86_64.elf stacked.c
gcc -O2 -g0 -o callbacks-x86_64.elf callbacks.c
x86_64-w64-mingw32-gcc -O2 -g0 -o program-x86_64.exe program.c
i686-w64-mingw32-gcc -O2 -g0 -o program-i686.exe program.c
c++ -O2 -g0 -o exceptions-x86_64.elf exceptions.cpp
c++ -O2 -g0 -o handlers-gcc-x86_64.elf handlers.cpp
clang++ -O2 -g0 -o handlers-clang-x86_64.elf handlers.cpp
c++ -O2 -g0 -o classes-gcc-x86_64.elf classes.cpp
clang++ -O2 -g0 -o classes-clang-x86_64.elf classes.cpp
cc -O2 -g0 -Wl,-z,noseparate-code -o rodata-x86_64.elf rodata.c
gcc -O2 -g0 -o variadic-gcc-x86_64.elf variadic.c
gcc -O0 -g0 -o variadic-gcc-O0-x86_64.elf variadic.c
gcc -O2 -g0 -o objects-gcc-x86_64.elf objects.c
gcc -O0 -g0 -o objects-gcc-O0-x86_64.elf objects.c
clang -O2 -g0 -o variadic-clang-x86_64.elf variadic.c
x86_64-w64-mingw32-gcc -O2 -g0 -o variadic-x86_64.exe variadic.c
zig_aarch64 variadic-clang-aarch64.elf -O2 -g0 variadic.c
gcc -O2 -g0 -o floats-x86_64.elf floats.c -lm
zig_aarch64 floats-aarch64.elf -O2 -g0 floats.c -lm
zig_aarch64 kept-float-aarch64.elf -O2 -g0 kept-float.c
x86_64-w64-mingw32-gcc -O2 -g0 -o kept-float-x86_64.exe kept-float.c
gcc -O3 -mavx2 -g0 -o simd-avx2-x86_64.elf simd.c
gcc -O2 -g0 -o atomics-x86_64.elf atomics.c
gcc -O2 -g0 -o enums-x86_64.elf enums.c
gcc -O2 -g0 -o chars-x86_64.elf chars.c
gcc -O2 -g0 -o unaligned-x86_64.elf unaligned.c
gcc -O2 -g0 -o aggregates-x86_64.elf aggregates.c
gcc -O2 -g0 -o forwarded-x86_64.elf forwarded.c
gcc -O2 -g0 -fPIC -shared -o forwarded-x86_64.so forwarded.c
gcc -O2 -g0 -o futex-x86_64.elf futex.c
gcc -O2 -g0 -fstack-protector-all -o cycles-x86_64.elf cycles.c
gcc -O2 -g0 -fno-builtin -rdynamic -o ifunc-x86_64.elf ifunc.c
gcc -O2 -g0 -o bits-x86_64.elf bits.c
gcc -O2 -g0 -fexceptions -fno-builtin -o nothrow-x86_64.elf nothrow.c
gcc -O2 -g0 -o x87-x86_64.elf x87.c
x86_64-w64-mingw32-gcc -O2 -g0 -o aggregates-x86_64.exe aggregates-win.c
x86_64-w64-mingw32-gcc -O2 -g0 -o saves-x86_64.exe saves-win.c
x86_64-w64-mingw32-gcc -nostdlib -Wl,-e,main -o chained-x86_64.exe chained.s
debug() {
    "$@" "$map" -o debug.elf
    objcopy --only-keep-debug debug.elf "$out"
    chmod -x "$out"
    rm debug.elf
}
out=program-x86_64.debug debug cc -O2 -g program.c
out=stacked-x86_64.debug debug cc -O2 -g stacked.c
out=rodata-x86_64.debug debug cc -O2 -g -Wl,-z,noseparate-code rodata.c
out=exceptions-x86_64.debug debug c++ -O2 -g exceptions.cpp
out=handlers-gcc-x86_64.debug debug c++ -O2 -g handlers.cpp
out=handlers-clang-x86_64.debug debug clang++ -O2 -g handlers.cpp
cc -O2 -g "$map" -o units.elf units-a.c units-b.c
objcopy --only-keep-debug units.elf units-x86_64.debug
chmod -x units-x86_64.debug
objcopy --strip-debug --add-gnu-debuglink=units-x86_64.debug units.elf units-x86_64.elf
rm units.elf
cc -O2 -g "$map" -o records.elf records.c
objcopy --only-keep-debug records.elf records-x86_64.debug
chmod -x records-x86_64.debug
objcopy --strip-debug --add-gnu-debuglink=records-x86_64.debug records.elf records-x86_64.elf
rm records.elf
clang --target=aarch64-linux-gnu -c -o dozen-aarch64.o dozen-aarch64.s
ld.lld -static -e _start -o dozen-aarch64.elf dozen-aarch64.o
rm dozen-aarch64.o
clang --target=aarch64-linux-gnu -c -o opaque-aarch64.o opaque-aarch64.s
ld.lld -static -e _start -o opaque-aarch64.elf opaque-aarch64.o
clang --target=x86_64-linux-gnu -c -o opaque-x86_64.o opaque-x86_64.s
ld.lld -static -e _start -o opaque-x86_64.elf opaque-x86_64.o
rm opaque-aarch64.o opaque-x86_64.o
clang --target=x86_64-linux-gnu -c -o kept-x86_64.o kept-x86_64.s
ld.lld -static -e _start -o kept-x86_64.elf kept-x86_64.o
rm kept-x86_64.o
clang --target=x86_64-linux-gnu -c -o undefined-x86_64.o undefined-x86_64.s
ld.lld -static -e _start -o undefined-x86_64.elf undefined-x86_64.o
rm undefined-x86_64.o
clang --target=aarch64-linux-gnu -c -o resolve-aarch64-lib.o resolve-aarch64-lib.s
ld.lld -shared -soname libresolve.so -o libresolve.so resolve-aarch64-lib.o
clang --target=aarch64-linux-gnu -c -o resolve-aarch64.o resolve-aarch64.s
ld.lld -z now -e _start -o resolve-aarch64.elf resolve-aarch64.o libresolve.so
rm resolve-aarch64-lib.o libresolve.so resolve-aarch64.o
clang --target=aarch64-linux-gnu -c -o mangled-aarch64.o mangled-aarch64.s
ld.lld -static -e _start -o mangled-aarch64.elf mangled-aarch64.o
rm mangled-aarch64.o
clang --target=x86_64-linux-gnu -c -o globals-x86_64.o globals-x86_64.s
ld.lld -static -e _start -o globals-x86_64.elf globals-x86_64.o
rm globals-x86_64.o
clang --target=x86_64-linux-gnu -c -o pointers-x86_64.o pointers-x86_64.s
ld.lld -static -e _start -o pointers-x86_64.elf pointers-x86_64.o
rm pointers-x86_64.o
clang --target=x86_64-linux-gnu -c -o interfaces-x86_64.o interfaces-x86_64.s
ld.lld -static -e _start -o interfaces-x86_64.elf interfaces-x86_64.o
rm interfaces-x86_64.o
clang --target=x86_64-linux-gnu -c -o textstrings-x86_64.o textstrings-x86_64.s
ld.lld -static -e _start -o textstrings-x86_64.elf textstrings-x86_64.o
rm textstrings-x86_64.o
clang --target=x86_64-linux-gnu -c -o exports-x86_64.o exports-x86_64.s
ld.lld -shared -soname libexports.so --version-script exports-x86_64.map \
    -o exports-x86_64.elf exports-x86_64.o
rm exports-x86_64.o
sigs="-O2 -g0 -ffreestanding -fno-builtin -fno-asynchronous-unwind-tables"
gsigs="$sigs -fno-tree-loop-distribute-patterns"
# shellcheck disable=SC2086
{
    gcc $gsigs -fno-pic -c -o sigs-gcc.o sigs.c
    gcc $gsigs -fno-pic -c -o sigs-wrap-gcc.o sigs-wrap.c
    rm -f sigs-gcc.a
    ar rcsD sigs-gcc.a sigs-gcc.o sigs-wrap-gcc.o
    rm sigs-gcc.o sigs-wrap-gcc.o
    gcc $gsigs -fno-pic -ffixed-r8 -c -o sigs-gcc-r8.o sigs.c
    gcc $gsigs -fno-pic -ffixed-r10 -ffixed-r11 -c -o sigs-gcc-r1011.o sigs.c
    gcc $gsigs -fno-pic -freorder-blocks-algorithm=simple -c -o sigs-gcc-blocks.o sigs.c
    gcc $gsigs -fPIE -c -o sigs-gcc-pie.o sigs.c
    gcc $gsigs -fno-pic -static -nostdlib -no-pie -Wl,--build-id=none -o sigs-gcc-lo.elf sigs.c
    gcc $gsigs -fno-pic -static -nostdlib -no-pie -Wl,--build-id=none \
        -Wl,-Ttext-segment=0x12340000 -o sigs-gcc-hi.elf sigs.c
    clang $sigs -fno-pic -c -o sigs-clang.o sigs.c
    gcc $gsigs -fno-pic -static -nostdlib -no-pie -Wl,--build-id=none -e wrap_start \
        -o sigs-wrap-gcc.elf sigs.c sigs-wrap.c
    gcc $gsigs -fno-pic -c -o sigs-exit-gcc.o sigs-exit.c
    gcc $gsigs -fno-pic -static -nostdlib -no-pie -Wl,--build-id=none -e app_start -s \
        -o sigs-app-gcc.elf sigs.c sigs-exit.c sigs-app.c
}
if command -v cl >/dev/null 2>&1; then
    scratch=$(mktemp -d)
    cp msvc.c "$scratch"
    (cd "$scratch" && WINEDEBUG=-all cl /nologo /O2 /MD /Zi /Brepro /Femsvc-x86_64.exe msvc.c \
        /link /DEBUG /INCREMENTAL:NO /Brepro '/PDBALTPATH:%_PDB%')
    cp "$scratch/msvc-x86_64.exe" .
    cp "$scratch/msvc-x86_64.pdb" .
    rm -r "$scratch"
    scratch=$(mktemp -d)
    cp records-win.c "$scratch"
    (cd "$scratch" && WINEDEBUG=-all cl /nologo /O2 /MD /Zi /Brepro /Ferecords-x86_64.exe \
        records-win.c /link /DEBUG /INCREMENTAL:NO /Brepro '/PDBALTPATH:%_PDB%')
    cp "$scratch/records-x86_64.exe" .
    cp "$scratch/records-x86_64.pdb" .
    rm -r "$scratch"
    scratch=$(mktemp -d)
    cp teb.c "$scratch"
    (cd "$scratch" && WINEDEBUG=-all cl /nologo /O2 /MD /Brepro /Feteb-x86_64.exe teb.c \
        /link /INCREMENTAL:NO /Brepro)
    cp "$scratch/teb-x86_64.exe" .
    rm -r "$scratch"
    arm64="$(dirname "$(dirname "$(command -v cl)")")/arm64"
    scratch=$(mktemp -d)
    cp teb.c "$scratch"
    (cd "$scratch" && WINEDEBUG=-all "$arm64/cl" /nologo /O2 /MD /Brepro /Feteb-aarch64.exe \
        teb.c /link /INCREMENTAL:NO /Brepro ntdll.lib)
    cp "$scratch/teb-aarch64.exe" .
    rm -r "$scratch"
    scratch=$(mktemp -d)
    cp seh.c eh.cpp "$scratch"
    (cd "$scratch" &&
        WINEDEBUG=-all cl /nologo /O2 /MD /Zi /Brepro /Feseh-x86_64.exe seh.c \
            /link /DEBUG /INCREMENTAL:NO /Brepro '/PDBALTPATH:%_PDB%' &&
        WINEDEBUG=-all cl /nologo /O2 /EHs /MD /Zi /Brepro /Feeh-x86_64.exe eh.cpp \
            /link /DEBUG /INCREMENTAL:NO /Brepro '/PDBALTPATH:%_PDB%' &&
        WINEDEBUG=-all cl /nologo /O2 /EHs /MD /Zi /Brepro /d2FH4- /Feeh-fh3-x86_64.exe \
            eh.cpp /link /DEBUG /INCREMENTAL:NO /Brepro '/PDBALTPATH:%_PDB%' &&
        WINEDEBUG=-all wine ./seh-x86_64.exe >seh-x86_64.stdout &&
        WINEDEBUG=-all wine ./eh-x86_64.exe >eh-x86_64.stdout)
    for f in seh-x86_64 eh-x86_64 eh-fh3-x86_64; do
        cp "$scratch/$f.exe" "$scratch/$f.pdb" .
    done
    cp "$scratch/seh-x86_64.stdout" "$scratch/eh-x86_64.stdout" .
    rm -r "$scratch"
    scratch=$(mktemp -d)
    cp coff-a.cpp coff-b.cpp coff.h coff-main.cpp coff-imports.def "$scratch"
    (cd "$scratch" &&
        WINEDEBUG=-all cl /nologo /c /O2 /Gy /GS- /Brepro coff-a.cpp coff-b.cpp coff-main.cpp &&
        WINEDEBUG=-all lib /nologo /Brepro /out:coff-x86_64.lib coff-a.obj coff-b.obj &&
        WINEDEBUG=-all lib /nologo /Brepro /def:coff-imports.def /machine:x64 \
            /out:coff-imports.lib &&
        WINEDEBUG=-all link /nologo /Brepro /NODEFAULTLIB /ENTRY:entry /SUBSYSTEM:CONSOLE \
            /INCREMENTAL:NO /MAP:coff-x86_64.map /OUT:coff-x86_64.exe coff-main.obj \
            coff-x86_64.lib coff-imports.lib)
    for f in coff-x86_64.lib coff-imports.lib coff-x86_64.exe coff-x86_64.map; do
        cp "$scratch/$f" .
    done
    rm -r "$scratch"
fi
# No fixture names the build machine's directories.
named=$(grep -rlaF -e "$dir" ${HOME:+-e "$HOME"} . || true)
if [ -n "$named" ]; then
    echo "build-fixtures.sh: these name the build machine's directories:" >&2
    echo "$named" >&2
    exit 1
fi
ls -l program-* exceptions-* handlers-* classes-* rodata-* dozen-* opaque-* undefined-*.elf resolve-*.elf exports-*.elf globals-*.elf pointers-*.elf \
    units-*.elf units-*.debug sigs-*
