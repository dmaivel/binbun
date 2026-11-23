#!/usr/bin/env bash
# Regenerates binbun's type databases with tools/typegen.
#
# Usage: scripts/typedb.sh [linux|aarch64|macos|win32|kernel|windows|native|all]   (default linux)
#   linux  crates/binbun-typedb/data/linux-x86_64-{libc,cxxabi,syscalls}.jsonl,
#          checked in: glibc's and the kernel's headers of this host (Arch
#          Linux: glibc, linux-api-headers; libclang), and syzkaller's
#          descriptions at a pinned commit (flag values resolved by
#          compiling a probe against this host's headers; each call
#          numbered from the kernel headers' asm/unistd_64.h). The C++
#          runtime's ABI (cxxabi): what libstdc++'s cxxabi.h and GCC's
#          unwind.h declare with C linkage (`__cxa_*`, `_Unwind_*`), read
#          as C++ (their `throw()`/`noexcept`), from this host's GCC.
#          The libc database also declares the object-size checking
#          functions _FORTIFY_SOURCE code calls that glibc's headers call
#          only as GCC builtins (`__memcpy_chk`, `__strcpy_chk`: GCC's
#          builtins.def, from this host's GCC's plugin headers).
#   macos  crates/binbun-typedb/data/macos-{x86_64,aarch64}-{libc,cxxabi}.jsonl,
#          checked in: the C library macOS programs import
#          (libSystem: the POSIX and C headers, _DARWIN_C_SOURCE, with
#          its _FORTIFY_SOURCE level 2) and the C++
#          runtime's ABI (libc++abi's cxxabi.h, unwind.h), read for
#          x86_64 and arm64 from the headers of a macOS SDK copied from
#          a Mac (its usr/include and SDKSettings.json, at $MACOS_SDK,
#          default $src/MacOSX.sdk: `xcrun --show-sdk-path`), with
#          nothing of this host's but clang's own headers.
#   aarch64 crates/binbun-typedb/data/linux-aarch64-{libc,cxxabi,syscalls}.jsonl,
#          checked in: the same headers for AArch64 Linux, from Debian
#          trixie's arm64 packages (glibc's libc6-dev, linux-libc-dev,
#          GCC 14's libstdc++-dev and libgcc-dev, and its plugin-dev for
#          builtins.def; the AArch64 corpus is Debian trixie's), at pinned
#          versions, checksums verified. The syscall database: linux's
#          descriptions, the flag values these headers give (the probe
#          built by clang for AArch64, linked statically with the
#          packages' glibc and libgcc, and run under qemu-aarch64), each
#          call numbered from the packages' asm/unistd_64.h (generated
#          from the kernel's arm64 table: plain numbers, as x86-64's); a
#          call arm64 does not have (open, arch_prctl) has no number.
#   win32  crates/binbun-typedb/data/windows-{x86_64,aarch64}-win32.jsonl,
#          checked in: the Windows API's functions, structures and
#          enumerations
#          (kernel32.dll, user32.dll and the others' exports), from the
#          last Windows.Win32.winmd built from Microsoft's win32metadata,
#          the copy windows-rs ships in the windows-bindgen crate (MIT OR
#          Apache-2.0), from crates.io at a pinned version, the crate's and
#          the winmd's checksums verified, for each architecture (what the
#          metadata declares for one only, as CONTEXT, is that one's). The
#          structures are laid out as MSVC compiles the SDK's headers
#          (WNDCLASSEXW's size 80), which the metadata does not state.
#   kernel crates/binbun-typedb/data/windows-{x86_64,aarch64}-kernel.jsonl,
#          checked in: what kernel-mode code (drivers) imports, the exports of
#          the kernel (ntoskrnl.exe), the HAL and the drivers others link
#          to (fltmgr.sys, ndis.sys, clfs.sys, fwpkclnt.sys, ksecdd.sys),
#          from Microsoft's WDK metadata (wdkmetadata, MIT), the
#          Windows.Wdk.winmd of win32's crate, read with its Win32 one, for
#          each architecture as win32.
#          The native API both declare as ntdll.dll's (Rtl*, Zw*,
#          DbgPrint), which the kernel exports too, is declared as
#          ntoskrnl.exe's. binbun-typedb takes it for kernel-mode images
#          only, and win32's and native's for user-mode ones only.
#   windows crates/binbun-typedb/data/windows-{x86_64,aarch64}-{ucrt,msvcrt}.jsonl,
#          checked in, read for each architecture: the C runtime
#          MSVC-built code imports (ucrtbase,
#          api-ms-win-crt-*, vcruntime), declared for any library, from
#          the UCRT and vcruntime headers of an MSVC installation
#          ($MSVC, default ~/.cache/msvc, msvc-wine's layout; the newest
#          SDK and toolset there), printf and its family declared as the
#          functions msvcrt.dll exports rather than inline wrappers
#          (_NO_CRT_STDIO_INLINE); and what msvcrt.dll exports that those
#          headers do not declare (MinGW-w64 binaries' imports), declared
#          for msvcrt.dll only, from mingw-w64's CRT headers configured for
#          msvcrt.dll (__MSVCRT_VERSION__ 0x700), the package of this host
#          (one set of headers for every architecture).
#          Only the C runtime's own headers' declarations are kept.
#   native crates/binbun-typedb/data/windows-{x86_64,aarch64}-native.jsonl,
#          checked in: Windows' native API (ntdll.dll's Nt*, Zw*, Rtl*, Ldr*) and
#          the process's own structures (TEB, PEB, PEB_LDR_DATA,
#          LDR_DATA_TABLE_ENTRY, RTL_USER_PROCESS_PARAMETERS and what they
#          reach), from System Informer's phnt headers (MIT) at a pinned
#          commit, user mode, PHNT_VERSION Windows 11 24H2, over the
#          Windows SDK of an MSVC installation ($MSVC, as `windows`), read
#          for each architecture. The functions are those phnt declares
#          that the architecture's ntdll.dll of Windows 11 24H2 (a pinned
#          build from Microsoft's symbol server, checksum verified) exports,
#          declared for ntdll.dll; the types those functions and TEB and
#          LDR_DATA_TABLE_ENTRY reach. ARM64's ntdll.dll is an ARM64X
#          image: its export table is the ARM64 one (the ARM64EC exports
#          sit behind its hybrid metadata, not read).
# Sources are fetched into ${XDG_CACHE_HOME:-~/.cache}/binbun-typedb-src.
# The output depends only on the inputs: a second run writes the same
# bytes. binbun-typedb's build compresses every database (zstd) to embed
# it; a database in $BINBUN_TYPEDB (default ~/.cache/binbun-typedb), as
# .jsonl or .jsonl.zst, is added at run time, and replaces the embedded
# one of its name. Needs: cargo, libclang, cc, git, curl, sha256sum, tar,
# bsdtar; for aarch64 also clang, ld.lld and qemu-aarch64.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
data="$root/crates/binbun-typedb/data"
src="${XDG_CACHE_HOME:-$HOME/.cache}/binbun-typedb-src"
target_dir="${CARGO_TARGET_DIR:-$root/tools/typegen/target}"
typegen="$target_dir/release/binbun-typegen"

syzkaller_commit=5cecaf1f6fc71be2d4f1998a5356a17869ac766e

# The Win32 database's winmd: default/Windows.Win32.winmd in windows-bindgen
# 0.66.0, the last version carrying win32metadata's file (SHA-256 of the
# .crate, as crates.io's index records it, and of the winmd).
win32_crate=windows-bindgen
win32_version=0.66.0
win32_crate_sha256=81b7ec123a4eadd44d1f44f76804316b477b2537abed9a2ab950b3c54afa1fcf
win32_winmd_sha256=97d24cf1a9dc3e50782bbf1dba0952bf6a025fa583d8b3ae6c5ef713b463c869
wdk_winmd_sha256=54b8e48866b0a7e066981b63bb6f82fc6947fe8c57e2b5cb4513b1537aa836c2

msvc="${MSVC:-$HOME/.cache/msvc}"
mingw=/usr/x86_64-w64-mingw32/include

# The Windows architectures the win32, kernel and windows modes read for.
windows_arches=(x86_64 aarch64)

# phnt (github.com/winsiderss/phnt) and the ntdll.dll whose exports each
# native database declares: Windows 11 24H2's 10.0.26100.9711 (KB5127648,
# 2026-10-13), x64 and ARM64, from Microsoft's symbol server by its PE
# timestamp and image size (winbindex.m417z.com lists them, ARM64 ones at
# ?arch=arm64), keyed by architecture.
phnt_commit=53fbbdc5b5d2b08761db1c7b26bfa8c820924356
ntdll_version=10.0.26100.9711
declare -A ntdll_key=([x86_64]=5FD39A05268000 [aarch64]=86E8EB7643A000)
declare -A ntdll_sha256=(
    [x86_64]=651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c
    [aarch64]=0a7201420df35a67e76aa2f2f4adb793b0c0b4fbc927d7da112268a7beb74930
)

# The C runtime headers the Windows databases declare: vcruntime's (MSVC's
# include directory), then the UCRT's (mingw-w64 has the same names but
# for vcruntime's own, whose declarations it spreads over others).
vcruntime_headers=(vcruntime.h vcruntime_string.h vcruntime_startup.h excpt.h setjmp.h)
crt_headers=(
    assert.h complex.h conio.h corecrt_startup.h ctype.h direct.h dos.h
    errno.h fcntl.h fenv.h float.h fpieee.h inttypes.h io.h locale.h malloc.h
    math.h mbctype.h mbstring.h memory.h process.h search.h share.h signal.h
    stddef.h stdio.h stdlib.h string.h time.h uchar.h wchar.h wctype.h
    sys/locking.h sys/stat.h sys/timeb.h sys/types.h sys/utime.h
)

# The glibc and kernel headers the libc database declares. glibc's full
# API (_GNU_SOURCE), with the fortified variants (`__printf_chk`,
# `__longjmp_chk`) that binaries built with _FORTIFY_SOURCE import.
headers=(
    aio.h arpa/inet.h assert.h ctype.h dirent.h dlfcn.h elf.h err.h errno.h
    error.h execinfo.h fcntl.h fnmatch.h ftw.h getopt.h glob.h grp.h iconv.h
    ifaddrs.h inttypes.h langinfo.h libgen.h libintl.h link.h
    linux/capability.h linux/futex.h linux/perf_event.h linux/seccomp.h
    locale.h malloc.h math.h
    mqueue.h net/if.h netdb.h netinet/in.h netinet/tcp.h netinet/udp.h poll.h
    pthread.h pwd.h regex.h sched.h semaphore.h setjmp.h signal.h spawn.h
    stdio.h stdio_ext.h stdlib.h string.h sys/auxv.h sys/epoll.h
    sys/eventfd.h sys/file.h sys/inotify.h sys/ioctl.h sys/ipc.h sys/mman.h
    sys/mount.h sys/msg.h sys/prctl.h sys/ptrace.h sys/random.h
    sys/resource.h sys/select.h sys/sem.h sys/sendfile.h sys/shm.h
    sys/signalfd.h sys/socket.h sys/stat.h sys/statvfs.h sys/swap.h
    sys/sysinfo.h sys/time.h sys/timerfd.h sys/times.h sys/types.h sys/uio.h
    sys/un.h sys/utsname.h sys/wait.h sys/xattr.h syslog.h termios.h
    threads.h time.h unistd.h utime.h wchar.h wctype.h
)
clang_args=(-D_GNU_SOURCE -D_FORTIFY_SOURCE=3 -O2)

# The headers the macOS libc databases declare: the POSIX and C library
# headers of `headers` that macOS has, and Darwin's own that programs
# commonly import from libSystem.
macos_headers=(
    aio.h arpa/inet.h assert.h ctype.h dirent.h dlfcn.h err.h errno.h
    execinfo.h fcntl.h fnmatch.h ftw.h getopt.h glob.h grp.h iconv.h
    ifaddrs.h inttypes.h langinfo.h libgen.h locale.h math.h net/if.h
    netdb.h netinet/in.h netinet/tcp.h netinet/udp.h poll.h pthread.h pwd.h
    regex.h sched.h semaphore.h setjmp.h signal.h spawn.h stdio.h stdlib.h
    string.h sys/file.h sys/ioctl.h sys/ipc.h sys/mman.h sys/mount.h
    sys/msg.h sys/ptrace.h sys/random.h sys/resource.h sys/select.h
    sys/sem.h sys/shm.h sys/socket.h sys/stat.h sys/statvfs.h sys/time.h
    sys/times.h sys/types.h sys/uio.h sys/un.h sys/utsname.h sys/wait.h
    sys/xattr.h syslog.h termios.h time.h unistd.h utime.h wchar.h wctype.h
    copyfile.h crt_externs.h libproc.h mach-o/dyld.h malloc/malloc.h
    os/lock.h sys/event.h sys/sysctl.h util.h xlocale.h
)
macos_args=(-D_DARWIN_C_SOURCE -D_FORTIFY_SOURCE=2 -O2)

# The C++ runtime's ABI headers the cxxabi databases declare (C linkage
# only), read as C++.
cxxabi_headers=(cxxabi.h unwind.h)
cxxabi_args=(-x c++ -std=c++17)

# Debian trixie's arm64 packages the AArch64 databases are read from: file
# in the pool, SHA-256.
debian=https://deb.debian.org/debian/pool/main
debian_arm64=(
    "g/glibc/libc6-dev_2.41-12+deb13u4_arm64.deb 71e373cb5e9da975b02fb4af555929cb1977560e2dd8245de4eb8a7b03677a08"
    "l/linux/linux-libc-dev_6.12.113-1_all.deb b2d475e01aaf0030c72bd3a0300d311f8be64aa9e82d82eae5da1a04f4010071"
    "g/gcc-14/libstdc++-14-dev_14.2.0-19_arm64.deb 8760122d044cd8eb8c69426311d6b5ce7bb8f0f76e9cda1944d153ae878138f8"
    "g/gcc-14/libgcc-14-dev_14.2.0-19_arm64.deb 64b8ebc7182a69aa9525df6eab5e7eb849b947e350d821549f8a8a3e9b19e5ba"
    "g/gcc-14/gcc-14-plugin-dev_14.2.0-19_arm64.deb 003138147ce4e346e79fab31ecbbab8b0594f78245cb55f0121f0023d39c6c4c"
)

# syzkaller's descriptions the syscall database declares.
syzlang=(sys.txt socket.txt aio.txt bpf.txt perf.txt io_uring.txt)
# The probe includes the descriptions' headers; kernel-internal ones do
# not compile in user space.
syzlang_skip=(--skip-include /sched/ --skip-include xen/ --skip-include fs/ --skip-include kernel/)

build() {
    (cd "$root/tools/typegen" && cargo build --release --quiet --features headers,winmd)
}

# The version of host package $1 (pacman), for the header.
package() {
    if command -v pacman > /dev/null; then
        pacman -Q "$1" | tr ' ' '@'
    else
        echo "$1@unknown"
    fi
}

linux() {
    mkdir -p "$src"
    local umbrella="$src/linux-x86_64-libc.h"
    printf '#include <%s>\n' "${headers[@]}" > "$umbrella"
    # libclang does not always find its own headers (stddef.h): name them.
    local resource_dir
    resource_dir="$(clang -print-resource-dir)"
    "$typegen" --arch x86_64 --os linux --env gnu --include-system \
        --gcc-builtins "$(gcc -print-file-name=plugin)/include" \
        --input "$(package glibc)" --input "$(package linux-api-headers)" \
        --input "builtins.def: $(package gcc)" \
        --input "clang args: ${clang_args[*]}" \
        -o "$data/linux-x86_64-libc.jsonl" "$umbrella" -- "${clang_args[@]}" \
        -resource-dir "$resource_dir"

    # GCC's unwind.h, not clang's: libgcc_s is the unwinder GCC-built code
    # imports from.
    local gcc_include cxx
    gcc_include="$(gcc -print-file-name=include)"
    cxx="/usr/include/c++/$(gcc -dumpversion)"
    umbrella="$src/linux-x86_64-cxxabi.h"
    printf '#include <%s>\n' "${cxxabi_headers[@]}" > "$umbrella"
    "$typegen" --arch x86_64 --os linux --env gnu --include-system \
        --from "$cxx/cxxabi.h" --from "$cxx/bits/cxxabi_init_exception.h" \
        --from "$cxx/bits/cxxabi_forced.h" --from "$cxx/x86_64-pc-linux-gnu/bits/cxxabi_tweaks.h" \
        --from "$gcc_include/unwind.h" \
        --input "$(package gcc)" --input "clang args: ${cxxabi_args[*]}" \
        -o "$data/linux-x86_64-cxxabi.jsonl" "$umbrella" -- "${cxxabi_args[@]}" \
        -isystem "$gcc_include" -resource-dir "$resource_dir"

    syzkaller
    # The calls' numbers are the kernel headers'.
    "$typegen" --arch x86_64 --os linux --env gnu "${syzlang_files[@]}" --resolve \
        "${syzlang_skip[@]}" --syscall-numbers /usr/include/asm/unistd_64.h \
        --input "syzkaller@$syzkaller_commit" --input "$(package linux-api-headers)" \
        --input "syscall numbers: asm/unistd_64.h" \
        -o "$data/linux-x86_64-syscalls.jsonl"
}

# syzkaller's descriptions at the pinned commit, and ours of the calls it
# leaves out: the --syzlang arguments, in syzlang_files.
syzkaller() {
    local syz="$src/syzkaller"
    if [[ "$(git -C "$syz" rev-parse HEAD 2> /dev/null)" != "$syzkaller_commit" ]]; then
        rm -rf "$syz"
        git init --quiet "$syz"
        git -C "$syz" remote add origin https://github.com/google/syzkaller.git
        git -C "$syz" sparse-checkout set sys/linux
        git -C "$syz" fetch --quiet --depth 1 --filter=blob:none origin "$syzkaller_commit"
        git -C "$syz" checkout --quiet FETCH_HEAD
    fi
    local file
    syzlang_files=()
    for file in "${syzlang[@]}"; do
        syzlang_files+=(--syzlang "$syz/sys/linux/$file")
    done
    syzlang_files+=(--syzlang "$root/tools/typegen/syzlang/unfuzzed.txt")
}

# Debian trixie's arm64 headers, unpacked into a root (a sysroot of headers
# and static libraries), read with nothing of this host's but clang's own
# headers.
aarch64() {
    local dir="$src/debian-arm64" sysroot="$src/debian-arm64/root" inputs=() entry file sha256
    mkdir -p "$dir"
    rm -rf "$sysroot"
    mkdir -p "$sysroot"
    for entry in "${debian_arm64[@]}"; do
        read -r file sha256 <<< "$entry"
        local package="$dir/${file##*/}"
        if ! echo "$sha256  $package" | sha256sum --check --status 2> /dev/null; then
            curl --fail --location --silent --show-error --output "$package.part" "$debian/$file"
            echo "$sha256  $package.part" | sha256sum --check --status || {
                echo "${file##*/}: checksum mismatch" >&2
                exit 1
            }
            mv "$package.part" "$package"
        fi
        # A .deb is an ar archive around data.tar.*.
        local unpacked="$dir/unpacked"
        rm -rf "$unpacked"
        mkdir -p "$unpacked"
        bsdtar -xf "$package" -C "$unpacked"
        bsdtar -xf "$unpacked"/data.tar.* -C "$sysroot"
        rm -rf "$unpacked"
        inputs+=(--input "debian:${file##*/}")
    done
    local resource_dir multiarch="$sysroot/usr/include/aarch64-linux-gnu"
    resource_dir="$(clang -print-resource-dir)"
    local system=(-nostdinc -isystem "$resource_dir/include" -isystem "$multiarch" -isystem "$sysroot/usr/include")
    local umbrella="$src/linux-aarch64-libc.h"
    printf '#include <%s>\n' "${headers[@]}" > "$umbrella"
    "$typegen" --arch aarch64 --os linux --env gnu --include-system \
        --gcc-builtins "$sysroot/usr/lib/gcc/aarch64-linux-gnu/14/plugin/include" \
        "${inputs[@]:0:4}" --input "builtins.def: ${inputs[9]}" \
        --input "clang args: ${clang_args[*]}" \
        -o "$data/linux-aarch64-libc.jsonl" "$umbrella" -- "${clang_args[@]}" \
        "${system[@]}" -resource-dir "$resource_dir"

    local gcc_include cxx="$sysroot/usr/include/c++/14"
    gcc_include="$sysroot/usr/lib/gcc/aarch64-linux-gnu/14/include"
    umbrella="$src/linux-aarch64-cxxabi.h"
    printf '#include <%s>\n' "${cxxabi_headers[@]}" > "$umbrella"
    "$typegen" --arch aarch64 --os linux --env gnu --include-system \
        --from "$cxx/cxxabi.h" --from "$cxx/bits/cxxabi_init_exception.h" \
        --from "$cxx/bits/cxxabi_forced.h" --from "$multiarch/c++/14/bits/cxxabi_tweaks.h" \
        --from "$gcc_include/unwind.h" \
        "${inputs[@]:4:4}" --input "clang args: ${cxxabi_args[*]}" \
        -o "$data/linux-aarch64-cxxabi.jsonl" "$umbrella" -- "${cxxabi_args[@]}" \
        -nostdinc++ -isystem "$cxx" -isystem "$multiarch/c++/14" -isystem "$gcc_include" \
        "${system[@]}" -resource-dir "$resource_dir"

    # The probe resolving the flag values is built for AArch64 against the
    # root (glibc's crt files and libc.a, libgcc's), statically, and run
    # under qemu-aarch64; $CC is a single program. C23, GCC's default, in
    # which glibc's struct timeval may repeat linux/time.h's; every error
    # reported, as GCC does, so each attempt leaves out every undeclared
    # name.
    syzkaller
    local cc="$src/aarch64-linux-gnu-cc"
    printf '#!/bin/sh\nexec clang --target=aarch64-linux-gnu --sysroot=%q -std=gnu23 -ferror-limit=0 -fuse-ld=lld -static "$@"\n' \
        "$sysroot" > "$cc"
    chmod +x "$cc"
    CC="$cc" "$typegen" --arch aarch64 --os linux --env gnu "${syzlang_files[@]}" --resolve \
        --probe-runner qemu-aarch64 "${syzlang_skip[@]}" \
        --syscall-numbers "$multiarch/asm/unistd_64.h" \
        --input "syzkaller@$syzkaller_commit" "${inputs[@]:0:4}" \
        --input "syscall numbers: asm/unistd_64.h" \
        -o "$data/linux-aarch64-syscalls.jsonl"
}

# A macOS SDK's headers ($MACOS_SDK), read for each architecture with
# nothing of this host's but clang's own headers.
macos() {
    local sdk="${MACOS_SDK:-$src/MacOSX.sdk}" version resource_dir arch target umbrella
    [[ -f "$sdk/SDKSettings.json" && -d "$sdk/usr/include" ]] || {
        echo "macos: no SDK at $sdk (copy usr/include and SDKSettings.json from a Mac's \`xcrun --show-sdk-path\`)" >&2
        exit 1
    }
    version="$(sed -n 's/.*"Version" *: *"\([^"]*\)".*/\1/p' "$sdk/SDKSettings.json" | head -1)"
    resource_dir="$(clang -print-resource-dir)"
    mkdir -p "$src"
    umbrella="$src/macos-libc.h"
    printf '#include <%s>\n' "${macos_headers[@]}" > "$umbrella"
    local cxxabi="$src/macos-cxxabi.h"
    printf '#include <%s>\n' "${cxxabi_headers[@]}" > "$cxxabi"
    for arch in x86_64 aarch64; do
        target="$arch"
        [[ "$arch" == aarch64 ]] && target=arm64
        local system=(--target="$target-apple-macos13" -isysroot "$sdk" -nostdinc
            -isystem "$resource_dir/include" -isystem "$sdk/usr/include")
        "$typegen" --arch "$arch" --os macos --env darwin --include-system \
            --input "MacOSX.sdk@$version usr/include" --input "clang args: ${macos_args[*]}" \
            -o "$data/macos-$arch-libc.jsonl" "$umbrella" -- "${macos_args[@]}" \
            "${system[@]}" -resource-dir "$resource_dir"
        "$typegen" --arch "$arch" --os macos --env darwin --include-system \
            --from "$sdk/usr/include/c++/v1/cxxabi.h" \
            --from "$sdk/usr/include/c++/v1/__cxxabi_config.h" \
            --from "$sdk/usr/include/unwind.h" \
            --input "MacOSX.sdk@$version usr/include" --input "clang args: ${cxxabi_args[*]}" \
            -o "$data/macos-$arch-cxxabi.jsonl" "$cxxabi" -- "${cxxabi_args[@]}" \
            -nostdinc++ -isystem "$sdk/usr/include/c++/v1" "${system[@]}" \
            -resource-dir "$resource_dir"
    done
}

# Fetches windows-bindgen's crate (checksum verified) and extracts its
# default/$1 (checksum $2, verified) into its directory in $src.
bindgen_winmd() {
    local dir="$src/$win32_crate-$win32_version"
    local crate="$dir/$win32_crate-$win32_version.crate" winmd="$dir/$1"
    mkdir -p "$dir"
    if ! echo "$win32_crate_sha256  $crate" | sha256sum --check --status 2> /dev/null; then
        curl --fail --location --silent --show-error --output "$crate.part" \
            "https://static.crates.io/crates/$win32_crate/$win32_crate-$win32_version.crate"
        echo "$win32_crate_sha256  $crate.part" | sha256sum --check --status || {
            echo "$win32_crate $win32_version: checksum mismatch" >&2
            exit 1
        }
        mv "$crate.part" "$crate"
    fi
    # A .crate is a gzipped tar of the crate's directory.
    tar -xzOf "$crate" "$win32_crate-$win32_version/default/$1" > "$winmd"
    echo "$2  $winmd" | sha256sum --check --status || {
        echo "$win32_crate $win32_version: $1 checksum mismatch" >&2
        exit 1
    }
}

win32() {
    local dir="$src/$win32_crate-$win32_version" arch
    bindgen_winmd Windows.Win32.winmd "$win32_winmd_sha256"
    for arch in "${windows_arches[@]}"; do
        "$typegen" --arch "$arch" --os windows --env msvc --winmd "$dir/Windows.Win32.winmd" --layouts \
            --input "crates.io:$win32_crate@$win32_version (MIT OR Apache-2.0) sha256:$win32_crate_sha256" \
            --input "default/Windows.Win32.winmd sha256:$win32_winmd_sha256" \
            -o "$data/windows-$arch-win32.jsonl"
    done
}

# The kernel database: the functions Microsoft's WDK metadata (wdkmetadata,
# MIT) declares for the kernel and the HAL and the drivers others link to
# (WDF's wdfldr.sys has none there), and the native API it declares as
# ntdll.dll's, as ntoskrnl.exe's, and the types they reach and
# DRIVER_INITIALIZE (the prototype binbun gives a driver's entry), from the
# Windows.Wdk.winmd windows-bindgen ships beside Windows.Win32.winmd, read
# with it (the WDK's types use the Win32 metadata's); the structures laid
# out as MSVC compiles the WDK's headers (DRIVER_OBJECT's MajorFunction at
# 0x70), which the metadata does not state.
kernel() {
    local dir="$src/$win32_crate-$win32_version" arch
    bindgen_winmd Windows.Win32.winmd "$win32_winmd_sha256"
    bindgen_winmd Windows.Wdk.winmd "$wdk_winmd_sha256"
    for arch in "${windows_arches[@]}"; do
        "$typegen" --arch "$arch" --os windows --env msvc \
            --winmd "$dir/Windows.Wdk.winmd" --winmd "$dir/Windows.Win32.winmd" --layouts \
            --rename-library ntdll.dll=ntoskrnl.exe \
            --only-library ntoskrnl.exe --only-library hal.dll --only-library fltmgr.sys \
            --only-library ndis.sys --only-library clfs.sys --only-library fwpkclnt.sys \
            --only-library ksecdd.sys \
            --keep Windows.Wdk.Foundation.DRIVER_INITIALIZE \
            --input "crates.io:$win32_crate@$win32_version (MIT OR Apache-2.0) sha256:$win32_crate_sha256" \
            --input "default/Windows.Wdk.winmd (wdkmetadata, MIT) sha256:$wdk_winmd_sha256" \
            --input "default/Windows.Win32.winmd sha256:$win32_winmd_sha256" \
            -o "$data/windows-$arch-kernel.jsonl"
    done
}

windows() {
    local ucrt vc sdk toolset arch
    ucrt="$(find "$msvc/Windows Kits/10/Include" -mindepth 2 -maxdepth 2 -name ucrt | sort -V | tail -1)"
    vc="$(find "$msvc/VC/Tools/MSVC" -mindepth 2 -maxdepth 2 -name include | sort -V | tail -1)"
    [[ -d "$ucrt" && -d "$vc" ]] || {
        echo "windows: no UCRT or MSVC headers under $msvc" >&2
        exit 1
    }
    sdk="$(basename "$(dirname "$ucrt")")"
    toolset="$(basename "$(dirname "$vc")")"
    mkdir -p "$src"
    local umbrella="$src/windows-ucrt.h" from=() header
    : > "$umbrella"
    for header in "${vcruntime_headers[@]}"; do
        printf '#include <%s>\n' "$header" >> "$umbrella"
        from+=(--from "$vc/$header")
    done
    printf '#include <%s>\n' "${crt_headers[@]}" >> "$umbrella"
    local ucrt_args=(-nostdinc -D_NO_CRT_STDIO_INLINE -fms-compatibility-version=19.51)
    for arch in "${windows_arches[@]}"; do
        "$typegen" --arch "$arch" --os windows --env msvc --include-system \
            "${from[@]}" --from "$ucrt" \
            --input "Windows SDK $sdk (ucrt)" --input "MSVC $toolset (vcruntime)" \
            --input "clang args: ${ucrt_args[*]}" \
            -o "$data/windows-$arch-ucrt.jsonl" "$umbrella" -- "${ucrt_args[@]}" \
            -isystem "$vc" -isystem "$ucrt"
    done

    # mingw-w64's declarations live in the CRT headers and those they
    # include for them (corecrt_*, sec_api, _mingw*).
    umbrella="$src/windows-msvcrt.h"
    from=()
    : > "$umbrella"
    for header in excpt.h setjmp.h "${crt_headers[@]}"; do
        printf '#include <%s>\n' "$header" >> "$umbrella"
        from+=(--from "$mingw/$header")
    done
    for header in "$mingw"/corecrt*.h "$mingw"/_mingw*.h "$mingw/sec_api"; do
        from+=(--from "$header")
    done
    local resource_dir
    resource_dir="$(clang -print-resource-dir)"
    for arch in "${windows_arches[@]}"; do
        local msvcrt_args=(--target="$arch"-w64-windows-gnu -nostdinc -D__MSVCRT_VERSION__=0x700)
        "$typegen" --arch "$arch" --os windows --env msvc --include-system "${from[@]}" \
            --library msvcrt.dll --except "$data/windows-$arch-ucrt.jsonl" \
            --input "$(package mingw-w64-headers)" --input "clang args: ${msvcrt_args[*]}" \
            -o "$data/windows-$arch-msvcrt.jsonl" "$umbrella" -- "${msvcrt_args[@]}" \
            -isystem "$mingw" -isystem "$resource_dir/include" -resource-dir "$resource_dir"
    done
}

native() {
    local kit vc arch
    kit="$(find "$msvc/Windows Kits/10/Include" -mindepth 1 -maxdepth 1 | sort -V | tail -1)"
    vc="$(find "$msvc/VC/Tools/MSVC" -mindepth 2 -maxdepth 2 -name include | sort -V | tail -1)"
    [[ -d "$kit/um" && -d "$vc" ]] || {
        echo "native: no Windows SDK or MSVC headers under $msvc" >&2
        exit 1
    }
    local phnt="$src/phnt"
    if [[ "$(git -C "$phnt" rev-parse HEAD 2> /dev/null)" != "$phnt_commit" ]]; then
        rm -rf "$phnt"
        git init --quiet "$phnt"
        git -C "$phnt" remote add origin https://github.com/winsiderss/phnt.git
        git -C "$phnt" fetch --quiet --depth 1 origin "$phnt_commit"
        git -C "$phnt" checkout --quiet FETCH_HEAD
    fi
    local umbrella="$src/windows-native.h"
    printf '#include <phnt_windows.h>\n#include <phnt.h>\n' > "$umbrella"
    local native_args=(-nostdinc -fms-compatibility-version=19.51 -DPHNT_VERSION=PHNT_WINDOWS_11_24H2)
    for arch in "${windows_arches[@]}"; do
        local ntdll="$src/ntdll-$ntdll_version-$arch.dll" sha256="${ntdll_sha256[$arch]}"
        if ! echo "$sha256  $ntdll" | sha256sum --check --status 2> /dev/null; then
            curl --fail --location --silent --show-error --output "$ntdll.part" \
                "https://msdl.microsoft.com/download/symbols/ntdll.dll/${ntdll_key[$arch]}/ntdll.dll"
            echo "$sha256  $ntdll.part" | sha256sum --check --status || {
                echo "ntdll.dll $ntdll_version ($arch): checksum mismatch" >&2
                exit 1
            }
            mv "$ntdll.part" "$ntdll"
        fi
        "$typegen" --arch "$arch" --os windows --env msvc --include-system --from "$phnt" \
            --exports "$ntdll" --library ntdll.dll --keep TEB --keep LDR_DATA_TABLE_ENTRY \
            --input "phnt@$phnt_commit (MIT)" --input "ntdll.dll@$ntdll_version (exports)" \
            --input "Windows SDK $(basename "$kit")" --input "clang args: ${native_args[*]}" \
            -o "$data/windows-$arch-native.jsonl" "$umbrella" -- "${native_args[@]}" \
            -isystem "$vc" -isystem "$kit/ucrt" -isystem "$kit/shared" -isystem "$kit/um" \
            -isystem "$phnt"
    done
}

build
case "${1:-linux}" in
    linux) linux ;;
    aarch64) aarch64 ;;
    macos) macos ;;
    win32) win32 ;;
    kernel) kernel ;;
    windows) windows ;;
    native) native ;;
    all) linux && aarch64 && macos && win32 && kernel && windows && native ;;
    *)
        echo "usage: $0 [linux|aarch64|macos|win32|kernel|windows|native|all]" >&2
        exit 2
        ;;
esac
