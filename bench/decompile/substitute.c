/*
 * Preloaded (LD_PRELOAD) into every process a test starts; acts only in a
 * process that has the target module loaded, found by its build ID
 * (BENCH_BUILD_ID, hex): the program itself or a library it uses. Elsewhere
 * it does nothing.
 *
 * Coverage (BENCH_COVERAGE, BENCH_ENTRIES): the module's functions (their
 * entries, file addresses in hex, sorted, one per line, in BENCH_ENTRIES)
 * each get a breakpoint; the first time one is hit, its byte in the
 * BENCH_COVERAGE file (one per function, shared by every process) is set
 * and the breakpoint removed, so the program runs as it would.
 *
 * Substitution (BENCH_SO, BENCH_FUNCTION, BENCH_ENTRY, BENCH_MAP,
 * BENCH_MARK): the shared object BENCH_SO (a tool's C for one function,
 * compiled) is loaded locally (its symbols visible to nobody else); its
 * relocations against the names in BENCH_MAP (`name address` lines, file
 * addresses in hex) are pointed at those addresses of the module (the
 * original's functions and data, so the C shares the program's state);
 * then the function at BENCH_ENTRY is replaced: its first bytes become a
 * jump (`movabs r11, ...; jmp r11`, r11 being free at a call) to a stub
 * that creates the file BENCH_MARK the first time it runs (so a run tells
 * whether the C was reached) and goes on to BENCH_FUNCTION of BENCH_SO.
 * After the patch only raw system calls are used: the function replaced
 * may be one of the C library's.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static long raw(long number, long a, long b, long c) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return result;
}

static long raw4(long number, long a, long b, long c, long d) {
    long result;
    register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
}

static void fail(const char *why) {
    raw(SYS_write, 2, (long)why, (long)strlen(why));
    raw(SYS_exit_group, 97, 0, 0);
}

/* The target module, once found. */
static unsigned char wanted[64];
static size_t wanted_length;
static uintptr_t base;
static const ElfW(Phdr) *headers;
static int header_count;

static int is_target(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[i];
        if (header->p_type != PT_NOTE)
            continue;
        const char *at = (const char *)(info->dlpi_addr + header->p_vaddr);
        const char *end = at + header->p_memsz;
        while (at + sizeof(ElfW(Nhdr)) <= end) {
            const ElfW(Nhdr) *note = (const ElfW(Nhdr) *)at;
            const char *name = at + sizeof *note;
            const unsigned char *desc =
                (const unsigned char *)(name + ((note->n_namesz + 3) & ~3u));
            if (note->n_type == NT_GNU_BUILD_ID && note->n_namesz == 4 &&
                memcmp(name, "GNU", 4) == 0 && note->n_descsz == wanted_length &&
                memcmp(desc, wanted, wanted_length) == 0) {
                base = info->dlpi_addr;
                headers = info->dlpi_phdr;
                header_count = info->dlpi_phnum;
                return 1;
            }
            at = (const char *)desc + ((note->n_descsz + 3) & ~3u);
        }
    }
    return 0;
}

static int found(void) {
    const char *id = getenv("BENCH_BUILD_ID");
    if (!id)
        return 0;
    size_t length = strlen(id) / 2;
    if (length == 0 || length > sizeof wanted)
        return 0;
    for (size_t i = 0; i < length; i++) {
        unsigned value;
        if (sscanf(id + 2 * i, "%2x", &value) != 1)
            return 0;
        wanted[i] = (unsigned char)value;
    }
    wanted_length = length;
    return dl_iterate_phdr(is_target, NULL) == 1;
}

/* Makes the module's code writable for good (coverage) or for a moment. */
static void code_protection(int protection) {
    for (int i = 0; i < header_count; i++) {
        const ElfW(Phdr) *header = &headers[i];
        if (header->p_type != PT_LOAD || !(header->p_flags & PF_X))
            continue;
        uintptr_t start = (base + header->p_vaddr) & ~(uintptr_t)4095;
        uintptr_t end = (base + header->p_vaddr + header->p_memsz + 4095) & ~(uintptr_t)4095;
        if (raw(SYS_mprotect, (long)start, (long)(end - start), protection) != 0)
            fail("substitute: cannot change the code's protection\n");
    }
}

/* Coverage. */
static uintptr_t *entries;
static unsigned char *originals;
static size_t entry_count;
static volatile unsigned char *covered;

static void trapped(int signal_number, siginfo_t *info, void *context) {
    (void)signal_number;
    (void)info;
    ucontext_t *state = context;
    uintptr_t at = (uintptr_t)state->uc_mcontext.gregs[REG_RIP] - 1;
    size_t low = 0, high = entry_count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (entries[middle] < at)
            low = middle + 1;
        else
            high = middle;
    }
    if (low < entry_count && entries[low] == at) {
        covered[low] = 1;
        *(volatile unsigned char *)at = originals[low];
        state->uc_mcontext.gregs[REG_RIP] = (greg_t)at;
        return;
    }
    /* Not one of ours: the default action. */
    struct {
        void *handler;
        unsigned long flags;
        void *restorer;
        unsigned long mask;
    } action = {SIG_DFL, 0, NULL, 0};
    raw4(SYS_rt_sigaction, SIGTRAP, (long)&action, 0, 8);
    raw(SYS_kill, raw(SYS_getpid, 0, 0, 0), SIGTRAP, 0);
}

static void coverage(const char *bitmap, const char *list) {
    FILE *file = fopen(list, "r");
    if (!file)
        fail("substitute: no entry list\n");
    size_t capacity = 1024;
    entries = malloc(capacity * sizeof *entries);
    unsigned long long address;
    while (fscanf(file, "%llx", &address) == 1) {
        if (entry_count == capacity) {
            capacity *= 2;
            entries = realloc(entries, capacity * sizeof *entries);
        }
        entries[entry_count++] = base + address;
        if (entry_count > 1 && entries[entry_count - 1] <= entries[entry_count - 2])
            fail("substitute: the entry list is not sorted\n");
    }
    fclose(file);
    int descriptor = open(bitmap, O_RDWR);
    if (descriptor < 0)
        fail("substitute: no coverage file\n");
    covered = mmap(NULL, entry_count ? entry_count : 1, PROT_READ | PROT_WRITE, MAP_SHARED,
                   descriptor, 0);
    close(descriptor);
    if (covered == MAP_FAILED)
        fail("substitute: cannot map the coverage file\n");
    originals = malloc(entry_count ? entry_count : 1);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_sigaction = trapped;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGTRAP, &action, NULL);
    code_protection(PROT_READ | PROT_WRITE | PROT_EXEC);
    for (size_t i = 0; i < entry_count; i++) {
        originals[i] = *(unsigned char *)entries[i];
        if (!covered[i])
            *(volatile unsigned char *)entries[i] = 0xcc;
    }
}

/* Substitution. */
__attribute__((visibility("hidden"))) void *bench_target;
__attribute__((visibility("hidden"))) char bench_mark_path[4096];
__attribute__((visibility("hidden"))) unsigned char bench_marked;
extern char bench_stub[] __attribute__((visibility("hidden")));

/* The stub the replaced function jumps to: creates BENCH_MARK once, every
 * register an argument may be in kept, then on to the C. */
__asm__(".text\n"
        ".hidden bench_stub\n"
        "bench_stub:\n"
        "    cmpb $0, bench_marked(%rip)\n"
        "    jne 1f\n"
        "    movb $1, bench_marked(%rip)\n"
        "    push %rax\n push %rdi\n push %rsi\n push %rdx\n push %rcx\n"
        "    push %r8\n push %r9\n push %r10\n push %r11\n"
        "    mov $2, %eax\n"
        "    lea bench_mark_path(%rip), %rdi\n"
        "    mov $0x241, %esi\n" /* O_WRONLY | O_CREAT | O_TRUNC */
        "    mov $0x1a4, %edx\n"
        "    syscall\n"
        "    mov %rax, %rdi\n"
        "    mov $3, %eax\n"
        "    syscall\n"
        "    pop %r11\n pop %r10\n pop %r9\n pop %r8\n pop %rcx\n"
        "    pop %rdx\n pop %rsi\n pop %rdi\n pop %rax\n"
        "1:  jmp *bench_target(%rip)\n");

struct name {
    char *name;
    uintptr_t address;
};

static uintptr_t relocated(const struct link_map *map, ElfW(Addr) pointer) {
    /* glibc relocates these entries of a loaded object's dynamic section
     * in place; an offset is below the object's base. */
    return pointer < map->l_addr ? map->l_addr + pointer : pointer;
}

static void substitute(const char *object, const char *function, const char *entry,
                       const char *names_path, const char *mark) {
    size_t count = 0, capacity = 64;
    struct name *names = malloc(capacity * sizeof *names);
    FILE *file = fopen(names_path, "r");
    if (!file)
        fail("substitute: no name map\n");
    char line[4096];
    while (fgets(line, sizeof line, file)) {
        char *space = strchr(line, ' ');
        if (!space)
            continue;
        *space = 0;
        if (count == capacity) {
            capacity *= 2;
            names = realloc(names, capacity * sizeof *names);
        }
        names[count].name = strdup(line);
        names[count].address = base + strtoull(space + 1, NULL, 16);
        count++;
    }
    fclose(file);

    void *handle = dlopen(object, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char *why = dlerror();
        fprintf(stderr, "substitute: %s\n", why ? why : "cannot load");
        _exit(97);
    }
    struct link_map *map;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0)
        fail("substitute: no link map\n");
    const ElfW(Sym) *symbols = NULL;
    const char *strings = NULL;
    const ElfW(Rela) *tables[2] = {NULL, NULL};
    size_t sizes[2] = {0, 0};
    for (const ElfW(Dyn) *d = map->l_ld; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB: symbols = (const void *)relocated(map, d->d_un.d_ptr); break;
        case DT_STRTAB: strings = (const void *)relocated(map, d->d_un.d_ptr); break;
        case DT_RELA: tables[0] = (const void *)relocated(map, d->d_un.d_ptr); break;
        case DT_RELASZ: sizes[0] = d->d_un.d_val; break;
        case DT_JMPREL: tables[1] = (const void *)relocated(map, d->d_un.d_ptr); break;
        case DT_PLTRELSZ: sizes[1] = d->d_un.d_val; break;
        }
    }
    if (!symbols || !strings)
        fail("substitute: no dynamic symbols\n");
    for (int t = 0; t < 2; t++) {
        for (size_t i = 0; tables[t] && i < sizes[t] / sizeof(ElfW(Rela)); i++) {
            const ElfW(Rela) *rela = &tables[t][i];
            unsigned type = ELF64_R_TYPE(rela->r_info);
            unsigned symbol = ELF64_R_SYM(rela->r_info);
            if (symbol == 0 ||
                (type != R_X86_64_GLOB_DAT && type != R_X86_64_JUMP_SLOT && type != R_X86_64_64))
                continue;
            const char *name = strings + symbols[symbol].st_name;
            for (size_t n = 0; n < count; n++) {
                if (strcmp(names[n].name, name) != 0)
                    continue;
                uintptr_t *slot = (uintptr_t *)(map->l_addr + rela->r_offset);
                uintptr_t page = (uintptr_t)slot & ~(uintptr_t)4095;
                uintptr_t end = ((uintptr_t)(slot + 1) + 4095) & ~(uintptr_t)4095;
                raw(SYS_mprotect, (long)page, (long)(end - page), PROT_READ | PROT_WRITE);
                *slot = names[n].address + (type == R_X86_64_64 ? (uintptr_t)rela->r_addend : 0);
                break;
            }
        }
    }
    bench_target = dlsym(handle, function);
    if (!bench_target) {
        fprintf(stderr, "substitute: no %s in the C\n", function);
        _exit(98);
    }
    if (strlen(mark) >= sizeof bench_mark_path)
        fail("substitute: mark path too long\n");
    strcpy(bench_mark_path, mark);

    unsigned char *at = (unsigned char *)(base + strtoull(entry, NULL, 16));
    uintptr_t stub = (uintptr_t)bench_stub;
    unsigned char patch[13] = {0x49, 0xbb};
    memcpy(patch + 2, &stub, 8);
    patch[10] = 0x41;
    patch[11] = 0xff;
    patch[12] = 0xe3;
    uintptr_t page = (uintptr_t)at & ~(uintptr_t)4095;
    uintptr_t end = ((uintptr_t)at + sizeof patch + 4095) & ~(uintptr_t)4095;
    if (raw(SYS_mprotect, (long)page, (long)(end - page), PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        fail("substitute: cannot write the code\n");
    for (int i = 0; i < 13; i++)
        ((volatile unsigned char *)at)[i] = patch[i];
    raw(SYS_mprotect, (long)page, (long)(end - page), PROT_READ | PROT_EXEC);
}

__attribute__((constructor)) static void start(void) {
    if (!found())
        return;
    const char *bitmap = getenv("BENCH_COVERAGE");
    const char *list = getenv("BENCH_ENTRIES");
    if (bitmap && list) {
        coverage(bitmap, list);
        return;
    }
    const char *object = getenv("BENCH_SO");
    const char *function = getenv("BENCH_FUNCTION");
    const char *entry = getenv("BENCH_ENTRY");
    const char *names = getenv("BENCH_MAP");
    const char *mark = getenv("BENCH_MARK");
    if (object && function && entry && names && mark)
        substitute(object, function, entry, names, mark);
}
