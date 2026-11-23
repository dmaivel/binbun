/* Walks of the thread's TEB to the process's loaded modules, as code that
 * finds a module without importing anything does, built with MSVC for x64
 * and ARM64 (cl /O2 /MD: see scripts/build-fixtures.sh): the PEB by its
 * address in the TEB (x64 gs:[0x60], ARM64 [x18+0x60]), the loader's data,
 * its in-memory-order module list, and a module's base by name; and the
 * process's id from the native API (ntdll.dll's NtQueryInformationProcess,
 * ARM64's build only: x64's predates it, and tests name its addresses).
 * Structures as the Windows SDK's winternl.h declares them. */
#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#define NOINLINE __declspec(noinline)

/* The TEB's quadword at an offset: gs-relative on x64; on ARM64 the
 * platform register x18 holds the TEB. */
#if defined(_M_ARM64)
#define TEB_QWORD(offset) __readx18qword(offset)
#else
#define TEB_QWORD(offset) __readgsqword(offset)
#endif

/* The PEB, read straight from the TEB's 0x60. */
NOINLINE PPEB peb(void) { return (PPEB)TEB_QWORD(0x60); }

/* The loader's data, through the TEB's own address. */
NOINLINE PPEB_LDR_DATA loader(void) { return NtCurrentTeb()->ProcessEnvironmentBlock->Ldr; }

/* How many modules are loaded. */
NOINLINE unsigned modules(void) {
    PPEB peb = (PPEB)TEB_QWORD(0x60);
    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    unsigned count = 0;
    for (LIST_ENTRY *entry = head->Flink; entry != head; entry = entry->Flink)
        count++;
    return count;
}

/* The base of the module whose full name has `length` bytes, or null. */
NOINLINE void *module_base(unsigned short length) {
    PPEB peb = (PPEB)TEB_QWORD(0x60);
    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY *entry = head->Flink; entry != head; entry = entry->Flink) {
        LDR_DATA_TABLE_ENTRY *module =
            CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (module->FullDllName.Length == length)
            return module->DllBase;
    }
    return NULL;
}

/* The process's command line, from its parameters. */
NOINLINE PWSTR command_line(void) {
    return ((PPEB)TEB_QWORD(0x60))->ProcessParameters->CommandLine.Buffer;
}

#if defined(_M_ARM64)
/* The process's id, from the native API (the current process's pseudo
 * handle, -1). */
NOINLINE ULONG_PTR process_id(void) {
    PROCESS_BASIC_INFORMATION info;
    ULONG length;
    if (NtQueryInformationProcess((HANDLE)(LONG_PTR)-1, ProcessBasicInformation, &info,
                                  sizeof info, &length) < 0)
        return 0;
    return info.UniqueProcessId;
}
#define PROCESS_ID() (process_id() != 0)
#else
#define PROCESS_ID() 0
#endif

int main(void) {
    return (int)modules() + (peb() != 0) + (loader() != 0) + (module_base(0) != 0) +
           (command_line() != 0) + PROCESS_ID();
}
