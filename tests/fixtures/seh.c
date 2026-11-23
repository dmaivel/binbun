/* Structured exception handling (C), built with MSVC (cl /O2 /MD /Zi:
 * see scripts/build-fixtures.sh): __try/__except with a filter
 * expression and with EXCEPTION_EXECUTE_HANDLER, __try/__finally, and the
 * two nested, one function each. The exceptions are raised by a call
 * (RaiseException) or by a fault (a write through a null pointer). */
#include <stdio.h>
#include <windows.h>

#define NOINLINE __declspec(noinline)

#define CODE(n) (0xE0000000u | (n))

volatile int sink;
int *volatile nowhere;

/* Raises the exception CODE(code), or returns if code is 0. */
NOINLINE void raise(int code) {
    if (code)
        RaiseException(CODE(code), 0, 0, NULL);
}

NOINLINE void note(const char *what) { puts(what); }

/* Which exceptions filtered handles: its own code. */
NOINLINE int mine(unsigned long code) { return code == CODE(1); }

/* A filter expression: takes the exception only if mine says so, else
 * the search goes on outside. */
NOINLINE int filtered(int code) {
    __try {
        raise(code);
        sink = 1;
    } __except (mine(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                         : EXCEPTION_CONTINUE_SEARCH) {
        return -1;
    }
    return sink;
}

/* Every exception, including a fault. */
NOINLINE int any(int fault) {
    __try {
        if (fault)
            *nowhere = 1;
        sink = 2;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -(int)(GetExceptionCode() & 0xff);
    }
    return sink;
}

/* A termination handler: runs on the way out, normal or not. */
NOINLINE int finally(int code) {
    int result = 0;
    __try {
        raise(code);
        result = 3;
    } __finally {
        note(AbnormalTermination() ? "finally: unwinding" : "finally: normal");
        sink = result;
    }
    return result;
}

/* A __finally inside an __except. */
NOINLINE int nested(int code) {
    int result = 0;
    __try {
        __try {
            raise(code);
            result = 4;
        } __finally {
            note("nested: inner finally");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = -4;
    }
    return result;
}

int main(int argc, char **argv) {
    int n = argc - 1;
    (void)argv;
    printf("filtered %d %d\n", filtered(n), filtered(n + 1));
    __try {
        filtered(n + 2);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("filtered passed %lx on\n", GetExceptionCode());
    }
    printf("any %d %d\n", any(n), any(n + 1));
    printf("finally %d\n", finally(n));
    __try {
        finally(n + 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("finally passed %lx on\n", GetExceptionCode());
    }
    printf("nested %d %d\n", nested(n), nested(n + 1));
    return 0;
}
