/*
 * DLL test: loading multiple independent DLLs.
 *
 * Loads dll_basic_funcs.dll and dll_math_funcs.dll, calls
 * exported functions from both.
 *
 * Exit codes:
 *   0 — ok
 *   1 — LoadLibrary(basic) failed
 *   2 — GetProcAddress(add) failed
 *   3 — add returned wrong value
 *   4 — LoadLibrary(math) failed
 *   5 — GetProcAddress(get_value) failed
 *   6 — get_value returned wrong value
 *   7 — FreeLibrary(basic) failed
 *   8 — FreeLibrary(math) failed
 */

#include <windows.h>

typedef int (*int_fn_int_int)(int, int);
typedef int (*int_fn_void)(void);

void entry(void) {
    HMODULE basic, math;
    int_fn_int_int add;
    int_fn_void get_val;
    int result;

    basic = LoadLibraryA("dll_basic_funcs.dll");
    if (basic == NULL) {
        ExitProcess(1);
    }

    add = (int_fn_int_int)(void*)GetProcAddress(basic, "add");
    if (add == NULL) {
        ExitProcess(2);
    }

    result = add(10, 20);
    if (result != 30) {
        ExitProcess(3);
    }

    math = LoadLibraryA("dll_math_funcs.dll");
    if (math == NULL) {
        ExitProcess(4);
    }

    get_val = (int_fn_void)(void*)GetProcAddress(math, "get_value");
    if (get_val == NULL) {
        ExitProcess(5);
    }

    result = get_val();
    if (result != 42) {
        ExitProcess(6);
    }

    if (!FreeLibrary(basic)) {
        ExitProcess(7);
    }

    if (!FreeLibrary(math)) {
        ExitProcess(8);
    }

    ExitProcess(0);
}
