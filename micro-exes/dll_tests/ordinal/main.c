/*
 * DLL test: GetProcAddress by ordinal.
 *
 * Loads dll_ordinal_funcs.dll, resolves export #1 and #2 by ordinal,
 * calls them, verifies results.
 *
 * Exit codes:
 *   0 — ok
 *   1 — LoadLibrary failed
 *   2 — GetProcAddress by ordinal 1 failed
 *   3 — ordinal 1 returned wrong value
 *   4 — GetProcAddress by ordinal 2 failed
 *   5 — ordinal 2 returned wrong value
 */

#include <windows.h>

typedef int (*int_fn)(void);

void entry(void) {
    HMODULE dll;
    int_fn fn1, fn2;
    int result;

    dll = LoadLibraryA("dll_ordinal_funcs.dll");
    if (dll == NULL) {
        ExitProcess(1);
    }

    /* Ordinal 1: get_one() */
    fn1 = (int_fn)(void*)GetProcAddress(dll, (LPCSTR)1);
    if (fn1 == NULL) {
        ExitProcess(2);
    }
    result = fn1();
    if (result != 1) {
        ExitProcess(3);
    }

    /* Ordinal 2: get_two() */
    fn2 = (int_fn)(void*)GetProcAddress(dll, (LPCSTR)2);
    if (fn2 == NULL) {
        ExitProcess(4);
    }
    result = fn2();
    if (result != 2) {
        ExitProcess(5);
    }

    FreeLibrary(dll);
    ExitProcess(0);
}
