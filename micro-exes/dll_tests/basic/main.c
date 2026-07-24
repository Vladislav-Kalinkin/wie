/*
 * DLL test: basic load + call exported function.
 *
 * Loads dll_basic_funcs.dll, resolves add() via GetProcAddress,
 * calls add(2, 3), expects 5.
 *
 * Exit codes:
 *   0 — ok
 *   1 — LoadLibrary failed
 *   2 — GetProcAddress failed
 *   3 — add returned wrong value
 */

#include <windows.h>

typedef int (*add_fn)(int, int);

void entry(void) {
    HMODULE dll;
    add_fn add;
    int result;

    dll = LoadLibraryA("dll_basic_funcs.dll");
    if (dll == NULL) {
        ExitProcess(1);
    }

    add = (add_fn)(void*)GetProcAddress(dll, "add");
    if (add == NULL) {
        ExitProcess(2);
    }

    result = add(2, 3);
    if (result != 5) {
        ExitProcess(3);
    }

    FreeLibrary(dll);
    ExitProcess(0);
}
