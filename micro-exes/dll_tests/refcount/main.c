/*
 * DLL test: LoadLibrary/FreeLibrary reference counting.
 *
 * Loads the same DLL twice, then frees it twice.
 * First FreeLibrary should succeed, second should also succeed
 * (the handle remains valid as a real loaded module handle
 * after refcount hits zero; the module is unmapped).
 *
 * Exit codes:
 *   0 — ok
 *   1 — first LoadLibrary failed
 *   2 — second LoadLibrary failed (same handle expected)
 *   3 — first FreeLibrary failed
 *   4 — second FreeLibrary failed
 *   5 — handle mismatch between loads
 */

#include <windows.h>

void entry(void) {
    HMODULE dll1, dll2;
    BOOL ok;

    dll1 = LoadLibraryA("dll_math_funcs.dll");
    if (dll1 == NULL) {
        ExitProcess(1);
    }

    dll2 = LoadLibraryA("dll_math_funcs.dll");
    if (dll2 == NULL) {
        ExitProcess(2);
    }

    /* Should get the same handle (already loaded, refcount bumped). */
    if (dll1 != dll2) {
        ExitProcess(5);
    }

    ok = FreeLibrary(dll1);
    if (!ok) {
        ExitProcess(3);
    }

    ok = FreeLibrary(dll2);
    if (!ok) {
        ExitProcess(4);
    }

    ExitProcess(0);
}
