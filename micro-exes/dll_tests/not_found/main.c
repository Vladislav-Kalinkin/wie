/*
 * DLL test: LoadLibrary on non-existent DLL.
 *
 * Exit codes:
 *   0 — ok (LoadLibrary correctly returned NULL)
 *   1 — LoadLibrary unexpectedly succeeded
 */

#include <windows.h>

void entry(void) {
    HMODULE dll;

    dll = LoadLibraryA("dll_does_not_exist_42.dll");
    if (dll != NULL) {
        /* Should have failed — DLL doesn't exist. */
        ExitProcess(1);
    }

    ExitProcess(0);
}
