/*
 * Micro-PE N3: module APIs (kernel32).
 *
 * Freestanding PE64. Clean room: Microsoft Learn semantics.
 *
 * Exit codes:
 *   0 — ok
 *   1 — GetModuleHandleA(NULL) failed
 *   2 — GetModuleFileNameA failed / empty
 *   3 — path does not look like C:\App\...
 *   4 — GetModuleHandleA("kernel32.dll") failed
 *   5 — GetProcAddress(EncodePointer) failed
 *   6 — GetProcAddress(unknown) was non-NULL
 *   7 — LoadLibraryA("kernel32.dll") failed
 *   8 — LoadLibrary handle != GetModuleHandle handle
 *
 * Docs: GetModuleHandleA, GetModuleFileNameA, GetProcAddress, LoadLibraryA.
 */

#include <windows.h>

void entry(void) {
    HMODULE self;
    HMODULE k32;
    HMODULE loaded;
    FARPROC enc;
    FARPROC missing;
    char path[260];
    DWORD n;
    unsigned i;
    int saw_app;

    self = GetModuleHandleA(NULL);
    if (self == NULL) {
        ExitProcess(1);
    }

    for (i = 0; i < 260; i++) {
        path[i] = 0;
    }
    n = GetModuleFileNameA(NULL, path, 260);
    if (n == 0 || n >= 260) {
        ExitProcess(2);
    }

    /* Expect guest identity path C:\App\<exe> (session ProcessIdentity). */
    saw_app = 0;
    for (i = 0; i + 4 < n; i++) {
        if (path[i] == 'A' && path[i + 1] == 'p' && path[i + 2] == 'p') {
            saw_app = 1;
            break;
        }
        if (path[i] == 'a' && path[i + 1] == 'p' && path[i + 2] == 'p') {
            saw_app = 1;
            break;
        }
    }
    if (!saw_app || path[0] != 'C') {
        ExitProcess(3);
    }

    k32 = GetModuleHandleA("kernel32.dll");
    if (k32 == NULL) {
        ExitProcess(4);
    }

    enc = GetProcAddress(k32, "EncodePointer");
    if (enc == NULL) {
        ExitProcess(5);
    }

    missing = GetProcAddress(k32, "DefinitelyNotAnExport_WIE");
    if (missing != NULL) {
        ExitProcess(6);
    }

    loaded = LoadLibraryA("kernel32.dll");
    if (loaded == NULL) {
        ExitProcess(7);
    }
    if (loaded != k32) {
        ExitProcess(8);
    }

    ExitProcess(0);
}
