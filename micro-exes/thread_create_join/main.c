/*
 * Micro-PE MT.2: CreateThread + shared cell + ExitThread + WaitForSingleObject.
 *
 * Freestanding PE64. Microsoft Learn: CreateThread, WaitForSingleObject,
 * GetExitCodeThread, CloseHandle, ExitThread, ExitProcess.
 *
 * Exit codes:
 *   0 — ok
 *   1 — CreateThread failed
 *   2 — WaitForSingleObject failed
 *   3 — worker exit code mismatch
 *   4 — shared cell not written by worker
 *   5 — GetExitCodeThread failed
 */

#include <windows.h>

static volatile LONG g_cell = 0;

static DWORD WINAPI worker(LPVOID param) {
    LONG marker = (LONG)(ULONG_PTR)param;
    /* Engine serializes guest threads on one CPU; plain store is enough for DoD. */
    g_cell = marker;
    ExitThread(0x42);
    return 0; /* unreachable */
}

void entry(void) {
    HANDLE h;
    DWORD tid = 0;
    DWORD wait;
    DWORD code = 0;
    const LONG marker = 0x13579BDF;

    h = CreateThread(NULL, 0, worker, (LPVOID)(ULONG_PTR)marker, 0, &tid);
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }
    if (tid == 0) {
        ExitProcess(1);
    }

    wait = WaitForSingleObject(h, INFINITE);
    if (wait != WAIT_OBJECT_0) {
        ExitProcess(2);
    }

    if (!GetExitCodeThread(h, &code)) {
        ExitProcess(5);
    }
    if (code != 0x42) {
        ExitProcess(3);
    }

    if (g_cell != marker) {
        ExitProcess(4);
    }

    CloseHandle(h);
    ExitProcess(0);
}
