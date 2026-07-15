/*
 * Micro-PE N1: process ids + last-error (kernel32).
 *
 * Freestanding PE64. Clean room: Microsoft Learn semantics only.
 *
 * Exit codes:
 *   0 — all checks passed
 *   1 — GetCurrentProcess is not (HANDLE)-1
 *   2 — GetCurrentProcessId returned 0
 *   3 — GetCurrentThreadId returned 0
 *   4 — SetLastError/GetLastError mismatch
 *
 * Docs: GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
 *       SetLastError, GetLastError, ExitProcess (Microsoft Learn).
 */

#include <windows.h>

void entry(void) {
    HANDLE proc = GetCurrentProcess();
    DWORD pid;
    DWORD tid;
    const DWORD marker = 0x0000002Au;

    /* Pseudohandle: (HANDLE)(LONG_PTR)-1 */
    if (proc != (HANDLE)(LONG_PTR)-1) {
        ExitProcess(1);
    }

    pid = GetCurrentProcessId();
    if (pid == 0) {
        ExitProcess(2);
    }

    tid = GetCurrentThreadId();
    if (tid == 0) {
        ExitProcess(3);
    }

    SetLastError(marker);
    if (GetLastError() != marker) {
        ExitProcess(4);
    }

    ExitProcess(0);
}
