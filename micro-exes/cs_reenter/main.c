/*
 * Micro-PE MT.1: reentrant CRITICAL_SECTION on a single guest thread.
 *
 * Freestanding PE64. Microsoft Learn: Initialize / Enter / Leave / Delete.
 *
 * Exit codes:
 *   0 — ok
 *   1 — OwningThread not set after Enter
 *   2 — RecursionCount not 2 after double Enter
 *   3 — still locked after balanced Leave
 *   4 — GetCurrentThreadId is 0
 */

#include <windows.h>

/* Win64 RTL_CRITICAL_SECTION field offsets (must match WIE host writer). */
#define CS_LOCK_COUNT_OFF 8
#define CS_RECURSION_OFF 12
#define CS_OWNER_OFF 16

static DWORD read_u32(const void *p) {
    return *(const DWORD *)p;
}

static ULONG_PTR read_uptr(const void *p) {
    return *(const ULONG_PTR *)p;
}

void entry(void) {
    CRITICAL_SECTION cs;
    DWORD tid;
    const BYTE *base;

    tid = GetCurrentThreadId();
    if (tid == 0) {
        ExitProcess(4);
    }

    InitializeCriticalSection(&cs);
    base = (const BYTE *)&cs;

    EnterCriticalSection(&cs);
    if (read_uptr(base + CS_OWNER_OFF) != (ULONG_PTR)tid) {
        ExitProcess(1);
    }

    EnterCriticalSection(&cs);
    if (read_u32(base + CS_RECURSION_OFF) != 2) {
        ExitProcess(2);
    }

    LeaveCriticalSection(&cs);
    LeaveCriticalSection(&cs);

    if (read_uptr(base + CS_OWNER_OFF) != 0) {
        ExitProcess(3);
    }
    if (read_u32(base + CS_LOCK_COUNT_OFF) != (DWORD)-1) {
        ExitProcess(3);
    }

    DeleteCriticalSection(&cs);
    ExitProcess(0);
}
