/*
 * Micro-PE MT.3: CRITICAL_SECTION shared by two guest threads.
 *
 * Freestanding PE64. Worker increments a counter under CS; primary joins.
 *
 * Exit codes:
 *   0 — ok
 *   1 — CreateThread failed
 *   2 — Wait failed
 *   3 — counter mismatch
 */

#include <windows.h>

static CRITICAL_SECTION g_cs;
static volatile LONG g_count = 0;

static DWORD WINAPI worker(LPVOID param) {
    int n = (int)(ULONG_PTR)param;
    int i;
    for (i = 0; i < n; i++) {
        EnterCriticalSection(&g_cs);
        g_count++;
        LeaveCriticalSection(&g_cs);
    }
    ExitThread(0);
    return 0;
}

void entry(void) {
    HANDLE h;
    DWORD wait;
    /* Keep small: each Enter/Leave is a host stop; contention parks briefly. */
    const int n = 64;

    InitializeCriticalSection(&g_cs);

    h = CreateThread(NULL, 0, worker, (LPVOID)(ULONG_PTR)n, 0, NULL);
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    {
        int i;
        for (i = 0; i < n; i++) {
            EnterCriticalSection(&g_cs);
            g_count++;
            LeaveCriticalSection(&g_cs);
        }
    }

    wait = WaitForSingleObject(h, INFINITE);
    if (wait != WAIT_OBJECT_0) {
        ExitProcess(2);
    }
    CloseHandle(h);

    DeleteCriticalSection(&g_cs);

    if (g_count != (LONG)(n * 2)) {
        ExitProcess(3);
    }
    ExitProcess(0);
}
