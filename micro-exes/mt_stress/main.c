/*
 * Micro-PE MT.4 stress: multi-thread Interlocked + CS + heap + shared buffer.
 *
 * Freestanding PE64. Spawns WORKERS host threads; each hammers:
 *   - InterlockedIncrement via GetProcAddress (preplanted soft slot)
 *   - CRITICAL_SECTION-protected heap alloc/free
 *   - writes into a shared slot buffer (one slot per worker)
 * Primary joins all, verifies totals, ExitProcess(0).
 *
 * Exit codes:
 *   0 — ok
 *   1 — CreateThread failed
 *   2 — Wait failed
 *   3 — interlocked counter mismatch
 *   4 — heap-protected counter mismatch
 *   5 — shared slot mismatch
 *   6 — event / GetProcAddress failed
 */

#include <windows.h>

#define WORKERS 4
#define ITERS   512

typedef LONG(WINAPI *PFN_Inc)(LONG volatile *);

static CRITICAL_SECTION g_cs;
static volatile LONG g_atomic = 0;
static volatile LONG g_under_cs = 0;
static volatile LONG g_slots[WORKERS];
static HANDLE g_start_event;
static HANDLE g_done_event;
static volatile LONG g_ready = 0;
static PFN_Inc g_inc;

static DWORD WINAPI worker(LPVOID param) {
    int id = (int)(ULONG_PTR)param;
    int i;
    HANDLE heap;
    LONG marker = 0x1000 + id;

    if (g_inc(&g_ready) == WORKERS) {
        SetEvent(g_done_event);
    }
    WaitForSingleObject(g_start_event, INFINITE);

    heap = GetProcessHeap();
    for (i = 0; i < ITERS; i++) {
        void *p;

        g_inc(&g_atomic);

        EnterCriticalSection(&g_cs);
        g_under_cs++;
        p = HeapAlloc(heap, 0, 64);
        if (p) {
            *((volatile LONG *)p) = marker;
            HeapFree(heap, 0, (LPVOID)p);
        }
        LeaveCriticalSection(&g_cs);

        g_slots[id] = marker;
    }

    ExitThread(0);
    return 0;
}

void entry(void) {
    HANDLE threads[WORKERS];
    DWORD wait;
    int i;
    HMODULE k;
    const LONG expect = (LONG)(WORKERS * ITERS);

    for (i = 0; i < WORKERS; i++) {
        g_slots[i] = 0;
    }

    k = GetModuleHandleA("KERNEL32.dll");
    if (!k) {
        k = GetModuleHandleA("kernel32.dll");
    }
    if (!k) {
        ExitProcess(6);
    }
    g_inc = (PFN_Inc)GetProcAddress(k, "InterlockedIncrement");
    if (!g_inc) {
        ExitProcess(6);
    }

    InitializeCriticalSection(&g_cs);
    g_start_event = CreateEventA(NULL, TRUE, FALSE, NULL); /* manual */
    g_done_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_start_event || !g_done_event) {
        ExitProcess(6);
    }

    for (i = 0; i < WORKERS; i++) {
        threads[i] = CreateThread(NULL, 0, worker, (LPVOID)(ULONG_PTR)i, 0, NULL);
        if (threads[i] == NULL || threads[i] == INVALID_HANDLE_VALUE) {
            ExitProcess(1);
        }
    }

    wait = WaitForSingleObject(g_done_event, 30000);
    if (wait != WAIT_OBJECT_0) {
        ExitProcess(6);
    }
    SetEvent(g_start_event);

    for (i = 0; i < WORKERS; i++) {
        wait = WaitForSingleObject(threads[i], INFINITE);
        if (wait != WAIT_OBJECT_0) {
            ExitProcess(2);
        }
        CloseHandle(threads[i]);
    }

    if (g_atomic != expect) {
        ExitProcess(3);
    }
    if (g_under_cs != expect) {
        ExitProcess(4);
    }
    for (i = 0; i < WORKERS; i++) {
        if (g_slots[i] != (LONG)(0x1000 + i)) {
            ExitProcess(5);
        }
    }

    DeleteCriticalSection(&g_cs);
    CloseHandle(g_start_event);
    CloseHandle(g_done_event);
    ExitProcess(0);
}
