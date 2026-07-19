/*
 * Micro-PE MT.3: auto-reset event handshake between two threads.
 *
 * Primary waits; worker sets event after writing a cell.
 *
 * Exit codes:
 *   0 — ok
 *   1 — CreateEvent failed
 *   2 — CreateThread failed
 *   3 — Wait failed
 *   4 — cell not written
 */

#include <windows.h>

static HANDLE g_event;
static volatile LONG g_cell = 0;

static DWORD WINAPI worker(LPVOID param) {
    (void)param;
    g_cell = 0xC0FFEE;
    SetEvent(g_event);
    ExitThread(0);
    return 0;
}

void entry(void) {
    HANDLE h;
    DWORD wait;

    g_event = CreateEventA(NULL, FALSE, FALSE, NULL); /* auto-reset, nonsignaled */
    if (g_event == NULL || g_event == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    h = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        ExitProcess(2);
    }

    wait = WaitForSingleObject(g_event, INFINITE);
    if (wait != WAIT_OBJECT_0) {
        ExitProcess(3);
    }

    if (g_cell != 0xC0FFEE) {
        ExitProcess(4);
    }

    WaitForSingleObject(h, INFINITE);
    CloseHandle(h);
    CloseHandle(g_event);
    ExitProcess(0);
}
