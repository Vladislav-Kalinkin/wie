/*
 * Micro-PE MT.1: process TLS indices, per-thread values (primary thread).
 *
 * Freestanding PE64. Microsoft Learn: TlsAlloc / TlsSetValue / TlsGetValue / TlsFree.
 *
 * Exit codes:
 *   0 — ok
 *   1 — TlsAlloc failed (TLS_OUT_OF_INDEXES)
 *   2 — TlsSetValue failed
 *   3 — TlsGetValue mismatch
 *   4 — second index cross-talk
 *   5 — TlsGetValue after free still non-zero (value should be cleared)
 */

#include <windows.h>

void entry(void) {
    DWORD a;
    DWORD b;
    const ULONG_PTR marker = (ULONG_PTR)0xC0FFEEu;
    const ULONG_PTR other = (ULONG_PTR)0xBEEFu;

    a = TlsAlloc();
    if (a == TLS_OUT_OF_INDEXES) {
        ExitProcess(1);
    }

    if (!TlsSetValue(a, (LPVOID)marker)) {
        ExitProcess(2);
    }
    if ((ULONG_PTR)TlsGetValue(a) != marker) {
        ExitProcess(3);
    }

    b = TlsAlloc();
    if (b == TLS_OUT_OF_INDEXES) {
        ExitProcess(1);
    }
    if (!TlsSetValue(b, (LPVOID)other)) {
        ExitProcess(2);
    }
    if ((ULONG_PTR)TlsGetValue(a) != marker || (ULONG_PTR)TlsGetValue(b) != other) {
        ExitProcess(4);
    }

    if (!TlsFree(a)) {
        ExitProcess(2);
    }
    /* Index a value cleared on free for active thread. */
    if ((ULONG_PTR)TlsGetValue(a) != 0) {
        ExitProcess(5);
    }

    ExitProcess(0);
}
