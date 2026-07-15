/*
 * Micro-PE N1: process heap core (kernel32).
 *
 * Freestanding PE64. Clean room: Microsoft Learn semantics only.
 *
 * Exit codes:
 *   0 — success
 *   1 — GetProcessHeap NULL
 *   2 — HeapAlloc NULL
 *   3 — HeapSize too small / failed after Alloc
 *   4 — payload write verify failed
 *   5 — HeapReAlloc NULL
 *   6 — data not preserved across ReAlloc
 *   7 — HeapSize failed after ReAlloc
 *   8 — HeapFree failed
 *
 * Docs: GetProcessHeap, HeapAlloc, HeapSize, HeapReAlloc, HeapFree, ExitProcess.
 *
 * Note: HeapSize may return a size >= requested (allocator size classes).
 */

#include <windows.h>

void entry(void) {
    HANDLE heap = GetProcessHeap();
    void *p;
    void *q;
    SIZE_T sz;
    unsigned char *bytes;

    if (heap == NULL) {
        ExitProcess(1);
    }

    p = HeapAlloc(heap, 0, 64);
    if (p == NULL) {
        ExitProcess(2);
    }

    sz = HeapSize(heap, 0, p);
    if (sz == (SIZE_T)-1 || sz < 64) {
        ExitProcess(3);
    }

    bytes = (unsigned char *)p;
    bytes[0] = 0x41;
    bytes[63] = 0x5A;
    if (bytes[0] != 0x41 || bytes[63] != 0x5A) {
        ExitProcess(4);
    }

    q = HeapReAlloc(heap, 0, p, 128);
    if (q == NULL) {
        ExitProcess(5);
    }

    bytes = (unsigned char *)q;
    if (bytes[0] != 0x41) {
        ExitProcess(6);
    }
    bytes[127] = 0x7E;

    sz = HeapSize(heap, 0, q);
    if (sz == (SIZE_T)-1 || sz < 128) {
        ExitProcess(7);
    }

    if (!HeapFree(heap, 0, q)) {
        ExitProcess(8);
    }

    ExitProcess(0);
}
