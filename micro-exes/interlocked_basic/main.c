/*
 * Micro-PE MT.4: Interlocked* host-atomic semantics (single thread).
 *
 * Freestanding PE64. Resolves Interlocked* via GetProcAddress into preplanted
 * soft slots (compiler builtins emit LOCK XADD; mingw has no kernel32 IAT
 * exports for these names).
 *
 * Exit codes:
 *   0 — ok
 *   1 — Increment/Decrement mismatch
 *   2 — ExchangeAdd / Exchange mismatch
 *   3 — CompareExchange mismatch
 *   4 — 64-bit path mismatch
 *   5 — GetProcAddress failed
 */

#include <windows.h>

typedef LONG(WINAPI *PFN_Inc)(LONG volatile *);
typedef LONG(WINAPI *PFN_Dec)(LONG volatile *);
typedef LONG(WINAPI *PFN_Xchg)(LONG volatile *, LONG);
typedef LONG(WINAPI *PFN_CmpXchg)(LONG volatile *, LONG, LONG);
typedef LONG(WINAPI *PFN_Xadd)(LONG volatile *, LONG);
typedef LONGLONG(WINAPI *PFN_Inc64)(LONGLONG volatile *);
typedef LONGLONG(WINAPI *PFN_CmpXchg64)(LONGLONG volatile *, LONGLONG, LONGLONG);

static volatile LONG g_long = 0;
static volatile LONGLONG g_longlong = 100;

void entry(void) {
    HMODULE k;
    PFN_Inc pInc;
    PFN_Dec pDec;
    PFN_Xchg pXchg;
    PFN_CmpXchg pCmp;
    PFN_Xadd pXadd;
    PFN_Inc64 pInc64;
    PFN_CmpXchg64 pCmp64;
    LONG v;
    LONGLONG v64;

    k = GetModuleHandleA("KERNEL32.dll");
    if (!k) {
        k = GetModuleHandleA("kernel32.dll");
    }
    if (!k) {
        ExitProcess(5);
    }

    pInc = (PFN_Inc)GetProcAddress(k, "InterlockedIncrement");
    pDec = (PFN_Dec)GetProcAddress(k, "InterlockedDecrement");
    pXchg = (PFN_Xchg)GetProcAddress(k, "InterlockedExchange");
    pCmp = (PFN_CmpXchg)GetProcAddress(k, "InterlockedCompareExchange");
    pXadd = (PFN_Xadd)GetProcAddress(k, "InterlockedExchangeAdd");
    pInc64 = (PFN_Inc64)GetProcAddress(k, "InterlockedIncrement64");
    pCmp64 = (PFN_CmpXchg64)GetProcAddress(k, "InterlockedCompareExchange64");
    if (!pInc || !pDec || !pXchg || !pCmp || !pXadd || !pInc64 || !pCmp64) {
        ExitProcess(5);
    }

    v = pInc(&g_long);
    if (v != 1 || g_long != 1) {
        ExitProcess(1);
    }
    v = pDec(&g_long);
    if (v != 0 || g_long != 0) {
        ExitProcess(1);
    }

    g_long = 10;
    v = pXadd(&g_long, 5);
    if (v != 10 || g_long != 15) {
        ExitProcess(2);
    }

    v = pXchg(&g_long, 42);
    if (v != 15 || g_long != 42) {
        ExitProcess(2);
    }

    v = pCmp(&g_long, 99, 42);
    if (v != 42 || g_long != 99) {
        ExitProcess(3);
    }
    v = pCmp(&g_long, 1, 42); /* fail: still 99 */
    if (v != 99 || g_long != 99) {
        ExitProcess(3);
    }

    v64 = pInc64(&g_longlong);
    if (v64 != 101 || g_longlong != 101) {
        ExitProcess(4);
    }
    v64 = pCmp64(&g_longlong, 200, 101);
    if (v64 != 101 || g_longlong != 200) {
        ExitProcess(4);
    }

    ExitProcess(0);
}
