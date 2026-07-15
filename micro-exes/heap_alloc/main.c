/*
 * Micro-PE: GetProcessHeap + HeapAlloc + HeapFree + ExitProcess.
 *
 * Freestanding PE64 (no CRT). Build with mingw; see micro-exes/Makefile.
 *
 * Exit codes:
 *   0 — success (alloc non-NULL, write byte, free ok)
 *   1 — HeapAlloc returned NULL
 *   2 — HeapFree failed
 *   3 — GetProcessHeap returned NULL
 *
 * Docs: HeapAlloc / HeapFree / GetProcessHeap (Microsoft Learn).
 * Clean room: no third-party reimplementation sources.
 */

#include <windows.h>

void entry(void) {
  HANDLE heap = GetProcessHeap();
  void *p;
  char *bytes;

  if (heap == NULL) {
    ExitProcess(3);
  }

  p = HeapAlloc(heap, 0, 64);
  if (p == NULL) {
    ExitProcess(1);
  }

  /* Prove the pointer is writable guest memory. */
  bytes = (char *)p;
  bytes[0] = 0x41;
  bytes[63] = 0x5A;

  if (!HeapFree(heap, 0, p)) {
    ExitProcess(2);
  }

  ExitProcess(0);
}
