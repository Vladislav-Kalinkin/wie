/*
 * Micro-PE N2: CreateFile(CREATE_ALWAYS) + WriteFile + CloseHandle.
 *
 * Requires bottle root (WIE_ROOT / --root): writes C:\App\n2_out.txt on host.
 *
 * Exit codes:
 *   0 — ok
 *   1 — CreateFile failed
 *   2 — WriteFile failed / short write
 *   3 — CloseHandle failed
 *
 * Docs: CreateFileA, WriteFile, CloseHandle (Microsoft Learn). Clean room.
 */

#include <windows.h>

void entry(void) {
    HANDLE h;
    DWORD written = 0;
    const char data[] = "WIE_N2";

    h = CreateFileA(
        "C:\\App\\n2_out.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    if (!WriteFile(h, data, 6, &written, NULL) || written != 6) {
        CloseHandle(h);
        ExitProcess(2);
    }

    if (!CloseHandle(h)) {
        ExitProcess(3);
    }

    ExitProcess(0);
}
