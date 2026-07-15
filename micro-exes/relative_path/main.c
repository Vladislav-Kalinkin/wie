/*
 * Micro-PE: relative path CreateFile/WriteFile against process CWD.
 *
 * Default session CWD is C:\App. Creates .\\n2_rel_out.txt → C:\App\n2_rel_out.txt
 * on the bottle host.
 *
 * Exit codes:
 *   0 — ok
 *   1 — CreateFile(.\\…) failed
 *   2 — WriteFile failed
 *   3 — CloseHandle failed
 *
 * Docs: CreateFile relative paths use the current directory (Microsoft Learn).
 * Clean room.
 */

#include <windows.h>

void entry(void) {
    HANDLE h;
    DWORD written = 0;
    const char data[] = "REL_OK";

    h = CreateFileA(
        ".\\n2_rel_out.txt",
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
