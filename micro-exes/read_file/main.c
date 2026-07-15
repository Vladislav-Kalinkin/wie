/*
 * Micro-PE N2: CreateFile(OPEN_EXISTING) + ReadFile + CloseHandle.
 *
 * Requires bottle with host file drive_c/App/n2_in.txt containing "hello-n2".
 *
 * Exit codes:
 *   0 — ok
 *   1 — CreateFile failed
 *   2 — ReadFile failed
 *   3 — content mismatch
 *   4 — CloseHandle failed
 *
 * Docs: CreateFileA, ReadFile, CloseHandle (Microsoft Learn). Clean room.
 */

#include <windows.h>

void entry(void) {
    HANDLE h;
    DWORD got = 0;
    char buf[16];
    unsigned i;

    h = CreateFileA(
        "C:\\App\\n2_in.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = 0;
    }

    if (!ReadFile(h, buf, 8, &got, NULL) || got != 8) {
        CloseHandle(h);
        ExitProcess(2);
    }

    /* "hello-n2" */
    if (buf[0] != 'h' || buf[1] != 'e' || buf[2] != 'l' || buf[3] != 'l' || buf[4] != 'o'
        || buf[5] != '-' || buf[6] != 'n' || buf[7] != '2') {
        CloseHandle(h);
        ExitProcess(3);
    }

    if (!CloseHandle(h)) {
        ExitProcess(4);
    }

    ExitProcess(0);
}
