/*
 * Micro-PE: final VFS round-trip before real binaries (7z).
 *
 * Host layout (wie-cli --root bottle --drive-d host_dir):
 *   D:\…  → host_dir (e.g. ~/Downloads or a test temp dir)
 *   C:\…  → bottle/drive_c
 *
 * Flow:
 *   1) Read  input  (default D:\vfs_in.txt)  — UTF-8 with EN/RU/CJK
 *   2) Write exact copy to bottle (default C:\App\vfs_copy.txt)
 *   3) Write modified payload back to host (default D:\vfs_out.txt)
 *      = original + stamp (ASCII marker + more EN/RU/CJK)
 *
 * Optional guest argv (after --):
 *   -i PATH   input guest path
 *   -c PATH   bottle copy path
 *   -o PATH   output guest path
 *
 * Exit codes:
 *   0 — ok
 *   1 — CreateFile input failed
 *   2 — GetFileSize / ReadFile failed
 *   3 — CreateFile / WriteFile bottle copy failed
 *   4 — CreateFile / WriteFile host output failed
 *   5 — CloseHandle failed
 *   6 — buffer too small / empty input
 *
 * Docs: CreateFileA, ReadFile, WriteFile, GetFileSize, CloseHandle,
 *       GetCommandLineA (Microsoft Learn). Clean room.
 */

#include <windows.h>

/* Keep stack small: freestanding PE has no ___chkstk_ms. */
#define BUF_CAP 2048
#define PATH_CAP 260

/* UTF-8 stamp appended after original bytes (hex-safe for freestanding). */
/* "\n---WIE_VFS---\nen:OK | ru:\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 | zh:\xe4\xbd\xa0\xe5\xa5\xbd | ja:\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\n" */
static const unsigned char k_stamp[] = {
    '\n', '-', '-', '-', 'W', 'I', 'E', '_', 'V', 'F', 'S', '-', '-', '-', '\n',
    'e', 'n', ':', 'O', 'K', ' ', '|', ' ',
    'r', 'u', ':',
    0xD0, 0x9F, 0xD1, 0x80, 0xD0, 0xB8, 0xD0, 0xB2, 0xD0, 0xB5, 0xD1, 0x82, /* Привет */
    ' ', '|', ' ',
    'z', 'h', ':',
    0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD, /* 你好 */
    ' ', '|', ' ',
    'j', 'a', ':',
    0xE6, 0x97, 0xA5, 0xE6, 0x9C, 0xAC, 0xE8, 0xAA, 0x9E, /* 日本語 */
    '\n'};

static int str_eq(const char *a, const char *b) {
    unsigned i = 0;
    if (!a || !b) {
        return 0;
    }
    for (;;) {
        if (a[i] != b[i]) {
            return 0;
        }
        if (a[i] == 0) {
            return 1;
        }
        i++;
    }
}

static void str_copy(char *dst, unsigned dst_cap, const char *src) {
    unsigned i = 0;
    if (!dst || dst_cap == 0) {
        return;
    }
    if (!src) {
        dst[0] = 0;
        return;
    }
    while (src[i] != 0 && i + 1 < dst_cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

/* Skip leading spaces/tabs. */
static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return p;
}

/* Next argv-ish token → out. Advances *pp. Returns 1 if a token was copied. */
static int next_token(const char **pp, char *out, unsigned out_cap) {
    const char *p;
    unsigned i = 0;
    int in_quote = 0;

    if (!pp || !*pp || !out || out_cap == 0) {
        return 0;
    }
    p = skip_ws(*pp);
    if (*p == 0) {
        *pp = p;
        return 0;
    }

    while (*p != 0) {
        char c = *p;
        if (in_quote) {
            if (c == '"') {
                in_quote = 0;
                p++;
                continue;
            }
            if (i + 1 < out_cap) {
                out[i++] = c;
            }
            p++;
            continue;
        }
        if (c == '"') {
            in_quote = 1;
            p++;
            continue;
        }
        if (c == ' ' || c == '\t') {
            break;
        }
        if (i + 1 < out_cap) {
            out[i++] = c;
        }
        p++;
    }
    out[i] = 0;
    *pp = p;
    return 1;
}

/*
 * Parse GetCommandLineA: skip argv0, then look for -i/-c/-o and their values.
 * Defaults applied when a flag is absent.
 */
static void parse_paths(const char *cmdline, char *in_path, char *copy_path, char *out_path) {
    const char *p;
    char tok[PATH_CAP];
    int saw_exe = 0;

    str_copy(in_path, PATH_CAP, "D:\\vfs_in.txt");
    str_copy(copy_path, PATH_CAP, "C:\\App\\vfs_copy.txt");
    str_copy(out_path, PATH_CAP, "D:\\vfs_out.txt");

    if (!cmdline) {
        return;
    }
    p = cmdline;
    while (next_token(&p, tok, sizeof(tok))) {
        if (!saw_exe) {
            saw_exe = 1;
            continue;
        }
        if (str_eq(tok, "-i")) {
            if (next_token(&p, tok, sizeof(tok))) {
                str_copy(in_path, PATH_CAP, tok);
            }
        } else if (str_eq(tok, "-c")) {
            if (next_token(&p, tok, sizeof(tok))) {
                str_copy(copy_path, PATH_CAP, tok);
            }
        } else if (str_eq(tok, "-o")) {
            if (next_token(&p, tok, sizeof(tok))) {
                str_copy(out_path, PATH_CAP, tok);
            }
        }
    }
}

static int write_all(HANDLE h, const void *data, DWORD len) {
    DWORD written = 0;
    DWORD off = 0;
    const char *p = (const char *)data;

    while (off < len) {
        if (!WriteFile(h, p + off, len - off, &written, NULL) || written == 0) {
            return 0;
        }
        off += written;
    }
    return 1;
}

void entry(void) {
    char in_path[PATH_CAP];
    char copy_path[PATH_CAP];
    char out_path[PATH_CAP];
    unsigned char buf[BUF_CAP];
    HANDLE hin = INVALID_HANDLE_VALUE;
    HANDLE hcopy = INVALID_HANDLE_VALUE;
    HANDLE hout = INVALID_HANDLE_VALUE;
    DWORD size_lo;
    DWORD size_hi = 0;
    DWORD got = 0;
    DWORD i;
    const char *cmdline;

    cmdline = GetCommandLineA();
    parse_paths(cmdline, in_path, copy_path, out_path);

    /* --- 1) Read host/D: input --- */
    hin = CreateFileA(
        in_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hin == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    size_lo = GetFileSize(hin, &size_hi);
    /* INVALID_FILE_SIZE / >4GiB / empty / too large for stack buffer. */
    if (size_hi != 0 || size_lo == 0 || size_lo == INVALID_FILE_SIZE
        || size_lo > BUF_CAP) {
        CloseHandle(hin);
        ExitProcess(6);
    }

    for (i = 0; i < BUF_CAP; i++) {
        buf[i] = 0;
    }

    if (!ReadFile(hin, buf, size_lo, &got, NULL) || got != size_lo) {
        CloseHandle(hin);
        ExitProcess(2);
    }
    if (!CloseHandle(hin)) {
        ExitProcess(5);
    }
    hin = INVALID_HANDLE_VALUE;

    /* --- 2) Exact copy into bottle C: --- */
    hcopy = CreateFileA(
        copy_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hcopy == INVALID_HANDLE_VALUE) {
        ExitProcess(3);
    }
    if (!write_all(hcopy, buf, size_lo)) {
        CloseHandle(hcopy);
        ExitProcess(3);
    }
    if (!CloseHandle(hcopy)) {
        ExitProcess(5);
    }
    hcopy = INVALID_HANDLE_VALUE;

    /* --- 3) Modified payload back to host/D: original + stamp --- */
    hout = CreateFileA(
        out_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hout == INVALID_HANDLE_VALUE) {
        ExitProcess(4);
    }
    if (!write_all(hout, buf, size_lo)) {
        CloseHandle(hout);
        ExitProcess(4);
    }
    if (!write_all(hout, k_stamp, (DWORD)sizeof(k_stamp))) {
        CloseHandle(hout);
        ExitProcess(4);
    }
    if (!CloseHandle(hout)) {
        ExitProcess(5);
    }

    ExitProcess(0);
}
