/*
 * Ordinary Win64 console program with the C runtime.
 *
 * Written as a normal Windows app (not freestanding, not WIE-shaped).
 * Link with the usual mingw CRT; entry is CRT → main → return.
 *
 * Exit: process exit code 0 on success.
 */

#include <stdio.h>
#include <string.h>

int main(void) {
    const char *msg = "hello from crt\n";
    size_t n = strlen(msg);

    if (fwrite(msg, 1, n, stdout) != n) {
        return 1;
    }
    if (fflush(stdout) != 0) {
        return 2;
    }
    return 0;
}
