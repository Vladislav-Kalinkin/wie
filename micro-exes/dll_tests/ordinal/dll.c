/*
 * DLL with ordinal-only exports.
 *
 * Exports two functions at ordinals 1 and 2.
 * Compiled as: x86_64-w64-mingw32-gcc -shared -o dll_ordinal_funcs.dll dll.c \
 *   -Wl,--output-def,dll_ordinal_funcs.def \
 *   -Wl,--kill-at
 */

#include <windows.h>

__declspec(dllexport) int get_one(void) {
    return 1;
}

__declspec(dllexport) int get_two(void) {
    return 2;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}
