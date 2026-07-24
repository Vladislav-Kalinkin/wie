/*
 * DLL with simple math functions for refcount/multi_dll tests.
 *
 * Compiled as: x86_64-w64-mingw32-gcc -shared -o dll_math_funcs.dll dll.c
 */

#include <windows.h>

__declspec(dllexport) int add(int a, int b) {
    return a + b;
}

__declspec(dllexport) int multiply(int a, int b) {
    return a * b;
}

__declspec(dllexport) int get_value(void) {
    return 42;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}
