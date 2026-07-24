// C++ exception: multiple catch blocks (int, const char*, ...).
// Compile: x86_64-w64-mingw32-g++ -o out/cpp_multi_catch.exe main.cpp -static

extern "C" void __stdcall ExitProcess(unsigned code);

enum { RESULT_INT = 10, RESULT_STR = 20, RESULT_ANY = 30, RESULT_NONE = 99 };

int test_int() {
    try { throw 42; }
    catch (const char*) { return RESULT_STR; }
    catch (int)         { return RESULT_INT; }
    catch (...)         { return RESULT_ANY; }
    return RESULT_NONE;
}

int test_catchall() {
    try { throw 3.14; }
    catch (int)         { return RESULT_INT; }
    catch (const char*) { return RESULT_STR; }
    catch (...)         { return RESULT_ANY; }
    return RESULT_NONE;
}

int test_nothrow() {
    try { /* no throw */ }
    catch (...)         { return RESULT_ANY; }
    return 0;
}

int main() {
    int r = test_int();
    if (r != RESULT_INT) ExitProcess(r);

    r = test_catchall();
    if (r != RESULT_ANY) ExitProcess(r);

    r = test_nothrow();
    ExitProcess(r);
    return 0;
}
