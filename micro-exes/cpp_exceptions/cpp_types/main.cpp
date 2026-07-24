// C++ exception: multiple catch blocks with specific types.
// Exits 0 if each catch executes successfully.
// Compile: x86_64-w64-mingw32-g++ -o out/cpp_types.exe main.cpp -static -O2

extern "C" void __stdcall ExitProcess(unsigned code);

static volatile int g_result = 1;

int main() {
    // Test 1: throw int, catch by int
    g_result = 1;
    try {
        throw 1;
    } catch (int val) {
        g_result = val - 1;  // 1 - 1 = 0 → success
    }
    if (g_result != 0) ExitProcess(1);

    // Test 2: throw double, catch by double
    g_result = 1;
    try {
        throw 3.14;
    } catch (double val) {
        g_result = 0;  // caught by type → success
    }
    if (g_result != 0) ExitProcess(2);

    ExitProcess(0);
    return 0;
}
