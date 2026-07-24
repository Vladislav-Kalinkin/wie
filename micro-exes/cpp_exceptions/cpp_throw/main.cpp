// Minimal C++ exception test: throw int, catch by type.
// Compile: x86_64-w64-mingw32-g++ -o out/cpp_throw.exe main.cpp -static

extern "C" void __stdcall ExitProcess(unsigned code);

static volatile int g_state = 0;

int main() {
    g_state = 1;
    try {
        g_state = 2;
        throw 42;
        g_state = 99; // unreachable
    } catch (int val) {
        g_state -= val - 40;
    }
    ExitProcess(g_state);
    return 0;
}
