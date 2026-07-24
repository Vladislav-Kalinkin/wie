// C++ exception: destructor called during stack unwinding.
// Compile: x86_64-w64-mingw32-g++ -o out/cpp_dtor.exe main.cpp -static

extern "C" void __stdcall ExitProcess(unsigned code);

static volatile int g_tracker = 0;

struct Guard {
    int id;
    Guard(int i) : id(i) { g_tracker |= (1 << id); }
    ~Guard() { g_tracker &= ~(1 << id); }
};

void thrower() {
    Guard g(1);
    g_tracker |= 0x100;  // pre-throw marker
    throw "error";
}

int main() {
    try {
        Guard g(0);
        thrower();
        g_tracker = 99;  // unreachable
    } catch (const char* msg) {
        // g(0) and g(1) should be destroyed before we get here.
        // After both destructors: g_tracker should be 0x100 | 0 = 0x100.
    }
    // g_tracker: bit 0 cleared (Guard(0) dtor), bit 1 cleared (Guard(1) dtor),
    // bit 8 still set (pre-throw marker).  Expected: 0x100.
    ExitProcess(g_tracker);
    return 0;
}
