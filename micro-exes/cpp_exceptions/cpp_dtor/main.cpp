// C++ exception: destructor called during stack unwinding.
// Exits 0 if both destructors run during unwind.
// Compile: x86_64-w64-mingw32-g++ -o out/cpp_dtor.exe main.cpp -static

extern "C" void __stdcall ExitProcess(unsigned code);

static volatile int g_tracker = 0;
static volatile int g_result = 1;

struct Guard {
    int id;
    Guard(int i) : id(i) { g_tracker |= (1 << id); }
    ~Guard() { g_tracker &= ~(1 << id); }
};

void thrower() {
    Guard g(1);
    g_tracker |= 0x100;  // pre-throw marker (bit 8)
    throw "error";
}

int main() {
    try {
        Guard g(0);
        thrower();
        g_tracker = 99;  // unreachable
    } catch (const char* msg) {
        // g(0) and g(1) should be destroyed before we get here.
        // After both destructors: bit 0 and bit 1 cleared,
        // bit 8 still set.  Expected g_tracker = 0x100 = 256.
        if (g_tracker == 0x100) {
            g_result = 0;  // success
        }
    }
    ExitProcess(g_result);
    return 0;
}
