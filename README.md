# WIE (_Wie Is Emulator_) - experimental userspace emulator prototype in Rust 1.97

> [!WARNING]
> **Work In Progress (WIP):** This is an early-stage experimental prototype.

**Idea** - Create an emulator to run custom 64-bit windows applications on MacOS Apple Silicon

**Not goals** - Running 32-bit applications, creating a universal emulator of the entire windows history. Only Windows 10 and applications running on it of older versions of the OS

At the moment, the project has more than a hundred different plugs made only to build the emulator engine and are not the final solution

### Core Components

- **`wie-cpu`** – the CPU core. Provides two backends:
  - **`JitCpu`** (default) – compiles x86‑64 basic blocks into ARM64 machine code via **Cranelift**. Compiled blocks are cached and can be chained directly without returning to the dispatcher.
  - **`IcedCpu`** – an interpreter based on **iced‑x86**, used as fallback for complex instructions or when the JIT is disabled.

- **`wie-winapi`** – emulation of Windows system calls. Contains dozens of handlers for KERNEL32, USER32, GDI32, ADVAPI32, COMCTL32, and other DLLs. API dispatch uses a dense integer‑based table (no string comparisons on the hot path).

- **`wie-runtime`** – manages the execution session: loads the PE, sets up guest memory, installs hooks on fake API addresses, drives the run loop, and maintains the overall state (registers, heap, windows, message queue, etc.).

- **`wie-pe`** – PE64 parsing, section loading, import table processing, and IAT patching with fake addresses.

### Execution Flow

1. **PE Loading**  
   `wie-pe` reads the file, builds the in‑memory image at virtual addresses, and parses the import table. Every imported function gets a **fake address** in a reserved region (e.g., `0x7000_0000_0000_xxxx`). These addresses are written into the IAT.

2. **Hook Installation**  
   The entire fake‑address range is covered by a **stop bitmap** (bit = 1 means “stop and hand over to the host handler”). For frequently called functions (e.g., `GetLastError`, `EnterCriticalSection`), **guest stubs** (small pieces of machine code) are placed directly in that range, so calls execute entirely in‑guest without stopping.

3. **Execution Start**  
   Control is transferred to the PE’s entry point. `JitCpu` starts decoding basic blocks from the current `RIP`. If a block is “pure” (only GPR ops, simple memory accesses, ALU, branches), it is compiled to ARM64 and executed. If the block is complex (SSE, system instructions) or cold, it is interpreted by `IcedCpu`.

4. **System Call Interception**  
   When execution reaches a fake address (i.e., a call to an imported function), the stop‑bit triggers. `JitCpu` or `IcedCpu` returns control to `RuntimeSession`. The session identifies which API was called and invokes the corresponding handler from `wie-winapi`. The handler reads arguments from guest registers/stack, performs emulation (often modifying state), and then calls `return_from_win64_api`, which restores `RIP` and `RSP` as if the call returned normally.

5. **In‑Guest Accelerators**  
   For the hottest APIs (e.g., `malloc`, `memcpy`, `ReadFile`, `HeapAlloc`), actual machine‑code stubs are placed in guest memory and their addresses are written into the IAT instead of the fake ones, with the corresponding stop‑bits cleared. This way, calls to these functions never leave the guest context, drastically reducing overhead. Implemented in modules `guest_stubs`, `guest_io`, `guest_heap`, and `guest_mbwc`.

6. **Block Chaining and Shadow Stack**  
   Compiled blocks can call each other directly, bypassing the dispatcher. For `call` instructions, a shadow return stack is maintained to improve prediction and speed up `ret` handling.

7. **Host System Interaction**  
   File system emulation (via “bottles” – root directories mapped to `C:\`) and windowing (fake HWNDs, message queuing) are implemented on the host. For example, `CreateFile` opens a file under `WIE_ROOT/drive_c`, while window messages are queued and dispatched through guest WndProc callbacks.

### JIT Compilation Details

- **Granularity**: only basic blocks (up to 32 instructions) ending in a branch, call, or return are compiled.
- **Hotness**: a block is compiled after 100 visits (or immediately for UCRT calls). Compiled blocks are cached in a `HashMap`.
- **SSE2 Support**: common XMM operations (mov, xor, add/sub/mul/div scalar/packed) are compiled; everything else goes to the interpreter.
- **Fast UCRT Imports**: calls to `malloc`, `free`, `memcpy`, `strlen`, `fwrite`, `fflush`, and `__acrt_iob_func` are compiled as direct host‑function calls, bypassing stops.

### Memory Management

- Guest memory is a `HashMap<page_key, Page>` backed by a 4‑level radix table for fast page lookups from JIT code.
- Heaps are emulated using segregated free‑lists (24 size classes) plus a bump allocator. The guest and host heap structures are synchronised via a shared control block in guest memory, allowing the `HeapAlloc/HeapFree` accelerators to run without host stops.

### Profiling and Debugging

- Set `WIE_RUNTIME_PROFILE=1` to collect timing statistics (emulation, handlers, resolution) and call counts per API.
- `WIE_API_JOURNAL=path` writes a log of every API call with register state, useful for comparing backends.

## CLI

```bash
./target/release/wie-cli --help
```

| Command                                      | Role                           |
| -------------------------------------------- | ------------------------------ |
| `inspect` / `sections` / `imports` / `image` | PE inspection                  |
| `winapi-map`                                 | Import coverage map            |
| `run-micro`                                  | **Primary** gate (ExitProcess) |
| `run`                                        | Run until yield / exit         |
| `entry-trace`                                | First N host API stops         |

## Installation & Prerequisites

To build the emulator and compile the test micro-executables on Apple Silicon Mac, you need to install the Rust toolchain and an x86_64 cross-compiler.

### 1. Install System Dependencies

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 2. Verify Rust
rustc --version
cargo --version

# 3. Install cross-compiler for micro-exes
brew install mingw-w64
```

### 2. Clone and Build WIE

Clone the repository and build the CLI tool in release mode:

```bash
git clone https://github.com/Vladislav-Kalinkin/wie
cd wie
cargo build -p wie-cli --release
```

### 3. Compile Test Binaries and Run

Build the local x86_64 PE samples using the installed MinGW compiler and run demo exes:

```bash
make -C micro-exes
./scripts/run-micro-suite.sh

# If you want to see advanced logs
RUST_LOG=info ./scripts/run-micro-suite.sh
```

### History

At the early stage of building the engine, the project began as an experiment to create an alternative way to launch FuSoYa's Lunar Magic.

The project had many workarounds for its launch and originally used Unicorn Engine. It was possible to achieve the entire initialization sequence, but later it was decided to delete the data associated with it and start creating its own engine based on iced-x86 and Cranelift.

In one of the tests before removing Lunar Specific elements, it was possible to accelerate the launch by almost 2 seconds compared to Unicorn Engine.

The engine is currently in a raw state. It can execute the bundled probe EXEs, but CPU consumption is extremely high (exceeding 90%). At this early stage of running ultra-small executable files, initial optimization attempts have not yet yielded positive results, and the engine lacks proper optimization passes.

## AI-Usage

This project uses code generated by artificial intelligence. It was used to write the main code, tests and implement architectural solutions. I (Author) - searched for information, monitored the purity of the code and clippy, run tests manually, checked the code and monitored the limitations of unsafe code, formed the idea of the project, changing the development angle and changing the engine was my decision.

I understand that the use of the generated code entails more problems and possible bugs and I also hate it when the developer does not monitor the state of the code, does not manually check the tests and shifts all tasks to the AI agent, hoping 'Maybe lucky'.

And also this section is not about boasting or a proclamation of AI power. I consider it a tool that with strict supervision, manual checks and author's decisions that can speed up the work and help the developer

## Contributing

If you find problems, vulnerabilities or optimization solutions that I have not noticed, I will be glad if you let me know.

## License

This project is licensed under the **GNU Lesser General Public License v3.0 (LGPL-3.0)**.
