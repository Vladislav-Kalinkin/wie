# WIE

**WIE** (_Wie Is Emulator_) — experimental **PE64 userspace emulator** in Rust.

**Product:** generic PE64 userspace. Prove WinAPI with **micro-PE64s** + Microsoft docs.
Lunar Magic open-rom is optional integration stress, not the design driver.
See [`docs/PIVOT.md`](docs/PIVOT.md).

**Universal PE64** — no per-EXE cheats. x86-64 only (no 32-bit).

Now the code has more than a hundred legacy winapi plugs, which will be gradually replaced

## CPU backends

| Backend                  | Env                         | Notes                      |
| ------------------------ | --------------------------- | -------------------------- |
| **Cranelift hybrid JIT** | `WIE_CPU=jit` (**default**) | Hot blocks + iced fallback |
| iced-x86 interpreter     | `WIE_CPU=iced`              | Full interpreter path      |

## CLI

```bash
cargo build -p wie-cli --release
./target/release/wie-cli --help
```

| Command                                      | Role                           |
| -------------------------------------------- | ------------------------------ |
| `inspect` / `sections` / `imports` / `image` | PE inspection                  |
| `winapi-map`                                 | Import coverage map            |
| `run-micro`                                  | **Primary** gate (ExitProcess) |
| `run`                                        | Run until yield / exit         |
| `entry-trace`                                | First N host API stops         |

## Quick start

```bash
./target/release/wie-cli run-micro micro-exes/out/heap_alloc.exe
./target/release/wie-cli run-micro micro-exes/out/crt_hello.exe --max-api 8000
```

## Installation & Prerequisites

To build the emulator and compile the test micro-executables on Apple Silicon Mac, you need to install the Rust toolchain and an x86_64 cross-compiler.

### 1. Install System Dependencies

Use [Homebrew](https://brew.sh) to install the required cross-compiler:

```bash
brew install mingw-w64
```

### 2. Clone and Build WIE

Clone the repository and build the CLI tool in release mode:

```bash
git clone https://github.com/Vladislav-Kalinkin/wie
cd wie
cargo build -p wie-cli --release
```

### 3. Compile Test Binaries

Build the local x86_64 PE samples using the installed MinGW compiler:

```bash
make -C micro-exes
```
