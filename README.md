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
make -C micro-exes                    # needs x86_64-w64-mingw32-gcc
./target/release/wie-cli run-micro micro-exes/out/heap_alloc.exe
./target/release/wie-cli run-micro micro-exes/out/crt_hello.exe --max-api 8000
```
