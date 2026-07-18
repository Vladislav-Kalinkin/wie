# WIE (_Wie Is Emulator_) - experimental userspace emulator prototype in Rust 1.97

[![Project status](https://img.shields.io/badge/status-experimental-orange?style=flat-square)](https://github.com/Vladislav-Kalinkin/wie)
[![License](https://img.shields.io/github/license/Vladislav-Kalinkin/wie?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.97+-blue?style=flat-square)](https://www.rust-lang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/Vladislav-Kalinkin/wie/ci.yml?style=flat-square)](https://github.com/Vladislav-Kalinkin/wie/actions)
[![GitHub stars](https://img.shields.io/github/stars/Vladislav-Kalinkin/wie?style=social)](https://github.com/Vladislav-Kalinkin/wie)

> [!WARNING]
> **Work In Progress (WIP):** This is an early-stage experimental prototype.
>
> WIE is a research engine for freestanding and CRT micro-PEs. It is **not** a general Windows app runner yet. Pure guest compute (e.g. `long_loop`) will pin a core near 100% by design — that is useful work in the JIT, not a hang. However, when waiting for user input (as seen in the interactive `cli_args` test), the engine does not waste resources and drops host CPU usage down to ~1%.

**Idea** — Emulate custom **64-bit Windows** user-mode binaries on **macOS Apple Silicon**.

**Not goals** — 32-bit apps; full historical Windows compatibility. Focus is Windows 10-era PE64 + the APIs real tools actually call.

The WinAPI surface is intentionally incomplete: many handlers are stubs sufficient for the micro-suite and engine bring-up, not a final product surface.

## Examples of launch

```bash
time ./target/release/wie-cli run-micro micro-exes/out/crt_hello.exe
# hello from crt
# run_micro: ok exit=0

time ./target/release/wie-cli run-micro micro-exes/out/winapi_heap.exe
# HeapAlloc / HeapSize / HeapReAlloc / HeapFree / double-free / size-0 paths
# run_micro: ok exit=0

time WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run-micro micro-exes/out/long_loop.exe
# ~100M loop iterations under Cranelift JIT; expect ~1.3–1.5s wall, ~100% CPU

time WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run-micro micro-exes/out/cli_args.exe -- -n 3 -m hi -i
# First interactive input test with flags
```

```bash
# Full clean-room gate
make -C micro-exes && ./scripts/run-micro-suite.sh
```

## Core Components

| Crate             | Role                                                                                                                                                                                          |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`wie-cpu`**     | CPU backends: **`JitCpu`** (default) — Cranelift x86-64→ARM64 block JIT + iced fallback; **`IcedCpu`** — pure iced-x86 interpreter (`WIE_CPU=iced`).                                          |
| **`wie-winapi`**  | KERNEL32 / UCRT / USER32 / GDI32 / … handlers. Dispatch is a dense `WinApiId` table (no string compares on the hot path). Guest heap: 24 size classes + bump + optional shared control block. |
| **`wie-runtime`** | Session: PE load, guest memory layout, fake-API hooks, guest accelerators (stubs / heap / I/O / MBWC), run loop, TEB last-error publish, bottles (`WIE_ROOT`).                                |
| **`wie-pe`**      | PE64 parse, section map, import/IAT patch with fake VAs.                                                                                                                                      |
| **`wie-cli`**     | `inspect` / `run-micro` / `run` / `entry-trace` / `winapi-map`.                                                                                                                               |

## Execution Flow

1. **PE loading** — `wie-pe` maps the image and rewrites every IAT slot to a **fake API VA** in a reserved range (e.g. `0x7000_0000_0000_xxxx`).

2. **Hooks + guest stubs** — A **stop bitmap** covers the fake range. Ultra-hot APIs (`GetLastError`, `SetLastError`, critical sections, …) get small **in-guest stubs** so they never host-stop. Optional accelerators rewire IAT entries to real guest machine code (`WIE_GUEST_HEAP`, `WIE_GUEST_IO`, `WIE_GUEST_MBWC`).

3. **Run** — Control starts at the PE entry. `JitCpu` decodes lowerable basic blocks (GPR, simple mem, jcc/jmp/call/ret, common SSE2). Hot pure blocks compile to ARM64 and are cached; complex/cold code falls back to iced.

4. **API stop** — Hitting a stop-bit fake VA returns to `RuntimeSession`, which resolves `WinApiId` and runs the handler. Handlers use Win64 register ABI and `return_from_win64_api`.

5. **Fast paths** — JIT can lower hot UCRT imports (`malloc`, `free`, `memcpy`, `strlen`, `fwrite`, `fflush`, `__acrt_iob_func`) as direct host calls. Block chaining + a shadow return stack keep control in native code across calls/rets/self-loops.

6. **Host resources** — Bottles map `C:\…` → `{root}/drive_c/…`. Files, fake HWNDs, and a minimal message path live on the host.

## JIT Compilation Details

- **Granularity**: blocks up to **64** instructions; fallthrough-only fragments need ≥ **8** insns to justify compile tax. Blocks ending in **jcc/jmp/call/ret** or string ops compile from **1** insn (tight loops must not stay on iced).
- **Hotness**: compile after **100** visits (tests: 0; UCRT call sites: 2).
- **Chaining**: self-loops become IR back-edges; open-addressing chain table + shadow stack for call/ret.
- **Memory**: 4-level radix page table + multi-way TLB + sticky hot page for JIT load/store helpers.
- **SSE2**: common XMM moves / bitwise / scalar+packed FP; pure GPR blocks **skip full XMM bank sync** on block entry/exit (CPU win).
- **Fallback**: anything not lowerable → iced `step`.

## Memory & Heap

- Guest pages: `HashMap` ownership + radix walk for JIT O(1) page base.
- Process heap: segregated freelists (**24** size classes, up to 64 KiB) + bump for virgin space; 8-byte size header before each payload.
- Host `GuestHeap` and optional in-guest `HeapAlloc`/`HeapFree` share a control block (bump + freelist heads). Default path is **host freelist** (`WIE_GUEST_HEAP=1` enables full guest rewire).
- `HeapFree` of a live block → TRUE; **double-free / unknown** → FALSE + `ERROR_INVALID_HANDLE` (6). `HeapAlloc(..., 0)` returns a valid freeable pointer; `HeapReAlloc(..., 0)` frees and returns NULL. `HEAP_ZERO_MEMORY` zeros the payload.

## Environment knobs

| Variable                | Effect                                                    |
| ----------------------- | --------------------------------------------------------- |
| `WIE_CPU=jit` \| `iced` | CPU backend (default **jit**)                             |
| `WIE_RUNTIME_PROFILE=1` | Wall/CPU%, host stops, JIT load/store counts, mem backend |
| `WIE_API_JOURNAL=path`  | Per-API journal for backend A/B diffs                     |
| `WIE_ROOT` / `--root`   | Bottle root for file APIs                                 |
| `WIE_GUEST_HEAP=1`      | Rewire process-heap `HeapAlloc`/`HeapFree` to guest code  |
| `WIE_GUEST_IO=…`        | Guest I/O accelerator policy                              |
| `WIE_GUEST_MBWC=1`      | Guest MultiByte↔WideChar helpers                          |
| `RUST_LOG`              | tracing filter                                            |

## CLI

```bash
./target/release/wie-cli --help
```

| Command                                      | Role                                                                                           |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `inspect` / `sections` / `imports` / `image` | PE inspection                                                                                  |
| `winapi-map`                                 | Import coverage map                                                                            |
| `run-micro`                                  | **Primary** gate (must reach `ExitProcess` with code 0)                                        |
| `run-micro … --stdin FILE -- args…`          | Inject console stdin + guest argv (`GetCommandLineA`, `ReadFile` on STD_INPUT)                 |
| `run-micro … -- args…` (no `--stdin`)        | Live host stdin on guest `ReadFile(STD_INPUT)` (line-oriented; blocks until Enter / pipe data) |
| `run`                                        | Run until yield / exit                                                                         |
| `entry-trace`                                | First N host API stops                                                                         |

## Performance notes (CPU / wall)

Phase 0 baselines (wall/CPU%, host stops, JIT load/store): see [`docs/phase0-baseline.md`](docs/phase0-baseline.md). Optimisation plan: [`Optimization ROADMAP.md`](Optimization%20ROADMAP.md).

What actually burns CPU today:

1. **Tight guest loops** — expected ~100% core use under JIT; iced is orders of magnitude slower and may hit slice budgets (`long_loop`).
2. **Per-memory JIT helpers** — stack/heap loads still go through TLB helpers; reducing mem ops in guest code helps more than micro-tweaking iced.
3. **Host API stops** — every non-stub import pays a stop; guest stubs / UCRT fast path / heap freelist exist to cut this.
4. **Block entry/exit** — GPR sync is mandatory; XMM sync is skipped for pure GPR blocks.
5. **Cold compile tax** — hotness threshold avoids compiling one-shot code; raise only if you measure thrashing.

Further wins worth pursuing: more in-guest stubs for remaining hot KERNEL32/UCRT exports; denser stop/API lookup; optional stack-relative mem inlining in the lowerer; lower hotness for proven self-loops after first decode.

## Installation & Prerequisites

Apple Silicon Mac: Rust toolchain + MinGW for micro-exes.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
brew install mingw-w64

git clone https://github.com/Vladislav-Kalinkin/wie
cd wie
cargo build -p wie-cli --release

make -C micro-exes
./scripts/run-micro-suite.sh
```

## History

Early work targeted an alternate way to run FuSoYa's Lunar Magic and used Unicorn Engine. After full init sequences proved feasible, Unicorn-specific paths were removed in favour of iced-x86 + Cranelift. Pre-removal Lunar-specific runs were already ~2s faster than Unicorn on the same workload.

## AI-Usage

This project uses code generated by artificial intelligence for implementation, tests, and architecture drafts. The author researches, reviews, runs tests, watches clippy/`unsafe` boundaries, and steers the product direction. Generated code is not accepted without human verification.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

### Pre-PR Checklist

1. **Format:** `cargo fmt --check`
2. **Lint:** `cargo clippy --all-targets -- -D warnings`
3. **Unit tests:** `cargo test`
4. **Integration:** `make -C micro-exes && ./scripts/run-micro-suite.sh`

## Acknowledgments

- [@DevYatsu](https://github.com/DevYatsu) — performance optimizations

## License

**GNU Lesser General Public License v3.0 (LGPL-3.0)** — see [LICENSE.txt](LICENSE.txt).
