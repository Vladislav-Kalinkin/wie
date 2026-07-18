# WIE (_Wie Is Emulator_) - experimental userspace emulator prototype in Rust 1.97

[![Project status](https://img.shields.io/badge/status-experimental-orange?style=flat-square)](https://github.com/Vladislav-Kalinkin/wie)
[![License](https://img.shields.io/github/license/Vladislav-Kalinkin/wie?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.97+-blue?style=flat-square)](https://www.rust-lang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/Vladislav-Kalinkin/wie/ci.yml?style=flat-square)](https://github.com/Vladislav-Kalinkin/wie/actions)
[![GitHub stars](https://img.shields.io/github/stars/Vladislav-Kalinkin/wie?style=social)](https://github.com/Vladislav-Kalinkin/wie)

> [!WARNING]
> **Work In Progress (WIP):** This is an early-stage experimental prototype.
>
> WIE is a research engine for freestanding and CRT micro-PEs. It is **not** a general Windows app runner yet. Pure guest compute (e.g. `long_loop`) will pin a core near 100% by design — that is useful work in the JIT, not a hang. When the guest blocks on live console input (`cli_args` without `--stdin`), the host waits on I/O and CPU drops to ~1%.

**Idea** — Emulate custom **64-bit Windows** user-mode binaries on **macOS Apple Silicon**.

**Not goals** — 32-bit apps; full historical Windows compatibility; Wine-style identity mapping (`mmap(addr = guest_va)`). Focus is Windows 10-era PE64 + the APIs real tools actually call. Guest VA always soft-translates through region tables / radix / TLB.

The WinAPI surface is intentionally incomplete: many handlers are stubs sufficient for the micro-suite and engine bring-up, not a final product surface.

**Status (post Phases 0–5.5):** Hybrid memory (mmap arenas + sparse HashMap), software page permissions + `Virtual*`, Cranelift block JIT with stack super-path / sticky + set-assoc Neon TLB / SIMD SSE2 / bulk + inline strings, and an expanded in-guest stub set. Idle-park policy (Phase 6) and default flip to pure mmap (Phase 7) are still open — see [`Optimization ROADMAP.md`](Optimization%20ROADMAP.md).

## Examples of launch

```bash
# Build release CLI once
cargo build -p wie-cli --release

# Tiny freestanding PE
time ./target/release/wie-cli run-micro micro-exes/out/crt_hello.exe
# hello from crt
# run_micro: ok exit=0

# Heap API matrix
time ./target/release/wie-cli run-micro micro-exes/out/winapi_heap.exe
# HeapAlloc / HeapSize / HeapReAlloc / HeapFree / double-free / size-0 paths
# run_micro: ok exit=0

# ~100M stack-volatile loop under Cranelift JIT (block-wide super path)
time WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run-micro micro-exes/out/long_loop.exe
# expect ~0.28–0.32s wall, ~100% CPU, mem_backend=hybrid

# Interactive argv + live stdin (blocks on host Read until Enter / pipe data)
time WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run-micro micro-exes/out/cli_args.exe -- -n 3 -m hi -i

# Deterministic stdin (no TTY) — same as the suite uses
printf 'CLI_IN\n' | ./target/release/wie-cli run-micro micro-exes/out/cli_args.exe --stdin /dev/stdin -- -n 3 -m hi -i

# Bottle files (guest C:\… → {root}/drive_c/…)
BOTTLE=$(mktemp -d)
mkdir -p "$BOTTLE/drive_c/App"
./target/release/wie-cli run-micro micro-exes/out/write_file.exe --root "$BOTTLE"
```

```bash
# Full clean-room gate (builds micros + runs all PE gates under WIE_CPU=jit)
make -C micro-exes && ./scripts/run-micro-suite.sh

# Backend / JIT A/B
WIE_MEM=hash  ./scripts/run-micro-suite.sh
WIE_MEM=mmap  ./scripts/run-micro-suite.sh
WIE_CPU=iced  ./scripts/run-micro-suite.sh          # interpreter only (long_loop may hit slice limit)
WIE_JIT_MEM=slow ./scripts/run-micro-suite.sh       # helper-only loads/stores
WIE_JIT_MEM=pin  ./scripts/run-micro-suite.sh       # sticky + heap pin IR
WIE_JIT_CHAIN=0  ./scripts/run-micro-suite.sh
WIE_STRING_BULK=0 ./scripts/run-micro-suite.sh
```

## Core Components

| Crate             | Role                                                                                                                                                                                                                             |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`wie-cpu`**     | CPU + guest memory: **`JitCpu`** (default) — Cranelift x86-64→ARM64 block JIT + iced fallback; **`IcedCpu`** — pure iced-x86 (`WIE_CPU=iced`). Memory: hybrid/mmap/hash backends, RegionTable, PageMap/VAD/SPC, JIT TLB + pins.  |
| **`wie-winapi`**  | KERNEL32 / UCRT / USER32 / GDI32 / … handlers. Dense `WinApiId` dispatch (no string compares on the hot path). Guest heap: 24 size classes + bump + optional shared control block. Real `VirtualAlloc`/`Free`/`Protect`/`Query`. |
| **`wie-runtime`** | Session: PE load, layout regions, fake-API hooks, guest accelerators (stubs / heap / I/O / MBWC), run loop, TEB last-error, bottles (`WIE_ROOT`). Profile via `WIE_RUNTIME_PROFILE`.                                             |
| **`wie-pe`**      | PE64 parse, section map plan, import/IAT patch with fake VAs, COFF → `PAGE_*` protects.                                                                                                                                          |
| **`wie-cli`**     | `inspect` / `sections` / `imports` / `image` / `winapi-map` / `run-micro` / `run` / `entry-trace`.                                                                                                                               |

## Execution Flow

1. **PE loading** — `wie-pe` maps the image into one `MEM_IMAGE` arena (or HashMap pages under `WIE_MEM=hash`), rewrites every IAT slot to a **fake API VA** (e.g. `0x7000_0000_0000_xxxx`), then applies section protects from COFF characteristics (software permission checks always; optional host `mprotect` on arenas).

2. **Hooks + guest stubs** — A **stop bitmap** covers the fake range. Hot APIs (`GetLastError` / `SetLastError`, critical sections, PID/TID, cmdline, metrics/colors, …) get small **in-guest stubs** so they never host-stop. Optional accelerators rewire IAT entries to real guest machine code (`WIE_GUEST_HEAP`, `WIE_GUEST_IO`, `WIE_GUEST_MBWC`).

3. **Run** — Control starts at the PE entry. `JitCpu` decodes lowerable basic blocks (GPR, simple mem, jcc/jmp/call/ret, common SSE2, bulk REP MOVS/STOS). Hot pure blocks compile to ARM64 and are cached; complex/cold code falls back to iced.

4. **API stop** — Hitting a stop-bit fake VA returns to `RuntimeSession`, which resolves `WinApiId` and runs the handler. Handlers use Win64 register ABI and `return_from_win64_api`.

5. **Fast paths** — JIT can lower hot UCRT imports (`malloc`, `free`, `memcpy`, `strlen`, `fwrite`, `fflush`, `__acrt_iob_func`) as direct host calls. Block chaining + edge IC + a shadow return stack keep control in native code across calls/rets/self-loops. Stack-heavy pure loops use a **block-wide pin super path** (bare host load/store after one prologue guard).

6. **Host resources** — Bottles map `C:\…` → `{root}/drive_c/…`. Files, fake HWNDs, and a minimal message path live on the host. `VirtualAlloc` family goes through PageMap + VAD (soft translate only — no guest-VA `mmap`).

## JIT Compilation Details

- **Granularity**: blocks up to **64** instructions; fallthrough-only fragments need ≥ **8** insns to justify compile tax. Blocks ending in **jcc/jmp/call/ret** or string ops compile from **1** insn (tight loops must not stay on iced).
- **Hotness**: compile after **100** visits (tests: 0; pure self-loops: **16**; UCRT call sites: 2).
- **Chaining**: self-loops become IR back-edges; open-addressing chain table + monomorphic **edge IC** + shadow stack for call/ret. Kill-switch: `WIE_JIT_CHAIN=0`.
- **Memory lower** (`WIE_JIT_MEM`):
  - **`sticky` (default)** — sticky multi-way TLB with SPC R/W bits + `mem_gen`; **stack `MemPin`** + block-wide super path when all memops are same stack base + const disp.
  - **`pin`** — sticky + stack pin + **heap** region pin IR.
  - **`slow`** — helper-only `wie_jit_load` / `wie_jit_store` (oracle / bisect).
- **SSE2**: common XMM moves / bitwise / scalar+packed FP lowered with Cranelift SIMD (`I8X16`/`F32X4`/…) → host Neon when `WIE_JIT_SIMD≠0`; pure GPR blocks **skip XMM bank**; live/dirty masks selective sync.
- **TLB**: sticky page + **16×4 set-associative** multi-way (Neon tag compare on aarch64; `WIE_TLB_NEON=0` scalar).
- **Strings**: REP MOVS/STOS (DF=0) — inline unrolled `I8X16` for 16–64 B (`WIE_STRING_INLINE`), else soft-translated host spans (`WIE_STRING_BULK=0` disables bulk). Overlap / DF=1 stay element-loop.
- **Fallback**: anything not lowerable → iced `step`.

## Memory & Heap

- **Backends** (`WIE_MEM`): default **`hybrid`** (maps ≥ 64 KiB → anonymous arena; tiny pages HashMap); force `mmap` (all arenas) or `hash` (legacy sparse only). Soft translate only — guest VA ≠ host VA.
- **Layout**: `RegionTable` names stack / heap / image / fake API / TEB / stubs; arena-backed regions expose `host_base` for JIT pins.
- **Permissions**: software PageMap + VAD (Free / Reserved / Committed, `PAGE_*`); SPC on every read/write/fetch and JIT TLB install. Optional dual `mprotect` on arena frames (`WIE_MPROTECT`, default on) — never the sole oracle under 4K guest / 16K host clinch.
- **Dynamic mapping**: real `VirtualAlloc` / `VirtualFree` / `VirtualProtect` / `VirtualQuery` (64 KiB reserve granularity, 4 KiB commit).
- **Process heap**: segregated freelists (**24** size classes, up to 64 KiB) + bump for virgin space; 8-byte size header before each payload.
- Host `GuestHeap` and optional in-guest `HeapAlloc`/`HeapFree` share a control block. Default path is **host freelist** (`WIE_GUEST_HEAP=1` enables full guest rewire).
- `HeapFree` of a live block → TRUE; **double-free / unknown** → FALSE + `ERROR_INVALID_HANDLE` (6). `HeapAlloc(..., 0)` returns a valid freeable pointer; `HeapReAlloc(..., 0)` frees and returns NULL. `HEAP_ZERO_MEMORY` zeros the payload.

## Environment knobs

| Variable                                | Effect                                                                                                |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `WIE_CPU=jit` \| `iced`                 | CPU backend (default **jit**)                                                                         |
| `WIE_MEM=hybrid` \| `mmap` \| `hash`    | Guest storage (default **hybrid**) — see [`docs/phase2-mmap-backend.md`](docs/phase2-mmap-backend.md) |
| `WIE_MPROTECT=0`                        | Disable optional host `mprotect` dual-protection on arenas (SPC remains on)                           |
| `WIE_JIT_MEM=sticky` \| `pin` \| `slow` | JIT mem lower mode (default **sticky** = sticky TLB + stack pin)                                      |
| `WIE_JIT_CHAIN=0`                       | Disable FuncRef chaining / chain table / edge IC                                                      |
| `WIE_STRING_BULK=0`                     | Disable host-span bulk REP MOVS/STOS                                                                  |
| `WIE_STRING_INLINE=0`                   | Disable inline 16–64 B REP Neon path (Phase 5.5)                                                      |
| `WIE_JIT_SIMD=0`                        | Scalar lo/hi XMM lowering (no CLIF SIMD / Neon)                                                       |
| `WIE_TLB_NEON=0`                        | Scalar 4-way TLB tag scan (no Neon compare)                                                           |
| `WIE_JIT_OPT=speed\|speed_and_size\|none` | Cranelift opt_level (default **speed**)                                                             |
| `WIE_JIT_VERIFY=1`                      | Enable Cranelift IR verifier outside tests                                                            |
| `WIE_RUNTIME_PROFILE=1`                 | Wall/CPU%, host stops, JIT load/store counts, `mem_backend`                                           |
| `WIE_API_JOURNAL=path`                  | Per-API journal for backend A/B diffs                                                                 |
| `WIE_ROOT` / `--root`                   | Bottle root for file APIs                                                                             |
| `WIE_GUEST_HEAP=1`                      | Rewire process-heap `HeapAlloc`/`HeapFree` to guest code                                              |
| `WIE_GUEST_IO=0` \| `all`               | I/O accelerator: default seeks/size in-guest; `all` also guest Read (large → host); `0` = all host    |
| `WIE_GUEST_MBWC=1`                      | Guest MultiByte↔WideChar helpers                                                                      |
| `WIE_HOST_SLEEP=1`                      | `Sleep(n>0)` parks the host thread (default is non-blocking slice)                                    |
| `RUST_LOG`                              | tracing filter (CLI defaults to `warn`)                                                               |

## CLI

```bash
./target/release/wie-cli --help
./target/release/wie-cli run-micro --help
```

| Command                                      | Role                                                                      |
| -------------------------------------------- | ------------------------------------------------------------------------- |
| `inspect` / `sections` / `imports` / `image` | PE inspection                                                             |
| `winapi-map`                                 | Import coverage map (`--out path` optional)                               |
| `run-micro`                                  | **Primary** gate (must reach `ExitProcess` with expected code, default 0) |
| `run-micro … --max-api N`                    | Cap host API stops (default 256)                                          |
| `run-micro … --expect-code N`                | Expected `ExitProcess` code                                               |
| `run-micro … --root DIR`                     | Bottle root (`C:\…` → `{DIR}/drive_c/…`)                                  |
| `run-micro … --stdin FILE -- args…`          | Inject console stdin + guest argv                                         |
| `run-micro … -- args…` (no `--stdin`)        | Live host stdin on guest `ReadFile(STD_INPUT)`                            |
| `run`                                        | Run until yield / exit (`--max-api`, default 3400)                        |
| `entry-trace`                                | First N host API stops (`--max-api`, default 20)                          |

## Performance notes (CPU / wall)

Phases 0–5 landed; baselines and design notes:

| Doc                                                            | Topic                                   |
| -------------------------------------------------------------- | --------------------------------------- |
| [`docs/phase0-baseline.md`](docs/phase0-baseline.md)           | Wall/CPU%, host stops, JIT counters     |
| [`docs/phase2-mmap-backend.md`](docs/phase2-mmap-backend.md)   | Hybrid / mmap / hash storage            |
| [`docs/phase3-permissions.md`](docs/phase3-permissions.md)     | SPC, PageMap/VAD, `Virtual*`            |
| [`docs/phase4-foundation.md`](docs/phase4-foundation.md)       | Sticky TLB + kill-switches              |
| [`docs/phase4-region-pins.md`](docs/phase4-region-pins.md)     | Stack/heap pins + block-wide super path |
| [`docs/phase4-jit-coherency.md`](docs/phase4-jit-coherency.md) | Chaining / edge IC / I$ policy          |
| [`docs/phase4-string-bulk.md`](docs/phase4-string-bulk.md)     | REP MOVS/STOS host spans                |
| [`docs/phase4-code-invalidation.md`](docs/phase4-code-invalidation.md) | Selective JIT drop on X-loss / SMC / free |
| [`docs/phase5-guest-stubs.md`](docs/phase5-guest-stubs.md)     | In-guest WinAPI stubs (Learn policy)    |
| [`docs/phase5.5-neon-cranelift.md`](docs/phase5.5-neon-cranelift.md) | Neon SIMD, TLB, inline strings, Cranelift flags |
| [`Optimization ROADMAP.md`](Optimization%20ROADMAP.md)         | Full plan (Phases 6–7 still open)       |

Headline numbers on Apple Silicon release builds (order-of-magnitude; re-measure with `WIE_RUNTIME_PROFILE=1`):

| Workload                                     |        Approx wall | Notes                                                           |
| -------------------------------------------- | -----------------: | --------------------------------------------------------------- |
| `long_loop` (100M, JIT sticky + stack super) |   **~0.28–0.32 s** | ~100% CPU by design; was ~1.4 s sticky-only, ~0.54 s hoist-only |
| Short micros (`crt_hello`, heap, …)          |      **~15–25 ms** | Init-dominated; emu often &lt; 1 ms                             |
| `long_loop` under `WIE_CPU=iced`             | fails slice budget | ~11M iced steps/s; needs JIT for pure compute                   |

What actually burns CPU today:

1. **Tight guest loops** — expected ~100% core under JIT; iced is orders of magnitude slower and may hit slice budgets (`long_loop`).
2. **Memory helpers** — cold / non-pinned loads still go through TLB helpers; pure stack loops largely avoid this via the super path. Mmap arenas help memory-heavy guests, not pure ALU loops.
3. **Host API stops** — every non-stub import pays a stop; guest stubs / UCRT fast path / heap freelist cut track (C).
4. **Block entry/exit** — GPR sync is mandatory; XMM sync is skipped for pure GPR blocks.
5. **Cold compile tax** — hotness threshold avoids compiling one-shot code; short micros spend most wall in session init.

Further wins worth pursuing (roadmap): idle park for Sleep/message waits (Phase 6); stress / cutover + optional default flip to `WIE_MEM=mmap` (Phase 7; core code invalidation is Phase 4.x); denser stop/API lookup.

## Installation & Prerequisites

Apple Silicon Mac: Rust toolchain.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

git clone https://github.com/Vladislav-Kalinkin/wie
cd wie
cargo build -p wie-cli --release

./scripts/run-micro-suite.sh
```

Useful local checks (same as pre-PR):

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
make -C micro-exes && ./scripts/run-micro-suite.sh
```

## History

Early work targeted an alternate way to run FuSoYa's Lunar Magic and used Unicorn Engine. After full init sequences proved feasible, Unicorn-specific paths were removed in favour of iced-x86 + Cranelift. Pre-removal Lunar-specific runs were already ~2s faster than Unicorn on the same workload.

Global optimisation (2026-07): memory backends + SPC/VAD, JIT sticky/pin/super-path and bulk strings, expanded guest stubs — documented under `docs/phase*.md` and the roadmap.

## AI-Usage

This project uses code generated by artificial intelligence for implementation, tests, and architecture drafts. The author researches, reviews, runs tests, watches clippy/`unsafe` boundaries, and steers the product direction. Generated code is not accepted without human verification.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

### Pre-PR Checklist

1. **Format:** `cargo fmt --check`
2. **Lint:** `cargo clippy --workspace --all-targets -- -D warnings`
3. **Unit tests:** `cargo test --workspace`
4. **Integration:** `make -C micro-exes && ./scripts/run-micro-suite.sh`

Optional backend matrix when touching memory or JIT:

```bash
WIE_MEM=hash ./scripts/run-micro-suite.sh
WIE_MEM=mmap ./scripts/run-micro-suite.sh
WIE_JIT_MEM=slow ./scripts/run-micro-suite.sh
WIE_JIT_MEM=pin ./scripts/run-micro-suite.sh
```

## Acknowledgments

- [@DevYatsu](https://github.com/DevYatsu) — performance optimizations

## License

**GNU Lesser General Public License v3.0 (LGPL-3.0)** — see [LICENSE.txt](LICENSE.txt).
