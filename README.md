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

**Not goals** — 32-bit apps; full historical Windows compatibility; Wine-style identity mapping (`mmap(addr = guest_va)`). Focus is Windows 10-era PE64 + the APIs real tools actually call. Guest VA always soft-translates through region tables / arenas / TLB.

The WinAPI surface is intentionally incomplete: many handlers are stubs sufficient for the micro-suite and engine bring-up, not a final product surface.

**Status (post great cleanup):** Soft-translate guest memory is **mmap-only** (no hash/hybrid fallback). Software page permissions + `Virtual*`, Cranelift block JIT with stack super-path / **2-way multi sticky** + 8-slot region pins (helper always; data pin IR opt-in) / set-assoc Neon TLB / SIMD SSE2 / bulk + inline strings, expanded in-guest stubs, host idle park (`WIE_IDLE`), invalidation stress + `FlushInstructionCache`. CLI compressed to `inspect` / `run` / `trace`. See [`docs/RUNBOOK.md`](docs/RUNBOOK.md) and [`Optimization ROADMAP.md`](Optimization%20ROADMAP.md).

**Real console 7-Zip (`7za`):** WIE runs the **Windows PE64** standalone console from 7-Zip Extra (not macOS `7za`, not GUI). The PE is **not** committed (`/real_exes` is gitignored) — download once, then create/list/extract `.7z` under JIT or iced. See [7-Zip console status](#7-zip-console-status-7za).

## Examples of launch

```bash
# Build release CLI once
cargo build -p wie-cli --release

# Tiny freestanding PE
time ./target/release/wie-cli run micro-exes/out/crt_hello.exe
# hello from crt
# run_micro: ok exit=0

# Heap API matrix
time ./target/release/wie-cli run micro-exes/out/winapi_heap.exe
# HeapAlloc / HeapSize / HeapReAlloc / HeapFree / double-free / size-0 paths
# run_micro: ok exit=0

# ~100M stack-volatile loop under Cranelift JIT (block-wide super path)
time WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run micro-exes/out/long_loop.exe
# expect ~0.28–0.32s wall, ~100% CPU, mem_backend=mmap

# Interactive argv + live stdin (blocks on host Read until Enter / pipe data)
time WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run micro-exes/out/cli_args.exe -- -n 3 -m hi -i

# Deterministic stdin (no TTY) — same as the suite uses
printf 'CLI_IN\n' | ./target/release/wie-cli run micro-exes/out/cli_args.exe --stdin /dev/stdin -- -n 3 -m hi -i

# Bottle files (guest C:\… → {root}/drive_c/…)
BOTTLE=$(mktemp -d)
mkdir -p "$BOTTLE/drive_c/App"
./target/release/wie-cli run micro-exes/out/write_file.exe --root "$BOTTLE"

# Optional host bridge: guest D:\… → host path (WIE_DRIVE_D / --drive-d)
# ./target/release/wie-cli run --root "$BOTTLE" --drive-d "$PWD/data" real_exes/7za.exe -- a C:\App\out.7z D:\sample.txt

# Multithreading micros (CreateThread / CS / events / Interlocked)
./target/release/wie-cli run micro-exes/out/thread_create_join.exe
./target/release/wie-cli run micro-exes/out/cs_two_threads.exe
./target/release/wie-cli run micro-exes/out/event_handshake.exe
./target/release/wie-cli run micro-exes/out/mt_stress.exe
# Kill-switch: WIE_MT=0 makes CreateThread fail (ST-only)
```

```bash
# Full clean-room gate (builds micros + runs all PE gates under WIE_CPU=jit)
make -C micro-exes && ./scripts/run-micro-suite.sh

# JIT / CPU A/B
WIE_CPU=iced  ./scripts/run-micro-suite.sh          # interpreter only (long_loop may hit slice limit)
WIE_JIT_MEM=slow ./scripts/run-micro-suite.sh       # helper-only loads/stores
WIE_JIT_MEM=pin  ./scripts/run-micro-suite.sh       # sticky + top-2 data pin IR
WIE_JIT_CHAIN=0  ./scripts/run-micro-suite.sh
WIE_STRING_BULK=0 ./scripts/run-micro-suite.sh
```

## Multithreading (guest threads)

WIE models **1:1 host thread ↔ guest thread**. Guest **CPU is still serialized** on one shared `CpuEngine` (process mutex): when a thread waits (`WaitFor*`, contended CS, …) it **drops** the engine lock so peers can run. True parallel JIT on two cores is a future step. Details: [`docs/mt-threads.md`](docs/mt-threads.md).

| Surface | Status |
| ------- | ------ |
| `CreateThread` / `ExitThread` / join via `WaitForSingleObject` | OK |
| CRT `_beginthreadex` / `_endthreadex` (same spawn path) | OK |
| `CREATE_SUSPENDED` + `ResumeThread` | OK |
| Critical sections (reenter + contended park) | OK |
| Events (`CreateEvent` / `Set` / `Reset` / wait) | OK |
| Semaphores (`CreateSemaphore` / `ReleaseSemaphore` / wait) | OK |
| `WaitForMultipleObjects` (any / all) | OK |
| Interlocked\* (host atomics when aligned + soft-translated) | OK |
| TLS (`TlsAlloc` / `Get` / `Set` / `Free`) | OK |

| Knob | Role | Default |
| ---- | ---- | ------- |
| `WIE_MT=0` | Disable worker spawn (`CreateThread` → fail) | enabled |
| `WIE_MT_MAX_THREADS` | Cap on guest workers | `64` |

Default **guest** worker stack is **1 MiB** when `dwStackSize == 0`. Host OS threads for workers use **8 MiB** (JIT/iced need room on secondary threads).

## 7-Zip console status (`7za`)

WIE emulates a **Windows PE64** standalone console 7-Zip (`7za.exe` from the official **7-Zip Extra** package). That is **not** a native macOS `7za`/`7z` binary and **not** the GUI (`7zFM` / full installer).

- **`/real_exes` is gitignored** — do not expect `7za.exe` in a clean clone; obtain the Windows PE yourself (steps below).
- Guest files use a **bottle**: host `{root}/drive_c/...` ↔ guest `C:\...` (`--root` / `WIE_ROOT`).

### What works (verified with 7-Zip Extra **26.02** `x64/7za.exe`)

| Guest command        | Meaning                         | Default JIT | `WIE_CPU=iced`          |
| -------------------- | ------------------------------- | ----------- | ----------------------- |
| `--help` / `help`    | Usage                           | OK `exit=0` | OK                      |
| `i`                  | Formats / codecs / hashers      | OK          | OK                      |
| `a -mmt1 -bd …`      | Create `.7z` (LZMA2, 1 thread)  | OK          | OK                      |
| `a -mmt2` / `-mmt4`  | Multi-thread create (CRT MT)    | OK          | OK                      |
| `l …`                | List archive                    | OK          | OK                      |
| `x -mmt1 -bd -y -o…` | Extract                         | OK          | OK (SHA matches source) |
| `x -mmt2` / `-mmt4`  | Multi-thread extract + roundtrip| OK          | OK                      |

7za multi-thread paths use **`msvcrt!_beginthreadex`**, events, and semaphores — the same generic WinAPI/CRT surface as the MT micros (not a 7za special case).

Recommended flags: **`-bd`** (no progress), **`-y`** on extract. Raise **`--max-api`** for real tools (`200000`–`500000`); micros keep the low default.

### Obtain Windows `7za.exe` (any Mac)

WIE needs the **x64 PE** from **7-Zip Extra** (standalone console). Root `7za.exe` in that package is **32-bit** — use **`x64/7za.exe`**.

| Path in Extra archive | Arch              | Use with WIE?                  |
| --------------------- | ----------------- | ------------------------------ |
| `7za.exe`             | Windows **x86**   | No                             |
| `x64/7za.exe`         | Windows **x64**   | **Yes** (this is what we run)  |
| `arm64/7za.exe`       | Windows **ARM64** | No (WIE is x86-64 guest today) |

**One-time setup** (run from the WIE repo root). Homebrew `p7zip` is only a **bootstrap** to unpack the Extra archive; the guest under WIE is still the **Windows** PE.

```bash
brew install p7zip

VER=26.02
VER_COMPACT=2602
mkdir -p real_exes /tmp/7z-extra-$$
curl -fL -o /tmp/7z-extra-$$/extra.7z \
  "https://github.com/ip7z/7zip/releases/download/${VER}/7z${VER_COMPACT}-extra.7z"
7za x -y -o/tmp/7z-extra-$$/out /tmp/7z-extra-$$/extra.7z

cp -f /tmp/7z-extra-$$/out/x64/7za.exe  real_exes/
cp -f /tmp/7z-extra-$$/out/x64/7za.dll  real_exes/
cp -f /tmp/7z-extra-$$/out/x64/7zxa.dll real_exes/
file real_exes/7za.exe
rm -rf /tmp/7z-extra-$$
```

Without Homebrew: open `7z*-extra.7z` anywhere you can, then copy **`x64/7za.exe`** into this repo’s `real_exes/` (still gitignored).

### Universal test payloads

Generate inputs on the fly (no personal `Downloads/` files, works in CI):

| Payload                | How                        | Purpose                      |
| ---------------------- | -------------------------- | ---------------------------- |
| Tiny text              | `echo '…' > hello.txt`     | Fast create / list / extract |
| Binary blob (~256 KiB) | Python deterministic bytes | LZMA2 + SHA-256 roundtrip    |
| Optional extra         | `cp /any/local/file …`     | Stress only; not required    |

### Universal example (create / list / extract / MT / SHA roundtrip)

One bottle, synthetic payloads only (no personal files). After `real_exes/7za.exe` is present:

```bash
cargo build -p wie-cli --release
CLI=./target/release/wie-cli
PE=real_exes/7za.exe
test -f "$PE" || { echo "missing $PE — install Windows x64 7za (see above)"; exit 1; }

BOTTLE="${TMPDIR:-/tmp}/wie-7za-bottle-$$"
APP="$BOTTLE/drive_c/App"
mkdir -p "$APP"
cp -f "$PE" "$APP/7za.exe"

echo 'hello from wie bottle' > "$APP/hello.txt"
python3 -c "
from pathlib import Path
app = Path(r'''$APP''')
data = bytes((i * 17 + 31) & 0xFF for i in range(256 * 1024))
(app / 'blob.bin').write_bytes(data)
print('blob.bin', len(data))
"

# Help + codec inventory
$CLI run --root "$BOTTLE" --max-api 100000 "$PE" -- --help
$CLI run --root "$BOTTLE" --max-api 100000 "$PE" -- i

# Create: single-thread + multi-thread (CRT _beginthreadex path)
$CLI run --root "$BOTTLE" --max-api 500000 "$PE" -- \
  a -mmt1 -bd 'C:\App\hello.7z' 'C:\App\hello.txt'
$CLI run --root "$BOTTLE" --max-api 500000 "$PE" -- \
  a -mmt2 -bd 'C:\App\blob.7z' 'C:\App\blob.bin'
$CLI run --root "$BOTTLE" --max-api 500000 "$PE" -- \
  a -mmt4 -bd 'C:\App\blob4.7z' 'C:\App\blob.bin'

# List
$CLI run --root "$BOTTLE" --max-api 100000 "$PE" -- l 'C:\App\blob.7z'

# Extract + SHA-256 roundtrip (mmt2)
rm -rf "$APP/out" && mkdir -p "$APP/out"
$CLI run --root "$BOTTLE" --max-api 500000 "$PE" -- \
  x -mmt2 -bd -y -o'C:\App\out' 'C:\App\blob.7z'
SRC=$(shasum -a 256 "$APP/blob.bin" | awk '{print $1}')
OUT=$(shasum -a 256 "$APP/out/blob.bin" | awk '{print $1}')
echo "src=$SRC out=$OUT"
test "$SRC" = "$OUT" && echo "ROUNDTRIP OK" || { echo "ROUNDTRIP FAIL"; exit 1; }

# Backend A/B (optional)
WIE_CPU=iced $CLI run --root "$BOTTLE" --max-api 500000 "$PE" -- \
  a -mmt2 -bd 'C:\App\blob_iced.7z' 'C:\App\blob.bin'
WIE_CPU=jit  $CLI run --root "$BOTTLE" --max-api 500000 "$PE" -- \
  a -mmt2 -bd 'C:\App\blob_jit.7z'  'C:\App\blob.bin'

rm -rf "$BOTTLE"
```

**CLI shape:**

```text
wie-cli run --root <bottle> --max-api N real_exes/7za.exe -- <7za-args...>
```

**Minimal smoke (text only, single-thread):**

```bash
cargo build -p wie-cli --release
test -f real_exes/7za.exe || { echo "install x64 7za.exe first"; exit 1; }
B=$(mktemp -d) && mkdir -p "$B/drive_c/App" && \
  cp real_exes/7za.exe "$B/drive_c/App/" && \
  echo hi > "$B/drive_c/App/hello.txt" && \
  ./target/release/wie-cli run --root "$B" --max-api 200000 real_exes/7za.exe -- \
    a -mmt1 -bd 'C:\App\h.7z' 'C:\App\hello.txt' && \
  ./target/release/wie-cli run --root "$B" --max-api 200000 real_exes/7za.exe -- \
    x -mmt1 -bd -y -o'C:\App\out' 'C:\App\h.7z' && \
  cat "$B/drive_c/App/out/hello.txt" && rm -rf "$B"
```

### Implementation notes (why real tools work)

1. **`SBB` flags** — MSVC COM `QueryInterface` uses `cmp` + `sbb r,r` + `sbb r,-1`. Wrong CF when `src+CF` overflowed the operand width picked the wrong interface → null call.
2. **`VirtualAlloc(NULL, size, MEM_COMMIT)`** — treated as **RESERVE|COMMIT** (Windows/Wine-compatible) for LZMA2 buffers.
3. **JIT dual_super GPR writeback** — only store live GPRs on block exit (do not zero callee-saved).
4. **Default `WIE_JIT_SUPER=loop`** — non-loop stack super can host-fault on some real tools (`7za a`); self-loop super keeps `long_loop` fast. Opt in with `WIE_JIT_SUPER=all` only when bisecting.
5. **CRT/WinAPI MT** — `_beginthreadex`, semaphores, events, `WaitForMultipleObjects`, save-before-switch on the shared engine (see Multithreading above).

### Not claimed yet

- GUI 7-Zip / `7zFM` / full installer PE.
- Password / crypto, solid multi-file update, or every format beyond default `.7z` LZMA2.

### Known issue: multi‑GiB / many‑file `7za a` “super-test” (open)

Small and medium `7za` create/list/extract gates (README universal example, MT micros) **work**. A **heavy** create over a large host tree via `--drive-d` is **not** green yet.

**Target command** (local stress only; not CI):

```bash
B="/tmp/w7z_heavy_$$" && mkdir -p "$B/drive_c/App"
time env WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run \
  --root "$B" \
  --drive-d "/path/to/large_tree" \   # e.g. ~10 GiB, tens of thousands of files
  --max-api 2000000 \
  real_exes/7za.exe -- \
  a -mmt4 -mx=1 -md=64k -bd 'C:\App\huge_cache.7z' 'D:\'
rm -rf "$B"
```

| Stage | Symptom | Status / notes |
| ----- | ------- | -------------- |
| Directory scan (~60k files) | `malloc` → `0` → `msvcrt!_CxxThrowException` → `unimplemented mnemonic Int3` | **Mitigated:** default process heap raised to **512 MiB** (was 16 MiB); override with `WIE_PROCESS_HEAP_MB`. `_CxxThrowException` now fails with an explicit OOM/EH message instead of bare Int3. |
| Same scan, large heap, **JIT** | Host `thread 'main' has overflowed its stack` | **Mitigated:** JIT block chaining nests host C frames; **`MAX_CHAIN_DEPTH` (48)** returns to the dispatcher instead of unbounded nesting. |
| After scan / early archive create | `invalid memory access … address=0x7f…` (guest read of unmapped VA) | **Open.** Scan can finish and print folder/file counts; create then faults. Needs more isolation (heap vs JIT chain vs VFS timestamps / file APIs). |
| Full 10 GiB compress + roundtrip | Successful super-test + README claim | **Not done** — left for a dedicated session (long wall time). |

**Related knobs**

| Knob | Role |
| ---- | ---- |
| `WIE_PROCESS_HEAP_MB` | Process-heap size in MiB (default **512**; mmap demand-zero, RSS grows on use). Raise further if huge scans still OOM. |
| `WIE_JIT_CHAIN=0` | Disable late-bound block chaining (debug / bisect host-stack vs correctness). |
| `WIE_CPU=iced` | Interpreter-only; useful to separate JIT chain issues from WinAPI/VFS bugs. |
| `--max-api` | Must be large (`2e6`–`2e7+`); scan alone is hundreds of thousands of charged APIs. |

When this path exits `0` end-to-end under default JIT, document it here as a successful super-test (command + measured wall/profile).

## Core Components

| Crate             | Role                                                                                                                                                                                                                             |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`wie-cpu`**     | CPU + guest memory: **`JitCpu`** (default) — Cranelift x86-64→ARM64 block JIT + iced fallback; **`IcedCpu`** — pure iced-x86 (`WIE_CPU=iced`). Memory: **mmap arenas only**, RegionTable, PageMap/VAD/SPC, JIT TLB + pins.       |
| **`wie-winapi`**  | KERNEL32 / UCRT / USER32 / GDI32 / … handlers. Dense `WinApiId` dispatch (no string compares on the hot path). Guest heap: 24 size classes + bump + optional shared control block. Real `VirtualAlloc`/`Free`/`Protect`/`Query`. |
| **`wie-runtime`** | Session: PE load, layout regions, fake-API hooks, guest accelerators (stubs / heap / I/O / MBWC), run loop, TEB last-error, bottles (`WIE_ROOT`). Profile via `WIE_RUNTIME_PROFILE`.                                             |
| **`wie-pe`**      | PE64 parse, section map plan, import/IAT patch with fake VAs, COFF → `PAGE_*` protects.                                                                                                                                          |
| **`wie-cli`**     | Three fundamentals: `inspect` / `run` / `trace` (aliases `run-micro`, `entry-trace` kept).                                                                                                                                       |

## Execution Flow

1. **PE loading** — `wie-pe` maps the image into one `MEM_IMAGE` arena, rewrites every IAT slot to a **fake API VA** (e.g. `0x7000_0000_0000_xxxx`), then applies section protects from COFF characteristics (software permission checks always; optional host `mprotect` on arenas).

2. **Hooks + guest stubs** — A **stop bitmap** covers the fake range. Hot APIs (`GetLastError` / `SetLastError`, critical sections, PID/TID, cmdline, metrics/colors, …) get small **in-guest stubs** so they never host-stop. Optional accelerators rewire IAT entries to real guest machine code (`WIE_GUEST_HEAP`, `WIE_GUEST_IO`, `WIE_GUEST_MBWC`).

3. **Run** — Control starts at the PE entry. `JitCpu` decodes lowerable basic blocks (GPR, simple mem, jcc/jmp/call/ret, common SSE2, bulk REP MOVS/STOS). Hot pure blocks compile to ARM64 and are cached; complex/cold code falls back to iced.

4. **API stop** — Hitting a stop-bit fake VA returns to `RuntimeSession`, which resolves `WinApiId` and runs the handler. Handlers use Win64 register ABI and `return_from_win64_api`.

5. **Fast paths** — JIT can lower hot UCRT imports (`malloc`, `free`, `memcpy`, `strlen`, `fwrite`, `fflush`, `__acrt_iob_func`) as direct host calls. Block chaining + edge IC + a shadow return stack keep control in native code across calls/rets/self-loops. Stack-heavy pure loops use a **block-wide pin super path** (bare host load/store after one prologue guard).

6. **Host resources** — Bottles map `C:\…` → `{root}/drive_c/…` (Win10 skeleton dirs, no PE/DLL payload). Optional **D:** host bridge (`--drive-d` / `WIE_DRIVE_D`). Files, fake HWNDs, and a minimal message path live on the host. `VirtualAlloc` family goes through PageMap + VAD (soft translate only — no guest-VA `mmap`).

## JIT Compilation Details

- **Granularity**: blocks up to **64** instructions; fallthrough-only fragments need ≥ **8** insns to justify compile tax. Blocks ending in **jcc/jmp/call/ret** or string ops compile from **1** insn (tight loops must not stay on iced).
- **Hotness**: compile after **100** visits (tests: 0; pure self-loops: **16**; UCRT call sites: 2).
- **Chaining**: self-loops become IR back-edges; open-addressing chain table + monomorphic **edge IC** + shadow stack for call/ret. Kill-switch: `WIE_JIT_CHAIN=0`.
- **Memory lower** (`WIE_JIT_MEM`):
  - **`sticky` (default)** — **2-way multi sticky** (last-2 MRU pages, SPC R/W + `mem_gen`); **stack `MemPin`**; block-wide super path on **self-loops** by default (`WIE_JIT_SUPER=all` opts into non-loop super). Helpers always try **all 8 region pins** (stack + size-ranked heaps/VirtualAlloc) before a page walk.
  - **`pin`** — same as sticky + **top-2 data pin IR** after multi sticky (opt-in; full pin cascade taxes thrashy paths).
  - **`slow`** — helper-only `wie_jit_load` / `wie_jit_store` (oracle / bisect).
- **SSE2**: common XMM moves / bitwise / scalar+packed FP lowered with Cranelift SIMD (`I8X16`/`F32X4`/…) → host Neon when `WIE_JIT_SIMD≠0`; pure GPR blocks **skip XMM bank**; live/dirty masks selective sync.
- **TLB**: multi sticky (IR) + **16×4 set-associative** multi-way helper TLB (Neon tag compare on aarch64; `WIE_TLB_NEON=0` scalar) + region pins.
- **Strings**: REP MOVS/STOS (DF=0) — inline unrolled `I8X16` for 16–64 B (`WIE_STRING_INLINE`), else soft-translated host spans (`WIE_STRING_BULK=0` disables bulk). Overlap / DF=1 stay element-loop.
- **Fallback**: anything not lowerable → iced `step`.

## Memory & Heap

- **Storage**: sole path is **mmap arenas** (every map → anonymous demand-zero arena). Soft translate only — guest VA ≠ host VA. Legacy `hash` / `hybrid` backends removed.
- **Layout**: `RegionTable` names stack / heap / image / fake API / TEB / stubs; arenas expose `host_base` for JIT pins.
- **Permissions**: software PageMap + VAD (Free / Reserved / Committed, `PAGE_*`); SPC on every read/write/fetch and JIT TLB install. Optional dual `mprotect` on arena frames (`WIE_MPROTECT`, default on) — never the sole oracle under 4K guest / 16K host clinch.
- **Dynamic mapping**: real `VirtualAlloc` / `VirtualFree` / `VirtualProtect` / `VirtualQuery` (64 KiB reserve granularity, 4 KiB commit).
- **Process heap**: segregated freelists (**24** size classes, up to 64 KiB) + bump for virgin space; 8-byte size header before each payload.
- Host `GuestHeap` and optional in-guest `HeapAlloc`/`HeapFree` share a control block. Default path is **host freelist** (`WIE_GUEST_HEAP=1` enables full guest rewire).
- `HeapFree` of a live block → TRUE; **double-free / unknown** → FALSE + `ERROR_INVALID_HANDLE` (6). `HeapAlloc(..., 0)` returns a valid freeable pointer; `HeapReAlloc(..., 0)` frees and returns NULL. `HEAP_ZERO_MEMORY` zeros the payload.

## Environment knobs

| Variable                                  | Effect                                                                                              |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `WIE_CPU=jit` \| `iced`                   | CPU backend (default **jit**)                                                                       |
| `WIE_MPROTECT=0`                          | Disable optional host `mprotect` dual-protection on arenas (SPC remains on)                         |
| `WIE_JIT_MEM=sticky` \| `pin` \| `slow`   | JIT mem lower (default **sticky** = 2-way multi sticky + stack pin; helpers always pin-resolve)     |
| `WIE_JIT_MEM_TRACE=1`                     | Dump helper mem-path histogram (sticky / multi / pin / walk) on finalize                            |
| `WIE_JIT_SUPER=loop` \| `0` \| `all`      | Block-wide stack super path: default **loop** (self-loops only); `0` off; `all` experimental        |
| `WIE_JIT_CHAIN=0`                         | Disable FuncRef chaining / chain table / edge IC                                                    |
| `WIE_STRING_BULK=0`                       | Disable host-span bulk REP MOVS/STOS                                                                |
| `WIE_STRING_INLINE=0`                     | Disable inline 16–64 B REP Neon path (Phase 5.5)                                                    |
| `WIE_JIT_SIMD=0`                          | Scalar lo/hi XMM lowering (no CLIF SIMD / Neon)                                                     |
| `WIE_TLB_NEON=0`                          | Scalar 4-way TLB tag scan (no Neon compare)                                                         |
| `WIE_JIT_OPT=speed\|speed_and_size\|none` | Cranelift opt_level (default **speed**)                                                             |
| `WIE_JIT_VERIFY=1`                        | Enable Cranelift IR verifier outside tests                                                          |
| `WIE_RUNTIME_PROFILE=1`                   | Wall/CPU%, host stops, JIT load/store counts, `mem_backend`                                         |
| `WIE_PROCESS_HEAP_MB`                     | Guest process-heap size in MiB (default **512**; large `7za` scans used to OOM at 16 MiB)           |
| `WIE_API_JOURNAL=path`                    | Per-API journal for backend A/B diffs                                                               |
| `WIE_ROOT` / `--root`                     | Bottle root for guest `C:\` file APIs                                                               |
| `WIE_DRIVE_D` / `--drive-d`               | Host root for guest `D:\` bridge (`auto` = host cwd); unset = no D:                                 |
| `WIE_GUEST_HEAP=1`                        | Rewire process-heap `HeapAlloc`/`HeapFree` to guest code                                            |
| `WIE_GUEST_IO=0` \| `all`                 | I/O accelerator: default seeks/size in-guest; `all` also guest Read (large → host); `0` = all host  |
| `WIE_GUEST_MBWC=1`                        | Guest MultiByte↔WideChar helpers                                                                    |
| `WIE_IDLE=busy\|yield\|park`              | Host idle policy (Phase 6): micros default **yield**; interactive `run` default **park** when unset |
| `WIE_IDLE_CAP_MS`                         | Max single `Sleep` park (default 60000)                                                             |
| `WIE_IDLE_PARK_MS`                        | Empty-`GetMessage` park quantum ms (default 25)                                                     |
| `WIE_IDLE_MAX_PARKS`                      | Max message park quanta before CLI yield (`0` = unlimited; default 40)                              |
| `WIE_HOST_SLEEP=1`                        | **Legacy:** enable `Sleep(n>0)` park only (prefer `WIE_IDLE=park`)                                  |
| `WIE_MT=0`                                | Disable guest worker spawn (`CreateThread` / `_beginthreadex` fail)                                 |
| `WIE_MT_MAX_THREADS`                      | Cap on guest worker threads (default **64**)                                                        |
| `RUST_LOG`                                | tracing filter (CLI defaults to `warn`)                                                             |

## CLI

Three fundamental commands (`run-micro` / `entry-trace` remain as aliases):

```bash
./target/release/wie-cli --help
./target/release/wie-cli run --help
```

| Command                 | Role                                                                                                                   |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `inspect <pe>`          | PE metadata; flags: `--sections`, `--imports` / `--find`, `--image`, `--winapi-map` / `--out`                          |
| `run <pe>`              | **Primary** micro gate (`ExitProcess`); `--max-api` (256), `--expect-code`, `--root`, `--stdin`, guest argv after `--` |
| `run <pe> --persistent` | Persistent loop until yield/exit (`--max-api` default 3400)                                                            |
| `trace <pe>`            | First N host API stops (`--max-api`, default 20)                                                                       |

## Performance notes (CPU / wall)

Phases 0–5 landed; baselines and design notes:

| Doc                                                                    | Topic                                              |
| ---------------------------------------------------------------------- | -------------------------------------------------- |
| [`docs/phase0-baseline.md`](docs/phase0-baseline.md)                   | Wall/CPU%, host stops, JIT counters                |
| [`docs/phase2-mmap-backend.md`](docs/phase2-mmap-backend.md)           | Mmap arena storage (historical dual-backend notes) |
| [`docs/phase3-permissions.md`](docs/phase3-permissions.md)             | SPC, PageMap/VAD, `Virtual*`                       |
| [`docs/phase4-foundation.md`](docs/phase4-foundation.md)               | Sticky TLB + kill-switches                         |
| [`docs/phase4-region-pins.md`](docs/phase4-region-pins.md)             | Stack/heap/VA pins, multi sticky, super path       |
| [`docs/phase4-jit-coherency.md`](docs/phase4-jit-coherency.md)         | Chaining / edge IC / I$ policy                     |
| [`docs/phase4-string-bulk.md`](docs/phase4-string-bulk.md)             | REP MOVS/STOS host spans                           |
| [`docs/phase4-code-invalidation.md`](docs/phase4-code-invalidation.md) | Selective JIT drop on X-loss / SMC / free          |
| [`docs/phase5-guest-stubs.md`](docs/phase5-guest-stubs.md)             | In-guest WinAPI stubs (Learn policy)               |
| [`docs/phase5.5-neon-cranelift.md`](docs/phase5.5-neon-cranelift.md)   | Neon SIMD, TLB, inline strings, Cranelift flags    |
| [`docs/phase6-idle.md`](docs/phase6-idle.md)                           | Host idle park (`Sleep` / empty GetMessage)        |
| [`docs/phase7-hardening.md`](docs/phase7-hardening.md)                 | Stress, FIC stub, mmap default cutover             |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md)                                   | Symptom → kill-switch playbook                     |
| [`Optimization ROADMAP.md`](Optimization%20ROADMAP.md)                 | Full plan (Phases 0–7 complete)                    |

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

Further wins worth pursuing: full wait objects beyond Sleep/GetMessage; optional SIGSEGV fault epic (explicit non-goal of Phases 0–7). **Denser API lookup** (IDs in fake VA, no HashMap on host stop) is landed.

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

Global optimisation (2026-07): memory backends + SPC/VAD, JIT multi sticky / region pins / super-path and bulk strings, expanded guest stubs — documented under `docs/phase*.md` and the roadmap.

## AI-Usage

This project uses code generated by artificial intelligence for implementation, tests, and architecture drafts. The author researches, reviews, runs tests, watches clippy/`unsafe` boundaries, and steers the product direction. Generated code is not accepted without human verification.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

### Pre-PR Checklist

1. **Format:** `cargo fmt --check`
2. **Lint:** `cargo clippy --workspace --all-targets -- -D warnings`
3. **Unit tests:** `cargo test --workspace`
4. **Integration:** `make -C micro-exes && ./scripts/run-micro-suite.sh`

Optional JIT matrix when touching memory lower / chaining:

```bash
WIE_JIT_MEM=slow ./scripts/run-micro-suite.sh
WIE_JIT_MEM=pin ./scripts/run-micro-suite.sh
WIE_CPU=iced ./scripts/run-micro-suite.sh
```

## Acknowledgments

- [@DevYatsu](https://github.com/DevYatsu) — performance optimizations

## License

**GNU Lesser General Public License v3.0 (LGPL-3.0)** — see [LICENSE.txt](LICENSE.txt).
