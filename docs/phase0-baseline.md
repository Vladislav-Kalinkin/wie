# Phase 0 – Baseline Measurement

**Date:** 2026-07-18  
**Host:** macOS Apple Silicon (M1+), release build (`cargo build -p wie-cli --release`, LTO)  
**Memory backend:** `hash` (default)  
**Method:** `WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run-micro <pe>`

Counters:

| Field | Meaning |
| ----- | ------- |
| `wall_ms` | End-to-end wall time including init |
| `cpu%` | `(user+sys) / wall` from `getrusage` |
| `emu_ms` | Time inside `run_until_stop` |
| `host_stops` | Fake-API host entries |
| `jit_insns` / `iced` | Retired via native blocks / iced steps (see note) |
| `load` / `store` | Calls into `wie_jit_load` / `wie_jit_store` helpers |

**Note on `jit_insns` / `cache_hits`:** Self-loops lowered as IR back-edges run entirely inside one native function. Host counters only advance on block *entry*; a 100M-iteration loop may report ~10 JIT insns and 0 cache hits while still spending ~1.4s in pure guest compute.

---

## Results (release)

### Pure / compute-heavy guests

| Guest | CPU | wall_ms | cpu% | emu_ms | host_stops | jit_insns | iced | compiles | cache_hits | load | store |
| ----- | --- | ------: | ---: | -----: | ---------: | --------: | ---: | -------: | ---------: | ---: | ----: |
| `long_loop` | **jit** | **1378–1646** | **~100%** | **1362–1622** | 1 | 11 | 174 | 3 | 0 | 1 | 0 |
| `long_loop` | iced | **~70045** (fail) | ~100% | ~70030 | 0 | 0 | 800M | 0 | 0 | 0 | 0 |
| `cpu_math` | jit | 17 | 95% | 0.01 | 1 | 0 | 3 | 2 | 0 | 0 | 0 |
| `cpu_math` | iced | 22 | 84% | 1.87 | 1 | 0 | 3 | 0 | 0 | 0 | 0 |
| `cpu_string` | jit | 17 | 98% | 0.10 | 1 | 0 | 323 | 2 | 0 | 0 | 0 |
| `cpu_string` | iced | 16 | 98% | 0.44 | 1 | 0 | 323 | 0 | 0 | 0 | 0 |

`long_loop` under iced: hit `no_hook_slice_limit` (40 × 20M budget = 800M steps) without `ExitProcess`. Throughput ~11.4M iced steps/s vs effectively unlimited iterations inside one JIT block.

### CRT / API-ish guests

| Guest | CPU | wall_ms | cpu% | emu_ms | host_stops | jit_insns | iced | compiles | cache_hits | load | store | notes |
| ----- | --- | ------: | ---: | -----: | ---------: | --------: | ---: | -------: | ---------: | ---: | ----: | ----- |
| `crt_hello` | jit | 21 | 98% | 2.1 | **2** | 64 | 363 | 34 | 18 | 13 | 1 | UCRT fast-path (malloc/memcpy/strlen/fwrite) avoids host stops |
| `crt_hello` | iced | 17 | 97% | 0.5 | **7** | 0 | 440 | 0 | 0 | 0 | 0 | every CRT import host-stops |
| `heap_alloc` | jit | 17 | 98% | 0.03 | 3 | 2 | 22 | 3 | 1 | 1 | 0 | |
| `heap_alloc` | iced | 16 | 98% | 0.41 | 3 | 0 | 24 | 0 | 0 | 0 | 0 | |
| `winapi_heap` | jit | 18 | 94% | 0.06 | 13 | 8 | 105 | 5 | 3 | 4 | 1 | |
| `modules` | jit | 17 | 98% | 0.07 | 7 | 0 | 123 | 2 | 0 | 0 | 0 | handler ~80% of accounted time |
| `process_ids` | jit | 17 | 99% | 0.02 | 1 | 12 | 17 | 7 | 5 | 6 | 1 | mostly guest stubs |

Init dominates short micros (`init_ms` ≈ 15–20 ms); wall ≈ init for everything except `long_loop`.

---

## Where CPU time goes (tracks A–D)

| Track | Description | Evidence | Addressable by |
| ----- | ----------- | -------- | -------------- |
| **(A) Pure guest computation** | Native JIT block (or iced step) doing guest ALU/branches | `long_loop`: **~100% emu**, ~1.4s wall, ~1 host stop, almost no load/store helpers | Phase 4 (better lower/codegen); **not** Phase 2 mmap, **not** Phase 6 idle |
| **(B) Memory helpers** | `wie_jit_load` / `wie_jit_store`, HashMap/radix walks, TLB fills | Short micros: **load/store counts tiny** (0–13). `long_loop`: 1 load. Hot path is TLB + sticky page; HashMap only on miss | Phase 1–2 (mmap arenas), Phase 4.1–4.2 (region-direct / stack inline) — high value on **memory-heavy** guests, low on pure loops |
| **(C) API dispatch** | Host-stop resolve + WinAPI handlers | `modules`: handler **~80%** of accounted time. `crt_hello` iced: 7 stops vs JIT 2 (UCRT in-guest) | Phase 5 guest stubs; keep/expand JIT UCRT fast path |
| **(D) Compile overhead** | Cranelift lower + finalize | `crt_hello`: 34 compiles, init ~19 ms. `long_loop`: 3 compiles, init ~16–24 ms (noise vs 1.4s run) | Hotness thresholds already; precompile stubs only |

### Rough “theoretically addressable” share

| Workload class | (A) | (B) | (C) | (D) |
| -------------- | --: | --: | --: | --: |
| `long_loop` (tight GPR) | **>98%** | <1% | <1% | ~1% init |
| Short compute micros (`cpu_*`) | high in emu | low | low | init dominates wall |
| API-heavy (`modules`, heap paths) | low–mid | low today | **high** | init |
| CRT startup (`crt_hello`) | mid | low | mid (iced) / low (jit UCRT) | init |

**CPU% ≈ 100% on `long_loop` is correct** — the guest is busy. Optimisation roadmap Phase 6 (idle park) will **not** reduce that; it targets message-wait / Sleep guests.

---

## Instrumentation added for this baseline

- `JitStats::{load_calls, store_calls}` accumulated from `JitCtx` in `wie_jit_load` / `wie_jit_store`
- `RuntimeProfile`: `wall_ns`, `cpu_user_us`, `cpu_sys_us`, `jit`, `mem_backend`
- `CpuEngine::cpu_stats` / `mem_backend_name`
- Profile printed under `WIE_RUNTIME_PROFILE=1`

Re-run:

```bash
cargo build -p wie-cli --release
WIE_RUNTIME_PROFILE=1 WIE_CPU=jit ./target/release/wie-cli run-micro micro-exes/out/long_loop.exe
WIE_RUNTIME_PROFILE=1 WIE_CPU=iced ./target/release/wie-cli run-micro micro-exes/out/crt_hello.exe
```
