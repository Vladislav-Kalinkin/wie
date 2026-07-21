# WIE Roadmap

This roadmap outlines the planned evolution of WIE’s memory management, JIT optimizations, API acceleration, and CPU‑idle policies. The goal is to improve performance and reduce host CPU usage while preserving correctness and avoiding the pitfalls of traditional Wine‑style identity mapping.

---

## Guiding Principles

1. **Guest VA ≠ Host VA** – Always use a soft translation layer (region table, arenas, TLB). No `mmap(addr = guest_va)`.
2. **Mmap-only storage** – Runtime guest pages live in anonymous arenas only (legacy `hash` / `hybrid` removed in the great cleanup).
3. **Parity first, speed second** – The entire micro‑suite must remain green before any JIT fast‑path is enabled.
4. **Targeted arenas** – Only map critical memory regions (heap, stack, image, file cache). Do **not** reserve a fixed 4 GB low address space.
5. **Incremental, self‑contained PRs** – Each phase is a separate, reviewable step.
6. **Dense fake-API VAs** – Library/function identity is encoded in the guest stop address (`wie_winapi::fake_va`); host-stop path is bit-mask decode, not a HashMap.

---

## Phase 0 – Baseline Measurement ✅

**Goal:** Establish a performance baseline before any memory‑backend changes.

- Profile `long_loop`, `cpu_math`, `crt_hello`, and typical API‑heavy guests under both `WIE_CPU=jit` and `WIE_CPU=iced`.
- Collect: wall‑time, CPU%, host‑stop count, JIT cache hits, `wie_jit_load/store` call counts, iced step counts.
- Identify whether CPU time is spent in (A) pure guest computation, (B) memory helper functions, (C) API dispatch, or (D) compile overhead.

**DoD:** A documented table with per‑test numbers, highlighting how much CPU is theoretically addressable by each optimisation track.

**Status (2026-07-18):** Done. Full tables and A–D attribution live in [`docs/phase0-baseline.md`](docs/phase0-baseline.md).  
Headline: `long_loop` is **~100% track (A)** under JIT (~1.4s wall); iced cannot finish it within the slice budget. Memory-helper call counts on current micros are tiny — Phase 2/4 memory work targets future memory-heavy guests, not pure loops. API-heavy micros spend wall in (C)/(D-init).

---

## Phase 1 – Memory Abstraction ✅

### 1.1 `GuestMemBackend` Trait ✅

- Split `crates/wie-cpu/src/mem.rs` into a backend trait and the existing `HashMap` implementation.
- Keep behaviour **identical**; no functional changes.

**DoD:** All tests pass; performance stays within noise.

**Status:** `GuestMemBackend` + `HashMapBackend` in `crates/wie-cpu/src/mem/`; `GuestMemory` facade unchanged for iced/JIT call sites.

### 1.2 Region Registry ✅

- Introduce a software `RegionTable` that tracks named ranges (stack, heap, image, fake API, TEB, etc.) with perms and optional host base.
- This will be used by both `HashMap` and `mmap` backends.

**DoD:** Layout ranges are registered at session start; `find_region(va)` returns the correct entry.

**Status:** `RegionTable` / `GuestRegion` / `RegionKind`; session `register_layout_regions` at init; `CpuEngine::{register_region, find_region}`.

### 1.3 Oracle Tests ✅

- Property‑based tests that compare `HashMap` vs. `mmap` backends byte‑for‑byte under random map/write/read operations.

**DoD:** A test harness that can be run in CI (time‑budgeted).

**Status:** `mem/oracle.rs` + test-only per-page `MmapPageBackend` (not Phase 2 arenas). Seeds: 2k ops + alt seeds; CI-friendly.

---

## Phase 2 – Mmap Storage Backend ✅

### 2.1 `MmapArenaBackend` ✅

- Implement a new backend that uses anonymous `mmap` for contiguous arenas (heap, stack, image, file cache).
- Each region is mapped as a single arena; pages are committed lazily (demand‑zero).
- `read`/`write` and `page_data_ptr` translate `guest_va → host_base + offset`.

**DoD:** Micro‑suite passes with `WIE_MEM=mmap`; oracle tests show identical results.

**Status:** `MmapArenaBackend` + `ArenaSet` in `crates/wie-cpu/src/mem/`; soft translate only; oracle HashMap ↔ arena.

### 2.2 Radix Tree Integration ✅

- Update the radix page‑table to store host pointers returned by the mmap backend (instead of `Box<[u8;4096]>`).
- Ensure `Drop` does not free mmap‑backed pages incorrectly.

**DoD:** No double‑free; address sanitizer clean; high‑VA tests pass.

**Status:** Pure mmap derives page host pointers from arena base (no owning radix leaves). Hybrid keeps HashMap radix for sparse pages only. Arena `Drop` owns `munmap`; TLB/JIT pointers non-owning.

### 2.3 Hybrid Default ✅

- Switch large regions (heap, stack, image, file arena) to `mmap` by default; keep tiny pages (TEB, stubs) on `HashMap` for now.
- The environment variable `WIE_MEM` still allows forcing `hash` or `mmap`.

**DoD:** Measurement shows reduced memory‑helper overhead on hot paths.

**Status (2026-07-18):** Landed hybrid (threshold 64 KiB → arena). Force `hash` / `mmap` / `hybrid`. `GuestRegion.host_base` filled for arena-backed layout regions. **Default later flipped to `mmap` in Phase 7.** Details: [`docs/phase2-mmap-backend.md`](docs/phase2-mmap-backend.md).

---

## Phase 3 – Permissions and Dynamic Mapping

**Status (2026-07-18):** Complete (PR A–E). SPC + PageMap + VAD; real `VirtualAlloc`/`Free`/`Protect`/`Query`; PE section protects; optional host `mprotect`. Details: [`docs/phase3-permissions.md`](docs/phase3-permissions.md), plan [`phase3_plan.md`](phase3_plan.md).

### 3.1 Software + mprotect Dual Protection

- Software permission checks at guest 4 KiB on all backends (correctness plane).
- Optional host `mprotect` on arena frames (`WIE_MPROTECT`, default on); never the sole oracle under 4K/16K clinch.

**DoD:** Reads/writes to unmapped or read‑only regions produce the same errors as the `HashMap` backend. ✅

### 3.2 VirtualAlloc / Free / Protect Support

- `KERNEL32!VirtualAlloc` / `VirtualFree` / `VirtualProtect` / `VirtualQuery` via `GuestMemory` PageMap + VAD (not RegionTable alone).
- RESERVE one arena (mmap/hybrid); COMMIT software; DECOMMIT zeros; RELEASE munmap; Query returns real MBI.

**DoD:** unit matrix + micros green with `WIE_MEM=mmap` / hash / hybrid. ✅

### 3.3 PE Section Mapping

- One image arena (`MEM_IMAGE`); copy-based load; section protects from COFF characteristics after IAT patch.
- Named `RegionTable` entries per section; SPC denies writes to `.text` after load.

**DoD:** `run-micro` on all PE files shows no regressions. ✅

---

## Phase 4 – JIT Optimisations

### 4.0 Foundation (SPC TLB + generation + kill-switches) ✅

- Tag sticky / multi-way TLB with software R/W bits and `GuestMemory::generation`.
- Inline sticky IR checks gen + permission bits before trusted host load/store.
- Kill-switches: `WIE_JIT_MEM=slow|sticky|pin`, `WIE_JIT_CHAIN=0`.
- Docs: [`docs/phase4-foundation.md`](docs/phase4-foundation.md).

**DoD:** Micro-suite green; RO/protect unit tests; no silent write via TLB after protect. ✅

**Status (2026-07-18):** Done (PR0).

### 4.1 Region‑Direct Load/Store Path ✅

- `MemPin` slots (`JIT_REGION_PIN_SLOTS = 8`): stack + size-ranked heaps / private VirtualAlloc spans (bootstrap image/file/TEB excluded from data ranking).
- Filled when `mem_gen` changes (cached on `JitCpu`); PageMap **intersection** R/W + `mem_gen` on each pin.
- Helper `pin_resolve` on TLB miss (always, all slots); Cranelift **data** pin IR only under `WIE_JIT_MEM=pin` (top-2; sticky still preferred default).
- Docs: [`docs/phase4-region-pins.md`](docs/phase4-region-pins.md).

**DoD:** Micro-suite green with `WIE_JIT_MEM=pin`; RO/mixed protect cannot silent-write via pin. ✅

**Status (2026-07-18 / 2026-07-21):** Done. Default remains sticky; full data pin IR opt-in. VA pins collapse helper walk% on 7za LZMA.

### 4.1b Stack pin + block-wide super-fast path ✅

- Stack `MemPin` hoisted once on block entry; normal path: CFG pin → multi sticky → helper.
- **Block-wide guard:** pre-compile scan of all load/store displacements; one prologue check that `[base+min_disp, base+max_end)` ⊆ pin; then dual path:
  - **Super:** `host = bias + guest_va` — bare host load/store, **no** per-access bounds IR
  - **Normal:** hoisted pin / sticky probes (guard miss / mixed protect)
- Eligible only when every memop is same stack base + const disp, base not mutated, no push/pop/call/ret.
- **Perf (`long_loop` 100M volatile stack ops, release):** ~1.4s sticky-only → ~0.54s hoist → **~0.28–0.32s** block-wide super.

**DoD:** Micro-suite green; pure stack loops use super path; guard fail stays correct. ✅

### 4.1c Multi sticky IR ✅

- `STICKY_WAYS = 2` last-MRU pages inlined in load/store IR (way 0 hottest).
- Cuts A↔B page thrash helper traffic (~2× fewer helpers on 7za); wall ~parity vs single sticky (full-miss cascade tax caps ways at 2).
- Opt-in histogram: `WIE_JIT_MEM_TRACE=1` (or `WIE_EXEC_TRACE=1`).

**DoD:** Micro-suite green; sticky miss diagnostics available. ✅

### 4.2 Chaining / I-cache policy (data plane) ✅

- **No executable patching** of Cranelift output; chaining stays FuncRef + chain table + monomorphic **edge IC** (`edge_ic_va`/`edge_ic_fn`).
- Docs: [`docs/phase4-jit-coherency.md`](docs/phase4-jit-coherency.md).

**DoD:** Documented I$/D$ policy; edge IC improves late-bound hits; `WIE_JIT_CHAIN=0` still works. ✅

### 4.3 Accelerated String Operations (REP MOVS/STOS) ✅

- Soft-translated host spans via `GuestMemory::host_span` → host `copy_nonoverlapping` / pattern fill after SPC.
- Guest-overlapping MOVS and DF=1 stay on element loop (x86 forward ≠ `memmove`).
- Kill-switch: `WIE_STRING_BULK=0`. Docs: [`docs/phase4-string-bulk.md`](docs/phase4-string-bulk.md).
- SCAS/CMPS remain element loop (ROI later).

**DoD:** `cpu_string` green; host-span unit tests; no guest-VA into libc. ✅

### 4.x Selective code invalidation (X-loss / SMC / VirtualProtect) ✅

- **X-loss:** `VirtualProtect` with non-executable `new_protect` drops overlapping Ready blocks.
- **SMC:** `GuestMemory::write` notes pending range; drained after compiled block / iced step → selective `invalidate_code_range`.
- **No W on X:** sticky/TLB/pin/`host_span` write never soft-translate onto executable pages (forces slow path + note).
- **Free/decommit:** invalidate code over freed span; edge IC cleared with chain on any drop.
- **code_pages** index for O(1) data-write fast-reject.
- Docs: [`docs/phase4-code-invalidation.md`](docs/phase4-code-invalidation.md).

**DoD:** Unit tests S1–S6 green; micro-suite green; `long_loop` not regressed. ✅

---

## Phase 5 – Guest Stub Expansion ✅

**Goal:** Reduce host‑stop frequency by implementing more common WinAPI calls as in‑guest machine‑code stubs.

**Correctness policy (Microsoft Learn):** Only plant guest stubs when the body can honour the documented API contract for the subset WIE models. **Do not** accelerate with “always success” simplifications that damage real apps (e.g. `VirtualProtect` with NULL `lpflOldProtect` must fail; `VirtualQuery` needs real regions; `LocalAlloc`/`GlobalAlloc` keep MOVEABLE/lock semantics on host).

**In-guest (Phase 5 + prior):**

- `GetACP`, `GetOEMCP`, `GetSystemDefaultLangID`, `GetUserDefaultLangID`
- `GetCurrentProcessId`, `GetCurrentThreadId`, `GetCurrentProcess`, `GetProcessHeap`
- `GetTickCount`, `GetLastError` / `SetLastError`, FLS, CS enter/leave/delete
- `GetCommandLineA` / `GetCommandLineW` (published env buffers)
- `GetCurrentDirectoryW` (guest cwd blob; Learn return-value rules)
- `GetSystemMetrics`, `GetSysColor`, `GetSysColorBrush`, `GetDesktopWindow` (fixed guest desktop tables/handles)
- `GetFileSize` / `SetFilePointer` via guest I/O table (pre-existing accelerator)

**Stays on host (intentionally):**

- `VirtualProtect` / `VirtualQuery` — host fixed to fail on NULL `lpflOldProtect` (Learn); full protect/query via RegionTable is Phase 3
- `LocalAlloc` / `GlobalAlloc` / Free — MOVEABLE / lock / size-0 discard must not be faked as plain `HeapAlloc`
- Module APIs (`GetModuleHandle*`, `GetProcAddress`, `LoadLibrary*`)

**Implementation:**

- `GuestStubConfig` + guest data page (metrics, colors, cwd) in `RuntimeMemoryLayout`
- Extended `GuestStubKind` / `plant_guest_stubs` / expanded OOL helper budget
- Host `VirtualProtect` corrected for NULL `lpflOldProtect`

**DoD:** Micro‑suite still passes; clippy clean; host‑stop drop on workloads that call the accelerated set (track C). Pure loops unchanged.

**Status (2026-07-18):** Done under Microsoft Learn policy above.

---

## Phase 5.5 – Neon Soft-Accel & Cranelift ISA Tuning ✅

**Goal:** ARM64 Neon + Cranelift tuning **before** idle-park (Phase 6).

### 5.5.A SSE2 → SIMD IR + lazy XMM sync ✅

- `XmmSlot` 16-byte aligned bank; CLIF `I8X16` load/store when `WIE_JIT_SIMD≠0`.
- Bitwise on `I8X16`; scalar/packed FP via native `fadd`/`fmul`/… (helpers only if SIMD off).
- Selective entry (`xmm_live_mask`) / exit (`xmm_dirty_bits` + `xmm_may_def_mask`).

### 5.5.B Set-associative Neon TLB ✅

- 16 sets × 4 ways: `TlbBucket` + `TlbBucketAux` (full `u64` tags).
- Neon tag broadcast/compare on aarch64; scalar fallback / `WIE_TLB_NEON=0`.

### 5.5.C Inline small REP MOVS/STOS ✅

- Dual-path: soft `wie_jit_host_span` + unrolled `I8X16` (16–64 B) else `wie_jit_string`.
- Kill-switch: `WIE_STRING_INLINE=0`.

### 5.5.D Cranelift Apple Silicon config ✅

- `opt_level=speed` (`WIE_JIT_OPT`), verifier under test / `WIE_JIT_VERIFY`, no unwind/spectre-heap.
- macOS PAC B-key re-asserted on ISA builder.

**Docs:** [`docs/phase5.5-neon-cranelift.md`](docs/phase5.5-neon-cranelift.md).

**DoD:** clippy `-D warnings`; micro-suite green; kill-switches work; pure GPR XMM skip preserved. ✅

**Status (2026-07-18):** Done.

---

## Phase 6 – Idle CPU Management ✅

**Goal:** Prevent unnecessary host CPU consumption when the guest is waiting.

**Status (2026-07-18):** Done (MVP). Docs: [`docs/phase6-idle.md`](docs/phase6-idle.md).

### 6.1 Idle Policy Design ✅

- States: `Running` | `HostCall` | `Parked` | `Exit` (logical; profiled via park counters).
- Park only on blocking waits: `Sleep(n>0)`, empty `GetMessage` under persistent `YieldOnIdle` + `IdlePolicy::Park`.
- Never park on pure guest spin loops (e.g., `while(1)` / `long_loop`).
- `WaitForSingleObject` / `MsgWait*` deferred (no full wait graph in MVP).

### 6.2 Implementation ✅

- `wie_winapi::idle::{IdlePolicy, apply_sleep, apply_message_park}` + env knobs.
- `Sleep` **not** planted as guest stub; host `handle_sleep` parks under `WIE_IDLE=park` or legacy `WIE_HOST_SLEEP=1`.
- Persistent `run` outer loop parks on `WaitingForMessage` and re-enters GetMessage (`WIE_IDLE_PARK_MS` / `WIE_IDLE_MAX_PARKS`).
- Micros: default `WIE_IDLE=yield` + `ExitOnIdle` (deterministic, no long sleeps).

**DoD:** Idle message path parks host (low CPU); `long_loop` still ~100%; micro-suite green; clippy `-D warnings`. ✅

---

## Phase 7 – Hardening & Cutover ✅

**Status (2026-07-18):** Done. Docs: [`docs/phase7-hardening.md`](docs/phase7-hardening.md), [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

### 7.1 Invalidation Rules ✅

- Core rules in **Phase 4.x** ([`docs/phase4-code-invalidation.md`](docs/phase4-code-invalidation.md)).
- Phase 7 residual: multi-region protect/free stress, SMC across page boundary, optional `FlushInstructionCache` → selective/full Ready drop.

**DoD:** Self‑modifying code and `VirtualProtect` tests pass; stress units green. ✅

### 7.2 Stress Testing ✅

- High guest VA, wrap-around map reject, ≥1 GiB RESERVE demand-zero, anti-Wine host≠guest on all backends.
- Single-threaded guest model (no concurrent guest writers); dual-backend oracle remains Phase 1.

**DoD:** No identity map; process survives large reserve / pressure paths. ✅

### 7.3 Default Flip ✅

- Default `WIE_MEM=mmap`; keep `hash` and `hybrid` as explicit overrides (Phase 7).
- README: mmap is storage throughput / soft arenas — **not** idle CPU (Phase 6).

**DoD:** Default path is mmap; `hash` / `hybrid` continue to work. ✅  
**Superseded:** great cleanup removes `hash` / `hybrid` entirely (mmap sole path).

### 7.4 Rollback Playbook ✅

- [`docs/RUNBOOK.md`](docs/RUNBOOK.md): symptoms → `WIE_CPU=iced`, idle/JIT knobs (no mem-backend switch).
- `WIE_RUNTIME_PROFILE=1` reports `mem_backend=mmap` + `idle_policy`.

**DoD:** Regressions mitigable by env. ✅

---

## Great cleanup (post Phase 7) ✅

**Goal:** Delete dual-backend scaffolding before multithreading so there is one memory path and a small CLI surface.

- Remove `HashMapBackend`, `HybridBackend`, `WIE_MEM`, and the `Storage` enum; `GuestMemory` owns `MmapArenaBackend` only.
- Oracle tests compare `mmap_arena` vs per-page `mmap_page` (test-only).
- CLI compressed to **`inspect` / `run` / `trace`** (`run-micro` / `entry-trace` aliases retained).
- Docs/RUNBOOK updated: no hash/hybrid rollback path.

**DoD:** Workspace tests + micro-suite green on mmap-only; no `WIE_MEM` knobs.

---

## Parallel Workstreams

- **Performance (Memory)** – Phases 0–4, 7 (mostly independent).
- **Idle CPU** – Phase 6 (can be started early, as it doesn’t depend on mmap).
- **API Acceleration** – Phase 5 (can be done in parallel with memory work).

---

## Non‑Goals (explicitly out of scope)

- Identity mapping of guest addresses to host addresses.
- Wine‑style 0–4 GB address reservation.
- Full SIGSEGV‑based memory fault handling (separate future epic).
- 32‑bit PE or WoW64 support.
- File‑backed `mmap` for PE images (copy‑based is sufficient for now).

---

_This roadmap is a living document. Items may be reprioritised based on real‑world performance data and community feedback._
