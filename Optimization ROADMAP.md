# WIE Roadmap

This roadmap outlines the planned evolution of WIE’s memory management, JIT optimizations, API acceleration, and CPU‑idle policies. The goal is to improve performance and reduce host CPU usage while preserving correctness and avoiding the pitfalls of traditional Wine‑style identity mapping.

---

## Guiding Principles

1. **Guest VA ≠ Host VA** – Always use a soft translation layer (region table, radix tree, TLB). No `mmap(addr = guest_va)`.
2. **Dual‑backend safety** – Keep the existing `HashMap`‑based storage as a fallback (`WIE_MEM=hash`) while developing the new `mmap` backend.
3. **Parity first, speed second** – The entire micro‑suite must remain green before any JIT fast‑path is enabled.
4. **Targeted arenas** – Only map critical memory regions (heap, stack, image, file cache). Do **not** reserve a fixed 4 GB low address space.
5. **Incremental, self‑contained PRs** – Each phase is a separate, reviewable step.

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

**Status (2026-07-18):** Default `WIE_MEM=hybrid` (threshold 64 KiB → arena). Force `hash` / `mmap` / `hybrid`. `GuestRegion.host_base` filled for arena-backed layout regions. Details: [`docs/phase2-mmap-backend.md`](docs/phase2-mmap-backend.md).

---

## Phase 3 – Permissions and Dynamic Mapping

### 3.1 Software + mprotect Dual Protection

- Keep software permission checks (as today) and optionally apply `mprotect` for host‑side enforcement.
- Do **not** rely on host faults for correctness yet.

**DoD:** Reads/writes to unmapped or read‑only regions produce the same errors as the `HashMap` backend.

### 3.2 VirtualAlloc / Free / Protect Support

- Route `KERNEL32!VirtualAlloc`, `VirtualFree`, `VirtualProtect` through `RegionTable` and the mmap backend.
- Support committing/decommitting within arenas.

**DoD:** `winapi_heap` and custom allocation tests pass with `WIE_MEM=mmap`.

### 3.3 PE Section Mapping

- Load PE sections using mmap arenas (copy‑based, not file‑backed initially).
- Apply section permissions via `mprotect`.

**DoD:** `run-micro` on all PE files shows no regressions.

---

## Phase 4 – JIT Optimisations

### 4.1 Region‑Direct Load/Store Path

- In JIT helpers, if the accessed address belongs to a hot mmap region (stack, heap), compute `host_ptr` without a full TLB/radix walk.
- Keep the existing multi‑way TLB as a fallback for other addresses.

**DoD:** Faster `wie_jit_load/store` on memory‑intensive blocks; micro‑benchmarks show improvement.

### 4.2 Stack‑Relative Inlining (optional but high‑value)

- When the stack region is pinned for the block’s lifetime, lower `RSP`/`RBP`‑relative memory accesses to direct host pointer arithmetic in Cranelift IR, avoiding helper calls entirely.

**DoD:** Pure GPR blocks with stack traffic run measurably faster; no correctness regressions on edge cases.

### 4.3 Accelerated String Operations (REP MOVS/STOS/SCAS/CMPS)

- Replace the current per‑page helper loop with bulk `memcpy`/`memmove`/`memset` from `libc` (optimised for Apple Silicon) for contiguous ranges.
- Use NEON‑aware implementations for comparisons and scans.

**DoD:** `cpu_string` and any guest using large `memcpy` see significant speed‑up; correctness for overlapping ranges is preserved.

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

## Phase 6 – Idle CPU Management

**Goal:** Prevent unnecessary host CPU consumption when the guest is waiting.

### 6.1 Idle Policy Design

- Define states: `Running` | `HostCall` | `Parked` | `Exit`.
- Park only on blocking waits: `Sleep`, `WaitForSingleObject`, `GetMessage`/`MsgWaitForMultipleObjects` with an empty queue, etc.
- Never park on pure guest spin loops (e.g., `while(1)`).

### 6.2 Implementation

- Implement host thread parking via `thread::sleep` for `Sleep` and timed waits.
- Extend the existing `GetMessage` yield to actually park when `YieldOnIdle` policy is active.
- Add environment knobs (`WIE_IDLE`) to optionally insert short sleeps between slices for user‑controlled responsiveness.

**DoD:** An idle GUI application (e.g., one waiting for messages) uses < 5–15% CPU; `long_loop` still runs at ~100% (correct behaviour).

---

## Phase 7 – Hardening & Cutover

### 7.1 Invalidation Rules

- Unify invalidation of TLB, JIT cache, and region table when memory protection changes or code is written.
- Ensure stale host pointers are never used after `VirtualFree` or `Unmap`.

**DoD:** Self‑modifying code and `VirtualProtect` tests pass.

### 7.2 Stress Testing

- Test high‑VA addresses, wrap‑around, large allocations (> 1 GB), and concurrent host reads.
- Verify that no fixed low‑address mappings are used (anti‑Wine checklist).

**DoD:** No address space conflicts; process survives `mmap` pressure.

### 7.3 Default Flip

- Make `WIE_MEM=mmap` the default; keep `hash` available for one release as a fallback.
- Update `README.md` with performance notes, clarifying that mmap improves memory throughput but **does not** reduce idle CPU.

**DoD:** CI uses `mmap` by default; `hash` builds continue to work.

### 7.4 Rollback Playbook

- Document a one‑page `RUNBOOK` with symptoms and remedial actions (`WIE_MEM=hash`, `WIE_CPU=iced`).
- Include a startup log line showing the active memory backend when `WIE_RUNTIME_PROFILE=1`.

**DoD:** Any regressions can be quickly mitigated by the user.

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
