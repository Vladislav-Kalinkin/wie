# MT Per-Thread Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the single-CpuEngine bottleneck by splitting `JitCpu` into per-thread engines that share a compiled-code cache.

**Architecture:** `JitCpu` is split into `JitShared` (Arc, one per process) and `PerThreadJitState` (one per guest thread). The runtime creates per-thread engines instead of serializing on `Mutex<Box<dyn CpuEngine>>`. The block cache is behind `RwLock` for concurrent reads. Chain tables are per-thread to avoid locking on the JIT fast path.

**Tech Stack:** Rust, Cranelift JIT, iced-x86, Arc/RwLock/Mutex for interior mutability.

---

## Background — Current Architecture

```
ProcessResources::SharedProcess
  ├── engine: Mutex<Box<dyn CpuEngine>>   // one JitCpu, serialized
  └── winapi: Mutex<WinApiState>

JitCpu (all fields in one struct)
  ├── iced: IcedCpu  (regs + GuestMemory)
  ├── engine: JitEngine  (Cranelift module)
  ├── cache: HashMap<u64, CacheEntry>
  ├── chain_ids: HashMap<u64, FuncId>
  ├── code_pages: HashMap<u64, u32>
  ├── fast_api: Vec<(u64, FastApiKind)>
  ├── stats: JitStats
  ├── tlb_sets/aux, tlb_hot_*, sticky_*   // TLB
  ├── pins, pins_gen                       // region pins
  ├── chain_va, chain_fn                   // block chain table
  ├── edge_ic_va/fn/rr                     // inline cache
  └── shadow_sp, shadow_ret                // return predictor
```

## Target Architecture

```
JitShared (Arc, shared across all threads)
  ├── engine: JitEngine                    // Cranelift module (read-only after init)
  ├── mem: Mutex<GuestMemory>              // page tables + backend (write-cold)
  ├── cache: RwLock<HashMap<u64, CacheEntry>>
  ├── chain_ids: RwLock<HashMap<u64, FuncId>>
  ├── code_pages: Mutex<HashMap<u64, u32>>
  ├── fast_api: Vec<(u64, FastApiKind)>    // read-only after init
  └── stats: JitStats (atomic fields)

PerThreadJitState (one per guest thread, owned by host thread)
  ├── regs: RegFile                        // GPR/XMM/RIP/RFLAGS
  ├── hooks: Option<HookWindow>
  ├── rip_trace*                           // diag
  ├── iced_steps: u64                      // diag
  ├── tlb_sets/aux, tlb_hot_*, sticky_*   // TLB (hot-mutated per thread)
  ├── pins, pins_gen                       // region pins
  ├── chain_va, chain_fn                   // 8 KB per-thread chain table (no lock)
  ├── edge_ic_va/fn/rr                     // inline cache (per-thread)
  └── shadow_sp, shadow_ret                // return predictor (per-thread)

ProcessResources (no Mutex<CpuEngine>)
  ├── engine: Box<dyn CpuEngine>           // primary thread's JitCpu
  └── winapi: Mutex<WinApiState>           // still shared

Worker host thread:
  └── owns Box<dyn CpuEngine>              // its own JitCpu, same Arc<JitShared>
```

### Key invariants
- `CpuEngine` trait **unchanged** — each thread has its own `Box<dyn CpuEngine>`
- `JitCpu.mem` behind `Mutex` — only on interpreter fallback + setup paths (cold)
- Chain table per-thread — no locking on `wie_jit_chain_lookup` hot path
- Block cache behind `RwLock` — concurrent reads, exclusive writes on compile
- `GuestMemory` needs `unsafe impl Send` for `Mutex<GuestMemory>` (same pattern as `unsafe impl Send for JitCpu`)

---

## Phase 1: Structural Split (NFC — No Functional Change)

Extract `JitShared` and `PerThreadJitState` from `JitCpu`. Everything still runs on one engine — just reorganised fields.

### Task 1.1: Create JitShared struct

**Files:**
- Modify: `crates/wie-cpu/src/jit/mod.rs`

**New struct in `jit/mod.rs`:**

```rust
/// Shared JIT state: Cranelift module + compilation cache. Thread-safe behind
/// internal locks. One instance per process, shared via Arc across all engines.
pub struct JitShared {
    /// Cranelift JIT module + codegen context (read-only after init).
    pub engine: JitEngine,
    /// Guest memory (page tables, mmap backend). Mutex: only interpreter
    /// fallback + init need it; JIT hot path uses TLB → host pointers.
    pub mem: Mutex<GuestMemory>,
    /// Guest entry VA → CacheEntry. RwLock: concurrent reads from executing
    /// threads, exclusive write from compiler.
    pub cache: RwLock<HashMap<u64, CacheEntry>>,
    /// FuncId index for block chaining (parallel to cache).
    pub chain_ids: RwLock<HashMap<u64, FuncId>>,
    /// Guest page keys covered by at least one Ready block (SMC tracking).
    pub code_pages: Mutex<HashMap<u64, u32>>,
    /// Fake-API VA → UCRT kind (set once at init, read-only).
    pub fast_api: Vec<(u64, FastApiKind)>,
    /// Diagnostic counters. AtomicU64 fields — safe for concurrent update.
    pub stats: JitStats,
}
```

**New enum or type for atomic stats (replace `saturating_add` with `AtomicU64`):**

```rust
// In JitCpu, stats fields like:
//   code_invs: u64,
// Change to AtomicU64 in JitShared:
pub code_invs: AtomicU64,
pub chain_hits: AtomicU64,
pub chain_misses: AtomicU64,
// etc. — whichever stats fields exist
```

- [ ] Step 1: Read the full `JitCpu` struct definition and `JitStats` struct
- [ ] Step 2: Define `JitShared` with fields moved from `JitCpu`
- [ ] Step 3: Add `AtomicU64` versions of stats fields
- [ ] Step 4: Read `JitEngine` to confirm it's `Send` + read-only after init

### Task 1.2: Create PerThreadJitState struct

```rust
/// Per-thread JIT execution state: registers, TLB, chain table, shadow stack.
/// One instance per guest thread, owned by the host thread that runs it.
pub struct PerThreadJitState {
    pub regs: RegFile,
    pub hooks: Option<HookWindow>,
    // RIP ring buffer (diag)
    pub rip_trace: [u64; 32],
    pub rip_trace_i: usize,
    pub rip_trace_n: usize,
    pub iced_steps: u64,
    // TLB — 4-way set-associative software TLB
    pub tlb_sets: [TlbBucket; TLB_SETS],
    pub tlb_aux: [TlbBucketAux; TLB_SETS],
    // Single-page sticky TLB
    pub tlb_hot_page: u64,
    pub tlb_hot_ptr: *mut u8,
    pub tlb_hot_prot: u64,
    pub tlb_hot_gen: u64,
    // Multi-way sticky pages
    pub sticky_page: [u64; STICKY_WAYS],
    pub sticky_ptr: [*mut u8; STICKY_WAYS],
    pub sticky_prot: [u64; STICKY_WAYS],
    pub sticky_gen: [u64; STICKY_WAYS],
    pub sticky_rr: u64,
    // Region-direct pins
    pub pins: [MemPin; PIN_SLOTS],
    pub pins_gen: u64,
    // Block chain table (per-thread to avoid locking)
    pub chain_va: Box<[u64; CHAIN_SLOTS]>,
    pub chain_fn: Box<[u64; CHAIN_SLOTS]>,
    // Edge inline cache
    pub edge_ic_va: [u64; lower::EDGE_IC_SLOTS],
    pub edge_ic_fn: [u64; lower::EDGE_IC_SLOTS],
    pub edge_ic_rr: u64,
    // Shadow return stack
    pub shadow_sp: u64,
    pub shadow_ret: [u64; lower::SHADOW_DEPTH],
}
```

Note: `IcedCpu` is **dissolved** — its `RegFile` moves to `PerThreadJitState.regs`, its `GuestMemory` moves to `JitShared.mem`, its hooks move to `PerThreadJitState.hooks`.

- [ ] Step 1: Define `PerThreadJitState` with all per-thread fields listed above
- [ ] Step 2: Move `invalidate_tlb()`, `invalidate_chain_and_shadow()`, `clear_compiled()` methods onto `PerThreadJitState`

### Task 1.3: Refactor JitCpu to hold shared + thread

```rust
pub struct JitCpu {
    pub shared: Arc<JitShared>,
    pub thread: PerThreadJitState,
    /// Generation seen at last `run_compiled` (diag, was on JitCpu directly).
    last_mem_gen: u64,
}
```

- [ ] Step 1: Change `JitCpu` fields to `shared: Arc<JitShared>` + `thread: PerThreadJitState`
- [ ] Step 2: Update `JitCpu::new()` to create both
- [ ] Step 3: Add `new_shared(shared: Arc<JitShared>) -> Self` for per-thread construction
- [ ] Step 4: Route all `self.iced.field` through `self.thread.field`
- [ ] Step 5: Route all `self.cache`, `self.engine`, etc. through `self.shared.*`
- [ ] Step 6: Route `self.iced.mem.*` through `self.shared.mem.lock()`

- [ ] Step 7: Build and fix all compile errors

```bash
cargo build --workspace 2>&1 | head -80
```

Repeat until clean.

### Task 1.4: Update CpuEngine trait methods on JitCpu

Every method on `impl CpuEngine for JitCpu` needs its body updated.

**Pattern for methods needing GuestMemory:**

```rust
fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
    let mut mem = self.shared.mem.lock().unwrap();
    mem.write(address, bytes)?;
    drop(mem);  // release before drain_pending_code_writes
    // drain_pending_code_writes should now operate on self.shared.code_pages
    self.drain_pending_code_writes();
    Ok(())
}
```

**`drain_pending_code_writes`** — currently reads `self.iced.mem.pending_write_pages`. Change to read `self.shared.mem.lock().pending_write_pages`.

**Interpreter fallback in `run_until_stop`**:

```rust
// When JIT can't compile a block and falls back to iced:
let mut mem = self.shared.mem.lock().unwrap();
// Hold the lock for the entire interpreted run (budget-bounded)
self.thread.run_interpreted(&mut mem, start_rip, budget, ...)?;
// drop(mem) on return
```

Create a helper `PerThreadJitState::run_interpreted(&mut self, mem: &mut GuestMemory, ...)` that does what `IcedCpu::run_until_stop` does, but with an external `GuestMemory` reference.

- [ ] Step 1: Update `mem_write`, `mem_read`, `host_span`, `mem_generation` to lock `self.shared.mem`
- [ ] Step 2: Update `virtual_alloc`, `virtual_free`, `virtual_protect`, `virtual_query`
- [ ] Step 3: Update `flush_instruction_cache`, `mem_map_image`
- [ ] Step 4: Create `PerThreadJitState::run_interpreted(&mut self, mem: &mut GuestMemory, ...)` 
- [ ] Step 5: Update `run_until_stop` to use it
- [ ] Step 6: Build and test

```bash
cargo build --workspace 2>&1
cargo test --workspace 2>&1
```

### Task 1.5: Update IcedCpu — remove GuestMemory ownership

`IcedCpu` currently owns `mem: GuestMemory`. Since `GuestMemory` moves to `JitShared`, `IcedCpu` dissolves into `PerThreadJitState`. But we may want to keep the interpreter logic clean.

**Option A (recommended):** Remove `IcedCpu` struct entirely. Move its logic into methods on `PerThreadJitState` that take `&mut GuestMemory`.

**Option B:** Keep `IcedCpu` but with `mem: &GuestMemory` (lifetime parameter). Problem: `Box<dyn CpuEngine>` doesn't carry lifetime.

Go with **Option A**.

Files to touch:
- `crates/wie-cpu/src/iced_cpu.rs` — move methods to `PerThreadJitState`
- `crates/wie-cpu/src/lib.rs` — remove `pub use iced_cpu::IcedCpu;`
- `crates/wie-cpu/src/jit/mod.rs` — inline iced logic or re-export

- [ ] Step 1: Read `iced_cpu.rs` — identify all methods that need migration
- [ ] Step 2: Move `run_until_stop` logic to `PerThreadJitState::run_interpreted`
- [ ] Step 3: Move `mem_read`/`mem_write`/etc. helpers (or just route through JitShared)
- [ ] Step 4: Delete or gut `IcedCpu`
- [ ] Step 5: Build

```bash
cargo build --workspace 2>&1
```

### Task 1.6: Update tests and benchmarks

- [ ] Step 1: Fix any test code that constructs `IcedCpu` or accesses `JitCpu` fields directly
- [ ] Step 2: Run test suite

```bash
cargo test --workspace 2>&1
```

- [ ] Step 3: Run micro-test suite

```bash
scripts/run-micro-suite.sh 2>&1
```

- [ ] Step 4: Commit Phase 1

```bash
git add -A && git commit -m "refactor(wie-cpu): split JitCpu into JitShared + PerThreadJitState

Structural refactor (NFC): extract JitShared (compilation cache,
Cranelift module, GuestMemory) and PerThreadJitState (registers,
TLB, chain table, shadow stack) from JitCpu. JitCpu now holds
Arc<JitShared> + PerThreadJitState. GuestMemory moved to JitShared
behind Mutex. IcedCpu dissolved — interpreter logic in PerThreadJitState.

Still serialized on process mutex — no functional change."
```

---

## Phase 2: Concurrent Cache

Make `cache`, `chain_ids`, and `code_pages` safe for concurrent access.

### Task 2.1: Make block cache concurrent

- [ ] Step 1: Change `CacheEntry::Hot { visits: u32 }` to `visits: AtomicU32`

```rust
// In CacheEntry:
Hot {
    visits: AtomicU32,
    thr: u32,
},
```

- [ ] Step 2: Update `step_one` hot-counter increment

```rust
// Before: cache_entry.visits += 1;
// After:
if let CacheEntry::Hot { visits, thr } = &mut entry {
    let v = visits.fetch_add(1, Ordering::Relaxed) + 1;
    if v >= *thr {
        // promote to compile
    }
}
```

- [ ] Step 3: Change `cache: RwLock<HashMap<u64, CacheEntry>>` in `JitShared`
- [ ] Step 4: Update all reads: `self.shared.cache.read().unwrap().get(&rip)`
- [ ] Step 5: Update all writes: `self.shared.cache.write().unwrap().insert(rip, entry)`
- [ ] Step 6: Update `clear_compiled`: `self.shared.cache.write().unwrap().clear()`
- [ ] Step 7: Handle the `step_one` read-then-write-promote pattern (read lock → decide → write lock)

**Pattern for read-then-write-promote:**

```rust
let should_compile = {
    let cache = self.shared.cache.read().unwrap();
    cache.get(&rip).map_or(false, |entry| {
        if let CacheEntry::Hot { visits, thr } = entry {
            visits.load(Ordering::Relaxed) >= *thr
        } else { false }
    })
};
if should_compile {
    let mut cache = self.shared.cache.write().unwrap();
    // re-check after upgrading
    if let Some(CacheEntry::Hot { visits, thr }) = cache.get(&rip) {
        if visits.load(Ordering::Relaxed) >= *thr {
            // compile
            cache.insert(rip, CacheEntry::Ready(...));
        }
    }
}
```

- [ ] Step 8: Build and test

```bash
cargo build --workspace && cargo test --workspace
```

### Task 2.2: Make chain_ids concurrent

- [ ] Step 1: Change `chain_ids: RwLock<HashMap<u64, FuncId>>` in `JitShared`
- [ ] Step 2: Update all reads and writes
- [ ] Step 3: Build

```bash
cargo build --workspace
```

### Task 2.3: Make code_pages concurrent

- [ ] Step 1: Change `code_pages: Mutex<HashMap<u64, u32>>` in `JitShared`
- [ ] Step 2: Update `invalidate_code_range`, `insert_ready`, `clear_compiled`
- [ ] Step 3: Build and test

```bash
cargo build --workspace && cargo test --workspace
```

### Task 2.4: Update `drain_pending_code_writes` for shared pending_write_pages

Currently `drain_pending_code_writes` reads `self.iced.mem.pending_write_pages`. Since guest memory is now behind `self.shared.mem.lock()`, we need:

```rust
fn drain_pending_code_writes(&mut self) {
    let pending = {
        let mut mem = self.shared.mem.lock().unwrap();
        // take pending pages
        std::mem::take(&mut mem.pending_write_pages)
    };
    if pending.is_empty() { return; }
    // process pages and invalidate code
    for page_key in pending {
        let va = page_key << 12;
        self.shared.invalidate_code_range(va, 0x1000);
    }
}
```

Or: pull `pending_write_pages` out of `GuestMemory` and put it directly in `JitShared` behind a separate lock (fewer lock cycles).

- [ ] Step 1: Move `pending_write_pages: Mutex<Vec<u64>>` and `pending_write_overflow: AtomicBool` to `JitShared`
- [ ] Step 2: Update `GuestMemory::write` (which currently pushes to pending_write_pages) — accept a `&Mutex<Vec<u64>>` parameter or use a callback
- [ ] Step 3: Update `drain_pending_code_writes` to read from `self.shared.pending_write_pages`
- [ ] Step 4: Build and test

```bash
cargo build --workspace && cargo test --workspace
```

### Task 2.5: Commit Phase 2

```bash
git add -A && git commit -m "refactor(wie-cpu): make cache/chain_ids/code_pages concurrent

Cache behind RwLock with AtomicU32 visits counter. chain_ids behind
RwLock. code_pages and pending_write_pages behind Mutex. Chain table
stays per-thread (no locking on JIT hot path)."
```

---

## Phase 3: Per-Thread Engines in Runtime

Update `wie-runtime` to create per-thread `JitCpu` instances instead of serializing on one.

### Task 3.1: Add `JitCpu::new_shared` constructor

- [ ] Step 1: Add constructor to `JitCpu`

```rust
impl JitCpu {
    /// Create a per-thread engine sharing the compilation cache + guest memory.
    pub fn new_shared(shared: Arc<JitShared>) -> Self {
        Self {
            shared,
            thread: PerThreadJitState::new(),
            last_mem_gen: 0,
        }
    }
}
```

- [ ] Step 2: Build

```bash
cargo build --workspace
```

### Task 3.2: Update SharedProcess in wie-runtime

File: `crates/wie-runtime/src/mt_runtime.rs`

**Current:**
```rust
pub(crate) struct SharedProcess {
    pub engine: Mutex<Box<dyn CpuEngine>>,
    pub winapi: Mutex<WinApiState>,
}
```

**New:**
```rust
pub(crate) struct SharedProcess {
    pub shared_jit: Arc<JitShared>,
    pub winapi: Mutex<WinApiState>,
}
```

**Update `ProcessResources`:**
- Remove `local_engine: Option<Box<dyn CpuEngine>>` — primary thread keeps its own engine separately
- Remove `ensure_shared()` — no more engine to promote
- Add `shared_jit: Option<Arc<JitShared>>` — set on first `CreateThread`

Actually, even simpler: create `Arc<JitShared>` during `ProcessResources::new()` by extracting it from the engine, and keep the engine for the primary thread.

```rust
pub(crate) struct ProcessResources {
    /// Primary thread's dedicated engine.
    pub engine: Box<dyn CpuEngine>,
    /// Shared WinAPI state.
    pub local_winapi: Option<WinApiState>,
    /// Shared JIT compilation cache + guest memory (None before any CreateThread).
    pub shared_jit: Option<Arc<JitShared>>,
    /// Shared WinAPI state (after first CreateThread).
    pub shared_winapi: Option<Arc<Mutex<WinApiState>>>,
    ...
}
```

Hmm, this changes the structure more than needed. Let me keep it simpler:

- `ProcessResources` holds `engine: Box<dyn CpuEngine>` (always, for the primary thread)
- `ProcessResources` holds `shared_jit: Arc<JitShared>` (extracted from engine during init)
- `SharedProcess` holds `shared_jit: Arc<JitShared>` + `winapi: Mutex<WinApiState>` — no engine mutex

The primary thread's engine never goes into a mutex. Each host thread owns its own.

- [ ] Step 1: Extract `Arc<JitShared>` from the engine during session init
- [ ] Step 2: Update `ProcessResources::new()` to take both engine and shared_jit
- [ ] Step 3: Change `SharedProcess` — remove `Mutex<Box<dyn CpuEngine>>`, add `shared_jit: Arc<JitShared>`
- [ ] Step 4: Build

```bash
cargo build --workspace 2>&1
```

### Task 3.3: Update ProcessResources methods

- [ ] Step 1: `lock_pair()` — remove engine mutex lock, return primary engine directly
- [ ] Step 2: `with_mut()` — remove engine mutex code path
- [ ] Step 3: Build

### Task 3.4: Update worker_main

File: `crates/wie-runtime/src/mt_runtime.rs`

**Current worker:**
```rust
fn worker_main(shared: Arc<SharedProcess>, ...) {
    loop {
        let mut eng = shared.engine.lock().unwrap();
        // ...
        eng.run_until_stop(...);
        // ...
    }
}
```

**New worker:**
```rust
fn worker_main(shared: Arc<SharedProcess>, ...) {
    let shared_jit = Arc::clone(&shared.shared_jit);
    let mut eng = JitCpu::new_shared(shared_jit);
    let mut state = WinApiState::new_per_thread();  // if needed

    loop {
        // No engine lock needed — this thread owns its engine
        eng.run_until_stop(...)?;
        // API dispatch
        dispatch_winapi(eng, state, ...)?;
    }
}
```

- [ ] Step 1: Rewrite `worker_main` to create per-thread engine
- [ ] Step 2: Remove engine mutex acquisition
- [ ] Step 3: Update `activate_thread`/`deactivate_thread` — with per-thread engines, thread context switches are no-ops (one guest thread per engine)

### Task 3.5: Simplify activate_thread / deactivate_thread

Since each host thread binds to one guest thread permanently:

```rust
fn activate_thread(engine: &mut dyn CpuEngine, state: &mut WinApiState, tid: u32) {
    // The engine is permanently assigned to this tid; no context save/restore.
    state.threads.activate(tid);
}

fn deactivate_thread(engine: &mut dyn CpuEngine, state: &mut WinApiState, tid: u32) {
    state.threads.save_active();
}
```

No more `thread_cpu` save/restore, no more `on_thread_switch`, no more register snapshot on deactivate.

- [ ] Step 1: Simplify `activate_thread` — remove engine context save/restore
- [ ] Step 2: Simplify `deactivate_thread` — just bookkeeping
- [ ] Step 3: Remove `thread_cpu` HashMap from sync state if it's no longer used elsewhere
- [ ] Step 4: Build and test

```bash
cargo build --workspace && cargo test --workspace
```

### Task 3.6: Update session run loop

File: `crates/wie-runtime/src/session.rs`

The primary run loop currently calls `self.process.with_mut(|eng, st| ...)` which returns a `ProcessPairGuard`. Simplify this — the primary thread has direct ownership of its engine.

- [ ] Step 1: Read the primary run loop (around line 1185)
- [ ] Step 2: Replace `self.process.with_mut()` with direct engine access
- [ ] Step 3: Remove `ProcessPairGuard` enum (no longer needed)
- [ ] Step 4: Build

### Task 3.7: Commit Phase 3

```bash
git add -A && git commit -m "refactor(wie-runtime): per-thread engines, remove engine mutex

Each guest thread now owns its own JitCpu sharing a common JitShared
(compilation cache + GuestMemory). worker_main creates per-thread
engines. activate/deactivate simplified (no engine context switch).
SharedProcess no longer holds Mutex<Box<dyn CpuEngine>>."
```

---

## Phase 4: Verification

### Task 4.1: Run test suite

- [ ] Step 1: Run all Rust unit tests

```bash
cargo test --workspace 2>&1
```

- [ ] Step 2: Run micro-test suite

```bash
scripts/run-micro-suite.sh 2>&1
```

- [ ] Step 3: Run 7za single-threaded

```bash
./scripts/fetch-7za.sh  # if not already fetched
cargo run -- run micro-exes/out/7za.exe -y a /tmp/test.7z /tmp/testdir 2>&1
```

- [ ] Step 4: Run 7za multi-threaded (`-mmt`)

```bash
cargo run -- run micro-exes/out/7za.exe -y -mmt a /tmp/test-mt.7z /tmp/testdir 2>&1
```

### Task 4.2: Benchmark comparison

- [ ] Step 1: Measure 7za -mmt performance before/after

```bash
# On main branch (baseline):
git stash && git checkout main
cargo build --release && time cargo run --release -- run micro-exes/out/7za.exe -y -mmt a /tmp/baseline.7z /tmp/testdir

# On mt-per-thread-engine branch:
git checkout mt-per-thread-engine
cargo build --release && time cargo run --release -- run micro-exes/out/7za.exe -y -mmt a /tmp/mt.7z /tmp/testdir
```

- [ ] Step 2: Measure thread contention reduction with runtime profiling

```bash
WIE_RUNTIME_PROFILE=1 cargo run -- run 7za.exe -y -mmt a /tmp/profile.7z /tmp/testdir
```

### Task 4.3: Final commit

```bash
git add -A && git commit -m "feat: per-thread JIT engines with shared compilation cache

Implements Option 2 from architecture review: each guest thread
gets its own CpuEngine with per-thread TLB/pins/chain table, sharing
a common compiled-code cache via Arc<JitShared>. Removes the
Mutex<Box<dyn CpuEngine>> bottleneck that serialized all guest threads."
```

---

## Riskiest Areas

1. **Chain table correctness with per-thread access** — the chain table is populated by the compiler (shared, behind RwLock) and read by all threads. The compiled function pointers in `chain_fn` are written during compilation and read during execution. Ensure `AtomicUsize`-aligned writes so threads see consistent function pointers.

2. **GuestMemory::pending_write_pages with Mutex** — previously owned by `IcedCpu` and mutated during `mem_write`. With `Mutex<GuestMemory>`, the lock is held briefly during write, then dropped before `drain_pending_code_writes`. Ensure no deadlock (don't lock `mem` and `cache` in inverted order).

3. **Interpreter fallback with shared GuestMemory** — `PerThreadJitState::run_interpreted` holds `&mut GuestMemory` (via the Mutex). For long interpreted runs, this blocks other threads from writing to guest memory via the interpreter. In practice, the JIT compiles almost everything, so this is cold.

4. **IcedCpu dissolution** — if `IcedCpu` is deeply coupled with `JitCpu` internals, dissolving it may be more work than expected. Backup plan: keep `IcedCpu` but change `mem: GuestMemory` to `mem: &'static GuestMemory` (using a raw pointer with lifetime contract).
