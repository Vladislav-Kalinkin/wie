# Multithreading (MT.0–MT.5)

**Date:** 2026-07-19  
**Status:** MT.0–MT.3 foundation + MT.4 Interlocked/hardening + MT.5 knobs/docs/suite.

## Model

| Piece | Owner |
| ----- | ----- |
| Guest TID / TLS values | `wie_winapi::ThreadState` / `GuestThread` |
| Process TLS index count | `ThreadState.tls_index_count` (`TlsAlloc`) |
| Critical section fields | Guest `RTL_CRITICAL_SECTION` + host wait queue |
| Kernel objects | `SyncState` (thread / event handles) |
| Primary TID | `PRIMARY_THREAD_ID` (`0x5678`) |
| CPU engine | Shared after first `CreateThread` (`ProcessResources`) |
| Memory generation | `AtomicU64` acquire/release (`GuestMemory::generation`) |

**1:1 host thread ↔ guest thread.** Each guest thread owns a **`CpuEngine`** (JIT: shared `Arc<JitShared>` compile cache; Iced: shared `Arc<RwLock<GuestMemory>>`). WinAPI / kernel objects / heap sit behind **`Arc<Mutex<WinApiState>>`**.

**Lock scope (critical):** the WinAPI mutex is held only for **activate / dispatch / state mutate**, **not** across pure `run_until_stop` guest compute. Host wait (`WaitFor*`, contended CS) parks **outside** the mutex so peers can `SetEvent` / `LeaveCriticalSection` / `ExitThread`.

**Active-TID rule:** `ThreadState.active` is process-global. After pure guest compute (no WinAPI lock), a peer may have activated itself. **Every** dispatch path must `activate(own_tid)` again under the WinAPI lock before any handler that uses `current_tid()` (CS owner, TLS, waits). Missing re-activate on the primary thread caused false CS ownership and deadlocks under `7za -mmt2` (workers steal `active` while primary runs pure guest code).

Default **guest** worker stack is **1 MiB** when `dwStackSize == 0` (Windows-like). Host OS threads for workers use an **8 MiB** stack so JIT/iced dispatch does not overflow secondary-thread defaults on macOS.

Concurrent guest data planes are intentional after the per-thread engine change; structural map/unmap/protect still serializes via WinAPI handlers (and Iced write-locks on the shared `GuestMemory`).

## What works

### MT.1 (single host runner)

- `GetCurrentThreadId` → active guest TID  
- `TlsAlloc` / `TlsGetValue` / `TlsSetValue` / `TlsFree` — process indices, per-active-thread values  
- `EnterCriticalSection` / `LeaveCriticalSection` — real owner + recursion  

### MT.2

- `CreateThread` — stack alloc, TID/handle, host `std::thread` worker  
- CRT `_beginthreadex` / `_endthreadex` — same spawn path as `CreateThread`  
- `CREATE_SUSPENDED` + `ResumeThread`  
- `ExitThread` / `GetExitCodeThread`  
- `WaitForSingleObject` on thread handles (join)  
- `CloseHandle` on thread objects  
- Micros: `thread_create_join.exe`  

### MT.3

- Contended CS: host park on CS condvar; Leave wakes one waiter  
- `CreateEventA/W`, `SetEvent`, `ResetEvent`  
- Counting `CreateSemaphoreA/W` + `ReleaseSemaphore`  
- `WaitForSingleObject` on events / semaphores  
- `WaitForMultipleObjects` (wait-any / wait-all, host park outside process locks)  
- Micros: `cs_two_threads.exe`, `event_handshake.exe`  

### MT.4

- **Interlocked\*** family via soft-translate → host `AtomicI32` / `AtomicI64` when guest VA is aligned and span-mappable; unaligned/non-span falls back to mem RMW (correct under process lock)  
  - `InterlockedIncrement/Decrement/Exchange/CompareExchange/ExchangeAdd`  
  - `*64` variants  
- `mem_gen` is `AtomicU64` (acquire load / acq-rel bump)  
- `ExitProcess` join protocol: `process_dying`, wake all CS waiters, signal all events, finish unfinished thread objects, join host workers  
- Infinite `WaitForSingleObject` on workers is sliced (50 ms) so dying is observed  
- Micros: `interlocked_basic.exe`, `mt_stress.exe`  

### MT.5 (knobs / docs / suite)

| Knob | Role | Default |
| ---- | ---- | ------- |
| `WIE_MT=0\|1` | Kill-switch: `0` makes `CreateThread` fail (`ERROR_NOT_SUPPORTED`) | enabled (unset ≠ 0) |
| `WIE_MT_MAX_THREADS` | Cap on worker threads (`CreateThread`) | `64` |
| `WIE_MT_DEBUG=1` | Stderr traces: CreateThread / ResumeThread / Wait / drain_spawns / worker start | off |
| `WIE_MPROTECT` | Dual host mprotect (SPC remains oracle). Safe under current process-lock serialize; set `0` if diagnosing mprotect races later | on |
| `WIE_GUEST_HEAP` | In-guest heap accel; keep off or locked under MT (default off) | off |

Suite: `scripts/run-micro-suite.sh` runs MT micros; `mt_stress` is skipped when `WIE_MT=0`.

## Explicit non-goals (still)

- Concurrent unlocked guest data planes (true parallel JIT on two cores)  
- Multi-TEB / GS base  
- Named events / named semaphores / mutex objects  
- Perfect wait-all rollback when auto-reset objects are mixed in the set  
- APC / alertable waits / fibers  

## ARM notes

- No patch of finalized JIT host code for chaining (see `phase4-jit-coherency.md`).  
- Thread switch flushes JIT TLB / pins / shadow (`on_thread_switch`).  
- Interlocked uses host LDXR/STXR through soft-translated pointers (SeqCst).  
- Arena **data** may race only if concurrent execute is opened later; today the process engine mutex serializes guest steps. Structural map/unmap/protect still exclusive.  

## Locks (summary)

| Resource | Lock |
| -------- | ---- |
| WinAPI state (heap, objects, TLS, CS metadata) | `Arc<Mutex<WinApiState>>` — **dispatch only** |
| Guest pure compute | **no** WinAPI mutex (per-thread `CpuEngine`) |
| CS wait | host `Condvar` **outside** WinAPI mutex |
| Waitable objects | host mutex/cv on object; wait outside WinAPI mutex |
| Iced guest memory | `Arc<RwLock<GuestMemory>>` (write = map/protect/free) |
| JIT guest memory | soft-translate + `mem_gen`; structural ops via WinAPI handlers |

## Verify

```bash
cargo test -p wie-winapi test_critical_section_reenter test_interlocked
cargo clippy --workspace --all-targets -- -D warnings
make -C micro-exes interlocked_basic mt_stress thread_create_join cs_two_threads event_handshake
./scripts/run-micro-suite.sh
WIE_CPU=iced ./scripts/run-micro-suite.sh
WIE_MT=0 ./scripts/run-micro-suite.sh   # skips mt_stress; CreateThread micros fail if they need MT
```

## RUNBOOK symptoms

| Symptom | Action |
| ------- | ------ |
| Hang on `WaitForSingleObject` | Check peer never signals; `ExitProcess` should wake via dying protocol. Infinite primary waits are sliced (50 ms) so nested `CreateThread` can `drain_spawns` and `process_dying` is observed |
| Hang on CS Enter | Owner never Leave; dying wakes all CS queues. If multi-thread only: confirm primary re-activates TID before dispatch (see Active-TID rule) |
| Hang after “1 file, N bytes” on `7za -mmt*` | Historically active-TID race (fixed): primary Enter/Leave CS with worker TID. Set `WIE_MT_DEBUG=1` for CreateThread / Wait / drain traces on stderr |
| `CreateThread` returns NULL | `WIE_MT=0` or hit `WIE_MT_MAX_THREADS` |
| Stress flaky under iced | Raise timeout; engine is serialized so should be deterministic |
