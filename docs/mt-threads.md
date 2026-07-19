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

**1:1 host thread ↔ guest thread.** Guest execution is **serialized** on one shared `CpuEngine` (process mutex). Host wait (`WaitFor*`, contended CS, `Sleep`) **drops** the engine lock so other guest threads can run. This preserves single-thread speed until the first `CreateThread` (local engine, no mutex).

True parallel guest data planes (two cores in JIT simultaneously) remain a future step; metadata is already MT-ready (`mem_gen` atomic, Interlocked host atomics, wake-all on `ExitProcess`).

## What works

### MT.1 (single host runner)

- `GetCurrentThreadId` → active guest TID  
- `TlsAlloc` / `TlsGetValue` / `TlsSetValue` / `TlsFree` — process indices, per-active-thread values  
- `EnterCriticalSection` / `LeaveCriticalSection` — real owner + recursion  

### MT.2

- `CreateThread` — stack alloc, TID/handle, host `std::thread` worker  
- `ExitThread` / `GetExitCodeThread`  
- `WaitForSingleObject` on thread handles (join)  
- `CloseHandle` on thread objects  
- Micros: `thread_create_join.exe`  

### MT.3

- Contended CS: host park on CS condvar; Leave wakes one waiter  
- `CreateEventA/W`, `SetEvent`, `ResetEvent`  
- `WaitForSingleObject` on events  
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
| `WIE_MPROTECT` | Dual host mprotect (SPC remains oracle). Safe under current process-lock serialize; set `0` if diagnosing mprotect races later | on |
| `WIE_GUEST_HEAP` | In-guest heap accel; keep off or locked under MT (default off) | off |

Suite: `scripts/run-micro-suite.sh` runs MT micros; `mt_stress` is skipped when `WIE_MT=0`.

## Explicit non-goals (still)

- Concurrent unlocked guest data planes (true parallel JIT on two cores)  
- `CREATE_SUSPENDED` / `ResumeThread`  
- Multi-TEB / GS base  
- Named events, mutex objects, `WaitForMultipleObjects`  
- APC / alertable waits / fibers  

## ARM notes

- No patch of finalized JIT host code for chaining (see `phase4-jit-coherency.md`).  
- Thread switch flushes JIT TLB / pins / shadow (`on_thread_switch`).  
- Interlocked uses host LDXR/STXR through soft-translated pointers (SeqCst).  
- Arena **data** may race only if concurrent execute is opened later; today the process engine mutex serializes guest steps. Structural map/unmap/protect still exclusive.  

## Locks (summary)

| Resource | Lock |
| -------- | ---- |
| CPU engine + WinAPI state | process `Mutex` pair after first `CreateThread` |
| CS wait | host `Condvar` **outside** process locks |
| Waitable objects | host mutex/cv on object; wait outside process locks |
| Heap freelist | process WinAPI mutex (same as engine share) |
| PageMap / VAD / arenas | under engine mutex (structural ops) |

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
| Hang on `WaitForSingleObject` | Check peer never signals; `ExitProcess` should wake via dying protocol |
| Hang on CS Enter | Owner never Leave; dying wakes all CS queues |
| `CreateThread` returns NULL | `WIE_MT=0` or hit `WIE_MT_MAX_THREADS` |
| Stress flaky under iced | Raise timeout; engine is serialized so should be deterministic |
