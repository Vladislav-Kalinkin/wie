# WIE Runbook (quick mitigations)

One-page playbook for regressions after Phases 0–7 and the **great cleanup** (mmap-only memory, compressed CLI). Prefer kill-switches over deep debug first.

## Identity

| Check | Command / note |
| ----- | -------------- |
| Active CPU | `WIE_CPU` unset → **jit**; `WIE_CPU=iced` for interpreter |
| Active mem | Always **mmap** arenas (`WIE_RUNTIME_PROFILE=1` → `mem_backend=mmap`) |
| Active idle | profile line `idle_policy=…` (Phase 6) |
| CLI | `inspect` / `run` / `trace` (`run-micro` and `entry-trace` are aliases) |

## Symptoms → actions

| Symptom | Try |
| ------- | --- |
| Crash / wrong reads after `VirtualProtect` / free | `WIE_MPROTECT=0`; bisect with `WIE_JIT_MEM=slow` / `WIE_CPU=iced` |
| Suspected JIT miscompile | `WIE_CPU=iced` or `WIE_JIT_MEM=slow` |
| Stale code after patch / protect | Expect `FlushInstructionCache` / X-loss inv (Phase 4.x + 7); bisect with `WIE_JIT_CHAIN=0` |
| Idle guest burns 100% CPU (message wait) | `WIE_IDLE=park` (interactive `run --persistent` defaults to park) |
| `Sleep(n)` ignored / too fast | Ensure not forced busy: `WIE_IDLE=park` or legacy `WIE_HOST_SLEEP=1` |
| Micros suddenly slow | Avoid `WIE_IDLE=park` on suite; default micro idle is **yield** |
| String / SIMD wrong results | `WIE_STRING_BULK=0`, `WIE_STRING_INLINE=0`, `WIE_JIT_SIMD=0` |
| TLB Neon issues on aarch64 | `WIE_TLB_NEON=0` |
| Host mprotect noise / faults | `WIE_MPROTECT=0` (SPC still enforces) |
| Heap freelist suspicion | `WIE_GUEST_HEAP=0` (host freelist only; default) |
| Hang on Wait / CS under MT | See [`mt-threads.md`](mt-threads.md); `ExitProcess` wakes waiters; check peer never signals |
| `CreateThread` fails | Unset `WIE_MT=0`; raise `WIE_MT_MAX_THREADS` (default 64) |
| Interlocked wrong | Expect host atomics via soft-translate; try `WIE_CPU=iced` |

## Regression matrix

```bash
cargo build -p wie-cli --release
./scripts/run-micro-suite.sh                 # mmap + jit (+ MT micros)
WIE_CPU=iced   ./scripts/run-micro-suite.sh
WIE_JIT_MEM=slow ./scripts/run-micro-suite.sh
WIE_JIT_MEM=pin  ./scripts/run-micro-suite.sh
```

## Profile snapshot

```bash
WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run micro-exes/out/long_loop.exe
# expect ~100% CPU on pure loops; mem_backend=mmap
```

## Docs map

| Topic | Doc |
| ----- | --- |
| Idle park | [`phase6-idle.md`](phase6-idle.md) |
| Hardening / cutover | [`phase7-hardening.md`](phase7-hardening.md) |
| Code invalidation | [`phase4-code-invalidation.md`](phase4-code-invalidation.md) |
| Memory backends (historical) | [`phase2-mmap-backend.md`](phase2-mmap-backend.md) |
| Full roadmap | [`../Optimization ROADMAP.md`](../Optimization%20ROADMAP.md) |
| Multithreading | [`mt-threads.md`](mt-threads.md) |

## Non-goals of this sheet

- Wine-style identity `mmap(guest_va)` — **never** a remediation path.
- Rolling back to HashMap / hybrid storage — **removed** in the great cleanup.
- Full Windows wait / APC debugging — not modelled.
