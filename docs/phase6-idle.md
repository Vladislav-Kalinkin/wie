# Phase 6 – Idle CPU Management

**Date:** 2026-07-18  
**Depends on:** Phases 0–5.5 (stable run loop, host WinAPI, guest stubs).  
**Scope:** Park the **host** thread when the guest is blocked on documented waits.  
**Does not:** throttle pure guest spins (`long_loop`); implement a full NT wait graph; copy Wine idle code.

## Goal

| Workload | Expected host CPU |
| -------- | ----------------- |
| Busy guest (`long_loop`, compute) | ~100% (unchanged) |
| `Sleep(n>0)` with park policy | low while sleeping |
| Empty `GetMessage` + park (interactive `run`) | typically &lt; 5–15% over multi-second idle |

## States (logical)

| State | Meaning |
| ----- | ------- |
| Running | Guest JIT / iced executing |
| HostCall | Inside a host WinAPI handler |
| Parked | Host `thread::sleep` / message quantum |
| Exit | Terminal stop (`ExitProcess`, …) |

## Policy (`WIE_IDLE`)

| Value | `Sleep(n>0)` | Empty `GetMessage` (`YieldOnIdle`) |
| ----- | ------------ | ----------------------------------- |
| `busy` | no-op | immediate yield signal (no sleep) |
| `yield` (default for micros) | no-op | yield signal, no sleep |
| `park` (default for persistent `run` when unset) | host sleep (capped) | outer loop parks + re-enters |

### Other knobs

| Variable | Default | Role |
| -------- | ------- | ---- |
| `WIE_IDLE_CAP_MS` | `60000` | Max single `Sleep` park |
| `WIE_IDLE_PARK_MS` | `25` | Empty-message park quantum |
| `WIE_IDLE_MAX_PARKS` | `40` | Max quanta before CLI gets `WaitingForMessage` (`0` = unlimited) |
| `WIE_IDLE_SLICE_MS` | `0` | Optional between-slice sleep (reserved; off by default) |
| `WIE_HOST_SLEEP=1` | off | **Legacy:** enable Sleep park only (does not force message park) |

## Implementation notes

1. **`Sleep` is not an in-guest stub** — void ret would skip host idle policy. Always host-dispatch (`handle_sleep` → `idle::apply_sleep`).
2. **`Sleep(0)`** always `thread::yield_now()` under every policy.
3. **Micros** use `MessageQueueIdlePolicy::ExitOnIdle` (synthetic `WM_QUIT`) and `IdleContext::Micro` → default `yield` so CI stays fast.
4. **Persistent run** (`run_persistent_until_yield` / CLI `run`): `YieldOnIdle` + `IdleContext::Persistent` → default `park`; on `WaitingForMessage`, sleep `WIE_IDLE_PARK_MS` and re-dispatch the same fake-API entry (return not taken).
5. **`PeekMessage`** never parks (non-blocking).
6. **Clean room** — Microsoft Learn contracts + WIE design only; no Wine/ReactOS.

## Profile

With `WIE_RUNTIME_PROFILE=1`:

```text
mem_backend=hybrid
idle_policy=yield|park|busy
idle_parks=N idle_park_ms=…
```

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p wie-winapi idle
cargo test --workspace
./scripts/run-micro-suite.sh

# Busy path: still ~100% CPU
WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run-micro micro-exes/out/long_loop.exe

# Sleep park (unit coverage in wie-winapi::idle)
WIE_IDLE=park  # + any guest that calls Sleep(n>0)
```

## Rollback

```bash
WIE_IDLE=busy          # never park
WIE_IDLE=yield         # pre-Phase-6 Sleep(n>0) no-op behaviour
# or leave unset for micros (yield)
```

## Out of scope / later

- Full `WaitForSingleObject` / APC / alertable waits  
- `MsgWaitForMultipleObjects`  
- Accurate guest-visible time advancement while parked  
