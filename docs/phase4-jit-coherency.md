# Phase 4.2 – JIT Coherency & Block Chaining (Data Plane)

**Date:** 2026-07-18  
**Depends on:** Phase 4.0 ([`phase4-foundation.md`](phase4-foundation.md)).  
**Scope:** Document I-cache / D-cache policy; keep chaining data-plane-only; optional monomorphic edge IC.  
**Does not:** rewrite branch opcodes inside finalized Cranelift output.

## Why this exists

On Apple Silicon (ARM64) the **I-cache and D-cache are split**. Stores that rewrite **executable** bytes are not automatically visible to the instruction fetcher. Publishing modified machine code requires a clean D-cache → invalidate I-cache → barrier sequence (`sys_icache_invalidate` on Darwin, plus `dsb`/`isb` semantics). Concurrent modification while another core executes the same lines is undefined without stop-the-world.

WIE’s Phase 4 decision: **never patch finalized host code** for block chaining. All successor binding uses **data** (function pointers), so normal single-threaded memory ordering is enough and **no I-cache maintenance is required** for chaining.

## What is allowed (Phase 4.x)

| Mechanism | Kind | I$ work? |
| --------- | ---- | -------- |
| Direct Cranelift `call` to a known successor `FuncRef` | Static at lower time | No |
| Late-bound open-addressing **chain table** (`chain_va` / `chain_fn`) | Data write | No |
| Monomorphic **edge IC** in `JitCtx` (`edge_ic_va` / `edge_ic_fn`) | Data write | No |
| Self-loop via SSA re-enter of a non-entry header block | Control only | No |
| Cranelift `finalize_definitions` once at compile | Library publish | Once at finalize (Cranelift/JIT module responsibility) |

## What is forbidden (Phase 4.x)

1. Storing into memory returned by `get_finalized_function` / equivalent to rewrite `b` / `bl` / other opcodes.
2. Self-modifying exit stubs that patch immediates in place.
3. Assuming “write then execute” of host JIT pages without a full publish protocol.

If a future epic requires code patch, hard rules:

| Rule | Requirement |
| ---- | ----------- |
| Single writer | Only the emulator thread that is **not** executing the target block may patch |
| Write window | Toggle JIT write protect if required; write full A64 instruction quanta (4-byte aligned) |
| Publish | `sys_icache_invalidate(ptr, len)` covering **all** modified bytes (Darwin) |
| Barrier | Prevent compiler reordering; volatile/atomic or explicit fence APIs |
| No torn patches | Multi-instruction sequences via trampoline or single atomic-width change |

## Edge inline cache (4.2)

Late-bound exits probe a small monomorphic cache **before** the open-addressing chain table:

```text
for slot in edge_ic:
  if edge_ic_va[slot] == target && edge_ic_fn[slot] != 0
    → call_indirect(edge_ic_fn[slot])
miss → wie_jit_chain_lookup (table + install edge IC) → call_indirect or dispatcher exit
```

- **Data plane only** — updating `edge_ic_*` is a plain store.
- Cleared with the chain table on code invalidation / full flush (`invalidate_chain_and_shadow`).
- Kill-switch: `WIE_JIT_CHAIN=0` disables late-bound + direct chain (dispatcher every block); edge IC is irrelevant when chaining is off.

## Interaction with memory generation / protect

- Data writes that do **not** overlap compiled guest ranges leave the chain table and edge IC intact.
- Code-overlapping guest writes drop compiled ranges and rebuild the chain table (edge IC cleared).
- `VirtualProtect` / free / map bump `mem_gen` and invalidate TLB/pins; they do **not** by themselves require I-cache ops for host JIT code.

## Kill-switches / bisect

```bash
WIE_JIT_CHAIN=0          # no FuncRef chain, no chain table, no edge IC benefit
WIE_JIT_MEM=slow         # helper-only loads/stores (unrelated, but common bisect)
WIE_CPU=iced             # full interpreter escape
```

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
WIE_JIT_CHAIN=0 ./scripts/run-micro-suite.sh
WIE_CPU=jit ./scripts/run-micro-suite.sh
```

## Related

- Foundation: [`phase4-foundation.md`](phase4-foundation.md)
- Region pins: [`phase4-region-pins.md`](phase4-region-pins.md)
- Roadmap: [`Optimization ROADMAP.md`](../Optimization%20ROADMAP.md)
