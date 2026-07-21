# Phase 4.0 – JIT Memory Foundation

**Date:** 2026-07-18  
**Scope:** Safety rails for Phase 4.1+ (region pins, bulk string, selective invalidation).  
**Does not:** enable region-direct pins by default, rewrite host machine code, or accelerate REP via host `memcpy` yet.

## Why this exists

Sticky-TLB and future pin IR load/store guest memory through **host pointers** without calling `GuestMemory::read`/`write`. Without software permission bits and a memory generation tag, a page that was TLB-installed as RW can keep accepting stores after `VirtualProtect(…, PAGE_READONLY)` if the TLB is not correctly invalidated — or worse, write through RO sticky entries **within the same generation** when install used “any access allowed”.

## Invariants

1. **Slow path is the oracle.** `wie_jit_load` / `wie_jit_store` → `GuestMemory::{read,write}` remain the semantic source of truth (SPC + backend).
2. **Fast path may only accelerate** accesses the slow path would accept.
3. **Guest VA ≠ host VA** — soft translate only; no identity map.
4. **No executable patching** of Cranelift output in Phase 4 (chaining stays data-plane: FuncRef + chain table).

## Memory generation

`GuestMemory::generation()` (already bumped on map / protect / commit / decommit / release) is snapshotted into `JitCtx.mem_gen` at each `run_compiled`.

TLB / sticky entries store `generation` at install. Hit requires `entry.generation == ctx.mem_gen`.

## SPC-tagged TLB

| Field                       | Role                                                    |
| --------------------------- | ------------------------------------------------------- |
| `tlb_page` / `tlb_ptr`      | Guest page key + host page base                         |
| `tlb_prot` / `tlb_hot_prot` | Bit0 = read, bit1 = write (`TLB_PROT_R` / `TLB_PROT_W`) |
| `tlb_gen` / `tlb_hot_gen`   | Generation at install                                   |

Install uses `GuestMemory::page_tlb_entry` / `page_tlb_entry_walk` (committed + protect meta + host ptr).  
Load requires R; store requires W. Deny → miss → slow path → SPC fault.

Inline multi sticky IR (`sticky_tlb_probe`, `STICKY_WAYS = 2`) checks key, non-null base, in-page, **gen match**, and **R or W bit** per way before trusted host load/store.

## Kill-switches

| Env                            | Effect                                            |
| ------------------------------ | ------------------------------------------------- |
| `WIE_JIT_MEM=slow`             | No sticky IR; every load/store is a helper call              |
| `WIE_JIT_MEM=sticky` (default) | Multi sticky IR (2 MRU) + stack pin; helpers pin-resolve all |
| `WIE_JIT_MEM=pin`              | Sticky + top-2 data pin IR (Phase 4.1; opt-in)               |
| `WIE_JIT_CHAIN=0`              | No direct FuncRef chain, no chain-table publish   |
| `WIE_CPU=iced`                 | Full interpreter escape hatch                     |

Read once at first use (`OnceLock`). Log via normal env when debugging; profile line integration is later.

## Rollback bisect

```bash
WIE_JIT_MEM=slow WIE_CPU=jit ./scripts/run-micro-suite.sh
WIE_JIT_CHAIN=0 WIE_CPU=jit ./scripts/run-micro-suite.sh
WIE_CPU=iced ./scripts/run-micro-suite.sh
```

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/run-micro-suite.sh                 # mmap-only storage
WIE_JIT_MEM=slow ./scripts/run-micro-suite.sh
WIE_JIT_MEM=pin  ./scripts/run-micro-suite.sh
```

## Next / status

- **4.1** ✅ Region pin slots (stack + ranked heaps/VA) — see [`phase4-region-pins.md`](phase4-region-pins.md).
- **4.1b** ✅ Stack pin + block-wide super-fast path (one entry guard, bare host mem in body).
- **4.1c** ✅ Multi sticky IR (`STICKY_WAYS = 2`) + gen-cached pins.
- **4.2** ✅ I-cache policy + edge IC — see [`phase4-jit-coherency.md`](phase4-jit-coherency.md).
- **4.3** ✅ REP MOVS/STOS host-span bulk — see [`phase4-string-bulk.md`](phase4-string-bulk.md).
- **Phase 4 core frozen.**
- **4.x** ✅ Selective code invalidation (X-loss / SMC / free) — see [`phase4-code-invalidation.md`](phase4-code-invalidation.md).

## Related

- Plan session: Phase 4 plan (risks 1–4)
- Phase 3: [`phase3-permissions.md`](phase3-permissions.md)
- Phase 4.1: [`phase4-region-pins.md`](phase4-region-pins.md)
- Phase 4.2: [`phase4-jit-coherency.md`](phase4-jit-coherency.md)
- Phase 4.3: [`phase4-string-bulk.md`](phase4-string-bulk.md)
- Phase 4.x: [`phase4-code-invalidation.md`](phase4-code-invalidation.md)
- Roadmap: [`Optimization ROADMAP.md`](../Optimization%20ROADMAP.md)
