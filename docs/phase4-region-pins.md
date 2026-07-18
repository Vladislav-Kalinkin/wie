# Phase 4.1 – Region-Direct Pins

**Date:** 2026-07-18  
**Depends on:** Phase 4.0 ([`phase4-foundation.md`](phase4-foundation.md)) — SPC TLB, `mem_gen`, kill-switches.  
**Scope:** Soft-translated stack/heap pins for JIT helpers + optional pin IR.  
**Does not:** bake immortal host pointers into code, patch Cranelift output, or default-on pin IR.

## Invariants (unchanged)

1. **Slow path is the oracle** — `GuestMemory::{read,write}` + PageMap SPC.
2. **Fast path may only accelerate** accesses the slow path would accept.
3. **Guest VA ≠ host VA** — `host = pin.host_base + (guest - pin.guest_base)`.
4. **No executable patching**.

## What a pin is

```text
MemPin {
  guest_base, guest_end,   // exclusive end
  host_base,               // arena soft-translate base (0 = empty)
  mem_gen,                 // GuestMemory::generation at fill
  allow,                   // TLB_PROT_R | TLB_PROT_W intersection
}
```

Built by `GuestMemory::region_pin` / `jit_region_pins`:

| Requirement | Failure → empty pin |
| ----------- | ------------------- |
| `GuestRegion.host_base` set (mmap/hybrid arena) | HashMap-only layout |
| Every page in range **Committed** | Free hole / reserved |
| Intersection of R/W over all pages | No usable rights |

**Conservative protect:** if any page is RO, `allow_w = 0` for the whole pin. Mixed heaps still accelerate **reads**; stores fall back to sticky/TLB (page-precise) or slow path.

Slots (registration order): **0 = Stack**, **1 = primary Heap**.

## When pins are filled

Every `JitCpu::run_compiled`:

1. `jit_region_pins()` from live RegionTable + PageMap.
2. Copy into `JitCtx.pins` with current `mem_gen`.
3. `virtual_protect` / free / map → `invalidate_tlb()` **clears** pins; next entry refills.

## Paths

| Path | When |
| ---- | ---- |
| Helper `pin_resolve` | Always on TLB miss (before page walk) — safe acceleration |
| Sticky IR + **stack pin** (4.1b) | Default (`WIE_JIT_MEM=sticky`) |
| Sticky + stack + **heap** pin IR | `WIE_JIT_MEM=pin` |
| Helper only | `WIE_JIT_MEM=slow` |

IR order: **sticky first**, then **stack pin** (always under sticky), then heap pins when `pin` mode. Sticky wins when both hit (page-precise rights).

## Kill-switches / bisect

```bash
WIE_JIT_MEM=slow   # no inline host ptr
WIE_JIT_MEM=sticky # default: sticky only
WIE_JIT_MEM=pin    # sticky + region pin IR
WIE_CPU=iced       # full escape
```

## Safety notes

- Pins never outlive gen: protect/free bumps `generation` and clears TLB/pins.
- Pin IR is **opt-in** until micro-suite + stress are trusted; helpers already use soft-translate on miss without requiring pin mode.
- Cross-pin / out-of-bounds → miss → helper → SPC fault.
- Hash backend: no `host_base` → empty pins → sticky/helper only.

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
WIE_MEM=hybrid WIE_JIT_MEM=pin ./scripts/run-micro-suite.sh
WIE_MEM=mmap   WIE_JIT_MEM=pin ./scripts/run-micro-suite.sh
WIE_JIT_MEM=slow ./scripts/run-micro-suite.sh
```

## Status (follow-ons)

- **4.1b** ✅ Hoisted stack pin + **block-wide super-fast path**:
  - Pre-compile: `analyze_block_stack_pin` → `min_disp` / `max_end` over all memops.
  - Entry: **one** range guard vs stack pin; dual CFG (super | normal).
  - Super body: `host = (host_base - guest_base) + guest_va` — no per-op bounds checks.
  - `long_loop` ~0.28–0.32s release (was ~0.54s hoist-only, ~1.4s sticky-only).
- **4.2** ✅ [`phase4-jit-coherency.md`](phase4-jit-coherency.md) + monomorphic edge IC.
- **4.3** ✅ [`phase4-string-bulk.md`](phase4-string-bulk.md) host-span REP bulk (DF=0/1).

## Phase 4 freeze

Mechanisms for pins / chaining / REP bulk are in place. **Next:** 4.x selective code invalidation on `VirtualProtect` X-loss / SMC so pin + JIT code stay coherent on real software (see plan risk 3).
