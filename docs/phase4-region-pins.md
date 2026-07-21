# Phase 4.1 – Region-Direct Pins

**Date:** 2026-07-18 (updated 2026-07-21)  
**Depends on:** Phase 4.0 ([`phase4-foundation.md`](phase4-foundation.md)) — SPC TLB, `mem_gen`, kill-switches.  
**Scope:** Soft-translated stack / heap / VirtualAlloc pins for JIT helpers + optional pin IR + multi sticky.  
**Does not:** bake immortal host pointers into code, patch Cranelift output, or default-on data pin IR.

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

Built by `GuestMemory::region_pin` / `span_pin` / `jit_region_pins`:

| Requirement | Failure → empty pin |
| ----------- | ------------------- |
| Arena `host_base` set (mmap) | No soft-translate base |
| Every page in range **Committed** | Free hole / reserved |
| Intersection of R/W over all pages | No usable rights |

**Conservative protect:** if any page is RO, `allow_w = 0` for the whole pin. Mixed heaps still accelerate **reads**; stores fall back to sticky/TLB (page-precise) or slow path.

`span_pin` soft-translates any contiguous committed arena span (not only named regions) — used for private VAD / VirtualAlloc runs.

## Pin slots (`JIT_REGION_PIN_SLOTS = 8`)

| Slot | Source |
| ---- | ------ |
| **0** | Stack region (super-path + hot locals) |
| **1..7** | Size-ranked **data** pins: named heaps + private **VirtualAlloc** committed runs |

**Ranking / filters:**

- Score = span size; RO spans score at **1/4** so RW LZMA / process heaps win over large RO maps.
- **Exclude bootstrap named** ranges that are not heap/stack (image, TEB, `guest_file_data` file mirror, …) — a 64 MiB file arena must not steal data slots from hot VirtualAlloc.
- No overlap with already chosen spans; minimum span ≥ one guest page.

## When pins are filled

`JitCpu` keeps a pin cache keyed by `mem_gen`:

1. On `run_compiled`, if `pins_gen != mem_gen`, call `jit_region_pins()` and copy into `JitCtx.pins`.
2. `virtual_protect` / free / map → `invalidate_tlb()` bumps generation and clears pins; next entry refills.
3. Helpers always see all filled slots; IR data-pin probes stay capped (top-2 under `WIE_JIT_MEM=pin`).

## Paths

| Path | When |
| ---- | ---- |
| Helper `pin_resolve` | Always on sticky/TLB miss (before page walk) — **all 8 slots** |
| Sticky IR + **stack pin** | Default (`WIE_JIT_MEM=sticky`) |
| Sticky + stack + **top-2 data pin IR** | `WIE_JIT_MEM=pin` |
| Helper only | `WIE_JIT_MEM=slow` |

**IR order (sticky):** stack pin → **multi sticky (2 MRU ways)** → helper.  
**IR order (`pin`):** stack pin → multi sticky → data pins `[1..2]` → helper.

Helpers always soft-translate via every filled pin before a page walk — this is the main win for VirtualAlloc (collapses walk% without IR cascade tax). Full data-pin IR cascade was measured and **regressed wall** on thrashy 7za; keep IR data pins opt-in and capped.

### Multi sticky (4.1c)

Last-**2** MRU guest pages (`sticky_page` / `sticky_ptr` / `sticky_prot` / `sticky_gen`; way 0 = hottest). IR probes both ways so A↔B page thrash stays out of `wie_jit_load` / `wie_jit_store`.

- **Sized at 2:** larger tables cut helpers further but the full-miss IR cascade taxes large-WS 7za wall time.
- Helper path still has the set-associative multi-way TLB (`16×4`) after sticky miss.

### Observability

```bash
WIE_JIT_MEM_TRACE=1 ./target/release/wie-cli run …   # or WIE_EXEC_TRACE=1
# [wie] mem_path helpers=… resolve: sticky= multi= pin= walk= …
# [wie] sticky_miss: key= gen= prot= swaps= …
```

## Kill-switches / bisect

```bash
WIE_JIT_MEM=slow   # no inline host ptr
WIE_JIT_MEM=sticky # default: multi sticky + stack pin
WIE_JIT_MEM=pin    # + top-2 data pin IR (helpers already use all pins)
WIE_CPU=iced       # full escape
```

## Safety notes

- Pins never outlive gen: protect/free bumps `generation` and clears TLB/pins.
- Pin IR is **opt-in** for data slots; helpers already soft-translate on miss without requiring pin mode.
- Cross-pin / out-of-bounds → miss → helper → SPC fault.
- No host soft-translate W onto executable pages (code stores force slow path + SMC drain).

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
WIE_JIT_MEM=pin  ./scripts/run-micro-suite.sh
WIE_JIT_MEM=slow ./scripts/run-micro-suite.sh
```

Unit coverage includes `span_pin` + ranking (VA preferred over bootstrap file mirror among data slots).

## Status

- **4.1** ✅ Region pin slots (stack + ranked heaps/VA, 8 slots) + helper `pin_resolve`.
- **4.1b** ✅ Hoisted stack pin + **block-wide super-fast path**:
  - Pre-compile: `analyze_block_stack_pin` → `min_disp` / `max_end` over all memops.
  - Entry: **one** range guard vs stack pin; dual CFG (super | normal).
  - Super body: `host = (host_base - guest_base) + guest_va` — no per-op bounds checks.
  - `long_loop` ~0.28–0.32s release (was ~0.54s hoist-only, ~1.4s sticky-only).
- **4.1c** ✅ Multi sticky IR (`STICKY_WAYS = 2`) + gen-cached pin rebuild + bootstrap exclude on data ranking.
  - 7za: helper counts roughly **halved** vs single sticky; wall ~parity (pin helper path already carried most VA traffic).
- **4.2** ✅ [`phase4-jit-coherency.md`](phase4-jit-coherency.md) + monomorphic edge IC.
- **4.3** ✅ [`phase4-string-bulk.md`](phase4-string-bulk.md) host-span REP bulk (DF=0/1).

## Phase 4 freeze

Mechanisms for pins / multi sticky / chaining / REP bulk are in place.

**4.x** ✅ Selective code invalidation — X-loss / SMC / free + **no W soft-translate on executable pages** (forces code stores through `GuestMemory::write` + pending drain). See [`phase4-code-invalidation.md`](phase4-code-invalidation.md).

**Optional later (not required):** hotness-based pin ranking, inline multi-way TLB IR, more sticky ways if a workload needs it without wall tax.
