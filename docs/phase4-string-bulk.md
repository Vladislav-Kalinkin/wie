# Phase 4.3 – REP String Host Bulk Copy

**Date:** 2026-07-18  
**Depends on:** Phase 4.0 SPC + soft translate; arena backends for multi-page spans.  
**Scope:** Accelerate REP MOVS/STOS via host `memcpy`/`memset` on soft-translated spans.  
**Does not:** pass guest VAs to libc; accelerate SCAS/CMPS with NEON (still element loop).

## Invariants

1. **Slow path is the oracle** — page-chunked `GuestMemory::{read,write}` + element loop remain available.
2. **Never** call `memcpy`/`memset` with guest virtual addresses.
3. Soft translate only: `host = arena_host + (guest - arena_guest_base)` or single-page TLB host + offset.
4. SPC (`PageMap::check_access`) must accept the **whole** span before any host write.

## Path selection

```text
REP STOS/MOVS, DF=0, count>1, byte_len ≥ 16, WIE_STRING_BULK on
  → GuestMemory::host_span(guest, len, r|w)
  → if Some(host): ptr write_bytes / copy_nonoverlapping; update RSI/RDI/RCX
  → else: existing page-chunked buffer path
DF=1 or guest-overlapping MOVS or tiny REP
  → element loop (or page-chunked non-overlap MOVS)
```

| Op | Acceleration |
| -- | ------------ |
| REP STOS (DF=0) | Host pattern fill (`write_bytes` / element pattern) |
| REP MOVS (DF=0, no guest overlap) | Host `copy_nonoverlapping` |
| REP MOVS (overlap) | Element loop (x86 forward copy ≠ `memmove`) |
| REP SCAS/CMPS | Unchanged element loop |
| DF=1 | Element loop |

## Kill-switch

```bash
WIE_STRING_BULK=0    # or off|slow|false — disable host-span bulk
```

## API

`GuestMemory::host_span(address, len, write) -> Option<*mut u8>`

| Case | Result |
| ---- | ------ |
| Single page, SPC ok | Page host + in-page offset (hash or mmap) |
| Multi-page, one arena, SPC ok | Soft-translated host base + offset |
| Multi-page sparse hash | `None` → chunked path |
| RO span + write | `None` |

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p wie-cpu host_span
WIE_MEM=hybrid ./scripts/run-micro-suite.sh   # includes cpu_string
WIE_STRING_BULK=0 ./scripts/run-micro-suite.sh
```

## Related

- Foundation: [`phase4-foundation.md`](phase4-foundation.md)
- Roadmap §4.3: [`Optimization ROADMAP.md`](../Optimization%20ROADMAP.md)
