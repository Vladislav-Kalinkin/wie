# Phase 3 – Permissions and Dynamic Mapping

**Date:** 2026-07-18  
**Scope:** Guest page state (Free / Reserved / Committed), software permission checks (SPC), `VirtualAlloc` / `VirtualFree` / `VirtualProtect` / `VirtualQuery`, PE section protects, optional host `mprotect`.

## Invariant

**Windows page state is software; host mapping is capacity and stability; host PTEs are never the guest permission oracle under the 4 KiB guest / 16 KiB host clinch.**

| Plane | Owner | Role |
| ----- | ----- | ---- |
| PageMap + VAD | `GuestMemory` | Free/Reserved/Committed, `PAGE_*`, VirtualQuery runs, SPC |
| Arena / HashMap | backends | Host bytes, soft translate, stable `host_base` for arenas |
| RegionTable | layout names | Diagnostics / Phase 4 pins (not authoritative for Query) |

## Software permission checks (SPC)

- Gate every `mem_read` / `mem_write` / `fetch_into` and JIT TLB install at **guest 4 KiB**.
- All-or-nothing per operation: if any spanned page denies, the whole op fails with no partial write.
- Identical across `WIE_MEM=hash|mmap|hybrid`.

## VirtualAlloc / Free

| Call | Behaviour |
| ---- | ---------- |
| `MEM_RESERVE` | VAD node; pages Reserved; mmap/hybrid: one arena for full span; hash: software-only until commit |
| `MEM_COMMIT` | Pages Committed + protect; host storage if needed |
| `MEM_DECOMMIT` | Pages → Reserved, host zeros, **no munmap** |
| `MEM_RELEASE` | `size==0` and address = allocation base; drop VAD + host arena |

Alignment: reserve uses 64 KiB granularity; commit uses 4 KiB pages.

## VirtualProtect / VirtualQuery

- Protect: transactional validation (one allocation, all committed), then `set_range` (run split/merge); returns old protect of the first page.
- Query: real `MEMORY_BASIC_INFORMATION` (48-byte x64 layout) from PageMap + VAD, including free runs.
- JIT: full TLB flush on alloc/free/protect (Phase 3 minimum).

## PE section mapping (3.3)

1. `mem_map_image` → one `MEM_IMAGE` committed range (`PAGE_EXECUTE_READWRITE` temporary).
2. Copy loader image (IAT already patched in the host buffer).
3. Protect: whole image `PAGE_NOACCESS` (gaps), headers `PAGE_READONLY`, each section from COFF `IMAGE_SCN_MEM_*` → `PAGE_*`.
4. `RegionTable`: `image`, `image.headers`, `image.<section>`.

Plan API: `wie_pe::PeMapPlan` / `pe_map_plan_from_file` / `protect_from_section_characteristics`.

## Optional dual mprotect (`WIE_MPROTECT`)

Default **on**. Set `WIE_MPROTECT=0` to disable.

- Per **host** page frame relative to arena guest base (so soft-translate offsets stay host-aligned).
- Uniform RO guest frame → host `PROT_READ`; mixed / reserved / NOACCESS → host stays RW.
- Failures ignored; SPC remains the correctness plane.

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
WIE_MEM=hash ./scripts/run-micro-suite.sh
WIE_MEM=mmap ./scripts/run-micro-suite.sh
WIE_MEM=hybrid ./scripts/run-micro-suite.sh
```

## Related

- Plan: [`phase3_plan.md`](../phase3_plan.md)
- Phase 2 storage: [`phase2-mmap-backend.md`](phase2-mmap-backend.md)
- Roadmap: [`Optimization ROADMAP.md`](../Optimization%20ROADMAP.md)
