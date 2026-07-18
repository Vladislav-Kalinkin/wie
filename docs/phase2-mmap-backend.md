# Phase 2 – Mmap Storage Backend

**Date:** 2026-07-18  
**Goal:** Soft-translated anonymous mmap arenas for guest memory, with HashMap fallback and hybrid default. Foundation for Phase 3 (perms / VirtualAlloc) and Phase 4 (region-direct JIT).

**Follow-on:** Phase 3 guest permissions and Virtual* APIs are documented in [`phase3-permissions.md`](phase3-permissions.md).

## Backends (`WIE_MEM`)

| Value | Behaviour |
| ----- | --------- |
| `hybrid` (default) | Maps with `size ≥ 64 KiB` → one anonymous arena each; smaller maps → `HashMap` + radix |
| `mmap` | Every map is an anonymous arena (even 4 KiB) |
| `hash` | Pre-Phase-2 storage only (rollback) |

```bash
WIE_MEM=hash ./target/release/wie-cli run-micro micro-exes/out/long_loop.exe
WIE_MEM=mmap WIE_RUNTIME_PROFILE=1 ./target/release/wie-cli run-micro micro-exes/out/crt_hello.exe
```

Profile line includes `mem_backend=hash|mmap|hybrid`.

## Soft translation

```
host_ptr = arena.host + (guest_va - arena.guest_base)
```

- `mmap(NULL, …, MAP_PRIVATE|MAP_ANON)` — OS picks host VA  
- **Never** `mmap` at guest VA / low 4 GB reservation  
- Arena owns `munmap`; JIT TLB / `page_data_ptr` hold **non-owning** pointers  

## Region `host_base`

On `register_region` (and after map), if an arena covers the region base, `GuestRegion.host_base` is set to the arena host pointer. Phase 4.1 can use this for region-direct load/store without a full TLB walk.

## Map semantics

Aligned with HashMap:

- Exact rematch → update software `perms` only  
- Already-mapped pages keep data; overlapping map may add new unmapped runs as extra arenas  
- No unmap API in Phase 2  

## Demand zero

Anonymous arenas are demand-paged: large heaps (16 MiB ×2, file arena 64 MiB) do not charge full RSS until first touch (unlike eager HashMap pages).

## Rollback

```bash
WIE_MEM=hash
```

## Out of scope (later phases)

- `mprotect` / software permission enforcement (Phase 3)  
- `VirtualAlloc` / Free / Protect via RegionTable (Phase 3)  
- JIT region-direct / stack inline IR (Phase 4)  
- File-backed PE image mmap  

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
WIE_MEM=hash ./scripts/run-micro-suite.sh
WIE_MEM=mmap ./scripts/run-micro-suite.sh
WIE_MEM=hybrid ./scripts/run-micro-suite.sh
```
