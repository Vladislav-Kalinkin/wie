# Phase 3 — Permissions and Dynamic Mapping (Architectural Plan)

**Status:** In progress — PR A (SPC/PageMap) + PR B (VAD/VirtualAlloc/Free) landed; PR C–E pending  
**Scope:** Roadmap § Phase 3.1–3.3  
**Constraints:** Clean-room from Microsoft Learn (no Wine/ReactOS design reuse); dual-backend (`hash` / `mmap` / `hybrid`); Guest VA ≠ Host VA; software checks are the correctness boundary; clippy `-D warnings` after implementation  
**Prior art in tree:** Phases 0–2 + 5 complete. `ArenaSet` / `HybridBackend` store data; `RegionTable` is layout bookkeeping only; `VirtualProtect`/`VirtualQuery` are stubs; PE image is one `mem_map` + `perm::ALL`; perms stored but not enforced on hot paths

---

## 0. Goals, Non-Goals, Success Criteria

### Goals

1. **Guest-correct page state machine** for private VA: Free / Reserved / Committed, with Windows-compatible protect bits, driven by `VirtualAlloc` / `VirtualFree` / `VirtualProtect` / `VirtualQuery`.
2. **Software permission enforcement** on interpreter and JIT load/store/fetch paths, at **guest 4 KiB** granularity, identical across all `WIE_MEM` backends.
3. **Stable host pointers** for arena-backed ranges (`host_base` / `page_data_ptr`) so Phase 4 region-direct JIT remains valid across reserve→fragmented commit→protect cycles.
4. **PE section permissions** (headers R, `.text` RX, `.rdata` R, `.data`/`.bss` RW, etc.) registered as real committed subregions, not one RWX slab.
5. **No host SIGSEGV as correctness mechanism** (roadmap non-goal). Optional `mprotect` is defense-in-depth only where host page size allows it.

### Non-goals (Phase 3)

- SIGSEGV / Mach exception handlers for guest faults.
- File-backed PE `mmap` (copy-based stays).
- Full CFG / `PAGE_TARGETS_*`, AWE, large pages, write-watch hardware emulation.
- Identity mapping or low 4 GiB host reservation.
- Making `VirtualProtect`/`VirtualQuery` into in-guest stubs (they stay host-dispatched; Phase 5 policy unchanged).
- Perfect Windows exception delivery (`STATUS_ACCESS_VIOLATION` → SEH); Phase 3 may report invalid access via existing `InvalidMemoryAccess` / error paths with correct _semantic_ denial; structured exception plumbing is later if needed.

### Definition of Done

| Item    | Check                                                                                                                                    |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 3.1     | Reads/writes/fetches to unmapped, reserved-only, or wrong-protect pages fail the same way on `hash`, `mmap`, `hybrid`                    |
| 3.2     | `VirtualAlloc` RESERVE / COMMIT / both; `VirtualFree` DECOMMIT / RELEASE; `VirtualProtect` + real `VirtualQuery` MBI; micro + unit tests |
| 3.3     | PE sections registered with differentiated protects; IAT patch still works; full micro-suite green all backends                          |
| Process | `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; `scripts/run-micro-suite.sh` under hash/mmap/hybrid   |

### Clean-room sources (Microsoft Learn only)

- [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [VirtualFree](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree)
- [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery) / MEMORY_BASIC_INFORMATION
- [Memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Page state](https://learn.microsoft.com/en-us/windows/win32/memory/page-state) (free / reserved / committed)
- PE COFF section characteristics (IMAGE_SCN_MEM_EXECUTE / READ / WRITE) via documented PE format fields already parsed by goblin — map _characteristics → PAGE__* using Learn constants only

---

## 1. Problem Analysis (the four critical edge cases)

### 1.1 Page clinch: Guest 4 KiB vs Host 16 KiB (macOS ARM64)

**Facts**

- WIE guest granule is fixed: `PAGE_SIZE = 0x1000` (`backend.rs`).
- Host anonymous `mmap` / `mprotect` on Apple Silicon is **16 KiB** aligned. A guest app may `VirtualAlloc`/`VirtualProtect` a **single 4 KiB** page with protect A next to another 4 KiB page with protect B inside the same host page.
- Today arenas are created with `PROT_READ | PROT_WRITE` for the entire span (`arena.rs`). Arena-level `perms: u32` is coarse and unused on the hot path.

**Why host-only enforcement is wrong for Phase 3**

If we `mprotect` a host 16 KiB frame to the _intersection_ of guest sub-page rights, a legitimate write to a RW guest page that shares the host page with a RO guest page can SIGSEGV the **emulator process**. If we use the _union_, host no longer rejects RO violations. Host faults therefore cannot implement Windows contracts under clinch.

**Chosen strategy: Software Permission Checks (SPC) as the sole correctness plane**

```
┌─────────────────────────────────────────────────────────────┐
│ Guest VA (4 KiB pages)                                       │
│  [ RX ][ R  ][ RW ][ -- ]  ← PageMap / VAD (software)       │
└──────────┬──────────────────────────────────────────────────┘
           │ soft translate (guest_va → host_ptr)
┌──────────▼──────────────────────────────────────────────────┐
│ Host storage (16 KiB host pages, arena or HashMap box)       │
│  Always host-accessible for *committed* content that may     │
│  need R or W (typically PROT_READ|PROT_WRITE on arenas).     │
│  Optional mprotect only on host-aligned *uniform* spans.     │
└─────────────────────────────────────────────────────────────┘
```

Rules:

1. **Correctness:** every `mem_read` / `mem_write` / instruction `fetch` / JIT TLB install path consults guest page state + protect **before** touching host memory.
2. **Host mapping:** committed guest pages that are stored in arenas keep the host mapping **RW** (data plane). Guest execute is **not** host execute — iced/JIT _read_ guest bytes as data; SPC treats “execute” as fetch permission only (`PAGE_EXECUTE*`).
3. **Optional mprotect (3.1 dual protection):** when an entire host-aligned span (16 KiB) has identical guest protect _and_ all sub-pages are committed, may tighten host prot to match the common case (e.g. all RO → host R). **Never** tighten if any 4 KiB sub-page needs more rights. **Never** use host faults as the denial path for mixed spans.
4. **HashMap backend:** each `Page` already has `perms`; enforce the same SPC rules; no host page-size issue for HashMap boxes (4 KiB host buffers). Hybrid: SPC is common above both stores.

### 1.2 MEM_RESERVE vs MEM_COMMIT and ArenaSet

**Windows contract (Learn)**

- `MEM_RESERVE`: carve VA without committing storage; later commit subsets.
- `MEM_COMMIT`: charge/commit within an already reserved range (or `RESERVE|COMMIT` in one call).
- Re-commit of already committed pages succeeds.
- Commit without reserve at a non-null address fails with `ERROR_INVALID_ADDRESS` unless the range is already reserved.

**Current gap**

`GuestMemBackend::map` eagerly creates host storage (arena or HashMap pages) and treats “mapped” as immediately readable/writable. There is no reserved-not-committed state. Layout heaps are fully mapped at session start (acceptable as pre-committed process heap), but dynamic VirtualAlloc is missing.

**Chosen strategy: Allocation (VAD) plane ≠ Host storage plane**

| Operation           | Software VAD                                                                            | Host storage (arena path)                                                                                                                                                                  |
| ------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| RESERVE large range | One allocation node: base, size, AllocationProtect, state=Reserved; pages Free→Reserved | **Create one contiguous `MmapArena` for the full reserved span** (or attach to existing if extending policy allows). Host pages demand-zero. `host_base` fixed for lifetime of reservation |
| COMMIT subset       | Per-page or run: state=Committed, Protect=flProtect                                     | **No new arena.** Software only flips pages to committed. Host bytes already zero from anonymous mmap                                                                                      |
| DECOMMIT subset     | Pages → Reserved (or Free if policy requires); contents discarded (zero)                | **No munmap.** Optionally `madvise(MADV_FREE)` / `posix_madvise` later for RSS; host_base unchanged                                                                                        |
| RELEASE whole alloc | Remove VAD node                                                                         | `munmap` exact arena if it was dedicated to this reservation; invalidate TLB/JIT pointers covering range                                                                                   |

Why mmap-on-reserve (not mmap-per-commit):

- Fragmented commits would otherwise create dozens of tiny arenas → `host_base` instability, Phase 4 pin failure, binary-search fragmentation.
- macOS anonymous mmap is demand-paged: reserving 1 GiB does not charge 1 GiB RSS until touch. Soft “uncommitted” prevents guest touch via SPC even though host mapping exists.
- Hybrid threshold: VirtualAlloc reservations **≥ hybrid threshold or always** should prefer a single arena for the whole reservation so sparse commits never scatter into HashMap pages mid-reservation (inconsistent host_base). Recommendation: **any MEM_RESERVE goes to a dedicated arena** under `mmap` and `hybrid`; under `hash`, reservation is software-only + HashMap pages allocated only on COMMIT.

**Allocation granularity vs page size**

Learn: reserve addresses round down to **allocation granularity** (Windows typically 64 KiB); commit rounds to **page** (4 KiB). Phase 3 must implement:

- `GUEST_PAGE_SIZE = 4 KiB` (existing).
- `GUEST_ALLOC_GRANULARITY = 64 KiB` (software constant matching documented Windows x64 behaviour for VirtualAlloc reserve alignment — not host page size).

NULL `lpAddress` reserve: pick a free guest VA hole from a high user-space search (existing layout uses high bases like `0x0000_7000_…` and image base from PE). Maintain a free-space cursor / hole list in the VAD manager; never place over stack/heap/image/fake API.

### 1.3 Cross-region / partial range edges (VirtualProtect / VirtualFree)

**Scenarios**

1. Protect `[stack_end-0x800, stack_end+0x800)` — straddles stack and free/other region → **must fail entirely** if any page is not compatible (Learn: entire range must be valid for the operation; none applied on failure).
2. Protect middle of one reserved/committed private allocation → **split** logical VAD runs so `VirtualQuery` reports correct `RegionSize` / `Protect` / `State`.
3. `MEM_DECOMMIT` partial inside allocation → decommit those pages only; allocation base remains; surrounding reserved/committed pages intact; **must not munmap** host memory that still backs sibling pages in the same arena.
4. `MEM_RELEASE` with non-zero size or address not allocation base → fail (`ERROR_INVALID_PARAMETER` per Learn).
5. Protect/free range covering PE image section boundary → operate on page runs inside image type; do not destroy adjacent section metadata incorrectly.

**Chosen strategy**

- All API operations are **transactional at the software VAD layer**: validate full page span first; then mutate; then optional host side-effects.
- Host arena is **never split** for protect/decommit (host_base stability). Splitting is **only** in the software interval map (page runs / VAD nodes).
- Arena destruction only on full RELEASE of an allocation that owns that arena end-to-end, or session teardown.
- Cross-allocation ranges: fail. Cross-kind (private vs image) ranges: fail unless the operation is defined (VirtualProtect across section runs of same image allocation base is OK if pages are committed — treat PE image as one AllocationBase = image_base with sub-runs of different Protect).

### 1.4 PE section mapping

**Today**

`session.rs`: single `mem_map(image_base, size_of_image, perm::ALL)` + bulk write of `build_loaded_image` buffer. `RegionTable` registers one `"image"` region with `perm::ALL`. Section characteristics ignored for protection.

**Target**

1. Still **one host arena** (or hybrid large map) for `[image_base, image_base+SizeOfImage)` for stable `host_base` and single soft-translate formula.
2. Software: image is one **MEM_IMAGE** allocation; after load, page runs match PE layout:
   - Headers `[0, SizeOfHeaders)` → `PAGE_READONLY` (after load complete).
   - Each section: round VirtualAddress/VirtualSize to guest pages; map characteristics:
     - EXECUTE+READ+!WRITE → `PAGE_EXECUTE_READ`
     - READ+WRITE → `PAGE_READWRITE` (and EXECUTE+WRITE → `PAGE_EXECUTE_READWRITE` if present)
     - READ only → `PAGE_READONLY`
     - gaps between sections inside SizeOfImage → reserved or `PAGE_NOACCESS` committed padding per loader-like behaviour (choose: leave as reserved-not-present for probes; or committed NOACCESS — document choice; recommend **committed PAGE_NOACCESS** for gap pages that were zero-filled in the image buffer so VirtualQuery matches “there is image space” without granting R/W).
3. **IAT patch window:** IAT often lives in `.rdata` (RO). Loader sequence:
   - Map/commit image pages with temporary `PAGE_READWRITE` (or at least IAT pages RW).
   - Copy sections + patch IAT / apply relocs if any.
   - `VirtualProtect`-equivalent to final section protects.
4. Register **named subregions** in `RegionTable` for diagnostics/Phase 4 (`image.headers`, `image.text`, …) **and** authoritative page runs in the new VAD/PageMap (RegionTable alone is insufficient for VirtualQuery runs).

---

## 2. Target Architecture

### 2.1 Layering

```
WinAPI (kernel32 Virtual*)
        │
        ▼
CpuEngine / GuestMemory  ── mem_virtual_alloc / free / protect / query
        │
        ▼
┌─────────────────── GuestVaSpace (NEW) ───────────────────┐
│  VAD tree / sorted allocation list                         │
│  PageMap (sparse): per guest page → State + Protect        │
│  SPC: check_access(va, len, AccessKind)                    │
│  Split/merge runs for Query / Protect                      │
└───────────────┬─────────────────────┬────────────────────┘
                │ controls            │ on commit/reserve
                ▼                     ▼
         RegionTable            GuestMemBackend
         (named layout)         map / read / write / unmap?
                                ArenaSet | HashMap | Hybrid
```

**Separation of duties**

| Component                | Owns                                          | Does not own                            |
| ------------------------ | --------------------------------------------- | --------------------------------------- |
| `GuestVaSpace` / PageMap | Windows-visible state, SPC, VirtualQuery runs | Host pointers                           |
| `ArenaSet` / backends    | Host bytes, soft translate, lifetime of mmap  | Windows page state                      |
| `RegionTable`            | Named layout pins for JIT/debug               | Authoritative VirtualQuery (may mirror) |

### 2.2 Data structures (proposed)

Place primarily in `crates/wie-cpu/src/mem/`:

```text
mem/
  vad.rs          // Allocation nodes + free VA search
  pagemap.rs      // Sparse guest page entries (state + protect)
  space.rs        // GuestVaSpace: API orchestration + SPC
  protect.rs      // PAGE_* ↔ internal bits, access checks
  arena.rs        // extend: optional host_prot; no per-guest-page host mprotect required
  backend.rs      // extend trait: unmap/decommit hooks optional
  mod.rs          // GuestMemory integrates space + storage
```

**`PageState`**

```rust
enum PageState {
    Free,       // not in any allocation
    Reserved,   // in allocation, not committed — SPC denies all access
    Committed,  // SPC uses Protect
}
```

**`PageProtect`** — store Windows `PAGE_*` values (u32), not only Unicorn rwx bits. Provide:

```rust
fn allows_read(p: u32) -> bool;
fn allows_write(p: u32) -> bool;
fn allows_execute(p: u32) -> bool; // fetch / JIT compile source
```

Mapping from legacy `perm::ALL = 7`:

| Internal rwx | Windows default          |
| ------------ | ------------------------ |
| 7            | `PAGE_EXECUTE_READWRITE` |
| 5 (r-x)      | `PAGE_EXECUTE_READ`      |
| 4 (r--)      | `PAGE_READONLY`          |
| 6 (rw-)      | `PAGE_READWRITE`         |
| 0            | `PAGE_NOACCESS`          |

Expand `wie_cpu::perm` to first-class READ/WRITE/EXEC bits **and** keep Windows constants in `wie_cpu::win_protect` or `mem::protect` so WinAPI and PE loader share one conversion path.

**`VadNode`**

```rust
struct VadNode {
    allocation_base: u64,      // rounded reserve base
    size: u64,                 // reservation size (granularity-aligned)
    allocation_protect: u32,   // flProtect at reserve time
    mem_type: MemType,         // Private | Image | (Mapped later)
    // Optional: arena_id / owns_arena flag for RELEASE → munmap
}
```

**PageMap storage options**

- Sparse `HashMap<u64 /*page_key*/, PageEntry>` — simple, good for tests.
- Or run-length encoding (`Vec<PageRun>`) for VirtualQuery speed.

Recommendation: **run-length `BTreeMap` of start_page → PageRun** for Query/Protect split performance, with O(log n) lookup for SPC. Hot path can cache last run (thread-local / engine-local single-entry cache) to keep SPC cheap.

**SPC hot path (performance)**

```text
check_access(va, size, kind):
  for each guest page spanned:
    entry = pagemap.lookup(page)   // cached run
    if entry.state != Committed: deny
    if !protect_allows(entry.protect, kind): deny
  ok
```

Optimizations (implement in order):

1. Single-page fast path (loads/stores ≤8 bytes rarely cross pages; still handle cross-page).
2. **Run cache:** last `(start, end, state, protect)` hit avoids tree walk for stack/heap streams.
3. JIT TLB: on fill, record protect bits or a generation counter; on protect/decommit, **bump `space_generation`** and flush TLB (or tag TLB entries with generation). Phase 3 minimum: **invalidate full JIT TLB + page_data_ptr cache on any protect/decommit/release** (correct, simple). Phase 4 can refine.
4. Do **not** call into VAD on every byte; page-granular loops only.

Interpreter path currently does not check `Page.perms` at all — wiring SPC into `GuestMemory::read/write/fetch_into` is mandatory and centralizes enforcement for all backends.

### 2.3 Backend API extensions

Extend `GuestMemBackend` carefully so HashMap/Mmap/Hybrid stay parity:

```rust
fn map(...)           // existing: ensure host storage exists (used by commit/load)
fn unmap_range(...)   // NEW: drop host storage for pages (RELEASE / full teardown)
fn discard_range(...) // NEW: zero pages; optional madvise; keep mapping (DECOMMIT)
// read/write/fetch unchanged but only called after SPC at GuestMemory layer
```

**Important:** SPC lives in `GuestMemory` / `GuestVaSpace`, **not** duplicated inside each backend. Backends remain storage engines. Backend `map` on already-mapped pages remains idempotent (data preserved).

**Arena RESERVE path**

```rust
// GuestVaSpace::reserve
backend.map(alloc_base, size, host_placeholder_perms)?; // creates arena RW
pagemap.set_range(..., Reserved, PAGE_NOACCESS);
// guest cannot read until commit even though host has mapping
```

**COMMIT path**

```rust
// validate all pages Reserved or Committed under same allocation_base
pagemap.set_range(..., Committed, flProtect);
// backend already has storage; if hash backend reserved without pages, map now
```

**Hash backend RESERVE:** may skip allocating `Box<[u8;4096]>` until COMMIT to save RAM (software-only reserve). **Mmap/Hybrid RESERVE:** prefer full-span arena for host_base stability as above.

### 2.4 CpuEngine surface

Add methods (object-safe) used by winapi:

```rust
fn virtual_alloc(&mut self, addr: u64, size: usize, alloc_type: u32, protect: u32) -> Result<u64, CpuError>;
fn virtual_free(&mut self, addr: u64, size: usize, free_type: u32) -> Result<(), CpuError>;
fn virtual_protect(&mut self, addr: u64, size: usize, new: u32) -> Result<u32 /*old*/, CpuError>;
fn virtual_query(&self, addr: u64) -> Result<MemoryBasicInformation, CpuError>;
```

Legacy `mem_map` used by session bootstrap becomes:

- Either a thin wrapper: `RESERVE|COMMIT` + protect derived from rwx bits, registered as Private (or Image when loader says so),
- Or an internal `force_commit_range` for trusted runtime layout that also updates PageMap.

**All session `mem_map` call sites must update PageMap**, or bootstrap will be invisible to VirtualQuery and SPC will deny PE/stack/heap. Migration plan: `GuestMemory::map` always inserts Committed pages with converted protect.

### 2.5 Optional host mprotect (dual protection)

Algorithm `sync_host_protect(range)`:

1. Expand range to host page boundaries (query via `libc::sysconf(_SC_PAGESIZE)` once, cache as `HOST_PAGE_SIZE`).
2. For each host page frame intersecting guest range:
   - Collect guest protects of all 4 KiB pages in frame.
   - If any guest page not committed → host keep RW (or leave as-is); SPC blocks guest.
   - If mixed guest protects → host **RW** (union of R/W needs); never host-RX tricks.
   - If uniform RO → optional `mprotect(R)`.
   - If uniform RW → `mprotect(RW)`.
3. Failures of mprotect are logged / ignored for correctness (SPC still rules).

Feature flag: always-on for mmap arenas in Phase 3 is fine if cheap; can gate with `WIE_MPROTECT=0` for debugging.

---

## 3. WinAPI Behaviour Spec (clean-room)

### 3.1 Constants (implement exactly)

| Name                   | Value     |
| ---------------------- | --------- |
| MEM_COMMIT             | 0x1000    |
| MEM_RESERVE            | 0x2000    |
| MEM_DECOMMIT           | 0x4000    |
| MEM_RELEASE            | 0x8000    |
| PAGE_NOACCESS          | 0x01      |
| PAGE_READONLY          | 0x02      |
| PAGE_READWRITE         | 0x04      |
| PAGE_EXECUTE           | 0x10      |
| PAGE_EXECUTE_READ      | 0x20      |
| PAGE_EXECUTE_READWRITE | 0x40      |
| MEM_PRIVATE            | 0x20000   |
| MEM_IMAGE              | 0x1000000 |

Phase 3 supports primary protect values above; `PAGE_GUARD` / `PAGE_WRITECOPY` / `MEM_RESET`: document as unsupported → `ERROR_INVALID_PARAMETER` or no-op policy (prefer **hard fail** for unknown flags to avoid silent wrong success).

### 3.2 VirtualAlloc

1. Validate `flAllocationType` contains RESERVE and/or COMMIT (not empty, not illegal combos for our subset).
2. Size 0 → fail.
3. Align:
   - RESERVE (new): base down to alloc granularity if addr≠0; size up so end covers request.
   - COMMIT only: base down to guest page; size up to page cover.
4. addr == 0: find free hole of required size (granularity-aligned); fail if none.
5. RESERVE: all pages in range must be Free; create VadNode; host arena/map as §2; pages Reserved.
6. COMMIT: all pages must be Reserved or Committed under one allocation; set Committed+protect; ensure host storage.
7. RESERVE|COMMIT: free pages only; create node; all Committed.
8. Success → return allocation base (reserve) or base of committed region as Learn describes.
9. Set `last_error` on failure paths in winapi layer.

### 3.3 VirtualFree

1. MEM_DECOMMIT: page-align range; pages must belong to same allocation; set Reserved; zero host bytes via `discard_range`; do not destroy VadNode; do not munmap arena.
2. MEM_RELEASE: `dwSize` must be 0; `lpAddress` must be `allocation_base`; decommit all; remove VadNode; unmap host arena if owned; free PageMap entries.
3. Invalidate JIT TLB / bump generation.

### 3.4 VirtualProtect

1. Keep Phase 5 fix: `lpflOldProtect == NULL` → fail `ERROR_INVALID_PARAMETER`.
2. Page-align range; every page must be **Committed** (Learn: protect committed pages).
3. `old` = protect of first page (Windows returns one old protect; region may need split so first-page-run is uniform — after split, first page’s previous protect).
4. Apply new protect; split runs; optional `sync_host_protect`; invalidate TLB if W removed or X changed.

### 3.5 VirtualQuery

Build real `MEMORY_BASIC_INFORMATION` (x64 layout 48 bytes):

| Field             | Source                                                      |
| ----------------- | ----------------------------------------------------------- |
| BaseAddress       | start of run with same State+Protect+Type within allocation |
| AllocationBase    | VadNode.allocation_base                                     |
| AllocationProtect | VadNode.allocation_protect                                  |
| RegionSize        | bytes to end of homogeneous run                             |
| State             | MEM_COMMIT / MEM_RESERVE / MEM_FREE                         |
| Protect           | page protect if committed else 0                            |
| Type              | MEM_PRIVATE / MEM_IMAGE / 0 if free                         |

Free VA: AllocationBase 0, RegionSize to next allocation or chosen free-run bound.

Replace current stub in `kernel32.rs` that always returns committed RWX 0x1000.

### 3.6 Wire-up

- `dispatch_kernel32_extra` / dense table: add `VirtualAlloc`, `VirtualFree` (Protect/Query already routed).
- Do **not** add guest stubs for these (Phase 5 policy).
- `GetSystemInfo` (if present): report `dwPageSize=0x1000`, `dwAllocationGranularity=0x10000` for guest-visible consistency — if not implemented, add minimal fields when touched by micros.

---

## 4. PE Loader Migration (3.3)

### Step sequence in `session.rs` / `wie-pe`

1. **Extend `wie-pe`** to emit structured load plan (no execution):

```rust
struct PeMapPlan {
  image_base, size_of_image, header_size,
  sections: Vec<PeSectionMap> {
    name, va, virtual_size, raw...,
    characteristics,
    final_protect: u32, // derived from characteristics
  }
}
```

2. **Derive protect** from section characteristics (COFF flags):

| Characteristics                      | final_protect          |
| ------------------------------------ | ---------------------- |
| MEM_EXECUTE \| MEM_READ              | PAGE_EXECUTE_READ      |
| MEM_READ \| MEM_WRITE                | PAGE_READWRITE         |
| MEM_EXECUTE \| MEM_READ \| MEM_WRITE | PAGE_EXECUTE_READWRITE |
| MEM_READ only                        | PAGE_READONLY          |
| none                                 | PAGE_NOACCESS          |

3. **Runtime load**:

```text
virtual_alloc(image_base, SizeOfImage, RESERVE|COMMIT, PAGE_READWRITE)
  OR trusted internal image_commit with MEM_IMAGE type
mem_write full built image (existing buffer path OK for Phase 3)
patch IAT (existing)
for each section run + headers:
  virtual_protect(final)
register RegionTable entries per section + image whole
```

4. **Relocs:** if currently assumed preferred base only, keep that; protect still applies.

5. **Guest code pages** (stubs, fake API): remain RWX or RX as appropriate; plant after image protect so stub writes use RW regions.

6. **Tests:** `inspect` CLI can print planned protects; unit test on a micro PE that `.text` is non-writable under SPC (write to entry page fails; fetch succeeds).

---

## 5. Implementation Phases (PR-sized steps)

### PR A — Protect model + SPC + PageMap (no VirtualAlloc yet)

**English implementation steps:**

1. Add `mem/protect.rs` with Windows PAGE_* constants, `AccessKind { Read, Write, Execute }`, `allows_*`.
2. Add `mem/pagemap.rs` run-length map: set_range, query_run, split, for_each_page.
3. Integrate into `GuestMemory`: on `map()`, mark pages Committed with protect from rwx or explicit PAGE_*.
4. Gate `read` / `write` / `fetch_into` with SPC; map failure to existing error strings / `InvalidMemoryAccess` shape for iced.
5. Expand `perm` module: READ=1, WRITE=2, EXEC=4 (compatible with ALL=7); convert to PAGE_*.
6. Unit tests: RO page write fails; RX fetch ok write fail; unmapped fail; cross-page write partial deny (all-or-nothing per operation: if any page denies, fail whole op without partial write — document and test).
7. Oracle: extend random ops with protect changes if feasible; at least backend parity for map/read/write still green.
8. `cargo clippy --workspace --all-targets -- -D warnings`.

**Risk:** session maps everything ALL — behaviour unchanged until PE PR. Good baseline.

### PR B — VAD + VirtualAlloc/Free + backend discard/unmap

1. Implement `VadNode` list + free VA allocator (high address scan, skip reserved layout).
2. Implement `virtual_alloc` / `virtual_free` on `GuestMemory` + `CpuEngine`.
3. Mmap/Hybrid: RESERVE creates one arena; COMMIT software-only; DECOMMIT zeros+Reserved; RELEASE munmap.
4. Hash: RESERVE software-only; COMMIT allocates pages; DECOMMIT drops pages from HashMap + clear radix leaf; RELEASE drops VAD.
5. Wire `kernel32` handlers; last_error codes.
6. Unit tests: reserve 1MiB commit 4K islands; re-commit ok; commit without reserve fails; release rules; host_base stable across commit (mmap).
7. Micro or new `micro-exes/virtual_alloc` if needed for DoD (roadmap cites winapi_heap — heap may not call VirtualAlloc; **add focused micro** for RESERVE/COMMIT/PROTECT/QUERY).
8. Clippy + all backends micro-suite.

### PR C — VirtualProtect + VirtualQuery + TLB invalidation

1. Protect with split runs; old protect out-param.
2. Real VirtualQuery MBI.
3. On protect/free: `JitCpu` full TLB flush + bump generation (minimal Phase 3).
4. Tests: protect subrange splits Query; NULL old protect fails; mixed range fail.
5. Clippy + suite.

### PR D — PE section mapping

1. `PeMapPlan` + characteristics → protect in `wie-pe`.
2. Session load sequence §4; RegionTable multi-entry.
3. SPC: write to `.text` fails after load; IAT slots writable only during patch window.
4. Optional mprotect sync for uniform host frames (image often has adjacent RX/R — clinch → host stays RW).
5. Full micro-suite all backends; clippy; short `docs/phase3-permissions.md`.

### PR E — Optional dual mprotect hardening + docs / roadmap checkbox

1. `HOST_PAGE_SIZE` detection; `sync_host_protect` on arena commits/protects.
2. Stress: 4K protect checkerboard inside 16K host page — guest RO denied by SPC, emulator process alive.
3. Update Optimization ROADMAP.md Phase 3 status; phase2 doc cross-links.

---

## 6. Edge-Case Matrix (must have tests)

| #   | Case                                       | Expected                                                 |
| --- | ------------------------------------------ | -------------------------------------------------------- |
| 1   | VirtualAlloc 4K COMMIT\|RESERVE            | Success; Query MEM_COMMIT                                |
| 2   | RESERVE 1GiB then COMMIT scattered 4K      | One arena (mmap); RSS not 1GiB; SPC only on committed    |
| 3   | COMMIT without prior RESERVE at fixed addr | Fail ERROR_INVALID_ADDRESS                               |
| 4   | Re-COMMIT committed pages                  | Success                                                  |
| 5   | VirtualProtect one 4K RO inside RW arena   | SPC denies write; host no crash; Query split             |
| 6   | Checkerboard RO/RW every 4K in 64K         | All enforcements software; optional mprotect no-op mixed |
| 7   | VirtualProtect range spanning two VadNodes | Fail entire op                                           |
| 8   | VirtualProtect into reserved-only pages    | Fail                                                     |
| 9   | DECOMMIT middle of allocation              | Pages reserved; neighbors intact; arena stays            |
| 10  | RELEASE with size≠0 or non-base            | Fail                                                     |
| 11  | RELEASE base                               | Pages free; munmap; Query free                           |
| 12  | PE .text write after load                  | Fail; fetch works                                        |
| 13  | PE .data write                             | Ok                                                       |
| 14  | IAT patch before final protect             | Ok                                                       |
| 15  | VirtualProtect NULL old                    | Fail (existing)                                          |
| 16  | Stack mem_map bootstrap still RW           | Micros green                                             |
| 17  | hash vs mmap vs hybrid same SPC results    | Oracle/property                                          |

---

## 7. Performance Budget

- SPC on hot path: one run-cache hit → few branches; target << HashMap lookup cost.
- Avoid per-byte syscalls; never mprotect per guest page.
- JIT: full TLB flush on protect is rare (loader + occasional runtime); acceptable for Phase 3.
- Large RESERVE: single mmap syscall; no page walk at reserve time.

---

## 8. Invalidation & Phase 4 readiness

When PageMap changes protect or drops commit:

1. Increment `GuestMemory::generation: u64`.
2. `JitCpu`: clear multi-way TLB; drop any cached host pointers.
3. `RegionTable.host_base`: remains valid if arena not released; on RELEASE clear host_base for affected regions.
4. Do not free host pointers while JIT might hold them — flush first, then munmap (ordering).

Phase 4 region-direct path must call SPC or trust generation-checked pins on ranges proven RW for the block lifetime — out of scope but design must not invent host_base that dies on decommit (decommit keeps mapping; only RELEASE kills host_base).

---

## 9. Verification Commands (post-code)

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
WIE_MEM=hash ./scripts/run-micro-suite.sh
WIE_MEM=mmap ./scripts/run-micro-suite.sh
WIE_MEM=hybrid ./scripts/run-micro-suite.sh
```

---

## 10. File Touch List (expected)

| Area        | Files                                                                                                                |
| ----------- | -------------------------------------------------------------------------------------------------------------------- |
| Core memory | `wie-cpu/src/mem/{mod,backend,arena,hybrid,hashmap,region}.rs`, new `protect.rs`, `pagemap.rs`, `vad.rs`, `space.rs` |
| CPU API     | `wie-cpu/src/lib.rs`, `iced_cpu.rs`, `jit/mod.rs`                                                                    |
| WinAPI      | `wie-winapi/src/kernel32.rs`, possibly `lib.rs` dispatch                                                             |
| PE          | `wie-pe/src/lib.rs` (map plan + characteristics)                                                                     |
| Session     | `wie-runtime/src/session.rs`                                                                                         |
| Docs        | `docs/phase3-permissions.md`, `Optimization ROADMAP.md`                                                              |
| Tests       | unit in mem + kernel32; optional `micro-exes/virtual_mem/`                                                           |

---

# Архитектурное ревью (русский)

## Суть этапа

Фаза 3 — это не «добавить mprotect», а **ввести полноценное гостевое виртуальное адресное пространство** поверх уже готового soft-translate storage (Phase 2). Сегодня у нас есть _хранилище байтов_ (HashMap / арены) и _декоративный_ `RegionTable`. Нет машины состояний Free/Reserved/Committed, нет enforcement прав, нет настоящего VirtualAlloc, а PE лежит одним RWX-слоем. Именно это и надо закрыть, не ломая стабильность `host_base` для будущего JIT.

## Четыре краевых случая — принятые решения

### 1. Клинч 4 КиБ / 16 КиБ

На Apple Silicon нельзя корректно выразить разные права соседних гостевых страниц через host `mprotect` без риска SIGSEGV самого эмулятора. **Корректность только через software permission checks** на каждом read/write/fetch (и при заполнении JIT TLB), с гранулярностью гостевых 4 КиБ. Host mapping для committed-данных остаётся достаточно широким (обычно RW); `mprotect` — опциональное ужесточение **только** для host-выровненных однородных прогонов. Это прямо следует roadmap («не опираться на host faults») и снимает класс фатальных падений.

### 2. RESERVE vs COMMIT

Критично **не плодить арены на каждый COMMIT**. Резервирование большого диапазона = один VAD-узел + **одна** анонимная арена (mmap/hybrid) с фиксированным `host_base`; commit — переключение записей PageMap. Reserved-но-не-committed страницы host-ом могут быть отображены (demand-zero), но SPC запрещает доступ — это дешевле и стабильнее, чем mmap по клочкам. На `hash` резерв может быть чисто программным, а страницы аллоцироваться при commit.

### 3. Распилы и пересечения

Операции API **транзакционны** на VAD/PageMap: сначала валидация всего диапазона, потом мутация. Частичный DECOMMIT/PROTECT **не режет host-арену** и не делает `munmap` «дыркой» внутри стека/кучи — только software-состояние (+ zero/discard). `munmap` — только на MEM_RELEASE целой аллокации. Пересечение двух allocation base → полный отказ операции. Так мы не снесем соседний регион и не инвалидируем лишние host-указатели.

### 4. PE-секции

Один image-арена на `SizeOfImage` (стабильный translate) + дифференцированные page runs по characteristics. Временное RW на время copy/IAT, затем protect в RX/R/RW. `RegionTable` получит именованные куски, но **источник истины для VirtualQuery — PageMap/VAD**, не layout registry.

## Риски

| Риск                                   | Митигация                                               |
| -------------------------------------- | ------------------------------------------------------- |
| SPC замедлит hot path                  | run-cache + page-granular checks; без syscall на access |
| Забыть PageMap на bootstrap `mem_map`  | `GuestMemory::map` всегда обновляет PageMap             |
| JIT держит stale pointer после RELEASE | flush TLB → затем munmap; generation counter            |
| Смешение rwx Unicorn-бит и PAGE_*      | единый `protect.rs`, явные конвертеры                   |
| Micros не бьют VirtualAlloc            | отдельный micro + unit matrix §6                        |
| Слишком большой PR                     | нарезка A→E (§5)                                        |

## Что сознательно не делаем

- Не копируем дизайн Wine/ReactOS; только контракты Microsoft Learn.
- Не делаем SIGSEGV-эмуляцию AV.
- Не выносим VirtualProtect/Query в guest stubs (Phase 5 policy).
- Не file-backed PE mmap.

## Порядок внедрения (кратко)

1. **PR A:** PageMap + SPC (поведение micros не ломается при ALL).
2. **PR B:** VAD + VirtualAlloc/Free + discard/unmap.
3. **PR C:** Protect/Query + TLB invalidate.
4. **PR D:** PE section protects.
5. **PR E:** optional host mprotect + docs; clippy/suite на hash/mmap/hybrid.

## Вердикт

Архитектура фазово согласована с Phase 2 (soft translate, targeted arenas) и Phase 4 (stable `host_base`, TLB generation). Главный инвариант фазы 3: **«Windows page state — software; host mapping — capacity and stability; host PTE — never the guest permission oracle under 4K/16K clinch.»** При соблюдении нарезки PR и матрицы тестов этап 3 реалистичен без упрощений-заглушек и без подглядывания в чужие эмуляторы.
