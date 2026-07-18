//! Guest virtual memory for interpreter + JIT (x86-64 only).
//!
//! Phase 2–3 layout:
//! - [`GuestMemBackend`] — storage trait
//! - [`HashMapBackend`] — `WIE_MEM=hash` (eager pages + radix)
//! - [`MmapArenaBackend`] — `WIE_MEM=mmap` (contiguous anonymous arenas)
//! - [`HybridBackend`] — large arenas + sparse HashMap (`WIE_MEM=hybrid`, default)
//! - [`RegionTable`] — named layout ranges (`host_base` filled for mmap arenas)
//! - [`PageMap`] / [`protect`] — Windows page state + software permission checks
//! - [`GuestMemory`] — facade used by iced/JIT (SPC on read/write/fetch)

mod arena;
mod backend;
mod hashmap;
mod hybrid;
mod mmap_arena;
mod pagemap;
pub mod protect;
mod region;
mod vad;

#[cfg(test)]
mod mmap_page;
#[cfg(test)]
mod oracle;

pub use backend::{GuestMemBackend, PAGE_SIZE, PAGE_SIZE_USIZE};
pub use hashmap::HashMapBackend;
pub use hybrid::HybridBackend;
pub use mmap_arena::MmapArenaBackend;
pub use pagemap::{PageMap, PageRun, PageState};
pub use region::{GuestRegion, RegionKind, RegionTable};
pub use vad::{
    align_down, align_up, win32_from_cpu_error, GUEST_ALLOC_GRANULARITY, MEM_COMMIT, MEM_DECOMMIT,
    MEM_FREE, MEM_IMAGE, MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE, MemType, VadNode, VadTable,
    ERROR_INVALID_ADDRESS, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY,
};
use vad::va_error;

#[cfg(test)]
use backend::page_key;

/// How guest pages are stored (`WIE_MEM`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemBackendKind {
    /// Eager HashMap + radix only.
    Hash,
    /// Every map is an anonymous arena.
    Mmap,
    /// Large maps → arena; tiny maps → HashMap.
    Hybrid,
}

impl MemBackendKind {
    /// Parse `WIE_MEM` (`hash` / `mmap` / `hybrid`). Default: hybrid.
    #[must_use]
    pub(crate) fn from_env() -> Self {
        match std::env::var("WIE_MEM") {
            Ok(v) if v.eq_ignore_ascii_case("hash") => Self::Hash,
            Ok(v) if v.eq_ignore_ascii_case("mmap") => Self::Mmap,
            Ok(v) if v.eq_ignore_ascii_case("hybrid") => Self::Hybrid,
            Ok(v) if v.eq_ignore_ascii_case("mmap_page") => Self::Mmap, // alias
            _ => Self::Hybrid,
        }
    }

}

/// Concrete storage behind [`GuestMemory`].
enum Storage {
    Hash(HashMapBackend),
    Mmap(MmapArenaBackend),
    Hybrid(HybridBackend),
}

impl Storage {
    fn new(kind: MemBackendKind) -> Self {
        match kind {
            MemBackendKind::Hash => Self::Hash(HashMapBackend::new()),
            MemBackendKind::Mmap => Self::Mmap(MmapArenaBackend::new()),
            MemBackendKind::Hybrid => Self::Hybrid(HybridBackend::new()),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Hash(b) => b.name(),
            Self::Mmap(b) => b.name(),
            Self::Hybrid(b) => b.name(),
        }
    }

    fn map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), crate::CpuError> {
        match self {
            Self::Hash(b) => b.map(address, size, perms),
            Self::Mmap(b) => b.map(address, size, perms),
            Self::Hybrid(b) => b.map(address, size, perms),
        }
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), crate::CpuError> {
        match self {
            Self::Hash(b) => b.write(address, bytes),
            Self::Mmap(b) => b.write(address, bytes),
            Self::Hybrid(b) => b.write(address, bytes),
        }
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), crate::CpuError> {
        match self {
            Self::Hash(b) => b.read(address, bytes),
            Self::Mmap(b) => b.read(address, bytes),
            Self::Hybrid(b) => b.read(address, bytes),
        }
    }

    fn page_data_ptr(&mut self, page_key: u64) -> Option<*mut u8> {
        match self {
            Self::Hash(b) => b.page_data_ptr(page_key),
            Self::Mmap(b) => b.page_data_ptr(page_key),
            Self::Hybrid(b) => b.page_data_ptr(page_key),
        }
    }

    fn page_data_ptr_walk(&self, page_key: u64) -> Option<*mut u8> {
        match self {
            Self::Hash(b) => b.page_data_ptr_walk(page_key),
            Self::Mmap(b) => b.page_data_ptr_walk(page_key),
            Self::Hybrid(b) => b.page_data_ptr_walk(page_key),
        }
    }

    fn fetch_into(&self, address: u64, out: &mut [u8]) -> Result<usize, crate::CpuError> {
        match self {
            Self::Hash(b) => b.fetch_into(address, out),
            Self::Mmap(b) => b.fetch_into(address, out),
            Self::Hybrid(b) => b.fetch_into(address, out),
        }
    }

    /// Host base of an mmap arena covering `va`, if any.
    fn arena_host_base_for_va(&self, va: u64) -> Option<u64> {
        match self {
            Self::Hash(_) => None,
            Self::Mmap(b) => b.arena_host_base_for_va(va),
            Self::Hybrid(b) => b.arena_host_base_for_va(va),
        }
    }

    /// Whether RESERVE should create host storage immediately (mmap/hybrid).
    fn reserve_maps_host(&self) -> bool {
        !matches!(self, Self::Hash(_))
    }

    fn unmap_range(&mut self, address: u64, size: usize) {
        match self {
            Self::Hash(b) => b.unmap_range(address, size),
            Self::Mmap(b) => b.unmap_range(address, size),
            Self::Hybrid(b) => b.unmap_range(address, size),
        }
    }

    fn discard_range(&mut self, address: u64, size: usize) -> Result<(), crate::CpuError> {
        match self {
            Self::Hash(b) => {
                b.discard_range(address, size);
                Ok(())
            }
            Self::Mmap(b) => b.discard_range(address, size),
            Self::Hybrid(b) => b.discard_range(address, size),
        }
    }
}

/// Guest memory: pluggable backend + region registry + software page map (SPC).
///
/// Call sites keep using this type; storage is selected via `WIE_MEM`.
/// Permission enforcement lives here (not inside backends) so all backends share
/// identical Windows-visible behaviour.
pub(crate) struct GuestMemory {
    backend: Storage,
    regions: RegionTable,
    pages: PageMap,
    vad: VadTable,
    /// Bumped when protect/commit/release change; JIT flushes TLB on change (Phase 3+).
    generation: u64,
}

impl Default for GuestMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for GuestMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestMemory")
            .field("backend", &self.backend.name())
            .field("regions", &self.regions.len())
            .field("page_runs", &self.pages.run_count())
            .field("vad", &self.vad.len())
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl GuestMemory {
    /// Create with backend from `WIE_MEM` (default hybrid).
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_kind(MemBackendKind::from_env())
    }

    /// Create with an explicit backend kind (tests).
    #[must_use]
    pub(crate) fn with_kind(kind: MemBackendKind) -> Self {
        Self {
            backend: Storage::new(kind),
            regions: RegionTable::new(),
            pages: PageMap::new(),
            vad: VadTable::new(),
            generation: 0,
        }
    }

    /// Active storage backend name (`hash` / `mmap` / `hybrid`).
    #[must_use]
    pub(crate) fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    /// Monotonic generation for TLB / pin invalidation.
    #[must_use]
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Software page map (tests / VirtualQuery plumbing).
    #[must_use]
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn page_map(&self) -> &PageMap {
        &self.pages
    }

    /// Register a named layout range; fill `host_base` when an arena covers it.
    pub(crate) fn register_region(&mut self, mut region: GuestRegion) {
        if region.host_base.is_none()
            && let Some(hb) = self.backend.arena_host_base_for_va(region.base)
        {
            region.host_base = Some(hb);
        }
        self.regions.register(region);
    }

    /// Find the named region containing `va`.
    #[must_use]
    pub(crate) fn find_region(&self, va: u64) -> Option<&GuestRegion> {
        self.regions.find(va)
    }

    /// Map `[address, address+size)` with Unicorn-style `perms` (r/w/x).
    ///
    /// Creates host storage, marks pages **Committed**, and registers a private
    /// VAD node so free-VA search and VirtualQuery see bootstrap layout.
    pub(crate) fn map(
        &mut self,
        address: u64,
        size: usize,
        perms: u32,
    ) -> Result<(), crate::CpuError> {
        self.backend.map(address, size, perms)?;
        let protect = protect::page_protect_from_rwx(perms);
        self.pages
            .set_range(address, size, PageState::Committed, protect)?;
        let size_u64 = u64::try_from(size).map_err(|_| {
            crate::CpuError::Message(format!("mem_map size {size} does not fit u64"))
        })?;
        // Bootstrap maps may overlap an existing VAD only on rematch of the same
        // base (idempotent map). Skip insert if already covered by same base.
        if self.vad.find_base(address).is_none() && !self.vad.overlaps(address, size_u64) {
            self.vad.insert(VadNode {
                allocation_base: address,
                size: size_u64,
                allocation_protect: protect,
                mem_type: MemType::Private,
                owns_host: true,
            })?;
        }
        self.generation = self.generation.saturating_add(1);
        // Backfill host_base for regions already registered that this map covers.
        if let Some(hb) = self.backend.arena_host_base_for_va(address) {
            self.regions.set_host_base_if_covers(address, hb);
        }
        Ok(())
    }

    /// `VirtualAlloc` — reserve and/or commit private pages.
    ///
    /// Returns the allocation base (reserve) or the committed region base.
    pub(crate) fn virtual_alloc(
        &mut self,
        addr: u64,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> Result<u64, crate::CpuError> {
        let do_reserve = (alloc_type & MEM_RESERVE) != 0;
        let do_commit = (alloc_type & MEM_COMMIT) != 0;
        if size == 0 || (!do_reserve && !do_commit) {
            return Err(va_error(
                ERROR_INVALID_PARAMETER,
                "VirtualAlloc size/type invalid",
            ));
        }
        // Reject unknown type bits beyond RESERVE|COMMIT for Phase 3.
        let known = MEM_RESERVE | MEM_COMMIT;
        if alloc_type & !known != 0 {
            return Err(va_error(
                ERROR_INVALID_PARAMETER,
                "VirtualAlloc unsupported allocation type flags",
            ));
        }
        if !protect::is_supported_protect(protect) {
            return Err(va_error(
                ERROR_INVALID_PARAMETER,
                "VirtualAlloc unsupported protect",
            ));
        }

        if do_reserve && do_commit {
            self.va_reserve_and_commit(addr, size, protect)
        } else if do_reserve {
            self.va_reserve_only(addr, size, protect)
        } else {
            self.va_commit_only(addr, size, protect)
        }
    }

    /// `VirtualFree` — decommit pages or release a whole allocation.
    pub(crate) fn virtual_free(
        &mut self,
        addr: u64,
        size: usize,
        free_type: u32,
    ) -> Result<(), crate::CpuError> {
        let decommit = (free_type & MEM_DECOMMIT) != 0;
        let release = (free_type & MEM_RELEASE) != 0;
        if decommit == release {
            // Exactly one of DECOMMIT or RELEASE.
            return Err(va_error(
                ERROR_INVALID_PARAMETER,
                "VirtualFree type must be DECOMMIT or RELEASE",
            ));
        }
        if release {
            if size != 0 {
                return Err(va_error(
                    ERROR_INVALID_PARAMETER,
                    "VirtualFree MEM_RELEASE requires size 0",
                ));
            }
            return self.va_release(addr);
        }
        self.va_decommit(addr, size)
    }

    fn va_reserve_only(
        &mut self,
        addr: u64,
        size: usize,
        protect: u32,
    ) -> Result<u64, crate::CpuError> {
        let (base, size_u64) = self.align_reserve_request(addr, size)?;
        self.ensure_pages_free(base, size_u64)?;
        // Host storage: mmap/hybrid create one arena for the full reservation.
        if self.backend.reserve_maps_host() {
            let size_usize = usize::try_from(size_u64).map_err(|_| {
                va_error(ERROR_NOT_ENOUGH_MEMORY, "reserve size does not fit usize")
            })?;
            // Host RW; SPC uses Reserved so guest cannot touch until commit.
            self.backend.map(base, size_usize, crate::perm::ALL)?;
        }
        let size_usize = usize::try_from(size_u64).map_err(|_| {
            va_error(ERROR_NOT_ENOUGH_MEMORY, "reserve size does not fit usize")
        })?;
        self.pages.set_range(
            base,
            size_usize,
            PageState::Reserved,
            protect::PAGE_NOACCESS,
        )?;
        self.vad.insert(VadNode {
            allocation_base: base,
            size: size_u64,
            allocation_protect: protect,
            mem_type: MemType::Private,
            owns_host: self.backend.reserve_maps_host(),
        })?;
        self.generation = self.generation.saturating_add(1);
        Ok(base)
    }

    fn va_reserve_and_commit(
        &mut self,
        addr: u64,
        size: usize,
        protect: u32,
    ) -> Result<u64, crate::CpuError> {
        let (base, size_u64) = self.align_reserve_request(addr, size)?;
        self.ensure_pages_free(base, size_u64)?;
        let size_usize = usize::try_from(size_u64).map_err(|_| {
            va_error(ERROR_NOT_ENOUGH_MEMORY, "alloc size does not fit usize")
        })?;
        // Host storage for full span (all backends).
        self.backend
            .map(base, size_usize, protect::rwx_from_page_protect(protect))?;
        self.pages
            .set_range(base, size_usize, PageState::Committed, protect)?;
        self.vad.insert(VadNode {
            allocation_base: base,
            size: size_u64,
            allocation_protect: protect,
            mem_type: MemType::Private,
            owns_host: true,
        })?;
        self.generation = self.generation.saturating_add(1);
        Ok(base)
    }

    fn va_commit_only(
        &mut self,
        addr: u64,
        size: usize,
        protect: u32,
    ) -> Result<u64, crate::CpuError> {
        if addr == 0 {
            // COMMIT with NULL address is not supported without RESERVE in Phase 3.
            return Err(va_error(
                ERROR_INVALID_PARAMETER,
                "VirtualAlloc COMMIT requires address or RESERVE",
            ));
        }
        let page_base = align_down(addr, PAGE_SIZE);
        let end = addr
            .checked_add(u64::try_from(size).map_err(|_| {
                va_error(ERROR_INVALID_PARAMETER, "commit size overflow")
            })?)
            .ok_or_else(|| va_error(ERROR_INVALID_PARAMETER, "commit end overflow"))?;
        let page_end = align_up(end, PAGE_SIZE);
        let size_u64 = page_end.saturating_sub(page_base);
        let size_usize = usize::try_from(size_u64)
            .map_err(|_| va_error(ERROR_NOT_ENOUGH_MEMORY, "commit size"))?;

        let node = self.vad.find(page_base).ok_or_else(|| {
            va_error(
                ERROR_INVALID_ADDRESS,
                "VirtualAlloc COMMIT without prior RESERVE",
            )
        })?;
        if !node.contains_range(page_base, size_u64) {
            return Err(va_error(
                ERROR_INVALID_ADDRESS,
                "VirtualAlloc COMMIT range outside allocation",
            ));
        }
        // All pages must be Reserved or already Committed under this allocation.
        let mut page = page_base >> 12;
        let last = page_end >> 12;
        while page < last {
            match self.pages.lookup(page) {
                Some(run)
                    if run.state == PageState::Reserved || run.state == PageState::Committed =>
                {
                    let next = run.end_page.min(last);
                    if next <= page {
                        return Err(va_error(
                            ERROR_INVALID_ADDRESS,
                            "VirtualAlloc COMMIT corrupt pagemap",
                        ));
                    }
                    page = next;
                }
                _ => {
                    return Err(va_error(
                        ERROR_INVALID_ADDRESS,
                        "VirtualAlloc COMMIT on free page",
                    ));
                }
            }
        }

        // Hash: allocate host pages now. Mmap: storage already present from RESERVE.
        if matches!(self.backend, Storage::Hash(_))
            || self.backend.page_data_ptr_walk(page_base >> 12).is_none()
        {
            self.backend
                .map(page_base, size_usize, protect::rwx_from_page_protect(protect))?;
        }
        self.pages
            .set_range(page_base, size_usize, PageState::Committed, protect)?;
        self.generation = self.generation.saturating_add(1);
        Ok(page_base)
    }

    fn va_decommit(&mut self, addr: u64, size: usize) -> Result<(), crate::CpuError> {
        if size == 0 {
            return Err(va_error(
                ERROR_INVALID_PARAMETER,
                "VirtualFree DECOMMIT size 0",
            ));
        }
        let page_base = align_down(addr, PAGE_SIZE);
        let end = addr
            .checked_add(u64::try_from(size).map_err(|_| {
                va_error(ERROR_INVALID_PARAMETER, "decommit size")
            })?)
            .ok_or_else(|| va_error(ERROR_INVALID_PARAMETER, "decommit overflow"))?;
        let page_end = align_up(end, PAGE_SIZE);
        let size_u64 = page_end.saturating_sub(page_base);
        let size_usize = usize::try_from(size_u64)
            .map_err(|_| va_error(ERROR_NOT_ENOUGH_MEMORY, "decommit size"))?;

        let node = self.vad.find(page_base).ok_or_else(|| {
            va_error(ERROR_INVALID_ADDRESS, "DECOMMIT outside allocation")
        })?;
        if !node.contains_range(page_base, size_u64) {
            return Err(va_error(
                ERROR_INVALID_ADDRESS,
                "DECOMMIT range crosses allocation",
            ));
        }
        // Transactional: every page must belong to this allocation (already checked)
        // and be Reserved or Committed (free is invalid).
        let mut page = page_base >> 12;
        let last = page_end >> 12;
        while page < last {
            match self.pages.lookup(page) {
                Some(run)
                    if run.state == PageState::Reserved || run.state == PageState::Committed =>
                {
                    let next = run.end_page.min(last);
                    if next <= page {
                        return Err(va_error(
                            ERROR_INVALID_ADDRESS,
                            "DECOMMIT corrupt pagemap",
                        ));
                    }
                    page = next;
                }
                _ => {
                    return Err(va_error(
                        ERROR_INVALID_ADDRESS,
                        "DECOMMIT free page in range",
                    ));
                }
            }
        }

        self.backend.discard_range(page_base, size_usize)?;
        self.pages.set_range(
            page_base,
            size_usize,
            PageState::Reserved,
            protect::PAGE_NOACCESS,
        )?;
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    fn va_release(&mut self, addr: u64) -> Result<(), crate::CpuError> {
        let node = self
            .vad
            .find_base(addr)
            .cloned()
            .ok_or_else(|| va_error(ERROR_INVALID_ADDRESS, "MEM_RELEASE not allocation base"))?;
        let size_usize = usize::try_from(node.size)
            .map_err(|_| va_error(ERROR_NOT_ENOUGH_MEMORY, "release size"))?;
        // Flush software state first conceptually; drop host after (Drop munmap).
        self.pages
            .set_range(node.allocation_base, size_usize, PageState::Free, 0)?;
        let _ = self.vad.remove_base(addr);
        if node.owns_host {
            self.backend.unmap_range(node.allocation_base, size_usize);
        } else {
            // Hash reserve-only: may have committed pages still in the map.
            self.backend.unmap_range(node.allocation_base, size_usize);
        }
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    fn align_reserve_request(
        &self,
        addr: u64,
        size: usize,
    ) -> Result<(u64, u64), crate::CpuError> {
        let size_u64 = u64::try_from(size)
            .map_err(|_| va_error(ERROR_INVALID_PARAMETER, "size does not fit u64"))?;
        if addr == 0 {
            let rounded = align_up(size_u64, GUEST_ALLOC_GRANULARITY);
            if rounded == 0 {
                return Err(va_error(ERROR_INVALID_PARAMETER, "reserve size 0"));
            }
            let base = self
                .vad
                .find_free_region(rounded, &|page| self.pages.lookup(page).is_some())
                .ok_or_else(|| {
                    va_error(ERROR_NOT_ENOUGH_MEMORY, "no free guest VA for reserve")
                })?;
            return Ok((base, rounded));
        }
        let base = align_down(addr, GUEST_ALLOC_GRANULARITY);
        let end = addr
            .checked_add(size_u64)
            .ok_or_else(|| va_error(ERROR_INVALID_PARAMETER, "reserve end overflow"))?;
        let end_aligned = align_up(end, GUEST_ALLOC_GRANULARITY);
        let span = end_aligned.saturating_sub(base);
        if span == 0 {
            return Err(va_error(ERROR_INVALID_PARAMETER, "reserve span 0"));
        }
        Ok((base, span))
    }

    fn ensure_pages_free(&self, base: u64, size: u64) -> Result<(), crate::CpuError> {
        let end = base.saturating_add(size);
        let mut page = base >> 12;
        let last = end >> 12;
        while page < last {
            if let Some(run) = self.pages.lookup(page) {
                // Presence in the map means Reserved or Committed (Free is absent).
                let next = run.end_page.min(last);
                if next <= page {
                    return Err(va_error(
                        ERROR_INVALID_ADDRESS,
                        "reserve over non-free page",
                    ));
                }
                return Err(va_error(
                    ERROR_INVALID_ADDRESS,
                    "reserve over non-free page",
                ));
            }
            page = page.saturating_add(1);
        }
        if self.vad.overlaps(base, size) {
            return Err(va_error(
                ERROR_INVALID_ADDRESS,
                "reserve over existing VAD",
            ));
        }
        Ok(())
    }

    /// Write `bytes` at guest `address` after SPC (write permission).
    pub(crate) fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), crate::CpuError> {
        self.pages
            .check_access(address, bytes.len(), protect::AccessKind::Write)?;
        self.backend.write(address, bytes)
    }

    /// Read into `bytes` from guest `address` after SPC (read permission).
    pub(crate) fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), crate::CpuError> {
        self.pages
            .check_access(address, bytes.len(), protect::AccessKind::Read)?;
        self.backend.read(address, bytes)
    }

    /// Instruction fetch into a small stack buffer after SPC (execute permission).
    pub(crate) fn fetch_into(
        &self,
        address: u64,
        out: &mut [u8],
    ) -> Result<usize, crate::CpuError> {
        let want = out.len().min(15);
        if want == 0 {
            return Ok(0);
        }
        // Fetch may shorten on the trailing edge of a mapping (same as backend
        // default), but never past a permission boundary: try full length first,
        // then shrink until a legal prefix is found.
        let mut len = want;
        while len > 0 {
            if self
                .pages
                .check_access(address, len, protect::AccessKind::Execute)
                .is_ok()
            {
                let Some(dst) = out.get_mut(..len) else {
                    break;
                };
                return self.backend.fetch_into(address, dst);
            }
            len = len.saturating_sub(1);
        }
        Err(crate::CpuError::Message(format!(
            "instruction fetch unmapped {address:#x}"
        )))
    }

    /// Host pointer to a mapped page's data (JIT TLB).
    ///
    /// Returns `None` if the page is not committed (JIT must not install a TLB
    /// entry for free/reserved pages). `PAGE_NOACCESS` also yields `None`.
    #[must_use]
    pub(crate) fn page_data_ptr(&mut self, page_key: u64) -> Option<*mut u8> {
        let run = self.pages.lookup(page_key)?;
        if run.state != PageState::Committed {
            return None;
        }
        // Allow TLB install if any access is possible; store/load still go
        // through SPC on the slow path. Phase 3.2+ may tag entries with protect.
        if !protect::allows_read(run.protect)
            && !protect::allows_write(run.protect)
            && !protect::allows_execute(run.protect)
        {
            return None;
        }
        self.backend.page_data_ptr(page_key)
    }

    /// Fast page-table walk (HashMap radix or arena formula).
    #[must_use]
    pub(crate) fn page_data_ptr_walk(&self, page_key: u64) -> Option<*mut u8> {
        let run = self.pages.lookup(page_key)?;
        if run.state != PageState::Committed {
            return None;
        }
        self.backend.page_data_ptr_walk(page_key)
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use super::{
        win32_from_cpu_error, ERROR_INVALID_ADDRESS, GUEST_ALLOC_GRANULARITY, MEM_COMMIT,
        MEM_DECOMMIT, MEM_RELEASE, MEM_RESERVE,
    };

    #[test]
    fn page_table_walk_matches_map() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        mem.map(0x10_0000, 0x2000, 7).expect("map");
        let k = page_key(0x10_0000);
        let p = mem.page_data_ptr_walk(k).expect("walk");
        assert!(!p.is_null());
        let p2 = mem.page_data_ptr(k).expect("hash");
        assert_eq!(p, p2);
        assert!(mem.page_data_ptr_walk(k + 100).is_none());
    }

    #[test]
    fn page_table_high_va() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        let base = 0x0000_7fff_0000_0000_u64;
        mem.map(base, 0x1000, 7).expect("map high");
        let k = page_key(base);
        assert!(mem.page_data_ptr_walk(k).is_some());
    }

    #[test]
    fn region_registry_find() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        mem.register_region(GuestRegion::new(
            "stack",
            RegionKind::Stack,
            0x2000_0000,
            0x1_0000,
            7,
        ));
        mem.map(0x2000_0000, 0x1_0000, 7).expect("map stack");
        assert_eq!(mem.find_region(0x2000_0800).expect("found").name, "stack");
        assert_eq!(mem.backend_name(), "hash");
    }

    #[test]
    fn mmap_backend_host_base_on_register() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Mmap);
        mem.map(0x2000_0000, 0x1_0000, 7).expect("map stack");
        mem.register_region(GuestRegion::new(
            "stack",
            RegionKind::Stack,
            0x2000_0000,
            0x1_0000,
            7,
        ));
        let r = mem.find_region(0x2000_0800).expect("found");
        let hb = r.host_base.expect("host_base should be filled from arena");
        assert_ne!(hb, 0);
        let p = mem.page_data_ptr_walk(0x2000_0800 >> 12).expect("page");
        assert!(!p.is_null());
        assert_eq!(mem.backend_name(), "mmap");
    }

    #[test]
    fn hybrid_backend_name() {
        let mem = GuestMemory::with_kind(MemBackendKind::Hybrid);
        assert_eq!(mem.backend_name(), "hybrid");
    }

    #[test]
    fn mmap_page_ptr_walk() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Mmap);
        mem.map(0x10_0000, 0x2000, 7).expect("map");
        let k = page_key(0x10_0000);
        let p = mem.page_data_ptr_walk(k).expect("walk");
        let p2 = mem.page_data_ptr(k).expect("ptr");
        assert_eq!(p, p2);
    }

    #[test]
    fn spc_readonly_write_fails_read_ok() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        mem.map(0x20_0000, 0x1000, crate::perm::READ).expect("map RO");
        let mut buf = [0_u8; 4];
        mem.read(0x20_0000, &mut buf).expect("read ok");
        assert!(mem.write(0x20_0000, &[1, 2, 3, 4]).is_err());
        // Host storage still present; failure is SPC, not unmapped.
        let err = mem.write(0x20_0000, &[1]).expect_err("write denied");
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn spc_rx_fetch_ok_write_fails() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        mem.map(
            0x30_0000,
            0x1000,
            crate::perm::READ | crate::perm::EXEC,
        )
        .expect("map RX");
        // Seed bytes via backend would bypass SPC; map is zeroed — fetch still ok.
        let mut out = [0_u8; 15];
        let n = mem.fetch_into(0x30_0000, &mut out).expect("fetch");
        assert!(n > 0);
        assert!(mem.write(0x30_0000, &[0x90]).is_err());
    }

    #[test]
    fn spc_unmapped_fails() {
        let mem = GuestMemory::with_kind(MemBackendKind::Hash);
        let mut buf = [0_u8; 4];
        assert!(mem.read(0x40_0000, &mut buf).is_err());
    }

    #[test]
    fn spc_cross_page_all_or_nothing() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        mem.map(0x50_0000, 0x1000, crate::perm::ALL).expect("map one");
        // Write straddling into unmapped second page must not partial-write.
        let payload = [0xAAu8; 8];
        assert!(mem.write(0x50_0ffc, &payload).is_err());
        let mut check = [0_u8; 4];
        mem.read(0x50_0ffc, &mut check).expect("prefix still zero");
        assert_eq!(check, [0, 0, 0, 0]);
    }

    #[test]
    fn spc_same_on_all_backends() {
        for kind in [
            MemBackendKind::Hash,
            MemBackendKind::Mmap,
            MemBackendKind::Hybrid,
        ] {
            let mut mem = GuestMemory::with_kind(kind);
            mem.map(0x60_0000, 0x1000, crate::perm::READ).expect("map");
            assert!(
                mem.write(0x60_0000, &[1]).is_err(),
                "backend {}",
                mem.backend_name()
            );
            let mut b = [0_u8; 1];
            mem.read(0x60_0000, &mut b).expect("read");
        }
    }

    #[test]
    fn map_updates_pagemap_committed() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        mem.map(0x70_0000, 0x2000, crate::perm::ALL).expect("map");
        let run = mem.page_map().query_run(0x70_0000).expect("run");
        assert_eq!(run.state, PageState::Committed);
        assert_eq!(
            run.protect,
            protect::PAGE_EXECUTE_READWRITE
        );
        assert!(mem.generation() >= 1);
    }

    #[test]
    fn virtual_alloc_reserve_commit_islands() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Mmap);
        let base = mem
            .virtual_alloc(
                0,
                0x10_0000,
                MEM_RESERVE,
                protect::PAGE_READWRITE,
            )
            .expect("reserve 1MiB");
        assert!(base.is_multiple_of(GUEST_ALLOC_GRANULARITY));
        // Reserved: no guest access.
        assert!(mem.read(base, &mut [0_u8; 1]).is_err());
        // Commit two 4K islands.
        let c0 = mem
            .virtual_alloc(base, 0x1000, MEM_COMMIT, protect::PAGE_READWRITE)
            .expect("commit0");
        assert_eq!(c0, base);
        let island = base + 0x8000;
        mem.virtual_alloc(island, 0x1000, MEM_COMMIT, protect::PAGE_READWRITE)
            .expect("commit1");
        mem.write(base, &[0x11, 0x22]).expect("write c0");
        mem.write(island, &[0x33]).expect("write island");
        // Gap still reserved.
        assert!(mem.read(base + 0x1000, &mut [0_u8; 1]).is_err());
        // Host base stable across commits (same arena).
        let hb0 = mem.backend.arena_host_base_for_va(base);
        let hb1 = mem.backend.arena_host_base_for_va(island);
        assert_eq!(hb0, hb1);
        assert!(hb0.is_some());
    }

    #[test]
    fn virtual_alloc_commit_without_reserve_fails() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        let err = mem
            .virtual_alloc(
                0x0000_0002_0000_0000,
                0x1000,
                MEM_COMMIT,
                protect::PAGE_READWRITE,
            )
            .expect_err("no reserve");
        assert_eq!(
            win32_from_cpu_error(&err),
            Some(ERROR_INVALID_ADDRESS)
        );
    }

    #[test]
    fn virtual_alloc_recommit_ok() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hash);
        let base = mem
            .virtual_alloc(
                0,
                0x1_0000,
                MEM_RESERVE | MEM_COMMIT,
                protect::PAGE_READWRITE,
            )
            .expect("r|c");
        mem.write(base, &[1, 2, 3, 4]).expect("w");
        mem.virtual_alloc(base, 0x1000, MEM_COMMIT, protect::PAGE_READWRITE)
            .expect("recommit");
        let mut b = [0_u8; 4];
        mem.read(base, &mut b).expect("r");
        assert_eq!(b, [1, 2, 3, 4]);
    }

    #[test]
    fn virtual_free_release_rules() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Hybrid);
        let base = mem
            .virtual_alloc(
                0,
                0x1_0000,
                MEM_RESERVE | MEM_COMMIT,
                protect::PAGE_READWRITE,
            )
            .expect("alloc");
        assert!(mem
            .virtual_free(base, 0x1000, MEM_RELEASE)
            .is_err());
        assert!(mem
            .virtual_free(base + 0x1000, 0, MEM_RELEASE)
            .is_err());
        mem.virtual_free(base, 0, MEM_RELEASE).expect("release");
        assert!(mem.read(base, &mut [0_u8; 1]).is_err());
    }

    #[test]
    fn virtual_free_decommit_middle() {
        let mut mem = GuestMemory::with_kind(MemBackendKind::Mmap);
        let base = mem
            .virtual_alloc(
                0,
                0x1_0000,
                MEM_RESERVE | MEM_COMMIT,
                protect::PAGE_READWRITE,
            )
            .expect("alloc");
        mem.write(base + 0x2000, &[0xAB]).expect("seed");
        mem.virtual_free(base + 0x2000, 0x1000, MEM_DECOMMIT)
            .expect("decommit");
        assert!(mem.read(base + 0x2000, &mut [0_u8; 1]).is_err());
        // Neighbours intact.
        mem.write(base, &[1]).expect("base");
        mem.write(base + 0x3000, &[2]).expect("after");
        // Arena still present.
        assert!(mem.backend.arena_host_base_for_va(base).is_some());
    }
}
