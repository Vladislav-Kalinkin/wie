//! Guest virtual memory for interpreter + JIT (x86-64 only).
//!
//! Phase 2 layout:
//! - [`GuestMemBackend`] — storage trait
//! - [`HashMapBackend`] — `WIE_MEM=hash` (eager pages + radix)
//! - [`MmapArenaBackend`] — `WIE_MEM=mmap` (contiguous anonymous arenas)
//! - [`HybridBackend`] — large arenas + sparse HashMap (`WIE_MEM=hybrid`, default)
//! - [`RegionTable`] — named layout ranges (`host_base` filled for mmap arenas)
//! - [`GuestMemory`] — facade used by iced/JIT

mod arena;
mod backend;
mod hashmap;
mod hybrid;
mod mmap_arena;
mod region;

#[cfg(test)]
mod mmap_page;
#[cfg(test)]
mod oracle;

pub use backend::{GuestMemBackend, PAGE_SIZE, PAGE_SIZE_USIZE};
pub use hashmap::HashMapBackend;
pub use hybrid::HybridBackend;
pub use mmap_arena::MmapArenaBackend;
pub use region::{GuestRegion, RegionKind, RegionTable};

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
}

/// Guest memory: pluggable backend + region registry.
///
/// Call sites keep using this type; storage is selected via `WIE_MEM`.
pub(crate) struct GuestMemory {
    backend: Storage,
    regions: RegionTable,
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
        }
    }

    /// Active storage backend name (`hash` / `mmap` / `hybrid`).
    #[must_use]
    pub(crate) fn backend_name(&self) -> &'static str {
        self.backend.name()
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

    /// Map `[address, address+size)` with `perms`.
    pub(crate) fn map(
        &mut self,
        address: u64,
        size: usize,
        perms: u32,
    ) -> Result<(), crate::CpuError> {
        self.backend.map(address, size, perms)?;
        // Backfill host_base for regions already registered that this map covers.
        if let Some(hb) = self.backend.arena_host_base_for_va(address) {
            self.regions.set_host_base_if_covers(address, hb);
        }
        Ok(())
    }

    /// Write `bytes` at guest `address`.
    pub(crate) fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), crate::CpuError> {
        self.backend.write(address, bytes)
    }

    /// Read into `bytes` from guest `address`.
    pub(crate) fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), crate::CpuError> {
        self.backend.read(address, bytes)
    }

    /// Host pointer to a mapped page's data (JIT TLB).
    #[must_use]
    pub(crate) fn page_data_ptr(&mut self, page_key: u64) -> Option<*mut u8> {
        self.backend.page_data_ptr(page_key)
    }

    /// Fast page-table walk (HashMap radix or arena formula).
    #[must_use]
    pub(crate) fn page_data_ptr_walk(&self, page_key: u64) -> Option<*mut u8> {
        self.backend.page_data_ptr_walk(page_key)
    }

    /// Instruction fetch into a small stack buffer.
    pub(crate) fn fetch_into(
        &self,
        address: u64,
        out: &mut [u8],
    ) -> Result<usize, crate::CpuError> {
        self.backend.fetch_into(address, out)
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

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
}
