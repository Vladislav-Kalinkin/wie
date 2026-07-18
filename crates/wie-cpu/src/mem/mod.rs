//! Guest virtual memory for interpreter + JIT (x86-64 only).
//!
//! Phase 1 layout:
//! - [`GuestMemBackend`] — storage trait
//! - [`HashMapBackend`] — default `HashMap` + radix page table
//! - [`RegionTable`] — named layout ranges
//! - [`GuestMemory`] — facade used by iced/JIT (identical API to pre-split)

mod backend;
mod hashmap;
mod region;

#[cfg(test)]
mod mmap_page;
#[cfg(test)]
mod oracle;

pub use backend::{GuestMemBackend, PAGE_SIZE, PAGE_SIZE_USIZE};
pub use hashmap::HashMapBackend;
pub use region::{GuestRegion, RegionKind, RegionTable};

#[cfg(test)]
use backend::page_key;

/// Guest memory: default backend + region registry.
///
/// Call sites keep using this type; storage is pluggable via [`GuestMemBackend`].
pub(crate) struct GuestMemory {
    backend: HashMapBackend,
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
            .field("backend", &self.backend)
            .field("regions", &self.regions.len())
            .finish_non_exhaustive()
    }
}

impl GuestMemory {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            backend: HashMapBackend::new(),
            regions: RegionTable::new(),
        }
    }

    /// Active storage backend name (`hash` today).
    #[must_use]
    pub(crate) fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    /// Register a named layout range.
    pub(crate) fn register_region(&mut self, region: GuestRegion) {
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
        self.backend.map(address, size, perms)
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

    /// Fast page-table walk (no HashMap).
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
        let mut mem = GuestMemory::new();
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
        let mut mem = GuestMemory::new();
        let base = 0x0000_7fff_0000_0000_u64;
        mem.map(base, 0x1000, 7).expect("map high");
        let k = page_key(base);
        assert!(mem.page_data_ptr_walk(k).is_some());
    }

    #[test]
    fn region_registry_find() {
        let mut mem = GuestMemory::new();
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
}
