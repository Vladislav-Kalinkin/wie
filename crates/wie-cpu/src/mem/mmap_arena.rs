//! Contiguous anonymous `mmap` storage backend (sole runtime path).
//!
//! Each guest `map` becomes one demand-zero arena. Soft translate via
//! [`super::arena::ArenaSet`]. Radix page tables are not used: page host
//! pointers are computed as `host + (va - guest_base)`.

use super::arena::ArenaSet;
use super::backend::{GuestMemBackend, check_map_args};
use crate::CpuError;

/// Guest memory where every mapped range is a single anonymous arena.
pub struct MmapArenaBackend {
    arenas: ArenaSet,
}

impl Default for MmapArenaBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MmapArenaBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapArenaBackend")
            .field("arenas", &self.arenas)
            .finish()
    }
}

impl MmapArenaBackend {
    /// Empty backend (no arenas).
    #[must_use]
    pub fn new() -> Self {
        Self {
            arenas: ArenaSet::new(),
        }
    }

    /// Host base of the arena containing `va`, if any.
    #[must_use]
    pub(super) fn arena_host_base_for_va(&self, va: u64) -> Option<u64> {
        self.arenas.arena_host_base_for_va(va)
    }

    /// Guest base of the arena containing `va`, if any.
    #[must_use]
    pub(super) fn arena_guest_base_for_va(&self, va: u64) -> Option<u64> {
        self.arenas.arena_guest_base_for_va(va)
    }

    /// MEM_RELEASE: munmap exact reservation arena.
    pub(super) fn unmap_range(&mut self, address: u64, size: usize) {
        self.arenas.unmap_exact(address, size);
    }

    /// MEM_DECOMMIT: zero host bytes, keep mapping.
    pub(super) fn discard_range(&mut self, address: u64, size: usize) -> Result<(), CpuError> {
        self.arenas.discard_range(address, size)
    }

    /// Optional dual-protection `mprotect` on arena-backed guest range.
    pub(super) fn mprotect_guest_range(
        &mut self,
        address: u64,
        size: usize,
        prot: i32,
    ) -> Result<(), ()> {
        self.arenas.mprotect_guest_range(address, size, prot)
    }
}

impl GuestMemBackend for MmapArenaBackend {
    fn map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        let (address, end) = check_map_args(address, size)?;
        self.arenas.map_range(address, end, size, perms)
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        self.arenas.write(address, bytes)
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        self.arenas.read(address, bytes)
    }

    fn page_data_ptr(&self, page_key: u64) -> Option<*mut u8> {
        self.arenas.page_data_ptr(page_key)
    }

    fn name(&self) -> &'static str {
        "mmap"
    }
}

impl MmapArenaBackend {
    /// Lock-free host pointer for data-plane write (no arena mutation).
    #[inline]
    pub(super) fn write_ptr(&self, address: u64) -> Option<*mut u8> {
        self.arenas.write_ptr(address)
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::as_conversions, unsafe_code)]
mod tests {
    use super::super::backend::PAGE_SIZE_USIZE;
    use super::*;

    #[test]
    fn page_ptrs_are_contiguous() {
        let mut b = MmapArenaBackend::new();
        b.map(0x40_0000, 0x2000, 7).expect("map");
        let p0 = b.page_data_ptr_walk(0x40_0000 >> 12).expect("p0");
        let p1 = b.page_data_ptr_walk(0x40_1000 >> 12).expect("p1");
        assert_eq!(p1 as usize - p0 as usize, PAGE_SIZE_USIZE);
        // Write via raw page base + offset must be visible through read.
        // SAFETY: p0 is a live mapped page base; offset 0x10 in-page.
        unsafe {
            std::ptr::write(p0.add(0x10), 0xAB);
        }
        let mut byte = [0_u8; 1];
        b.read(0x40_0010, &mut byte).expect("read");
        assert_eq!(byte[0], 0xAB);
    }
}
