//! Hybrid guest memory: large ranges as mmap arenas, tiny pages on HashMap (Phase 2.3).
//!
//! Threshold is page-aligned: maps with `size >= ARENA_THRESHOLD` go to arenas.
//! Stack (64 KiB) and heaps/file arenas qualify; TEB/env/stub pages stay sparse.

use super::arena::ArenaSet;
use super::backend::{GuestMemBackend, PAGE_SIZE, PAGE_SIZE_USIZE, check_map_args, page_key};
use super::hashmap::HashMapBackend;
use crate::CpuError;

/// Minimum map size (bytes) routed to an mmap arena under hybrid mode.
///
/// 64 KiB includes the default guest stack so Phase 4 stack-relative paths can
/// pin a single host base.
pub(super) const ARENA_THRESHOLD: usize = 0x1_0000;

/// Large arenas + sparse HashMap pages (exclusive ownership per guest page).
pub struct HybridBackend {
    arenas: ArenaSet,
    sparse: HashMapBackend,
}

impl Default for HybridBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HybridBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridBackend")
            .field("arenas", &self.arenas)
            .field("sparse", &self.sparse)
            .finish()
    }
}

impl HybridBackend {
    /// Empty hybrid backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            arenas: ArenaSet::new(),
            sparse: HashMapBackend::new(),
        }
    }

    #[must_use]
    pub(super) fn arena_host_base_for_va(&self, va: u64) -> Option<u64> {
        self.arenas.arena_host_base_for_va(va)
    }

    /// MEM_RELEASE: drop exact arena and/or sparse pages in range.
    pub(super) fn unmap_range(&mut self, address: u64, size: usize) {
        self.arenas.unmap_exact(address, size);
        self.sparse.unmap_range(address, size);
    }

    /// MEM_DECOMMIT: zero arena bytes; drop sparse pages.
    pub(super) fn discard_range(
        &mut self,
        address: u64,
        size: usize,
    ) -> Result<(), CpuError> {
        self.arenas.discard_range(address, size)?;
        self.sparse.discard_range(address, size);
        Ok(())
    }

    /// Map a fully unmapped run into arena or sparse storage.
    fn map_unmapped_run(
        &mut self,
        start: u64,
        run_end: u64,
        perms: u32,
        prefer_arena: bool,
    ) -> Result<(), CpuError> {
        let run_size = usize::try_from(run_end.saturating_sub(start)).map_err(|_| {
            CpuError::Message("hybrid map run size overflow".into())
        })?;
        if run_size == 0 {
            return Ok(());
        }
        if prefer_arena {
            // Prefer contiguous host span for large original maps (even small holes).
            self.arenas.map_range(start, run_end, run_size, perms)
        } else {
            self.sparse.map(start, run_size, perms)
        }
    }
}

impl GuestMemBackend for HybridBackend {
    fn map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        let (address, end) = check_map_args(address, size)?;
        if address == end {
            return Ok(());
        }

        // Already-mapped pages (either store): keep data, refresh software perms.
        // Only unmapped pages are allocated into the store chosen by threshold.
        let mut page_va = address;
        let mut run_start: Option<u64> = None;
        let prefer_arena = size >= ARENA_THRESHOLD;

        while page_va < end {
            let in_arena = self.arenas.find_va(page_va).is_some();
            let in_sparse = self.sparse.page_data_ptr_walk(page_key(page_va)).is_some();
            if in_arena {
                if let Some(a) = self.arenas.find_va_mut(page_va) {
                    a.set_perms(perms);
                }
                if let Some(start) = run_start.take() {
                    Self::map_unmapped_run(self, start, page_va, perms, prefer_arena)?;
                }
            } else if in_sparse {
                // Sparse already owns this page — rematch via HashMap path.
                self.sparse.map(page_va, PAGE_SIZE_USIZE, perms)?;
                if let Some(start) = run_start.take() {
                    Self::map_unmapped_run(self, start, page_va, perms, prefer_arena)?;
                }
            } else if run_start.is_none() {
                run_start = Some(page_va);
            }
            page_va = page_va.saturating_add(PAGE_SIZE);
        }
        if let Some(start) = run_start {
            Self::map_unmapped_run(self, start, end, perms, prefer_arena)?;
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        if bytes.is_empty() {
            return Ok(());
        }
        // Prefer arena if the first byte is arena-backed; otherwise sparse.
        // Multi-page writes that cross stores are rejected page-by-page below.
        let mut offset = 0_usize;
        let mut va = address;
        while offset < bytes.len() {
            let page_off = usize::try_from(va & (PAGE_SIZE - 1))
                .map_err(|_| CpuError::Message("page offset does not fit usize".into()))?;
            let room = super::backend::PAGE_SIZE_USIZE.saturating_sub(page_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room.min(remaining);
            let src = bytes
                .get(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_write slice OOB".into()))?;
            if self.arenas.find_va(va).is_some() {
                self.arenas.write(va, src)?;
            } else {
                self.sparse.write(va, src)?;
            }
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
        }
        Ok(())
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0_usize;
        let mut va = address;
        while offset < bytes.len() {
            let page_off = usize::try_from(va & (PAGE_SIZE - 1))
                .map_err(|_| CpuError::Message("page offset does not fit usize".into()))?;
            let room = super::backend::PAGE_SIZE_USIZE.saturating_sub(page_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room.min(remaining);
            let dst = bytes
                .get_mut(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_read slice OOB".into()))?;
            if self.arenas.find_va(va).is_some() {
                self.arenas.read(va, dst)?;
            } else {
                self.sparse.read(va, dst)?;
            }
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
        }
        Ok(())
    }

    fn page_data_ptr(&mut self, page_key: u64) -> Option<*mut u8> {
        if let Some(p) = self.arenas.page_data_ptr(page_key) {
            return Some(p);
        }
        self.sparse.page_data_ptr(page_key)
    }

    fn page_data_ptr_walk(&self, page_key: u64) -> Option<*mut u8> {
        if let Some(p) = self.arenas.page_data_ptr(page_key) {
            return Some(p);
        }
        self.sparse.page_data_ptr_walk(page_key)
    }

    fn name(&self) -> &'static str {
        "hybrid"
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn large_map_uses_arena_small_uses_sparse() {
        let mut b = HybridBackend::new();
        b.map(0x50_0000, ARENA_THRESHOLD, 7).expect("large");
        b.map(0x60_0000, 0x1000, 7).expect("small");
        assert!(b.arenas.find_va(0x50_0000).is_some());
        assert!(b.arenas.find_va(0x60_0000).is_none());
        assert!(b.sparse.page_data_ptr_walk(0x60_0000 >> 12).is_some());
    }

    #[test]
    fn write_read_both_stores() {
        let mut b = HybridBackend::new();
        b.map(0x70_0000, ARENA_THRESHOLD, 7).expect("arena");
        b.map(0x80_0000, 0x1000, 7).expect("sparse");
        b.write(0x70_0010, b"arena").expect("w1");
        b.write(0x80_0020, b"hash").expect("w2");
        let mut a = [0_u8; 5];
        let mut h = [0_u8; 4];
        b.read(0x70_0010, &mut a).expect("r1");
        b.read(0x80_0020, &mut h).expect("r2");
        assert_eq!(&a, b"arena");
        assert_eq!(&h, b"hash");
        assert!(b.page_data_ptr_walk(0x70_0000 >> 12).is_some());
        assert!(b.page_data_ptr_walk(0x80_0000 >> 12).is_some());
    }
}
