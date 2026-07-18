//! Contiguous anonymous `mmap` arenas for guest VA ranges (Phase 2).
//!
//! Soft translation only: host VA is OS-chosen (`mmap` with null hint). Guest VA
//! never equals host VA by design.
//!
//! **Ownership:** each [`MmapArena`] owns its `mmap` / `munmap`. Pointers returned
//! by [`ArenaSet::page_data_ptr`] / [`ArenaSet::host_ptr_for_va`] are non-owning
//! and stay valid only while the arena set (and the covering arena) is alive.
//! JIT TLB and any future radix leaves must not free these pointers.

#![allow(
    unsafe_code // libc mmap/munmap + forming page slices from raw mapping
)]

use super::backend::{PAGE_SIZE, PAGE_SIZE_USIZE};
use crate::CpuError;

/// One contiguous anonymous mapping covering a guest VA range.
pub(super) struct MmapArena {
    /// Inclusive guest base (page-aligned).
    guest_base: u64,
    /// Byte length (page-aligned, non-zero for live arenas).
    size: usize,
    /// Host mapping base from `mmap` (null after drop).
    host: *mut u8,
    /// Software permission bits (Phase 3 may apply `mprotect`).
    perms: u32,
}

// SAFETY: arenas are only accessed through exclusive/shared borrows on the
// owning backend; not shared across threads.
unsafe impl Send for MmapArena {}

impl Drop for MmapArena {
    fn drop(&mut self) {
        if !self.host.is_null() && self.size > 0 {
            // SAFETY: `host` came from mmap of exactly `size` bytes.
            unsafe {
                let _ = libc::munmap(self.host.cast(), self.size);
            }
            self.host = std::ptr::null_mut();
            self.size = 0;
        }
    }
}

impl std::fmt::Debug for MmapArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapArena")
            .field("guest_base", &format_args!("{:#x}", self.guest_base))
            .field("size", &format_args!("{:#x}", self.size))
            .field("host", &self.host)
            .field("perms", &self.perms)
            .finish()
    }
}

impl MmapArena {
    /// Map a new anonymous private region for `[guest_base, guest_base+size)`.
    pub(super) fn map_new(guest_base: u64, size: usize, perms: u32) -> Result<Self, CpuError> {
        if size == 0 {
            return Err(CpuError::Message("mmap arena size 0".into()));
        }
        // SAFETY: anonymous private mapping of `size` is well-defined.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(CpuError::Message(format!(
                "mmap arena failed for guest {guest_base:#x}+{size:#x}"
            )));
        }
        Ok(Self {
            guest_base,
            size,
            host: ptr.cast(),
            perms,
        })
    }

    #[inline]
    pub(super) fn guest_base(&self) -> u64 {
        self.guest_base
    }

    #[inline]
    pub(super) fn size(&self) -> usize {
        self.size
    }

    #[inline]
    pub(super) fn host(&self) -> *mut u8 {
        self.host
    }

    #[inline]
    pub(super) fn set_perms(&mut self, perms: u32) {
        self.perms = perms;
    }

    /// Exclusive end guest VA (`base + size`), saturating.
    #[inline]
    pub(super) fn guest_end(&self) -> u64 {
        let size_u64 = u64::try_from(self.size).unwrap_or(u64::MAX);
        self.guest_base.saturating_add(size_u64)
    }

    #[inline]
    pub(super) fn contains_va(&self, va: u64) -> bool {
        va >= self.guest_base && va < self.guest_end()
    }

    /// Whether this arena is exactly `[address, address+size)`.
    pub(super) fn is_exact_range(&self, address: u64, size: usize) -> bool {
        self.guest_base == address && self.size == size
    }

    /// Host base of the 4 KiB page containing `page_key` if covered.
    pub(super) fn page_data_ptr(&self, pkey: u64) -> Option<*mut u8> {
        let va = pkey.saturating_mul(PAGE_SIZE);
        // Page must start inside the arena (whole page is inside if start is
        // and arena is page-aligned, which map always guarantees).
        if self.host.is_null() || !self.contains_va(va) {
            return None;
        }
        let off = va.saturating_sub(self.guest_base);
        let off_usize = usize::try_from(off).ok()?;
        if off_usize >= self.size {
            return None;
        }
        // SAFETY: offset is within the live mmap of `size` bytes.
        Some(unsafe { self.host.add(off_usize) })
    }

    /// Shared slice of the whole arena.
    ///
    /// # Safety
    /// Caller holds a shared borrow of the arena for the slice lifetime.
    pub(super) unsafe fn as_slice(&self) -> &[u8] {
        // SAFETY: live mmap of `size`; shared borrow of arena.
        unsafe { std::slice::from_raw_parts(self.host, self.size) }
    }

    /// Mutable slice of the whole arena.
    ///
    /// # Safety
    /// Caller holds an exclusive borrow of the arena for the slice lifetime.
    pub(super) unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: live mmap of `size`; exclusive borrow of arena.
        unsafe { std::slice::from_raw_parts_mut(self.host, self.size) }
    }
}

/// Sorted set of non-overlapping arenas (by guest base).
#[derive(Default)]
pub(super) struct ArenaSet {
    /// Sorted ascending by `guest_base`.
    arenas: Vec<MmapArena>,
}

impl std::fmt::Debug for ArenaSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArenaSet")
            .field("arenas", &self.arenas.len())
            .finish_non_exhaustive()
    }
}

impl ArenaSet {
    #[must_use]
    pub(super) fn new() -> Self {
        Self {
            arenas: Vec::new(),
        }
    }

    /// Binary-search index of the arena that may contain `va` (largest base ≤ va).
    #[allow(clippy::integer_division)] // binary-search midpoint
    fn candidate_index(&self, va: u64) -> Option<usize> {
        if self.arenas.is_empty() {
            return None;
        }
        let mut lo = 0_usize;
        let mut hi = self.arenas.len();
        while lo < hi {
            let mid = lo.saturating_add(hi.saturating_sub(lo) / 2);
            let Some(a) = self.arenas.get(mid) else {
                break;
            };
            if a.guest_base() <= va {
                lo = mid.saturating_add(1);
            } else {
                hi = mid;
            }
        }
        lo.checked_sub(1)
    }

    /// Arena containing `va`.
    pub(super) fn find_va(&self, va: u64) -> Option<&MmapArena> {
        let i = self.candidate_index(va)?;
        let a = self.arenas.get(i)?;
        if a.contains_va(va) { Some(a) } else { None }
    }

    pub(super) fn find_va_mut(&mut self, va: u64) -> Option<&mut MmapArena> {
        let i = self.candidate_index(va)?;
        let a = self.arenas.get_mut(i)?;
        if a.contains_va(va) { Some(a) } else { None }
    }

    /// Whether any arena overlaps `[address, end)`.
    pub(super) fn any_overlap(&self, address: u64, end: u64) -> bool {
        for a in &self.arenas {
            if a.guest_base() < end && a.guest_end() > address {
                return true;
            }
        }
        false
    }

    /// Exact-range arena for rematch, if present.
    pub(super) fn find_exact(&mut self, address: u64, size: usize) -> Option<&mut MmapArena> {
        self.arenas
            .iter_mut()
            .find(|a| a.is_exact_range(address, size))
    }

    /// Insert a newly mapped arena (no overlap). Keeps sort order.
    pub(super) fn insert(&mut self, arena: MmapArena) -> Result<(), CpuError> {
        let base = arena.guest_base();
        let end = arena.guest_end();
        if self.any_overlap(base, end) {
            return Err(CpuError::Message(format!(
                "mmap arena overlap at {base:#x}+{:#x}",
                arena.size()
            )));
        }
        let pos = self
            .arenas
            .iter()
            .position(|a| a.guest_base() > base)
            .unwrap_or(self.arenas.len());
        self.arenas.insert(pos, arena);
        Ok(())
    }

    /// Host base of page `page_key` if mapped in some arena.
    pub(super) fn page_data_ptr(&self, pkey: u64) -> Option<*mut u8> {
        let va = pkey.saturating_mul(PAGE_SIZE);
        self.find_va(va)?.page_data_ptr(pkey)
    }

    /// Host base of the arena that contains `va` (arena start), if any.
    #[allow(clippy::as_conversions)] // pointer → address for GuestRegion.host_base
    pub(super) fn arena_host_base_for_va(&self, va: u64) -> Option<u64> {
        let a = self.find_va(va)?;
        if a.host().is_null() {
            return None;
        }
        // Host pointers fit in u64 on supported targets (64-bit).
        Some(a.host() as usize as u64)
    }

    /// Read `bytes.len()` from guest `address` into `bytes` (may span arenas page-wise).
    pub(super) fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0_usize;
        let mut va = address;
        while offset < bytes.len() {
            let page_off = usize::try_from(va & (PAGE_SIZE - 1)).map_err(|_| {
                CpuError::Message("page offset does not fit usize".into())
            })?;
            let arena = self.find_va(va).ok_or_else(|| {
                CpuError::Message(format!("mem_read unmapped {va:#x}"))
            })?;
            // SAFETY: exclusive to read path; shared borrow of arena set.
            let slice = unsafe { arena.as_slice() };
            let arena_off = usize::try_from(va.saturating_sub(arena.guest_base())).map_err(
                |_| CpuError::Message("arena offset does not fit usize".into()),
            )?;
            let room_in_page = PAGE_SIZE_USIZE.saturating_sub(page_off);
            let room_in_arena = arena.size().saturating_sub(arena_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room_in_page.min(room_in_arena).min(remaining);
            if chunk == 0 {
                return Err(CpuError::Message(format!("mem_read unmapped {va:#x}")));
            }
            let src = slice
                .get(arena_off..arena_off.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_read arena OOB".into()))?;
            let dst = bytes
                .get_mut(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_read slice OOB".into()))?;
            dst.copy_from_slice(src);
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
        }
        Ok(())
    }

    /// Write `bytes` at guest `address`.
    pub(super) fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0_usize;
        let mut va = address;
        while offset < bytes.len() {
            let page_off = usize::try_from(va & (PAGE_SIZE - 1)).map_err(|_| {
                CpuError::Message("page offset does not fit usize".into())
            })?;
            // Split borrow: locate index then mutably borrow.
            let i = self.candidate_index(va).ok_or_else(|| {
                CpuError::Message(format!("mem_write unmapped {va:#x}"))
            })?;
            let arena = self.arenas.get_mut(i).ok_or_else(|| {
                CpuError::Message(format!("mem_write unmapped {va:#x}"))
            })?;
            if !arena.contains_va(va) {
                return Err(CpuError::Message(format!("mem_write unmapped {va:#x}")));
            }
            let arena_off = usize::try_from(va.saturating_sub(arena.guest_base())).map_err(
                |_| CpuError::Message("arena offset does not fit usize".into()),
            )?;
            let room_in_page = PAGE_SIZE_USIZE.saturating_sub(page_off);
            let room_in_arena = arena.size().saturating_sub(arena_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room_in_page.min(room_in_arena).min(remaining);
            if chunk == 0 {
                return Err(CpuError::Message(format!("mem_write unmapped {va:#x}")));
            }
            let src = bytes
                .get(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_write slice OOB".into()))?;
            // SAFETY: exclusive borrow of this arena for the write.
            let slice = unsafe { arena.as_slice_mut() };
            let dst = slice
                .get_mut(arena_off..arena_off.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_write arena OOB".into()))?;
            dst.copy_from_slice(src);
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
        }
        Ok(())
    }

    /// Map `[address, end)` as arena(s), matching HashMap page semantics:
    /// - exact rematch → update perms only;
    /// - already-mapped pages → update covering arena perms, keep data;
    /// - unmapped runs → new contiguous arenas (coalesced).
    ///
    /// Conflicting remaps that would need to split an existing larger arena
    /// are not supported: if a page is mapped, it stays in its arena.
    pub(super) fn map_range(
        &mut self,
        address: u64,
        end: u64,
        size: usize,
        perms: u32,
    ) -> Result<(), CpuError> {
        if address == end {
            return Ok(());
        }
        if let Some(existing) = self.find_exact(address, size) {
            existing.set_perms(perms);
            return Ok(());
        }

        // First pass: update perms on arenas that already cover pages in range.
        let mut page_va = address;
        while page_va < end {
            if let Some(a) = self.find_va_mut(page_va) {
                a.set_perms(perms);
            }
            page_va = page_va.saturating_add(PAGE_SIZE);
        }

        // Second pass: map contiguous unmapped runs as new arenas.
        let mut run_start: Option<u64> = None;
        page_va = address;
        while page_va < end {
            let mapped = self.find_va(page_va).is_some();
            if mapped {
                if let Some(start) = run_start.take() {
                    let run_size = usize::try_from(page_va.saturating_sub(start)).map_err(
                        |_| CpuError::Message("mmap arena run size overflow".into()),
                    )?;
                    if run_size > 0 {
                        let arena = MmapArena::map_new(start, run_size, perms)?;
                        self.insert(arena)?;
                    }
                }
            } else if run_start.is_none() {
                run_start = Some(page_va);
            }
            page_va = page_va.saturating_add(PAGE_SIZE);
        }
        if let Some(start) = run_start {
            let run_size = usize::try_from(end.saturating_sub(start)).map_err(|_| {
                CpuError::Message("mmap arena run size overflow".into())
            })?;
            if run_size > 0 {
                let arena = MmapArena::map_new(start, run_size, perms)?;
                self.insert(arena)?;
            }
        }
        Ok(())
    }

    /// Drop the arena that exactly covers `[address, address+size)` (MEM_RELEASE).
    ///
    /// No-op if no exact match (partial ranges must not munmap sibling pages).
    pub(super) fn unmap_exact(&mut self, address: u64, size: usize) {
        if let Some(i) = self
            .arenas
            .iter()
            .position(|a| a.is_exact_range(address, size))
        {
            // Drop runs munmap via `MmapArena::Drop`.
            self.arenas.remove(i);
        }
    }

    /// Zero host bytes in `[address, address+size)` without munmap (MEM_DECOMMIT).
    pub(super) fn discard_range(
        &mut self,
        address: u64,
        size: usize,
    ) -> Result<(), CpuError> {
        if size == 0 {
            return Ok(());
        }
        let zeros = vec![0_u8; size.min(PAGE_SIZE_USIZE)];
        let mut offset = 0_usize;
        let mut va = address;
        while offset < size {
            let remaining = size.saturating_sub(offset);
            let page_off = usize::try_from(va & (PAGE_SIZE - 1)).map_err(|_| {
                CpuError::Message("page offset does not fit usize".into())
            })?;
            let chunk = remaining
                .min(PAGE_SIZE_USIZE.saturating_sub(page_off))
                .min(zeros.len());
            if chunk == 0 {
                break;
            }
            let src = zeros
                .get(..chunk)
                .ok_or_else(|| CpuError::Message("discard slice OOB".into()))?;
            // Best-effort: unmapped gaps are ignored (software already Reserved).
            drop(self.write(va, src));
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::as_conversions)]
mod tests {
    use super::*;
    use super::super::backend::check_map_args;

    #[test]
    fn map_write_read_roundtrip() {
        let mut set = ArenaSet::new();
        let (addr, end) = check_map_args(0x10_0000, 0x3000).expect("args");
        set.map_range(addr, end, 0x3000, 7).expect("map");
        set.write(0x10_0ff0, &[1, 2, 3, 4, 5, 6, 7, 8])
            .expect("cross-page write");
        let mut buf = [0_u8; 8];
        set.read(0x10_0ff0, &mut buf).expect("read");
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
        let p0 = set.page_data_ptr(0x10_0000 >> 12).expect("p0");
        let p1 = set.page_data_ptr(0x10_1000 >> 12).expect("p1");
        assert_eq!(p1 as usize - p0 as usize, PAGE_SIZE_USIZE);
    }

    #[test]
    fn exact_rematch_updates_perms() {
        let mut set = ArenaSet::new();
        let (addr, end) = check_map_args(0x20_0000, 0x1000).expect("args");
        set.map_range(addr, end, 0x1000, 7).expect("map");
        set.map_range(addr, end, 0x1000, 5).expect("remap");
        assert_eq!(set.find_va(0x20_0000).expect("a").perms, 5);
        assert_eq!(set.arenas.len(), 1);
    }

    #[test]
    fn partial_remap_extends_without_losing_data() {
        let mut set = ArenaSet::new();
        let (a, e) = check_map_args(0x30_0000, 0x1000).expect("args");
        set.map_range(a, e, 0x1000, 7).expect("map");
        set.write(0x30_0010, &[0x11, 0x22]).expect("write");
        // Overlapping map that also covers a new page: keep old, add new.
        let (a2, e2) = check_map_args(0x30_0000, 0x2000).expect("args2");
        set.map_range(a2, e2, 0x2000, 5).expect("extend");
        let mut buf = [0_u8; 2];
        set.read(0x30_0010, &mut buf).expect("read");
        assert_eq!(buf, [0x11, 0x22]);
        assert!(set.page_data_ptr(0x30_1000 >> 12).is_some());
        assert_eq!(set.find_va(0x30_0000).expect("a0").perms, 5);
    }

    #[test]
    fn high_va_arena() {
        let mut set = ArenaSet::new();
        let base = 0x0000_7fff_0000_0000_u64;
        let (addr, end) = check_map_args(base, 0x1000).expect("args");
        set.map_range(addr, end, 0x1000, 7).expect("map high");
        assert!(set.page_data_ptr(base >> 12).is_some());
    }
}
