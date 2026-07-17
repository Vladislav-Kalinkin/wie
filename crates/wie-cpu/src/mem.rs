//! Guest virtual memory for the iced interpreter (x86-64 only).
//!
//! Storage: `HashMap` owns page boxes (perms + data). A **4-level radix page
//! table** (9 bits × 4 of `page_key` = 36 bits → full 48-bit VA) mirrors host
//! data pointers so JIT can walk pages with plain loads.

#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing, // fixed-size PT_SIZE arrays, masked indices
    unsafe_code // page-table raw pointers for Drop + install
)]

use crate::CpuError;
use std::collections::HashMap;

/// Page size used by the interpreter (4 KiB).
pub(crate) const PAGE_SIZE: u64 = 0x1000;
/// `log2(PAGE_SIZE)` — prefer shifts over division for page keys.
pub(crate) const PAGE_SHIFT: u32 = 12;

#[inline]
fn page_key(va: u64) -> u64 {
    va >> PAGE_SHIFT
}

/// Bits per radix level (512-way).
pub(crate) const PT_BITS: u32 = 9;
/// Entries per level table.
pub(crate) const PT_SIZE: usize = 1 << PT_BITS; // 512
/// Mask for one level index.
pub(crate) const PT_MASK: u64 = (PT_SIZE as u64) - 1;
/// Level-3 leaf: host pointers to 4 KiB page data (`null` = unmapped).
#[repr(C)]
struct PtL3 {
    entries: [*mut u8; PT_SIZE],
}

/// Level-2: pointers to L3 leaves.
#[repr(C)]
struct PtL2 {
    entries: [*mut PtL3; PT_SIZE],
}

/// Level-1: pointers to L2 tables.
#[repr(C)]
struct PtL1 {
    entries: [*mut PtL2; PT_SIZE],
}

impl PtL3 {
    fn new() -> Self {
        Self {
            entries: [std::ptr::null_mut(); PT_SIZE],
        }
    }
}
impl PtL2 {
    fn new() -> Self {
        Self {
            entries: [std::ptr::null_mut(); PT_SIZE],
        }
    }
}
impl PtL1 {
    fn new() -> Self {
        Self {
            entries: [std::ptr::null_mut(); PT_SIZE],
        }
    }
}

/// Guest memory: sparse page map + JIT-friendly radix page table.
pub(crate) struct GuestMemory {
    pages: HashMap<u64, Page>,
    /// L0 directory: 512 pointers to L1 (null until first use).
    l0: Box<[*mut PtL1; PT_SIZE]>,
}

#[derive(Debug, Clone)]
struct Page {
    data: Box<[u8; PAGE_SIZE as usize]>,
    perms: u32,
}

impl Default for GuestMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        for i0 in 0..PT_SIZE {
            let l1p = self.l0[i0];
            if l1p.is_null() {
                continue;
            }
            // SAFETY: L1 from Box::into_raw in install_pt.
            let l1 = unsafe { Box::from_raw(l1p) };
            for i1 in 0..PT_SIZE {
                let l2p = l1.entries[i1];
                if l2p.is_null() {
                    continue;
                }
                // SAFETY: L2 from Box::into_raw.
                let l2 = unsafe { Box::from_raw(l2p) };
                for i2 in 0..PT_SIZE {
                    let l3p = l2.entries[i2];
                    if !l3p.is_null() {
                        // SAFETY: L3 from Box::into_raw.
                        unsafe {
                            drop(Box::from_raw(l3p));
                        }
                    }
                }
            }
        }
    }
}

impl std::fmt::Debug for GuestMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestMemory")
            .field("pages", &self.pages.len())
            .finish_non_exhaustive()
    }
}

impl GuestMemory {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            pages: HashMap::new(),
            l0: Box::new([std::ptr::null_mut(); PT_SIZE]),
        }
    }

    /// Indices for `page_key` at each radix level (L0..L3).
    #[inline]
    fn indices(page_key: u64) -> [usize; 4] {
        [
            usize::try_from((page_key >> (3 * PT_BITS)) & PT_MASK).unwrap_or(0),
            usize::try_from((page_key >> (2 * PT_BITS)) & PT_MASK).unwrap_or(0),
            usize::try_from((page_key >> PT_BITS) & PT_MASK).unwrap_or(0),
            usize::try_from(page_key & PT_MASK).unwrap_or(0),
        ]
    }

    /// Install `data_ptr` for `page_key` into the radix tree.
    fn install_pt(&mut self, page_key: u64, data_ptr: *mut u8) {
        let [i0, i1, i2, i3] = Self::indices(page_key);

        if self.l0[i0].is_null() {
            self.l0[i0] = Box::into_raw(Box::new(PtL1::new()));
        }
        // SAFETY: L1 installed by us.
        let l1 = unsafe { &mut *self.l0[i0] };
        if l1.entries[i1].is_null() {
            l1.entries[i1] = Box::into_raw(Box::new(PtL2::new()));
        }
        // SAFETY: L2 installed by us.
        let l2 = unsafe { &mut *l1.entries[i1] };
        if l2.entries[i2].is_null() {
            l2.entries[i2] = Box::into_raw(Box::new(PtL3::new()));
        }
        // SAFETY: L3 installed by us.
        let l3 = unsafe { &mut *l2.entries[i2] };
        l3.entries[i3] = data_ptr;
    }

    /// Map `[address, address+size)` with `perms` (Unicorn-compatible `PROT_*`).
    pub(crate) fn map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        if size == 0 {
            return Ok(());
        }
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(CpuError::Message(format!(
                "mem_map address {address:#x} not page-aligned"
            )));
        }
        let size_u64 = u64::try_from(size).map_err(|_| {
            CpuError::Message(format!("mem_map size {size} does not fit u64"))
        })?;
        if !size_u64.is_multiple_of(PAGE_SIZE) {
            return Err(CpuError::Message(format!(
                "mem_map size {size:#x} not page-aligned"
            )));
        }
        let end = address.checked_add(size_u64).ok_or_else(|| {
            CpuError::Message(format!("mem_map overflow at {address:#x}+{size:#x}"))
        })?;
        let mut page_va = address;
        while page_va < end {
            let key = page_key(page_va);
            self.pages.entry(key).or_insert_with(|| Page {
                data: Box::new([0_u8; PAGE_SIZE as usize]),
                perms,
            });
            let ptr = {
                let page = self.pages.get_mut(&key).ok_or_else(|| {
                    CpuError::Message("mem_map internal missing page".into())
                })?;
                page.perms = perms;
                page.data.as_mut_ptr()
            };
            self.install_pt(key, ptr);
            page_va = page_va.saturating_add(PAGE_SIZE);
        }
        Ok(())
    }

    /// Write `bytes` at guest `address`.
    pub(crate) fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0_usize;
        let mut va = address;
        while offset < bytes.len() {
            let pkey = page_key(va);
            let page_off = usize::try_from(va & (PAGE_SIZE - 1)).map_err(|_| {
                CpuError::Message("page offset does not fit usize".into())
            })?;
            let page = self.page_data_mut(pkey).ok_or_else(|| {
                CpuError::Message(format!("mem_write unmapped {va:#x}"))
            })?;
            let room = (PAGE_SIZE as usize).saturating_sub(page_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room.min(remaining);
            let src = bytes
                .get(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_write slice OOB".into()))?;
            page[page_off..page_off.saturating_add(chunk)].copy_from_slice(src);
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
            // PT already points at page data (Box heap ptr is stable across HashMap moves).
        }
        Ok(())
    }

    /// Read into `bytes` from guest `address`.
    pub(crate) fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0_usize;
        let mut va = address;
        while offset < bytes.len() {
            let pkey = page_key(va);
            let page_off = usize::try_from(va & (PAGE_SIZE - 1)).map_err(|_| {
                CpuError::Message("page offset does not fit usize".into())
            })?;
            let page = self.page_data_ref(pkey).ok_or_else(|| {
                CpuError::Message(format!("mem_read unmapped {va:#x}"))
            })?;
            let room = (PAGE_SIZE as usize).saturating_sub(page_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room.min(remaining);
            let dst = bytes
                .get_mut(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_read slice OOB".into()))?;
            dst.copy_from_slice(&page[page_off..page_off.saturating_add(chunk)]);
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
        }
        Ok(())
    }

    /// Host pointer to a mapped page's data (JIT TLB). `page_key = va / PAGE_SIZE`.
    #[must_use]
    pub(crate) fn page_data_ptr(&mut self, page_key: u64) -> Option<*mut u8> {
        // Prefer dense walk (O(1) levels); install only if missing.
        if let Some(p) = self.page_data_ptr_walk(page_key) {
            return Some(p);
        }
        let ptr = {
            let page = self.pages.get_mut(&page_key)?;
            page.data.as_mut_ptr()
        };
        self.install_pt(page_key, ptr);
        Some(ptr)
    }

    /// Shared reference to a mapped page's data via radix-page-table walk
    /// (4 pointer loads, no HashMap).  Safe wrapper around [`page_data_ptr_walk`].
    fn page_data_ref(&self, page_key: u64) -> Option<&[u8; PAGE_SIZE as usize]> {
        let ptr = self.page_data_ptr_walk(page_key)?;
        // SAFETY: `ptr` was installed by `install_pt` from a `Box<[u8; PAGE_SIZE]>`.
        // It remains valid for the lifetime of `self` because `GuestMemory` owns
        // the backing `pages` HashMap and never deallocates individual pages.
        // There is no mutable aliasing through `&self`.
        Some(unsafe { &*ptr.cast::<[u8; PAGE_SIZE as usize]>() })
    }

    /// Mutable reference to a mapped page's data via radix-page-table walk
    /// (4 pointer loads, no HashMap).  Safe wrapper around [`page_data_ptr_walk`].
    fn page_data_mut(&mut self, page_key: u64) -> Option<&mut [u8; PAGE_SIZE as usize]> {
        let ptr = self.page_data_ptr_walk(page_key)?;
        // SAFETY: same as `page_data_ref`, and `&mut self` guarantees unique access.
        Some(unsafe { &mut *ptr.cast::<[u8; PAGE_SIZE as usize]>() })
    }

    /// Fast page-table walk (no HashMap). Used by JIT host helper and tests.
    #[must_use]
    pub(crate) fn page_data_ptr_walk(&self, page_key: u64) -> Option<*mut u8> {
        let [i0, i1, i2, i3] = Self::indices(page_key);
        let l1p = self.l0[i0];
        if l1p.is_null() {
            return None;
        }
        // SAFETY: non-null L1 installed by us.
        let l1 = unsafe { &*l1p };
        let l2p = l1.entries[i1];
        if l2p.is_null() {
            return None;
        }
        // SAFETY: non-null L2.
        let l2 = unsafe { &*l2p };
        let l3p = l2.entries[i2];
        if l3p.is_null() {
            return None;
        }
        // SAFETY: non-null L3.
        let l3 = unsafe { &*l3p };
        let p = l3.entries[i3];
        if p.is_null() {
            None
        } else {
            Some(p)
        }
    }

    /// Read up to `max_len` bytes for instruction fetch; fails if first page unmapped.
    pub(crate) fn fetch(&self, address: u64, max_len: usize) -> Result<Vec<u8>, CpuError> {
        let mut buf = vec![0_u8; max_len.min(15)];
        if buf.is_empty() {
            return Ok(buf);
        }
        if self.read(address, &mut buf).is_ok() {
            return Ok(buf);
        }
        let mut len = buf.len();
        while len > 0 {
            let mut try_buf = vec![0_u8; len];
            if self.read(address, &mut try_buf).is_ok() {
                return Ok(try_buf);
            }
            len = len.saturating_sub(1);
        }
        Err(CpuError::Message(format!(
            "instruction fetch unmapped {address:#x}"
        )))
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
        // Typical user stack-ish high canonical address.
        let mut mem = GuestMemory::new();
        let base = 0x0000_7fff_0000_0000_u64;
        mem.map(base, 0x1000, 7).expect("map high");
        let k = page_key(base);
        assert!(mem.page_data_ptr_walk(k).is_some());
    }
}
