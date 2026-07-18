//! `HashMap`-backed guest page storage + 4-level radix page table (default backend).
//!
//! Intermediate radix levels are owned `Box` trees (no raw ownership). Leaf slots
//! store host pointers into page `Box` data for the JIT TLB; interpreter read/write
//! always goes through the `HashMap` (fully safe).

use super::backend::{GuestMemBackend, PAGE_SIZE, PAGE_SIZE_USIZE, check_map_args, page_key};
use crate::CpuError;
use std::collections::HashMap;

/// Bits per radix level (512-way).
pub(crate) const PT_BITS: u32 = 9;
/// Entries per level table.
pub(crate) const PT_SIZE: usize = 1 << PT_BITS; // 512
/// Mask for one level index.
pub(crate) const PT_MASK: u64 = (1_u64 << PT_BITS) - 1;

/// Level-3 leaf: host pointers to 4 KiB page data (`null` = unmapped).
///
/// Pointers alias `Page::data` owned by [`HashMapBackend::pages`]. They are only
/// returned to the JIT (`page_data_ptr*`); interpreter paths use the HashMap.
struct PtL3 {
    entries: [*mut u8; PT_SIZE],
}

/// Level-2: owned L3 leaves.
struct PtL2 {
    entries: [Option<Box<PtL3>>; PT_SIZE],
}

/// Level-1: owned L2 tables.
struct PtL1 {
    entries: [Option<Box<PtL2>>; PT_SIZE],
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
            entries: std::array::from_fn(|_| None),
        }
    }
}
impl PtL1 {
    fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
        }
    }
}

/// Sparse page map + JIT-friendly radix page table (`WIE_MEM=hash` default).
pub struct HashMapBackend {
    pages: HashMap<u64, Page>,
    /// L0 directory: 512 optional L1 tables.
    l0: Box<[Option<Box<PtL1>>; PT_SIZE]>,
}

struct Page {
    data: Box<[u8; PAGE_SIZE_USIZE]>,
    perms: u32,
}

impl Default for HashMapBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HashMapBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashMapBackend")
            .field("pages", &self.pages.len())
            .finish_non_exhaustive()
    }
}

impl HashMapBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pages: HashMap::new(),
            l0: Box::new(std::array::from_fn(|_| None)),
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

    /// Install `data_ptr` for `page_key` into the radix tree (safe `Box` ownership).
    fn install_pt(&mut self, page_key: u64, data_ptr: *mut u8) {
        let [i0, i1, i2, i3] = Self::indices(page_key);

        let Some(l0_slot) = self.l0.get_mut(i0) else {
            return;
        };
        let l1 = l0_slot.get_or_insert_with(|| Box::new(PtL1::new()));
        let Some(l1_slot) = l1.entries.get_mut(i1) else {
            return;
        };
        let l2 = l1_slot.get_or_insert_with(|| Box::new(PtL2::new()));
        let Some(l2_slot) = l2.entries.get_mut(i2) else {
            return;
        };
        let l3 = l2_slot.get_or_insert_with(|| Box::new(PtL3::new()));
        if let Some(leaf) = l3.entries.get_mut(i3) {
            *leaf = data_ptr;
        }
    }

    fn page_data_ref(&self, page_key: u64) -> Option<&[u8; PAGE_SIZE_USIZE]> {
        self.pages.get(&page_key).map(|p| p.data.as_ref())
    }

    fn page_data_mut(&mut self, page_key: u64) -> Option<&mut [u8; PAGE_SIZE_USIZE]> {
        self.pages.get_mut(&page_key).map(|p| p.data.as_mut())
    }
}

impl GuestMemBackend for HashMapBackend {
    fn map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        let (address, end) = check_map_args(address, size)?;
        if address == end {
            return Ok(());
        }
        let mut page_va = address;
        while page_va < end {
            let key = page_key(page_va);
            self.pages.entry(key).or_insert_with(|| Page {
                data: Box::new([0_u8; PAGE_SIZE_USIZE]),
                perms,
            });
            let ptr = {
                let page = self
                    .pages
                    .get_mut(&key)
                    .ok_or_else(|| CpuError::Message("mem_map internal missing page".into()))?;
                page.perms = perms;
                page.data.as_mut_ptr()
            };
            self.install_pt(key, ptr);
            page_va = page_va.saturating_add(PAGE_SIZE);
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0_usize;
        let mut va = address;
        while offset < bytes.len() {
            let pkey = page_key(va);
            let page_off = usize::try_from(va & (PAGE_SIZE - 1))
                .map_err(|_| CpuError::Message("page offset does not fit usize".into()))?;
            let page = self
                .page_data_mut(pkey)
                .ok_or_else(|| CpuError::Message(format!("mem_write unmapped {va:#x}")))?;
            let room = PAGE_SIZE_USIZE.saturating_sub(page_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room.min(remaining);
            let src = bytes
                .get(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_write slice OOB".into()))?;
            let dst = page
                .get_mut(page_off..page_off.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_write page OOB".into()))?;
            dst.copy_from_slice(src);
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
            let pkey = page_key(va);
            let page_off = usize::try_from(va & (PAGE_SIZE - 1))
                .map_err(|_| CpuError::Message("page offset does not fit usize".into()))?;
            let page = self
                .page_data_ref(pkey)
                .ok_or_else(|| CpuError::Message(format!("mem_read unmapped {va:#x}")))?;
            let room = PAGE_SIZE_USIZE.saturating_sub(page_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room.min(remaining);
            let dst = bytes
                .get_mut(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_read slice OOB".into()))?;
            let src = page
                .get(page_off..page_off.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_read page OOB".into()))?;
            dst.copy_from_slice(src);
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
        }
        Ok(())
    }

    fn page_data_ptr(&mut self, page_key: u64) -> Option<*mut u8> {
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

    fn page_data_ptr_walk(&self, page_key: u64) -> Option<*mut u8> {
        let [i0, i1, i2, i3] = Self::indices(page_key);
        let l1 = self.l0.get(i0)?.as_ref()?;
        let l2 = l1.entries.get(i1)?.as_ref()?;
        let l3 = l2.entries.get(i2)?.as_ref()?;
        let p = *l3.entries.get(i3)?;
        if p.is_null() { None } else { Some(p) }
    }

    fn name(&self) -> &'static str {
        "hash"
    }
}
