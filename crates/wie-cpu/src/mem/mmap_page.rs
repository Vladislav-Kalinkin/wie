//! Per-page anonymous `mmap` backend for oracle tests (Phase 1.3).
//!
//! Not the Phase 2 arena backend: each guest page is a separate `mmap` mapping.
//! Used to prove `GuestMemBackend` semantic parity with [`super::HashMapBackend`].

#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    unsafe_code
)]

use super::backend::{GuestMemBackend, PAGE_SIZE, check_map_args, page_key};
use crate::CpuError;
use std::collections::HashMap;

/// One mapped guest page owned via `mmap` / `munmap`.
struct MmapPage {
    ptr: *mut u8,
    perms: u32,
}

// SAFETY: we only touch page data through exclusive `&mut self` / shared `&self`
// on the owning backend; pages are never shared across threads.
unsafe impl Send for MmapPage {}

impl Drop for MmapPage {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: pointer from mmap of PAGE_SIZE; munmap matches.
            unsafe {
                let _ = libc::munmap(self.ptr.cast(), PAGE_SIZE as usize);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

/// Sparse guest memory where each page is an independent anonymous mapping.
pub(super) struct MmapPageBackend {
    pages: HashMap<u64, MmapPage>,
}

impl Default for MmapPageBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MmapPageBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapPageBackend")
            .field("pages", &self.pages.len())
            .finish_non_exhaustive()
    }
}

impl MmapPageBackend {
    #[must_use]
    pub(super) fn new() -> Self {
        Self {
            pages: HashMap::new(),
        }
    }

    fn map_one_page(perms: u32) -> Result<MmapPage, CpuError> {
        // SAFETY: anonymous private mapping of PAGE_SIZE is well-defined.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(CpuError::Message("mmap page failed".into()));
        }
        Ok(MmapPage {
            ptr: ptr.cast(),
            perms,
        })
    }
}

impl GuestMemBackend for MmapPageBackend {
    fn map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        let (address, end) = check_map_args(address, size)?;
        if address == end {
            return Ok(());
        }
        let mut page_va = address;
        while page_va < end {
            let key = page_key(page_va);
            match self.pages.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    e.get_mut().perms = perms;
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(Self::map_one_page(perms)?);
                }
            }
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
                .pages
                .get_mut(&pkey)
                .ok_or_else(|| CpuError::Message(format!("mem_write unmapped {va:#x}")))?;
            let room = (PAGE_SIZE as usize).saturating_sub(page_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room.min(remaining);
            let src = bytes
                .get(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_write slice OOB".into()))?;
            // SAFETY: page mapped RW for PAGE_SIZE; chunk stays in-page.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    src.as_ptr(),
                    page.ptr.add(page_off),
                    chunk,
                );
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
            let pkey = page_key(va);
            let page_off = usize::try_from(va & (PAGE_SIZE - 1))
                .map_err(|_| CpuError::Message("page offset does not fit usize".into()))?;
            let page = self
                .pages
                .get(&pkey)
                .ok_or_else(|| CpuError::Message(format!("mem_read unmapped {va:#x}")))?;
            let room = (PAGE_SIZE as usize).saturating_sub(page_off);
            let remaining = bytes.len().saturating_sub(offset);
            let chunk = room.min(remaining);
            let dst = bytes
                .get_mut(offset..offset.saturating_add(chunk))
                .ok_or_else(|| CpuError::Message("mem_read slice OOB".into()))?;
            // SAFETY: page mapped; chunk stays in-page.
            unsafe {
                std::ptr::copy_nonoverlapping(page.ptr.add(page_off), dst.as_mut_ptr(), chunk);
            }
            offset = offset.saturating_add(chunk);
            va = va.saturating_add(u64::try_from(chunk).unwrap_or(0));
        }
        Ok(())
    }

    fn page_data_ptr(&mut self, page_key: u64) -> Option<*mut u8> {
        self.pages.get(&page_key).map(|p| p.ptr)
    }

    fn page_data_ptr_walk(&self, page_key: u64) -> Option<*mut u8> {
        self.pages.get(&page_key).map(|p| p.ptr)
    }

    fn name(&self) -> &'static str {
        "mmap_page"
    }
}
