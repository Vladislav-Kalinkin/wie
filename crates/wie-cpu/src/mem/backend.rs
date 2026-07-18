//! Guest memory storage backend trait (Phase 1).
//!
//! Implementations own page data; the radix page table lives on
//! [`crate::mem::hashmap::HashMapBackend`] today. Future mmap arenas will
//! implement the same surface without changing JIT/interpreter call sites.

use crate::CpuError;

/// Page size used by all guest memory backends (4 KiB).
pub const PAGE_SIZE: u64 = 0x1000;
/// `log2(PAGE_SIZE)` — prefer shifts over division for page keys.
pub(crate) const PAGE_SHIFT: u32 = 12;

#[inline]
pub(crate) fn page_key(va: u64) -> u64 {
    va >> PAGE_SHIFT
}

/// Storage backend for guest virtual memory.
///
/// Soft translation only: guest VA is never assumed equal to host VA.
/// Not `Send`: backends hold raw page-table pointers and are single-threaded
/// (one session / one emulator thread).
pub trait GuestMemBackend {
    /// Map `[address, address+size)` with `perms` (Unicorn-compatible `PROT_*`).
    fn map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError>;

    /// Write `bytes` at guest `address`.
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError>;

    /// Read into `bytes` from guest `address`.
    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError>;

    /// Host pointer to a mapped page's data (JIT TLB). `page_key = va >> PAGE_SHIFT`.
    fn page_data_ptr(&mut self, page_key: u64) -> Option<*mut u8>;

    /// Fast page-table walk without HashMap (may be identical to [`page_data_ptr`]).
    fn page_data_ptr_walk(&self, page_key: u64) -> Option<*mut u8>;

    /// Fill `out` (≤15 bytes) from guest `address` for instruction fetch.
    /// Returns the number of valid bytes written.
    fn fetch_into(&self, address: u64, out: &mut [u8]) -> Result<usize, CpuError> {
        let want = out.len().min(15);
        if want == 0 {
            return Ok(0);
        }
        let mut len = want;
        while len > 0 {
            if self.read(address, &mut out[..len]).is_ok() {
                return Ok(len);
            }
            len = len.saturating_sub(1);
        }
        Err(CpuError::Message(format!(
            "instruction fetch unmapped {address:#x}"
        )))
    }

    /// Backend name for diagnostics (`hash`, `mmap_page`, …).
    fn name(&self) -> &'static str;
}

/// Validate page-aligned map args shared by all backends.
pub(crate) fn check_map_args(address: u64, size: usize) -> Result<(u64, u64), CpuError> {
    if size == 0 {
        return Ok((address, address));
    }
    if !address.is_multiple_of(PAGE_SIZE) {
        return Err(CpuError::Message(format!(
            "mem_map address {address:#x} not page-aligned"
        )));
    }
    let size_u64 = u64::try_from(size)
        .map_err(|_| CpuError::Message(format!("mem_map size {size} does not fit u64")))?;
    if !size_u64.is_multiple_of(PAGE_SIZE) {
        return Err(CpuError::Message(format!(
            "mem_map size {size:#x} not page-aligned"
        )));
    }
    let end = address.checked_add(size_u64).ok_or_else(|| {
        CpuError::Message(format!("mem_map overflow at {address:#x}+{size:#x}"))
    })?;
    Ok((address, end))
}
