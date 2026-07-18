//! Virtual Address Descriptor (VAD) table for Phase 3 VirtualAlloc/Free.
//!
//! Tracks reservation bases, sizes, and allocation protect. Per-page state lives
//! in [`super::pagemap::PageMap`]; this table answers “which allocation owns VA?”
//! and free-space search for NULL `lpAddress`.

use crate::CpuError;

/// Windows allocation granularity for reserve alignment (Learn: typically 64 KiB).
pub const GUEST_ALLOC_GRANULARITY: u64 = 0x1_0000;

/// Free-VA scan start (just above 4 GiB).
const FREE_VA_SEARCH_START: u64 = 0x0000_0001_0000_0000;
/// Free-VA scan end (below common high layout heaps).
const FREE_VA_SEARCH_END: u64 = 0x0000_7000_0000_0000;

/// `MEM_COMMIT`
pub const MEM_COMMIT: u32 = 0x1000;
/// `MEM_RESERVE`
pub const MEM_RESERVE: u32 = 0x2000;
/// `MEM_DECOMMIT`
pub const MEM_DECOMMIT: u32 = 0x4000;
/// `MEM_RELEASE`
pub const MEM_RELEASE: u32 = 0x8000;
/// `MEM_FREE` (VirtualQuery state)
pub const MEM_FREE: u32 = 0x1_0000;
/// `MEM_PRIVATE`
pub const MEM_PRIVATE: u32 = 0x2_0000;
/// `MEM_IMAGE`
pub const MEM_IMAGE: u32 = 0x100_0000;

/// Memory type reported in VirtualQuery / stored on the VAD node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemType {
    /// Private committed/reserved region.
    Private,
    /// PE image mapping.
    Image,
}

impl MemType {
    /// Windows `Type` field value.
    #[must_use]
    pub fn win32(self) -> u32 {
        match self {
            Self::Private => MEM_PRIVATE,
            Self::Image => MEM_IMAGE,
        }
    }
}

/// One reservation / allocation descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VadNode {
    /// Allocation base (granularity-aligned for new reserves).
    pub allocation_base: u64,
    /// Reservation size in bytes (page-aligned; typically granularity-aligned).
    pub size: u64,
    /// `flProtect` at reserve / create time.
    pub allocation_protect: u32,
    /// Private vs image.
    pub mem_type: MemType,
    /// When true, `MEM_RELEASE` should drop host storage for the full span.
    pub owns_host: bool,
}

impl VadNode {
    /// Exclusive end VA.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.allocation_base.saturating_add(self.size)
    }

    /// Whether `va` lies in `[base, base+size)`.
    #[must_use]
    pub fn contains(&self, va: u64) -> bool {
        va >= self.allocation_base && va < self.end()
    }

    /// Whether `[addr, addr+len)` is fully inside this node.
    #[must_use]
    pub fn contains_range(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return self.contains(addr);
        }
        let Some(end) = addr.checked_add(len) else {
            return false;
        };
        addr >= self.allocation_base && end <= self.end()
    }
}

/// Sorted VAD list (few dozen entries; linear scan is fine).
#[derive(Debug, Clone, Default)]
pub struct VadTable {
    nodes: Vec<VadNode>,
}

impl VadTable {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// All nodes in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &VadNode> {
        self.nodes.iter()
    }

    /// Number of allocations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Node whose range contains `va`.
    #[must_use]
    pub fn find(&self, va: u64) -> Option<&VadNode> {
        self.nodes.iter().find(|n| n.contains(va))
    }

    /// Node with exact `allocation_base`.
    #[must_use]
    pub fn find_base(&self, allocation_base: u64) -> Option<&VadNode> {
        self.nodes
            .iter()
            .find(|n| n.allocation_base == allocation_base)
    }

    /// Insert a new node; fails if it overlaps any existing node.
    pub fn insert(&mut self, node: VadNode) -> Result<(), CpuError> {
        if node.size == 0 {
            return Err(CpuError::Message("VAD size 0".into()));
        }
        let base = node.allocation_base;
        let end = node.end();
        for n in &self.nodes {
            if n.allocation_base < end && n.end() > base {
                return Err(CpuError::Message(format!(
                    "win32({ERROR_INVALID_ADDRESS}): VAD overlap at {base:#x}"
                )));
            }
        }
        let pos = self
            .nodes
            .iter()
            .position(|n| n.allocation_base > base)
            .unwrap_or(self.nodes.len());
        self.nodes.insert(pos, node);
        Ok(())
    }

    /// Remove node by allocation base; returns the removed node.
    pub fn remove_base(&mut self, allocation_base: u64) -> Option<VadNode> {
        let i = self
            .nodes
            .iter()
            .position(|n| n.allocation_base == allocation_base)?;
        Some(self.nodes.remove(i))
    }

    /// True if `[base, base+size)` overlaps any VAD.
    #[must_use]
    pub fn overlaps(&self, base: u64, size: u64) -> bool {
        let end = base.saturating_add(size);
        self.nodes
            .iter()
            .any(|n| n.allocation_base < end && n.end() > base)
    }

    /// Find a free hole of `size` bytes (already granularity-aligned), scanning
    /// upward from a high user-space band.
    ///
    /// `is_page_busy` reports whether a page key is non-free in the PageMap
    /// (covers bootstrap `mem_map` without a VAD gap).
    pub fn find_free_region(&self, size: u64, is_page_busy: &dyn Fn(u64) -> bool) -> Option<u64> {
        if size == 0 || !size.is_multiple_of(GUEST_ALLOC_GRANULARITY) {
            return None;
        }
        // Prefer high user-space similar to existing layout (0x7000_… region used
        // by heaps); start just above 4 GiB to avoid low-VA PE defaults.
        let mut addr = FREE_VA_SEARCH_START;
        while addr.saturating_add(size) <= FREE_VA_SEARCH_END {
            if self.region_is_free(addr, size, is_page_busy) {
                return Some(addr);
            }
            // Skip forward: if a VAD blocks us, jump past it.
            if let Some(blocker) = self
                .nodes
                .iter()
                .find(|n| n.allocation_base < addr.saturating_add(size) && n.end() > addr)
            {
                let next = align_up(blocker.end(), GUEST_ALLOC_GRANULARITY);
                if next <= addr {
                    addr = addr.saturating_add(GUEST_ALLOC_GRANULARITY);
                } else {
                    addr = next;
                }
            } else {
                // PageMap-busy: advance one granularity (caller is_page_busy).
                addr = addr.saturating_add(GUEST_ALLOC_GRANULARITY);
            }
        }
        None
    }

    fn region_is_free(&self, base: u64, size: u64, is_page_busy: &dyn Fn(u64) -> bool) -> bool {
        if self.overlaps(base, size) {
            return false;
        }
        let end = base.saturating_add(size);
        let mut page = base >> super::backend::PAGE_SHIFT;
        let last = end >> super::backend::PAGE_SHIFT;
        while page < last {
            if is_page_busy(page) {
                return false;
            }
            page = page.saturating_add(1);
        }
        true
    }
}

/// Round `x` down to multiple of `gran`.
#[must_use]
#[allow(
    clippy::integer_division,
    clippy::arithmetic_side_effects // intentional floor alignment
)]
pub fn align_down(x: u64, gran: u64) -> u64 {
    if gran == 0 {
        return x;
    }
    x / gran * gran
}

/// Round `x` up to multiple of `gran` (saturating).
#[must_use]
#[allow(
    clippy::integer_division,
    clippy::arithmetic_side_effects // intentional remainder alignment
)]
pub fn align_up(x: u64, gran: u64) -> u64 {
    if gran == 0 {
        return x;
    }
    let rem = x % gran;
    if rem == 0 {
        x
    } else {
        x.saturating_add(gran.saturating_sub(rem))
    }
}

/// Win32 `ERROR_INVALID_ADDRESS`
pub const ERROR_INVALID_ADDRESS: u32 = 487;
/// Win32 `ERROR_INVALID_PARAMETER`
pub const ERROR_INVALID_PARAMETER: u32 = 87;
/// Win32 `ERROR_NOT_ENOUGH_MEMORY`
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;

/// Build a `CpuError` carrying a Win32 code in a stable string form.
#[must_use]
pub(crate) fn va_error(win32: u32, msg: impl Into<String>) -> CpuError {
    CpuError::Message(format!("win32({win32}): {}", msg.into()))
}

/// Parse `win32(N):` prefix from a [`CpuError`] message, if present.
#[must_use]
pub fn win32_from_cpu_error(err: &CpuError) -> Option<u32> {
    let s = err.to_string();
    let rest = s.strip_prefix("win32(")?;
    let (num, _) = rest.split_once(')')?;
    num.parse().ok()
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_find() {
        let mut t = VadTable::new();
        t.insert(VadNode {
            allocation_base: 0x1_0000,
            size: 0x1_0000,
            allocation_protect: 0x04,
            mem_type: MemType::Private,
            owns_host: true,
        })
        .expect("insert");
        assert!(t.find(0x1_0800).is_some());
        assert!(t.find(0x2_0000).is_none());
    }

    #[test]
    fn overlap_rejected() {
        let mut t = VadTable::new();
        t.insert(VadNode {
            allocation_base: 0x1_0000,
            size: 0x2_0000,
            allocation_protect: 0x04,
            mem_type: MemType::Private,
            owns_host: true,
        })
        .expect("a");
        assert!(
            t.insert(VadNode {
                allocation_base: 0x2_0000,
                size: 0x1_0000,
                allocation_protect: 0x04,
                mem_type: MemType::Private,
                owns_host: true,
            })
            .is_err()
        );
    }

    #[test]
    fn align_helpers() {
        assert_eq!(align_down(0x12345, 0x10000), 0x10000);
        assert_eq!(align_up(0x10001, 0x10000), 0x20000);
        assert_eq!(align_up(0x10000, 0x10000), 0x10000);
    }

    #[test]
    fn find_free_skips_busy() {
        let mut t = VadTable::new();
        t.insert(VadNode {
            allocation_base: 0x0000_0001_0000_0000,
            size: 0x1_0000,
            allocation_protect: 0x04,
            mem_type: MemType::Private,
            owns_host: true,
        })
        .expect("insert");
        let hole = t.find_free_region(0x1_0000, &|_| false).expect("hole");
        assert!(hole >= 0x0000_0001_0001_0000);
    }
}
