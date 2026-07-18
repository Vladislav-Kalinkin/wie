//! Sparse run-length guest page map (state + protect) for Phase 3 SPC / VirtualQuery.
//!
//! Absence of a page key means [`PageState::Free`]. Host storage is owned by the
//! backend; this map is the Windows-visible correctness plane only.

use super::backend::{PAGE_SHIFT, PAGE_SIZE};
use super::protect::{self, AccessKind};
use crate::CpuError;
use std::cell::Cell;
use std::collections::BTreeMap;

/// Guest page lifecycle state (Microsoft Learn page states).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PageState {
    /// Not part of any allocation.
    #[default]
    Free,
    /// Reserved but not committed — all access denied.
    Reserved,
    /// Committed — access gated by protect bits.
    Committed,
}

/// One homogeneous run of guest pages `[start_page, end_page)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRun {
    /// Inclusive start page key (`va >> 12`).
    pub start_page: u64,
    /// Exclusive end page key.
    pub end_page: u64,
    /// Run state (never Free inside the map).
    pub state: PageState,
    /// Windows `PAGE_*` when committed; ignored for reserved (treat as no access).
    pub protect: u32,
}

impl PageRun {
    /// Number of pages in the run.
    #[must_use]
    pub fn page_count(&self) -> u64 {
        self.end_page.saturating_sub(self.start_page)
    }

    /// Inclusive start guest VA.
    #[must_use]
    pub fn start_va(&self) -> u64 {
        self.start_page.saturating_mul(PAGE_SIZE)
    }

    /// Exclusive end guest VA.
    #[must_use]
    pub fn end_va(&self) -> u64 {
        self.end_page.saturating_mul(PAGE_SIZE)
    }
}

/// Single-entry cache for hot SPC walks (stack/heap streams).
#[derive(Debug, Clone, Copy, Default)]
struct RunCache {
    valid: bool,
    start_page: u64,
    end_page: u64,
    state: PageState,
    protect: u32,
}

/// Sparse run-length page map: `start_page → PageRun` (non-overlapping, sorted).
///
/// Run-cache uses [`Cell`] so SPC can run on shared [`GuestMemory`] borrows
/// (interpreter reads, JIT helpers).
#[derive(Debug, Default)]
pub struct PageMap {
    /// Keyed by `start_page`; runs do not overlap.
    runs: BTreeMap<u64, PageRun>,
    cache: Cell<RunCache>,
}

impl Clone for PageMap {
    fn clone(&self) -> Self {
        Self {
            runs: self.runs.clone(),
            cache: Cell::new(self.cache.get()),
        }
    }
}

impl PageMap {
    /// Empty map (all VA free).
    #[must_use]
    pub fn new() -> Self {
        Self {
            runs: BTreeMap::new(),
            cache: Cell::new(RunCache::default()),
        }
    }

    /// Invalidate the hot-path run cache (after any mutation).
    fn bump_cache(&mut self) {
        self.cache.set(RunCache::default());
    }

    /// Look up the run covering `page_key`, if any.
    #[must_use]
    pub fn lookup(&self, page_key: u64) -> Option<PageRun> {
        let c = self.cache.get();
        if c.valid && page_key >= c.start_page && page_key < c.end_page {
            return Some(PageRun {
                start_page: c.start_page,
                end_page: c.end_page,
                state: c.state,
                protect: c.protect,
            });
        }
        // Greatest start_page ≤ page_key.
        let (&start, run) = self.runs.range(..=page_key).next_back()?;
        if page_key < run.end_page {
            debug_assert_eq!(start, run.start_page);
            Some(*run)
        } else {
            None
        }
    }

    /// Cache a successful lookup for subsequent adjacent accesses.
    fn fill_cache(&self, run: PageRun) {
        self.cache.set(RunCache {
            valid: true,
            start_page: run.start_page,
            end_page: run.end_page,
            state: run.state,
            protect: run.protect,
        });
    }

    /// Software permission check for `[va, va+len)`.
    ///
    /// All-or-nothing: if any spanned page is free, reserved, or wrong protect,
    /// the whole operation fails and no host bytes are touched by the caller.
    pub fn check_access(&self, va: u64, len: usize, kind: AccessKind) -> Result<(), CpuError> {
        if len == 0 {
            return Ok(());
        }
        let len_u64 = u64::try_from(len).map_err(|_| {
            CpuError::Message(format!("access length {len} does not fit u64"))
        })?;
        let end = va.checked_add(len_u64).ok_or_else(|| {
            CpuError::Message(format!("access overflow at {va:#x}+{len:#x}"))
        })?;

        let mut page = va >> PAGE_SHIFT;
        let last_page = end.saturating_sub(1) >> PAGE_SHIFT;
        while page <= last_page {
            let run = self.lookup(page);
            let Some(run) = run else {
                return Err(access_denied(va, kind, "unmapped"));
            };
            if run.state != PageState::Committed {
                return Err(access_denied(va, kind, "not committed"));
            }
            if !protect::allows(run.protect, kind) {
                return Err(access_denied(va, kind, "permission denied"));
            }
            self.fill_cache(run);
            // Advance past this homogeneous run (or at least this page).
            let next = run.end_page;
            if next <= page {
                // Defensive: corrupt run would infinite-loop.
                return Err(CpuError::Message("pagemap corrupt run".into()));
            }
            page = next;
        }
        Ok(())
    }

    /// Mark `[address, address+size)` as `state`/`protect`, splitting and merging runs.
    ///
    /// `size` and `address` must be page-aligned; `size == 0` is a no-op.
    /// Setting [`PageState::Free`] removes entries from the map.
    pub fn set_range(
        &mut self,
        address: u64,
        size: usize,
        state: PageState,
        protect: u32,
    ) -> Result<(), CpuError> {
        if size == 0 {
            return Ok(());
        }
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(CpuError::Message(format!(
                "pagemap set_range address {address:#x} not page-aligned"
            )));
        }
        let size_u64 = u64::try_from(size).map_err(|_| {
            CpuError::Message(format!("pagemap size {size} does not fit u64"))
        })?;
        if !size_u64.is_multiple_of(PAGE_SIZE) {
            return Err(CpuError::Message(format!(
                "pagemap set_range size {size:#x} not page-aligned"
            )));
        }
        let end = address.checked_add(size_u64).ok_or_else(|| {
            CpuError::Message(format!("pagemap overflow at {address:#x}+{size:#x}"))
        })?;

        let start_page = address >> PAGE_SHIFT;
        let end_page = end >> PAGE_SHIFT;
        self.set_page_range(start_page, end_page, state, protect);
        Ok(())
    }

    /// Core mutator on page-key half-open range `[start_page, end_page)`.
    fn set_page_range(
        &mut self,
        start_page: u64,
        end_page: u64,
        state: PageState,
        protect: u32,
    ) {
        if start_page >= end_page {
            return;
        }
        self.bump_cache();

        // Collect runs that overlap [start_page, end_page) and any adjacent merges.
        // First split any run that straddles the boundaries so we can replace the middle.
        self.split_at(start_page);
        self.split_at(end_page);

        // Remove fully covered runs inside [start_page, end_page).
        let doomed: Vec<u64> = self
            .runs
            .range(start_page..end_page)
            .map(|(&k, _)| k)
            .collect();
        for k in doomed {
            self.runs.remove(&k);
        }

        if state != PageState::Free {
            let mut new_run = PageRun {
                start_page,
                end_page,
                state,
                protect,
            };
            // Merge with left neighbour if homogeneous.
            if start_page > 0
                && let Some(left) = self.lookup_exact_end(start_page)
                && left.state == state
                && left.protect == protect
            {
                new_run.start_page = left.start_page;
                self.runs.remove(&left.start_page);
            }
            // Merge with right neighbour.
            if let Some(right) = self.runs.get(&end_page).copied()
                && right.state == state
                && right.protect == protect
            {
                new_run.end_page = right.end_page;
                self.runs.remove(&end_page);
            }
            self.runs.insert(new_run.start_page, new_run);
        }
    }

    /// Run whose exclusive end equals `page`, if stored as a single entry.
    fn lookup_exact_end(&self, page: u64) -> Option<PageRun> {
        let (&start, run) = self.runs.range(..page).next_back()?;
        if run.end_page == page && run.start_page == start {
            Some(*run)
        } else {
            None
        }
    }

    /// Split a run at `page` so that `page` is either a run start or outside all runs.
    fn split_at(&mut self, page: u64) {
        let Some(run) = self.lookup(page) else {
            return;
        };
        if run.start_page == page {
            return;
        }
        // page is strictly inside [start, end).
        self.runs.remove(&run.start_page);
        let left = PageRun {
            start_page: run.start_page,
            end_page: page,
            state: run.state,
            protect: run.protect,
        };
        let right = PageRun {
            start_page: page,
            end_page: run.end_page,
            state: run.state,
            protect: run.protect,
        };
        self.runs.insert(left.start_page, left);
        self.runs.insert(right.start_page, right);
    }

    /// Homogeneous run starting at or covering `va` for VirtualQuery (Phase 3.2+).
    #[must_use]
    pub fn query_run(&self, va: u64) -> Option<PageRun> {
        let page = va >> PAGE_SHIFT;
        self.lookup(page)
    }

    /// Iterate all stored runs in VA order.
    pub fn iter_runs(&self) -> impl Iterator<Item = &PageRun> {
        self.runs.values()
    }

    /// Number of stored runs (diagnostics / tests).
    #[must_use]
    pub fn run_count(&self) -> usize {
        self.runs.len()
    }
}

fn access_denied(va: u64, kind: AccessKind, why: &str) -> CpuError {
    let op = match kind {
        AccessKind::Read => "mem_read",
        AccessKind::Write => "mem_write",
        AccessKind::Execute => "instruction fetch",
    };
    CpuError::Message(format!("{op} {why} {va:#x}"))
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mem::protect::{
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    };

    #[test]
    fn set_and_lookup_committed() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x2000, PageState::Committed, PAGE_READWRITE)
            .expect("set");
        let r = m.lookup(0x1000 >> 12).expect("run");
        assert_eq!(r.state, PageState::Committed);
        assert_eq!(r.protect, PAGE_READWRITE);
        assert_eq!(r.page_count(), 2);
        assert!(m.lookup(0x3000 >> 12).is_none());
    }

    #[test]
    fn merge_adjacent_same_protect() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x1000, PageState::Committed, PAGE_READONLY)
            .expect("a");
        m.set_range(0x2000, 0x1000, PageState::Committed, PAGE_READONLY)
            .expect("b");
        assert_eq!(m.run_count(), 1);
        let r = m.lookup(0x1000 >> 12).expect("run");
        assert_eq!(r.end_page - r.start_page, 2);
    }

    #[test]
    fn split_on_protect_change() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x3000, PageState::Committed, PAGE_READWRITE)
            .expect("set");
        m.set_range(0x2000, 0x1000, PageState::Committed, PAGE_READONLY)
            .expect("mid");
        assert_eq!(m.run_count(), 3);
        assert_eq!(
            m.lookup(0x1000 >> 12).expect("l").protect,
            PAGE_READWRITE
        );
        assert_eq!(m.lookup(0x2000 >> 12).expect("m").protect, PAGE_READONLY);
        assert_eq!(
            m.lookup(0x3000 >> 12).expect("r").protect,
            PAGE_READWRITE
        );
    }

    #[test]
    fn free_removes_range() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x3000, PageState::Committed, PAGE_READWRITE)
            .expect("set");
        m.set_range(0x2000, 0x1000, PageState::Free, 0)
            .expect("free");
        assert!(m.lookup(0x2000 >> 12).is_none());
        assert!(m.lookup(0x1000 >> 12).is_some());
        assert!(m.lookup(0x3000 >> 12).is_some());
    }

    #[test]
    fn check_access_ro_write_fails() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x1000, PageState::Committed, PAGE_READONLY)
            .expect("set");
        assert!(m.check_access(0x1000, 8, AccessKind::Read).is_ok());
        assert!(m.check_access(0x1000, 8, AccessKind::Write).is_err());
        assert!(m.check_access(0x1000, 8, AccessKind::Execute).is_err());
    }

    #[test]
    fn check_access_rx_fetch_ok() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x1000, PageState::Committed, PAGE_EXECUTE_READ)
            .expect("set");
        assert!(m.check_access(0x1000, 15, AccessKind::Execute).is_ok());
        assert!(m.check_access(0x1000, 8, AccessKind::Write).is_err());
    }

    #[test]
    fn check_access_reserved_denied() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x1000, PageState::Reserved, PAGE_NOACCESS)
            .expect("set");
        assert!(m.check_access(0x1000, 1, AccessKind::Read).is_err());
    }

    #[test]
    fn check_access_cross_page_all_or_nothing() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x1000, PageState::Committed, PAGE_EXECUTE_READWRITE)
            .expect("a");
        // Second page unmapped — spanning write must fail entirely.
        let err = m
            .check_access(0x1ffc, 8, AccessKind::Write)
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("unmapped") || msg.contains("not committed"));
    }

    #[test]
    fn check_access_cross_page_ok_when_both_committed() {
        let mut m = PageMap::new();
        m.set_range(0x1000, 0x2000, PageState::Committed, PAGE_READWRITE)
            .expect("set");
        m.check_access(0x1ffc, 8, AccessKind::Write).expect("ok");
    }
}
