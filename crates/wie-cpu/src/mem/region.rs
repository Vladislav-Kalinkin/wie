//! Software region registry for named guest VA ranges (Phase 1.2).
//!
//! Tracks stack, heap, image, fake API, TEB, etc. with permissions and an
//! optional host base (filled once an mmap arena is attached in Phase 2).

/// Kind of guest memory region (layout bookkeeping).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionKind {
    /// PE image mapping.
    Image,
    /// Guest stack.
    Stack,
    /// Process heap / shadow heap.
    Heap,
    /// Fake WinAPI trampoline page.
    FakeApi,
    /// TEB / TIB page(s).
    Teb,
    /// Environment / module path strings.
    Env,
    /// Guest-code stubs / accelerators.
    GuestCode,
    /// Guest I/O tables / file mirror arena.
    GuestIo,
    /// Resource blob.
    Resource,
    /// Other / uncategorised.
    Other,
}

/// One named contiguous guest VA range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRegion {
    /// Stable name (`"stack"`, `"process_heap"`, …).
    pub name: String,
    /// Semantic kind.
    pub kind: RegionKind,
    /// Inclusive start VA (page-aligned).
    pub base: u64,
    /// Size in bytes (page-aligned).
    pub size: usize,
    /// Permission bits (`perm::ALL` etc.).
    pub perms: u32,
    /// Optional host mapping base once an mmap arena is attached.
    pub host_base: Option<u64>,
}

impl GuestRegion {
    /// Construct a region without a host base.
    #[must_use]
    pub fn new(name: impl Into<String>, kind: RegionKind, base: u64, size: usize, perms: u32) -> Self {
        Self {
            name: name.into(),
            kind,
            base,
            size,
            perms,
            host_base: None,
        }
    }

    /// Exclusive end VA (`base + size`), saturating on overflow.
    #[must_use]
    pub fn end(&self) -> u64 {
        let size_u64 = u64::try_from(self.size).unwrap_or(u64::MAX);
        self.base.saturating_add(size_u64)
    }

    /// Whether `va` lies in `[base, base+size)`.
    #[must_use]
    pub fn contains(&self, va: u64) -> bool {
        va >= self.base && va < self.end()
    }
}

/// Ordered table of guest regions (linear scan is fine: O(tens of entries)).
#[derive(Debug, Clone, Default)]
pub struct RegionTable {
    regions: Vec<GuestRegion>,
}

impl RegionTable {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Register or replace a region by name.
    pub fn register(&mut self, region: GuestRegion) {
        if let Some(existing) = self.regions.iter_mut().find(|r| r.name == region.name) {
            *existing = region;
        } else {
            self.regions.push(region);
        }
    }

    /// First region containing `va`.
    #[must_use]
    pub fn find(&self, va: u64) -> Option<&GuestRegion> {
        self.regions.iter().find(|r| r.contains(va))
    }

    /// First registered region of the given kind (registration order).
    #[must_use]
    pub fn find_by_kind(&self, kind: RegionKind) -> Option<&GuestRegion> {
        self.regions.iter().find(|r| r.kind == kind)
    }

    /// Lookup by exact name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&GuestRegion> {
        self.regions.iter().find(|r| r.name == name)
    }

    /// All registered regions (registration order).
    pub fn iter(&self) -> impl Iterator<Item = &GuestRegion> {
        self.regions.iter()
    }

    /// Number of registered regions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Set `host_base` on every region that contains `va` when still unset.
    ///
    /// Used after an mmap arena is attached so Phase 4 can pin host pointers.
    pub fn set_host_base_if_covers(&mut self, va: u64, host_base: u64) {
        for r in &mut self.regions {
            if r.contains(va) && r.host_base.is_none() {
                r.host_base = Some(host_base);
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn find_region_by_va() {
        let mut t = RegionTable::new();
        t.register(GuestRegion::new("stack", RegionKind::Stack, 0x2000_0000, 0x1_0000, 7));
        t.register(GuestRegion::new(
            "heap",
            RegionKind::Heap,
            0x1_6000_0000,
            0x100_0000,
            7,
        ));
        assert_eq!(
            t.find(0x2000_1000).expect("stack").name,
            "stack"
        );
        assert_eq!(
            t.find(0x1_6000_0040).expect("heap").name,
            "heap"
        );
        assert!(t.find(0x1000).is_none());
        assert_eq!(t.by_name("stack").expect("name").base, 0x2000_0000);
    }
}
