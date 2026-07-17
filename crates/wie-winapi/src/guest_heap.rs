//! Guest process-heap: segregated free-list (size classes) + bump for virgin space.
//!
//! Goals:
//! - **Correct free**: blocks return to freelists and are reused (no permanent arena leak).
//! - **Fast path O(1)**: alloc/free for class-sized blocks are stack pop/push + HashMap.
//! - Large blocks use a separate free list with best-fit scan (rare for WIE).

use std::collections::HashMap;

/// Number of fixed size classes (powers-of-two-ish ladder).
pub const HEAP_SIZE_CLASS_COUNT: usize = 24;

/// Size classes in bytes (must be strictly increasing, all ≥ 16 and 16-byte aligned).
const SIZE_CLASSES: [u64; HEAP_SIZE_CLASS_COUNT] = [
    16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192,
    12288, 16384, 24576, 32768, 49152, 65536,
];

/// Threshold above which blocks use the large free-list instead of size classes.
const LARGE_THRESHOLD: u64 = 65_536;

/// One free large block awaiting reuse.
#[derive(Debug, Clone, Copy)]
struct LargeFreeBlock {
    address: u64,
    size: u64,
}

/// Host-side model of the guest process heap region.
#[derive(Debug, Clone)]
pub struct GuestHeap {
    /// Inclusive base of the mapped heap region.
    pub base: u64,
    /// Exclusive end of the mapped heap region.
    pub end: u64,
    /// Bump cursor for never-before-used space (always ≥ `base`, ≤ `end`).
    bump: u64,
    /// Free lists for each size class (LIFO stacks of block addresses).
    free_lists: [Vec<u64>; HEAP_SIZE_CLASS_COUNT],
    /// Free large blocks (size > [`LARGE_THRESHOLD`]).
    large_free: Vec<LargeFreeBlock>,
    /// Live allocations: payload address → allocated size (class or large rounded).
    live: HashMap<u64, u64>,
    /// When set, freelist heads + bump live in guest memory at this VA (shared with
    /// in-guest HeapAlloc/HeapFree helpers). Host path must use
    /// [`Self::sync_from_guest`] / [`Self::sync_to_guest`].
    guest_ctrl_va: Option<u64>,
}

impl GuestHeap {
    /// Creates an empty heap covering `[base, end)`.
    #[must_use]
    pub fn new(base: u64, end: u64) -> Self {
        Self {
            base,
            end,
            bump: base,
            free_lists: std::array::from_fn(|_| Vec::with_capacity(64)),
            large_free: Vec::new(),
            live: HashMap::with_capacity(4096),
            guest_ctrl_va: None,
        }
    }

    /// Attach shared guest control block (bump + freelist heads).
    pub fn attach_guest_control(&mut self, ctrl_va: u64) {
        self.guest_ctrl_va = Some(ctrl_va);
    }

    fn read_u64(engine: &mut dyn wie_cpu::CpuEngine, va: u64) -> Option<u64> {
        let mut b = [0_u8; 8];
        engine.mem_read(va, &mut b).ok()?;
        Some(u64::from_le_bytes(b))
    }

    fn write_u64(engine: &mut dyn wie_cpu::CpuEngine, va: u64, value: u64) {
        drop(engine.mem_write(va, &value.to_le_bytes()));
    }

    fn head_va(ctrl: u64, class: usize) -> u64 {
        let class_u64 = u64::try_from(class).unwrap_or(0);
        ctrl.wrapping_add(8).wrapping_add(class_u64.wrapping_mul(8))
    }

    /// Pull only the bump cursor (O(1)). Freelists stay in guest memory.
    pub fn sync_bump_from_guest(&mut self, engine: &mut dyn wie_cpu::CpuEngine) {
        let Some(ctrl) = self.guest_ctrl_va else {
            return;
        };
        if let Some(bump) = Self::read_u64(engine, ctrl) {
            self.bump = bump;
        }
    }

    pub fn sync_bump_to_guest(&self, engine: &mut dyn wie_cpu::CpuEngine) {
        let Some(ctrl) = self.guest_ctrl_va else {
            return;
        };
        Self::write_u64(engine, ctrl, self.bump);
    }

    /// High-water mark used by GDI handle generators (not a free cursor).
    #[must_use]
    pub fn bump_cursor(&self) -> u64 {
        self.bump
    }

    /// Number of live allocations (debug / handle serial helpers).
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    /// Allocates `size` bytes (16-byte aligned). Returns 0 on OOM.
    ///
    /// When guest control is attached, call [`Self::sync_from_guest`] before and
    /// [`Self::sync_to_guest`] after (handlers that also write size headers).
    #[inline]
    pub fn alloc(&mut self, size: u64) -> u64 {
        if size == 0 {
            return 0;
        }
        let rounded = round_up_size(size);
        if rounded == 0 {
            return 0;
        }

        if rounded <= LARGE_THRESHOLD {
            let class = size_class_index(rounded);
            if let Some(addr) = self.free_lists.get_mut(class).and_then(std::vec::Vec::pop) {
                self.live.insert(addr, rounded);
                return addr;
            }
            self.bump_alloc(rounded)
        } else {
            // Large: best-fit among free large blocks, else bump.
            if let Some(best_i) = self.find_large_fit(rounded) {
                let block = self.large_free.swap_remove(best_i);
                // Optional: residual remainder goes back to freelist if large enough.
                if block.size >= rounded.saturating_add(LARGE_THRESHOLD) {
                    let residual_addr = block.address.saturating_add(rounded);
                    let residual_size = block.size.saturating_sub(rounded);
                    if residual_addr > block.address && residual_size >= 16 {
                        self.large_free.push(LargeFreeBlock {
                            address: residual_addr,
                            size: residual_size,
                        });
                    }
                }
                self.live.insert(block.address, rounded);
                return block.address;
            }
            self.bump_alloc(rounded)
        }
    }

    /// Like [`Self::alloc`], but keeps guest control block + size headers coherent.
    ///
    /// **O(1)** against guest freelist heads — never walks the free chain (wall-clock).
    pub fn alloc_coherent(&mut self, engine: &mut dyn wie_cpu::CpuEngine, size: u64) -> u64 {
        let Some(ctrl) = self.guest_ctrl_va else {
            return self.alloc(size);
        };
        if size == 0 {
            return 0;
        }
        let rounded = round_up_size(size);
        if rounded == 0 {
            return 0;
        }

        if rounded <= LARGE_THRESHOLD {
            let class = size_class_index(rounded);
            let hva = Self::head_va(ctrl, class);
            if let Some(head) = Self::read_u64(engine, hva)
                && head != 0
                && head >= self.base
                && head < self.end
            {
                let next = Self::read_u64(engine, head).unwrap_or(0);
                Self::write_u64(engine, hva, next);
                Self::write_u64(engine, head.wrapping_sub(8), rounded);
                self.live.insert(head, rounded);
                return head;
            }
            // Bump from guest cursor.
            self.sync_bump_from_guest(engine);
            let addr = self.bump_alloc(rounded);
            if addr != 0 {
                Self::write_u64(engine, addr.wrapping_sub(8), rounded);
                self.sync_bump_to_guest(engine);
            }
            return addr;
        }

        // Large: host large freelist + guest bump only.
        self.sync_bump_from_guest(engine);
        let addr = self.alloc(size);
        if addr != 0 {
            if let Some(sz) = self.live.get(&addr).copied() {
                Self::write_u64(engine, addr.wrapping_sub(8), sz);
            }
            self.sync_bump_to_guest(engine);
        }
        addr
    }

    /// Frees a previously allocated block. Returns `true` if the address was live.
    #[inline]
    pub fn free(&mut self, address: u64) -> bool {
        if address == 0 {
            return false;
        }
        let Some(size) = self.live.remove(&address) else {
            return false;
        };
        if size <= LARGE_THRESHOLD {
            let class = size_class_index(size);
            if let Some(list) = self.free_lists.get_mut(class) {
                list.push(address);
            }
        } else {
            self.large_free.push(LargeFreeBlock { address, size });
        }
        true
    }

    /// Free that also accepts guest-allocated blocks (size from header).
    /// **O(1)** guest head push — no freelist rebuild.
    pub fn free_coherent(&mut self, engine: &mut dyn wie_cpu::CpuEngine, address: u64) -> bool {
        if address == 0 {
            return true;
        }
        let Some(ctrl) = self.guest_ctrl_va else {
            return self.free(address);
        };

        if let Some(size) = self.live.remove(&address) {
            return self.free_known_block(engine, ctrl, address, size);
        }

        // Guest-side alloc (or host lost the live entry): size header is the source of truth.
        // Zeroed header after a prior free → double-free / unknown → false.
        if address >= self.base
            && address < self.end
            && let Some(size) = Self::read_u64(engine, address.wrapping_sub(8))
            && size != 0
        {
            return self.free_known_block(engine, ctrl, address, size);
        }
        false
    }
    fn free_known_block(
        &mut self,
        engine: &mut dyn wie_cpu::CpuEngine,
        ctrl: u64,
        address: u64,
        size: u64,
    ) -> bool {
        if size == 0 {
            return false;
        }
        if size > LARGE_THRESHOLD {
            self.large_free.push(LargeFreeBlock { address, size });
        } else {
            let class = size_class_index(size);
            let hva = Self::head_va(ctrl, class);
            let old_head = Self::read_u64(engine, hva).unwrap_or(0);
            Self::write_u64(engine, address, old_head);
            Self::write_u64(engine, hva, address);
        }
        Self::write_u64(engine, address.wrapping_sub(8), 0);
        true
    }

    /// Returns the allocated size of a live block (HeapSize semantics: block size).
    #[inline]
    pub fn size_of(&self, address: u64) -> Option<u64> {
        self.live.get(&address).copied()
    }

    /// Whether `address` is a currently live allocation.
    #[inline]
    pub fn is_live(&self, address: u64) -> bool {
        self.live.contains_key(&address)
    }

    /// Tries to satisfy realloc without moving the block.
    ///
    /// Returns `Some(address)` if the existing physical block is large enough;
    /// `None` if the caller must allocate a new block and copy.
    #[inline]
    pub fn try_realloc_in_place(&mut self, address: u64, new_size: u64) -> Option<u64> {
        let old_size = self.live.get(&address).copied()?;
        let rounded_new = round_up_size(new_size);
        if rounded_new == 0 {
            return None;
        }
        // Physical size stays `old_size` so freelist class remains correct on free.
        if rounded_new <= old_size {
            return Some(address);
        }
        None
    }

    fn bump_alloc(&mut self, rounded: u64) -> u64 {
        // Layout matches guest helper: 8-byte size header, then 16-byte-aligned payload.
        // payload = align16(bump + 8); header at payload-8; bump' = payload + rounded.
        let Some(pre) = self.bump.checked_add(8) else {
            return 0;
        };
        let payload = pre.wrapping_add(15) & !15_u64;
        if payload < self.base {
            return 0;
        }
        let Some(end) = payload.checked_add(rounded) else {
            return 0;
        };
        if end > self.end || end < payload {
            return 0;
        }
        self.bump = end;
        self.live.insert(payload, rounded);
        payload
    }

    fn find_large_fit(&self, need: u64) -> Option<usize> {
        let mut best: Option<(usize, u64)> = None;
        for (i, block) in self.large_free.iter().enumerate() {
            if block.size >= need {
                match best {
                    None => best = Some((i, block.size)),
                    Some((_, best_size)) if block.size < best_size => {
                        best = Some((i, block.size));
                    }
                    _ => {}
                }
            }
        }
        best.map(|(i, _)| i)
    }
}

/// Rounds a user size up to the next size class (or 16-byte alignment for large).
#[inline]
fn round_up_size(size: u64) -> u64 {
    let size = size.max(1);
    if size <= LARGE_THRESHOLD {
        let class = size_class_index(size);
        SIZE_CLASSES.get(class).copied().unwrap_or(0)
    } else {
        size.wrapping_add(15) & !15_u64
    }
}

/// Index of the smallest size class that fits `size` (size already ≥ 1).
#[inline]
fn size_class_index(size: u64) -> usize {
    // Linear scan is fine for 24 classes; branchy binary search not worth it.
    for (i, &class_size) in SIZE_CLASSES.iter().enumerate() {
        if size <= class_size {
            return i;
        }
    }
    HEAP_SIZE_CLASS_COUNT - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freelist_reuses_blocks() {
        let mut heap = GuestHeap::new(0x1000, 0x1000 + 1024 * 1024);
        let a = heap.alloc(32);
        let b = heap.alloc(32);
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
        assert!(heap.free(a));
        let c = heap.alloc(32);
        assert_eq!(c, a, "freed 32-byte block must be reused");
        assert!(heap.free(b));
        assert!(heap.free(c));
        assert_eq!(heap.live_count(), 0);
    }

    #[test]
    fn free_unknown_is_false() {
        let mut heap = GuestHeap::new(0x1000, 0x2000);
        assert!(!heap.free(0x1234));
        assert!(!heap.free(0));
    }

    #[test]
    fn size_of_tracks_allocation() {
        let mut heap = GuestHeap::new(0x1000, 0x1000 + 64 * 1024);
        let a = heap.alloc(100);
        assert_eq!(heap.size_of(a), Some(128)); // rounded to class
        heap.free(a);
        assert_eq!(heap.size_of(a), None);
    }
}
