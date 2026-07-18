//! Property-style oracle: same ops on two backends must agree (Phase 1.3).
//!
//! Time-budgeted for CI: fixed PRNG seed, capped operation count.

#![cfg(test)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use super::backend::{GuestMemBackend, PAGE_SIZE};
use super::hashmap::HashMapBackend;
use super::mmap_arena::MmapArenaBackend;
use super::mmap_page::MmapPageBackend;

/// Simple xorshift64 for deterministic sequences (no extra crate).
struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn gen_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            0
        } else {
            self.next_u64() % max
        }
    }
}

#[derive(Clone, Copy)]
enum Op {
    Map {
        page: u32,
        pages: u32,
    },
    Write {
        page: u32,
        off: u16,
        len: u16,
        fill: u8,
    },
    Read {
        page: u32,
        off: u16,
        len: u16,
    },
}

fn apply(backend: &mut dyn GuestMemBackend, op: Op) -> Result<Option<Vec<u8>>, String> {
    const BASE: u64 = 0x10_0000;
    match op {
        Op::Map { page, pages } => {
            let addr = BASE.saturating_add(u64::from(page).saturating_mul(PAGE_SIZE));
            let size = usize::try_from(u64::from(pages).saturating_mul(PAGE_SIZE)).unwrap_or(0);
            backend
                .map(addr, size, 7)
                .map_err(|e| format!("map {addr:#x}+{size:#x}: {e}"))?;
            Ok(None)
        }
        Op::Write {
            page,
            off,
            len,
            fill,
        } => {
            let addr = BASE
                .saturating_add(u64::from(page).saturating_mul(PAGE_SIZE))
                .saturating_add(u64::from(off));
            let data = vec![fill; len as usize];
            backend
                .write(addr, &data)
                .map_err(|e| format!("write {addr:#x}: {e}"))?;
            Ok(None)
        }
        Op::Read { page, off, len } => {
            let addr = BASE
                .saturating_add(u64::from(page).saturating_mul(PAGE_SIZE))
                .saturating_add(u64::from(off));
            let mut buf = vec![0_u8; len as usize];
            match backend.read(addr, &mut buf) {
                Ok(()) => Ok(Some(buf)),
                Err(e) => Err(format!("read {addr:#x}: {e}")),
            }
        }
    }
}

fn gen_ops(rng: &mut XorShift64, n: usize) -> Vec<Op> {
    let mut ops = Vec::with_capacity(n.saturating_add(8));
    // Always map a working set first so reads/writes have a chance to succeed.
    ops.push(Op::Map { page: 0, pages: 16 });
    ops.push(Op::Map { page: 32, pages: 8 });
    for _ in 0..n {
        match rng.next_u32() % 10 {
            0 => {
                let page = rng.gen_range(64) as u32;
                let pages = 1 + (rng.gen_range(4) as u32);
                ops.push(Op::Map { page, pages });
            }
            1..=5 => {
                let page = rng.gen_range(48) as u32;
                let off = rng.gen_range(PAGE_SIZE) as u16;
                let room = PAGE_SIZE.saturating_sub(u64::from(off)).min(256);
                let len = 1 + rng.gen_range(room.max(1)) as u16;
                let fill = rng.next_u32() as u8;
                ops.push(Op::Write {
                    page,
                    off,
                    len,
                    fill,
                });
            }
            _ => {
                let page = rng.gen_range(48) as u32;
                let off = rng.gen_range(PAGE_SIZE) as u16;
                let room = PAGE_SIZE.saturating_sub(u64::from(off)).min(256);
                let len = 1 + rng.gen_range(room.max(1)) as u16;
                ops.push(Op::Read { page, off, len });
            }
        }
    }
    ops
}

fn run_oracle_pair(
    seed: u64,
    n_ops: usize,
    label: &str,
    mut a: Box<dyn GuestMemBackend>,
    mut b: Box<dyn GuestMemBackend>,
) {
    let mut rng = XorShift64(seed);
    let ops = gen_ops(&mut rng, n_ops);
    for (i, op) in ops.into_iter().enumerate() {
        let ra = apply(a.as_mut(), op);
        let rb = apply(b.as_mut(), op);
        match (ra, rb) {
            (Ok(Some(va)), Ok(Some(vb))) => {
                assert_eq!(va, vb, "seed={seed} op#{i} read mismatch ({label})");
            }
            // Both succeeded with no payload, or both failed (e.g. unmapped read).
            (Ok(None), Ok(None)) | (Err(_), Err(_)) => {}
            (la, lb) => {
                panic!("seed={seed} op#{i} outcome diverge ({label}): a={la:?} b={lb:?}");
            }
        }
    }
}

fn run_oracle_page(seed: u64, n_ops: usize) {
    run_oracle_pair(
        seed,
        n_ops,
        "hash vs mmap_page",
        Box::new(HashMapBackend::new()),
        Box::new(MmapPageBackend::new()),
    );
}

fn run_oracle_arena(seed: u64, n_ops: usize) {
    run_oracle_pair(
        seed,
        n_ops,
        "hash vs mmap_arena",
        Box::new(HashMapBackend::new()),
        Box::new(MmapArenaBackend::new()),
    );
}

#[test]
fn oracle_hash_vs_mmap_page_default_seed() {
    // ~2k ops keeps CI under a second on Apple Silicon.
    run_oracle_page(0x001E_BEEF_u64, 2_000);
}

#[test]
fn oracle_hash_vs_mmap_page_alt_seeds() {
    for seed in [1_u64, 42, 0xDEAD_BEEF, 0x00C0_FFEE] {
        run_oracle_page(seed, 500);
    }
}

#[test]
fn oracle_hash_vs_mmap_arena_default_seed() {
    run_oracle_arena(0x001E_BEEF_u64, 2_000);
}

#[test]
fn oracle_hash_vs_mmap_arena_alt_seeds() {
    for seed in [1_u64, 42, 0xDEAD_BEEF, 0x00C0_FFEE] {
        run_oracle_arena(seed, 500);
    }
}

#[test]
fn oracle_page_ptr_walk_agrees() {
    let mut a = HashMapBackend::new();
    let mut b = MmapPageBackend::new();
    let mut c = MmapArenaBackend::new();
    a.map(0x20_0000, 0x2000, 7).expect("hash map");
    b.map(0x20_0000, 0x2000, 7).expect("mmap_page map");
    c.map(0x20_0000, 0x2000, 7).expect("mmap_arena map");
    let payload = b"hello-oracle";
    a.write(0x20_0040, payload).expect("hash write");
    b.write(0x20_0040, payload).expect("mmap_page write");
    c.write(0x20_0040, payload).expect("mmap_arena write");
    let mut ha = [0_u8; 12];
    let mut hb = [0_u8; 12];
    let mut hc = [0_u8; 12];
    a.read(0x20_0040, &mut ha).expect("hash read");
    b.read(0x20_0040, &mut hb).expect("mmap_page read");
    c.read(0x20_0040, &mut hc).expect("mmap_arena read");
    assert_eq!(ha, hb);
    assert_eq!(ha, hc);
    assert!(a.page_data_ptr_walk(0x20_0000 >> 12).is_some());
    assert!(b.page_data_ptr_walk(0x20_0000 >> 12).is_some());
    assert!(c.page_data_ptr_walk(0x20_0000 >> 12).is_some());
    // Arena consecutive pages are contiguous in host VA.
    let p0 = c.page_data_ptr_walk(0x20_0000 >> 12).expect("c0");
    let p1 = c.page_data_ptr_walk(0x20_1000 >> 12).expect("c1");
    assert_eq!(p1 as usize - p0 as usize, PAGE_SIZE as usize);
}
