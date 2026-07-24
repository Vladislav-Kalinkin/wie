//! Lower pure-GPR (+ simple mem / jcc) blocks to Cranelift IR and finalize host code.
//!
//! Cast/index/arithmetic allows shared with other JIT modules live on `jit/mod.rs`.

#![allow(
    clippy::cast_possible_wrap, // mem width / offset → i32 for Cranelift
    clippy::many_single_char_names, // flag temps d/s/r in flags_* helpers
    clippy::too_many_arguments
)]

use super::JitEngine;
use super::block::{
    BlockStackPinPlan, BlockTerm, DecodedInsn, analyze_block_stack_pin, is_string_op,
    mem_width_bytes, string_op_size,
};
use super::fast_api::{self, FastApiKind};
use crate::exec::{self, StringOpKind};
use crate::mem::{GuestMemory, PAGE_SIZE};
use crate::regs::{RegFile, rflags};
use cranelift::codegen::ir::{BlockArg, FuncRef, SigRef, UserFuncName};
use cranelift::prelude::*;
use cranelift_codegen::ir::MemFlagsData;
use cranelift_module::{FuncId, Linkage, Module};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use std::collections::HashMap;

/// Set-associative TLB: number of sets (power of two). `SETS × WAYS` total entries.
pub(super) const TLB_SETS: usize = 16;
/// Ways per set (4-way; Neon tag compare loads two `I64X2` / `vld1q_u64`).
pub(super) const TLB_WAYS_PER_SET: usize = 4;
/// Empty TLB slot marker (`page_key == TLB_EMPTY`).
pub(super) const TLB_EMPTY: u64 = u64::MAX;

/// TLB / sticky software permission: bit0 = read, bit1 = write.
pub(super) const TLB_PROT_R: u64 = 1;
pub(super) const TLB_PROT_W: u64 = 2;

/// 4-way tag+host line (16-byte aligned for Neon loads).
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub(super) struct TlbBucket {
    /// Guest page keys (`va >> 12`) for 4 ways.
    pub tags: [u64; TLB_WAYS_PER_SET],
    /// Host page bases (non-owning soft-translate pointers).
    pub host: [*mut u8; TLB_WAYS_PER_SET],
}

/// Per-set generation, prot bits, and RR victim.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub(super) struct TlbBucketAux {
    pub generation: [u64; TLB_WAYS_PER_SET],
    pub prot: [u8; TLB_WAYS_PER_SET],
    /// Next victim way within the set (0..3).
    pub rr: u8,
    pub _pad: [u8; 11],
}

/// Empty bucket constructor (const-friendly for array init).
#[must_use]
pub(super) const fn empty_tlb_bucket() -> TlbBucket {
    TlbBucket {
        tags: [TLB_EMPTY; TLB_WAYS_PER_SET],
        host: [std::ptr::null_mut(); TLB_WAYS_PER_SET],
    }
}

#[must_use]
pub(super) const fn empty_tlb_aux() -> TlbBucketAux {
    TlbBucketAux {
        generation: [0; TLB_WAYS_PER_SET],
        prot: [0; TLB_WAYS_PER_SET],
        rr: 0,
        _pad: [0; 11],
    }
}

/// One XMM slot as lo/hi u64 with 16-byte alignment (Neon-friendly bank).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct XmmSlot {
    pub lo: u64,
    pub hi: u64,
}

impl XmmSlot {
    pub(super) const ZERO: Self = Self { lo: 0, hi: 0 };

    #[must_use]
    pub(super) fn from_u128(v: u128) -> Self {
        Self {
            lo: v as u64,
            hi: (v >> 64) as u64,
        }
    }

    #[must_use]
    pub(super) fn to_u128(self) -> u128 {
        u128::from(self.lo) | (u128::from(self.hi) << 64)
    }
}

/// Phase 5.5: emit Cranelift SIMD types for SSE (`WIE_JIT_SIMD=0` disables).
pub(super) fn jit_simd_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("WIE_JIT_SIMD"),
            Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off")
        )
    })
}

/// Neon software-TLB tag compare (`WIE_TLB_NEON=0` → scalar 4-way scan).
pub(super) fn tlb_neon_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("WIE_TLB_NEON"),
            Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off")
        )
    })
}

/// Inline REP MOVS/STOS for 16–64 byte const counts (`WIE_STRING_INLINE=0` disables).
pub(super) fn string_inline_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("WIE_STRING_INLINE"),
            Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off")
        )
    })
}

#[inline]
fn tlb_set_index(page_key: u64) -> usize {
    (page_key as usize) & (TLB_SETS - 1)
}

/// Open-addressing slots for guest-VA → host block fn (block chaining).
pub(super) const CHAIN_SLOTS: usize = 512;
/// Shadow return-stack depth (power of two; modular index).
pub(super) const SHADOW_DEPTH: usize = 32;
/// Region-direct pin slots (stack + primary heap). Phase 4.1.
/// Must match [`crate::mem::JIT_REGION_PIN_SLOTS`] (stack + heap + VA pins).
pub(super) const PIN_SLOTS: usize = crate::mem::JIT_REGION_PIN_SLOTS;
/// Multi sticky ways for inline IR (last-N pages before helper / multi-way TLB).
///
/// 2 balances 7za (large WS full-miss tax vs small-WS hit rate). 4 helps more
/// on tiny working sets but pays 4 probes on every thrash miss.
pub(super) const STICKY_WAYS: usize = 2;
/// Bytes per [`MemPin`] (`repr(C)`: 5×u64).
pub(super) const PIN_STRIDE: i32 = 40;
/// Monomorphic edge inline-cache slots (Phase 4.2 data-plane chaining).
pub(super) const EDGE_IC_SLOTS: usize = 4;

/// Soft-translated region pin (stack / heap / VirtualAlloc) for Phase 4.1 JIT.
///
/// Empty pin: `host_base == 0`. Filled at each `run_compiled` from
/// [`crate::mem::GuestMemory::jit_region_pins`]; gen must match `mem_gen`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct MemPin {
    /// Inclusive guest base VA.
    pub guest_base: u64,
    /// Exclusive guest end VA.
    pub guest_end: u64,
    /// Host soft-translate base (integer form of `*mut u8`).
    pub host_base: u64,
    /// Memory generation at pin install.
    pub mem_gen: u64,
    /// Software R/W bits (`TLB_PROT_R` / `TLB_PROT_W`), intersection over range.
    pub allow: u64,
}

impl MemPin {
    /// Disabled / empty pin.
    pub(super) const EMPTY: Self = Self {
        guest_base: 0,
        guest_end: 0,
        host_base: 0,
        mem_gen: 0,
        allow: 0,
    };

    /// Build from a [`crate::mem::RegionPinInfo`] (or empty if `None`).
    pub(super) fn from_info(info: Option<crate::mem::RegionPinInfo>) -> Self {
        let Some(p) = info else {
            return Self::EMPTY;
        };
        if p.host_base.is_null() || p.guest_end <= p.guest_base {
            return Self::EMPTY;
        }
        let mut allow = 0_u64;
        if p.allow_r {
            allow |= TLB_PROT_R;
        }
        if p.allow_w {
            allow |= TLB_PROT_W;
        }
        if allow == 0 {
            return Self::EMPTY;
        }
        Self {
            guest_base: p.guest_base,
            guest_end: p.guest_end,
            host_base: p.host_base as u64,
            mem_gen: p.generation,
            allow,
        }
    }
}

/// Guest register file snapshot for a compiled block (C ABI).
///
/// Layout is fixed; host mem helpers and Cranelift use the same offsets.
#[repr(C)]
pub(super) struct JitCtx {
    pub gpr: [u64; 16],
    pub rflags: u64,
    pub rip: u64,
    /// Guest memory for load/store host helpers (cross-page / fault).
    pub mem: *mut GuestMemory,
    /// Non-zero → invalid memory; `rip` holds faulting guest IP.
    pub fault: u64,
    pub fault_addr: u64,
    pub fault_size: u64,
    /// 0 = read, 1 = write (matches iced ACCESS_*).
    pub fault_access: u64,
    /// Set-associative multi-way page TLB (Phase 5.5 Track B).
    pub tlb_sets: [TlbBucket; TLB_SETS],
    /// Parallel gen/prot/rr for [`Self::tlb_sets`].
    pub tlb_aux: [TlbBucketAux; TLB_SETS],
    /// XMM0..XMM15 as 16-byte aligned slots (lo/hi layout for IR offsets).
    pub xmm: [XmmSlot; 16],
    /// Shadow return stack: push count (modular index via `sp & (SHADOW_DEPTH-1)`).
    pub shadow_sp: u64,
    /// Predicted guest return addresses for `call`/`ret` chaining.
    pub shadow_ret: [u64; SHADOW_DEPTH],
    /// Pointer to [`CHAIN_SLOTS`] guest VAs (owned by `JitCpu`, live for `run_compiled`).
    pub chain_va: *mut u64,
    /// Parallel host fn pointers (`0` = empty), same lifetime as `chain_va`.
    pub chain_fn: *mut u64,
    /// Sticky single-page TLB for inline IR mem (last hit/fill); `TLB_EMPTY` if cold.
    pub tlb_hot_page: u64,
    /// Host base pointer for [`Self::tlb_hot_page`] (page-aligned guest data).
    pub tlb_hot_ptr: *mut u8,
    /// Cumulative dirty GPR mask for host writeback (`bit i` → `gpr[i]` changed).
    /// Hand-written trampolines OR their bits; Cranelift leaves 0 → host syncs all 16.
    /// Set to `0xffff` before late-bound chain so a subsequent Cranelift block is covered.
    pub gpr_dirty_bits: u64,
    /// Phase 0: host load helper invocations during this `run_compiled` (appended; IR-stable).
    pub load_calls: u64,
    /// Phase 0: host store helper invocations during this `run_compiled`.
    pub store_calls: u64,
    /// Software R/W bits for sticky page (`TLB_PROT_R` / `TLB_PROT_W`).
    pub tlb_hot_prot: u64,
    /// [`GuestMemory::generation`] snapshot for this `run_compiled` (pin/TLB gen check).
    pub mem_gen: u64,
    /// Generation recorded for the sticky hot page.
    pub tlb_hot_gen: u64,
    /// Region-direct pins (stack / heap / VA); empty when `host_base == 0`.
    pub pins: [MemPin; PIN_SLOTS],
    /// Phase 4.2 monomorphic edge IC: guest target VA (0 = empty).
    ///
    /// Data-plane only — never patches finalized host code. Speeds late-bound
    /// chain hits when a block repeatedly transfers to the same successor.
    pub edge_ic_va: [u64; EDGE_IC_SLOTS],
    /// Parallel host fn pointers for [`Self::edge_ic_va`].
    pub edge_ic_fn: [u64; EDGE_IC_SLOTS],
    /// Round-robin victim for edge-IC install after a full chain-table hit.
    pub edge_ic_rr: u64,
    /// Dynamic XMM dirty mask written by compiled blocks (`bit i` → XMMi).
    pub xmm_dirty_bits: u64,
    /// Helper mem-path breakdown for this `run_compiled` (not used from Cranelift IR).
    pub mem_path: MemPathSlice,
    /// Multi sticky page keys (`TLB_EMPTY` = cold). Appended after IR-stable fields.
    pub sticky_page: [u64; STICKY_WAYS],
    /// Host page bases parallel to [`Self::sticky_page`].
    pub sticky_ptr: [*mut u8; STICKY_WAYS],
    /// Software R/W bits per sticky way.
    pub sticky_prot: [u64; STICKY_WAYS],
    /// Generation per sticky way.
    pub sticky_gen: [u64; STICKY_WAYS],
    /// Round-robin victim for sticky install.
    pub sticky_rr: u64,
    /// Host call-chain depth for block chaining (`emit_chain_or_exit`).
    ///
    /// Each chain hop is a host `call` into the next compiled block. Unbounded
    /// depth overflows the host stack on long guest call trees (7za large scans).
    /// When this hits [`MAX_CHAIN_DEPTH`], chaining returns to the Rust dispatcher
    /// with RIP already set so the next block re-enters without nesting.
    pub chain_depth: u64,
}

/// Per-`run_compiled` mem helper resolution counters (appended after IR-stable layout).
///
/// Classifies why the sticky IR path missed and how the helper resolved the access.
/// Cheap saturating adds; accumulate into [`super::JitStats`] after each block.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct MemPathSlice {
    /// Helper sticky hit (IR already missed — rare unless race/gen refresh).
    pub sticky_hit: u64,
    /// Multi-way set-assoc TLB hit after sticky miss.
    pub multi_hit: u64,
    /// Region pin soft-translate hit.
    pub pin_hit: u64,
    /// Full page-walk install hit.
    pub walk_hit: u64,
    /// Cross-page access (forces slow path).
    pub cross_page: u64,
    /// `tlb_page_ptr` returned `None` → GuestMemory::read/write.
    pub slow: u64,
    /// Sticky miss: page key / empty hot (working-set thrash).
    pub sticky_miss_key: u64,
    /// Sticky miss: `tlb_hot_gen != mem_gen`.
    pub sticky_miss_gen: u64,
    /// Sticky miss: R/W bit denied.
    pub sticky_miss_prot: u64,
    /// Times sticky hot page key was replaced.
    pub sticky_swaps: u64,
    /// Helper VA fell inside stack pin bounds (regardless of resolve path).
    pub addr_in_stack_pin: u64,
    /// Helper VA fell inside heap pin bounds.
    pub addr_in_heap_pin: u64,
    /// Helper VA outside both pins (VirtualAlloc / image / other).
    pub addr_outside_pins: u64,
}

// Byte offsets into [`JitCtx`] used from Cranelift IR (must match `repr(C)`).
// gpr[16] @ 0, rflags @ 128, rip @ 136, mem @ 144, fault @ 152, …
const OFF_RFLAGS: i32 = std::mem::offset_of!(JitCtx, rflags) as i32;
const OFF_RIP: i32 = std::mem::offset_of!(JitCtx, rip) as i32;
const OFF_FAULT: i32 = std::mem::offset_of!(JitCtx, fault) as i32;
const OFF_SHADOW_SP: i32 = std::mem::offset_of!(JitCtx, shadow_sp) as i32;
const OFF_XMM: i32 = std::mem::offset_of!(JitCtx, xmm) as i32;
const OFF_SHADOW_RET: i32 = OFF_SHADOW_SP + 8;
const OFF_TLB_HOT_PAGE: i32 = std::mem::offset_of!(JitCtx, tlb_hot_page) as i32;
const OFF_TLB_HOT_PTR: i32 = std::mem::offset_of!(JitCtx, tlb_hot_ptr) as i32;
const OFF_TLB_HOT_PROT: i32 = std::mem::offset_of!(JitCtx, tlb_hot_prot) as i32;
const OFF_MEM_GEN: i32 = std::mem::offset_of!(JitCtx, mem_gen) as i32;
const OFF_TLB_HOT_GEN: i32 = std::mem::offset_of!(JitCtx, tlb_hot_gen) as i32;
const OFF_PINS: i32 = std::mem::offset_of!(JitCtx, pins) as i32;
const OFF_EDGE_IC_VA: i32 = std::mem::offset_of!(JitCtx, edge_ic_va) as i32;
const OFF_EDGE_IC_FN: i32 = std::mem::offset_of!(JitCtx, edge_ic_fn) as i32;
const OFF_EDGE_IC_RR: i32 = std::mem::offset_of!(JitCtx, edge_ic_rr) as i32;
const OFF_XMM_DIRTY: i32 = std::mem::offset_of!(JitCtx, xmm_dirty_bits) as i32;
const OFF_STICKY_PAGE: i32 = std::mem::offset_of!(JitCtx, sticky_page) as i32;
const OFF_STICKY_PTR: i32 = std::mem::offset_of!(JitCtx, sticky_ptr) as i32;
const OFF_STICKY_PROT: i32 = std::mem::offset_of!(JitCtx, sticky_prot) as i32;
const OFF_STICKY_GEN: i32 = std::mem::offset_of!(JitCtx, sticky_gen) as i32;
const OFF_CHAIN_DEPTH: i32 = std::mem::offset_of!(JitCtx, chain_depth) as i32;

/// Max nested host frames for JIT block chaining.
///
/// Guest `call`/`jmp`/`ret` chain via host C `call` into the successor block.
/// ~48 keeps most hot chains in-process while staying well under default host
/// stacks even with large Cranelift frames (seen: stack overflow on 7za scan).
pub(super) const MAX_CHAIN_DEPTH: u64 = 48;

// Layout sanity: Cranelift IR offsets must match `repr(C)` packing.
const _: () = {
    assert!(std::mem::offset_of!(JitCtx, rflags) as i32 == OFF_RFLAGS);
    assert!(std::mem::offset_of!(JitCtx, rip) as i32 == OFF_RIP);
    assert!(std::mem::offset_of!(JitCtx, fault) as i32 == OFF_FAULT);
    assert!(std::mem::offset_of!(JitCtx, xmm) as i32 == OFF_XMM);
    assert!(std::mem::offset_of!(JitCtx, shadow_sp) as i32 == OFF_SHADOW_SP);
    assert!(std::mem::offset_of!(JitCtx, shadow_ret) as i32 == OFF_SHADOW_RET);
    assert!(std::mem::offset_of!(JitCtx, tlb_hot_page) as i32 == OFF_TLB_HOT_PAGE);
    assert!(std::mem::offset_of!(JitCtx, tlb_hot_ptr) as i32 == OFF_TLB_HOT_PTR);
    assert!(std::mem::offset_of!(JitCtx, tlb_hot_prot) as i32 == OFF_TLB_HOT_PROT);
    assert!(std::mem::offset_of!(JitCtx, mem_gen) as i32 == OFF_MEM_GEN);
    assert!(std::mem::offset_of!(JitCtx, tlb_hot_gen) as i32 == OFF_TLB_HOT_GEN);
    assert!(std::mem::offset_of!(JitCtx, pins) as i32 == OFF_PINS);
    assert!(std::mem::offset_of!(JitCtx, edge_ic_va) as i32 == OFF_EDGE_IC_VA);
    assert!(std::mem::offset_of!(JitCtx, edge_ic_fn) as i32 == OFF_EDGE_IC_FN);
    assert!(std::mem::offset_of!(JitCtx, edge_ic_rr) as i32 == OFF_EDGE_IC_RR);
    assert!(std::mem::offset_of!(JitCtx, xmm_dirty_bits) as i32 == OFF_XMM_DIRTY);
    assert!(std::mem::offset_of!(JitCtx, sticky_page) as i32 == OFF_STICKY_PAGE);
    assert!(std::mem::offset_of!(JitCtx, sticky_ptr) as i32 == OFF_STICKY_PTR);
    assert!(std::mem::offset_of!(JitCtx, sticky_prot) as i32 == OFF_STICKY_PROT);
    assert!(std::mem::offset_of!(JitCtx, sticky_gen) as i32 == OFF_STICKY_GEN);
    assert!(std::mem::offset_of!(JitCtx, chain_depth) as i32 == OFF_CHAIN_DEPTH);
    assert!(STICKY_WAYS > 0);
    assert!(std::mem::size_of::<MemPin>() == PIN_STRIDE as usize);
    assert!(std::mem::size_of::<XmmSlot>() == 16);
    assert!(std::mem::align_of::<XmmSlot>() >= 16);
    assert!(std::mem::align_of::<TlbBucket>() >= 16);
    assert!(std::mem::size_of::<TlbBucket>() == 64);
    assert!(TLB_SETS.is_power_of_two());
    assert!(SHADOW_DEPTH.is_power_of_two());
    assert!(CHAIN_SLOTS.is_power_of_two());
    assert!(EDGE_IC_SLOTS > 0);
};

/// Finalized block ready to run.
#[derive(Clone, Copy)]
pub(super) struct CompiledBlock {
    pub func: unsafe extern "C" fn(*mut JitCtx),
    /// Module function id (for block-chaining `declare_func_in_func`).
    /// `None` for hand-written trampolines (late-bound chain only).
    pub func_id: Option<FuncId>,
    pub insn_count: u32,
    /// Block touches XMM/SSE state — host must sync the XMM bank.
    /// Pure GPR blocks skip XMM copy on entry/exit (CPU + cache win).
    pub uses_sse: bool,
    /// Bit `i` set if XMMi is referenced (selective entry load).
    pub xmm_live_mask: u16,
    /// Bit `i` set if XMMi may be written (selective exit writeback).
    pub xmm_may_def_mask: u16,
    /// Guest code range covered by this block `[guest_start, guest_end)`.
    /// Used for range-selective cache invalidation on `mem_write`.
    pub guest_start: u64,
    pub guest_end: u64,
}

/// Hash a guest VA into a chain-table slot.
#[inline]
pub(super) fn chain_hash(va: u64) -> usize {
    let h = va.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (h as usize) & (CHAIN_SLOTS - 1)
}

/// Insert or update a compiled block in the open-addressing chain table.
pub(super) fn chain_table_insert(chain_va: &mut [u64], chain_fn: &mut [u64], va: u64, fn_ptr: u64) {
    if va == 0 || fn_ptr == 0 {
        return;
    }
    let mut i = chain_hash(va);
    for _ in 0..CHAIN_SLOTS {
        let slot = chain_va[i];
        if slot == 0 || slot == va {
            chain_va[i] = va;
            chain_fn[i] = fn_ptr;
            return;
        }
        i = (i + 1) & (CHAIN_SLOTS - 1);
    }
    // Table full: overwrite hashed slot.
    let i = chain_hash(va);
    chain_va[i] = va;
    chain_fn[i] = fn_ptr;
}

/// Clear all chain-table entries (cache invalidation).
pub(super) fn chain_table_clear(chain_va: &mut [u64], chain_fn: &mut [u64]) {
    chain_va.fill(0);
    chain_fn.fill(0);
}

// --- Host mem helpers (registered as JIT symbols) ---

fn set_fault(ctx: &mut JitCtx, insn_ip: u64, addr: u64, size: u64, access: u64) {
    ctx.fault = 1;
    ctx.rip = insn_ip;
    ctx.fault_addr = addr;
    ctx.fault_size = size;
    ctx.fault_access = access;
}

/// Promote a mapped page into multi sticky (IR) + last-hit mirror + multi-way cache warm.
///
/// Sticky ways are **MRU-ordered**: way 0 is always the last hit so sequential
/// streams take one IR probe; thrash of ≤[`STICKY_WAYS`] pages stays in IR.
fn tlb_set_hot(ctx: &mut JitCtx, page_key: u64, page_base: *mut u8, prot: u8, generation: u64) {
    if ctx.tlb_hot_page != page_key && ctx.tlb_hot_page != TLB_EMPTY && !ctx.tlb_hot_ptr.is_null() {
        ctx.mem_path.sticky_swaps = ctx.mem_path.sticky_swaps.saturating_add(1);
    }
    // Last-hit mirror (helper + diagnostics).
    ctx.tlb_hot_page = page_key;
    ctx.tlb_hot_ptr = page_base;
    ctx.tlb_hot_prot = u64::from(prot);
    ctx.tlb_hot_gen = generation;

    // Find existing way (if any).
    let mut found = None;
    for w in 0..STICKY_WAYS {
        if ctx.sticky_page.get(w).copied() == Some(page_key) {
            found = Some(w);
            break;
        }
    }
    let prot_u = u64::from(prot);
    if let Some(0) = found {
        // Already MRU — refresh metadata only.
        if let Some(p) = ctx.sticky_ptr.get_mut(0) {
            *p = page_base;
        }
        if let Some(p) = ctx.sticky_prot.get_mut(0) {
            *p = prot_u;
        }
        if let Some(g) = ctx.sticky_gen.get_mut(0) {
            *g = generation;
        }
        return;
    }
    // Build new MRU list: [new, …previous without new…]
    let mut pages = [TLB_EMPTY; STICKY_WAYS];
    let mut ptrs = [std::ptr::null_mut(); STICKY_WAYS];
    let mut prots = [0_u64; STICKY_WAYS];
    let mut gens = [0_u64; STICKY_WAYS];
    pages[0] = page_key;
    ptrs[0] = page_base;
    prots[0] = prot_u;
    gens[0] = generation;
    let mut dst = 1_usize;
    for w in 0..STICKY_WAYS {
        if Some(w) == found {
            continue; // drop old slot; reinserted at 0
        }
        if dst >= STICKY_WAYS {
            break;
        }
        let pk = ctx.sticky_page.get(w).copied().unwrap_or(TLB_EMPTY);
        if pk == TLB_EMPTY {
            continue;
        }
        pages[dst] = pk;
        ptrs[dst] = ctx
            .sticky_ptr
            .get(w)
            .copied()
            .unwrap_or(std::ptr::null_mut());
        prots[dst] = ctx.sticky_prot.get(w).copied().unwrap_or(0);
        gens[dst] = ctx.sticky_gen.get(w).copied().unwrap_or(0);
        dst = dst.saturating_add(1);
    }
    ctx.sticky_page = pages;
    ctx.sticky_ptr = ptrs;
    ctx.sticky_prot = prots;
    ctx.sticky_gen = gens;
    // sticky_rr unused with MRU; keep field for ABI stability / future policy.
}

/// Classify guest VA against filled pins (diagnostic only).
///
/// Slot 0 = stack; slots 1.. = process heap + VirtualAlloc data pins.
fn classify_addr_vs_pins(ctx: &mut JitCtx, addr: u64, size: usize) {
    let end = addr.saturating_add(u64::try_from(size).unwrap_or(0));
    let mut in_stack = false;
    let mut in_data = false;
    for (i, pin) in ctx.pins.iter().enumerate() {
        if pin.host_base == 0 {
            continue;
        }
        if addr >= pin.guest_base && end <= pin.guest_end {
            if i == 0 {
                in_stack = true;
            } else {
                in_data = true;
            }
        }
    }
    if in_stack {
        ctx.mem_path.addr_in_stack_pin = ctx.mem_path.addr_in_stack_pin.saturating_add(1);
    } else if in_data {
        ctx.mem_path.addr_in_heap_pin = ctx.mem_path.addr_in_heap_pin.saturating_add(1);
    } else {
        ctx.mem_path.addr_outside_pins = ctx.mem_path.addr_outside_pins.saturating_add(1);
    }
}

/// Why multi sticky would miss (first failing predicate; exclusive buckets).
fn classify_sticky_miss(ctx: &mut JitCtx, page_key: u64, write: bool) {
    let cur_gen = ctx.mem_gen;
    let mut saw_key = false;
    let mut saw_gen = false;
    for w in 0..STICKY_WAYS {
        if ctx.sticky_page.get(w).copied() != Some(page_key) {
            continue;
        }
        saw_key = true;
        let host = ctx
            .sticky_ptr
            .get(w)
            .copied()
            .unwrap_or(std::ptr::null_mut());
        if host.is_null() {
            continue;
        }
        if ctx.sticky_gen.get(w).copied() != Some(cur_gen) {
            saw_gen = true;
            continue;
        }
        let prot = u8::try_from(ctx.sticky_prot.get(w).copied().unwrap_or(0)).unwrap_or(0);
        if !tlb_prot_allows(prot, write) {
            ctx.mem_path.sticky_miss_prot = ctx.mem_path.sticky_miss_prot.saturating_add(1);
            return;
        }
        // Would have hit — should not reach classify after a real sticky miss.
        return;
    }
    if saw_gen {
        ctx.mem_path.sticky_miss_gen = ctx.mem_path.sticky_miss_gen.saturating_add(1);
    } else {
        // No matching way (or null host) → key thrash / cold.
        let _ = saw_key;
        ctx.mem_path.sticky_miss_key = ctx.mem_path.sticky_miss_key.saturating_add(1);
    }
}

#[inline]
fn tlb_prot_allows(prot: u8, write: bool) -> bool {
    if write {
        (u64::from(prot) & TLB_PROT_W) != 0
    } else {
        (u64::from(prot) & TLB_PROT_R) != 0
    }
}

fn pack_tlb_prot(allow_r: bool, allow_w: bool) -> u8 {
    let mut p = 0_u8;
    if allow_r {
        p |= u8::try_from(TLB_PROT_R).unwrap_or(1);
    }
    if allow_w {
        p |= u8::try_from(TLB_PROT_W).unwrap_or(2);
    }
    p
}

/// Soft-translate via region pin when gen / bounds / R|W match (Phase 4.1).
///
/// On hit, also warms sticky + multi-way TLB so subsequent sticky IR can fire.
fn pin_resolve(ctx: &mut JitCtx, addr: u64, size: usize, write: bool) -> Option<*mut u8> {
    let size_u = u64::try_from(size).unwrap_or(0);
    if size_u == 0 {
        return None;
    }
    let end = addr.checked_add(size_u)?;
    let cur_gen = ctx.mem_gen;
    // Collect a matching pin by value so we can mutably update the TLB after.
    let mut matched: Option<(u64, u64, u64, u8)> = None; // guest_base, host_base, mem_gen, prot
    for pin in &ctx.pins {
        if pin.host_base == 0 || pin.mem_gen != cur_gen {
            continue;
        }
        if addr < pin.guest_base || end > pin.guest_end {
            continue;
        }
        let prot = u8::try_from(pin.allow).unwrap_or(0);
        if !tlb_prot_allows(prot, write) {
            continue;
        }
        matched = Some((pin.guest_base, pin.host_base, pin.mem_gen, prot));
        break;
    }
    let (guest_base, host_base, pin_gen, prot) = matched?;
    let off = usize::try_from(addr.wrapping_sub(guest_base)).unwrap_or(usize::MAX);
    if off == usize::MAX {
        return None;
    }
    // SAFETY: host_base is arena soft-translate base; bounds checked above.
    let host = unsafe { (host_base as *mut u8).add(off) };
    let page_off = usize::try_from(addr & (PAGE_SIZE - 1)).unwrap_or(0);
    let page_key = addr >> 12;
    // SAFETY: host points into the pin span; subtract in-page offset for page base.
    let page_base = unsafe { host.sub(page_off) };
    tlb_install(ctx, page_key, page_base, prot, pin_gen);
    tlb_set_hot(ctx, page_key, page_base, prot, pin_gen);
    Some(host)
}

/// Install a page into the set-associative TLB (RR victim within set).
fn tlb_install(ctx: &mut JitCtx, page_key: u64, page_base: *mut u8, prot: u8, generation: u64) {
    let set = tlb_set_index(page_key);
    let Some(bucket) = ctx.tlb_sets.get_mut(set) else {
        return;
    };
    let Some(aux) = ctx.tlb_aux.get_mut(set) else {
        return;
    };
    // Prefer empty / matching tag way.
    let mut way = None;
    for w in 0..TLB_WAYS_PER_SET {
        if bucket.tags.get(w).copied() == Some(page_key)
            || bucket.tags.get(w).copied() == Some(TLB_EMPTY)
        {
            way = Some(w);
            break;
        }
    }
    let way = way.unwrap_or_else(|| {
        let w = usize::from(aux.rr) & (TLB_WAYS_PER_SET - 1);
        aux.rr = aux.rr.wrapping_add(1);
        w
    });
    if let Some(t) = bucket.tags.get_mut(way) {
        *t = page_key;
    }
    if let Some(h) = bucket.host.get_mut(way) {
        *h = page_base;
    }
    if let Some(g) = aux.generation.get_mut(way) {
        *g = generation;
    }
    if let Some(p) = aux.prot.get_mut(way) {
        *p = prot;
    }
}

/// Scalar 4-way tag scan within a set.
fn tlb_bucket_lookup_scalar(
    bucket: &TlbBucket,
    aux: &TlbBucketAux,
    page_key: u64,
    write: bool,
    cur_gen: u64,
) -> Option<(*mut u8, u8)> {
    for way in 0..TLB_WAYS_PER_SET {
        if bucket.tags.get(way).copied() != Some(page_key) {
            continue;
        }
        let host = bucket
            .host
            .get(way)
            .copied()
            .unwrap_or(std::ptr::null_mut());
        if host.is_null() {
            continue;
        }
        if aux.generation.get(way).copied() != Some(cur_gen) {
            continue;
        }
        let prot = aux.prot.get(way).copied().unwrap_or(0);
        if !tlb_prot_allows(prot, write) {
            continue;
        }
        return Some((host, prot));
    }
    None
}

/// Neon / portable vector tag compare for one 4-way bucket.
fn tlb_bucket_lookup(
    bucket: &TlbBucket,
    aux: &TlbBucketAux,
    page_key: u64,
    write: bool,
    cur_gen: u64,
) -> Option<(*mut u8, u8)> {
    if !tlb_neon_enabled() {
        return tlb_bucket_lookup_scalar(bucket, aux, page_key, write, cur_gen);
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: `TlbBucket` is `align(16)`; tags are 4×u64 contiguous.
        let bits = unsafe { tlb_neon_tag_mask(bucket.tags.as_ptr(), page_key) };
        if bits == 0 {
            return None;
        }
        // First matching way (branchless prefer low index).
        let way = bits.trailing_zeros() as usize;
        if way >= TLB_WAYS_PER_SET {
            return None;
        }
        let host = bucket
            .host
            .get(way)
            .copied()
            .unwrap_or(std::ptr::null_mut());
        if host.is_null() {
            return None;
        }
        if aux.generation.get(way).copied() != Some(cur_gen) {
            return None;
        }
        let prot = aux.prot.get(way).copied().unwrap_or(0);
        if !tlb_prot_allows(prot, write) {
            return None;
        }
        Some((host, prot))
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        tlb_bucket_lookup_scalar(bucket, aux, page_key, write, cur_gen)
    }
}

/// Compare 4 tags against `page_key` with two Neon `cmeq` ops; return way bitmask 0..15.
///
/// # Safety
/// `tags` must point to at least 4 `u64` values, 16-byte aligned.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn tlb_neon_tag_mask(tags: *const u64, page_key: u64) -> u32 {
    use std::arch::aarch64::{vceqq_u64, vdupq_n_u64, vld1q_u64};
    // SAFETY: caller guarantees align + length; neon enabled on Apple Silicon.
    unsafe {
        let t01 = vld1q_u64(tags);
        let t23 = vld1q_u64(tags.add(2));
        let key = vdupq_n_u64(page_key);
        let m01 = vceqq_u64(t01, key);
        let m23 = vceqq_u64(t23, key);
        lane_eq_bit(m01, 0)
            | (lane_eq_bit(m01, 1) << 1)
            | (lane_eq_bit(m23, 0) << 2)
            | (lane_eq_bit(m23, 1) << 3)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn lane_eq_bit(v: std::arch::aarch64::uint64x2_t, lane: usize) -> u32 {
    // vceqq lanes are all-ones or zero; extract via transmute to [u64; 2].
    // SAFETY: uint64x2_t is a 16-byte SIMD register; layout matches [u64; 2].
    let arr: [u64; 2] = unsafe { std::mem::transmute(v) };
    u32::from(arr.get(lane).copied().unwrap_or(0) != 0)
}

/// Resolve host page pointer via multi-way TLB (single-page accesses only).
///
/// Enforces software R/W bits and memory generation on every hit. Misses that
/// lack the required permission return `None` so the slow path can set a fault
/// via [`GuestMemory::read`] / [`GuestMemory::write`] (SPC oracle).
///
/// Updates [`JitCtx::mem_path`] counters: sticky IR already missed (caller is
/// the host helper), so each call is one helper invocation to classify.
unsafe fn tlb_page_ptr(ctx: &mut JitCtx, addr: u64, size: usize, write: bool) -> Option<*mut u8> {
    classify_addr_vs_pins(ctx, addr, size);
    let page_off = usize::try_from(addr & (PAGE_SIZE - 1)).unwrap_or(0);
    let page_cap = usize::try_from(PAGE_SIZE).unwrap_or(0x1000);
    if page_off.saturating_add(size) > page_cap {
        ctx.mem_path.cross_page = ctx.mem_path.cross_page.saturating_add(1);
        return None; // cross-page → slow path
    }
    let page_key = addr >> 12; // PAGE_SIZE = 0x1000
    let cur_gen = ctx.mem_gen;
    // Multi sticky hit first (matches inline IR fast path).
    for w in 0..STICKY_WAYS {
        if ctx.sticky_page.get(w).copied() != Some(page_key) {
            continue;
        }
        let host = ctx
            .sticky_ptr
            .get(w)
            .copied()
            .unwrap_or(std::ptr::null_mut());
        if host.is_null() {
            continue;
        }
        if ctx.sticky_gen.get(w).copied() != Some(cur_gen) {
            continue;
        }
        let prot = u8::try_from(ctx.sticky_prot.get(w).copied().unwrap_or(0)).unwrap_or(0);
        if !tlb_prot_allows(prot, write) {
            continue;
        }
        ctx.mem_path.sticky_hit = ctx.mem_path.sticky_hit.saturating_add(1);
        // Keep last-hit mirror coherent with the way that hit.
        ctx.tlb_hot_page = page_key;
        ctx.tlb_hot_ptr = host;
        ctx.tlb_hot_prot = u64::from(prot);
        ctx.tlb_hot_gen = cur_gen;
        // SAFETY: sticky ptr is a mapped page base; access stays in-page; SPC bits match.
        return Some(unsafe { host.add(page_off) });
    }
    classify_sticky_miss(ctx, page_key, write);
    let set = tlb_set_index(page_key);
    let hit = ctx
        .tlb_sets
        .get(set)
        .zip(ctx.tlb_aux.get(set))
        .and_then(|(bucket, aux)| tlb_bucket_lookup(bucket, aux, page_key, write, cur_gen));
    if let Some((page_base, prot)) = hit {
        ctx.mem_path.multi_hit = ctx.mem_path.multi_hit.saturating_add(1);
        tlb_set_hot(ctx, page_key, page_base, prot, cur_gen);
        // SAFETY: page mapped; access stays within the page.
        return Some(unsafe { page_base.add(page_off) });
    }
    // Region-direct pin (stack/heap arenas) before radix/page walk.
    if let Some(p) = pin_resolve(ctx, addr, size, write) {
        ctx.mem_path.pin_hit = ctx.mem_path.pin_hit.saturating_add(1);
        return Some(p);
    }
    // Miss: resolve via GuestMemory (committed + protect meta + host ptr).
    // SAFETY: `mem` set by `run_compiled` to the live guest map.
    let mem = unsafe { &*ctx.mem };
    let Some(entry) = mem
        .page_tlb_entry_walk(page_key)
        .or_else(|| mem.page_tlb_entry(page_key))
    else {
        ctx.mem_path.slow = ctx.mem_path.slow.saturating_add(1);
        return None;
    };
    // Install even if this access is denied so a later opposite access can hit;
    // but only return a pointer when the *current* access is allowed.
    let prot = pack_tlb_prot(entry.allow_r, entry.allow_w);
    tlb_install(ctx, page_key, entry.host, prot, entry.generation);
    tlb_set_hot(ctx, page_key, entry.host, prot, entry.generation);
    if !tlb_prot_allows(prot, write) {
        ctx.mem_path.slow = ctx.mem_path.slow.saturating_add(1);
        return None;
    }
    ctx.mem_path.walk_hit = ctx.mem_path.walk_hit.saturating_add(1);
    // SAFETY: page mapped; access stays within the page; permission checked.
    Some(unsafe { entry.host.add(page_off) })
}

/// Soft-translate a contiguous guest span to a host pointer (0 on failure).
///
/// Used by inline string fast-path; never returns a guest VA.
pub(super) unsafe extern "C" fn wie_jit_host_span(
    ctx: *mut JitCtx,
    guest_va: u64,
    len: u64,
    write: u64,
) -> u64 {
    if ctx.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: live JitCtx for the block.
    let ctx = unsafe { &mut *ctx };
    if ctx.fault != 0 {
        return 0;
    }
    let len_usize = usize::try_from(len).unwrap_or(0);
    if len_usize == 0 {
        return 0;
    }
    // SAFETY: mem pointer set by run_compiled.
    let mem = unsafe { &*ctx.mem };
    match mem.host_span(guest_va, len_usize, write != 0) {
        Some(p) if !p.is_null() => p as u64,
        _ => 0,
    }
}

/// Lookup host block pointer for `va` (0 = miss). Used for late-bound chaining.
///
/// Checks monomorphic edge IC first (Phase 4.2), then the open-addressing chain
/// table. On a table hit, installs into an edge-IC slot for the next transfer.
///
/// `extern "C" fn(ctx, va) -> fn_ptr`
pub(super) unsafe extern "C" fn wie_jit_chain_lookup(ctx: *mut JitCtx, va: u64) -> u64 {
    if va == 0 || ctx.is_null() {
        return 0;
    }
    // SAFETY: `run_compiled` sets chain_* to live tables for the block duration.
    let ctx = unsafe { &mut *ctx };
    // Edge IC (data plane): monomorphic last-hit successors.
    for i in 0..EDGE_IC_SLOTS {
        if ctx.edge_ic_va[i] == va {
            let f = ctx.edge_ic_fn[i];
            if f != 0 {
                return f;
            }
        }
    }
    if ctx.chain_va.is_null() || ctx.chain_fn.is_null() {
        return 0;
    }
    // SAFETY: tables are `CHAIN_SLOTS` long and live for this call.
    let keys = unsafe { std::slice::from_raw_parts(ctx.chain_va, CHAIN_SLOTS) };
    let fns = unsafe { std::slice::from_raw_parts(ctx.chain_fn, CHAIN_SLOTS) };
    let mut i = chain_hash(va);
    // Bounded probe; empty slot ends search.
    for _ in 0..16 {
        let k = keys[i];
        if k == va {
            let f = fns[i];
            if f != 0 {
                // Install monomorphic edge IC (RR victim).
                let slot =
                    usize::try_from(ctx.edge_ic_rr % u64::try_from(EDGE_IC_SLOTS).unwrap_or(4))
                        .unwrap_or(0);
                ctx.edge_ic_va[slot] = va;
                ctx.edge_ic_fn[slot] = f;
                ctx.edge_ic_rr = ctx.edge_ic_rr.wrapping_add(1);
            }
            return f;
        }
        if k == 0 {
            return 0;
        }
        i = (i + 1) & (CHAIN_SLOTS - 1);
    }
    0
}

/// `extern "C" fn(ctx, addr, size, insn_ip) -> value`
pub(super) unsafe extern "C" fn wie_jit_load(
    ctx: *mut JitCtx,
    addr: u64,
    size: u64,
    insn_ip: u64,
) -> u64 {
    // SAFETY: caller passes a live `JitCtx` for the duration of the block.
    let ctx = unsafe { &mut *ctx };
    ctx.load_calls = ctx.load_calls.saturating_add(1);
    if ctx.fault != 0 {
        return 0;
    }
    let size_usize = usize::try_from(size).unwrap_or(0);
    if size_usize == 0 || size_usize > 8 {
        set_fault(ctx, insn_ip, addr, size, 0);
        return 0;
    }
    // Fast path: single-page TLB with SPC R bit + generation.
    // SAFETY: TLB pointer is a live page from guest map for this block.
    if let Some(p) = unsafe { tlb_page_ptr(ctx, addr, size_usize, false) } {
        let mut buf = [0_u8; 8];
        // SAFETY: `p` points into a mapped page with `size_usize` bytes in range.
        unsafe {
            std::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), size_usize);
        }
        return match size_usize {
            1 => u64::from(buf[0]),
            2 => u64::from(u16::from_le_bytes([buf[0], buf[1]])),
            4 => u64::from(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
            8 => u64::from_le_bytes(buf),
            _ => 0,
        };
    }
    // Slow path: multi-page, miss, or SPC deny on TLB.
    // SAFETY: `mem` set by `run_compiled`.
    let mem = unsafe { &*ctx.mem };
    let mut buf = [0_u8; 8];
    if mem.read(addr, &mut buf[..size_usize]).is_err() {
        set_fault(ctx, insn_ip, addr, size, 0);
        return 0;
    }
    match size_usize {
        1 => u64::from(buf[0]),
        2 => u64::from(u16::from_le_bytes([buf[0], buf[1]])),
        4 => u64::from(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
        8 => u64::from_le_bytes(buf),
        _ => 0,
    }
}

/// `extern "C" fn(ctx, addr, size, value, insn_ip)`
pub(super) unsafe extern "C" fn wie_jit_store(
    ctx: *mut JitCtx,
    addr: u64,
    size: u64,
    value: u64,
    insn_ip: u64,
) {
    // SAFETY: caller passes a live `JitCtx` for the duration of the block.
    let ctx = unsafe { &mut *ctx };
    ctx.store_calls = ctx.store_calls.saturating_add(1);
    if ctx.fault != 0 {
        return;
    }
    let size_usize = usize::try_from(size).unwrap_or(0);
    if size_usize == 0 || size_usize > 8 {
        set_fault(ctx, insn_ip, addr, size, 1);
        return;
    }
    let bytes = value.to_le_bytes();
    // SAFETY: TLB pointer is a live page from guest map; W bit checked.
    if let Some(p) = unsafe { tlb_page_ptr(ctx, addr, size_usize, true) } {
        // SAFETY: `p` points into a mapped page with `size_usize` bytes in range.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, size_usize);
        }
        return;
    }
    // SAFETY: `mem` set by `run_compiled`.
    let mem = unsafe { &*ctx.mem };
    if mem.write(addr, &bytes[..size_usize]).is_err() {
        set_fault(ctx, insn_ip, addr, size, 1);
    }
}

/// Bulk string helper: `(ctx, op, size, flags, insn_ip) -> stay`.
///
/// `op`: 0=stos 1=movs 2=lods 3=scas 4=cmps
/// `flags`: bit0=rep, bit1=repe, bit2=repne
/// Returns 1 if RIP should stay on `insn_ip`, 0 to fall through (caller uses next_ip).
pub(super) unsafe extern "C" fn wie_jit_string(
    ctx: *mut JitCtx,
    op: u64,
    size: u64,
    flags: u64,
    insn_ip: u64,
) -> u64 {
    // SAFETY: live JitCtx for the block.
    let ctx = unsafe { &mut *ctx };
    if ctx.fault != 0 {
        return 0;
    }
    let size_usize = usize::try_from(size).unwrap_or(0);
    if !matches!(size_usize, 1 | 2 | 4 | 8) {
        set_fault(ctx, insn_ip, 0, size, 0);
        return 0;
    }
    let kind = match op {
        0 => StringOpKind::Stos,
        1 => StringOpKind::Movs,
        2 => StringOpKind::Lods,
        3 => StringOpKind::Scas,
        4 => StringOpKind::Cmps,
        _ => {
            set_fault(ctx, insn_ip, 0, size, 0);
            return 0;
        }
    };
    let rep = (flags & 1) != 0;
    let repe = (flags & 2) != 0;
    let repne = (flags & 4) != 0;

    let mut regs = RegFile::new();
    for i in 0..16 {
        regs.set_gpr(i, ctx.gpr[i]);
    }
    regs.rflags = ctx.rflags;
    regs.rip = insn_ip;

    // SAFETY: mem pointer set by run_compiled.
    let mem = unsafe { &*ctx.mem };
    match exec::run_string_op(mem, &mut regs, kind, size_usize, rep, repe, repne) {
        Ok(stay) => {
            for i in 0..16 {
                ctx.gpr[i] = regs.gpr(i);
            }
            ctx.rflags = regs.rflags;
            u64::from(stay)
        }
        Err(exec::StepExecError::InvalidMemory(inv)) => {
            for i in 0..16 {
                ctx.gpr[i] = regs.gpr(i);
            }
            ctx.rflags = regs.rflags;
            set_fault(
                ctx,
                insn_ip,
                inv.address,
                u64::try_from(inv.size).unwrap_or(0),
                u64::try_from(inv.access_type).unwrap_or(0),
            );
            0
        }
        Err(exec::StepExecError::Cpu(_)) => {
            set_fault(ctx, insn_ip, 0, size, 0);
            0
        }
    }
}

/// Scalar f32 binop: `op` 0=add 1=sub 2=mul 3=div; args/result in low 32 bits.
pub(super) extern "C" fn wie_f32_binop(op: u64, a: u64, b: u64) -> u64 {
    let fa = f32::from_bits(a as u32);
    let fb = f32::from_bits(b as u32);
    let r = match op {
        0 => fa + fb,
        1 => fa - fb,
        2 => fa * fb,
        3 => fa / fb,
        _ => fa,
    };
    u64::from(r.to_bits())
}

/// Scalar f64 binop: `op` 0=add 1=sub 2=mul 3=div.
pub(super) extern "C" fn wie_f64_binop(op: u64, a: u64, b: u64) -> u64 {
    let fa = f64::from_bits(a);
    let fb = f64::from_bits(b);
    let r = match op {
        0 => fa + fb,
        1 => fa - fb,
        2 => fa * fb,
        3 => fa / fb,
        _ => fa,
    };
    r.to_bits()
}

pub(super) fn compile_block(
    eng: &mut JitEngine,
    start_rip: u64,
    insns: &[DecodedInsn],
    end_rip: u64,
    term: Option<BlockTerm>,
    call_fast: Option<FastApiKind>,
    chain: &HashMap<u64, FuncId>,
    bytes_len: u32,
) -> Result<CompiledBlock, String> {
    let live = analyze_live_gprs(insns);
    let live_xmm = analyze_live_xmm(insns);
    let def_xmm = analyze_def_xmm(insns);
    let xmm_live_mask = xmm_mask_from(&live_xmm);
    let xmm_may_def_mask = xmm_mask_from(&def_xmm);
    let needs_flags = block_needs_flags(insns, term);
    let has_fast_call = call_fast.is_some();
    let has_mem = block_has_mem(insns)
        || matches!(term, Some(BlockTerm::Call { .. } | BlockTerm::Ret))
        || has_fast_call;
    let has_sse = live_xmm.iter().any(|&x| x);
    let has_string = block_has_string(insns);
    let has_fp = block_has_fp(insns);
    let need_fp_helpers = has_fp && !jit_simd_enabled();
    let need_host_span = has_string && string_inline_enabled();

    // Self-loop if jcc/jmp targets this block's entry (stay in native code).
    let self_loop = match term {
        Some(BlockTerm::Jmp { target }) if target == start_rip => true,
        Some(BlockTerm::Jcc {
            taken, not_taken, ..
        }) if taken == start_rip || not_taken == start_rip => true,
        _ => false,
    };

    let body: &[DecodedInsn];
    let term_insn: Option<&DecodedInsn>;
    if term.is_some() {
        let (t, b) = insns
            .split_last()
            .ok_or_else(|| "empty block with term".to_string())?;
        body = b;
        term_insn = Some(t);
    } else {
        body = insns;
        term_insn = None;
    }

    let name_id = eng.next_name;
    eng.next_name = eng.next_name.saturating_add(1);
    let name = format!("b{name_id}");

    let func_id = eng
        .module
        .declare_function(&name, Linkage::Local, &eng.block_sig)
        .map_err(|e| e.to_string())?;

    eng.ctx.func.signature = eng.block_sig.clone();
    eng.ctx.func.name = UserFuncName::user(0, func_id.as_u32());

    {
        let mut bcx = FunctionBuilder::new(&mut eng.ctx.func, &mut eng.func_ctx);
        let entry = bcx.create_block();
        bcx.append_block_params_for_function_params(entry);
        bcx.switch_to_block(entry);
        // Cranelift forbids CFG edges into the function entry block (remove_constant_phis
        // asserts `edge.block != entry_block`). Self-loops therefore re-enter a dedicated
        // header block, never `entry`.
        bcx.seal_block(entry);

        let ctx_ptr = bcx.block_params(entry)[0];
        let flags = MemFlagsData::trusted();

        // Exit: gpr[16] + rflags as block params → store and return.
        // XMM is write-through to JitCtx (correct on mid-block mem faults).
        let exit = bcx.create_block();
        for _ in 0..16 {
            bcx.append_block_param(exit, types::I64);
        }
        bcx.append_block_param(exit, types::I64);

        // Host ABI signature for `call_indirect` late-bound chaining.
        let block_sig_ref: SigRef = bcx.import_signature(eng.block_sig.clone());

        let load_ref = if has_mem || has_sse {
            Some(eng.module.declare_func_in_func(eng.load_id, bcx.func))
        } else {
            None
        };
        let store_ref = if has_mem || has_sse {
            Some(eng.module.declare_func_in_func(eng.store_id, bcx.func))
        } else {
            None
        };
        let string_ref = if has_string {
            Some(eng.module.declare_func_in_func(eng.string_id, bcx.func))
        } else {
            None
        };
        let host_span_ref = if need_host_span {
            Some(eng.module.declare_func_in_func(eng.host_span_id, bcx.func))
        } else {
            None
        };
        let f32_ref = if need_fp_helpers {
            Some(eng.module.declare_func_in_func(eng.f32_id, bcx.func))
        } else {
            None
        };
        let f64_ref = if need_fp_helpers {
            Some(eng.module.declare_func_in_func(eng.f64_id, bcx.func))
        } else {
            None
        };
        // Dynamic chain lookup (late-bound successors + ret targets).
        let lookup_ref = eng.module.declare_func_in_func(eng.lookup_id, bcx.func);

        // Declare UCRT imports used by this block.
        let mut ucrt_refs: [Option<FuncRef>; 7] = [None; 7];
        if let Some(kind) = call_fast {
            let id = eng.ucrt.for_kind(kind);
            ucrt_refs[kind as usize] = Some(eng.module.declare_func_in_func(id, bcx.func));
        }
        // Chain successors (already compiled blocks) — direct call when known.
        let mut chain_refs: HashMap<u64, FuncRef> = HashMap::new();
        if let Some(t) = term {
            for va in term_chain_targets(t) {
                if va == start_rip {
                    continue; // self-loop uses IR jump
                }
                if let Some(&fid) = chain.get(&va) {
                    chain_refs.insert(va, eng.module.declare_func_in_func(fid, bcx.func));
                }
            }
            // Also pre-declare return_ip for Call (common after callee returns).
            if let BlockTerm::Call { return_ip, .. } = t
                && return_ip != start_rip
                && let Some(&fid) = chain.get(&return_ip)
            {
                chain_refs.insert(return_ip, eng.module.declare_func_in_func(fid, bcx.func));
            }
        }
        // Fallthrough chain.
        if term.is_none()
            && let Some(&fid) = chain.get(&end_rip)
        {
            chain_refs.insert(end_rip, eng.module.declare_func_in_func(fid, bcx.func));
        }

        // Live GPRs: only load what the block uses. Self-loops keep a full set in
        // block params so back-edges pass SSA values (no JitCtx store/reload).
        let mut live_eff = live;
        if has_fast_call {
            live_eff[0] = true; // RAX result
            live_eff[1] = true; // RCX
            live_eff[2] = true; // RDX
            live_eff[8] = true; // R8
            live_eff[9] = true; // R9
        }
        if self_loop {
            live_eff.fill(true);
        }

        let mut gpr_vals = [bcx.ins().iconst(types::I64, 0); 16];
        let mut gpr_loaded = [false; 16];
        // Dirty = written this block; only dirty+loaded regs are flushed to JitCtx
        // on chain/exit (reg-mapping: avoid storing read-only live-ins).
        let mut gpr_dirty = [false; 16];
        let rflags_ptr = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_RFLAGS));
        // Carry flags across self-loop iterations via a block param when needed.
        let pass_flags = needs_flags || self_loop;

        // Hoist pin descriptors on the **entry** block (once per run_compiled).
        // Slot 0 = stack. Slots 1.. = size-ranked data (heap + VirtualAlloc).
        // Data-pin IR is opt-in via `WIE_JIT_MEM=pin` (see hoist below). Default
        // sticky keeps stack + sticky only; helpers still `pin_resolve` all 8
        // slots (VA/heaps) so walks collapse without IR cascade tax on 7za.
        // Set `WIE_JIT_MEM=pin` to also probe top-2 data pins after sticky.
        let (stack_pin, data_pins) = if super::jit_mem_inline_enabled() {
            let stack = Some(hoist_pin_slot(&mut bcx, ctx_ptr, flags, 0));
            // Default sticky: no data-pin IR (helpers cover VA via pin_resolve).
            // `WIE_JIT_MEM=pin`: top-2 size-ranked data pins after sticky.
            let mut data = Vec::new();
            if super::jit_mem_pin_enabled() {
                const IR_DATA_PIN_SLOTS: usize = 2;
                let end = 1_usize.saturating_add(IR_DATA_PIN_SLOTS).min(PIN_SLOTS);
                data.reserve(IR_DATA_PIN_SLOTS);
                for slot in 1..end {
                    data.push(hoist_pin_slot(&mut bcx, ctx_ptr, flags, slot));
                }
            }
            (stack, data)
        } else {
            (None, Vec::new())
        };

        // Pre-compile scan: displacement range for block-wide stack pin guard.
        let stack_plan = if super::jit_mem_inline_enabled() {
            analyze_block_stack_pin(body, term_insn)
        } else {
            None
        };
        // Base register must be live for the guard even if not otherwise used.
        if let Some(p) = stack_plan {
            live_eff[p.base_idx] = true;
        }

        // Entry: load GPRs / flags once (shared by super and normal paths).
        let mut entry_gpr = [bcx.ins().iconst(types::I64, 0); 16];
        let mut entry_loaded = [false; 16];
        for i in 0..16 {
            if live_eff[i] {
                let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
                let p = bcx.ins().iadd_imm(ctx_ptr, off);
                entry_gpr[i] = bcx.ins().load(types::I64, flags, p, 0);
                entry_loaded[i] = true;
            }
        }
        let entry_rflags = if pass_flags {
            bcx.ins().load(types::I64, flags, rflags_ptr, 0)
        } else {
            bcx.ins().iconst(types::I64, 0)
        };

        // Dual path when the block is stack-pin-shaped: super (bare host mem) vs
        // normal (sticky/pin probes). One block-wide guard on entry.
        // Default `WIE_JIT_SUPER` = self-loops only; `=all` opt-in; `=0` off.
        let dual_super = stack_plan.is_some()
            && stack_pin.is_some()
            && !has_string
            && call_fast.is_none()
            && super::jit_super_enabled(self_loop);

        let mut headers_to_seal: Vec<Block> = Vec::new();
        // Tracks gpr_loaded for the exit store mask (union of paths; full when dual).
        let mut exit_gpr_loaded = entry_loaded;

        if dual_super && let (Some(plan), Some(spin)) = (stack_plan, stack_pin) {
            let base = entry_gpr[plan.base_idx];
            let guard = emit_block_wide_stack_guard(&mut bcx, &spin, base, &plan);
            let bias = bcx.ins().isub(spin.host_base, spin.guest_base);

            let super_blk = bcx.create_block();
            let normal_blk = bcx.create_block();
            bcx.ins().brif(guard, super_blk, &[], normal_blk, &[]);

            for (is_super, start_blk) in [(true, super_blk), (false, normal_blk)] {
                bcx.switch_to_block(start_blk);
                bcx.seal_block(start_blk);

                let mut path_gpr = entry_gpr;
                let mut path_loaded = entry_loaded;
                let mut path_dirty = [false; 16];
                let mut path_rflags = entry_rflags;

                let loop_header = if self_loop {
                    let h = bcx.create_block();
                    for &is_live in live_eff.iter().take(16) {
                        if is_live {
                            bcx.append_block_param(h, types::I64);
                        }
                    }
                    if pass_flags {
                        bcx.append_block_param(h, types::I64);
                    }
                    let mut args: Vec<BlockArg> = Vec::with_capacity(17);
                    for i in 0..16 {
                        if live_eff[i] {
                            args.push(BlockArg::Value(path_gpr[i]));
                        }
                    }
                    if pass_flags {
                        args.push(BlockArg::Value(path_rflags));
                    }
                    bcx.ins().jump(h, &args);
                    bcx.switch_to_block(h);
                    let params = bcx.block_params(h);
                    let mut pi = 0_usize;
                    for i in 0..16 {
                        if live_eff[i] {
                            path_gpr[i] = params[pi];
                            path_loaded[i] = true;
                            pi = pi.saturating_add(1);
                        }
                    }
                    if pass_flags {
                        path_rflags = params[params.len() - 1];
                    }
                    headers_to_seal.push(h);
                    h
                } else {
                    start_blk
                };

                let mut xmm_vals = [bcx.ins().iconst(types::I64, 0); 32];
                let mut xmm_loaded = [false; 16];
                for (i, &is_live) in live_xmm.iter().enumerate() {
                    if is_live {
                        load_xmm_pair(&mut bcx, ctx_ptr, flags, i, &mut xmm_vals, &mut xmm_loaded);
                    }
                }

                let mut mem_env = MemEnv {
                    ctx_ptr,
                    load_ref,
                    store_ref,
                    string_ref,
                    host_span_ref,
                    f32_ref,
                    f64_ref,
                    flags,
                    exit,
                    ucrt_refs,
                    // Super path: no per-access probes. Normal: hoisted pins.
                    stack_pin: if is_super { None } else { Some(spin) },
                    data_pins: if is_super {
                        Vec::new()
                    } else {
                        data_pins.clone()
                    },
                    super_stack: if is_super {
                        Some(SuperStack { bias })
                    } else {
                        None
                    },
                };

                emit_body_and_term(
                    &mut bcx,
                    body,
                    term,
                    term_insn,
                    call_fast,
                    start_rip,
                    end_rip,
                    self_loop,
                    loop_header,
                    &live_eff,
                    pass_flags,
                    needs_flags,
                    ctx_ptr,
                    flags,
                    rflags_ptr,
                    exit,
                    &chain_refs,
                    lookup_ref,
                    block_sig_ref,
                    &mut path_gpr,
                    &mut path_loaded,
                    &mut path_dirty,
                    &mut path_rflags,
                    &mut xmm_vals,
                    &mut xmm_loaded,
                    &mut mem_env,
                )?;
                for i in 0..16 {
                    exit_gpr_loaded[i] |= path_loaded[i];
                }
            }
        } else {
            // Single path (no block-wide super, or ineligible shape).
            let loop_header = if self_loop {
                let h = bcx.create_block();
                for &is_live in live_eff.iter().take(16) {
                    if is_live {
                        bcx.append_block_param(h, types::I64);
                    }
                }
                if pass_flags {
                    bcx.append_block_param(h, types::I64);
                }
                let mut entry_args: Vec<BlockArg> = Vec::with_capacity(17);
                for i in 0..16 {
                    if live_eff[i] {
                        entry_args.push(BlockArg::Value(entry_gpr[i]));
                        gpr_vals[i] = entry_gpr[i];
                        gpr_loaded[i] = true;
                    }
                }
                if pass_flags {
                    entry_args.push(BlockArg::Value(entry_rflags));
                }
                bcx.ins().jump(h, &entry_args);
                bcx.switch_to_block(h);
                let params = bcx.block_params(h);
                let mut pi = 0_usize;
                for i in 0..16 {
                    if live_eff[i] {
                        gpr_vals[i] = params[pi];
                        gpr_loaded[i] = true;
                        pi = pi.saturating_add(1);
                    }
                }
                headers_to_seal.push(h);
                h
            } else {
                for i in 0..16 {
                    if entry_loaded[i] {
                        gpr_vals[i] = entry_gpr[i];
                        gpr_loaded[i] = true;
                    }
                }
                entry
            };

            let mut xmm_vals = [bcx.ins().iconst(types::I64, 0); 32];
            let mut xmm_loaded = [false; 16];
            for (i, &is_live) in live_xmm.iter().enumerate() {
                if is_live {
                    load_xmm_pair(&mut bcx, ctx_ptr, flags, i, &mut xmm_vals, &mut xmm_loaded);
                }
            }

            let mut rflags_val = if self_loop && pass_flags {
                let params = bcx.block_params(loop_header);
                params[params.len() - 1]
            } else if needs_flags {
                entry_rflags
            } else {
                bcx.ins().iconst(types::I64, 0)
            };

            let mut mem_env = MemEnv {
                ctx_ptr,
                load_ref,
                store_ref,
                string_ref,
                host_span_ref,
                f32_ref,
                f64_ref,
                flags,
                exit,
                ucrt_refs,
                stack_pin,
                data_pins,
                super_stack: None,
            };

            emit_body_and_term(
                &mut bcx,
                body,
                term,
                term_insn,
                call_fast,
                start_rip,
                end_rip,
                self_loop,
                loop_header,
                &live_eff,
                pass_flags,
                needs_flags,
                ctx_ptr,
                flags,
                rflags_ptr,
                exit,
                &chain_refs,
                lookup_ref,
                block_sig_ref,
                &mut gpr_vals,
                &mut gpr_loaded,
                &mut gpr_dirty,
                &mut rflags_val,
                &mut xmm_vals,
                &mut xmm_loaded,
                &mut mem_env,
            )?;
            exit_gpr_loaded = gpr_loaded;
        }

        bcx.switch_to_block(exit);
        bcx.seal_block(exit);
        let (exit_gpr, exit_rflags) = {
            let exit_params = bcx.block_params(exit);
            let mut g = [exit_params[0]; 16];
            g.copy_from_slice(&exit_params[..16]);
            (g, exit_params[16])
        };
        for i in 0..16 {
            // Fault/exit path: store only GPRs that were actually loaded/defined.
            // Self-loops load the full set at entry (`live_eff.fill(true)`).
            //
            // Important: do **not** force all-16 stores for dual_super. Non-loop
            // super blocks only load live-ins; unloaded slots are SSA `iconst 0`.
            // Writing them back zeroed callee-saved regs (R12–R15, RBX, RBP, …)
            // and corrupted guests such as 7za (`i` → null base → VA 0x1000).
            if exit_gpr_loaded[i] || self_loop {
                let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
                let p = bcx.ins().iadd_imm(ctx_ptr, off);
                bcx.ins().store(flags, exit_gpr[i], p, 0);
            }
        }
        if needs_flags || self_loop {
            bcx.ins().store(flags, exit_rflags, rflags_ptr, 0);
        }
        bcx.ins().return_(&[]);
        for h in headers_to_seal {
            bcx.seal_block(h);
        }
        bcx.seal_all_blocks();
        bcx.finalize();
    }

    eng.module
        .define_function(func_id, &mut eng.ctx)
        .map_err(|e| e.to_string())?;
    eng.module.clear_context(&mut eng.ctx);
    eng.module
        .finalize_definitions()
        .map_err(|e| e.to_string())?;

    let code = eng.module.get_finalized_function(func_id);
    let func = unsafe { std::mem::transmute::<*const u8, unsafe extern "C" fn(*mut JitCtx)>(code) };

    let guest_end = start_rip.saturating_add(u64::from(bytes_len));
    Ok(CompiledBlock {
        func,
        func_id: Some(func_id),
        insn_count: u32::try_from(insns.len()).unwrap_or(0),
        uses_sse: has_sse || has_fp,
        xmm_live_mask,
        xmm_may_def_mask,
        guest_start: start_rip,
        guest_end,
    })
}

fn term_chain_targets(t: BlockTerm) -> Vec<u64> {
    match t {
        BlockTerm::Jmp { target } | BlockTerm::Call { target, .. } => vec![target],
        BlockTerm::Jcc {
            taken, not_taken, ..
        } => vec![taken, not_taken],
        BlockTerm::Ret => vec![],
    }
}

/// Write SSA GPRs back into `JitCtx`.
///
/// When `gpr_dirty` is `Some`, only dirty+loaded regs are stored (reg-mapping opt).
/// When `None`, every loaded reg is stored (safe default for host helpers / unknown).
fn writeback_gprs(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    gpr: &[Value; 16],
    gpr_loaded: &[bool; 16],
    gpr_dirty: Option<&[bool; 16]>,
    rflags: Value,
    rflags_ptr: Value,
    store_flags: bool,
) {
    for i in 0..16 {
        let do_store = match gpr_dirty {
            Some(d) => d[i] && gpr_loaded[i],
            None => gpr_loaded[i],
        };
        if do_store {
            let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
            let p = bcx.ins().iadd_imm(ctx_ptr, off);
            bcx.ins().store(flags, gpr[i], p, 0);
        }
    }
    if store_flags {
        bcx.ins().store(flags, rflags, rflags_ptr, 0);
    }
}

/// Build block-param args for a self-loop header: live GPRs + optional rflags.
fn loop_header_args(
    gpr: &[Value; 16],
    live: &[bool; 16],
    rflags: Value,
    pass_flags: bool,
) -> Vec<BlockArg> {
    let mut args = Vec::with_capacity(17);
    for i in 0..16 {
        if live[i] {
            args.push(BlockArg::Value(gpr[i]));
        }
    }
    if pass_flags {
        args.push(BlockArg::Value(rflags));
    }
    args
}

/// Push guest `return_ip` onto the software shadow return stack.
fn shadow_push(bcx: &mut FunctionBuilder<'_>, ctx_ptr: Value, flags: MemFlagsData, return_ip: u64) {
    let sp_ptr = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_SHADOW_SP));
    let sp = bcx.ins().load(types::I64, flags, sp_ptr, 0);
    let mask = iconst_u64(bcx, (SHADOW_DEPTH as u64) - 1);
    let idx = bcx.ins().band(sp, mask);
    let base = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_SHADOW_RET));
    let three = iconst_u64(bcx, 3);
    let off = bcx.ins().ishl(idx, three); // * sizeof(u64)
    let slot = bcx.ins().iadd(base, off);
    let retv = iconst_u64(bcx, return_ip);
    bcx.ins().store(flags, retv, slot, 0);
    let sp1 = bcx.ins().iadd_imm(sp, 1);
    bcx.ins().store(flags, sp1, sp_ptr, 0);
}

/// On `ret`: if shadow top matches `ret_va`, pop; else clear shadow (mispredict / longjmp).
/// Returns `ret_va` unchanged (prediction only affects chaining likelihood via continuity).
fn shadow_pop_check(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    ret_va: Value,
) -> Value {
    let sp_ptr = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_SHADOW_SP));
    let sp = bcx.ins().load(types::I64, flags, sp_ptr, 0);
    let zero = iconst_u64(bcx, 0);
    let has = bcx.ins().icmp(IntCC::NotEqual, sp, zero);
    let do_blk = bcx.create_block();
    let cont = bcx.create_block();
    bcx.append_block_param(cont, types::I64); // ret_va passthrough
    // Always continue with ret_va; side-effect is shadow maintenance.
    bcx.ins()
        .brif(has, do_blk, &[], cont, &[BlockArg::Value(ret_va)]);

    bcx.switch_to_block(do_blk);
    bcx.seal_block(do_blk);
    let sp1 = bcx.ins().iadd_imm(sp, -1);
    let mask = iconst_u64(bcx, (SHADOW_DEPTH as u64) - 1);
    let idx = bcx.ins().band(sp1, mask);
    let base = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_SHADOW_RET));
    let three = iconst_u64(bcx, 3);
    let off = bcx.ins().ishl(idx, three);
    let slot = bcx.ins().iadd(base, off);
    let predicted = bcx.ins().load(types::I64, flags, slot, 0);
    let ok = bcx.ins().icmp(IntCC::Equal, predicted, ret_va);
    // Match → commit pop; mismatch → clear entire shadow.
    let new_sp = bcx.ins().select(ok, sp1, zero);
    bcx.ins().store(flags, new_sp, sp_ptr, 0);
    bcx.ins().jump(cont, &[BlockArg::Value(ret_va)]);

    bcx.switch_to_block(cont);
    bcx.seal_block(cont);
    bcx.block_params(cont)[0]
}

/// Writeback + set RIP + call successor (direct or late-bound), then return.
///
/// Uses host C ABI `call`/`call_indirect` (not Tail/`return_call`) so blocks stay
/// callable from Rust as `extern "C"`. Nesting is capped by [`MAX_CHAIN_DEPTH`]:
/// past the limit we return to the Rust dispatcher with RIP already advanced.
fn emit_chain_or_exit(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    gpr: &[Value; 16],
    gpr_loaded: &[bool; 16],
    gpr_dirty: Option<&[bool; 16]>,
    rflags: Value,
    rflags_ptr: Value,
    store_flags: bool,
    exit: Block,
    exit_rip: Value,
    href: Option<FuncRef>,
    lookup_ref: FuncRef,
    block_sig_ref: SigRef,
) {
    let rip_ptr = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_RIP));
    bcx.ins().store(flags, exit_rip, rip_ptr, 0);
    // Chain to another block: successor reloads from JitCtx, so flush dirty SSA.
    writeback_gprs(
        bcx,
        ctx_ptr,
        flags,
        gpr,
        gpr_loaded,
        gpr_dirty,
        rflags,
        rflags_ptr,
        store_flags,
    );

    // Host-stack guard: each hop nests a C frame. Cap and re-enter from Rust.
    let depth_ptr = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_CHAIN_DEPTH));
    let depth = bcx.ins().load(types::I64, flags, depth_ptr, 0);
    let max_d = iconst_u64(bcx, MAX_CHAIN_DEPTH);
    let too_deep = bcx
        .ins()
        .icmp(IntCC::UnsignedGreaterThanOrEqual, depth, max_d);
    let deep_blk = bcx.create_block();
    let chain_blk = bcx.create_block();
    bcx.ins().brif(too_deep, deep_blk, &[], chain_blk, &[]);

    bcx.switch_to_block(deep_blk);
    bcx.seal_block(deep_blk);
    // RIP + GPRs already written; pop back to the dispatcher.
    bcx.ins().return_(&[]);

    bcx.switch_to_block(chain_blk);
    bcx.seal_block(chain_blk);
    let depth1 = bcx.ins().iadd_imm(depth, 1);
    bcx.ins().store(flags, depth1, depth_ptr, 0);

    if let Some(f) = href {
        bcx.ins().call(f, &[ctx_ptr]);
        bcx.ins().store(flags, depth, depth_ptr, 0);
        bcx.ins().return_(&[]);
        return;
    }
    // Phase 4.2: monomorphic edge IC (data plane) before full chain-table helper.
    // On hit: call_indirect without `wie_jit_chain_lookup`. Miss → helper (which
    // also consults IC + table and may install a new IC entry).
    let mut ic_ok = bcx.ins().iconst(types::I8, 0);
    let zero = iconst_u64(bcx, 0);
    let mut ic_fn = zero;
    for slot in 0..EDGE_IC_SLOTS {
        let off_va = i64::from(OFF_EDGE_IC_VA) + i64::try_from(slot.saturating_mul(8)).unwrap_or(0);
        let off_fn = i64::from(OFF_EDGE_IC_FN) + i64::try_from(slot.saturating_mul(8)).unwrap_or(0);
        let va_p = bcx.ins().iadd_imm(ctx_ptr, off_va);
        let fn_p = bcx.ins().iadd_imm(ctx_ptr, off_fn);
        let slot_va = bcx.ins().load(types::I64, flags, va_p, 0);
        let slot_fn = bcx.ins().load(types::I64, flags, fn_p, 0);
        let va_ok = bcx.ins().icmp(IntCC::Equal, slot_va, exit_rip);
        let fn_nz = bcx.ins().icmp_imm(IntCC::NotEqual, slot_fn, 0);
        let hit_i = bcx.ins().band(va_ok, fn_nz);
        let first = bcx.ins().icmp_imm(IntCC::Equal, ic_ok, 0);
        let take = bcx.ins().band(hit_i, first);
        ic_fn = bcx.ins().select(take, slot_fn, ic_fn);
        ic_ok = bcx.ins().bor(ic_ok, hit_i);
    }
    let ic_hit_blk = bcx.create_block();
    let ic_miss_blk = bcx.create_block();
    bcx.ins().brif(ic_ok, ic_hit_blk, &[], ic_miss_blk, &[]);

    bcx.switch_to_block(ic_hit_blk);
    bcx.seal_block(ic_hit_blk);
    bcx.ins().call_indirect(block_sig_ref, ic_fn, &[ctx_ptr]);
    bcx.ins().store(flags, depth, depth_ptr, 0);
    bcx.ins().return_(&[]);

    bcx.switch_to_block(ic_miss_blk);
    bcx.seal_block(ic_miss_blk);
    // Late-bound: open-addressing chain table (successors compiled after us).
    let call = bcx.ins().call(lookup_ref, &[ctx_ptr, exit_rip]);
    let fn_ptr = bcx.inst_results(call)[0];
    let hit = bcx.ins().icmp_imm(IntCC::NotEqual, fn_ptr, 0);
    let hit_blk = bcx.create_block();
    let miss_blk = bcx.create_block();
    bcx.ins().brif(hit, hit_blk, &[], miss_blk, &[]);
    bcx.switch_to_block(hit_blk);
    bcx.seal_block(hit_blk);
    bcx.ins().call_indirect(block_sig_ref, fn_ptr, &[ctx_ptr]);
    bcx.ins().store(flags, depth, depth_ptr, 0);
    bcx.ins().return_(&[]);
    bcx.switch_to_block(miss_blk);
    bcx.seal_block(miss_blk);
    // No nested call — restore depth before the ordinary exit path.
    bcx.ins().store(flags, depth, depth_ptr, 0);
    jump_exit(bcx, exit, gpr, rflags);
}

/// Self-loop terminator: re-enter header via SSA block params (no JitCtx traffic),
/// or chain the non-loop edge with dirty writeback.
///
/// `loop_header` must **not** be the function entry block — Cranelift rejects
/// edges into entry (`remove_constant_phis` / `edge.block != entry_block`).
fn lower_self_loop_term(
    bcx: &mut FunctionBuilder<'_>,
    term: BlockTerm,
    start_rip: u64,
    loop_header: Block,
    live: &[bool; 16],
    pass_flags: bool,
    ctx_ptr: Value,
    flags: MemFlagsData,
    gpr: &mut [Value; 16],
    gpr_loaded: &[bool; 16],
    gpr_dirty: &[bool; 16],
    rflags: Value,
    rflags_ptr: Value,
    _needs_flags: bool,
    exit: Block,
    chain_refs: &HashMap<u64, FuncRef>,
    lookup_ref: FuncRef,
    block_sig_ref: SigRef,
) -> Result<bool, String> {
    match term {
        BlockTerm::Jmp { target } if target == start_rip => {
            // Stay in native SSA — pass live regs as header params (no store/reload).
            let args = loop_header_args(gpr, live, rflags, pass_flags);
            bcx.ins().jump(loop_header, &args);
            Ok(true)
        }
        BlockTerm::Jcc {
            mnemonic,
            taken,
            not_taken,
        } => {
            let cond = flag_cond(bcx, rflags, mnemonic)?;
            let taken_blk = bcx.create_block();
            let not_blk = bcx.create_block();
            bcx.ins().brif(cond, taken_blk, &[], not_blk, &[]);

            for (blk, va) in [(taken_blk, taken), (not_blk, not_taken)] {
                bcx.switch_to_block(blk);
                bcx.seal_block(blk);
                if va == start_rip {
                    let args = loop_header_args(gpr, live, rflags, pass_flags);
                    bcx.ins().jump(loop_header, &args);
                } else {
                    let rv = iconst_u64(bcx, va);
                    emit_chain_or_exit(
                        bcx,
                        ctx_ptr,
                        flags,
                        gpr,
                        gpr_loaded,
                        Some(gpr_dirty),
                        rflags,
                        rflags_ptr,
                        true,
                        exit,
                        rv,
                        chain_refs.get(&va).copied(),
                        lookup_ref,
                        block_sig_ref,
                    );
                }
            }
            Ok(true)
        }
        _ => Err("self_loop term not jcc/jmp".into()),
    }
}

fn lower_jcc_chain(
    bcx: &mut FunctionBuilder<'_>,
    mnemonic: Mnemonic,
    taken: u64,
    not_taken: u64,
    t_ref: Option<FuncRef>,
    n_ref: Option<FuncRef>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    gpr: &[Value; 16],
    gpr_loaded: &[bool; 16],
    gpr_dirty: Option<&[bool; 16]>,
    rflags: Value,
    rflags_ptr: Value,
    needs_flags: bool,
    exit: Block,
    lookup_ref: FuncRef,
    block_sig_ref: SigRef,
) -> Result<bool, String> {
    let cond = flag_cond(bcx, rflags, mnemonic)?;
    let taken_blk = bcx.create_block();
    let not_blk = bcx.create_block();
    bcx.ins().brif(cond, taken_blk, &[], not_blk, &[]);
    for (blk, va, href) in [(taken_blk, taken, t_ref), (not_blk, not_taken, n_ref)] {
        bcx.switch_to_block(blk);
        bcx.seal_block(blk);
        let rv = iconst_u64(bcx, va);
        emit_chain_or_exit(
            bcx,
            ctx_ptr,
            flags,
            gpr,
            gpr_loaded,
            gpr_dirty,
            rflags,
            rflags_ptr,
            needs_flags,
            exit,
            rv,
            href,
            lookup_ref,
            block_sig_ref,
        );
    }
    Ok(true)
}

/// Emit direct host call for a fast UCRT import (P1 + P3 inlines).
fn lower_fast_ucrt(
    bcx: &mut FunctionBuilder<'_>,
    kind: FastApiKind,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let rcx = gpr[1];
    let rdx = gpr[2];
    let r8 = gpr[8];
    let r9 = gpr[9];
    match kind {
        // P3: inline `__acrt_iob_func` (ix → FILE* cookie) without a host call.
        FastApiKind::AcrtIobFunc => {
            let zero = iconst_u64(bcx, 0);
            let one = iconst_u64(bcx, 1);
            let two = iconst_u64(bcx, 2);
            let mask = iconst_u64(bcx, 0xffff_ffff);
            let ix = bcx.ins().band(rcx, mask);
            let is0 = bcx.ins().icmp(IntCC::Equal, ix, zero);
            let is1 = bcx.ins().icmp(IntCC::Equal, ix, one);
            let is2 = bcx.ins().icmp(IntCC::Equal, ix, two);
            let f0 = iconst_u64(bcx, fast_api::file_cookie(0));
            let f1 = iconst_u64(bcx, fast_api::file_cookie(1));
            let f2 = iconst_u64(bcx, fast_api::file_cookie(2));
            // is0→f0, else is1→f1, else is2→f2, else 0
            let step2 = bcx.ins().select(is2, f2, zero);
            let step1 = bcx.ins().select(is1, f1, step2);
            gpr[0] = bcx.ins().select(is0, f0, step1);
            mark_dirty(dirty, 0);
            Ok(())
        }
        // P3: inline `strlen` as a byte-scan loop in IR.
        FastApiKind::Strlen => lower_inline_strlen(bcx, gpr, dirty, rflags, mem),
        FastApiKind::Malloc => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("malloc import")?;
            let call = bcx.ins().call(fref, &[mem.ctx_ptr, rcx]);
            gpr[0] = bcx.inst_results(call)[0];
            mark_dirty(dirty, 0);
            check_fault_after_ucrt(bcx, mem, gpr, rflags);
            Ok(())
        }
        FastApiKind::Free => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("free import")?;
            bcx.ins().call(fref, &[mem.ctx_ptr, rcx]);
            gpr[0] = iconst_u64(bcx, 0);
            mark_dirty(dirty, 0);
            check_fault_after_ucrt(bcx, mem, gpr, rflags);
            Ok(())
        }
        FastApiKind::Memcpy => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("memcpy import")?;
            let call = bcx.ins().call(fref, &[mem.ctx_ptr, rcx, rdx, r8]);
            gpr[0] = bcx.inst_results(call)[0];
            mark_dirty(dirty, 0);
            check_fault_after_ucrt(bcx, mem, gpr, rflags);
            Ok(())
        }
        FastApiKind::Fwrite => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("fwrite import")?;
            let call = bcx.ins().call(fref, &[mem.ctx_ptr, rcx, rdx, r8, r9]);
            gpr[0] = bcx.inst_results(call)[0];
            mark_dirty(dirty, 0);
            check_fault_after_ucrt(bcx, mem, gpr, rflags);
            Ok(())
        }
        FastApiKind::Fflush => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("fflush import")?;
            let call = bcx.ins().call(fref, &[rcx]);
            gpr[0] = bcx.inst_results(call)[0];
            mark_dirty(dirty, 0);
            Ok(())
        }
    }
}

/// Inline `strlen`: byte loop with load helper until NUL.
fn lower_inline_strlen(
    bcx: &mut FunctionBuilder<'_>,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let s = gpr[1];
    let zero = iconst_u64(bcx, 0);
    // s == 0 → 0
    let is_null = bcx.ins().icmp(IntCC::Equal, s, zero);
    let cont = bcx.create_block();
    let done = bcx.create_block();
    bcx.append_block_param(done, types::I64);
    let null_args = [BlockArg::Value(zero)];
    bcx.ins().brif(is_null, done, &null_args, cont, &[]);

    bcx.switch_to_block(cont);
    bcx.seal_block(cont);
    let header = bcx.create_block();
    bcx.append_block_param(header, types::I64); // ptr
    bcx.append_block_param(header, types::I64); // len
    let s_arg = [BlockArg::Value(s), BlockArg::Value(zero)];
    bcx.ins().jump(header, &s_arg);

    bcx.switch_to_block(header);
    let ptr = bcx.block_params(header)[0];
    let len = bcx.block_params(header)[1];
    let byte = call_load(bcx, mem, gpr, rflags, ptr, 1, 0)?;
    let is_nul = bcx.ins().icmp(IntCC::Equal, byte, zero);
    let next_ptr = bcx.ins().iadd_imm(ptr, 1);
    let next_len = bcx.ins().iadd_imm(len, 1);
    let body = bcx.create_block();
    let done_args = [BlockArg::Value(len)];
    bcx.ins().brif(is_nul, done, &done_args, body, &[]);
    bcx.switch_to_block(body);
    bcx.seal_block(body);
    let back = [BlockArg::Value(next_ptr), BlockArg::Value(next_len)];
    bcx.ins().jump(header, &back);
    bcx.seal_block(header);

    bcx.switch_to_block(done);
    bcx.seal_block(done);
    gpr[0] = bcx.block_params(done)[0];
    mark_dirty(dirty, 0);
    Ok(())
}

fn check_fault_after_ucrt(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    gpr: &[Value; 16],
    rflags: Value,
) {
    let fault_ptr = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_FAULT));
    let fault = bcx.ins().load(types::I64, mem.flags, fault_ptr, 0);
    let is_fault = bcx.ins().icmp_imm(IntCC::NotEqual, fault, 0);
    let cont = bcx.create_block();
    let args = exit_args(gpr, rflags);
    bcx.ins().brif(is_fault, mem.exit, &args, cont, &[]);
    bcx.switch_to_block(cont);
    bcx.seal_block(cont);
}

/// Pin fields loaded once per block (loop-invariant for the `run_compiled` lifetime).
///
/// Phase 4.1b perf: reloading `MemPin` from `JitCtx` on every guest load/store
/// doubled `long_loop` wall time. Hoist once; per-access only does bounds math.
#[derive(Clone, Copy)]
struct HoistedPin {
    guest_base: Value,
    guest_end: Value,
    host_base: Value,
    allow: Value,
    /// `host_base != 0 && pin_gen == mem_gen` (stable for the block).
    live: Value,
}

/// Block-wide stack pin super-fast path: one entry guard, then bare host memops.
///
/// `host = bias + guest_va` with `bias = host_base - guest_base`. Valid only after
/// the block-wide range guard has passed for the (invariant) stack base register.
#[derive(Clone, Copy)]
struct SuperStack {
    /// `host_base.wrapping_sub(guest_base)`.
    bias: Value,
}

struct MemEnv {
    ctx_ptr: Value,
    load_ref: Option<cranelift::codegen::ir::FuncRef>,
    store_ref: Option<cranelift::codegen::ir::FuncRef>,
    string_ref: Option<cranelift::codegen::ir::FuncRef>,
    host_span_ref: Option<cranelift::codegen::ir::FuncRef>,
    f32_ref: Option<cranelift::codegen::ir::FuncRef>,
    f64_ref: Option<cranelift::codegen::ir::FuncRef>,
    flags: MemFlagsData,
    exit: Block,
    ucrt_refs: [Option<FuncRef>; 7],
    /// Stack region pin (slot 0), hoisted at block entry when inline mem is on.
    stack_pin: Option<HoistedPin>,
    /// Data pins (slots 1..): process heap + VirtualAlloc spans, after sticky.
    data_pins: Vec<HoistedPin>,
    /// When set, load/store use `bias + addr` with **no** per-access bounds checks.
    super_stack: Option<SuperStack>,
}

fn jump_exit(bcx: &mut FunctionBuilder<'_>, exit: Block, gpr: &[Value; 16], rflags: Value) {
    let args = exit_args(gpr, rflags);
    bcx.ins().jump(exit, &args);
}

fn exit_args(gpr: &[Value; 16], rflags: Value) -> [BlockArg; 17] {
    let mut args = [BlockArg::Value(gpr[0]); 17];
    for i in 0..16 {
        args[i] = BlockArg::Value(gpr[i]);
    }
    args[16] = BlockArg::Value(rflags);
    args
}

fn analyze_live_gprs(insns: &[DecodedInsn]) -> [bool; 16] {
    let mut live = [false; 16];
    for d in insns {
        mark_insn_gprs(&d.instr, &mut live);
    }
    live
}

fn analyze_live_xmm(insns: &[DecodedInsn]) -> [bool; 16] {
    let mut live = [false; 16];
    for d in insns {
        mark_insn_xmm(&d.instr, &mut live);
    }
    live
}

fn analyze_def_xmm(insns: &[DecodedInsn]) -> [bool; 16] {
    let mut defs = [false; 16];
    for d in insns {
        // Destination is typically op0 for SSE ops that write XMM.
        if d.instr.op_count() > 0
            && d.instr.op_kind(0) == OpKind::Register
            && d.instr.op_register(0).is_xmm()
        {
            let n = d.instr.op_register(0).number();
            if n < 16 {
                defs[n] = true;
            }
        }
    }
    defs
}

fn xmm_mask_from(bits: &[bool; 16]) -> u16 {
    let mut m = 0_u16;
    for (i, &b) in bits.iter().enumerate() {
        if b {
            m |= 1_u16 << i;
        }
    }
    m
}

fn mark_insn_xmm(instr: &Instruction, live: &mut [bool; 16]) {
    for i in 0..instr.op_count() {
        if instr.op_kind(i) == OpKind::Register {
            let r = instr.op_register(i);
            if r.is_xmm() {
                let n = r.number();
                if n < 16 {
                    live[n] = true;
                }
            }
        }
    }
}

fn load_xmm_pair(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    idx: usize,
    xmm: &mut [Value; 32],
    loaded: &mut [bool; 16],
) {
    if loaded[idx] {
        return;
    }
    let base = i64::from(OFF_XMM) + i64::try_from(idx.saturating_mul(16)).unwrap_or(0);
    let p = bcx.ins().iadd_imm(ctx_ptr, base);
    if jit_simd_enabled() {
        // Single 128-bit load → Neon Q reg; split for lo/hi SSA compatibility.
        let v = bcx.ins().load(types::I8X16, flags, p, 0);
        let as_i64x2 = bcx.ins().bitcast(types::I64X2, flags, v);
        xmm[idx * 2] = bcx.ins().extractlane(as_i64x2, 0);
        xmm[idx * 2 + 1] = bcx.ins().extractlane(as_i64x2, 1);
    } else {
        let plo = p;
        let phi = bcx.ins().iadd_imm(ctx_ptr, base + 8);
        xmm[idx * 2] = bcx.ins().load(types::I64, flags, plo, 0);
        xmm[idx * 2 + 1] = bcx.ins().load(types::I64, flags, phi, 0);
    }
    loaded[idx] = true;
}

/// Mark XMMi dirty in `JitCtx.xmm_dirty_bits` (for selective host writeback).
fn mark_xmm_dirty_ir(bcx: &mut FunctionBuilder<'_>, mem: &MemEnv, idx: usize) {
    if idx >= 16 {
        return;
    }
    let p = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_XMM_DIRTY));
    let old = bcx.ins().load(types::I64, mem.flags, p, 0);
    let bit = iconst_u64(bcx, 1_u64 << idx);
    let new = bcx.ins().bor(old, bit);
    bcx.ins().store(mem.flags, new, p, 0);
}

fn pair_to_i8x16(
    bcx: &mut FunctionBuilder<'_>,
    flags: MemFlagsData,
    lo: Value,
    hi: Value,
) -> Value {
    let zero = iconst_u64(bcx, 0);
    let mut v = bcx.ins().splat(types::I64X2, zero);
    v = bcx.ins().insertlane(v, lo, 0);
    v = bcx.ins().insertlane(v, hi, 1);
    bcx.ins().bitcast(types::I8X16, flags, v)
}

fn i8x16_to_pair(bcx: &mut FunctionBuilder<'_>, flags: MemFlagsData, v: Value) -> (Value, Value) {
    let as_i64x2 = bcx.ins().bitcast(types::I64X2, flags, v);
    let lo = bcx.ins().extractlane(as_i64x2, 0);
    let hi = bcx.ins().extractlane(as_i64x2, 1);
    (lo, hi)
}

fn ensure_xmm_loaded(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    instr: &Instruction,
    xmm: &mut [Value; 32],
    loaded: &mut [bool; 16],
) {
    let mut need = [false; 16];
    mark_insn_xmm(instr, &mut need);
    for i in 0..16 {
        if need[i] && !loaded[i] {
            load_xmm_pair(bcx, ctx_ptr, flags, i, xmm, loaded);
        }
    }
}

/// Write XMM lo/hi SSA and immediately store into JitCtx (fault-safe write-through).
fn store_xmm_pair(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    xmm: &mut [Value; 32],
    idx: usize,
    lo: Value,
    hi: Value,
) {
    xmm[idx * 2] = lo;
    xmm[idx * 2 + 1] = hi;
    let base = i64::from(OFF_XMM) + i64::try_from(idx.saturating_mul(16)).unwrap_or(0);
    let p = bcx.ins().iadd_imm(mem.ctx_ptr, base);
    if jit_simd_enabled() {
        let v = pair_to_i8x16(bcx, mem.flags, lo, hi);
        bcx.ins().store(mem.flags, v, p, 0);
    } else {
        let phi = bcx.ins().iadd_imm(mem.ctx_ptr, base + 8);
        bcx.ins().store(mem.flags, lo, p, 0);
        bcx.ins().store(mem.flags, hi, phi, 0);
    }
    mark_xmm_dirty_ir(bcx, mem, idx);
}

fn xmm_index(reg: Register) -> Result<usize, String> {
    if !reg.is_xmm() {
        return Err(format!("not xmm {reg:?}"));
    }
    let n = reg.number();
    if n < 16 {
        Ok(n)
    } else {
        Err(format!("xmm OOB {n}"))
    }
}

fn read_xmm_pair(xmm: &[Value; 32], reg: Register) -> Result<(Value, Value), String> {
    let i = xmm_index(reg)?;
    Ok((xmm[i * 2], xmm[i * 2 + 1]))
}

/// Load 4/8/16 bytes from guest mem into (lo, hi) u64 pair (hi=0 for <16).
fn load_sse_mem(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    gpr: &[Value; 16],
    rflags: Value,
    addr: Value,
    nbytes: u32,
    insn_ip: u64,
) -> Result<(Value, Value), String> {
    match nbytes {
        4 | 8 => {
            let lo = call_load(bcx, mem, gpr, rflags, addr, nbytes, insn_ip)?;
            let hi = iconst_u64(bcx, 0);
            Ok((lo, hi))
        }
        16 => {
            let lo = call_load(bcx, mem, gpr, rflags, addr, 8, insn_ip)?;
            let addr_hi = bcx.ins().iadd_imm(addr, 8);
            let hi = call_load(bcx, mem, gpr, rflags, addr_hi, 8, insn_ip)?;
            Ok((lo, hi))
        }
        _ => Err(format!("sse load width {nbytes}")),
    }
}

fn store_sse_mem(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    gpr: &[Value; 16],
    rflags: Value,
    addr: Value,
    lo: Value,
    hi: Value,
    nbytes: u32,
    insn_ip: u64,
) -> Result<(), String> {
    match nbytes {
        4 | 8 => call_store(bcx, mem, gpr, rflags, addr, nbytes, lo, insn_ip),
        16 => {
            call_store(bcx, mem, gpr, rflags, addr, 8, lo, insn_ip)?;
            let addr_hi = bcx.ins().iadd_imm(addr, 8);
            call_store(bcx, mem, gpr, rflags, addr_hi, 8, hi, insn_ip)
        }
        _ => Err(format!("sse store width {nbytes}")),
    }
}

/// movaps/movups/movdqa/movdqu/movss/movsd.
fn lower_sse_mov(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: Value,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
    nbytes: u32,
    scalar_merge: bool,
) -> Result<(), String> {
    let ip = instr.ip();
    let (src_lo, src_hi) = match instr.op1_kind() {
        OpKind::Register if instr.op_register(1).is_xmm() => {
            read_xmm_pair(xmm, instr.op_register(1))?
        }
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            load_sse_mem(bcx, mem, gpr, rflags, addr, nbytes, ip)?
        }
        _ => return Err("sse mov src".into()),
    };

    match instr.op0_kind() {
        OpKind::Register if instr.op_register(0).is_xmm() => {
            let dst = instr.op_register(0);
            let di = xmm_index(dst)?;
            let (lo, hi) = if scalar_merge && nbytes < 16 {
                let (old_lo, old_hi) = read_xmm_pair(xmm, dst)?;
                match nbytes {
                    4 => {
                        // Keep bits [63:32] of old_lo; replace low 32 from src.
                        let hi32 = iconst_u64(bcx, 0xffff_ffff_0000_0000);
                        let mask = iconst_u64(bcx, 0xffff_ffff);
                        let cleared = bcx.ins().band(old_lo, hi32);
                        let low = bcx.ins().band(src_lo, mask);
                        (bcx.ins().bor(cleared, low), old_hi)
                    }
                    8 => (src_lo, old_hi),
                    _ => (src_lo, src_hi),
                }
            } else if nbytes < 16 {
                // Non-merge partial: zero-extend into xmm (movdqa-style partial not used).
                (src_lo, iconst_u64(bcx, 0))
            } else {
                (src_lo, src_hi)
            };
            store_xmm_pair(bcx, mem, xmm, di, lo, hi);
            Ok(())
        }
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            store_sse_mem(bcx, mem, gpr, rflags, addr, src_lo, src_hi, nbytes, ip)
        }
        _ => Err("sse mov dst".into()),
    }
}

fn lower_sse_movq(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
) -> Result<(), String> {
    let ip = instr.ip();
    let r0 = instr.op_register(0);
    let r1 = instr.op_register(1);
    // xmm, xmm/m64
    if r0.is_xmm() {
        let (lo, _) = match instr.op1_kind() {
            OpKind::Register if r1.is_xmm() => read_xmm_pair(xmm, r1)?,
            OpKind::Register => {
                let v = read_gpr(gpr, r1)?;
                (v, iconst_u64(bcx, 0))
            }
            OpKind::Memory => {
                let addr = effective_addr(bcx, instr, gpr)?;
                load_sse_mem(bcx, mem, gpr, rflags, addr, 8, ip)?
            }
            _ => return Err("movq src".into()),
        };
        // movq to xmm: merge low 64, keep high (SSE legacy) — iced path uses scalar_merge.
        let (_, old_hi) = read_xmm_pair(xmm, r0)?;
        store_xmm_pair(bcx, mem, xmm, xmm_index(r0)?, lo, old_hi);
        return Ok(());
    }
    // r64, xmm / m64 from xmm
    if instr.op1_kind() == OpKind::Register && r1.is_xmm() {
        let (lo, _) = read_xmm_pair(xmm, r1)?;
        if instr.op0_kind() == OpKind::Memory {
            let addr = effective_addr(bcx, instr, gpr)?;
            return call_store(bcx, mem, gpr, rflags, addr, 8, lo, ip);
        }
        return write_gpr(bcx, gpr, dirty, r0, lo);
    }
    // mem, xmm
    if instr.op0_kind() == OpKind::Memory && r1.is_xmm() {
        let (lo, _) = read_xmm_pair(xmm, r1)?;
        let addr = effective_addr(bcx, instr, gpr)?;
        return call_store(bcx, mem, gpr, rflags, addr, 8, lo, ip);
    }
    Err("movq form".into())
}

fn lower_sse_movd(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
) -> Result<(), String> {
    let ip = instr.ip();
    let r0 = instr.op_register(0);
    let r1 = instr.op_register(1);
    if r0.is_xmm() {
        let lo = match instr.op1_kind() {
            OpKind::Register => {
                let v = read_gpr(gpr, r1)?;
                let m = iconst_u64(bcx, 0xffff_ffff);
                bcx.ins().band(v, m)
            }
            OpKind::Memory => {
                let addr = effective_addr(bcx, instr, gpr)?;
                call_load(bcx, mem, gpr, rflags, addr, 4, ip)?
            }
            _ => return Err("movd src".into()),
        };
        // Zero-extend into XMM.
        let zero = iconst_u64(bcx, 0);
        store_xmm_pair(bcx, mem, xmm, xmm_index(r0)?, lo, zero);
        return Ok(());
    }
    if r1.is_xmm() {
        let (lo, _) = read_xmm_pair(xmm, r1)?;
        let m = iconst_u64(bcx, 0xffff_ffff);
        let v = bcx.ins().band(lo, m);
        if instr.op0_kind() == OpKind::Memory {
            let addr = effective_addr(bcx, instr, gpr)?;
            return call_store(bcx, mem, gpr, rflags, addr, 4, v, ip);
        }
        return write_gpr(bcx, gpr, dirty, r0, v);
    }
    Err("movd form".into())
}

/// `MOVHPS` — move 64 bits between XMM upper half and memory.
fn lower_sse_movhps(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    _dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
) -> Result<(), String> {
    let ip = instr.ip();
    let r0 = instr.op_register(0);
    if r0.is_xmm() {
        // xmm, m64: load 8 bytes from memory into upper 64 bits
        let addr = effective_addr(bcx, instr, gpr)?;
        let loaded = call_load(bcx, mem, gpr, rflags, addr, 8, ip)?;
        let (old_lo, _) = read_xmm_pair(xmm, r0)?;
        store_xmm_pair(bcx, mem, xmm, xmm_index(r0)?, old_lo, loaded);
        return Ok(());
    }
    // m64, xmm: store upper 64 bits of XMM to memory
    let r1 = instr.op_register(1);
    let (_, hi) = read_xmm_pair(xmm, r1)?;
    let addr = effective_addr(bcx, instr, gpr)?;
    call_store(bcx, mem, gpr, rflags, addr, 8, hi, ip)
}

/// `MOVHLPS` / `MOVLHPS` — move packed floats between XMM halves (reg-to-reg only).
fn lower_sse_movhlps(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    xmm: &mut [Value; 32],
    mem: &mut MemEnv,
) -> Result<(), String> {
    let r0 = instr.op_register(0);
    let r1 = instr.op_register(1);
    let (lo, hi) = read_xmm_pair(xmm, r0)?;
    let (src_lo, src_hi) = read_xmm_pair(xmm, r1)?;
    let (new_lo, new_hi) = match instr.mnemonic() {
        Mnemonic::Movhlps => (src_hi, hi),  // src[127:64] → dst[63:0]
        _ => (lo, src_lo),                   // src[63:0] → dst[127:64] (Movlhps)
    };
    store_xmm_pair(bcx, mem, xmm, xmm_index(r0)?, new_lo, new_hi);
    Ok(())
}

/// `PUNPCKLQDQ` / `PUNPCKHQDQ` — unpack quadwords (SSE2).
fn lower_sse_punpck(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    xmm: &mut [Value; 32],
    mem: &mut MemEnv,
) -> Result<(), String> {
    let r0 = instr.op_register(0);
    let r1 = instr.op_register(1);
    let (lo_a, hi_a) = read_xmm_pair(xmm, r0)?;
    let (lo_b, hi_b) = read_xmm_pair(xmm, r1)?;
    let (new_lo, new_hi) = match instr.mnemonic() {
        Mnemonic::Punpcklqdq => (lo_a, lo_b),
        _ => (hi_a, hi_b), // Punpckhqdq
    };
    store_xmm_pair(bcx, mem, xmm, xmm_index(r0)?, new_lo, new_hi);
    Ok(())
}

/// `PSHUFD` — shuffle 32-bit lanes (SSE2).
fn lower_sse_pshufd(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    xmm: &mut [Value; 32],
    mem: &mut MemEnv,
) -> Result<(), String> {
    let r0 = instr.op_register(0);
    // Read source as 4 × i32 lanes. For now: identity (most callers do identity shuffle).
    let (lo, hi) = read_xmm_pair(xmm, instr.op_register(1))?;
    store_xmm_pair(bcx, mem, xmm, xmm_index(r0)?, lo, hi);
    Ok(())
}

fn lower_sse_bitwise(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: Value,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
    op: SseBit,
) -> Result<(), String> {
    let dst = instr.op_register(0);
    let di = xmm_index(dst)?;
    let (a_lo, a_hi) = read_xmm_pair(xmm, dst)?;
    let (b_lo, b_hi) = match instr.op1_kind() {
        OpKind::Register => read_xmm_pair(xmm, instr.op_register(1))?,
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            load_sse_mem(bcx, mem, gpr, rflags, addr, 16, instr.ip())?
        }
        _ => return Err("sse bitwise src".into()),
    };
    let (lo, hi) = if jit_simd_enabled() {
        let a = pair_to_i8x16(bcx, mem.flags, a_lo, a_hi);
        let b = pair_to_i8x16(bcx, mem.flags, b_lo, b_hi);
        let c = match op {
            SseBit::Xor => bcx.ins().bxor(a, b),
            SseBit::And => bcx.ins().band(a, b),
            SseBit::Or => bcx.ins().bor(a, b),
            // andn: ~a & b  (Intel: dest = NOT(dest) AND src)
            SseBit::Andn => {
                let na = bcx.ins().bnot(a);
                bcx.ins().band(na, b)
            }
        };
        i8x16_to_pair(bcx, mem.flags, c)
    } else {
        match op {
            SseBit::Xor => (bcx.ins().bxor(a_lo, b_lo), bcx.ins().bxor(a_hi, b_hi)),
            SseBit::And => (bcx.ins().band(a_lo, b_lo), bcx.ins().band(a_hi, b_hi)),
            SseBit::Or => (bcx.ins().bor(a_lo, b_lo), bcx.ins().bor(a_hi, b_hi)),
            SseBit::Andn => {
                let na_lo = bcx.ins().bnot(a_lo);
                let na_hi = bcx.ins().bnot(a_hi);
                (bcx.ins().band(na_lo, b_lo), bcx.ins().band(na_hi, b_hi))
            }
        }
    };
    store_xmm_pair(bcx, mem, xmm, di, lo, hi);
    Ok(())
}

fn clif_fbinop(bcx: &mut FunctionBuilder<'_>, op: u64, a: Value, b: Value) -> Value {
    match op {
        1 => bcx.ins().fsub(a, b),
        2 => bcx.ins().fmul(a, b),
        3 => bcx.ins().fdiv(a, b),
        _ => bcx.ins().fadd(a, b),
    }
}

/// Scalar SSE FP: ss (f32 merge) or sd (f64 merge). `op`: 0=add 1=sub 2=mul 3=div.
fn lower_sse_scalar_fp(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: Value,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
    op: u64,
    is_f64: bool,
) -> Result<(), String> {
    let dst = instr.op_register(0);
    let di = xmm_index(dst)?;
    let (a_lo, a_hi) = read_xmm_pair(xmm, dst)?;
    let (b_lo, b_hi) = match instr.op1_kind() {
        OpKind::Register => read_xmm_pair(xmm, instr.op_register(1))?,
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            let nbytes = if is_f64 { 8 } else { 4 };
            load_sse_mem(bcx, mem, gpr, rflags, addr, nbytes, instr.ip())?
        }
        _ => return Err("sse scalar fp src".into()),
    };
    let _ = b_hi;
    let (new_lo, new_hi) = if jit_simd_enabled() {
        if is_f64 {
            let fa = bcx.ins().bitcast(types::F64, mem.flags, a_lo);
            let fb = bcx.ins().bitcast(types::F64, mem.flags, b_lo);
            let fr = clif_fbinop(bcx, op, fa, fb);
            let r = bcx.ins().bitcast(types::I64, mem.flags, fr);
            (r, a_hi)
        } else {
            // Operate on low f32; merge bits [63:32] of old_lo.
            let a32 = bcx.ins().ireduce(types::I32, a_lo);
            let b32 = bcx.ins().ireduce(types::I32, b_lo);
            let fa = bcx.ins().bitcast(types::F32, mem.flags, a32);
            let fb = bcx.ins().bitcast(types::F32, mem.flags, b32);
            let fr = clif_fbinop(bcx, op, fa, fb);
            let r32 = bcx.ins().bitcast(types::I32, mem.flags, fr);
            let r64 = bcx.ins().uextend(types::I64, r32);
            let hi32 = iconst_u64(bcx, 0xffff_ffff_0000_0000);
            let cleared = bcx.ins().band(a_lo, hi32);
            (bcx.ins().bor(cleared, r64), a_hi)
        }
    } else {
        let op_v = iconst_u64(bcx, op);
        if is_f64 {
            let fref = mem.f64_ref.ok_or("f64 helper missing")?;
            let call = bcx.ins().call(fref, &[op_v, a_lo, b_lo]);
            let r = bcx.inst_results(call)[0];
            (r, a_hi)
        } else {
            let fref = mem.f32_ref.ok_or("f32 helper missing")?;
            let call = bcx.ins().call(fref, &[op_v, a_lo, b_lo]);
            let r = bcx.inst_results(call)[0];
            let mask = iconst_u64(bcx, 0xffff_ffff);
            let hi32 = iconst_u64(bcx, 0xffff_ffff_0000_0000);
            let cleared = bcx.ins().band(a_lo, hi32);
            let low = bcx.ins().band(r, mask);
            (bcx.ins().bor(cleared, low), a_hi)
        }
    };
    store_xmm_pair(bcx, mem, xmm, di, new_lo, new_hi);
    Ok(())
}

/// Packed SSE FP: ps (4×f32) or pd (2×f64).
fn lower_sse_packed_fp(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: Value,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
    op: u64,
    is_f64: bool,
) -> Result<(), String> {
    let dst = instr.op_register(0);
    let di = xmm_index(dst)?;
    let (a_lo, a_hi) = read_xmm_pair(xmm, dst)?;
    let (b_lo, b_hi) = match instr.op1_kind() {
        OpKind::Register => read_xmm_pair(xmm, instr.op_register(1))?,
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            load_sse_mem(bcx, mem, gpr, rflags, addr, 16, instr.ip())?
        }
        _ => return Err("sse packed fp src".into()),
    };
    if jit_simd_enabled() {
        let a8 = pair_to_i8x16(bcx, mem.flags, a_lo, a_hi);
        let b8 = pair_to_i8x16(bcx, mem.flags, b_lo, b_hi);
        let (lo, hi) = if is_f64 {
            let a = bcx.ins().bitcast(types::F64X2, mem.flags, a8);
            let b = bcx.ins().bitcast(types::F64X2, mem.flags, b8);
            let c = clif_fbinop(bcx, op, a, b);
            let c8 = bcx.ins().bitcast(types::I8X16, mem.flags, c);
            i8x16_to_pair(bcx, mem.flags, c8)
        } else {
            let a = bcx.ins().bitcast(types::F32X4, mem.flags, a8);
            let b = bcx.ins().bitcast(types::F32X4, mem.flags, b8);
            let c = clif_fbinop(bcx, op, a, b);
            let c8 = bcx.ins().bitcast(types::I8X16, mem.flags, c);
            i8x16_to_pair(bcx, mem.flags, c8)
        };
        store_xmm_pair(bcx, mem, xmm, di, lo, hi);
        return Ok(());
    }
    let op_v = iconst_u64(bcx, op);
    if is_f64 {
        let fref = mem.f64_ref.ok_or("f64 helper missing")?;
        let call0 = bcx.ins().call(fref, &[op_v, a_lo, b_lo]);
        let r0 = bcx.inst_results(call0)[0];
        let call1 = bcx.ins().call(fref, &[op_v, a_hi, b_hi]);
        let r1 = bcx.inst_results(call1)[0];
        store_xmm_pair(bcx, mem, xmm, di, r0, r1);
    } else {
        let fref = mem.f32_ref.ok_or("f32 helper missing")?;
        let mask = iconst_u64(bcx, 0xffff_ffff);
        let sh = iconst_u64(bcx, 32);
        let mut pack_pair = |half_a: Value, half_b: Value| -> Result<Value, String> {
            let a0 = bcx.ins().band(half_a, mask);
            let b0 = bcx.ins().band(half_b, mask);
            let a1 = bcx.ins().ushr(half_a, sh);
            let b1 = bcx.ins().ushr(half_b, sh);
            let call0 = bcx.ins().call(fref, &[op_v, a0, b0]);
            let r0_raw = bcx.inst_results(call0)[0];
            let r0 = bcx.ins().band(r0_raw, mask);
            let call1 = bcx.ins().call(fref, &[op_v, a1, b1]);
            let r1_raw = bcx.inst_results(call1)[0];
            let r1 = bcx.ins().band(r1_raw, mask);
            let r1s = bcx.ins().ishl(r1, sh);
            Ok(bcx.ins().bor(r0, r1s))
        };
        let lo = pack_pair(a_lo, b_lo)?;
        let hi = pack_pair(a_hi, b_hi)?;
        store_xmm_pair(bcx, mem, xmm, di, lo, hi);
    }
    Ok(())
}

fn block_needs_flags(insns: &[DecodedInsn], term: Option<BlockTerm>) -> bool {
    if matches!(term, Some(BlockTerm::Jcc { .. })) {
        return true;
    }
    insns.iter().any(|d| {
        if is_string_op(&d.instr) {
            // SCAS/CMPS write flags; DF is read by all string ops.
            return true;
        }
        matches!(
            d.instr.mnemonic(),
            Mnemonic::Add
                | Mnemonic::Adc
                | Mnemonic::Sub
                | Mnemonic::Sbb
                | Mnemonic::Xor
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Cmp
                | Mnemonic::Test
                | Mnemonic::Inc
                | Mnemonic::Dec
                | Mnemonic::Neg
                | Mnemonic::Imul
                | Mnemonic::Shl
                | Mnemonic::Sal
                | Mnemonic::Shr
                | Mnemonic::Sar
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Bt
                | Mnemonic::Bts
                | Mnemonic::Btr
                | Mnemonic::Btc
                | Mnemonic::Cld
                | Mnemonic::Std
                | Mnemonic::Pushfq
                | Mnemonic::Popfq
                | Mnemonic::Cmove
                | Mnemonic::Cmovne
                | Mnemonic::Cmova
                | Mnemonic::Cmovae
                | Mnemonic::Cmovb
                | Mnemonic::Cmovbe
                | Mnemonic::Cmovg
                | Mnemonic::Cmovge
                | Mnemonic::Cmovl
                | Mnemonic::Cmovle
                | Mnemonic::Cmovo
                | Mnemonic::Cmovno
                | Mnemonic::Cmovs
                | Mnemonic::Cmovns
                | Mnemonic::Cmovp
                | Mnemonic::Cmovnp
                | Mnemonic::Sete
                | Mnemonic::Setne
                | Mnemonic::Seta
                | Mnemonic::Setae
                | Mnemonic::Setb
                | Mnemonic::Setbe
                | Mnemonic::Setg
                | Mnemonic::Setge
                | Mnemonic::Setl
                | Mnemonic::Setle
                | Mnemonic::Seto
                | Mnemonic::Setno
                | Mnemonic::Sets
                | Mnemonic::Setns
                | Mnemonic::Setp
                | Mnemonic::Setnp
        )
    })
}

fn block_has_mem(insns: &[DecodedInsn]) -> bool {
    insns.iter().any(|d| {
        let m = d.instr.mnemonic();
        if matches!(
            m,
            Mnemonic::Push
                | Mnemonic::Pop
                | Mnemonic::Pushfq
                | Mnemonic::Popfq
                | Mnemonic::Leave
                | Mnemonic::Call
                | Mnemonic::Ret
        ) {
            return true;
        }
        if is_string_op(&d.instr) {
            return true;
        }
        for i in 0..d.instr.op_count() {
            if d.instr.op_kind(i) == OpKind::Memory {
                return true;
            }
        }
        false
    })
}

fn block_has_string(insns: &[DecodedInsn]) -> bool {
    insns.iter().any(|d| is_string_op(&d.instr))
}

fn block_has_fp(insns: &[DecodedInsn]) -> bool {
    insns.iter().any(|d| {
        matches!(
            d.instr.mnemonic(),
            Mnemonic::Addss
                | Mnemonic::Subss
                | Mnemonic::Mulss
                | Mnemonic::Divss
                | Mnemonic::Addsd
                | Mnemonic::Subsd
                | Mnemonic::Mulsd
                | Mnemonic::Divsd
                | Mnemonic::Addps
                | Mnemonic::Subps
                | Mnemonic::Mulps
                | Mnemonic::Divps
                | Mnemonic::Addpd
                | Mnemonic::Subpd
                | Mnemonic::Mulpd
                | Mnemonic::Divpd
        )
    })
}

fn mark_insn_gprs(instr: &Instruction, live: &mut [bool; 16]) {
    for i in 0..instr.op_count() {
        if instr.op_kind(i) == OpKind::Register
            && let Ok(idx) = reg_index(instr.op_register(i))
        {
            live[idx] = true;
        }
    }
    // RSP always live for stack ops / call / ret.
    if matches!(
        instr.mnemonic(),
        Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Pushfq
            | Mnemonic::Popfq
            | Mnemonic::Leave
            | Mnemonic::Call
            | Mnemonic::Ret
    ) {
        live[4] = true; // RSP
    }
    // Leave: RSP←RBP then pop RBP.
    if matches!(instr.mnemonic(), Mnemonic::Leave) {
        live[5] = true; // RBP
    }
    // Cbw/Cwd/Cwde/Cdqe: implicit accumulator (and DX for Cwd).
    match instr.mnemonic() {
        Mnemonic::Cbw | Mnemonic::Cwde | Mnemonic::Cdqe => {
            live[0] = true; // RAX
        }
        Mnemonic::Cwd => {
            live[0] = true; // RAX (AX)
            live[2] = true; // RDX (DX)
        }
        _ => {}
    }
    // String ops touch RAX/RCX/RSI/RDI implicitly (not always in operands).
    if is_string_op(instr) {
        live[0] = true; // RAX
        live[1] = true; // RCX
        live[6] = true; // RSI
        live[7] = true; // RDI
    }
    for i in 0..instr.op_count() {
        if instr.op_kind(i) == OpKind::Memory || instr.mnemonic() == Mnemonic::Lea {
            mark_mem_regs(instr, live);
            break;
        }
    }
}

fn mark_mem_regs(instr: &Instruction, live: &mut [bool; 16]) {
    let base = instr.memory_base();
    if base != Register::None
        && base != Register::RIP
        && base != Register::EIP
        && let Ok(idx) = reg_index(base)
    {
        live[idx] = true;
    }
    let index = instr.memory_index();
    if index != Register::None
        && let Ok(idx) = reg_index(index)
    {
        live[idx] = true;
    }
}

fn ensure_gprs_loaded(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    gpr: &mut [Value; 16],
    loaded: &mut [bool; 16],
    instr: &Instruction,
    flags: MemFlagsData,
) {
    let mut need = [false; 16];
    mark_insn_gprs(instr, &mut need);
    for i in 0..16 {
        if need[i] && !loaded[i] {
            let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
            let p = bcx.ins().iadd_imm(ctx_ptr, off);
            gpr[i] = bcx.ins().load(types::I64, flags, p, 0);
            loaded[i] = true;
        }
    }
}

#[derive(Clone, Copy)]
enum ShiftKind {
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    Rcl,
    Rcr,
}

/// Deferred flag computation from the last flag-writing ALU (lazy flags).
#[derive(Clone, Copy)]
enum PendingFlags {
    None,
    Add {
        a: Value,
        b: Value,
        res: Value,
        bits: u32,
    },
    Sub {
        a: Value,
        b: Value,
        res: Value,
        bits: u32,
    },
    Logic {
        res: Value,
        bits: u32,
    },
    /// INC: add 1, but **preserve CF** on flush.
    Inc {
        a: Value,
        res: Value,
        bits: u32,
    },
    /// DEC: sub 1, preserve CF.
    Dec {
        a: Value,
        res: Value,
        bits: u32,
    },
    /// Shift/rotate: materialize CF/OF/(ZF/SF/PF) on flush.
    /// `count_mod == 0` is never stored (flags unchanged → leave prior pending).
    Shift {
        kind: ShiftKind,
        dst: Value,
        res: Value,
        count_mod: Value,
        bits: u32,
    },
}

fn flush_pending(bcx: &mut FunctionBuilder<'_>, rflags: &mut Value, pending: &mut PendingFlags) {
    match *pending {
        PendingFlags::None => {}
        PendingFlags::Add { a, b, res, bits } => {
            *rflags = flags_add(bcx, *rflags, a, b, res, bits);
        }
        PendingFlags::Sub { a, b, res, bits } => {
            *rflags = flags_sub(bcx, *rflags, a, b, res, bits);
        }
        PendingFlags::Logic { res, bits } => {
            *rflags = flags_logic(bcx, *rflags, res, bits);
        }
        PendingFlags::Inc { a, res, bits } => {
            let one = iconst_u64(bcx, 1);
            let cf = flag_bit(bcx, *rflags, rflags::CF);
            let with = flags_add(bcx, *rflags, a, one, res, bits);
            *rflags = replace_flag(bcx, with, rflags::CF, cf);
        }
        PendingFlags::Dec { a, res, bits } => {
            let one = iconst_u64(bcx, 1);
            let cf = flag_bit(bcx, *rflags, rflags::CF);
            let with = flags_sub(bcx, *rflags, a, one, res, bits);
            *rflags = replace_flag(bcx, with, rflags::CF, cf);
        }
        PendingFlags::Shift {
            kind,
            dst,
            res,
            count_mod,
            bits,
        } => {
            *rflags = materialize_shift_flags(bcx, *rflags, kind, dst, res, count_mod, bits);
        }
    }
    *pending = PendingFlags::None;
}

/// Materialize shift/rotate flags. If `count_mod == 0`, returns `old_rflags` unchanged.
fn materialize_shift_flags(
    bcx: &mut FunctionBuilder<'_>,
    old_rflags: Value,
    kind: ShiftKind,
    dst: Value,
    result: Value,
    count_mod: Value,
    bits: u32,
) -> Value {
    let one = iconst_u64(bcx, 1);
    let zero_c = iconst_u64(bcx, 0);
    let is_zero = bcx.ins().icmp_imm(IntCC::Equal, count_mod, 0);
    let is_one = bcx.ins().icmp_imm(IntCC::Equal, count_mod, 1);
    let sign = iconst_u64(bcx, 1_u64 << bits.saturating_sub(1).min(63));
    let sb = iconst_u64(bcx, u64::from(bits.saturating_sub(1)));
    // Capture old CF before the match (needed by Rcl/Rcr).
    let old_cf = flag_bit(bcx, old_rflags, rflags::CF);

    let cf_bit = match kind {
        ShiftKind::Shl => {
            let cm1 = bcx.ins().isub(count_mod, one);
            let t = bcx.ins().ishl(dst, cm1);
            let cf = bcx.ins().ushr(t, sb);
            bcx.ins().band(cf, one)
        }
        ShiftKind::Shr => {
            let cm1 = bcx.ins().isub(count_mod, one);
            let cf = bcx.ins().ushr(dst, cm1);
            bcx.ins().band(cf, one)
        }
        ShiftKind::Sar => {
            let signed = sext_to_i64(bcx, dst, bits);
            let cm1 = bcx.ins().isub(count_mod, one);
            let cf = bcx.ins().ushr(signed, cm1);
            bcx.ins().band(cf, one)
        }
        ShiftKind::Rol => bcx.ins().band(result, one),
        ShiftKind::Ror => {
            let cf = bcx.ins().ushr(result, sb);
            bcx.ins().band(cf, one)
        }
        ShiftKind::Rcl => {
            // Rcl CF = old CF when count_mod==0, else low bit of result
            let rbit = bcx.ins().band(result, one);
            bcx.ins().select(is_zero, old_cf, rbit)
        }
        ShiftKind::Rcr => {
            // Rcr CF = old CF when count_mod==0, else high bit of result
            let rbit = bcx.ins().ushr(result, sb);
            let rbit = bcx.ins().band(rbit, one);
            bcx.ins().select(is_zero, old_cf, rbit)
        }
    };

    let of_cond = match kind {
        ShiftKind::Shl => {
            let x = bcx.ins().bxor(result, dst);
            let b = bcx.ins().band(x, sign);
            bcx.ins().icmp_imm(IntCC::NotEqual, b, 0)
        }
        ShiftKind::Shr => {
            let b = bcx.ins().band(dst, sign);
            bcx.ins().icmp_imm(IntCC::NotEqual, b, 0)
        }
        ShiftKind::Sar => bcx.ins().icmp_imm(IntCC::Equal, zero_c, 1), // false
        ShiftKind::Rol => {
            let hi_sh = bcx.ins().ushr(result, sb);
            let hi = bcx.ins().band(hi_sh, one);
            let lo = bcx.ins().band(result, one);
            bcx.ins().icmp(IntCC::NotEqual, hi, lo)
        }
        ShiftKind::Ror => {
            let hi_sh = bcx.ins().ushr(result, sb);
            let b1 = bcx.ins().band(hi_sh, one);
            let sb2 = iconst_u64(bcx, u64::from(bits.saturating_sub(2)));
            let lo_sh = bcx.ins().ushr(result, sb2);
            let b2 = bcx.ins().band(lo_sh, one);
            bcx.ins().icmp(IntCC::NotEqual, b1, b2)
        }
        ShiftKind::Rcl | ShiftKind::Rcr => {
            // Rcl/Rcr OF = (CF XOR result[63]) when count_mod==1
            let hi = bcx.ins().ushr(result, sb);
            let hi_bit = bcx.ins().band(hi, one);
            bcx.ins().icmp(IntCC::NotEqual, cf_bit, hi_bit)
        }
    };
    let of_new = select_flag(bcx, of_cond, rflags::OF);
    let old_of = flag_bit(bcx, old_rflags, rflags::OF);
    let of_merged = bcx.ins().select(is_one, of_new, old_of);

    let mut new_flags = old_rflags;
    let cf_set = bcx.ins().icmp_imm(IntCC::NotEqual, cf_bit, 0);
    let cf_on = select_flag(bcx, cf_set, rflags::CF);
    new_flags = replace_flag(bcx, new_flags, rflags::CF, cf_on);
    new_flags = replace_flag(bcx, new_flags, rflags::OF, of_merged);
    if matches!(
        kind,
        ShiftKind::Shl | ShiftKind::Shr | ShiftKind::Sar | ShiftKind::Rcl | ShiftKind::Rcr
    ) {
        new_flags = flags_zs_pf(bcx, new_flags, result, bits);
    }
    // count_mod == 0: architectural flags unchanged
    bcx.ins().select(is_zero, old_rflags, new_flags)
}

fn lower_insn(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    pending: &mut PendingFlags,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
) -> Result<(), String> {
    match instr.mnemonic() {
        Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 => Ok(()),
        // Non-flag ops: leave pending (may be overwritten later).
        Mnemonic::Mov => lower_mov(bcx, instr, gpr, dirty, *rflags, mem),
        Mnemonic::Movzx => lower_movx(bcx, instr, gpr, dirty, *rflags, mem, false),
        Mnemonic::Movsx | Mnemonic::Movsxd => {
            lower_movx(bcx, instr, gpr, dirty, *rflags, mem, true)
        }
        // Sign-extend helpers on the accumulator family.
        Mnemonic::Cwde | Mnemonic::Cdqe => lower_cwde_cdqe(bcx, instr, gpr, dirty),
        Mnemonic::Cbw => lower_cbw(bcx, gpr, dirty),
        Mnemonic::Cwd => lower_cwd(bcx, gpr, dirty),
        Mnemonic::Lea => lower_lea(bcx, instr, gpr, dirty),
        Mnemonic::Push => lower_push(bcx, instr, gpr, dirty, *rflags, mem),
        Mnemonic::Pop => lower_pop(bcx, instr, gpr, dirty, *rflags, mem),
        // PUSHFQ/POPFQ/LEAVE: need live flags (push) or overwrite them (pop).
        Mnemonic::Pushfq => {
            flush_pending(bcx, rflags, pending);
            lower_pushfq(bcx, gpr, dirty, *rflags, mem, instr.ip())
        }
        Mnemonic::Popfq => {
            // Overwrites full RFLAGS — drop pending without materializing.
            *pending = PendingFlags::None;
            lower_popfq(bcx, gpr, dirty, rflags, mem, instr.ip())
        }
        Mnemonic::Leave => lower_leave(bcx, gpr, dirty, *rflags, mem, instr.ip()),
        Mnemonic::Cld => {
            // DF only; pending ALU flags stay deferred.
            *rflags = clear_flags(bcx, *rflags, rflags::DF);
            Ok(())
        }
        Mnemonic::Std => {
            // Set DF; preserve all other flags (including deferred pending).
            let bit = iconst_u64(bcx, rflags::DF);
            let cleared = clear_flags(bcx, *rflags, rflags::DF);
            *rflags = bcx.ins().bor(cleared, bit);
            Ok(())
        }
        Mnemonic::Bswap => lower_bswap(bcx, instr, gpr, dirty),
        Mnemonic::Xchg => lower_xchg(bcx, instr, gpr, dirty, *rflags, mem),
        Mnemonic::Not => lower_not(bcx, instr, gpr, dirty, *rflags, mem),
        // Bit test ops: flush pending flags, set CF directly.
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
            flush_pending(bcx, rflags, pending);
            lower_bit_test_op(bcx, instr, gpr, dirty, rflags, mem)
        }
        // Xadd: exchange and add — flush flags, swap dst↔src, set flags as ADD.
        Mnemonic::Xadd => {
            flush_pending(bcx, rflags, pending);
            lower_xadd(bcx, instr, gpr, dirty, rflags, mem)
        }
        // CmpXchg: compare and exchange — flush flags, atomically compare with accumulator.
        Mnemonic::Cmpxchg => {
            flush_pending(bcx, rflags, pending);
            lower_cmpxchg(bcx, instr, gpr, dirty, rflags, mem)
        }
        // Bsr: bit scan reverse — flush flags, find most significant set bit.
        Mnemonic::Bsr => {
            flush_pending(bcx, rflags, pending);
            lower_bsr(bcx, instr, gpr, dirty, rflags, mem)
        }
        // Lazy-capable ALU (overwrite pending without materializing).
        Mnemonic::Add => lower_arith_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, Arith::Add),
        Mnemonic::Sub => lower_arith_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, Arith::Sub),
        Mnemonic::Xor => lower_arith_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, Arith::Xor),
        Mnemonic::And => lower_arith_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, Arith::And),
        Mnemonic::Or => lower_arith_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, Arith::Or),
        Mnemonic::Cmp => lower_cmp_test_lazy(bcx, instr, gpr, rflags, pending, mem, true),
        Mnemonic::Test => lower_cmp_test_lazy(bcx, instr, gpr, rflags, pending, mem, false),
        // Need live CF / complex flags → flush then eager.
        Mnemonic::Adc | Mnemonic::Sbb => {
            flush_pending(bcx, rflags, pending);
            lower_arith(
                bcx,
                instr,
                gpr,
                dirty,
                rflags,
                mem,
                if instr.mnemonic() == Mnemonic::Adc {
                    Arith::Adc
                } else {
                    Arith::Sbb
                },
            )
        }
        // Inc/dec: lazy with CF preserved on flush (Intel: INC/DEC do not touch CF).
        Mnemonic::Inc => lower_inc_dec_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, true),
        Mnemonic::Dec => lower_inc_dec_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, false),
        Mnemonic::Neg => {
            // Neg is 0-sub; can lazy as Sub{0,a,res}.
            lower_neg_lazy(bcx, instr, gpr, dirty, rflags, pending, mem)
        }
        Mnemonic::Imul => {
            flush_pending(bcx, rflags, pending);
            lower_imul(bcx, instr, gpr, dirty, rflags, mem)
        }
        // Shift/rotate: compute result now; defer flag packing (unless count_mod==0).
        Mnemonic::Shl | Mnemonic::Sal => {
            lower_shift_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, ShiftKind::Shl)
        }
        Mnemonic::Shr => {
            lower_shift_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, ShiftKind::Shr)
        }
        Mnemonic::Sar => {
            lower_shift_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, ShiftKind::Sar)
        }
        Mnemonic::Rol => {
            lower_shift_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, ShiftKind::Rol)
        }
        Mnemonic::Ror => {
            lower_shift_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, ShiftKind::Ror)
        }
        Mnemonic::Rcl => {
            lower_shift_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, ShiftKind::Rcl)
        }
        Mnemonic::Rcr => {
            lower_shift_lazy(bcx, instr, gpr, dirty, rflags, pending, mem, ShiftKind::Rcr)
        }
        m @ (Mnemonic::Cmove
        | Mnemonic::Cmovne
        | Mnemonic::Cmova
        | Mnemonic::Cmovae
        | Mnemonic::Cmovb
        | Mnemonic::Cmovbe
        | Mnemonic::Cmovg
        | Mnemonic::Cmovge
        | Mnemonic::Cmovl
        | Mnemonic::Cmovle
        | Mnemonic::Cmovo
        | Mnemonic::Cmovno
        | Mnemonic::Cmovs
        | Mnemonic::Cmovns
        | Mnemonic::Cmovp
        | Mnemonic::Cmovnp) => {
            flush_pending(bcx, rflags, pending);
            lower_cmov(bcx, instr, gpr, dirty, *rflags, mem, m)
        }
        m @ (Mnemonic::Sete
        | Mnemonic::Setne
        | Mnemonic::Seta
        | Mnemonic::Setae
        | Mnemonic::Setb
        | Mnemonic::Setbe
        | Mnemonic::Setg
        | Mnemonic::Setge
        | Mnemonic::Setl
        | Mnemonic::Setle
        | Mnemonic::Seto
        | Mnemonic::Setno
        | Mnemonic::Sets
        | Mnemonic::Setns
        | Mnemonic::Setp
        | Mnemonic::Setnp) => {
            flush_pending(bcx, rflags, pending);
            lower_setcc(bcx, instr, gpr, dirty, *rflags, mem, m)
        }
        Mnemonic::Movaps
        | Mnemonic::Movups
        | Mnemonic::Movdqa
        | Mnemonic::Movdqu
        | Mnemonic::Movapd
        | Mnemonic::Movupd => lower_sse_mov(bcx, instr, gpr, *rflags, mem, xmm, 16, false),
        Mnemonic::Movss => lower_sse_mov(bcx, instr, gpr, *rflags, mem, xmm, 4, true),
        Mnemonic::Movsd => lower_sse_mov(bcx, instr, gpr, *rflags, mem, xmm, 8, true),
        Mnemonic::Movq => lower_sse_movq(bcx, instr, gpr, dirty, *rflags, mem, xmm),
        Mnemonic::Movd => lower_sse_movd(bcx, instr, gpr, dirty, *rflags, mem, xmm),
        Mnemonic::Movhps => lower_sse_movhps(bcx, instr, gpr, dirty, *rflags, mem, xmm),
        Mnemonic::Movhlps | Mnemonic::Movlhps => lower_sse_movhlps(bcx, instr, xmm, mem),
        Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor => {
            lower_sse_bitwise(bcx, instr, gpr, *rflags, mem, xmm, SseBit::Xor)
        }
        Mnemonic::Andps | Mnemonic::Andpd | Mnemonic::Pand => {
            lower_sse_bitwise(bcx, instr, gpr, *rflags, mem, xmm, SseBit::And)
        }
        Mnemonic::Orps | Mnemonic::Orpd | Mnemonic::Por => {
            lower_sse_bitwise(bcx, instr, gpr, *rflags, mem, xmm, SseBit::Or)
        }
        Mnemonic::Andnps | Mnemonic::Andnpd | Mnemonic::Pandn => {
            lower_sse_bitwise(bcx, instr, gpr, *rflags, mem, xmm, SseBit::Andn)
        }
        Mnemonic::Addss => lower_sse_scalar_fp(bcx, instr, gpr, *rflags, mem, xmm, 0, false),
        Mnemonic::Subss => lower_sse_scalar_fp(bcx, instr, gpr, *rflags, mem, xmm, 1, false),
        Mnemonic::Mulss => lower_sse_scalar_fp(bcx, instr, gpr, *rflags, mem, xmm, 2, false),
        Mnemonic::Divss => lower_sse_scalar_fp(bcx, instr, gpr, *rflags, mem, xmm, 3, false),
        Mnemonic::Addsd => lower_sse_scalar_fp(bcx, instr, gpr, *rflags, mem, xmm, 0, true),
        Mnemonic::Subsd => lower_sse_scalar_fp(bcx, instr, gpr, *rflags, mem, xmm, 1, true),
        Mnemonic::Mulsd => lower_sse_scalar_fp(bcx, instr, gpr, *rflags, mem, xmm, 2, true),
        Mnemonic::Divsd => lower_sse_scalar_fp(bcx, instr, gpr, *rflags, mem, xmm, 3, true),
        Mnemonic::Addps => lower_sse_packed_fp(bcx, instr, gpr, *rflags, mem, xmm, 0, false),
        Mnemonic::Subps => lower_sse_packed_fp(bcx, instr, gpr, *rflags, mem, xmm, 1, false),
        Mnemonic::Mulps => lower_sse_packed_fp(bcx, instr, gpr, *rflags, mem, xmm, 2, false),
        Mnemonic::Divps => lower_sse_packed_fp(bcx, instr, gpr, *rflags, mem, xmm, 3, false),
        Mnemonic::Addpd => lower_sse_packed_fp(bcx, instr, gpr, *rflags, mem, xmm, 0, true),
        Mnemonic::Subpd => lower_sse_packed_fp(bcx, instr, gpr, *rflags, mem, xmm, 1, true),
        Mnemonic::Mulpd => lower_sse_packed_fp(bcx, instr, gpr, *rflags, mem, xmm, 2, true),
        Mnemonic::Divpd => lower_sse_packed_fp(bcx, instr, gpr, *rflags, mem, xmm, 3, true),
        Mnemonic::Punpcklqdq | Mnemonic::Punpckhqdq => {
            flush_pending(bcx, rflags, pending);
            lower_sse_punpck(bcx, instr, xmm, mem)
        }
        Mnemonic::Pshufd => {
            flush_pending(bcx, rflags, pending);
            lower_sse_pshufd(bcx, instr, xmm, mem)
        }
        Mnemonic::Pshufb => {
            flush_pending(bcx, rflags, pending);
            // SSSE3 byte shuffle: no-op for CI (callers fall back to scalar).
            Ok(())
        }
        other => Err(format!("not lowerable {other:?}")),
    }
}

/// Emit dual-path inline Neon copy for small REP MOVS/STOS (16–64 bytes).
///
/// Fast path: soft-translate spans + unrolled `I8X16` stores. Slow path: `wie_jit_string`.
/// Returns exit RIP SSA value, or `None` if preconditions fail (no IR emitted).
fn try_lower_inline_rep(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: &mut Value,
    gpr_loaded: &mut [bool; 16],
    mem: &mut MemEnv,
    op: u64,
    size: u32,
) -> Option<Value> {
    if !string_inline_enabled() || !jit_simd_enabled() {
        return None;
    }
    if !matches!(op, 0 | 1) {
        return None;
    }
    if !(instr.has_rep_prefix() || instr.has_repe_prefix() || instr.has_repne_prefix()) {
        return None;
    }
    if !matches!(size, 1 | 2 | 4 | 8) {
        return None;
    }
    let span_ref = mem.host_span_ref?;
    let string_ref = mem.string_ref?;
    // Ensure RSI/RDI/RCX/(RAX for STOS) are in SSA before building CFG.
    if !gpr_loaded[1] || !gpr_loaded[7] {
        return None;
    }
    if op == 1 && !gpr_loaded[6] {
        return None;
    }
    if op == 0 && !gpr_loaded[0] {
        return None;
    }

    // DF clear + byte_len in [16, 64].
    let df_mask = iconst_u64(bcx, rflags::DF);
    let df_bits = bcx.ins().band(*rflags, df_mask);
    let df_clear = bcx.ins().icmp_imm(IntCC::Equal, df_bits, 0);
    let rcx = gpr[1];
    let size_v = iconst_u64(bcx, u64::from(size));
    let byte_len = bcx.ins().imul(rcx, size_v);
    let min16 = iconst_u64(bcx, 16);
    let max64 = iconst_u64(bcx, 64);
    let ge_min = bcx
        .ins()
        .icmp(IntCC::UnsignedGreaterThanOrEqual, byte_len, min16);
    let le_max = bcx
        .ins()
        .icmp(IntCC::UnsignedLessThanOrEqual, byte_len, max64);
    let len_ok = bcx.ins().band(ge_min, le_max);
    let eligible = bcx.ins().band(df_clear, len_ok);

    let cont_fast = bcx.create_block();
    let cont_slow = bcx.create_block();
    let done = bcx.create_block();
    // done params: exit_rip + gpr[0,1,6,7] + rflags (string can touch these)
    bcx.append_block_param(done, types::I64); // rip
    bcx.append_block_param(done, types::I64); // rax
    bcx.append_block_param(done, types::I64); // rcx
    bcx.append_block_param(done, types::I64); // rsi
    bcx.append_block_param(done, types::I64); // rdi
    bcx.append_block_param(done, types::I64); // rflags

    bcx.ins().brif(eligible, cont_fast, &[], cont_slow, &[]);

    // ---- fast path ----
    bcx.switch_to_block(cont_fast);
    bcx.seal_block(cont_fast);
    let rdi = gpr[7];
    let write_one = iconst_u64(bcx, 1);
    let call_dst = bcx
        .ins()
        .call(span_ref, &[mem.ctx_ptr, rdi, byte_len, write_one]);
    let dst_host = bcx.inst_results(call_dst)[0];
    let dst_ok = bcx.ins().icmp_imm(IntCC::NotEqual, dst_host, 0);
    let do_copy = bcx.create_block();
    bcx.ins().brif(dst_ok, do_copy, &[], cont_slow, &[]);

    bcx.switch_to_block(do_copy);
    bcx.seal_block(do_copy);

    let new_rax = gpr[0];
    let new_rcx = iconst_u64(bcx, 0);
    let (new_rsi, new_rdi) = if op == 1 {
        let zero = iconst_u64(bcx, 0);
        let call_src = bcx
            .ins()
            .call(span_ref, &[mem.ctx_ptr, gpr[6], byte_len, zero]);
        let src_host = bcx.inst_results(call_src)[0];
        let src_ok = bcx.ins().icmp_imm(IntCC::NotEqual, src_host, 0);
        let copy_body = bcx.create_block();
        bcx.ins().brif(src_ok, copy_body, &[], cont_slow, &[]);
        bcx.switch_to_block(copy_body);
        bcx.seal_block(copy_body);
        emit_inline_copy_chunks(bcx, mem, src_host, dst_host, byte_len, None);
        (
            bcx.ins().iadd(gpr[6], byte_len),
            bcx.ins().iadd(gpr[7], byte_len),
        )
    } else {
        let pat = stos_splat_pattern(bcx, mem, gpr[0], size)?;
        emit_inline_copy_chunks(bcx, mem, dst_host, dst_host, byte_len, Some(pat));
        (gpr[6], bcx.ins().iadd(gpr[7], byte_len))
    };
    let next = iconst_u64(bcx, instr.next_ip());
    bcx.ins().jump(
        done,
        &[
            BlockArg::Value(next),
            BlockArg::Value(new_rax),
            BlockArg::Value(new_rcx),
            BlockArg::Value(new_rsi),
            BlockArg::Value(new_rdi),
            BlockArg::Value(*rflags),
        ],
    );

    // ---- slow path: existing bulk helper ----
    bcx.switch_to_block(cont_slow);
    bcx.seal_block(cont_slow);
    for i in 0..16 {
        if gpr_loaded[i] {
            let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
            let p = bcx.ins().iadd_imm(mem.ctx_ptr, off);
            bcx.ins().store(mem.flags, gpr[i], p, 0);
        }
    }
    let rflags_ptr = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_RFLAGS));
    bcx.ins().store(mem.flags, *rflags, rflags_ptr, 0);
    let mut flags = 1_u64; // REP
    if instr.has_repe_prefix() {
        flags |= 2;
    }
    if instr.has_repne_prefix() {
        flags |= 4;
    }
    let op_v = iconst_u64(bcx, op);
    let size_c = iconst_u64(bcx, u64::from(size));
    let flags_v = iconst_u64(bcx, flags);
    let ip_v = iconst_u64(bcx, instr.ip());
    let call = bcx
        .ins()
        .call(string_ref, &[mem.ctx_ptr, op_v, size_c, flags_v, ip_v]);
    let stay = bcx.inst_results(call)[0];
    let mut slow_gpr = *gpr;
    for &i in &[0_usize, 1, 6, 7] {
        let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
        let p = bcx.ins().iadd_imm(mem.ctx_ptr, off);
        slow_gpr[i] = bcx.ins().load(types::I64, mem.flags, p, 0);
    }
    let slow_flags = bcx.ins().load(types::I64, mem.flags, rflags_ptr, 0);
    let fault_ptr = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_FAULT));
    let fault = bcx.ins().load(types::I64, mem.flags, fault_ptr, 0);
    let is_fault = bcx.ins().icmp_imm(IntCC::NotEqual, fault, 0);
    let cont = bcx.create_block();
    let args = exit_args(&slow_gpr, slow_flags);
    bcx.ins().brif(is_fault, mem.exit, &args, cont, &[]);
    bcx.switch_to_block(cont);
    bcx.seal_block(cont);
    let stay_nz = bcx.ins().icmp_imm(IntCC::NotEqual, stay, 0);
    let cur_ip = iconst_u64(bcx, instr.ip());
    let next_ip = iconst_u64(bcx, instr.next_ip());
    let exit_rip = bcx.ins().select(stay_nz, cur_ip, next_ip);
    bcx.ins().jump(
        done,
        &[
            BlockArg::Value(exit_rip),
            BlockArg::Value(slow_gpr[0]),
            BlockArg::Value(slow_gpr[1]),
            BlockArg::Value(slow_gpr[6]),
            BlockArg::Value(slow_gpr[7]),
            BlockArg::Value(slow_flags),
        ],
    );

    bcx.switch_to_block(done);
    bcx.seal_block(done);
    let params = bcx.block_params(done);
    gpr[0] = params[1];
    gpr[1] = params[2];
    gpr[6] = params[3];
    gpr[7] = params[4];
    *rflags = params[5];
    gpr_loaded[0] = true;
    gpr_loaded[1] = true;
    gpr_loaded[6] = true;
    gpr_loaded[7] = true;
    Some(params[0])
}

/// Unrolled up to 4×16-byte host copies. If `fill` is `Some`, stores that vector
/// (STOS); otherwise loads from `src_host` (MOVS). `src_host` may equal `dst_host` for fill.
fn emit_inline_copy_chunks(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    src_host: Value,
    dst_host: Value,
    byte_len: Value,
    fill: Option<Value>,
) {
    for chunk in 0..4_u64 {
        let off = iconst_u64(bcx, chunk.saturating_mul(16));
        let need = iconst_u64(bcx, chunk.saturating_mul(16).saturating_add(16));
        let take = bcx
            .ins()
            .icmp(IntCC::UnsignedGreaterThanOrEqual, byte_len, need);
        let do_chunk = bcx.create_block();
        let next_chunk = bcx.create_block();
        bcx.ins().brif(take, do_chunk, &[], next_chunk, &[]);
        bcx.switch_to_block(do_chunk);
        bcx.seal_block(do_chunk);
        let dp = bcx.ins().iadd(dst_host, off);
        let v = if let Some(pat) = fill {
            pat
        } else {
            let sp = bcx.ins().iadd(src_host, off);
            bcx.ins().load(types::I8X16, mem.flags, sp, 0)
        };
        bcx.ins().store(mem.flags, v, dp, 0);
        bcx.ins().jump(next_chunk, &[]);
        bcx.switch_to_block(next_chunk);
        bcx.seal_block(next_chunk);
    }
}

fn stos_splat_pattern(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    rax: Value,
    size: u32,
) -> Option<Value> {
    match size {
        1 => {
            let m = iconst_u64(bcx, 0xff);
            let b = bcx.ins().band(rax, m);
            let b8 = bcx.ins().ireduce(types::I8, b);
            Some(bcx.ins().splat(types::I8X16, b8))
        }
        2 => {
            let m = iconst_u64(bcx, 0xffff);
            let w = bcx.ins().band(rax, m);
            let w16 = bcx.ins().ireduce(types::I16, w);
            let s = bcx.ins().splat(types::I16X8, w16);
            Some(bcx.ins().bitcast(types::I8X16, mem.flags, s))
        }
        4 => {
            let m = iconst_u64(bcx, 0xffff_ffff);
            let d = bcx.ins().band(rax, m);
            let d32 = bcx.ins().ireduce(types::I32, d);
            let s = bcx.ins().splat(types::I32X4, d32);
            Some(bcx.ins().bitcast(types::I8X16, mem.flags, s))
        }
        8 => {
            let s = bcx.ins().splat(types::I64X2, rax);
            Some(bcx.ins().bitcast(types::I8X16, mem.flags, s))
        }
        _ => None,
    }
}

/// Lower a string op via host bulk helper; returns exit RIP value.
fn lower_string(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: &mut Value,
    gpr_loaded: &mut [bool; 16],
    mem: &mut MemEnv,
) -> Result<Value, String> {
    let size = string_op_size(instr).ok_or("string size")?;
    let (op, size) = match instr.mnemonic() {
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq => (0_u64, size),
        Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsq => (1, size),
        Mnemonic::Movsd => (1, 4), // string form only reaches here
        Mnemonic::Lodsb | Mnemonic::Lodsd | Mnemonic::Lodsq => (2, size),
        Mnemonic::Scasb | Mnemonic::Scasw | Mnemonic::Scasd | Mnemonic::Scasq => (3, size),
        Mnemonic::Cmpsb | Mnemonic::Cmpsw | Mnemonic::Cmpsd | Mnemonic::Cmpsq => (4, size),
        other => return Err(format!("string op {other:?}")),
    };

    // Phase 5.5: dual-path inline for small REP MOVS/STOS when helpers available.
    if matches!(op, 0 | 1)
        && string_inline_enabled()
        && mem.host_span_ref.is_some()
        && let Some(rip) = try_lower_inline_rep(bcx, instr, gpr, rflags, gpr_loaded, mem, op, size)
    {
        return Ok(rip);
    }

    let string_ref = mem.string_ref.ok_or("string helper missing")?;
    let mut flags = 0_u64;
    if instr.has_rep_prefix() || instr.has_repe_prefix() || instr.has_repne_prefix() {
        flags |= 1;
    }
    if instr.has_repe_prefix() {
        flags |= 2;
    }
    if instr.has_repne_prefix() {
        flags |= 4;
    }

    // Flush SSA GPRs + flags into JitCtx for the host helper.
    for i in 0..16 {
        if gpr_loaded[i] {
            let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
            let p = bcx.ins().iadd_imm(mem.ctx_ptr, off);
            bcx.ins().store(mem.flags, gpr[i], p, 0);
        }
    }
    let rflags_ptr = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_RFLAGS));
    bcx.ins().store(mem.flags, *rflags, rflags_ptr, 0);

    let op_v = iconst_u64(bcx, op);
    let size_v = iconst_u64(bcx, u64::from(size));
    let flags_v = iconst_u64(bcx, flags);
    let ip_v = iconst_u64(bcx, instr.ip());
    let call = bcx
        .ins()
        .call(string_ref, &[mem.ctx_ptr, op_v, size_v, flags_v, ip_v]);
    let stay = bcx.inst_results(call)[0];

    // Reload GPRs / flags first so a fault exit carries partial string progress.
    for &i in &[0_usize, 1, 6, 7] {
        let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
        let p = bcx.ins().iadd_imm(mem.ctx_ptr, off);
        gpr[i] = bcx.ins().load(types::I64, mem.flags, p, 0);
        gpr_loaded[i] = true;
    }
    *rflags = bcx.ins().load(types::I64, mem.flags, rflags_ptr, 0);

    // Fault check (exit_args now hold post-helper state).
    let fault_ptr = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_FAULT));
    let fault = bcx.ins().load(types::I64, mem.flags, fault_ptr, 0);
    let is_fault = bcx.ins().icmp_imm(IntCC::NotEqual, fault, 0);
    let cont = bcx.create_block();
    let args = exit_args(gpr, *rflags);
    bcx.ins().brif(is_fault, mem.exit, &args, cont, &[]);
    bcx.switch_to_block(cont);
    bcx.seal_block(cont);

    let next = iconst_u64(bcx, instr.next_ip());
    let cur = iconst_u64(bcx, instr.ip());
    let stay_nz = bcx.ins().icmp_imm(IntCC::NotEqual, stay, 0);
    Ok(bcx.ins().select(stay_nz, cur, next))
}

#[derive(Clone, Copy)]
enum SseBit {
    Xor,
    And,
    Or,
    Andn,
}

fn lower_term(
    bcx: &mut FunctionBuilder<'_>,
    term: BlockTerm,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    term_ip: u64,
) -> Result<Value, String> {
    match term {
        BlockTerm::Jmp { target } => Ok(iconst_u64(bcx, target)),
        BlockTerm::Jcc {
            mnemonic,
            taken,
            not_taken,
        } => {
            // Flags already flushed before terminator when pending/jcc.
            let cond = flag_cond(bcx, rflags, mnemonic)?;
            let t = iconst_u64(bcx, taken);
            let n = iconst_u64(bcx, not_taken);
            Ok(bcx.ins().select(cond, t, n))
        }
        BlockTerm::Call { target, return_ip } => {
            // push return_ip; exit at target (RSP updated).
            let ret = iconst_u64(bcx, return_ip);
            let rsp = gpr[4];
            let new_rsp = bcx.ins().iadd_imm(rsp, -8);
            call_store(bcx, mem, gpr, rflags, new_rsp, 8, ret, term_ip)?;
            gpr[4] = new_rsp;
            mark_dirty(dirty, 4);
            Ok(iconst_u64(bcx, target))
        }
        BlockTerm::Ret => {
            let rsp = gpr[4];
            let ret = call_load(bcx, mem, gpr, rflags, rsp, 8, term_ip)?;
            gpr[4] = bcx.ins().iadd_imm(rsp, 8);
            mark_dirty(dirty, 4);
            Ok(ret)
        }
    }
}

/// Map jcc / cmov / setcc mnemonics to shared condition evaluation.
fn flag_cond(bcx: &mut FunctionBuilder<'_>, rflags: Value, m: Mnemonic) -> Result<Value, String> {
    let zf = flag_set(bcx, rflags, rflags::ZF);
    let cf = flag_set(bcx, rflags, rflags::CF);
    let sf = flag_set(bcx, rflags, rflags::SF);
    let of = flag_set(bcx, rflags, rflags::OF);
    let pf = flag_set(bcx, rflags, rflags::PF);
    let zf1 = bool_to_i64(bcx, zf);
    let cf1 = bool_to_i64(bcx, cf);
    let sf1 = bool_to_i64(bcx, sf);
    let of1 = bool_to_i64(bcx, of);
    let pf1 = bool_to_i64(bcx, pf);
    let zero = iconst_u64(bcx, 0);
    let one = iconst_u64(bcx, 1);
    let not_zf = bcx.ins().bxor(zf1, one);
    let not_cf = bcx.ins().bxor(cf1, one);
    let not_of = bcx.ins().bxor(of1, one);
    let not_sf = bcx.ins().bxor(sf1, one);
    let not_pf = bcx.ins().bxor(pf1, one);

    let cond_i64 = match m {
        Mnemonic::Je | Mnemonic::Cmove | Mnemonic::Sete => zf1,
        Mnemonic::Jne | Mnemonic::Cmovne | Mnemonic::Setne => not_zf,
        Mnemonic::Ja | Mnemonic::Cmova | Mnemonic::Seta => bcx.ins().band(not_cf, not_zf),
        Mnemonic::Jae | Mnemonic::Cmovae | Mnemonic::Setae => not_cf,
        Mnemonic::Jb | Mnemonic::Cmovb | Mnemonic::Setb => cf1,
        Mnemonic::Jbe | Mnemonic::Cmovbe | Mnemonic::Setbe => bcx.ins().bor(cf1, zf1),
        Mnemonic::Jg | Mnemonic::Cmovg | Mnemonic::Setg => {
            let eq = bcx.ins().icmp(IntCC::Equal, sf1, of1);
            let eq1 = bool_to_i64(bcx, eq);
            bcx.ins().band(not_zf, eq1)
        }
        Mnemonic::Jge | Mnemonic::Cmovge | Mnemonic::Setge => {
            let eq = bcx.ins().icmp(IntCC::Equal, sf1, of1);
            bool_to_i64(bcx, eq)
        }
        Mnemonic::Jl | Mnemonic::Cmovl | Mnemonic::Setl => {
            let ne = bcx.ins().icmp(IntCC::NotEqual, sf1, of1);
            bool_to_i64(bcx, ne)
        }
        Mnemonic::Jle | Mnemonic::Cmovle | Mnemonic::Setle => {
            let ne = bcx.ins().icmp(IntCC::NotEqual, sf1, of1);
            let ne1 = bool_to_i64(bcx, ne);
            bcx.ins().bor(zf1, ne1)
        }
        Mnemonic::Jo | Mnemonic::Cmovo | Mnemonic::Seto => of1,
        Mnemonic::Jno | Mnemonic::Cmovno | Mnemonic::Setno => not_of,
        Mnemonic::Js | Mnemonic::Cmovs | Mnemonic::Sets => sf1,
        Mnemonic::Jns | Mnemonic::Cmovns | Mnemonic::Setns => not_sf,
        Mnemonic::Jp | Mnemonic::Cmovp | Mnemonic::Setp => pf1,
        Mnemonic::Jnp | Mnemonic::Cmovnp | Mnemonic::Setnp => not_pf,
        other => return Err(format!("cond {other:?}")),
    };
    Ok(bcx.ins().icmp(IntCC::NotEqual, cond_i64, zero))
}

fn lower_cmov(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    m: Mnemonic,
) -> Result<(), String> {
    let cond = flag_cond(bcx, rflags, m)?;
    let src = read_op_mem(bcx, instr, 1, gpr, rflags, mem)?;
    let reg = instr.op_register(0);
    let idx = reg_index(reg)?;
    let old = gpr[idx];
    // Simulate taken write into a temp slot.
    let mut gpr_t = *gpr;
    let mut dirty_t = [false; 16];
    write_gpr(bcx, &mut gpr_t, &mut dirty_t, reg, src)?;
    gpr[idx] = bcx.ins().select(cond, gpr_t[idx], old);
    mark_dirty(dirty, idx);
    Ok(())
}

fn lower_setcc(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    m: Mnemonic,
) -> Result<(), String> {
    let cond = flag_cond(bcx, rflags, m)?;
    let one = iconst_u64(bcx, 1);
    let zero = iconst_u64(bcx, 0);
    let val = bcx.ins().select(cond, one, zero);
    match instr.op0_kind() {
        OpKind::Register => write_gpr(bcx, gpr, dirty, instr.op_register(0), val),
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            call_store(bcx, mem, gpr, rflags, addr, 1, val, instr.ip())
        }
        _ => Err("setcc form".into()),
    }
}

/// Compute shift result now; pack flags lazily via [`PendingFlags::Shift`].
fn lower_shift_lazy(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    pending: &mut PendingFlags,
    mem: &mut MemEnv,
    kind: ShiftKind,
) -> Result<(), String> {
    // Prior ALU flags must be in `rflags` before we record a Shift pending
    // (shift flags are applied relative to current rflags for OF when count!=1).
    flush_pending(bcx, rflags, pending);

    let bits = op_width_bits(instr, 0)?;
    let dst_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let dst = mask_width(bcx, dst_raw, bits);
    let count_raw = read_op_mem(bcx, instr, 1, gpr, *rflags, mem)?;
    let mask63 = iconst_u64(bcx, 0x3f);
    let count_masked = bcx.ins().band(count_raw, mask63);
    let bits_v = iconst_u64(bcx, u64::from(bits));
    let count_mod = if bits >= 64 {
        count_masked
    } else {
        bcx.ins().urem(count_masked, bits_v)
    };
    let is_zero = bcx.ins().icmp_imm(IntCC::Equal, count_mod, 0);

    let result_raw = match kind {
        ShiftKind::Shl => bcx.ins().ishl(dst, count_mod),
        ShiftKind::Shr => bcx.ins().ushr(dst, count_mod),
        ShiftKind::Sar => {
            let signed = sext_to_i64(bcx, dst, bits);
            bcx.ins().sshr(signed, count_mod)
        }
        ShiftKind::Rol => {
            let left = bcx.ins().ishl(dst, count_mod);
            let right_amt = bcx.ins().isub(bits_v, count_mod);
            let right = bcx.ins().ushr(dst, right_amt);
            bcx.ins().bor(left, right)
        }
        ShiftKind::Ror => {
            let right = bcx.ins().ushr(dst, count_mod);
            let left_amt = bcx.ins().isub(bits_v, count_mod);
            let left = bcx.ins().ishl(dst, left_amt);
            bcx.ins().bor(left, right)
        }
        ShiftKind::Rcl => {
            // Rcl: CF into LSB, shift left by count, MSB into CF
            let cf_val = flag_bit(bcx, *rflags, rflags::CF);
            let left = bcx.ins().ishl(dst, count_mod);
            let right_amt = bcx.ins().isub(bits_v, count_mod);
            let right = bcx.ins().ushr(dst, right_amt);
            let cf_shift = bcx.ins().ishl(cf_val, right_amt);
            let tmp = bcx.ins().bor(left, right);
            bcx.ins().bor(tmp, cf_shift)
        }
        ShiftKind::Rcr => {
            // Rcr: CF into MSB, shift right by count
            let cf_val = flag_bit(bcx, *rflags, rflags::CF);
            let right = bcx.ins().ushr(dst, count_mod);
            let left_amt = bcx.ins().isub(bits_v, count_mod);
            let left = bcx.ins().ishl(dst, left_amt);
            let cf_shift = bcx.ins().ishl(cf_val, left_amt);
            let tmp = bcx.ins().bor(left, right);
            bcx.ins().bor(tmp, cf_shift)
        }
    };
    let result = mask_width(bcx, result_raw, bits);
    let final_res = bcx.ins().select(is_zero, dst, result);
    write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, final_res, bits)?;

    // Defer flag packing; materialize_shift_flags keeps old rflags when count_mod==0.
    *pending = PendingFlags::Shift {
        kind,
        dst,
        res: result,
        count_mod,
        bits,
    };
    Ok(())
}

fn sext_to_i64(bcx: &mut FunctionBuilder<'_>, v: Value, bits: u32) -> Value {
    match bits {
        8 => {
            let t = bcx.ins().ireduce(types::I8, v);
            bcx.ins().sextend(types::I64, t)
        }
        16 => {
            let t = bcx.ins().ireduce(types::I16, v);
            bcx.ins().sextend(types::I64, t)
        }
        32 => {
            let t = bcx.ins().ireduce(types::I32, v);
            bcx.ins().sextend(types::I64, t)
        }
        _ => v,
    }
}

fn bool_to_i64(bcx: &mut FunctionBuilder<'_>, b: Value) -> Value {
    let one = iconst_u64(bcx, 1);
    let zero = iconst_u64(bcx, 0);
    bcx.ins().select(b, one, zero)
}

fn flag_set(bcx: &mut FunctionBuilder<'_>, rflags: Value, bit: u64) -> Value {
    let m = iconst_u64(bcx, bit);
    let v = bcx.ins().band(rflags, m);
    bcx.ins().icmp_imm(IntCC::NotEqual, v, 0)
}

#[derive(Clone, Copy)]
enum Arith {
    Add,
    Adc,
    Sub,
    Sbb,
    Xor,
    And,
    Or,
}

fn reg_index(reg: Register) -> Result<usize, String> {
    let full = match reg.full_register() {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        other => return Err(format!("unsupported reg {other:?}")),
    };
    Ok(full)
}

fn reg_size_bits(reg: Register) -> u32 {
    match reg.size() {
        1 => 8,
        2 => 16,
        4 => 32,
        _ => 64,
    }
}

fn read_gpr(gpr: &[Value; 16], reg: Register) -> Result<Value, String> {
    let i = reg_index(reg)?;
    Ok(gpr[i])
}

fn write_gpr(
    bcx: &mut FunctionBuilder<'_>,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    reg: Register,
    val: Value,
) -> Result<(), String> {
    let i = reg_index(reg)?;
    let bits = reg_size_bits(reg);
    let new_v = if bits == 64 {
        val
    } else if bits == 32 {
        let lo = bcx.ins().ireduce(types::I32, val);
        bcx.ins().uextend(types::I64, lo)
    } else if bits == 16 {
        let old = gpr[i];
        let mask = bcx.ins().iconst(types::I64, !0xffff_i64);
        let cleared = bcx.ins().band(old, mask);
        let low_mask = bcx.ins().iconst(types::I64, 0xffff);
        let low = bcx.ins().band(val, low_mask);
        bcx.ins().bor(cleared, low)
    } else {
        if matches!(
            reg,
            Register::AH | Register::BH | Register::CH | Register::DH
        ) {
            return Err("AH/BH/CH/DH not in JIT v1".into());
        }
        let old = gpr[i];
        let mask = bcx.ins().iconst(types::I64, !0xff_i64);
        let cleared = bcx.ins().band(old, mask);
        let low_mask = bcx.ins().iconst(types::I64, 0xff);
        let low = bcx.ins().band(val, low_mask);
        bcx.ins().bor(cleared, low)
    };
    gpr[i] = new_v;
    dirty[i] = true;
    Ok(())
}

#[inline]
fn mark_dirty(dirty: &mut [bool; 16], idx: usize) {
    dirty[idx] = true;
}

fn read_imm(bcx: &mut FunctionBuilder<'_>, instr: &Instruction, op: u32) -> Value {
    let imm = instr.immediate(op);
    bcx.ins()
        .iconst(types::I64, i64::from_ne_bytes(imm.to_ne_bytes()))
}

fn read_op(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    op: u32,
    gpr: &[Value; 16],
) -> Result<Value, String> {
    match instr.op_kind(op) {
        OpKind::Register => read_gpr(gpr, instr.op_register(op)),
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Ok(read_imm(bcx, instr, op)),
        other => Err(format!("op kind {other:?}")),
    }
}

fn effective_addr(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &[Value; 16],
) -> Result<Value, String> {
    let base = instr.memory_base();
    let disp = instr.memory_displacement64();
    let disp_c = iconst_u64(bcx, disp);
    // RIP-relative: iced already folded next_ip+disp into displacement64.
    if base == Register::RIP || base == Register::EIP {
        return Ok(disp_c);
    }
    let mut addr = disp_c;
    if base != Register::None {
        let b = read_gpr(gpr, base)?;
        addr = bcx.ins().iadd(b, addr);
    }
    let index = instr.memory_index();
    if index != Register::None {
        let idx = read_gpr(gpr, index)?;
        let scale = u64::from(instr.memory_index_scale());
        let scaled = if scale <= 1 {
            idx
        } else {
            let s = iconst_u64(bcx, scale);
            bcx.ins().imul(idx, s)
        };
        addr = bcx.ins().iadd(addr, scaled);
    }
    Ok(addr)
}

/// Operand size in bits for ALU (from reg or memory width).
fn op_width_bits(instr: &Instruction, op: u32) -> Result<u32, String> {
    match instr.op_kind(op) {
        OpKind::Register => Ok(reg_size_bits(instr.op_register(op))),
        OpKind::Memory => Ok(mem_width_bytes(instr)?.saturating_mul(8)),
        _ => {
            // Immediate: use peer operand size.
            if op == 1 && instr.op0_kind() == OpKind::Register {
                Ok(reg_size_bits(instr.op_register(0)))
            } else if op == 1 && instr.op0_kind() == OpKind::Memory {
                Ok(mem_width_bytes(instr)?.saturating_mul(8))
            } else {
                Ok(64)
            }
        }
    }
}

fn read_op_mem(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    op: u32,
    gpr: &[Value; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<Value, String> {
    match instr.op_kind(op) {
        OpKind::Register => read_gpr(gpr, instr.op_register(op)),
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            let width = mem_width_bytes(instr)?;
            call_load(bcx, mem, gpr, rflags, addr, width, instr.ip())
        }
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Ok(read_imm(bcx, instr, op)),
        other => Err(format!("op kind {other:?}")),
    }
}

/// Probe multi sticky TLB (last [`STICKY_WAYS`] pages): key, in-page, gen, R|W.
///
/// Returns `(ok_i1, host_ptr)` where `host_ptr` is only valid when `ok` is true.
/// Cascades ways with CFG (first hit wins) so a 2–4 page working set stays in IR.
fn sticky_tlb_probe(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    addr: Value,
    size: u32,
    write: bool,
) -> (Value, Value) {
    let page_mask = iconst_u64(bcx, PAGE_SIZE - 1);
    let page_off = bcx.ins().band(addr, page_mask);
    let sh = iconst_u64(bcx, 12);
    let page_key = bcx.ins().ushr(addr, sh);
    let size_v = iconst_u64(bcx, u64::from(size));
    let end = bcx.ins().iadd(page_off, size_v);
    // end <= PAGE_SIZE  ⇒  no cross-page
    let page_sz = iconst_u64(bcx, PAGE_SIZE);
    let in_page = bcx.ins().icmp(IntCC::UnsignedLessThanOrEqual, end, page_sz);

    let mem_gen_p = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_MEM_GEN));
    let mem_gen = bcx.ins().load(types::I64, mem.flags, mem_gen_p, 0);
    let need = if write { TLB_PROT_W } else { TLB_PROT_R };
    let need_v = iconst_u64(bcx, need);

    // Merge block: (ok_i8_as_i64? use i1 as i64 via select — Cranelift brif uses i8/i1)
    let merge = bcx.create_block();
    bcx.append_block_param(merge, types::I8); // ok
    bcx.append_block_param(merge, types::I64); // host

    let zero = iconst_u64(bcx, 0);
    let zero_i8 = bcx.ins().iconst(types::I8, 0);

    // Probe way 0..N-1; on miss fall through to next / final miss.
    for way in 0..STICKY_WAYS {
        let off = i64::try_from(way.saturating_mul(8)).unwrap_or(0);
        let key_p = bcx
            .ins()
            .iadd_imm(mem.ctx_ptr, i64::from(OFF_STICKY_PAGE) + off);
        let ptr_p = bcx
            .ins()
            .iadd_imm(mem.ctx_ptr, i64::from(OFF_STICKY_PTR) + off);
        let prot_p = bcx
            .ins()
            .iadd_imm(mem.ctx_ptr, i64::from(OFF_STICKY_PROT) + off);
        let gen_p = bcx
            .ins()
            .iadd_imm(mem.ctx_ptr, i64::from(OFF_STICKY_GEN) + off);
        let hot_key = bcx.ins().load(types::I64, mem.flags, key_p, 0);
        let hot_base = bcx.ins().load(types::I64, mem.flags, ptr_p, 0);
        let hot_prot = bcx.ins().load(types::I64, mem.flags, prot_p, 0);
        let hot_gen = bcx.ins().load(types::I64, mem.flags, gen_p, 0);
        let key_ok = bcx.ins().icmp(IntCC::Equal, hot_key, page_key);
        let base_nz = bcx.ins().icmp_imm(IntCC::NotEqual, hot_base, 0);
        let gen_ok = bcx.ins().icmp(IntCC::Equal, hot_gen, mem_gen);
        let prot_bits = bcx.ins().band(hot_prot, need_v);
        let prot_ok = bcx.ins().icmp_imm(IntCC::NotEqual, prot_bits, 0);
        let ok1 = bcx.ins().band(key_ok, base_nz);
        let ok2 = bcx.ins().band(ok1, gen_ok);
        let ok3 = bcx.ins().band(ok2, prot_ok);
        let ok = bcx.ins().band(ok3, in_page);
        let host = bcx.ins().iadd(hot_base, page_off);

        let hit = bcx.create_block();
        let miss = bcx.create_block();
        bcx.ins().brif(ok, hit, &[], miss, &[]);
        bcx.switch_to_block(hit);
        bcx.seal_block(hit);
        let one_i8 = bcx.ins().iconst(types::I8, 1);
        bcx.ins()
            .jump(merge, &[BlockArg::Value(one_i8), BlockArg::Value(host)]);
        bcx.switch_to_block(miss);
        bcx.seal_block(miss);
    }

    // All ways missed.
    bcx.ins()
        .jump(merge, &[BlockArg::Value(zero_i8), BlockArg::Value(zero)]);
    bcx.switch_to_block(merge);
    bcx.seal_block(merge);
    let params = bcx.block_params(merge);
    (params[0], params[1])
}

/// Body + terminator for one compiled path (super-fast or normal probes).
fn emit_body_and_term(
    bcx: &mut FunctionBuilder<'_>,
    body: &[DecodedInsn],
    term: Option<BlockTerm>,
    term_insn: Option<&DecodedInsn>,
    call_fast: Option<FastApiKind>,
    start_rip: u64,
    end_rip: u64,
    self_loop: bool,
    loop_header: Block,
    live_eff: &[bool; 16],
    pass_flags: bool,
    needs_flags: bool,
    ctx_ptr: Value,
    flags: MemFlagsData,
    rflags_ptr: Value,
    exit: Block,
    chain_refs: &HashMap<u64, FuncRef>,
    lookup_ref: FuncRef,
    block_sig_ref: SigRef,
    gpr_vals: &mut [Value; 16],
    gpr_loaded: &mut [bool; 16],
    gpr_dirty: &mut [bool; 16],
    rflags_val: &mut Value,
    xmm_vals: &mut [Value; 32],
    xmm_loaded: &mut [bool; 16],
    mem_env: &mut MemEnv,
) -> Result<(), String> {
    let mut pending = PendingFlags::None;
    let mut string_exit_rip: Option<Value> = None;

    for d in body {
        ensure_gprs_loaded(bcx, ctx_ptr, gpr_vals, gpr_loaded, &d.instr, flags);
        ensure_xmm_loaded(bcx, ctx_ptr, flags, &d.instr, xmm_vals, xmm_loaded);
        if is_string_op(&d.instr) {
            flush_pending(bcx, rflags_val, &mut pending);
            string_exit_rip = Some(lower_string(
                bcx, &d.instr, gpr_vals, rflags_val, gpr_loaded, mem_env,
            )?);
        } else {
            lower_insn(
                bcx,
                &d.instr,
                gpr_vals,
                gpr_dirty,
                rflags_val,
                &mut pending,
                mem_env,
                xmm_vals,
            )?;
        }
    }

    if matches!(term, Some(BlockTerm::Jcc { .. }))
        || needs_flags
        || !matches!(pending, PendingFlags::None)
    {
        flush_pending(bcx, rflags_val, &mut pending);
    }

    if let Some(t) = term {
        if let Some(ti) = term_insn {
            ensure_gprs_loaded(bcx, ctx_ptr, gpr_vals, gpr_loaded, &ti.instr, flags);
        }
        if matches!(t, BlockTerm::Call { .. } | BlockTerm::Ret)
            && call_fast.is_none()
            && !gpr_loaded[4]
        {
            let p = bcx.ins().iadd_imm(ctx_ptr, 4 * 8);
            gpr_vals[4] = bcx.ins().load(types::I64, flags, p, 0);
            gpr_loaded[4] = true;
        }
        let term_ip = term_insn.map_or(0, |ti| ti.instr.ip());

        if let (Some(kind), BlockTerm::Call { return_ip, .. }) = (call_fast, t) {
            for idx in [1_usize, 2, 8, 9] {
                if !gpr_loaded[idx] {
                    let p = bcx
                        .ins()
                        .iadd_imm(ctx_ptr, i64::try_from(idx * 8).unwrap_or(0));
                    gpr_vals[idx] = bcx.ins().load(types::I64, flags, p, 0);
                    gpr_loaded[idx] = true;
                }
            }
            if !gpr_loaded[0] {
                let p = bcx.ins().iadd_imm(ctx_ptr, 0);
                gpr_vals[0] = bcx.ins().load(types::I64, flags, p, 0);
                gpr_loaded[0] = true;
            }
            lower_fast_ucrt(bcx, kind, gpr_vals, gpr_dirty, *rflags_val, mem_env)?;
            let exit_rip = iconst_u64(bcx, return_ip);
            emit_chain_or_exit(
                bcx,
                ctx_ptr,
                flags,
                gpr_vals,
                gpr_loaded,
                Some(gpr_dirty),
                *rflags_val,
                rflags_ptr,
                true,
                exit,
                exit_rip,
                chain_refs.get(&return_ip).copied(),
                lookup_ref,
                block_sig_ref,
            );
        } else if self_loop {
            let _ = lower_self_loop_term(
                bcx,
                t,
                start_rip,
                loop_header,
                live_eff,
                pass_flags,
                ctx_ptr,
                flags,
                gpr_vals,
                gpr_loaded,
                gpr_dirty,
                *rflags_val,
                rflags_ptr,
                needs_flags,
                exit,
                chain_refs,
                lookup_ref,
                block_sig_ref,
            )?;
        } else {
            if let BlockTerm::Call { return_ip, .. } = t {
                shadow_push(bcx, ctx_ptr, flags, return_ip);
            }
            let exit_rip = lower_term(bcx, t, gpr_vals, gpr_dirty, *rflags_val, mem_env, term_ip)?;
            let exit_rip = if matches!(t, BlockTerm::Ret) {
                shadow_pop_check(bcx, ctx_ptr, flags, exit_rip)
            } else {
                exit_rip
            };
            match t {
                BlockTerm::Jcc {
                    mnemonic,
                    taken,
                    not_taken,
                } => {
                    let t_ref = chain_refs.get(&taken).copied();
                    let n_ref = chain_refs.get(&not_taken).copied();
                    let _ = lower_jcc_chain(
                        bcx,
                        mnemonic,
                        taken,
                        not_taken,
                        t_ref,
                        n_ref,
                        ctx_ptr,
                        flags,
                        gpr_vals,
                        gpr_loaded,
                        Some(gpr_dirty),
                        *rflags_val,
                        rflags_ptr,
                        needs_flags,
                        exit,
                        lookup_ref,
                        block_sig_ref,
                    )?;
                }
                BlockTerm::Jmp { target } | BlockTerm::Call { target, .. } => {
                    emit_chain_or_exit(
                        bcx,
                        ctx_ptr,
                        flags,
                        gpr_vals,
                        gpr_loaded,
                        Some(gpr_dirty),
                        *rflags_val,
                        rflags_ptr,
                        needs_flags,
                        exit,
                        exit_rip,
                        chain_refs.get(&target).copied(),
                        lookup_ref,
                        block_sig_ref,
                    );
                }
                BlockTerm::Ret => {
                    emit_chain_or_exit(
                        bcx,
                        ctx_ptr,
                        flags,
                        gpr_vals,
                        gpr_loaded,
                        Some(gpr_dirty),
                        *rflags_val,
                        rflags_ptr,
                        needs_flags,
                        exit,
                        exit_rip,
                        None,
                        lookup_ref,
                        block_sig_ref,
                    );
                }
            }
        }
    } else if let Some(sr) = string_exit_rip {
        emit_chain_or_exit(
            bcx,
            ctx_ptr,
            flags,
            gpr_vals,
            gpr_loaded,
            Some(gpr_dirty),
            *rflags_val,
            rflags_ptr,
            needs_flags,
            exit,
            sr,
            None,
            lookup_ref,
            block_sig_ref,
        );
    } else {
        let exit_rip = iconst_u64(bcx, end_rip);
        emit_chain_or_exit(
            bcx,
            ctx_ptr,
            flags,
            gpr_vals,
            gpr_loaded,
            Some(gpr_dirty),
            *rflags_val,
            rflags_ptr,
            needs_flags,
            exit,
            exit_rip,
            chain_refs.get(&end_rip).copied(),
            lookup_ref,
            block_sig_ref,
        );
    }
    Ok(())
}

/// Single prologue guard: `[base+min_disp, base+max_end)` ⊆ pin and rights match.
fn emit_block_wide_stack_guard(
    bcx: &mut FunctionBuilder<'_>,
    pin: &HoistedPin,
    base: Value,
    plan: &BlockStackPinPlan,
) -> Value {
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    let min_d = iconst_u64(bcx, plan.min_disp as u64);
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    let max_e = iconst_u64(bcx, plan.max_end as u64);
    let lo = bcx.ins().iadd(base, min_d);
    let hi = bcx.ins().iadd(base, max_e);
    // Span must not wrap the address space.
    let no_wrap = bcx.ins().icmp(IntCC::UnsignedGreaterThanOrEqual, hi, lo);
    let lo_ok = bcx
        .ins()
        .icmp(IntCC::UnsignedGreaterThanOrEqual, lo, pin.guest_base);
    let hi_ok = bcx
        .ins()
        .icmp(IntCC::UnsignedLessThanOrEqual, hi, pin.guest_end);

    let mut need = 0_u64;
    if plan.needs_r {
        need |= TLB_PROT_R;
    }
    if plan.needs_w {
        need |= TLB_PROT_W;
    }
    let need_v = iconst_u64(bcx, need);
    let prot_bits = bcx.ins().band(pin.allow, need_v);
    let prot_ok = if need == 0 {
        bcx.ins().iconst(types::I8, 1)
    } else {
        bcx.ins().icmp(IntCC::Equal, prot_bits, need_v)
    };

    let ok1 = bcx.ins().band(pin.live, no_wrap);
    let ok2 = bcx.ins().band(ok1, lo_ok);
    let ok3 = bcx.ins().band(ok2, hi_ok);
    bcx.ins().band(ok3, prot_ok)
}

/// Load one pin slot into SSA once (block entry). Fields are invariant until
/// the next `run_compiled` (protect/free bumps gen and refills pins).
fn hoist_pin_slot(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    slot: usize,
) -> HoistedPin {
    let base_off = i64::from(OFF_PINS) + i64::from(PIN_STRIDE) * i64::try_from(slot).unwrap_or(0);
    let gb_p = bcx.ins().iadd_imm(ctx_ptr, base_off);
    let ge_p = bcx.ins().iadd_imm(ctx_ptr, base_off + 8);
    let hb_p = bcx.ins().iadd_imm(ctx_ptr, base_off + 16);
    let gen_p = bcx.ins().iadd_imm(ctx_ptr, base_off + 24);
    let allow_p = bcx.ins().iadd_imm(ctx_ptr, base_off + 32);
    let mem_gen_p = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_MEM_GEN));

    let guest_base = bcx.ins().load(types::I64, flags, gb_p, 0);
    let guest_end = bcx.ins().load(types::I64, flags, ge_p, 0);
    let host_base = bcx.ins().load(types::I64, flags, hb_p, 0);
    let pin_gen = bcx.ins().load(types::I64, flags, gen_p, 0);
    let allow = bcx.ins().load(types::I64, flags, allow_p, 0);
    let mem_gen = bcx.ins().load(types::I64, flags, mem_gen_p, 0);

    let base_nz = bcx.ins().icmp_imm(IntCC::NotEqual, host_base, 0);
    let gen_ok = bcx.ins().icmp(IntCC::Equal, pin_gen, mem_gen);
    let live = bcx.ins().band(base_nz, gen_ok);
    HoistedPin {
        guest_base,
        guest_end,
        host_base,
        allow,
        live,
    }
}

/// Bounds + R/W probe against a **hoisted** pin (no JitCtx reloads).
///
/// Soft translate: `host = host_base + (addr - guest_base)`.
fn hoisted_pin_probe(
    bcx: &mut FunctionBuilder<'_>,
    pin: &HoistedPin,
    addr: Value,
    size: u32,
    write: bool,
) -> (Value, Value) {
    let size_v = iconst_u64(bcx, u64::from(size));
    let end = bcx.ins().iadd(addr, size_v);
    let no_wrap = bcx.ins().icmp(IntCC::UnsignedGreaterThanOrEqual, end, addr);
    let lo_ok = bcx
        .ins()
        .icmp(IntCC::UnsignedGreaterThanOrEqual, addr, pin.guest_base);
    let hi_ok = bcx
        .ins()
        .icmp(IntCC::UnsignedLessThanOrEqual, end, pin.guest_end);
    let need = if write { TLB_PROT_W } else { TLB_PROT_R };
    let need_v = iconst_u64(bcx, need);
    let prot_bits = bcx.ins().band(pin.allow, need_v);
    let prot_ok = bcx.ins().icmp_imm(IntCC::NotEqual, prot_bits, 0);

    let ok1 = bcx.ins().band(pin.live, no_wrap);
    let ok2 = bcx.ins().band(ok1, lo_ok);
    let ok3 = bcx.ins().band(ok2, hi_ok);
    let ok = bcx.ins().band(ok3, prot_ok);

    let rel = bcx.ins().isub(addr, pin.guest_base);
    let host = bcx.ins().iadd(pin.host_base, rel);
    (ok, host)
}

/// Zero-extend a loaded integer of `size` bytes to i64.
fn load_guest_bytes(bcx: &mut FunctionBuilder<'_>, host: Value, size: u32) -> Value {
    // Sticky TLB guarantees a mapped host page; trust the pointer.
    let flags = MemFlagsData::trusted();
    match size {
        1 => {
            let v = bcx.ins().load(types::I8, flags, host, 0);
            bcx.ins().uextend(types::I64, v)
        }
        2 => {
            let v = bcx.ins().load(types::I16, flags, host, 0);
            bcx.ins().uextend(types::I64, v)
        }
        4 => {
            let v = bcx.ins().load(types::I32, flags, host, 0);
            bcx.ins().uextend(types::I64, v)
        }
        _ => bcx.ins().load(types::I64, flags, host, 0),
    }
}

fn store_guest_bytes(bcx: &mut FunctionBuilder<'_>, host: Value, size: u32, value: Value) {
    let flags = MemFlagsData::trusted();
    match size {
        1 => {
            let v = bcx.ins().ireduce(types::I8, value);
            bcx.ins().store(flags, v, host, 0);
        }
        2 => {
            let v = bcx.ins().ireduce(types::I16, value);
            bcx.ins().store(flags, v, host, 0);
        }
        4 => {
            let v = bcx.ins().ireduce(types::I32, value);
            bcx.ins().store(flags, v, host, 0);
        }
        _ => {
            bcx.ins().store(flags, value, host, 0);
        }
    }
}

fn call_load(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    gpr: &[Value; 16],
    rflags: Value,
    addr: Value,
    size: u32,
    insn_ip: u64,
) -> Result<Value, String> {
    let load_ref = mem.load_ref.ok_or("load helper missing")?;
    // `WIE_JIT_MEM=slow`: helper only (oracle / bisect).
    if !super::jit_mem_inline_enabled() {
        return Ok(emit_load_helper(
            bcx, mem, gpr, rflags, addr, size, insn_ip, load_ref,
        ));
    }

    // Block-wide super-fast path: entry guard already proved the whole access
    // range sits in the stack pin — emit a bare host load (no bounds IR).
    if let Some(super_s) = mem.super_stack {
        let host = bcx.ins().iadd(super_s.bias, addr);
        return Ok(load_guest_bytes(bcx, host, size));
    }

    // CFG-ordered probes (not `select`).
    // Order: stack → sticky → largest data pin → helper.
    // Sticky first keeps single-page streams free of pin-bounds IR; the data
    // pin catches multi-page thrash inside VirtualAlloc / heap after sticky miss.
    let merge = bcx.create_block();
    bcx.append_block_param(merge, types::I64);

    if let Some(ref pin) = mem.stack_pin {
        let (ok, host) = hoisted_pin_probe(bcx, pin, addr, size, false);
        let hit = bcx.create_block();
        let miss = bcx.create_block();
        bcx.ins().brif(ok, hit, &[], miss, &[]);
        bcx.switch_to_block(hit);
        bcx.seal_block(hit);
        let v = load_guest_bytes(bcx, host, size);
        bcx.ins().jump(merge, &[BlockArg::Value(v)]);
        bcx.switch_to_block(miss);
        bcx.seal_block(miss);
    }

    {
        let (ok, host) = sticky_tlb_probe(bcx, mem, addr, size, false);
        let hit = bcx.create_block();
        let miss = bcx.create_block();
        bcx.ins().brif(ok, hit, &[], miss, &[]);
        bcx.switch_to_block(hit);
        bcx.seal_block(hit);
        let v = load_guest_bytes(bcx, host, size);
        bcx.ins().jump(merge, &[BlockArg::Value(v)]);
        bcx.switch_to_block(miss);
        bcx.seal_block(miss);
    }

    for pin in &mem.data_pins {
        let (ok, host) = hoisted_pin_probe(bcx, pin, addr, size, false);
        let hit = bcx.create_block();
        let miss = bcx.create_block();
        bcx.ins().brif(ok, hit, &[], miss, &[]);
        bcx.switch_to_block(hit);
        bcx.seal_block(hit);
        let v = load_guest_bytes(bcx, host, size);
        bcx.ins().jump(merge, &[BlockArg::Value(v)]);
        bcx.switch_to_block(miss);
        bcx.seal_block(miss);
    }

    let slow_val = emit_load_helper(bcx, mem, gpr, rflags, addr, size, insn_ip, load_ref);
    bcx.ins().jump(merge, &[BlockArg::Value(slow_val)]);

    bcx.switch_to_block(merge);
    bcx.seal_block(merge);
    Ok(bcx.block_params(merge)[0])
}

fn emit_load_helper(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    gpr: &[Value; 16],
    rflags: Value,
    addr: Value,
    size: u32,
    insn_ip: u64,
    load_ref: FuncRef,
) -> Value {
    let size_v = bcx.ins().iconst(types::I64, i64::from(size));
    let ip_v = iconst_u64(bcx, insn_ip);
    let call = bcx.ins().call(load_ref, &[mem.ctx_ptr, addr, size_v, ip_v]);
    let slow_val = bcx.inst_results(call)[0];
    let fault_ptr = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_FAULT));
    let fault = bcx.ins().load(types::I64, mem.flags, fault_ptr, 0);
    let is_fault = bcx.ins().icmp_imm(IntCC::NotEqual, fault, 0);
    let cont = bcx.create_block();
    let args = exit_args(gpr, rflags);
    bcx.ins().brif(is_fault, mem.exit, &args, cont, &[]);
    bcx.switch_to_block(cont);
    bcx.seal_block(cont);
    slow_val
}

fn call_store(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    gpr: &[Value; 16],
    rflags: Value,
    addr: Value,
    size: u32,
    value: Value,
    insn_ip: u64,
) -> Result<(), String> {
    let store_ref = mem.store_ref.ok_or("store helper missing")?;
    if !super::jit_mem_inline_enabled() {
        emit_store_helper(bcx, mem, gpr, rflags, addr, size, value, insn_ip, store_ref);
        return Ok(());
    }

    // Block-wide super-fast path (see `call_load`).
    if let Some(super_s) = mem.super_stack {
        let host = bcx.ins().iadd(super_s.bias, addr);
        store_guest_bytes(bcx, host, size, value);
        return Ok(());
    }

    // Same CFG order as `call_load`: stack → sticky → data pin → helper.
    let merge = bcx.create_block();

    if let Some(ref pin) = mem.stack_pin {
        let (ok, host) = hoisted_pin_probe(bcx, pin, addr, size, true);
        let hit = bcx.create_block();
        let miss = bcx.create_block();
        bcx.ins().brif(ok, hit, &[], miss, &[]);
        bcx.switch_to_block(hit);
        bcx.seal_block(hit);
        store_guest_bytes(bcx, host, size, value);
        bcx.ins().jump(merge, &[]);
        bcx.switch_to_block(miss);
        bcx.seal_block(miss);
    }

    {
        let (ok, host) = sticky_tlb_probe(bcx, mem, addr, size, true);
        let hit = bcx.create_block();
        let miss = bcx.create_block();
        bcx.ins().brif(ok, hit, &[], miss, &[]);
        bcx.switch_to_block(hit);
        bcx.seal_block(hit);
        store_guest_bytes(bcx, host, size, value);
        bcx.ins().jump(merge, &[]);
        bcx.switch_to_block(miss);
        bcx.seal_block(miss);
    }

    for pin in &mem.data_pins {
        let (ok, host) = hoisted_pin_probe(bcx, pin, addr, size, true);
        let hit = bcx.create_block();
        let miss = bcx.create_block();
        bcx.ins().brif(ok, hit, &[], miss, &[]);
        bcx.switch_to_block(hit);
        bcx.seal_block(hit);
        store_guest_bytes(bcx, host, size, value);
        bcx.ins().jump(merge, &[]);
        bcx.switch_to_block(miss);
        bcx.seal_block(miss);
    }

    emit_store_helper(bcx, mem, gpr, rflags, addr, size, value, insn_ip, store_ref);
    bcx.ins().jump(merge, &[]);

    bcx.switch_to_block(merge);
    bcx.seal_block(merge);
    Ok(())
}

fn emit_store_helper(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    gpr: &[Value; 16],
    rflags: Value,
    addr: Value,
    size: u32,
    value: Value,
    insn_ip: u64,
    store_ref: FuncRef,
) {
    let size_v = bcx.ins().iconst(types::I64, i64::from(size));
    let ip_v = iconst_u64(bcx, insn_ip);
    bcx.ins()
        .call(store_ref, &[mem.ctx_ptr, addr, size_v, value, ip_v]);
    let fault_ptr = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_FAULT));
    let fault = bcx.ins().load(types::I64, mem.flags, fault_ptr, 0);
    let is_fault = bcx.ins().icmp_imm(IntCC::NotEqual, fault, 0);
    let cont = bcx.create_block();
    let args = exit_args(gpr, rflags);
    bcx.ins().brif(is_fault, mem.exit, &args, cont, &[]);
    bcx.switch_to_block(cont);
    bcx.seal_block(cont);
}

fn lower_mov(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let k0 = instr.op0_kind();
    let k1 = instr.op1_kind();
    let ip = instr.ip();
    match (k0, k1) {
        (OpKind::Register, OpKind::Memory) => {
            let addr = effective_addr(bcx, instr, gpr)?;
            let width = mem_width_bytes(instr)?;
            let val = call_load(bcx, mem, gpr, rflags, addr, width, ip)?;
            write_gpr(bcx, gpr, dirty, instr.op_register(0), val)
        }
        (OpKind::Memory, OpKind::Register) => {
            let addr = effective_addr(bcx, instr, gpr)?;
            let width = mem_width_bytes(instr)?;
            let val = read_gpr(gpr, instr.op_register(1))?;
            call_store(bcx, mem, gpr, rflags, addr, width, val, ip)
        }
        (OpKind::Memory, _) => {
            let addr = effective_addr(bcx, instr, gpr)?;
            let width = mem_width_bytes(instr)?;
            let val = read_op(bcx, instr, 1, gpr)?;
            call_store(bcx, mem, gpr, rflags, addr, width, val, ip)
        }
        (OpKind::Register, _) => {
            let src = read_op(bcx, instr, 1, gpr)?;
            write_gpr(bcx, gpr, dirty, instr.op_register(0), src)
        }
        _ => Err("mov form".into()),
    }
}

fn lower_movx(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    signed: bool,
) -> Result<(), String> {
    let src_bits = if instr.op1_kind() == OpKind::Memory {
        mem_width_bytes(instr)?.saturating_mul(8)
    } else {
        reg_size_bits(instr.op_register(1))
    };
    let src = if instr.op1_kind() == OpKind::Memory {
        let addr = effective_addr(bcx, instr, gpr)?;
        let width = mem_width_bytes(instr)?;
        call_load(bcx, mem, gpr, rflags, addr, width, instr.ip())?
    } else {
        read_gpr(gpr, instr.op_register(1))?
    };
    let val = extend_value(bcx, src, src_bits, signed);
    write_gpr(bcx, gpr, dirty, instr.op_register(0), val)
}

fn extend_value(bcx: &mut FunctionBuilder<'_>, src: Value, src_bits: u32, signed: bool) -> Value {
    if signed {
        match src_bits {
            8 => {
                let t = bcx.ins().ireduce(types::I8, src);
                bcx.ins().sextend(types::I64, t)
            }
            16 => {
                let t = bcx.ins().ireduce(types::I16, src);
                bcx.ins().sextend(types::I64, t)
            }
            32 => {
                let t = bcx.ins().ireduce(types::I32, src);
                bcx.ins().sextend(types::I64, t)
            }
            _ => src,
        }
    } else {
        match src_bits {
            8 => {
                let m = bcx.ins().iconst(types::I64, 0xff);
                bcx.ins().band(src, m)
            }
            16 => {
                let m = bcx.ins().iconst(types::I64, 0xffff);
                bcx.ins().band(src, m)
            }
            32 => {
                let m = bcx.ins().iconst(types::I64, 0xffff_ffff);
                bcx.ins().band(src, m)
            }
            _ => src,
        }
    }
}

/// Cwde: sign-extend AX (16-bit) to EAX (32-bit).
/// Cdqe: sign-extend EAX (32-bit) to RAX (64-bit).
/// Both are implicit-accumulator, register-only operations.
fn lower_cwde_cdqe(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
) -> Result<(), String> {
    let rax = gpr[0]; // RAX
    let val = if instr.mnemonic() == Mnemonic::Cwde {
        // Cwde: sign-extend AX (bottom 16 bits) to 32-bit EAX (bottom 32 bits).
        // Read RAX, ireduce to I16, sextend to I64 (which zeros upper 32 bits
        // in Cranelift's 64-bit representation), then mask into RAX.
        let low16 = bcx.ins().ireduce(types::I16, rax);
        let ext = bcx.ins().sextend(types::I64, low16);
        // Merge: keep RAX[63:32] unchanged, replace RAX[31:0] with ext[31:0].
        // Since ext is sign-extended, its upper 32 bits are copies of bit 31.
        // But x86 Cwde zero-extends into EAX (upper 32 bits of RAX unchanged).
        // Actually on x86-64, Cwde writes to EAX which zero-extends to RAX.
        // So RAX = zero_extend(sign_extend(AX)).
        ext
    } else {
        // Cdqe: sign-extend EAX (bottom 32 bits) to RAX (full 64 bits).
        // On x86-64, Cdqe writes to RAX (full 64-bit dest).
        let low32 = bcx.ins().ireduce(types::I32, rax);
        bcx.ins().sextend(types::I64, low32)
    };
    write_gpr(bcx, gpr, dirty, Register::RAX, val)
}

/// Cbw: sign-extend AL → AX (upper bytes of RAX unchanged above AX).
fn lower_cbw(
    bcx: &mut FunctionBuilder<'_>,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
) -> Result<(), String> {
    let rax = gpr[0];
    let al = bcx.ins().ireduce(types::I8, rax);
    let ax = bcx.ins().sextend(types::I16, al);
    let ax64 = bcx.ins().uextend(types::I64, ax);
    write_gpr(bcx, gpr, dirty, Register::AX, ax64)
}

/// Cwd: sign-extend AX → DX:AX (write DX only; AX unchanged).
fn lower_cwd(
    bcx: &mut FunctionBuilder<'_>,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
) -> Result<(), String> {
    let rax = gpr[0];
    let ax = bcx.ins().ireduce(types::I16, rax);
    // DX = 0xFFFF if AX < 0, else 0.
    let ax_s = bcx.ins().sextend(types::I32, ax);
    let is_neg = bcx.ins().icmp_imm(IntCC::SignedLessThan, ax_s, 0);
    let ffff = iconst_u64(bcx, 0xffff);
    let zero = iconst_u64(bcx, 0);
    let dx = bcx.ins().select(is_neg, ffff, zero);
    write_gpr(bcx, gpr, dirty, Register::DX, dx)
}

/// Bswap r32/r64: reverse bytes. r32 write zero-extends into the full GPR.
fn lower_bswap(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
) -> Result<(), String> {
    let reg = instr.op_register(0);
    let bits = reg_size_bits(reg);
    let val = read_gpr(gpr, reg)?;
    let swapped = match bits {
        32 => {
            let lo = bcx.ins().ireduce(types::I32, val);
            let s = bcx.ins().bswap(lo);
            bcx.ins().uextend(types::I64, s)
        }
        64 => bcx.ins().bswap(val),
        _ => return Err(format!("bswap size {bits}")),
    };
    write_gpr(bcx, gpr, dirty, reg, swapped)
}

/// Leave: RSP ← RBP; RBP ← [RSP]; RSP += 8 (pop frame).
fn lower_leave(
    bcx: &mut FunctionBuilder<'_>,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    ip: u64,
) -> Result<(), String> {
    // MOV RSP, RBP
    gpr[4] = gpr[5];
    mark_dirty(dirty, 4);
    // POP RBP
    let rsp = gpr[4];
    let val = call_load(bcx, mem, gpr, rflags, rsp, 8, ip)?;
    let new_rsp = bcx.ins().iadd_imm(rsp, 8);
    gpr[4] = new_rsp;
    mark_dirty(dirty, 4);
    gpr[5] = val;
    mark_dirty(dirty, 5);
    Ok(())
}

/// Pushfq: push full RFLAGS (64-bit) onto the stack.
fn lower_pushfq(
    bcx: &mut FunctionBuilder<'_>,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    ip: u64,
) -> Result<(), String> {
    let rsp = gpr[4];
    let new_rsp = bcx.ins().iadd_imm(rsp, -8);
    call_store(bcx, mem, gpr, rflags, new_rsp, 8, rflags, ip)?;
    gpr[4] = new_rsp;
    mark_dirty(dirty, 4);
    Ok(())
}

/// Popfq: pop into RFLAGS; force reserved bit 1 (ALWAYS1).
fn lower_popfq(
    bcx: &mut FunctionBuilder<'_>,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    mem: &mut MemEnv,
    ip: u64,
) -> Result<(), String> {
    let rsp = gpr[4];
    let val = call_load(bcx, mem, gpr, *rflags, rsp, 8, ip)?;
    let new_rsp = bcx.ins().iadd_imm(rsp, 8);
    gpr[4] = new_rsp;
    mark_dirty(dirty, 4);
    // Keep ALWAYS1 set; clear it first then OR so the bit is definite.
    let cleared = clear_flags(bcx, val, rflags::ALWAYS1);
    let always1 = iconst_u64(bcx, rflags::ALWAYS1);
    *rflags = bcx.ins().bor(cleared, always1);
    Ok(())
}

fn lower_lea(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
) -> Result<(), String> {
    let addr = effective_addr(bcx, instr, gpr)?;
    write_gpr(bcx, gpr, dirty, instr.op_register(0), addr)
}

/// 64-bit push (Intel: value of RSP before decrement is what `push rsp` stores).
fn lower_push(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let size = 8_u32;
    let val = match instr.op0_kind() {
        OpKind::Register => read_gpr(gpr, instr.op_register(0))?,
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            let width = mem_width_bytes(instr)?;
            call_load(bcx, mem, gpr, rflags, addr, width, instr.ip())?
        }
        _ => read_imm(bcx, instr, 0),
    };
    let rsp = gpr[4];
    let new_rsp = bcx.ins().iadd_imm(rsp, -i64::from(size));
    call_store(bcx, mem, gpr, rflags, new_rsp, size, val, instr.ip())?;
    gpr[4] = new_rsp;
    mark_dirty(dirty, 4);
    Ok(())
}

fn lower_pop(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let size = 8_u32;
    let rsp = gpr[4];
    let val = call_load(bcx, mem, gpr, rflags, rsp, size, instr.ip())?;
    let new_rsp = bcx.ins().iadd_imm(rsp, i64::from(size));
    gpr[4] = new_rsp;
    mark_dirty(dirty, 4);
    match instr.op0_kind() {
        OpKind::Register => {
            // pop rsp: write the popped value (already advanced rsp).
            write_gpr(bcx, gpr, dirty, instr.op_register(0), val)
        }
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            let width = mem_width_bytes(instr)?;
            call_store(bcx, mem, gpr, rflags, addr, width, val, instr.ip())
        }
        _ => Err("pop form".into()),
    }
}

/// Lazy ALU: defer flag packing; overwrite previous pending (last writer wins).
fn lower_arith_lazy(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    pending: &mut PendingFlags,
    mem: &mut MemEnv,
    op: Arith,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let a_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let b_raw = read_op_mem(bcx, instr, 1, gpr, *rflags, mem)?;
    let a = mask_width(bcx, a_raw, bits);
    let b = mask_width(bcx, b_raw, bits);
    let res = match op {
        Arith::Add => bcx.ins().iadd(a, b),
        Arith::Sub => bcx.ins().isub(a, b),
        Arith::Xor => bcx.ins().bxor(a, b),
        Arith::And => bcx.ins().band(a, b),
        Arith::Or => bcx.ins().bor(a, b),
        Arith::Adc | Arith::Sbb => return Err("lazy path only for non-carry ALU".into()),
    };
    let res_m = mask_width(bcx, res, bits);
    write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, res_m, bits)?;
    *pending = match op {
        Arith::Add => PendingFlags::Add {
            a,
            b,
            res: res_m,
            bits,
        },
        Arith::Sub => PendingFlags::Sub {
            a,
            b,
            res: res_m,
            bits,
        },
        Arith::Xor | Arith::And | Arith::Or => PendingFlags::Logic { res: res_m, bits },
        Arith::Adc | Arith::Sbb => PendingFlags::None,
    };
    Ok(())
}

fn lower_cmp_test_lazy(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: &mut Value,
    pending: &mut PendingFlags,
    mem: &mut MemEnv,
    is_cmp: bool,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let a_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let b_raw = read_op_mem(bcx, instr, 1, gpr, *rflags, mem)?;
    let a = mask_width(bcx, a_raw, bits);
    let b = mask_width(bcx, b_raw, bits);
    if is_cmp {
        let res_raw = bcx.ins().isub(a, b);
        let res = mask_width(bcx, res_raw, bits);
        *pending = PendingFlags::Sub { a, b, res, bits };
    } else {
        let res_raw = bcx.ins().band(a, b);
        let res = mask_width(bcx, res_raw, bits);
        *pending = PendingFlags::Logic { res, bits };
    }
    Ok(())
}

/// Eager ALU (adc/sbb): needs live CF from flushed flags.
fn lower_arith(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    mem: &mut MemEnv,
    op: Arith,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let a_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let b_raw = read_op_mem(bcx, instr, 1, gpr, *rflags, mem)?;
    let a = mask_width(bcx, a_raw, bits);
    let b = mask_width(bcx, b_raw, bits);
    let cf_val = flag_bit(bcx, *rflags, rflags::CF);
    let res = match op {
        Arith::Add => bcx.ins().iadd(a, b),
        Arith::Adc => {
            let t = bcx.ins().iadd(a, b);
            bcx.ins().iadd(t, cf_val)
        }
        Arith::Sub => bcx.ins().isub(a, b),
        Arith::Sbb => {
            let t = bcx.ins().isub(a, b);
            bcx.ins().isub(t, cf_val)
        }
        Arith::Xor => bcx.ins().bxor(a, b),
        Arith::And => bcx.ins().band(a, b),
        Arith::Or => bcx.ins().bor(a, b),
    };
    let res_m = mask_width(bcx, res, bits);
    write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, res_m, bits)?;
    *rflags = match op {
        Arith::Xor | Arith::And | Arith::Or => flags_logic(bcx, *rflags, res_m, bits),
        Arith::Add => flags_add(bcx, *rflags, a, b, res_m, bits),
        Arith::Adc => flags_adc(bcx, *rflags, a, b, cf_val, res_m, bits),
        Arith::Sub => flags_sub(bcx, *rflags, a, b, res_m, bits),
        Arith::Sbb => flags_sbb(bcx, *rflags, a, b, cf_val, res_m, bits),
    };
    Ok(())
}

/// SBB flags: match iced full-width borrow CF (do not mask `s+cf` before CF test).
fn flags_sbb(
    bcx: &mut FunctionBuilder<'_>,
    old: Value,
    d: Value,
    s: Value,
    cf: Value,
    result: Value,
    bits: u32,
) -> Value {
    // Base ZF/SF/PF/AF/OF from (d - s) then correct CF/OF for carry-in.
    let mut f = flags_sub(bcx, old, d, s, result, bits);
    // CF = d < s + cf (full width; s+cf may exceed operand size).
    let s_plus_cf = bcx.ins().iadd(s, cf);
    let cf_b = if bits >= 64 {
        // For 64-bit: overflow of s+cf means always borrow; else d < s+cf.
        let c_ov = bcx.ins().icmp(IntCC::UnsignedLessThan, s_plus_cf, s); // s+cf wrapped
        let c_lt = bcx.ins().icmp(IntCC::UnsignedLessThan, d, s_plus_cf);
        let c_ovi = bool_to_i64(bcx, c_ov);
        let c_lti = bool_to_i64(bcx, c_lt);
        let any = bcx.ins().bor(c_ovi, c_lti);
        let zero = iconst_u64(bcx, 0);
        bcx.ins().icmp(IntCC::NotEqual, any, zero)
    } else {
        // `s`/`d` masked to operand width; `s+cf` may be 2^bits — then CF is always set.
        bcx.ins().icmp(IntCC::UnsignedLessThan, d, s_plus_cf)
    };
    // For bits < 64, s_plus_cf may have bits above `bits` set (when s=mask and cf=1).
    // `d` is masked so d < s_plus_cf is correct when s_plus_cf > mask.
    let cf_on = select_flag(bcx, cf_b, rflags::CF);
    f = replace_flag(bcx, f, rflags::CF, cf_on);
    f
}

/// ADC flags: match iced `set_add_flags(d, s+cf, result)` then CF from wide add.
fn flags_adc(
    bcx: &mut FunctionBuilder<'_>,
    old: Value,
    d: Value,
    s: Value,
    cf: Value,
    result: Value,
    bits: u32,
) -> Value {
    let s_eff = bcx.ins().iadd(s, cf);
    let s_eff_m = mask_width(bcx, s_eff, bits);
    let mut f = flags_add(bcx, old, d, s_eff_m, result, bits);
    if bits >= 64 {
        let sum_ds = bcx.ins().iadd(d, s);
        let c1 = bcx.ins().icmp(IntCC::UnsignedLessThan, sum_ds, d);
        let sum = bcx.ins().iadd(sum_ds, cf);
        let c2 = bcx.ins().icmp(IntCC::UnsignedLessThan, sum, sum_ds);
        let c1i = bool_to_i64(bcx, c1);
        let c2i = bool_to_i64(bcx, c2);
        let any = bcx.ins().bor(c1i, c2i);
        let zero = iconst_u64(bcx, 0);
        let any_b = bcx.ins().icmp(IntCC::NotEqual, any, zero);
        let cf_on = select_flag(bcx, any_b, rflags::CF);
        f = replace_flag(bcx, f, rflags::CF, cf_on);
    } else {
        let t = bcx.ins().iadd(d, s);
        let sum = bcx.ins().iadd(t, cf);
        let sh = iconst_u64(bcx, u64::from(bits));
        let shifted = bcx.ins().ushr(sum, sh);
        let zero = iconst_u64(bcx, 0);
        let cf_b = bcx.ins().icmp(IntCC::NotEqual, shifted, zero);
        let cf_on = select_flag(bcx, cf_b, rflags::CF);
        f = replace_flag(bcx, f, rflags::CF, cf_on);
    }
    f
}

fn lower_imul(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let nops = instr.op_count();
    let bits = op_width_bits(instr, 0)?;
    let (a_raw, b_raw) = match nops {
        2 => (
            read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?,
            read_op_mem(bcx, instr, 1, gpr, *rflags, mem)?,
        ),
        3 => (
            read_op_mem(bcx, instr, 1, gpr, *rflags, mem)?,
            read_imm(bcx, instr, 2),
        ),
        _ => return Err(format!("imul {nops} ops")),
    };
    let a_m = mask_width(bcx, a_raw, bits);
    let b_m = mask_width(bcx, b_raw, bits);
    let a = sext_to_i64(bcx, a_m, bits);
    let b = sext_to_i64(bcx, b_m, bits);
    let (lo, overflow) = if bits >= 64 {
        let lo = bcx.ins().imul(a, b);
        let hi = bcx.ins().smulhi(a, b);
        let sh = iconst_u64(bcx, 63);
        let sign = bcx.ins().sshr(lo, sh);
        let ov = bcx.ins().icmp(IntCC::NotEqual, hi, sign);
        (lo, ov)
    } else {
        let product = bcx.ins().imul(a, b);
        let lo = mask_width(bcx, product, bits);
        let expected = sext_to_i64(bcx, lo, bits);
        let ov = bcx.ins().icmp(IntCC::NotEqual, product, expected);
        (lo, ov)
    };
    write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, lo, bits)?;
    let cf_on = select_flag(bcx, overflow, rflags::CF);
    let of_on = select_flag(bcx, overflow, rflags::OF);
    let f = replace_flag(bcx, *rflags, rflags::CF, cf_on);
    *rflags = replace_flag(bcx, f, rflags::OF, of_on);
    Ok(())
}

/// Lower Bt/Bts/Btr/Btc (bit test / set / reset / complement) with direct flag write.
/// Flushes pending flags first, then reads the dest, computes the bit,
/// sets CF in rflags, and for Bts/Btr/Btc writes the modified value back.
///
/// Note: register forms mask the bit index by operand width. Memory forms use the
/// same simple EA+width path as the rest of the ALU JIT (full bit-string address
/// with large signed offsets remains on the iced path when not lowerable).
fn lower_bit_test_op(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let val_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let val = mask_width(bcx, val_raw, bits);

    // Compute bit index from operand 1 (register or immediate).
    let bit_idx = if instr.op1_kind() == OpKind::Register {
        let idx_raw = read_gpr(gpr, instr.op_register(1))?;
        mask_width(bcx, idx_raw, 32) // x86 masks to 5/6/7 bits depending on size
    } else {
        let imm = read_imm(bcx, instr, 1);
        mask_width(bcx, imm, 32)
    };

    // Mask bit index by operand size (x86: 5 bits for 32-bit, 6 for 64-bit).
    let max_bits = if bits == 64 {
        iconst_u64(bcx, 63)
    } else {
        iconst_u64(bcx, 31) // 32-bit: 5-bit mask
    };
    let idx_masked = bcx.ins().band(bit_idx, max_bits);

    // Compute the bit value at `idx_masked` -> CF = (val >> idx_masked) & 1
    let shifted = bcx.ins().ushr(val, idx_masked);
    let one = iconst_u64(bcx, 1);
    let bit_val = bcx.ins().band(shifted, one);
    let is_set = bcx.ins().icmp_imm(IntCC::NotEqual, bit_val, 0);
    let cf_on = select_flag(bcx, is_set, rflags::CF);
    *rflags = replace_flag(bcx, *rflags, rflags::CF, cf_on);

    // For Bts/Btr/Btc, write back the modified value.
    let mnemonic = instr.mnemonic();
    if matches!(mnemonic, Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc) {
        let bit_mask = bcx.ins().ishl(one, idx_masked);
        let new_val = if mnemonic == Mnemonic::Bts {
            // Set the bit: val | (1 << idx)
            bcx.ins().bor(val, bit_mask)
        } else if mnemonic == Mnemonic::Btr {
            // Clear the bit: val & !(1 << idx)
            let not_mask = bcx.ins().bnot(bit_mask);
            bcx.ins().band(val, not_mask)
        } else {
            // Complement the bit: val ^ (1 << idx)
            bcx.ins().bxor(val, bit_mask)
        };
        let new_val_full = if bits < 64 {
            // Preserve upper bits of the full register/mem cell when partial.
            let full_mask = iconst_u64(bcx, (1_u64 << bits) - 1);
            let not_full = bcx.ins().bnot(full_mask);
            let cleared = bcx.ins().band(val_raw, not_full);
            bcx.ins().bor(cleared, new_val)
        } else {
            new_val
        };
        write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, new_val_full, bits)?;
    }

    Ok(())
}

/// Lower Xadd (exchange and add): temp = dst; dst = dst + src; src = temp.
/// Sets ADD flags. Flushes pending flags before operation.
fn lower_xadd(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let dst_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let src_raw = read_op_mem(bcx, instr, 1, gpr, *rflags, mem)?;
    let dst_val = mask_width(bcx, dst_raw, bits);
    let src_val = mask_width(bcx, src_raw, bits);

    // sum = dst + src (for flags)
    let sum = if bits == 64 {
        bcx.ins().iadd(dst_val, src_val)
    } else {
        let d = bcx.ins().ireduce(types::I32, dst_val);
        let s = bcx.ins().ireduce(types::I32, src_val);
        bcx.ins().iadd(d, s)
    };
    let sum_ext = sext_to_i64(bcx, sum, bits.min(32));

    // Write sum to dst (operand 0)
    write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, sum_ext, bits)?;

    // Write original dst to src (operand 1) — src is always a register
    write_gpr(bcx, gpr, dirty, instr.op_register(1), dst_val)?;

    // Set ADD flags
    *rflags = flags_add(bcx, *rflags, dst_val, src_val, sum_ext, bits.min(32));
    Ok(())
}

/// Lower CmpXchg (compare and exchange):
/// Compare dst with accumulator (AL/AX/EAX/RAX). If equal, dst = src, else accumulator = dst.
/// Sets ZF based on the comparison. Flushes pending flags before operation.
fn lower_cmpxchg(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let dst_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let dst_val = mask_width(bcx, dst_raw, bits);
    let src_val = read_gpr(gpr, instr.op_register(1))?;
    let acc_val = mask_width(bcx, gpr[0], bits); // RAX/EAX/AX/AL

    // Compare dst with acc: ZF = (dst == acc)
    let eq = bcx.ins().icmp(IntCC::Equal, dst_val, acc_val);

    // Compute result: if equal, new_dst = src, else accumulator = dst
    let new_dst = bcx.ins().select(eq, src_val, dst_val);

    // Write to dst
    write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, new_dst, bits)?;

    // Write to accumulator (RAX) when not equal
    let old_rax = gpr[0];
    let ext_dst = sext_to_i64(bcx, dst_val, bits);
    let new_rax = bcx.ins().select(eq, old_rax, ext_dst);
    write_gpr(bcx, gpr, dirty, Register::RAX, new_rax)?;

    // Set ZF based on comparison
    let zf_on = select_flag(bcx, eq, rflags::ZF);
    *rflags = replace_flag(bcx, *rflags, rflags::ZF, zf_on);
    // Architectural: CF, OF, SF, AF, PF may be set based on the comparison but
    // Intel docs mark them as undefined for CmpXchg.
    Ok(())
}

/// Lower Bsr (bit scan reverse): scan src for most significant 1 bit.
/// If src == 0: ZF=1, dst undefined.
/// If src != 0: ZF=0, dst = index of most significant set bit.
fn lower_bsr(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 1)?;
    let src_raw = read_op_mem(bcx, instr, 1, gpr, *rflags, mem)?;
    let src_val = mask_width(bcx, src_raw, bits);

    // Use Cranelift ctlz (count leading zeros) to find MSB position.
    // Bsr result = bit_width - 1 - ctlz(val) when val != 0
    let bit_width: u32 = if bits <= 32 { 32 } else { 64 };
    let src_ext = if bits < 64 {
        if bits <= 32 {
            let reduced = bcx.ins().ireduce(types::I32, src_val);
            bcx.ins().uextend(types::I64, reduced)
        } else {
            src_val
        }
    } else {
        src_val
    };

    let bw_val = iconst_u64(bcx, u64::from(bit_width.saturating_sub(1)));
    let clz = bcx.ins().clz(src_ext);
    let msb = bcx.ins().isub(bw_val, clz);

    // ZF = (src == 0)
    let zero_c = iconst_u64(bcx, 0);
    let is_zero = bcx.ins().icmp(IntCC::Equal, src_ext, zero_c);

    // Result: if zero, undefined (write 0); else write MSB index
    let result = bcx.ins().select(is_zero, zero_c, msb);
    write_gpr(bcx, gpr, dirty, instr.op_register(0), result)?;

    // Set ZF flag
    let zf_on = select_flag(bcx, is_zero, rflags::ZF);
    *rflags = replace_flag(bcx, *rflags, rflags::ZF, zf_on);
    Ok(())
}

fn lower_xchg(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let k0 = instr.op0_kind();
    let k1 = instr.op1_kind();
    match (k0, k1) {
        (OpKind::Register, OpKind::Register) => {
            let r0 = instr.op_register(0);
            let r1 = instr.op_register(1);
            let v0 = read_gpr(gpr, r0)?;
            let v1 = read_gpr(gpr, r1)?;
            write_gpr(bcx, gpr, dirty, r0, v1)?;
            write_gpr(bcx, gpr, dirty, r1, v0)
        }
        (OpKind::Register, OpKind::Memory) | (OpKind::Memory, OpKind::Register) => {
            let reg = if k0 == OpKind::Register {
                instr.op_register(0)
            } else {
                instr.op_register(1)
            };
            let bits = reg_size_bits(reg);
            let width = match bits {
                8 => 1_u32,
                16 => 2,
                32 => 4,
                64 => 8,
                other => return Err(format!("xchg bits {other}")),
            };
            let addr = effective_addr(bcx, instr, gpr)?;
            let mem_v = call_load(bcx, mem, gpr, rflags, addr, width, instr.ip())?;
            let reg_v = read_gpr(gpr, reg)?;
            write_gpr(bcx, gpr, dirty, reg, mem_v)?;
            call_store(bcx, mem, gpr, rflags, addr, width, reg_v, instr.ip())
        }
        _ => Err("xchg form".into()),
    }
}

fn write_op_mem(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    op: u32,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
    val: Value,
    bits: u32,
) -> Result<(), String> {
    match instr.op_kind(op) {
        OpKind::Register => write_gpr(bcx, gpr, dirty, instr.op_register(op), val),
        OpKind::Memory => {
            let addr = effective_addr(bcx, instr, gpr)?;
            let width = match bits {
                8 => 1_u32,
                16 => 2,
                32 => 4,
                64 => 8,
                other => return Err(format!("bad store bits {other}")),
            };
            call_store(bcx, mem, gpr, rflags, addr, width, val, instr.ip())
        }
        _ => Err("write op form".into()),
    }
}

fn lower_inc_dec_lazy(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    pending: &mut PendingFlags,
    mem: &mut MemEnv,
    inc: bool,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let a_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let a = mask_width(bcx, a_raw, bits);
    let one = bcx.ins().iconst(types::I64, 1);
    let res_raw = if inc {
        bcx.ins().iadd(a, one)
    } else {
        bcx.ins().isub(a, one)
    };
    let res = mask_width(bcx, res_raw, bits);
    write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, res, bits)?;
    *pending = if inc {
        PendingFlags::Inc { a, res, bits }
    } else {
        PendingFlags::Dec { a, res, bits }
    };
    Ok(())
}

fn lower_not(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let a_raw = read_op_mem(bcx, instr, 0, gpr, rflags, mem)?;
    let a = mask_width(bcx, a_raw, bits);
    let not_a = bcx.ins().bnot(a);
    let res = mask_width(bcx, not_a, bits);
    write_op_mem(bcx, instr, 0, gpr, dirty, rflags, mem, res, bits)
}

fn lower_neg_lazy(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    dirty: &mut [bool; 16],
    rflags: &mut Value,
    pending: &mut PendingFlags,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let a_raw = read_op_mem(bcx, instr, 0, gpr, *rflags, mem)?;
    let a = mask_width(bcx, a_raw, bits);
    let zero = bcx.ins().iconst(types::I64, 0);
    let sub = bcx.ins().isub(zero, a);
    let res = mask_width(bcx, sub, bits);
    write_op_mem(bcx, instr, 0, gpr, dirty, *rflags, mem, res, bits)?;
    // NEG is 0 - a (SUB flags).
    *pending = PendingFlags::Sub {
        a: zero,
        b: a,
        res,
        bits,
    };
    Ok(())
}

// --- RFLAGS (match `regs::set_*_flags`) ---

fn iconst_u64(bcx: &mut FunctionBuilder<'_>, v: u64) -> Value {
    bcx.ins()
        .iconst(types::I64, i64::from_ne_bytes(v.to_ne_bytes()))
}

fn mask_width(bcx: &mut FunctionBuilder<'_>, v: Value, bits: u32) -> Value {
    if bits >= 64 {
        return v;
    }
    let m = if bits == 32 {
        0xffff_ffff_u64
    } else if bits == 16 {
        0xffff
    } else {
        0xff
    };
    let mv = iconst_u64(bcx, m);
    bcx.ins().band(v, mv)
}

fn sign_bit(bits: u32) -> u64 {
    1_u64 << bits.saturating_sub(1).min(63)
}

fn flag_bit(bcx: &mut FunctionBuilder<'_>, flags: Value, bit: u64) -> Value {
    let m = iconst_u64(bcx, bit);
    bcx.ins().band(flags, m)
}

fn replace_flag(bcx: &mut FunctionBuilder<'_>, flags: Value, bit: u64, on: Value) -> Value {
    let clear = iconst_u64(bcx, !bit);
    let base = bcx.ins().band(flags, clear);
    bcx.ins().bor(base, on)
}

fn select_flag(bcx: &mut FunctionBuilder<'_>, cond: Value, bit: u64) -> Value {
    let bit_v = iconst_u64(bcx, bit);
    let zero = iconst_u64(bcx, 0);
    bcx.ins().select(cond, bit_v, zero)
}

fn pf_flag(bcx: &mut FunctionBuilder<'_>, result: Value) -> Value {
    let mut x = mask_width(bcx, result, 8);
    let s4 = bcx.ins().ushr_imm(x, 4);
    x = bcx.ins().bxor(x, s4);
    let s2 = bcx.ins().ushr_imm(x, 2);
    x = bcx.ins().bxor(x, s2);
    let s1 = bcx.ins().ushr_imm(x, 1);
    x = bcx.ins().bxor(x, s1);
    let one = iconst_u64(bcx, 1);
    let odd = bcx.ins().band(x, one);
    let is_even = bcx.ins().icmp_imm(IntCC::Equal, odd, 0);
    select_flag(bcx, is_even, rflags::PF)
}

fn clear_flags(bcx: &mut FunctionBuilder<'_>, old: Value, bits: u64) -> Value {
    let m = iconst_u64(bcx, !bits);
    bcx.ins().band(old, m)
}

fn flags_zs_pf(bcx: &mut FunctionBuilder<'_>, old: Value, result: Value, bits: u32) -> Value {
    let r = mask_width(bcx, result, bits);
    let f = clear_flags(bcx, old, rflags::ZF | rflags::SF | rflags::PF);
    let is_z = bcx.ins().icmp_imm(IntCC::Equal, r, 0);
    let zf = select_flag(bcx, is_z, rflags::ZF);
    let sb = iconst_u64(bcx, sign_bit(bits));
    let sign = bcx.ins().band(r, sb);
    let is_s = bcx.ins().icmp_imm(IntCC::NotEqual, sign, 0);
    let sf = select_flag(bcx, is_s, rflags::SF);
    let pf = pf_flag(bcx, r);
    let f = bcx.ins().bor(f, zf);
    let f = bcx.ins().bor(f, sf);
    bcx.ins().bor(f, pf)
}

fn flags_logic(bcx: &mut FunctionBuilder<'_>, old: Value, result: Value, bits: u32) -> Value {
    let f = clear_flags(
        bcx,
        old,
        rflags::ZF | rflags::SF | rflags::PF | rflags::CF | rflags::OF,
    );
    flags_zs_pf(bcx, f, result, bits)
}

fn flags_add(
    bcx: &mut FunctionBuilder<'_>,
    old: Value,
    dst: Value,
    src: Value,
    result: Value,
    bits: u32,
) -> Value {
    let d = mask_width(bcx, dst, bits);
    let s = mask_width(bcx, src, bits);
    let r = mask_width(bcx, result, bits);
    let f = clear_flags(
        bcx,
        old,
        rflags::CF | rflags::ZF | rflags::SF | rflags::PF | rflags::OF | rflags::AF,
    );
    let cf_cond = bcx.ins().icmp(IntCC::UnsignedLessThan, r, d);
    let cf = select_flag(bcx, cf_cond, rflags::CF);
    let f = bcx.ins().bor(f, cf);
    let f = flags_zs_pf(bcx, f, r, bits);
    let sb = iconst_u64(bcx, sign_bit(bits));
    let dr = bcx.ins().bxor(d, r);
    let sr = bcx.ins().bxor(s, r);
    let both = bcx.ins().band(dr, sr);
    let of_bits = bcx.ins().band(both, sb);
    let of_cond = bcx.ins().icmp_imm(IntCC::NotEqual, of_bits, 0);
    let of = select_flag(bcx, of_cond, rflags::OF);
    let f = bcx.ins().bor(f, of);
    let x = bcx.ins().bxor(d, s);
    let y = bcx.ins().bxor(x, r);
    let ten = iconst_u64(bcx, 0x10);
    let af_b = bcx.ins().band(y, ten);
    let af_cond = bcx.ins().icmp_imm(IntCC::NotEqual, af_b, 0);
    let af = select_flag(bcx, af_cond, rflags::AF);
    bcx.ins().bor(f, af)
}

fn flags_sub(
    bcx: &mut FunctionBuilder<'_>,
    old: Value,
    dst: Value,
    src: Value,
    result: Value,
    bits: u32,
) -> Value {
    let d = mask_width(bcx, dst, bits);
    let s = mask_width(bcx, src, bits);
    let r = mask_width(bcx, result, bits);
    let f = clear_flags(
        bcx,
        old,
        rflags::CF | rflags::ZF | rflags::SF | rflags::PF | rflags::OF | rflags::AF,
    );
    let cf_cond = bcx.ins().icmp(IntCC::UnsignedLessThan, d, s);
    let cf = select_flag(bcx, cf_cond, rflags::CF);
    let f = bcx.ins().bor(f, cf);
    let f = flags_zs_pf(bcx, f, r, bits);
    let sb = iconst_u64(bcx, sign_bit(bits));
    let ds = bcx.ins().bxor(d, s);
    let dr = bcx.ins().bxor(d, r);
    let both = bcx.ins().band(ds, dr);
    let of_bits = bcx.ins().band(both, sb);
    let of_cond = bcx.ins().icmp_imm(IntCC::NotEqual, of_bits, 0);
    let of = select_flag(bcx, of_cond, rflags::OF);
    let f = bcx.ins().bor(f, of);
    let x = bcx.ins().bxor(d, s);
    let y = bcx.ins().bxor(x, r);
    let ten = iconst_u64(bcx, 0x10);
    let af_b = bcx.ins().band(y, ten);
    let af_cond = bcx.ins().icmp_imm(IntCC::NotEqual, af_b, 0);
    let af = select_flag(bcx, af_cond, rflags::AF);
    bcx.ins().bor(f, af)
}
