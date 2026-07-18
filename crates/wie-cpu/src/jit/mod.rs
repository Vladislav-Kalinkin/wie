//! Phase 2: hybrid Cranelift block JIT + iced interpreter fallback.
//!
//! **Strategy:** decode a lowerable block at RIP (GPR, mem, ALU, shift, call/ret,
//! jcc, SSE, bulk string); if hot enough, compile once and cache by guest entry VA.
//! Complex forms / cold sites → iced `step`.
//!
//! **Fast UCRT path:** hot CRT imports (`malloc`/`memcpy`/…) are Cranelift imports;
//! `call` to those fake-API VAs is lowered in-place (no host-stop).
//! **Block chaining:** self-loops, direct `call` to known successors, and late-bound
//! open-addressing chain-table lookups keep control in native code (no dispatcher).
//! **Shadow return stack:** `call` pushes guest return VA; `ret` validates and
//! chain-lookups the target for better call/ret prediction.

#![allow(
    unsafe_code, // Cranelift finalized fn pointers + host mem helpers
    clippy::indexing_slicing, // fixed gpr[0..16]
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]

mod block;
mod fast_api;
mod lower;
mod trampolines;

pub use fast_api::{FastApiKind, JitFastPathConfig, JitHeapLayout};

use crate::exec::{self, StepResult};
use crate::iced_cpu::IcedCpu;
use crate::{CodeHookOutcome, InvalidMemoryAccess};
use crate::{CpuEngine, CpuError, RunUntilHook};
use block::{BlockKind, decode_pure_gpr_block, pure_is_self_loop};
use fast_api::{
    install_heap_layout, wie_ucrt_fflush, wie_ucrt_free, wie_ucrt_fwrite, wie_ucrt_iob,
    wie_ucrt_malloc, wie_ucrt_memcpy, wie_ucrt_strlen,
};
use lower::{
    CHAIN_SLOTS, CompiledBlock, JitCtx, TLB_EMPTY, TLB_WAYS, chain_table_clear, chain_table_insert,
    compile_block, wie_f32_binop, wie_f64_binop, wie_jit_chain_lookup, wie_jit_load, wie_jit_store,
    wie_jit_string,
};
use std::collections::HashMap;
use trampolines::match_micro_stub;

/// Compile after this many visits to the same guest entry (skip cold code).
/// Higher values cut compile tax on open-rom (mem/push coverage widens Pure set).
/// Tests use 0 (eager compile on first Pure decode).
fn hotness_threshold() -> u32 {
    if cfg!(test) { 0 } else { 100 }
}

/// Known pure self-loops: compile sooner (trade one Cranelift pass vs iced warmup).
fn pure_loop_hotness() -> u32 {
    if cfg!(test) { 0 } else { 16 }
}

/// Hybrid CPU: Cranelift for hot pure-GPR blocks, iced for everything else.
pub struct JitCpu {
    iced: IcedCpu,
    /// `None` if host ISA / JIT module failed to open (always fall back to iced).
    engine: Option<JitEngine>,
    /// Guest block entry VA → cache entry.
    cache: HashMap<u64, CacheEntry>,
    /// Ready-block FuncIds for chaining (kept in sync with `cache`; avoids
    /// rebuilding a full HashMap on every compile).
    chain_ids: HashMap<u64, cranelift_module::FuncId>,
    stats: JitStats,
    /// Persistent multi-way page TLB across chained blocks (invalidate on mem_write/hooks).
    tlb_page: [u64; TLB_WAYS],
    tlb_ptr: [*mut u8; TLB_WAYS],
    tlb_rr: u64,
    /// Sticky last-hit page for inline IR mem path.
    tlb_hot_page: u64,
    tlb_hot_ptr: *mut u8,
    /// Fake-API VA → fast UCRT kind (compile-time lookup).
    fast_api: HashMap<u64, FastApiKind>,
    /// Open-addressing guest VA → host block fn (late-bound block chaining).
    chain_va: Box<[u64; CHAIN_SLOTS]>,
    chain_fn: Box<[u64; CHAIN_SLOTS]>,
    /// Shadow return-stack depth across block entries (persisted in `run_compiled`).
    shadow_sp: u64,
    shadow_ret: [u64; lower::SHADOW_DEPTH],
}

enum CacheEntry {
    /// Native block ready to run.
    Ready(CompiledBlock),
    /// Do not retry decode/compile at this VA (cold fail or non-pure).
    Never,
    /// Visit counter + compile threshold (threshold fixed on first sight so we
    /// do not re-decode for UCRT peek on every warmup visit).
    Hot { visits: u32, thr: u32 },
}

struct JitEngine {
    module: cranelift_jit::JITModule,
    ctx: cranelift_codegen::Context,
    func_ctx: cranelift::prelude::FunctionBuilderContext,
    next_name: u32,
    /// Shared signature: `(i64 ctx_ptr)` — host C ABI (callable from Rust).
    block_sig: cranelift::codegen::ir::Signature,
    /// Host `wie_jit_load` import.
    load_id: cranelift_module::FuncId,
    /// Host `wie_jit_store` import.
    store_id: cranelift_module::FuncId,
    /// Host bulk string helper.
    string_id: cranelift_module::FuncId,
    /// Scalar f32 binop helper.
    f32_id: cranelift_module::FuncId,
    /// Scalar f64 binop helper.
    f64_id: cranelift_module::FuncId,
    /// Host chain-table lookup (`wie_jit_chain_lookup`).
    lookup_id: cranelift_module::FuncId,
    /// UCRT fast-path imports (malloc, free, memcpy, …).
    ucrt: UcrtImportIds,
}

/// Cranelift `FuncId`s for direct UCRT host calls.
#[derive(Clone, Copy)]
pub(super) struct UcrtImportIds {
    pub malloc: cranelift_module::FuncId,
    pub free: cranelift_module::FuncId,
    pub memcpy: cranelift_module::FuncId,
    pub strlen: cranelift_module::FuncId,
    pub iob: cranelift_module::FuncId,
    pub fwrite: cranelift_module::FuncId,
    pub fflush: cranelift_module::FuncId,
}

impl UcrtImportIds {
    pub(super) fn for_kind(self, kind: FastApiKind) -> cranelift_module::FuncId {
        match kind {
            FastApiKind::Malloc => self.malloc,
            FastApiKind::Free => self.free,
            FastApiKind::Memcpy => self.memcpy,
            FastApiKind::Strlen => self.strlen,
            FastApiKind::AcrtIobFunc => self.iob,
            FastApiKind::Fwrite => self.fwrite,
            FastApiKind::Fflush => self.fflush,
        }
    }
}

/// Lightweight counters for `WIE_CPU=jit` diagnostics / Phase 0 baselines.
#[derive(Debug, Default, Clone, Copy)]
pub struct JitStats {
    /// Instructions retired via native blocks.
    pub jit_insns: u64,
    /// Instructions retired via iced fallback.
    pub iced_insns: u64,
    /// Successful block compiles.
    pub compiles: u64,
    /// Block decode declined or cold skip.
    pub compile_skip: u64,
    /// Cache hits (native run).
    pub cache_hits: u64,
    /// Calls into host `wie_jit_load` (TLB hit or miss).
    pub load_calls: u64,
    /// Calls into host `wie_jit_store` (TLB hit or miss).
    pub store_calls: u64,
}

impl JitCpu {
    /// Open hybrid JIT on the host ISA (ARM64 on Apple Silicon).
    #[must_use]
    pub fn open_x86_64() -> Self {
        let engine = match JitEngine::new() {
            Ok(e) => {
                tracing::info!("cranelift JIT module ready");
                Some(e)
            }
            Err(e) => {
                tracing::warn!(error = %e, "cranelift JIT unavailable; iced-only");
                None
            }
        };
        Self {
            iced: IcedCpu::open_x86_64(),
            engine,
            cache: HashMap::new(),
            chain_ids: HashMap::new(),
            stats: JitStats {
                ..JitStats::default()
            },
            tlb_page: [TLB_EMPTY; TLB_WAYS],
            tlb_ptr: [std::ptr::null_mut(); TLB_WAYS],
            tlb_rr: 0,
            tlb_hot_page: TLB_EMPTY,
            tlb_hot_ptr: std::ptr::null_mut(),
            fast_api: HashMap::new(),
            chain_va: Box::new([0; CHAIN_SLOTS]),
            chain_fn: Box::new([0; CHAIN_SLOTS]),
            shadow_sp: 0,
            shadow_ret: [0; lower::SHADOW_DEPTH],
        }
    }

    /// Snapshot of JIT diagnostics counters (Phase 0 baselines).
    #[must_use]
    pub fn stats(&self) -> JitStats {
        self.stats
    }

    /// Install UCRT/heap fast-path config (called once after fake-API table build).
    pub fn configure_fast_path(&mut self, cfg: JitFastPathConfig) {
        install_heap_layout(cfg.heap);
        self.fast_api = cfg.by_va;
        // New mappings invalidate prior compiles that missed the fast path.
        if !self.cache.is_empty() {
            self.cache.clear();
            self.chain_ids.clear();
        }
        self.invalidate_chain_and_shadow();
    }

    /// Insert a Ready block and keep `chain_ids` consistent.
    fn insert_ready(&mut self, rip: u64, compiled: CompiledBlock) {
        if let Some(fid) = compiled.func_id {
            self.chain_ids.insert(rip, fid);
        }
        self.cache.insert(rip, CacheEntry::Ready(compiled));
    }

    /// Drop all compiled blocks (self-modifying code / hook reinstall).
    fn clear_compiled(&mut self) {
        self.cache.clear();
        self.chain_ids.clear();
    }

    /// Drop only Ready blocks whose guest code range overlaps `[addr, addr+len)`.
    /// Data writes that miss all compiled ranges leave the cache intact.
    fn invalidate_compiled_overlapping(&mut self, addr: u64, len: usize) {
        if self.cache.is_empty() || len == 0 {
            return;
        }
        let write_end = addr.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        let to_drop: Vec<u64> = self
            .cache
            .iter()
            .filter_map(|(va, entry)| match entry {
                CacheEntry::Ready(c)
                    if ranges_overlap(c.guest_start, c.guest_end, addr, write_end) =>
                {
                    Some(*va)
                }
                _ => None,
            })
            .collect();
        if to_drop.is_empty() {
            // Data-only write: page buffers are updated in place; TLB stays valid.
            return;
        }
        for va in &to_drop {
            self.cache.remove(va);
            self.chain_ids.remove(va);
        }
        // Rebuild late-bound chain from remaining Ready entries.
        chain_table_clear(self.chain_va.as_mut(), self.chain_fn.as_mut());
        for (va, entry) in &self.cache {
            if let CacheEntry::Ready(c) = entry {
                let fn_ptr = c.func as usize as u64;
                chain_table_insert(self.chain_va.as_mut(), self.chain_fn.as_mut(), *va, fn_ptr);
            }
        }
        // Code bytes changed under a previously compiled region — drop shadow.
        self.shadow_sp = 0;
        self.shadow_ret = [0; lower::SHADOW_DEPTH];
    }

    /// Returns `(result, guest_insns_retired)` for budget accounting.
    fn step_one(&mut self) -> Result<(StepResult, usize), CpuError> {
        let rip = self.iced.regs().rip;
        if let Some(hook) = self.iced.hooks_ref()
            && hook.should_host_stop(rip)
        {
            return Ok((
                StepResult::HostStop {
                    address: rip,
                    size: 1,
                },
                0,
            ));
        }

        if self.engine.is_some() {
            match self.cache.get(&rip) {
                Some(CacheEntry::Ready(compiled)) => {
                    self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
                    let meta = CompiledRunMeta::from(compiled);
                    return Ok(self.finish_compiled(rip, meta));
                }
                Some(CacheEntry::Never) => {
                    // Fast path: known non-JIT site.
                }
                Some(&CacheEntry::Hot { visits, thr }) => {
                    let next = visits.saturating_add(1);
                    if thr > 0 && next < thr {
                        self.cache
                            .insert(rip, CacheEntry::Hot { visits: next, thr });
                    } else if let Some(compiled) = self.try_compile(rip) {
                        let meta = CompiledRunMeta::from(&compiled);
                        self.insert_ready(rip, compiled);
                        return Ok(self.finish_compiled(rip, meta));
                    } else {
                        self.cache.insert(rip, CacheEntry::Never);
                    }
                }
                None => {
                    // Eager when tests (thr=0) OR first sight of a fast-UCRT call site
                    // (host_stop avoidance is worth the compile tax even once).
                    // Pure self-loops use a lower threshold (compile sooner, less iced).
                    let is_ucrt = self.peek_fast_ucrt_call(rip);
                    let is_loop = self.peek_self_loop(rip);
                    let thr = if is_ucrt {
                        2
                    } else if is_loop {
                        pure_loop_hotness()
                    } else {
                        hotness_threshold()
                    };
                    if thr == 0 || is_ucrt {
                        if let Some(compiled) = self.try_compile(rip) {
                            let meta = CompiledRunMeta::from(&compiled);
                            self.insert_ready(rip, compiled);
                            return Ok(self.finish_compiled(rip, meta));
                        }
                        self.cache.insert(rip, CacheEntry::Never);
                    } else {
                        // First visit: start hotness, interpret (avoid compile on cold code).
                        self.cache.insert(rip, CacheEntry::Hot { visits: 1, thr });
                    }
                }
            }
        }

        // Iced does not maintain the shadow return stack — drop prediction.
        self.shadow_sp = 0;
        self.stats.iced_insns = self.stats.iced_insns.saturating_add(1);
        Ok((self.iced.step_once_result()?, 1))
    }

    /// True when a Pure block at `rip` ends in a near-call to a registered UCRT fast API.
    fn peek_fast_ucrt_call(&self, rip: u64) -> bool {
        if self.fast_api.is_empty() {
            return false;
        }
        match decode_pure_gpr_block(&self.iced, rip) {
            BlockKind::Pure {
                term: Some(block::BlockTerm::Call { target, .. }),
                ..
            } => {
                let final_va = resolve_thunk_va(&self.iced, target);
                self.fast_api.contains_key(&final_va)
            }
            _ => false,
        }
    }

    /// True when decode yields a pure self-loop (jcc/jmp back to entry).
    fn peek_self_loop(&self, rip: u64) -> bool {
        let kind = decode_pure_gpr_block(&self.iced, rip);
        pure_is_self_loop(&kind, rip)
    }

    fn try_compile(&mut self, rip: u64) -> Option<CompiledBlock> {
        match decode_pure_gpr_block(&self.iced, rip) {
            BlockKind::Pure {
                insns,
                end_rip,
                bytes_len,
                term,
            } => {
                // 1–3 insn guest stubs: hand-written host trampoline (no Cranelift).
                if let Some(micro) = match_micro_stub(&insns, term) {
                    let guest_end = rip.saturating_add(u64::from(bytes_len));
                    let compiled = CompiledBlock {
                        func: micro.func(),
                        func_id: None,
                        insn_count: micro.insn_count(),
                        uses_sse: false,
                        guest_start: rip,
                        guest_end,
                    };
                    self.stats.compiles = self.stats.compiles.saturating_add(1);
                    let fn_ptr = compiled.func as usize as u64;
                    chain_table_insert(self.chain_va.as_mut(), self.chain_fn.as_mut(), rip, fn_ptr);
                    tracing::debug!(
                        start = format_args!("{rip:#x}"),
                        insns = compiled.insn_count,
                        "jit micro-stub trampoline"
                    );
                    return Some(compiled);
                }

                // Resolve import thunks before mutably borrowing the JIT engine.
                let call_fast = match term {
                    Some(block::BlockTerm::Call { target, .. }) => {
                        let final_va = resolve_thunk_va(&self.iced, target);
                        self.fast_api.get(&final_va).copied()
                    }
                    _ => None,
                };
                // Split borrows: `chain_ids` (Ready FuncIds) + `engine` mutably.
                // Avoids rebuilding a HashMap over the full cache each compile.
                let JitCpu {
                    engine,
                    chain_ids,
                    chain_va,
                    chain_fn,
                    stats,
                    ..
                } = self;
                let eng = engine.as_mut()?;
                match compile_block(
                    eng, rip, &insns, end_rip, term, call_fast, chain_ids, bytes_len,
                ) {
                    Ok(compiled) => {
                        stats.compiles = stats.compiles.saturating_add(1);
                        // Publish into late-bound chain table so older blocks can
                        // `call_indirect` here without recompilation.
                        let fn_ptr = compiled.func as usize as u64;
                        chain_table_insert(chain_va.as_mut(), chain_fn.as_mut(), rip, fn_ptr);
                        tracing::debug!(
                            start = format_args!("{rip:#x}"),
                            end = format_args!("{end_rip:#x}"),
                            insns = compiled.insn_count,
                            bytes = bytes_len,
                            has_term = term.is_some(),
                            fast = call_fast.is_some(),
                            "jit compiled block"
                        );
                        Some(compiled)
                    }
                    Err(e) => {
                        stats.compile_skip = stats.compile_skip.saturating_add(1);
                        tracing::debug!(start = format_args!("{rip:#x}"), error = %e, "jit lower failed");
                        None
                    }
                }
            }
            BlockKind::NotPure => {
                self.stats.compile_skip = self.stats.compile_skip.saturating_add(1);
                None
            }
        }
    }

    fn finish_compiled(&mut self, entry_rip: u64, meta: CompiledRunMeta) -> (StepResult, usize) {
        if let Some(inv) = self.run_compiled(entry_rip, meta) {
            (StepResult::InvalidMemory(inv), 0)
        } else {
            self.stats.jit_insns = self
                .stats
                .jit_insns
                .saturating_add(u64::from(meta.insn_count));
            (
                StepResult::Continue,
                usize::try_from(meta.insn_count).unwrap_or(1),
            )
        }
    }

    /// Returns `Some(InvalidMem)` when a host mem helper faulted.
    fn run_compiled(&mut self, entry_rip: u64, meta: CompiledRunMeta) -> Option<exec::InvalidMem> {
        let mem_ptr = std::ptr::from_mut(self.iced.guest_mem_mut());
        let regs = self.iced.regs_mut();
        // Full GPR snapshot on entry: late-bound chaining reloads live regs from
        // JitCtx, so every architectural GPR must be valid for successors.
        let mut gpr = [0_u64; 16];
        for (i, slot) in gpr.iter_mut().enumerate() {
            *slot = regs.gpr(i);
        }
        // Pure GPR blocks skip the 16×u128 XMM bank copy on both sides of the call.
        let mut xmm = [0_u64; 32];
        if meta.uses_sse {
            for i in 0..16 {
                let v = regs.xmm_at(i);
                xmm[i * 2] = v as u64;
                xmm[i * 2 + 1] = (v >> 64) as u64;
            }
        }
        let mut ctx = JitCtx {
            gpr,
            rflags: regs.rflags,
            rip: entry_rip,
            mem: mem_ptr,
            fault: 0,
            fault_addr: 0,
            fault_size: 0,
            fault_access: 0,
            tlb_page: self.tlb_page,
            tlb_ptr: self.tlb_ptr,
            tlb_rr: self.tlb_rr,
            xmm,
            shadow_sp: self.shadow_sp,
            shadow_ret: self.shadow_ret,
            chain_va: self.chain_va.as_mut_ptr(),
            chain_fn: self.chain_fn.as_mut_ptr(),
            tlb_hot_page: self.tlb_hot_page,
            tlb_hot_ptr: self.tlb_hot_ptr,
            // 0 = Cranelift path (host falls back to full writeback);
            // trampolines OR their dirty bits; chain sets 0xffff.
            gpr_dirty_bits: 0,
            load_calls: 0,
            store_calls: 0,
        };
        // SAFETY: `func` is a finalized Cranelift block or hand-written trampoline.
        unsafe {
            (meta.func)(std::ptr::from_mut(&mut ctx));
        }
        self.stats.load_calls = self.stats.load_calls.saturating_add(ctx.load_calls);
        self.stats.store_calls = self.stats.store_calls.saturating_add(ctx.store_calls);
        // Persist multi-way TLB + sticky hot page + shadow stack across chained blocks.
        self.tlb_page = ctx.tlb_page;
        self.tlb_ptr = ctx.tlb_ptr;
        self.tlb_rr = ctx.tlb_rr;
        self.tlb_hot_page = ctx.tlb_hot_page;
        self.tlb_hot_ptr = ctx.tlb_hot_ptr;
        self.shadow_sp = ctx.shadow_sp;
        self.shadow_ret = ctx.shadow_ret;
        // Prefer cumulative trampoline dirty bits (partial writeback when a
        // micro-stub does not chain). Cranelift leaves bits at 0 → full sync
        // (internal block chaining can dirty arbitrary GPRs).
        let dirty = if ctx.fault != 0 || ctx.gpr_dirty_bits == 0 {
            0xffff_u16
        } else {
            ctx.gpr_dirty_bits as u16
        };
        if dirty == 0xffff {
            for i in 0..16 {
                if let Some(&v) = ctx.gpr.get(i) {
                    regs.set_gpr(i, v);
                }
            }
        } else {
            let mut m = dirty;
            let mut i = 0_usize;
            while m != 0 {
                if m & 1 != 0
                    && let Some(&v) = ctx.gpr.get(i)
                {
                    regs.set_gpr(i, v);
                }
                m >>= 1;
                i = i.saturating_add(1);
            }
        }
        if meta.uses_sse {
            for i in 0..16 {
                let lo = ctx.xmm[i * 2];
                let hi = ctx.xmm[i * 2 + 1];
                let v = u128::from(lo) | (u128::from(hi) << 64);
                regs.set_xmm_at(i, v);
            }
        }
        regs.rflags = ctx.rflags;
        regs.rip = ctx.rip;
        if ctx.fault != 0 {
            Some(exec::InvalidMem {
                access_type: i32::try_from(ctx.fault_access).unwrap_or(0),
                address: ctx.fault_addr,
                size: i32::try_from(ctx.fault_size).unwrap_or(0),
                value: 0,
            })
        } else {
            None
        }
    }

    fn invalidate_tlb(&mut self) {
        self.tlb_page = [TLB_EMPTY; TLB_WAYS];
        self.tlb_ptr = [std::ptr::null_mut(); TLB_WAYS];
        self.tlb_rr = 0;
        self.tlb_hot_page = TLB_EMPTY;
        self.tlb_hot_ptr = std::ptr::null_mut();
    }

    fn invalidate_chain_and_shadow(&mut self) {
        chain_table_clear(self.chain_va.as_mut(), self.chain_fn.as_mut());
        self.shadow_sp = 0;
        self.shadow_ret = [0; lower::SHADOW_DEPTH];
    }
}

/// Snapshot of a Ready block needed to run it without holding a cache borrow.
#[derive(Clone, Copy)]
struct CompiledRunMeta {
    func: unsafe extern "C" fn(*mut JitCtx),
    insn_count: u32,
    uses_sse: bool,
}

impl From<&CompiledBlock> for CompiledRunMeta {
    fn from(c: &CompiledBlock) -> Self {
        Self {
            func: c.func,
            insn_count: c.insn_count,
            uses_sse: c.uses_sse,
        }
    }
}

/// Half-open range overlap: `[a0, a1)` vs `[b0, b1)`.
#[inline]
fn ranges_overlap(a0: u64, a1: u64, b0: u64, b1: u64) -> bool {
    a0 < b1 && b0 < a1
}

/// Follow PE import thunks / short jumps to the final callee VA.
fn resolve_thunk_va(cpu: &IcedCpu, mut va: u64) -> u64 {
    let mut buf = [0_u8; 16];
    for _ in 0..4 {
        if cpu.mem_read_into(va, &mut buf).is_err() {
            return va;
        }
        if buf[0] == 0xff && buf[1] == 0x25 {
            let rel = i32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
            let iat = va
                .wrapping_add(6)
                .wrapping_add(i64::from(rel).cast_unsigned());
            let mut slot = [0_u8; 8];
            if cpu.mem_read_into(iat, &mut slot).is_ok() {
                va = u64::from_le_bytes(slot);
                continue;
            }
            return va;
        }
        if buf[0] == 0xe9 {
            let rel = i32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
            va = va
                .wrapping_add(5)
                .wrapping_add(i64::from(rel).cast_unsigned());
            continue;
        }
        if buf[0] == 0x48 && buf[1] == 0xb8 && buf[10] == 0xff && buf[11] == 0xe0 {
            va = u64::from_le_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]);
            continue;
        }
        if buf[0] == 0xeb {
            let rel = buf[1].cast_signed();
            va = va
                .wrapping_add(2)
                .wrapping_add(i64::from(rel).cast_unsigned());
            continue;
        }
        return va;
    }
    va
}

impl JitEngine {
    fn new() -> Result<Self, String> {
        use cranelift::prelude::*;
        use cranelift_jit::{JITBuilder, JITModule};
        use cranelift_module::{Linkage, Module, default_libcall_names};

        let mut flag_builder = settings::builder();
        flag_builder
            .set("opt_level", "speed_and_size")
            .map_err(|e| e.to_string())?;
        flag_builder
            .set("enable_verifier", "false")
            .map_err(|e| e.to_string())?;
        flag_builder
            .set("is_pic", "false")
            .map_err(|e| e.to_string())?;
        flag_builder
            .set("use_colocated_libcalls", "false")
            .map_err(|e| e.to_string())?;
        flag_builder
            .set("enable_probestack", "false")
            .map_err(|e| e.to_string())?;
        // Prefer speed of generated code; opt_level=speed is default for cranelift-native.
        let isa_builder =
            cranelift_native::builder().map_err(|msg| format!("host ISA unsupported: {msg}"))?;
        let isa = isa_builder
            .finish(settings::Flags::new(flag_builder))
            .map_err(|e| e.to_string())?;

        let mut builder = JITBuilder::with_isa(isa, default_libcall_names());
        // SAFETY: function pointers are valid for the process lifetime.
        builder.symbol("wie_jit_load", wie_jit_load as *const u8);
        builder.symbol("wie_jit_store", wie_jit_store as *const u8);
        builder.symbol("wie_jit_string", wie_jit_string as *const u8);
        builder.symbol("wie_f32_binop", wie_f32_binop as *const u8);
        builder.symbol("wie_f64_binop", wie_f64_binop as *const u8);
        builder.symbol("wie_jit_chain_lookup", wie_jit_chain_lookup as *const u8);
        builder.symbol("wie_ucrt_malloc", wie_ucrt_malloc as *const u8);
        builder.symbol("wie_ucrt_free", wie_ucrt_free as *const u8);
        builder.symbol("wie_ucrt_memcpy", wie_ucrt_memcpy as *const u8);
        builder.symbol("wie_ucrt_strlen", wie_ucrt_strlen as *const u8);
        builder.symbol("wie_ucrt_iob", wie_ucrt_iob as *const u8);
        builder.symbol("wie_ucrt_fwrite", wie_ucrt_fwrite as *const u8);
        builder.symbol("wie_ucrt_fflush", wie_ucrt_fflush as *const u8);
        let mut module = JITModule::new(builder);

        // Host default call-conv (AppleAarch64 / SystemV) — must match Rust `extern "C"`.
        let mut block_sig = module.make_signature();
        block_sig.params.push(AbiParam::new(types::I64));

        // load: (ctx, addr, size, insn_ip) -> i64
        let mut load_sig = module.make_signature();
        load_sig.params.push(AbiParam::new(types::I64));
        load_sig.params.push(AbiParam::new(types::I64));
        load_sig.params.push(AbiParam::new(types::I64));
        load_sig.params.push(AbiParam::new(types::I64));
        load_sig.returns.push(AbiParam::new(types::I64));
        let load_id = module
            .declare_function("wie_jit_load", Linkage::Import, &load_sig)
            .map_err(|e| e.to_string())?;

        // store: (ctx, addr, size, value, insn_ip)
        let mut store_sig = module.make_signature();
        store_sig.params.push(AbiParam::new(types::I64));
        store_sig.params.push(AbiParam::new(types::I64));
        store_sig.params.push(AbiParam::new(types::I64));
        store_sig.params.push(AbiParam::new(types::I64));
        store_sig.params.push(AbiParam::new(types::I64));
        let store_id = module
            .declare_function("wie_jit_store", Linkage::Import, &store_sig)
            .map_err(|e| e.to_string())?;

        // string: (ctx, op, size, flags, insn_ip) -> stay
        let mut string_sig = module.make_signature();
        string_sig.params.push(AbiParam::new(types::I64));
        string_sig.params.push(AbiParam::new(types::I64));
        string_sig.params.push(AbiParam::new(types::I64));
        string_sig.params.push(AbiParam::new(types::I64));
        string_sig.params.push(AbiParam::new(types::I64));
        string_sig.returns.push(AbiParam::new(types::I64));
        let string_id = module
            .declare_function("wie_jit_string", Linkage::Import, &string_sig)
            .map_err(|e| e.to_string())?;

        // f32/f64 binop: (op, a, b) -> r
        let mut f_sig = module.make_signature();
        f_sig.params.push(AbiParam::new(types::I64));
        f_sig.params.push(AbiParam::new(types::I64));
        f_sig.params.push(AbiParam::new(types::I64));
        f_sig.returns.push(AbiParam::new(types::I64));
        let f32_id = module
            .declare_function("wie_f32_binop", Linkage::Import, &f_sig)
            .map_err(|e| e.to_string())?;
        let f64_id = module
            .declare_function("wie_f64_binop", Linkage::Import, &f_sig)
            .map_err(|e| e.to_string())?;

        // chain lookup: (ctx, va) -> fn_ptr
        let mut lookup_sig = module.make_signature();
        lookup_sig.params.push(AbiParam::new(types::I64));
        lookup_sig.params.push(AbiParam::new(types::I64));
        lookup_sig.returns.push(AbiParam::new(types::I64));
        let lookup_id = module
            .declare_function("wie_jit_chain_lookup", Linkage::Import, &lookup_sig)
            .map_err(|e| e.to_string())?;

        // UCRT: (ctx, …args) -> rax  /  free is void
        let mut sig_ctx1 = module.make_signature();
        sig_ctx1.params.push(AbiParam::new(types::I64)); // ctx
        sig_ctx1.params.push(AbiParam::new(types::I64)); // a0
        sig_ctx1.returns.push(AbiParam::new(types::I64));
        let mut sig_ctx1_void = module.make_signature();
        sig_ctx1_void.params.push(AbiParam::new(types::I64));
        sig_ctx1_void.params.push(AbiParam::new(types::I64));
        let mut sig_ctx3 = module.make_signature();
        sig_ctx3.params.push(AbiParam::new(types::I64));
        sig_ctx3.params.push(AbiParam::new(types::I64));
        sig_ctx3.params.push(AbiParam::new(types::I64));
        sig_ctx3.params.push(AbiParam::new(types::I64));
        sig_ctx3.returns.push(AbiParam::new(types::I64));
        let mut sig_ctx4 = module.make_signature();
        sig_ctx4.params.push(AbiParam::new(types::I64));
        for _ in 0..4 {
            sig_ctx4.params.push(AbiParam::new(types::I64));
        }
        sig_ctx4.returns.push(AbiParam::new(types::I64));
        let mut sig_1 = module.make_signature();
        sig_1.params.push(AbiParam::new(types::I64));
        sig_1.returns.push(AbiParam::new(types::I64));

        let malloc = module
            .declare_function("wie_ucrt_malloc", Linkage::Import, &sig_ctx1)
            .map_err(|e| e.to_string())?;
        let free = module
            .declare_function("wie_ucrt_free", Linkage::Import, &sig_ctx1_void)
            .map_err(|e| e.to_string())?;
        let memcpy = module
            .declare_function("wie_ucrt_memcpy", Linkage::Import, &sig_ctx3)
            .map_err(|e| e.to_string())?;
        let strlen = module
            .declare_function("wie_ucrt_strlen", Linkage::Import, &sig_ctx1)
            .map_err(|e| e.to_string())?;
        let iob = module
            .declare_function("wie_ucrt_iob", Linkage::Import, &sig_1)
            .map_err(|e| e.to_string())?;
        let fwrite = module
            .declare_function("wie_ucrt_fwrite", Linkage::Import, &sig_ctx4)
            .map_err(|e| e.to_string())?;
        let fflush = module
            .declare_function("wie_ucrt_fflush", Linkage::Import, &sig_1)
            .map_err(|e| e.to_string())?;

        Ok(Self {
            module,
            ctx: cranelift_codegen::Context::new(),
            func_ctx: FunctionBuilderContext::new(),
            next_name: 0,
            block_sig,
            load_id,
            store_id,
            string_id,
            f32_id,
            f64_id,
            lookup_id,
            ucrt: UcrtImportIds {
                malloc,
                free,
                memcpy,
                strlen,
                iob,
                fwrite,
                fflush,
            },
        })
    }
}

impl CpuEngine for JitCpu {
    fn mem_map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        self.iced.mem_map(address, size, perms)
    }

    fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        // Only invalidate compiled blocks whose guest code range overlaps the write.
        // Data writes (stack/heap/TEB) leave the JIT cache and chain table intact.
        self.invalidate_compiled_overlapping(address, bytes.len());
        self.iced.mem_write(address, bytes)
    }

    fn mem_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        self.iced.mem_read(address, bytes)
    }

    fn virtual_alloc(
        &mut self,
        addr: u64,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> Result<u64, CpuError> {
        self.iced.virtual_alloc(addr, size, alloc_type, protect)
    }

    fn virtual_free(
        &mut self,
        addr: u64,
        size: usize,
        free_type: u32,
    ) -> Result<(), CpuError> {
        // Full TLB/cache invalidate is PR C; release may drop host pages.
        self.iced.virtual_free(addr, size, free_type)
    }

    fn cpu_stats(&self) -> Option<crate::JitStats> {
        Some(self.stats)
    }

    fn mem_backend_name(&self) -> &'static str {
        self.iced.mem_backend_name()
    }

    fn register_region(&mut self, region: crate::mem::GuestRegion) {
        self.iced.register_region(region);
    }

    fn find_region(&self, va: u64) -> Option<crate::mem::GuestRegion> {
        self.iced.find_region(va)
    }

    fn install_runtime_hooks(
        &mut self,
        hook_begin: u64,
        hook_end: u64,
        stop_bitmap: Vec<u8>,
    ) -> Result<(), CpuError> {
        self.clear_compiled();
        self.invalidate_tlb();
        self.invalidate_chain_and_shadow();
        self.iced
            .install_runtime_hooks(hook_begin, hook_end, stop_bitmap)
    }

    fn configure_jit_fast_path(&mut self, cfg: JitFastPathConfig) {
        self.configure_fast_path(cfg);
        self.invalidate_chain_and_shadow();
    }

    fn precompile_at(&mut self, address: u64) {
        if self.engine.is_none() {
            return;
        }
        // Host-stop slots never run native code (checked before cache lookup).
        // Skip decode/compile tax for pure stop-bitmap entries.
        if let Some(hook) = self.iced.hooks_ref()
            && hook.should_host_stop(address)
        {
            return;
        }
        if let Some(compiled) = self.try_compile(address) {
            self.insert_ready(address, compiled);
        } else {
            // Remember NotPure so first runtime hit does not re-decode.
            self.cache.entry(address).or_insert(CacheEntry::Never);
        }
    }

    fn run_until_stop(
        &mut self,
        begin: u64,
        until: u64,
        _timeout: u64,
        count: usize,
        _hook_begin: u64,
        _hook_end: u64,
    ) -> Result<RunUntilHook, CpuError> {
        self.iced.regs_mut().rip = begin;
        let budget = if count == 0 { 100_000_000_usize } else { count };
        let mut executed = 0_usize;
        while executed < budget {
            let rip = self.iced.regs().rip;
            if until != 0 && rip == until {
                break;
            }
            // Fast host-stop (before cache / iced).
            if let Some(hook) = self.iced.hooks_ref()
                && hook.should_host_stop(rip)
            {
                return Ok(RunUntilHook {
                    code: CodeHookOutcome {
                        hit: true,
                        address: rip,
                        size: 1,
                    },
                    invalid_memory: InvalidMemoryAccess {
                        hit: false,
                        access_type: 0,
                        address: 0,
                        size: 0,
                        value: 0,
                    },
                });
            }
            // Hot chain: run consecutive Ready blocks without re-entering step_one.
            if self.engine.is_some()
                && let Some(CacheEntry::Ready(compiled)) = self.cache.get(&rip)
            {
                self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
                let meta = CompiledRunMeta::from(compiled);
                let (result, retired) = self.finish_compiled(rip, meta);
                match result {
                    StepResult::Continue => {
                        executed = executed.saturating_add(retired.max(1));
                        continue;
                    }
                    StepResult::HostStop { address, size } => {
                        return Ok(RunUntilHook {
                            code: CodeHookOutcome {
                                hit: true,
                                address,
                                size,
                            },
                            invalid_memory: InvalidMemoryAccess {
                                hit: false,
                                access_type: 0,
                                address: 0,
                                size: 0,
                                value: 0,
                            },
                        });
                    }
                    StepResult::InvalidMemory(inv) => {
                        return Ok(RunUntilHook {
                            code: CodeHookOutcome {
                                hit: false,
                                address: 0,
                                size: 0,
                            },
                            invalid_memory: InvalidMemoryAccess {
                                hit: true,
                                access_type: inv.access_type,
                                address: inv.address,
                                size: inv.size,
                                value: inv.value,
                            },
                        });
                    }
                }
            }
            let (result, retired) = self.step_one()?;
            match result {
                StepResult::Continue => {
                    executed = executed.saturating_add(retired.max(1));
                }
                StepResult::HostStop { address, size } => {
                    return Ok(RunUntilHook {
                        code: CodeHookOutcome {
                            hit: true,
                            address,
                            size,
                        },
                        invalid_memory: InvalidMemoryAccess {
                            hit: false,
                            access_type: 0,
                            address: 0,
                            size: 0,
                            value: 0,
                        },
                    });
                }
                StepResult::InvalidMemory(inv) => {
                    return Ok(RunUntilHook {
                        code: CodeHookOutcome {
                            hit: false,
                            address: 0,
                            size: 0,
                        },
                        invalid_memory: InvalidMemoryAccess {
                            hit: true,
                            access_type: inv.access_type,
                            address: inv.address,
                            size: inv.size,
                            value: inv.value,
                        },
                    });
                }
            }
        }
        Ok(RunUntilHook {
            code: CodeHookOutcome {
                hit: false,
                address: 0,
                size: 0,
            },
            invalid_memory: InvalidMemoryAccess {
                hit: false,
                access_type: 0,
                address: 0,
                size: 0,
                value: 0,
            },
        })
    }

    fn return_from_win64_api(&mut self, rax: u64) -> Result<u64, CpuError> {
        // Host-side API return bypasses guest `ret` — invalidate shadow prediction.
        self.shadow_sp = 0;
        self.iced.return_from_win64_api(rax)
    }

    fn read_rip(&mut self) -> Result<u64, CpuError> {
        self.iced.read_rip()
    }
    fn write_rip(&mut self, value: u64) -> Result<(), CpuError> {
        self.iced.write_rip(value)
    }
    fn read_rsp(&mut self) -> Result<u64, CpuError> {
        self.iced.read_rsp()
    }
    fn write_rsp(&mut self, value: u64) -> Result<(), CpuError> {
        self.iced.write_rsp(value)
    }
    fn read_rax(&mut self) -> Result<u64, CpuError> {
        self.iced.read_rax()
    }
    fn write_rax(&mut self, value: u64) -> Result<(), CpuError> {
        self.iced.write_rax(value)
    }
    fn read_rcx(&mut self) -> Result<u64, CpuError> {
        self.iced.read_rcx()
    }
    fn write_rcx(&mut self, value: u64) -> Result<(), CpuError> {
        self.iced.write_rcx(value)
    }
    fn read_rdx(&mut self) -> Result<u64, CpuError> {
        self.iced.read_rdx()
    }
    fn write_rdx(&mut self, value: u64) -> Result<(), CpuError> {
        self.iced.write_rdx(value)
    }
    fn read_r8(&mut self) -> Result<u64, CpuError> {
        self.iced.read_r8()
    }
    fn write_r8(&mut self, value: u64) -> Result<(), CpuError> {
        self.iced.write_r8(value)
    }
    fn read_r9(&mut self) -> Result<u64, CpuError> {
        self.iced.read_r9()
    }
    fn write_r9(&mut self, value: u64) -> Result<(), CpuError> {
        self.iced.write_r9(value)
    }
    fn read_rbx(&mut self) -> Result<u64, CpuError> {
        self.iced.read_rbx()
    }
    fn read_r12(&mut self) -> Result<u64, CpuError> {
        self.iced.read_r12()
    }
}
