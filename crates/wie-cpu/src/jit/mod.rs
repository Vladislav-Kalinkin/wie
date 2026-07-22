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
    private_interfaces, // JitShared/PerThreadJitState expose crate-private types
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

use crate::exec::{self, StepResult, HookWindow};
use crate::mem::{self, GuestMemory, PAGE_SIZE, PAGE_SIZE_USIZE, protect};
use crate::regs::RegFile;
use crate::{CodeHookOutcome, InvalidMemoryAccess};
use crate::{CpuEngine, CpuError, RunUntilHook};
use block::{BlockKind, decode_pure_gpr_block, pure_is_self_loop};
use fast_api::{
    install_heap_layout, wie_ucrt_fflush, wie_ucrt_free, wie_ucrt_fwrite, wie_ucrt_iob,
    wie_ucrt_malloc, wie_ucrt_memcpy, wie_ucrt_strlen,
};
use lower::{
    CHAIN_SLOTS, CompiledBlock, JitCtx, MemPathSlice, MemPin, PIN_SLOTS, STICKY_WAYS, TLB_EMPTY,
    TLB_SETS, TlbBucket, TlbBucketAux, XmmSlot, chain_table_clear, chain_table_insert,
    compile_block, empty_tlb_aux, empty_tlb_bucket, wie_f32_binop, wie_f64_binop,
    wie_jit_chain_lookup, wie_jit_host_span, wie_jit_load, wie_jit_store, wie_jit_string,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use trampolines::match_micro_stub;

/// Compile after this many visits to the same guest entry (skip cold code).
///
/// Default **100**: lower values (e.g. 12) cut residual iced but thrash short
/// non-loop blocks on 7za and **increase** wall (sweep 2026-07-21: thr=100 best).
/// Residual iced under thr=100 is almost all already-lowerable warmup (Mov/Call/…).
/// Override: `WIE_JIT_HOTNESS=N` (`0` = eager first visit). Tests use 0.
fn hotness_threshold() -> u32 {
    use std::sync::OnceLock;
    static THR: OnceLock<u32> = OnceLock::new();
    *THR.get_or_init(|| {
        if cfg!(test) {
            return 0;
        }
        match std::env::var("WIE_JIT_HOTNESS") {
            Ok(v) => v.parse::<u32>().unwrap_or(100),
            Err(_) => 100,
        }
    })
}

/// Known pure self-loops: compile sooner (trade one Cranelift pass vs iced warmup).
/// Override: `WIE_JIT_LOOP_HOTNESS=N` (default 8; tests 0).
fn pure_loop_hotness() -> u32 {
    use std::sync::OnceLock;
    static THR: OnceLock<u32> = OnceLock::new();
    *THR.get_or_init(|| {
        if cfg!(test) {
            return 0;
        }
        match std::env::var("WIE_JIT_LOOP_HOTNESS") {
            Ok(v) => v.parse::<u32>().unwrap_or(8),
            Err(_) => 8,
        }
    })
}

/// JIT memory lower mode (`WIE_JIT_MEM`).
///
/// - unset / `sticky` — sticky-TLB IR + **stack pin** (4.1b); helpers use all
///   pin slots (stack / heaps / VirtualAlloc) via `pin_resolve`
/// - `slow` — helper-only loads/stores (oracle / bisect; no host ptr in IR)
/// - `pin` — sticky + stack + **top-2 data pin IR** (heaps/VA); helpers same
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JitMemMode {
    Slow,
    Sticky,
    Pin,
}

fn jit_mem_mode() -> JitMemMode {
    use std::sync::OnceLock;
    static MODE: OnceLock<JitMemMode> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("WIE_JIT_MEM") {
        Ok(v) if v.eq_ignore_ascii_case("slow") || v == "0" || v.eq_ignore_ascii_case("off") => {
            JitMemMode::Slow
        }
        Ok(v) if v.eq_ignore_ascii_case("pin") => JitMemMode::Pin,
        Ok(v) if v.eq_ignore_ascii_case("sticky") || v.eq_ignore_ascii_case("fast") => {
            JitMemMode::Sticky
        }
        _ => JitMemMode::Sticky,
    })
}

/// Whether Cranelift may emit inline sticky-TLB load/store (not helper-only).
pub(super) fn jit_mem_inline_enabled() -> bool {
    !matches!(jit_mem_mode(), JitMemMode::Slow)
}

/// Whether Cranelift may emit **data** pin IR (heap + VirtualAlloc) after sticky.
///
/// Default sticky still fills all pin slots for helper `pin_resolve`; only
/// `WIE_JIT_MEM=pin` adds IR probes (can help some heaps, tax on thrashy paths).
pub(super) fn jit_mem_pin_enabled() -> bool {
    matches!(jit_mem_mode(), JitMemMode::Pin)
}

/// Opt-in mem helper resolution histogram (`WIE_JIT_MEM_TRACE=1`).
fn mem_path_trace_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| match std::env::var("WIE_JIT_MEM_TRACE") {
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes") => {
            true
        }
        // Also dump when residual iced trace is on (profiling runs).
        _ => matches!(
            std::env::var("WIE_EXEC_TRACE"),
            Ok(v) if v == "1" || v.eq_ignore_ascii_case("true")
        ),
    })
}

/// Block-wide stack super path (`WIE_JIT_SUPER`).
///
/// - unset / `loop` — **default**: only self-loop blocks (safe; `long_loop`-style)
/// - `0` / `off` / `false` — disabled (sticky/pin probes only)
/// - `all` / `1` / `true` — all stack-pin-shaped blocks (experimental; can host-fault
///   on non-loop super, e.g. `7za a` under default All previously)
pub(super) fn jit_super_enabled(self_loop: bool) -> bool {
    use std::sync::OnceLock;
    #[derive(Clone, Copy)]
    enum SuperMode {
        Off,
        LoopOnly,
        All,
    }
    static MODE: OnceLock<SuperMode> = OnceLock::new();
    let mode = *MODE.get_or_init(|| match std::env::var("WIE_JIT_SUPER") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("false") => {
            SuperMode::Off
        }
        Ok(v)
            if v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("on")
                || v.eq_ignore_ascii_case("all") =>
        {
            SuperMode::All
        }
        // unset, "loop", "selfloop", or any other value → self-loops only
        _ => SuperMode::LoopOnly,
    });
    match mode {
        SuperMode::Off => false,
        SuperMode::LoopOnly => self_loop,
        SuperMode::All => true,
    }
}

/// Late-bound + direct block chaining (`WIE_JIT_CHAIN=0` disables).
fn jit_chain_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("WIE_JIT_CHAIN"),
            Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off")
        )
    })
}

/// Shared JIT state: Cranelift module + compilation cache + guest memory.
/// One instance per process, shared via Arc across all per-thread engines.
#[doc(hidden)]
pub struct JitShared {
    /// Cranelift JIT module (behind Mutex: compiled blocks are serialized anyway).
    #[doc(hidden)]
    pub engine: Mutex<Option<JitEngine>>,
    /// Guest memory: page tables, mmap backend. Mutex protects metadata.
    #[doc(hidden)]
    pub mem: Mutex<GuestMemory>,
    /// Guest entry VA → CacheEntry.
    #[doc(hidden)]
    pub cache: RwLock<HashMap<u64, CacheEntry>>,
    /// Ready-block FuncIds for chaining.
    #[doc(hidden)]
    pub chain_ids: RwLock<HashMap<u64, cranelift_module::FuncId>>,
    /// Guest page keys covered by Ready blocks (SMC tracking).
    #[doc(hidden)]
    pub code_pages: Mutex<HashMap<u64, u32>>,
}

impl JitShared {
    fn new() -> Self {
        Self {
            engine: Mutex::new(match JitEngine::new() {
                Ok(e) => {
                    tracing::info!("cranelift JIT module ready");
                    Some(e)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "cranelift JIT unavailable; iced-only");
                    None
                }
            }),
            mem: Mutex::new(GuestMemory::new()),
            cache: RwLock::new(HashMap::new()),
            chain_ids: RwLock::new(HashMap::new()),
            code_pages: Mutex::new(HashMap::new()),
        }
    }
}

// SAFETY: GuestMemory behind Mutex; raw pointers in GuestMemory are
// non-owning views of mmap arenas that live for the process lifetime.
// Mutex provides synchronization for the metadata; JIT hot path uses
// per-thread TLB with host pointers directly.
#[expect(unsafe_code)]
unsafe impl Send for JitShared {}
#[expect(unsafe_code)]
unsafe impl Sync for JitShared {}

/// Per-thread JIT execution state: registers, TLB, chain table, shadow stack.
/// One instance per guest thread. Not shared.
#[doc(hidden)]
pub struct PerThreadJitState {
    /// x86-64 register file.
    #[doc(hidden)]
    pub regs: RegFile,
    /// Runtime hook window (stop-bitmap for fake-API range).
    #[doc(hidden)]
    pub hooks: Option<HookWindow>,
    /// Recent RIP history for diagnostics (ring buffer).
    pub rip_trace: [u64; 32],
    pub rip_trace_i: usize,
    pub rip_trace_n: usize,
    /// Instructions retired via interpreter (Phase 0 baselines).
    pub iced_steps: u64,
    /// Persistent set-associative page TLB across chained blocks.
    pub tlb_sets: [TlbBucket; TLB_SETS],
    pub tlb_aux: [TlbBucketAux; TLB_SETS],
    /// Sticky last-hit page for inline IR mem path.
    pub tlb_hot_page: u64,
    pub tlb_hot_ptr: *mut u8,
    pub tlb_hot_prot: u64,
    pub tlb_hot_gen: u64,
    /// Multi sticky ways.
    pub sticky_page: [u64; STICKY_WAYS],
    pub sticky_ptr: [*mut u8; STICKY_WAYS],
    pub sticky_prot: [u64; STICKY_WAYS],
    pub sticky_gen: [u64; STICKY_WAYS],
    pub sticky_rr: u64,
    /// Region-direct pins.
    pub pins: [MemPin; PIN_SLOTS],
    /// Generation at which pins were last rebuilt.
    pub pins_gen: u64,
    /// Open-addressing guest VA → host block fn (late-bound block chaining).
    pub chain_va: Box<[u64; CHAIN_SLOTS]>,
    pub chain_fn: Box<[u64; CHAIN_SLOTS]>,
    /// Phase 4.2 monomorphic edge IC.
    pub edge_ic_va: [u64; lower::EDGE_IC_SLOTS],
    pub edge_ic_fn: [u64; lower::EDGE_IC_SLOTS],
    pub edge_ic_rr: u64,
    /// Shadow return-stack depth.
    pub shadow_sp: u64,
    pub shadow_ret: [u64; lower::SHADOW_DEPTH],
}

// SAFETY: TLB/pin raw pointers are non-owning views of guest mmap arenas.
// Each PerThreadJitState is owned by one host thread; never moved between threads.
#[expect(unsafe_code)]
unsafe impl Send for PerThreadJitState {}

impl PerThreadJitState {
    fn new() -> Self {
        Self {
            regs: RegFile::new(),
            hooks: None,
            rip_trace: [0; 32],
            rip_trace_i: 0,
            rip_trace_n: 0,
            iced_steps: 0,
            tlb_sets: [empty_tlb_bucket(); TLB_SETS],
            tlb_aux: [empty_tlb_aux(); TLB_SETS],
            tlb_hot_page: TLB_EMPTY,
            tlb_hot_ptr: std::ptr::null_mut(),
            tlb_hot_prot: 0,
            tlb_hot_gen: 0,
            sticky_page: [TLB_EMPTY; STICKY_WAYS],
            sticky_ptr: [std::ptr::null_mut(); STICKY_WAYS],
            sticky_prot: [0; STICKY_WAYS],
            sticky_gen: [0; STICKY_WAYS],
            sticky_rr: 0,
            pins: [MemPin::EMPTY; PIN_SLOTS],
            pins_gen: u64::MAX,
            chain_va: Box::new([0; CHAIN_SLOTS]),
            chain_fn: Box::new([0; CHAIN_SLOTS]),
            edge_ic_va: [0; lower::EDGE_IC_SLOTS],
            edge_ic_fn: [0; lower::EDGE_IC_SLOTS],
            edge_ic_rr: 0,
            shadow_sp: 0,
            shadow_ret: [0; lower::SHADOW_DEPTH],
        }
    }
}

/// Hybrid CPU: Cranelift for hot pure-GPR blocks, iced for everything else.
///
/// Holds a shared compilation cache + guest memory (Arc) and per-thread
/// execution state (registers, TLB, chain table, shadow stack).
pub struct JitCpu {
    /// Shared compilation cache + guest memory (one per process).
    pub(crate) shared: Arc<JitShared>,
    /// Per-thread execution state (registers, TLB, chain table, etc.).
    pub(crate) thread: PerThreadJitState,
    /// Fake-API VA → fast UCRT kind (per-thread; configured once during init).
    pub(crate) fast_api: Vec<(u64, FastApiKind)>,
    /// Diagnostic counters (per-thread).
    pub(crate) stats: JitStats,
    /// Previous `GuestMemory::generation` at last `run_compiled` (diag).
    pub(crate) last_mem_gen: u64,
}

// SAFETY: Arc<JitShared> is Send + Sync (via unsafe impl above).
// PerThreadJitState is Send (raw pointers owned by one thread).
#[expect(unsafe_code)]
unsafe impl Send for JitCpu {}

#[doc(hidden)]
pub enum CacheEntry {
    /// Native block ready to run.
    Ready(CompiledBlock),
    /// Do not retry decode/compile at this VA (cold fail or non-pure).
    Never,
    /// Visit counter + compile threshold (threshold fixed on first sight so we
    /// do not re-decode for UCRT peek on every warmup visit).
    Hot { visits: u32, thr: u32 },
}

pub(crate) struct JitEngine {
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
    /// Soft-translated host span for inline string copies.
    host_span_id: cranelift_module::FuncId,
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

/// Dump helper mem-path histogram when `WIE_JIT_MEM_TRACE=1` or `WIE_EXEC_TRACE=1`.
pub fn dump_mem_path_stats(s: &JitStats) {
    if !mem_path_trace_enabled() {
        return;
    }
    let helpers = s.load_calls.saturating_add(s.store_calls);
    eprintln!(
        "[wie] mem_path helpers={helpers} load={} store={}",
        s.load_calls, s.store_calls
    );
    eprintln!(
        "[wie]   resolve: sticky={} multi={} pin={} walk={} cross={} slow={}",
        s.mem_sticky_hit,
        s.mem_multi_hit,
        s.mem_pin_hit,
        s.mem_walk_hit,
        s.mem_cross_page,
        s.mem_slow
    );
    eprintln!(
        "[wie]   sticky_miss: key={} gen={} prot={} swaps={}",
        s.mem_sticky_miss_key, s.mem_sticky_miss_gen, s.mem_sticky_miss_prot, s.mem_sticky_swaps
    );
    eprintln!(
        "[wie]   addr_vs_pin: stack={} heap={} outside={}",
        s.mem_addr_stack_pin, s.mem_addr_heap_pin, s.mem_addr_outside
    );
    eprintln!(
        "[wie]   gen: bumps={} peak={}  pins: stack_bytes={:#x} heap_bytes={:#x} allow={:#x}",
        s.mem_gen_bumps, s.mem_gen_peak, s.pin_stack_bytes, s.pin_heap_bytes, s.pin_allow_bits
    );
    if helpers > 0 {
        let pct10 = |n: u64| -> u64 { n.saturating_mul(1000).checked_div(helpers).unwrap_or(0) };
        let fmt = |n: u64| {
            let t = pct10(n);
            format!("{}.{}", t.checked_div(10).unwrap_or(0), t % 10)
        };
        eprintln!(
            "[wie]   resolve%: multi={}% pin={}% walk={}% key_miss={}% outside={}%",
            fmt(s.mem_multi_hit),
            fmt(s.mem_pin_hit),
            fmt(s.mem_walk_hit),
            fmt(s.mem_sticky_miss_key),
            fmt(s.mem_addr_outside),
        );
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
    /// Phase 4.x: selective code-cache invalidations (SMC / X-loss / unmap).
    pub code_invs: u64,
    /// Helper sticky hit after IR miss.
    pub mem_sticky_hit: u64,
    /// Helper multi-way TLB hit.
    pub mem_multi_hit: u64,
    /// Helper region-pin hit.
    pub mem_pin_hit: u64,
    /// Helper page-walk install hit.
    pub mem_walk_hit: u64,
    /// Helper cross-page (slow).
    pub mem_cross_page: u64,
    /// Helper full slow path (`GuestMemory::{read,write}`).
    pub mem_slow: u64,
    /// Sticky miss reason: wrong/empty page key.
    pub mem_sticky_miss_key: u64,
    /// Sticky miss reason: generation mismatch.
    pub mem_sticky_miss_gen: u64,
    /// Sticky miss reason: R/W denied.
    pub mem_sticky_miss_prot: u64,
    /// Sticky hot-page replacements.
    pub mem_sticky_swaps: u64,
    /// Helper VA inside stack pin.
    pub mem_addr_stack_pin: u64,
    /// Helper VA inside heap pin.
    pub mem_addr_heap_pin: u64,
    /// Helper VA outside both pins.
    pub mem_addr_outside: u64,
    /// Times `GuestMemory::generation` increased between `run_compiled` entries.
    pub mem_gen_bumps: u64,
    /// Peak `mem_gen` observed.
    pub mem_gen_peak: u64,
    /// Last stack pin guest span size (0 if empty).
    pub pin_stack_bytes: u64,
    /// Last heap pin guest span size (0 if empty).
    pub pin_heap_bytes: u64,
    /// Last pin allow bits: bit0 stack R, bit1 stack W, bit2 heap R, bit3 heap W.
    pub pin_allow_bits: u64,
}

impl JitCpu {
    /// Open hybrid JIT on the host ISA (ARM64 on Apple Silicon).
    #[must_use]
    pub fn open_x86_64() -> Self {
        let shared = JitShared::new();
        Self {
            shared: Arc::new(shared),
            thread: PerThreadJitState::new(),
            fast_api: Vec::new(),
            stats: JitStats::default(),
            last_mem_gen: 0,
        }
    }

    /// Create a per-thread engine sharing the compilation cache + guest memory.
    #[must_use]
    pub fn new_shared(shared: Arc<JitShared>) -> Self {
        Self {
            shared,
            thread: PerThreadJitState::new(),
            fast_api: Vec::new(),
            stats: JitStats::default(),
            last_mem_gen: 0,
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
        self.fast_api = cfg.pairs;
        self.clear_compiled();
        self.invalidate_chain_and_shadow();
    }

    #[inline]
    fn fast_api_kind(&self, va: u64) -> Option<FastApiKind> {
        self.fast_api
            .iter()
            .find_map(|&(k, kind)| (k == va).then_some(kind))
    }

    fn insert_ready(&mut self, rip: u64, compiled: CompiledBlock) {
        let removed = {
            let mut cache = self.shared.cache.write().unwrap();
            let old = cache.remove(&rip);
            if let Some(CacheEntry::Ready(ref old)) = old {
                self.shared.chain_ids.write().unwrap().remove(&rip);
                Some((old.guest_start, old.guest_end))
            } else {
                None
            }
        };
        if let Some((gs, ge)) = removed {
            self.code_pages_remove_range(gs, ge);
        }
        if jit_chain_enabled()
            && let Some(fid) = compiled.func_id
        {
            self.shared.chain_ids.write().unwrap().insert(rip, fid);
        }
        self.code_pages_add_range(compiled.guest_start, compiled.guest_end);
        self.shared.cache.write().unwrap().insert(rip, CacheEntry::Ready(compiled));
    }

    fn clear_compiled(&mut self) {
        self.shared.cache.write().unwrap().clear();
        self.shared.chain_ids.write().unwrap().clear();
        self.shared.code_pages.lock().unwrap().clear();
    }

    fn invalidate_code_range(&mut self, addr: u64, len: usize) {
        {
            let cache = self.shared.cache.read().unwrap();
            if cache.is_empty() || len == 0 {
                return;
            }
        }
        if !self.code_pages_overlap(addr, len) {
            return;
        }
        let write_end = addr.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        let to_drop: Vec<u64> = {
            let cache = self.shared.cache.read().unwrap();
            cache
                .iter()
                .filter_map(|(va, entry)| match entry {
                    CacheEntry::Ready(c)
                        if ranges_overlap(c.guest_start, c.guest_end, addr, write_end) =>
                    {
                        Some(*va)
                    }
                    _ => None,
                })
                .collect()
        };
        if to_drop.is_empty() {
            return;
        }
        for va in &to_drop {
            let mut cache = self.shared.cache.write().unwrap();
            if let Some(CacheEntry::Ready(c)) = cache.remove(va) {
                drop(cache);
                self.code_pages_remove_range(c.guest_start, c.guest_end);
            }
            self.shared.chain_ids.write().unwrap().remove(va);
        }
        self.stats.code_invs = self.stats.code_invs.saturating_add(1);
        self.invalidate_chain_and_shadow();
        if jit_chain_enabled() {
            let cache = self.shared.cache.read().unwrap();
            for (va, entry) in &*cache {
                if let CacheEntry::Ready(c) = entry {
                    let fn_ptr = c.func as usize as u64;
                    chain_table_insert(
                        self.thread.chain_va.as_mut(),
                        self.thread.chain_fn.as_mut(),
                        *va,
                        fn_ptr,
                    );
                }
            }
        }
    }

    #[inline]
    fn code_pages_overlap(&self, addr: u64, len: usize) -> bool {
        let code_pages = self.shared.code_pages.lock().unwrap();
        if len == 0 || code_pages.is_empty() {
            return false;
        }
        let end = addr.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        if end <= addr {
            return !code_pages.is_empty();
        }
        let mut page = addr >> 12;
        let last = end.saturating_sub(1) >> 12;
        while page <= last {
            if code_pages.contains_key(&page) {
                return true;
            }
            page = page.saturating_add(1);
        }
        false
    }

    fn code_pages_add_range(&mut self, guest_start: u64, guest_end: u64) {
        if guest_end <= guest_start {
            return;
        }
        let mut code_pages = self.shared.code_pages.lock().unwrap();
        let mut page = guest_start >> 12;
        let last = guest_end.saturating_sub(1) >> 12;
        while page <= last {
            code_pages
                .entry(page)
                .and_modify(|c| *c = c.saturating_add(1))
                .or_insert(1);
            page = page.saturating_add(1);
        }
    }

    fn code_pages_remove_range(&mut self, guest_start: u64, guest_end: u64) {
        if guest_end <= guest_start {
            return;
        }
        let mut code_pages = self.shared.code_pages.lock().unwrap();
        let mut page = guest_start >> 12;
        let last = guest_end.saturating_sub(1) >> 12;
        while page <= last {
            match code_pages.get_mut(&page) {
                Some(c) if *c > 1 => *c = c.saturating_sub(1),
                Some(_) => { code_pages.remove(&page); }
                None => {}
            }
            page = page.saturating_add(1);
        }
    }

    fn drain_pending_code_writes(&mut self) {
        let (pages, overflow) = self.shared.mem.lock().unwrap().take_pending_code_writes();
        if overflow {
            if !self.shared.cache.read().unwrap().is_empty() {
                self.clear_compiled();
                self.invalidate_chain_and_shadow();
                self.stats.code_invs = self.stats.code_invs.saturating_add(1);
            }
            return;
        }
        for page in pages {
            self.invalidate_code_range(page << 12, PAGE_SIZE_USIZE);
        }
    }

    fn code_inv_span_for_free(
        &self,
        addr: u64,
        size: usize,
        free_type: u32,
    ) -> Option<(u64, usize)> {
        if (free_type & mem::MEM_RELEASE) != 0 {
            return self.shared.mem.lock().unwrap().allocation_span_at_base(addr);
        }
        if (free_type & mem::MEM_DECOMMIT) != 0 {
            if size == 0 {
                return None;
            }
            let page_base = addr & !(PAGE_SIZE - 1);
            let end = addr.saturating_add(u64::try_from(size).unwrap_or(u64::MAX));
            let page_end = end
                .saturating_add(PAGE_SIZE - 1)
                .wrapping_div(PAGE_SIZE)
                .saturating_mul(PAGE_SIZE);
            let n = usize::try_from(page_end.saturating_sub(page_base)).unwrap_or(0);
            if n == 0 {
                return None;
            }
            return Some((page_base, n));
        }
        None
    }

    #[cfg(test)]
    #[must_use]
    fn has_ready_at(&self, rip: u64) -> bool {
        matches!(
            self.shared.cache.read().unwrap().get(&rip),
            Some(CacheEntry::Ready(_))
        )
    }

    /// Returns `(result, guest_insns_retired)` for budget accounting.
    fn step_one(&mut self) -> Result<(StepResult, usize), CpuError> {
        let rip = self.thread.regs.rip;
        if let Some(hook) = self.thread.hooks.as_ref()
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

        if self.shared.engine.lock().unwrap().is_some() {
            let cache = self.shared.cache.write().unwrap();
            match cache.get(&rip) {
                Some(CacheEntry::Ready(compiled)) => {
                    self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
                    let meta = CompiledRunMeta::from(compiled);
                    drop(cache); // release lock before finish_compiled (may call drain_pending_code_writes)
                    return Ok(self.finish_compiled(rip, meta));
                }
                Some(CacheEntry::Never) => {}
                Some(CacheEntry::Hot { visits: _, thr: _ }) => {
                    // Read visits via pattern match bypass — use clone to get value
                    let is_hot_entry = cache.get(&rip).map(|e| match e {
                        CacheEntry::Hot { visits, thr } => (*visits, *thr),
                        _ => (0, 0),
                    });
                    drop(cache);
                    if let Some((visits, thr)) = is_hot_entry {
                        let next = visits.saturating_add(1);
                        if thr > 0 && next < thr {
                            self.shared.cache.write().unwrap()
                                .insert(rip, CacheEntry::Hot { visits: next, thr });
                        } else if let Some(compiled) = self.try_compile(rip) {
                            let meta = CompiledRunMeta::from(&compiled);
                            self.insert_ready(rip, compiled);
                            return Ok(self.finish_compiled(rip, meta));
                        } else {
                            self.shared.cache.write().unwrap()
                                .insert(rip, CacheEntry::Never);
                        }
                    }
                }
                None => {
                    drop(cache);
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
                        self.shared.cache.write().unwrap()
                            .insert(rip, CacheEntry::Never);
                    } else {
                        self.shared.cache.write().unwrap()
                            .insert(rip, CacheEntry::Hot { visits: 1, thr });
                    }
                }
            }
        }

        // Iced does not maintain the shadow return stack — drop prediction.
        self.thread.shadow_sp = 0;
        self.stats.iced_insns = self.stats.iced_insns.saturating_add(1);
        // Inline step_once_result: push RIP trace, call exec::step, update counters.
        {
            let rip = self.thread.regs.rip;
            let i = self.thread.rip_trace_i & 31;
            if let Some(slot) = self.thread.rip_trace.get_mut(i) {
                *slot = rip;
            }
            self.thread.rip_trace_i = self.thread.rip_trace_i.wrapping_add(1);
            if self.thread.rip_trace_n < 32 {
                self.thread.rip_trace_n = self.thread.rip_trace_n.saturating_add(1);
            }
        }
        let hook = self.thread.hooks.as_ref();
        let result = exec::step(&mut *self.shared.mem.lock().unwrap(), &mut self.thread.regs, hook)?;
        if matches!(result, StepResult::Continue) {
            self.thread.iced_steps = self.thread.iced_steps.saturating_add(1);
        }
        self.drain_pending_code_writes();
        Ok((result, 1))
    }

    /// True when a Pure block at `rip` ends in a near-call to a registered UCRT fast API.
    fn peek_fast_ucrt_call(&self, rip: u64) -> bool {
        if self.fast_api.is_empty() {
            return false;
        }
        let mem = self.shared.mem.lock().unwrap();
        match decode_pure_gpr_block(&*mem, self.thread.hooks.as_ref(), rip) {
            BlockKind::Pure {
                term: Some(block::BlockTerm::Call { target, .. }),
                ..
            } => {
                let final_va = resolve_thunk_va(&*mem, target);
                self.fast_api_kind(final_va).is_some()
            }
            _ => false,
        }
    }

    fn peek_self_loop(&self, rip: u64) -> bool {
        let mem = self.shared.mem.lock().unwrap();
        let kind = decode_pure_gpr_block(&*mem, self.thread.hooks.as_ref(), rip);
        pure_is_self_loop(&kind, rip)
    }

    fn try_compile(&mut self, rip: u64) -> Option<CompiledBlock> {
        let mem_guard = self.shared.mem.lock().unwrap();
        let result = decode_pure_gpr_block(&*mem_guard, self.thread.hooks.as_ref(), rip);
        drop(mem_guard); // release before compiling (engine needs mutable access)
        match result {
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
                        xmm_live_mask: 0,
                        xmm_may_def_mask: 0,
                        guest_start: rip,
                        guest_end,
                    };
                    self.stats.compiles = self.stats.compiles.saturating_add(1);
                    if jit_chain_enabled() {
                        let fn_ptr = compiled.func as usize as u64;
                        chain_table_insert(
                            self.thread.chain_va.as_mut(),
                            self.thread.chain_fn.as_mut(),
                            rip,
                            fn_ptr,
                        );
                    }
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
                        let mem = self.shared.mem.lock().unwrap();
                        let final_va = resolve_thunk_va(&*mem, target);
                        drop(mem);
                        self.fast_api.iter()
                            .find_map(|&(k, kind)| (k == final_va).then_some(kind))
                    }
                    _ => None,
                };
                // Split borrows: `chain_ids` (Ready FuncIds) + `engine` mutably.
                let chain_on = jit_chain_enabled();
                let empty_chain = HashMap::new();
                let mut eng_guard = self.shared.engine.lock().unwrap();
                let eng = eng_guard.as_mut()?;
                let chain_ids = &*self.shared.chain_ids.read().unwrap();
                let chain_map = if chain_on { chain_ids } else { &empty_chain };
                match compile_block(
                    eng, rip, &insns, end_rip, term, call_fast, chain_map, bytes_len,
                ) {
                    Ok(compiled) => {
                        self.stats.compiles = self.stats.compiles.saturating_add(1);
                        if chain_on {
                            let fn_ptr = compiled.func as usize as u64;
                            chain_table_insert(
                                self.thread.chain_va.as_mut(),
                                self.thread.chain_fn.as_mut(),
                                rip,
                                fn_ptr,
                            );
                        }
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
                        self.stats.compile_skip = self.stats.compile_skip.saturating_add(1);
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
                .stats.jit_insns
                .saturating_add(u64::from(meta.insn_count));
            (
                StepResult::Continue,
                usize::try_from(meta.insn_count).unwrap_or(1),
            )
        }
    }

    /// Returns `Some(InvalidMem)` when a host mem helper faulted.
    fn run_compiled(&mut self, entry_rip: u64, meta: CompiledRunMeta) -> Option<exec::InvalidMem> {
        // Refresh pins only when GuestMemory generation changes (map/protect/free).
        // Rebuilding VAD-ranked pins every block was measurable on 7za.
        let mem_gen = self.shared.mem.lock().unwrap().generation();
        if self.thread.pins_gen != mem_gen {
            let infos = self.shared.mem.lock().unwrap().jit_region_pins();
            self.thread.pins = std::array::from_fn(|i| MemPin::from_info(infos[i]));
            self.thread.pins_gen = mem_gen;
        }
        // Gen-bump + pin-shape diagnostics (cheap; always on for stats).
        if self.last_mem_gen != 0 && mem_gen > self.last_mem_gen {
            self.stats.mem_gen_bumps = self
                .stats.mem_gen_bumps
                .saturating_add(mem_gen.saturating_sub(self.last_mem_gen));
        }
        self.last_mem_gen = mem_gen;
        if mem_gen > self.stats.mem_gen_peak {
            self.stats.mem_gen_peak = mem_gen;
        }
        {
            let stack = self.thread.pins[0];
            self.stats.pin_stack_bytes = if stack.host_base != 0 {
                stack.guest_end.saturating_sub(stack.guest_base)
            } else {
                0
            };
            let mut data_bytes = 0_u64;
            let mut bits = 0_u64;
            if stack.host_base != 0 {
                bits |= stack.allow & 0b11;
            }
            for (i, pin) in self.thread.pins.iter().enumerate().skip(1) {
                if pin.host_base == 0 {
                    continue;
                }
                data_bytes =
                    data_bytes.saturating_add(pin.guest_end.saturating_sub(pin.guest_base));
                // Pack first two data pins' allow into bits 2..5 for compact dump.
                if i <= 2 {
                    let shift = (i.saturating_sub(1).saturating_add(1)) * 2;
                    bits |= (pin.allow & 0b11) << shift;
                }
            }
            self.stats.pin_heap_bytes = data_bytes;
            self.stats.pin_allow_bits = bits;
        }
        let mut mem_guard = self.shared.mem.lock().unwrap();
        let mem_ptr = std::ptr::from_mut(&mut *mem_guard);
        let regs = &mut self.thread.regs;
        // Full GPR snapshot on entry: late-bound chaining reloads live regs from
        // JitCtx, so every architectural GPR must be valid for successors.
        let mut gpr = [0_u64; 16];
        for (i, slot) in gpr.iter_mut().enumerate() {
            *slot = regs.gpr(i);
        }
        // Pure GPR blocks skip the XMM bank copy on both sides of the call.
        // SSE blocks load only live XMMs (Phase 5.5 Track A live mask).
        let mut xmm = [XmmSlot::ZERO; 16];
        if meta.uses_sse {
            let mut m = meta.xmm_live_mask;
            // If mask is empty but uses_sse (fp-only edge), load all.
            if m == 0 {
                m = 0xffff;
            }
            let mut i = 0_usize;
            while m != 0 {
                if m & 1 != 0 {
                    let v = regs.xmm_at(i);
                    if let Some(slot) = xmm.get_mut(i) {
                        *slot = XmmSlot::from_u128(v);
                    }
                }
                m >>= 1;
                i = i.saturating_add(1);
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
            tlb_sets: self.thread.tlb_sets,
            tlb_aux: self.thread.tlb_aux,
            xmm,
            shadow_sp: self.thread.shadow_sp,
            shadow_ret: self.thread.shadow_ret,
            chain_va: self.thread.chain_va.as_mut_ptr(),
            chain_fn: self.thread.chain_fn.as_mut_ptr(),
            tlb_hot_page: self.thread.tlb_hot_page,
            tlb_hot_ptr: self.thread.tlb_hot_ptr,
            // 0 = Cranelift path (host falls back to full writeback);
            // trampolines OR their dirty bits; chain sets 0xffff.
            gpr_dirty_bits: 0,
            load_calls: 0,
            store_calls: 0,
            tlb_hot_prot: self.thread.tlb_hot_prot,
            mem_gen,
            tlb_hot_gen: self.thread.tlb_hot_gen,
            pins: self.thread.pins,
            edge_ic_va: self.thread.edge_ic_va,
            edge_ic_fn: self.thread.edge_ic_fn,
            edge_ic_rr: self.thread.edge_ic_rr,
            xmm_dirty_bits: 0,
            mem_path: MemPathSlice::default(),
            sticky_page: self.thread.sticky_page,
            sticky_ptr: self.thread.sticky_ptr,
            sticky_prot: self.thread.sticky_prot,
            sticky_gen: self.thread.sticky_gen,
            sticky_rr: self.thread.sticky_rr,
            // Fresh dispatcher entry always starts a new host-chain budget.
            chain_depth: 0,
        };
        // SAFETY: `func` is a finalized Cranelift block or hand-written trampoline.
        unsafe {
            (meta.func)(std::ptr::from_mut(&mut ctx));
        }
        drop(mem_guard); // GuestMemory no longer needed; drain_pending_code_writes locks it again
        self.stats.load_calls = self.stats.load_calls.saturating_add(ctx.load_calls);
        self.stats.store_calls = self.stats.store_calls.saturating_add(ctx.store_calls);
        {
            let m = &ctx.mem_path;
            let s = &mut self.stats;
            s.mem_sticky_hit = s.mem_sticky_hit.saturating_add(m.sticky_hit);
            s.mem_multi_hit = s.mem_multi_hit.saturating_add(m.multi_hit);
            s.mem_pin_hit = s.mem_pin_hit.saturating_add(m.pin_hit);
            s.mem_walk_hit = s.mem_walk_hit.saturating_add(m.walk_hit);
            s.mem_cross_page = s.mem_cross_page.saturating_add(m.cross_page);
            s.mem_slow = s.mem_slow.saturating_add(m.slow);
            s.mem_sticky_miss_key = s.mem_sticky_miss_key.saturating_add(m.sticky_miss_key);
            s.mem_sticky_miss_gen = s.mem_sticky_miss_gen.saturating_add(m.sticky_miss_gen);
            s.mem_sticky_miss_prot = s.mem_sticky_miss_prot.saturating_add(m.sticky_miss_prot);
            s.mem_sticky_swaps = s.mem_sticky_swaps.saturating_add(m.sticky_swaps);
            s.mem_addr_stack_pin = s.mem_addr_stack_pin.saturating_add(m.addr_in_stack_pin);
            s.mem_addr_heap_pin = s.mem_addr_heap_pin.saturating_add(m.addr_in_heap_pin);
            s.mem_addr_outside = s.mem_addr_outside.saturating_add(m.addr_outside_pins);
        }
        // Phase 4.x: guest stores via `GuestMemory::write` leave a pending range;
        // apply selective code invalidation only after the native frame returns.
        // Persist per-thread execution state from JitCtx.
        self.thread.tlb_sets = ctx.tlb_sets;
        self.thread.tlb_aux = ctx.tlb_aux;
        self.thread.tlb_hot_page = ctx.tlb_hot_page;
        self.thread.tlb_hot_ptr = ctx.tlb_hot_ptr;
        self.thread.tlb_hot_prot = ctx.tlb_hot_prot;
        self.thread.tlb_hot_gen = ctx.tlb_hot_gen;
        self.thread.sticky_page = ctx.sticky_page;
        self.thread.sticky_ptr = ctx.sticky_ptr;
        self.thread.sticky_prot = ctx.sticky_prot;
        self.thread.sticky_gen = ctx.sticky_gen;
        self.thread.sticky_rr = ctx.sticky_rr;
        self.thread.edge_ic_va = ctx.edge_ic_va;
        self.thread.edge_ic_fn = ctx.edge_ic_fn;
        self.thread.edge_ic_rr = ctx.edge_ic_rr;
        self.thread.shadow_sp = ctx.shadow_sp;
        self.thread.shadow_ret = ctx.shadow_ret;
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
            // Prefer dynamic dirty bits; on fault use may_def so partial defs are visible.
            let mut mask = if ctx.fault != 0 {
                u16::try_from(ctx.xmm_dirty_bits).unwrap_or(0xffff) | meta.xmm_may_def_mask
            } else if ctx.xmm_dirty_bits != 0 {
                u16::try_from(ctx.xmm_dirty_bits).unwrap_or(0)
            } else {
                meta.xmm_may_def_mask
            };
            if mask == 0 {
                mask = meta.xmm_live_mask;
            }
            let mut i = 0_usize;
            let mut m = mask;
            while m != 0 {
                if m & 1 != 0
                    && let Some(slot) = ctx.xmm.get(i)
                {
                    regs.set_xmm_at(i, slot.to_u128());
                }
                m >>= 1;
                i = i.saturating_add(1);
            }
        }
        regs.rflags = ctx.rflags;
        regs.rip = ctx.rip;
        let fault = if ctx.fault != 0 {
            Some(exec::InvalidMem {
                access_type: i32::try_from(ctx.fault_access).unwrap_or(0),
                address: ctx.fault_addr,
                size: i32::try_from(ctx.fault_size).unwrap_or(0),
                value: 0,
            })
        } else {
            None
        };
        // Safe point: drop Ready blocks overlapping any stores from this block.
        self.drain_pending_code_writes();
        fault
    }

    fn invalidate_tlb(&mut self) {
        self.thread.tlb_sets = [empty_tlb_bucket(); TLB_SETS];
        self.thread.tlb_aux = [empty_tlb_aux(); TLB_SETS];
        self.thread.tlb_hot_page = TLB_EMPTY;
        self.thread.tlb_hot_ptr = std::ptr::null_mut();
        self.thread.tlb_hot_prot = 0;
        self.thread.tlb_hot_gen = 0;
        self.thread.sticky_page = [TLB_EMPTY; STICKY_WAYS];
        self.thread.sticky_ptr = [std::ptr::null_mut(); STICKY_WAYS];
        self.thread.sticky_prot = [0; STICKY_WAYS];
        self.thread.sticky_gen = [0; STICKY_WAYS];
        self.thread.sticky_rr = 0;
        self.thread.pins = [MemPin::EMPTY; PIN_SLOTS];
        self.thread.pins_gen = u64::MAX;
    }

    fn invalidate_chain_and_shadow(&mut self) {
        chain_table_clear(self.thread.chain_va.as_mut(), self.thread.chain_fn.as_mut());
        self.thread.edge_ic_va = [0; lower::EDGE_IC_SLOTS];
        self.thread.edge_ic_fn = [0; lower::EDGE_IC_SLOTS];
        self.thread.edge_ic_rr = 0;
        self.thread.shadow_sp = 0;
        self.thread.shadow_ret = [0; lower::SHADOW_DEPTH];
    }
}

/// Snapshot of a Ready block needed to run it without holding a cache borrow.
#[derive(Clone, Copy)]
struct CompiledRunMeta {
    func: unsafe extern "C" fn(*mut JitCtx),
    insn_count: u32,
    uses_sse: bool,
    /// XMMi referenced in the block (selective entry load).
    xmm_live_mask: u16,
    /// XMMi that may be defined (conservative exit writeback on fault).
    xmm_may_def_mask: u16,
}

impl From<&CompiledBlock> for CompiledRunMeta {
    fn from(c: &CompiledBlock) -> Self {
        Self {
            func: c.func,
            insn_count: c.insn_count,
            uses_sse: c.uses_sse,
            xmm_live_mask: c.xmm_live_mask,
            xmm_may_def_mask: c.xmm_may_def_mask,
        }
    }
}

/// Half-open range overlap: `[a0, a1)` vs `[b0, b1)`.
#[inline]
fn ranges_overlap(a0: u64, a1: u64, b0: u64, b1: u64) -> bool {
    a0 < b1 && b0 < a1
}

/// Follow PE import thunks / short jumps to the final callee VA.
fn resolve_thunk_va(mem: &GuestMemory, mut va: u64) -> u64 {
    let mut buf = [0_u8; 16];
    for _ in 0..4 {
        if mem.read(va, &mut buf).is_err() {
            return va;
        }
        if buf[0] == 0xff && buf[1] == 0x25 {
            let rel = i32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
            let iat = va
                .wrapping_add(6)
                .wrapping_add(i64::from(rel).cast_unsigned());
            let mut slot = [0_u8; 8];
            if mem.read(iat, &mut slot).is_ok() {
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

/// Cranelift `opt_level` from `WIE_JIT_OPT` (`speed` | `speed_and_size` | `none`).
/// Default: `speed` (Phase 5.5 — hot guest blocks over code size).
fn jit_opt_level() -> &'static str {
    use std::sync::OnceLock;
    static LVL: OnceLock<&'static str> = OnceLock::new();
    LVL.get_or_init(|| match std::env::var("WIE_JIT_OPT") {
        Ok(v) if v.eq_ignore_ascii_case("none") || v == "0" => "none",
        Ok(v)
            if v.eq_ignore_ascii_case("speed_and_size")
                || v.eq_ignore_ascii_case("size")
                || v.eq_ignore_ascii_case("speed-and-size") =>
        {
            "speed_and_size"
        }
        Ok(v) if v.eq_ignore_ascii_case("speed") || v.eq_ignore_ascii_case("fast") => "speed",
        _ => "speed",
    })
}

/// Run Cranelift IR verifier (`WIE_JIT_VERIFY=1` or always under `cfg(test)`).
fn jit_verifier_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    if cfg!(test) {
        return true;
    }
    *ON.get_or_init(|| {
        matches!(
            std::env::var("WIE_JIT_VERIFY"),
            Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on")
        )
    })
}

impl JitEngine {
    fn new() -> Result<Self, String> {
        use cranelift::prelude::*;
        use cranelift_codegen::settings::Configurable;
        use cranelift_jit::{JITBuilder, JITModule};
        use cranelift_module::{Linkage, Module, default_libcall_names};

        let mut flag_builder = settings::builder();
        // Phase 5.5 Track D: prefer speed of host code for hot translated blocks.
        flag_builder
            .set("opt_level", jit_opt_level())
            .map_err(|e| e.to_string())?;
        let verify = if jit_verifier_enabled() {
            "true"
        } else {
            "false"
        };
        flag_builder
            .set("enable_verifier", verify)
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
        // Guest frames are not host-unwound; skip metadata tax.
        flag_builder
            .set("unwind_info", "false")
            .map_err(|e| e.to_string())?;
        // Not a Wasm sandbox heap — soft-translate already bounds guest accesses.
        flag_builder
            .set("enable_heap_access_spectre_mitigation", "false")
            .map_err(|e| e.to_string())?;

        let mut isa_builder =
            cranelift_native::builder().map_err(|msg| format!("host ISA unsupported: {msg}"))?;
        // Apple Silicon: cranelift_native already enables LSE/PAC/FP16 + macOS PAC B-key.
        // Re-assert PAC signing so JIT call/return stays ABI-consistent if detect fails.
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        {
            isa_builder
                .enable("sign_return_address")
                .map_err(|e| e.to_string())?;
            isa_builder
                .enable("sign_return_address_with_bkey")
                .map_err(|e| e.to_string())?;
            isa_builder.enable("has_pauth").map_err(|e| e.to_string())?;
        }
        let isa = isa_builder
            .finish(settings::Flags::new(flag_builder))
            .map_err(|e| e.to_string())?;

        let mut builder = JITBuilder::with_isa(isa, default_libcall_names());
        // SAFETY: function pointers are valid for the process lifetime.
        builder.symbol("wie_jit_load", wie_jit_load as *const u8);
        builder.symbol("wie_jit_store", wie_jit_store as *const u8);
        builder.symbol("wie_jit_string", wie_jit_string as *const u8);
        builder.symbol("wie_jit_host_span", wie_jit_host_span as *const u8);
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

        // host_span: (ctx, guest_va, len, write) -> host_ptr_or_0
        let mut span_sig = module.make_signature();
        span_sig.params.push(AbiParam::new(types::I64));
        span_sig.params.push(AbiParam::new(types::I64));
        span_sig.params.push(AbiParam::new(types::I64));
        span_sig.params.push(AbiParam::new(types::I64));
        span_sig.returns.push(AbiParam::new(types::I64));
        let host_span_id = module
            .declare_function("wie_jit_host_span", Linkage::Import, &span_sig)
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
            host_span_id,
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
        self.shared.mem.lock().unwrap().map(address, size, perms)
    }

    fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        self.shared.mem.lock().unwrap().write(address, bytes)?;
        self.drain_pending_code_writes();
        Ok(())
    }

    fn mem_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        self.shared.mem.lock().unwrap().read(address, bytes)
    }

    fn host_span(&mut self, address: u64, len: usize, write: bool) -> Option<*mut u8> {
        self.shared.mem.lock().unwrap().host_span(address, len, write)
    }

    fn mem_generation(&self) -> u64 {
        self.shared.mem.lock().unwrap().generation()
    }

    fn virtual_alloc(
        &mut self,
        addr: u64,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> Result<u64, CpuError> {
        let r = self.shared.mem.lock().unwrap().virtual_alloc(addr, size, alloc_type, protect);
        self.invalidate_tlb();
        r
    }

    fn virtual_free(&mut self, addr: u64, size: usize, free_type: u32) -> Result<(), CpuError> {
        let inv_span = self.code_inv_span_for_free(addr, size, free_type);
        self.invalidate_tlb();
        let r = self.shared.mem.lock().unwrap().virtual_free(addr, size, free_type);
        if r.is_ok()
            && let Some((a, n)) = inv_span
        {
            self.invalidate_code_range(a, n);
        }
        r
    }

    fn virtual_protect(
        &mut self,
        addr: u64,
        size: usize,
        new_protect: u32,
    ) -> Result<u32, CpuError> {
        let r = self.shared.mem.lock().unwrap().virtual_protect(addr, size, new_protect);
        if r.is_ok() && !protect::allows_execute(new_protect) {
            self.invalidate_code_range(addr, size);
        }
        self.invalidate_tlb();
        r
    }

    fn virtual_query(&self, addr: u64) -> crate::MemoryBasicInformation {
        self.shared.mem.lock().unwrap().virtual_query(addr)
    }

    fn flush_instruction_cache(&mut self, addr: u64, size: usize) -> Result<(), CpuError> {
        if size == 0 {
            if !self.shared.cache.read().unwrap().is_empty() {
                self.clear_compiled();
                self.invalidate_chain_and_shadow();
                self.stats.code_invs = self.stats.code_invs.saturating_add(1);
            }
        } else {
            self.invalidate_code_range(addr, size);
        }
        Ok(())
    }

    fn mem_map_image(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        let r = self.shared.mem.lock().unwrap().map_image(address, size, perms);
        self.invalidate_tlb();
        r
    }

    fn cpu_stats(&self) -> Option<crate::JitStats> {
        Some(self.stats)
    }

    fn mem_backend_name(&self) -> &'static str {
        self.shared.mem.lock().unwrap().backend_name()
    }

    fn register_region(&mut self, region: crate::mem::GuestRegion) {
        self.shared.mem.lock().unwrap().register_region(region);
    }

    fn find_region(&self, va: u64) -> Option<crate::mem::GuestRegion> {
        self.shared.mem.lock().unwrap().find_region(va).cloned()
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
        let range_len = hook_end.saturating_sub(hook_begin).saturating_add(1);
        let expected_bytes = usize::try_from(range_len).unwrap_or(usize::MAX).div_ceil(8);
        if expected_bytes != usize::MAX && stop_bitmap.len() < expected_bytes {
            return Err(CpuError::Message(format!(
                "stop_bitmap too small: {} < {expected_bytes}",
                stop_bitmap.len()
            )));
        }
        self.thread.hooks = Some(HookWindow {
            begin: hook_begin,
            end: hook_end,
            stop_bitmap,
        });
        Ok(())
    }

    fn configure_jit_fast_path(&mut self, cfg: JitFastPathConfig) {
        self.configure_fast_path(cfg);
        self.invalidate_chain_and_shadow();
    }

    fn precompile_at(&mut self, address: u64) {
        if self.shared.engine.lock().unwrap().is_none() {
            return;
        }
        if let Some(hook) = self.thread.hooks.as_ref()
            && hook.should_host_stop(address)
        {
            return;
        }
        if let Some(compiled) = self.try_compile(address) {
            self.insert_ready(address, compiled);
        } else {
            self.shared.cache.write().unwrap().entry(address).or_insert(CacheEntry::Never);
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
        self.thread.regs.rip = begin;
        let budget = if count == 0 { 100_000_000_usize } else { count };
        let mut executed = 0_usize;
        while executed < budget {
            let rip = self.thread.regs.rip;
            if until != 0 && rip == until {
                break;
            }
            if let Some(hook) = self.thread.hooks.as_ref()
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
            let mut chain_result = None;
            if self.shared.engine.lock().unwrap().is_some() {
                let meta = {
                    let cache = self.shared.cache.read().unwrap();
                    cache.get(&rip).and_then(|e| match e {
                        CacheEntry::Ready(c) => Some(CompiledRunMeta::from(c)),
                        _ => None,
                    })
                };
                if let Some(meta) = meta {
                    self.stats.cache_hits = self.stats.cache_hits.saturating_add(1);
                    let (result, retired) = self.finish_compiled(rip, meta);
                    match result {
                        StepResult::Continue => {
                            executed = executed.saturating_add(retired.max(1));
                            continue;
                        }
                        other => { chain_result = Some(other); }
                    }
                }
            }
            if let Some(result) = chain_result {
                return match result {
                    StepResult::HostStop { address, size } => Ok(RunUntilHook {
                        code: CodeHookOutcome { hit: true, address, size },
                        invalid_memory: InvalidMemoryAccess { hit: false, access_type: 0, address: 0, size: 0, value: 0 },
                    }),
                    StepResult::InvalidMemory(inv) => Ok(RunUntilHook {
                        code: CodeHookOutcome { hit: false, address: 0, size: 0 },
                        invalid_memory: InvalidMemoryAccess { hit: true, access_type: inv.access_type, address: inv.address, size: inv.size, value: inv.value },
                    }),
                    StepResult::Continue => unreachable!(),
                };
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
        self.thread.shadow_sp = 0;
        let rsp = self.thread.regs.rsp();
        let mut ret_bytes = [0_u8; 8];
        self.shared.mem.lock().unwrap()
            .read(rsp, &mut ret_bytes)
            .map_err(|e| CpuError::Message(format!("return_from_win64_api stack read: {e}")))?;
        let return_address = u64::from_le_bytes(ret_bytes);
        self.thread.regs.set_rsp(rsp.wrapping_add(8));
        self.thread.regs.set_rax(rax);
        self.thread.regs.rip = return_address;
        Ok(return_address)
    }

    fn read_rip(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.rip) }
    fn write_rip(&mut self, value: u64) -> Result<(), CpuError> { self.thread.regs.rip = value; Ok(()) }
    fn read_rsp(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.rsp()) }
    fn write_rsp(&mut self, value: u64) -> Result<(), CpuError> { self.thread.regs.set_rsp(value); Ok(()) }
    fn read_rax(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.rax()) }
    fn write_rax(&mut self, value: u64) -> Result<(), CpuError> { self.thread.regs.set_rax(value); Ok(()) }
    fn read_rcx(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.rcx()) }
    fn write_rcx(&mut self, value: u64) -> Result<(), CpuError> { self.thread.regs.set_rcx(value); Ok(()) }
    fn read_rdx(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.rdx()) }
    fn write_rdx(&mut self, value: u64) -> Result<(), CpuError> { self.thread.regs.set_rdx(value); Ok(()) }
    fn read_r8(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.r8()) }
    fn write_r8(&mut self, value: u64) -> Result<(), CpuError> { self.thread.regs.set_r8(value); Ok(()) }
    fn read_r9(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.r9()) }
    fn write_r9(&mut self, value: u64) -> Result<(), CpuError> { self.thread.regs.set_r9(value); Ok(()) }
    fn read_rbx(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.gpr(3)) }
    fn read_r12(&mut self) -> Result<u64, CpuError> { Ok(self.thread.regs.gpr(12)) }

    fn snapshot_thread_context(&mut self) -> crate::ThreadContext {
        self.thread.regs.snapshot()
    }

    fn restore_thread_context(&mut self, ctx: &crate::ThreadContext) {
        self.thread.regs.restore(ctx);
    }

    fn on_thread_switch(&mut self) {
        self.invalidate_tlb();
        self.invalidate_chain_and_shadow();
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mem::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE};
    use crate::perm;

    unsafe extern "C" fn dummy_block(_ctx: *mut JitCtx) {}

    impl JitCpu {
        /// Test helper: plant a Ready entry without Cranelift.
        fn test_plant_ready(&mut self, rip: u64, guest_end: u64) {
            self.insert_ready(
                rip,
                CompiledBlock {
                    func: dummy_block,
                    func_id: None,
                    insn_count: 1,
                    uses_sse: false,
                    xmm_live_mask: 0,
                    xmm_may_def_mask: 0,
                    guest_start: rip,
                    guest_end,
                },
            );
            if jit_chain_enabled() {
                let fn_ptr = dummy_block as *const () as usize as u64;
                chain_table_insert(self.thread.chain_va.as_mut(), self.thread.chain_fn.as_mut(), rip, fn_ptr);
            }
            // Simulate edge IC hit for S6.
            self.thread.edge_ic_va[0] = rip;
            self.thread.edge_ic_fn[0] = dummy_block as *const () as usize as u64;
        }
    }

    #[test]
    fn code_inv_x_loss_drops_ready() {
        let mut cpu = JitCpu::open_x86_64();
        let base = 0x1000_0000_u64;
        cpu.virtual_alloc(
            base,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_EXECUTE_READWRITE,
        )
        .expect("alloc");
        cpu.test_plant_ready(base, base + 16);
        assert!(cpu.has_ready_at(base));
        assert!(cpu.code_pages_overlap(base, 16));

        cpu.virtual_protect(base, 0x1000, protect::PAGE_READONLY)
            .expect("x-loss");
        assert!(!cpu.has_ready_at(base));
        assert!(!cpu.code_pages_overlap(base, 16));
        assert_eq!(cpu.thread.edge_ic_va[0], 0);
        assert!(cpu.stats().code_invs >= 1);
    }

    #[test]
    fn code_inv_smc_write_drops_ready() {
        let mut cpu = JitCpu::open_x86_64();
        let base = 0x1001_0000_u64;
        cpu.virtual_alloc(
            base,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_EXECUTE_READWRITE,
        )
        .expect("alloc");
        cpu.test_plant_ready(base + 0x10, base + 0x20);
        assert!(cpu.has_ready_at(base + 0x10));

        // Guest/host store into compiled range.
        cpu.mem_write(base + 0x12, &[0x90, 0x90]).expect("smc");
        assert!(!cpu.has_ready_at(base + 0x10));
        assert_eq!(cpu.thread.edge_ic_fn[0], 0);
    }

    #[test]
    fn code_inv_data_write_leaves_code() {
        let mut cpu = JitCpu::open_x86_64();
        let code = 0x1002_0000_u64;
        let data = 0x1003_0000_u64;
        cpu.virtual_alloc(
            code,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_EXECUTE_READWRITE,
        )
        .expect("code");
        cpu.virtual_alloc(
            data,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_READWRITE,
        )
        .expect("data");
        cpu.test_plant_ready(code, code + 8);
        let invs = cpu.stats().code_invs;
        cpu.mem_write(data, &[1, 2, 3, 4]).expect("data write");
        assert!(cpu.has_ready_at(code));
        assert_eq!(cpu.stats().code_invs, invs);
        assert_eq!(cpu.thread.edge_ic_va[0], code);
    }

    #[test]
    fn code_inv_free_drops_ready() {
        let mut cpu = JitCpu::open_x86_64();
        let base = 0x1004_0000_u64;
        cpu.virtual_alloc(
            base,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_EXECUTE_READWRITE,
        )
        .expect("alloc");
        cpu.test_plant_ready(base, base + 4);
        cpu.virtual_free(base, 0, MEM_RELEASE).expect("free");
        assert!(!cpu.has_ready_at(base));
        assert!(cpu.shared.code_pages.lock().unwrap().is_empty());
    }

    #[test]
    fn code_inv_rx_stays_on_x_preserve() {
        let mut cpu = JitCpu::open_x86_64();
        let base = 0x1005_0000_u64;
        cpu.virtual_alloc(
            base,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_EXECUTE_READWRITE,
        )
        .expect("alloc");
        cpu.test_plant_ready(base, base + 8);
        // Keep execute; only drop write — code content unchanged.
        cpu.virtual_protect(base, 0x1000, protect::PAGE_EXECUTE_READ)
            .expect("rx");
        assert!(cpu.has_ready_at(base));
    }

    #[test]
    fn ranges_overlap_half_open() {
        assert!(ranges_overlap(0x10, 0x20, 0x1f, 0x30));
        assert!(!ranges_overlap(0x10, 0x20, 0x20, 0x30));
        assert!(ranges_overlap(0x10, 0x20, 0x00, 0x11));
    }

    #[test]
    fn no_w_tlb_on_executable_page() {
        let mut cpu = JitCpu::open_x86_64();
        let base = 0x1006_0000_u64;
        cpu.virtual_alloc(
            base,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_EXECUTE_READWRITE,
        )
        .expect("alloc");
        let e = cpu
            .shared.mem.lock().unwrap()
            .page_tlb_entry(base >> 12)
            .expect("tlb");
        assert!(e.allow_r);
        assert!(!e.allow_w);
        let data = 0x1007_0000_u64;
        cpu.virtual_alloc(
            data,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_READWRITE,
        )
        .expect("data");
        let e2 = cpu
            .shared.mem.lock().unwrap()
            .page_tlb_entry(data >> 12)
            .expect("data tlb");
        assert!(e2.allow_r && e2.allow_w);
        let _ = perm::ALL; // silence if unused in some cfgs
    }

    // --- Phase 7 stress residual (invalidation multi-region / FIC) ---

    #[test]
    fn code_inv_smc_across_page_boundary() {
        let mut cpu = JitCpu::open_x86_64();
        let base = 0x1010_0000_u64;
        cpu.virtual_alloc(
            base,
            0x2000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_EXECUTE_READWRITE,
        )
        .expect("alloc 2 pages");
        // Ready block straddles page boundary (last 8 B of page0 + first of page1).
        let entry = base + 0x0ff8;
        cpu.test_plant_ready(entry, entry + 16);
        assert!(cpu.has_ready_at(entry));
        // Store on page1 half of the range.
        cpu.mem_write(base + 0x1000, &[0x90, 0x90]).expect("smc p1");
        assert!(!cpu.has_ready_at(entry));
        assert_eq!(cpu.thread.edge_ic_va[0], 0);
    }

    #[test]
    fn code_inv_multi_region_protect_and_free() {
        let mut cpu = JitCpu::open_x86_64();
        let a = 0x1011_0000_u64;
        let b = 0x1012_0000_u64;
        for base in [a, b] {
            cpu.virtual_alloc(
                base,
                0x1000,
                MEM_RESERVE | MEM_COMMIT,
                protect::PAGE_EXECUTE_READWRITE,
            )
            .expect("alloc");
            cpu.test_plant_ready(base, base + 8);
        }
        assert!(cpu.has_ready_at(a) && cpu.has_ready_at(b));
        // X-loss on A only.
        cpu.virtual_protect(a, 0x1000, protect::PAGE_READONLY)
            .expect("protect a");
        assert!(!cpu.has_ready_at(a));
        assert!(cpu.has_ready_at(b));
        assert_eq!(cpu.thread.edge_ic_va[0], 0); // edge IC cleared on any selective drop
        // Free B.
        cpu.virtual_free(b, 0, MEM_RELEASE).expect("free b");
        assert!(!cpu.has_ready_at(b));
    }

    #[test]
    fn flush_instruction_cache_drops_ready_range() {
        let mut cpu = JitCpu::open_x86_64();
        let base = 0x1013_0000_u64;
        cpu.virtual_alloc(
            base,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            protect::PAGE_EXECUTE_READWRITE,
        )
        .expect("alloc");
        cpu.test_plant_ready(base, base + 16);
        assert!(cpu.has_ready_at(base));
        cpu.flush_instruction_cache(base, 16).expect("fic");
        assert!(!cpu.has_ready_at(base));
        assert!(cpu.stats().code_invs >= 1);
    }

    #[test]
    fn flush_instruction_cache_size_zero_clears_all() {
        let mut cpu = JitCpu::open_x86_64();
        let a = 0x1014_0000_u64;
        let b = 0x1015_0000_u64;
        for base in [a, b] {
            cpu.virtual_alloc(
                base,
                0x1000,
                MEM_RESERVE | MEM_COMMIT,
                protect::PAGE_EXECUTE_READWRITE,
            )
            .expect("alloc");
            cpu.test_plant_ready(base, base + 4);
        }
        cpu.flush_instruction_cache(0, 0).expect("fic all");
        assert!(!cpu.has_ready_at(a));
        assert!(!cpu.has_ready_at(b));
        assert!(cpu.shared.code_pages.lock().unwrap().is_empty());
    }
}
