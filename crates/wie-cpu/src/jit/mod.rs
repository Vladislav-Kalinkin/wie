//! Phase 2: hybrid Cranelift block JIT + iced interpreter fallback.
//!
//! **Strategy:** decode a lowerable block at RIP (GPR, mem, ALU, shift, call/ret,
//! jcc); if hot enough, compile once and cache by guest entry VA. SSE / complex
//! forms / cold sites → iced `step`.
//!
//! Unicorn remains the product default until Phase 3.

#![allow(
    unsafe_code, // Cranelift finalized fn pointers + host mem helpers
    clippy::indexing_slicing, // fixed gpr[0..16]
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]

mod block;
mod lower;

use crate::exec::{self, StepResult};
use crate::iced_cpu::IcedCpu;
use crate::{CpuEngine, CpuError, RunUntilHook};
use block::{BlockKind, decode_pure_gpr_block};
use crate::{CodeHookOutcome, InvalidMemoryAccess};
use lower::{
    CompiledBlock, JitCtx, TLB_EMPTY, TLB_WAYS, compile_block, wie_jit_load, wie_jit_store,
};
use std::collections::HashMap;

/// Compile after this many visits to the same guest entry (skip cold code).
/// Higher values cut compile tax on open-rom (mem/push coverage widens Pure set).
/// Tests use 0 (eager compile on first Pure decode).
fn hotness_threshold() -> u32 {
    if cfg!(test) {
        0
    } else {
        5
    }
}

/// Hybrid CPU: Cranelift for hot pure-GPR blocks, iced for everything else.
pub struct JitCpu {
    iced: IcedCpu,
    /// `None` if host ISA / JIT module failed to open (always fall back to iced).
    engine: Option<JitEngine>,
    /// Guest block entry VA → cache entry.
    cache: HashMap<u64, CacheEntry>,
    stats: JitStats,
    /// Persistent multi-way page TLB across chained blocks (invalidate on mem_write/hooks).
    tlb_page: [u64; TLB_WAYS],
    tlb_ptr: [*mut u8; TLB_WAYS],
    tlb_rr: u64,
}

enum CacheEntry {
    /// Native block ready to run.
    Ready(CompiledBlock),
    /// Do not retry decode/compile at this VA (cold fail or non-pure).
    Never,
    /// Visit counter before compile attempt.
    Hot(u32),
}

struct JitEngine {
    module: cranelift_jit::JITModule,
    ctx: cranelift_codegen::Context,
    func_ctx: cranelift::prelude::FunctionBuilderContext,
    next_name: u32,
    /// Shared signature: `(i64 ctx_ptr)`.
    block_sig: cranelift::codegen::ir::Signature,
    /// Host `wie_jit_load` import.
    load_id: cranelift_module::FuncId,
    /// Host `wie_jit_store` import.
    store_id: cranelift_module::FuncId,
}

/// Lightweight counters for `WIE_CPU=jit` diagnostics.
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
            stats: JitStats::default(),
            tlb_page: [TLB_EMPTY; TLB_WAYS],
            tlb_ptr: [std::ptr::null_mut(); TLB_WAYS],
            tlb_rr: 0,
        }
    }

    /// JIT vs interpreter retirement counters.
    #[must_use]
    pub fn stats(&self) -> JitStats {
        self.stats
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
                    let n = compiled.insn_count;
                    let func = compiled.func;
                    return Ok(self.finish_compiled(rip, func, n));
                }
                Some(CacheEntry::Never) => {
                    // Fast path: known non-JIT site.
                }
                Some(CacheEntry::Hot(n)) => {
                    let next = n.saturating_add(1);
                    let thr = hotness_threshold();
                    if thr > 0 && next < thr {
                        self.cache.insert(rip, CacheEntry::Hot(next));
                    } else if let Some(compiled) = self.try_compile(rip) {
                        let n = compiled.insn_count;
                        let func = compiled.func;
                        self.cache.insert(rip, CacheEntry::Ready(compiled));
                        return Ok(self.finish_compiled(rip, func, n));
                    } else {
                        self.cache.insert(rip, CacheEntry::Never);
                    }
                }
                None => {
                    if hotness_threshold() == 0 {
                        // Eager (tests): compile immediately if Pure.
                        if let Some(compiled) = self.try_compile(rip) {
                            let n = compiled.insn_count;
                            let func = compiled.func;
                            self.cache.insert(rip, CacheEntry::Ready(compiled));
                            return Ok(self.finish_compiled(rip, func, n));
                        }
                        self.cache.insert(rip, CacheEntry::Never);
                    } else {
                        // First visit: start hotness, interpret (avoid compile on cold code).
                        self.cache.insert(rip, CacheEntry::Hot(1));
                    }
                }
            }
        }

        self.stats.iced_insns = self.stats.iced_insns.saturating_add(1);
        Ok((self.iced.step_once_result()?, 1))
    }

    fn try_compile(&mut self, rip: u64) -> Option<CompiledBlock> {
        match decode_pure_gpr_block(&self.iced, rip) {
            BlockKind::Pure {
                insns,
                end_rip,
                bytes_len,
                term,
            } => {
                let eng = self.engine.as_mut()?;
                match compile_block(eng, rip, &insns, end_rip, term) {
                    Ok(compiled) => {
                        self.stats.compiles = self.stats.compiles.saturating_add(1);
                        tracing::debug!(
                            start = format_args!("{rip:#x}"),
                            end = format_args!("{end_rip:#x}"),
                            insns = compiled.insn_count,
                            bytes = bytes_len,
                            has_term = term.is_some(),
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

    fn finish_compiled(
        &mut self,
        entry_rip: u64,
        func: unsafe extern "C" fn(*mut JitCtx),
        n: u32,
    ) -> (StepResult, usize) {
        if let Some(inv) = self.run_compiled(entry_rip, func) {
            (StepResult::InvalidMemory(inv), 0)
        } else {
            self.stats.jit_insns = self.stats.jit_insns.saturating_add(u64::from(n));
            (StepResult::Continue, usize::try_from(n).unwrap_or(1))
        }
    }

    /// Returns `Some(InvalidMem)` when a host mem helper faulted.
    fn run_compiled(
        &mut self,
        entry_rip: u64,
        func: unsafe extern "C" fn(*mut JitCtx),
    ) -> Option<exec::InvalidMem> {
        let mem_ptr = std::ptr::from_mut(self.iced.guest_mem_mut());
        let regs = self.iced.regs_mut();
        let mut gpr = [0_u64; 16];
        for (i, slot) in gpr.iter_mut().enumerate() {
            *slot = regs.gpr(i);
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
        };
        // SAFETY: `func` was finalized by Cranelift for this process; `ctx` is valid.
        unsafe {
            func(std::ptr::from_mut(&mut ctx));
        }
        // Persist multi-way TLB across chained blocks (same guest map).
        self.tlb_page = ctx.tlb_page;
        self.tlb_ptr = ctx.tlb_ptr;
        self.tlb_rr = ctx.tlb_rr;
        for i in 0..16 {
            if let Some(&v) = ctx.gpr.get(i) {
                regs.set_gpr(i, v);
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
    }
}

impl JitEngine {
    fn new() -> Result<Self, String> {
        use cranelift::prelude::*;
        use cranelift_jit::{JITBuilder, JITModule};
        use cranelift_module::{Linkage, Module, default_libcall_names};

        let mut flag_builder = settings::builder();
        flag_builder
            .set("use_colocated_libcalls", "false")
            .map_err(|e| e.to_string())?;
        flag_builder
            .set("is_pic", "false")
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
        let mut module = JITModule::new(builder);

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

        Ok(Self {
            module,
            ctx: cranelift_codegen::Context::new(),
            func_ctx: FunctionBuilderContext::new(),
            next_name: 0,
            block_sig,
            load_id,
            store_id,
        })
    }
}

impl CpuEngine for JitCpu {
    fn mem_map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        self.iced.mem_map(address, size, perms)
    }

    fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        // Self-modifying / patched guest code: drop JIT cache (simple, correct).
        if !self.cache.is_empty() {
            self.cache.clear();
        }
        self.invalidate_tlb();
        self.iced.mem_write(address, bytes)
    }

    fn mem_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        self.iced.mem_read(address, bytes)
    }

    fn install_runtime_hooks(
        &mut self,
        hook_begin: u64,
        hook_end: u64,
        stop_bitmap: Vec<u8>,
    ) -> Result<(), CpuError> {
        self.cache.clear();
        self.invalidate_tlb();
        self.iced
            .install_runtime_hooks(hook_begin, hook_end, stop_bitmap)
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
        let budget = if count == 0 {
            100_000_000_usize
        } else {
            count
        };
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
                let n = compiled.insn_count;
                let func = compiled.func;
                let (result, retired) = self.finish_compiled(rip, func, n);
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
