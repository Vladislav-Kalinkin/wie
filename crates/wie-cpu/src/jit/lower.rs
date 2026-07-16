//! Lower pure-GPR (+ simple mem / jcc) blocks to Cranelift IR and finalize host code.

#![allow(
    clippy::indexing_slicing, // fixed gpr[0..16] / TLB ways
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names, // flag temps d/s/r in flags_* helpers
    clippy::too_many_arguments
)]

use super::JitEngine;
use super::block::{BlockTerm, DecodedInsn, is_string_op, mem_width_bytes, string_op_size};
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

/// Associative guest-page TLB ways (stack vs heap thrashing).
pub(super) const TLB_WAYS: usize = 32;
/// Empty TLB slot marker (`page_key == TLB_EMPTY`).
pub(super) const TLB_EMPTY: u64 = u64::MAX;

/// Open-addressing slots for guest-VA → host block fn (block chaining).
pub(super) const CHAIN_SLOTS: usize = 512;
/// Shadow return-stack depth (power of two; modular index).
pub(super) const SHADOW_DEPTH: usize = 32;

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
    /// Multi-way page TLB: guest page keys (`va >> 12`), or [`TLB_EMPTY`].
    pub tlb_page: [u64; TLB_WAYS],
    /// Host pointers to mapped page data (parallel to `tlb_page`).
    pub tlb_ptr: [*mut u8; TLB_WAYS],
    /// Round-robin victim index for TLB fill.
    pub tlb_rr: u64,
    /// XMM0..XMM15 as lo/hi u64 pairs (`xmm[2*i]` = low 64, `xmm[2*i+1]` = high 64).
    /// Appended so existing OFF_* constants stay stable.
    pub xmm: [u64; 32],
    /// Shadow return stack: push count (modular index via `sp & (SHADOW_DEPTH-1)`).
    pub shadow_sp: u64,
    /// Predicted guest return addresses for `call`/`ret` chaining.
    pub shadow_ret: [u64; SHADOW_DEPTH],
    /// Pointer to [`CHAIN_SLOTS`] guest VAs (owned by `JitCpu`, live for `run_compiled`).
    pub chain_va: *mut u64,
    /// Parallel host fn pointers (`0` = empty), same lifetime as `chain_va`.
    pub chain_fn: *mut u64,
}

// Byte offsets into [`JitCtx`] used from Cranelift IR (must match `repr(C)`).
// gpr[16] @ 0, rflags @ 128, rip @ 136, mem @ 144, fault @ 152, …
const OFF_RFLAGS: i32 = std::mem::offset_of!(JitCtx, rflags) as i32;
const OFF_RIP: i32 = std::mem::offset_of!(JitCtx, rip) as i32;
const OFF_FAULT: i32 = std::mem::offset_of!(JitCtx, fault) as i32;
const OFF_SHADOW_SP: i32 = std::mem::offset_of!(JitCtx, shadow_sp) as i32;
const OFF_XMM: i32 = std::mem::offset_of!(JitCtx, xmm) as i32;
const OFF_SHADOW_RET: i32 = OFF_SHADOW_SP + 8;

// Layout sanity: Cranelift IR offsets must match `repr(C)` packing.
const _: () = {
    assert!(std::mem::offset_of!(JitCtx, rflags) as i32 == OFF_RFLAGS);
    assert!(std::mem::offset_of!(JitCtx, rip) as i32 == OFF_RIP);
    assert!(std::mem::offset_of!(JitCtx, fault) as i32 == OFF_FAULT);
    assert!(std::mem::offset_of!(JitCtx, xmm) as i32 == OFF_XMM);
    assert!(std::mem::offset_of!(JitCtx, shadow_sp) as i32 == OFF_SHADOW_SP);
    assert!(std::mem::offset_of!(JitCtx, shadow_ret) as i32 == OFF_SHADOW_RET);
    assert!(SHADOW_DEPTH.is_power_of_two());
    assert!(CHAIN_SLOTS.is_power_of_two());
};

/// Finalized block ready to run.
#[derive(Clone, Copy)]
pub(super) struct CompiledBlock {
    pub func: unsafe extern "C" fn(*mut JitCtx),
    /// Module function id (for block-chaining `declare_func_in_func`).
    pub func_id: FuncId,
    pub insn_count: u32,
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

/// Resolve host page pointer via multi-way TLB (single-page accesses only).
unsafe fn tlb_page_ptr(ctx: &mut JitCtx, addr: u64, size: usize) -> Option<*mut u8> {
    let page_off = usize::try_from(addr & (PAGE_SIZE - 1)).unwrap_or(0);
    let page_cap = usize::try_from(PAGE_SIZE).unwrap_or(0x1000);
    if page_off.saturating_add(size) > page_cap {
        return None; // cross-page → slow path
    }
    let page_key = addr >> 12; // PAGE_SIZE = 0x1000
    for i in 0..TLB_WAYS {
        if ctx.tlb_page[i] == page_key && !ctx.tlb_ptr[i].is_null() {
            // SAFETY: page mapped; access stays within the page.
            return Some(unsafe { ctx.tlb_ptr[i].add(page_off) });
        }
    }
    // Miss: walk dense page table first (no HashMap), else install via map path.
    // SAFETY: `mem` set by `run_compiled` to the live guest map.
    let mem = unsafe { &mut *ctx.mem };
    let ptr = mem
        .page_data_ptr_walk(page_key)
        .or_else(|| mem.page_data_ptr(page_key))?;
    let slot = usize::try_from(ctx.tlb_rr % u64::try_from(TLB_WAYS).unwrap_or(4)).unwrap_or(0);
    ctx.tlb_page[slot] = page_key;
    ctx.tlb_ptr[slot] = ptr;
    ctx.tlb_rr = ctx.tlb_rr.wrapping_add(1);
    // SAFETY: page mapped; access stays within the page.
    Some(unsafe { ptr.add(page_off) })
}

/// Lookup host block pointer for `va` (0 = miss). Used for late-bound chaining.
///
/// `extern "C" fn(ctx, va) -> fn_ptr`
pub(super) unsafe extern "C" fn wie_jit_chain_lookup(ctx: *mut JitCtx, va: u64) -> u64 {
    if va == 0 || ctx.is_null() {
        return 0;
    }
    // SAFETY: `run_compiled` sets chain_* to live tables for the block duration.
    let ctx = unsafe { &*ctx };
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
            return fns[i];
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
    if ctx.fault != 0 {
        return 0;
    }
    let size_usize = usize::try_from(size).unwrap_or(0);
    if size_usize == 0 || size_usize > 8 {
        set_fault(ctx, insn_ip, addr, size, 0);
        return 0;
    }
    // Fast path: single-page TLB.
    // SAFETY: TLB pointer is a live page from guest map for this block.
    if let Some(p) = unsafe { tlb_page_ptr(ctx, addr, size_usize) } {
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
    // Slow path: multi-page or miss.
    // SAFETY: `mem` set by `run_compiled`.
    let mem = unsafe { &mut *ctx.mem };
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
    if ctx.fault != 0 {
        return;
    }
    let size_usize = usize::try_from(size).unwrap_or(0);
    if size_usize == 0 || size_usize > 8 {
        set_fault(ctx, insn_ip, addr, size, 1);
        return;
    }
    let bytes = value.to_le_bytes();
    // SAFETY: TLB pointer is a live page from guest map for this block.
    if let Some(p) = unsafe { tlb_page_ptr(ctx, addr, size_usize) } {
        // SAFETY: `p` points into a mapped page with `size_usize` bytes in range.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, size_usize);
        }
        return;
    }
    // SAFETY: `mem` set by `run_compiled`.
    let mem = unsafe { &mut *ctx.mem };
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
    let mem = unsafe { &mut *ctx.mem };
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
) -> Result<CompiledBlock, String> {
    let live = analyze_live_gprs(insns);
    let live_xmm = analyze_live_xmm(insns);
    let needs_flags = block_needs_flags(insns, term);
    let has_fast_call = call_fast.is_some();
    let has_mem = block_has_mem(insns)
        || matches!(term, Some(BlockTerm::Call { .. } | BlockTerm::Ret))
        || has_fast_call;
    let has_sse = live_xmm.iter().any(|&x| x);
    let has_string = block_has_string(insns);
    let has_fp = block_has_fp(insns);

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

        // Loop header: body + self-loop back-edges land here (reload GPRs from JitCtx).
        let loop_header = if self_loop {
            let h = bcx.create_block();
            bcx.ins().jump(h, &[]);
            bcx.switch_to_block(h);
            // Leave unsealed until after self-loop back-edges are emitted.
            h
        } else {
            entry
        };

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
        let f32_ref = if has_fp {
            Some(eng.module.declare_func_in_func(eng.f32_id, bcx.func))
        } else {
            None
        };
        let f64_ref = if has_fp {
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

        let mut gpr_vals = [bcx.ins().iconst(types::I64, 0); 16];
        let mut gpr_loaded = [false; 16];
        // For self-loops and fast calls, ensure Win64 arg/result regs are available.
        let mut live_eff = live;
        if has_fast_call {
            live_eff[0] = true; // RAX result
            live_eff[1] = true; // RCX
            live_eff[2] = true; // RDX
            live_eff[8] = true; // R8
            live_eff[9] = true; // R9
        }
        if self_loop {
            // Reload a broad set on re-entry (safe for loops).
            live_eff.fill(true);
        }
        for i in 0..16 {
            if live_eff[i] {
                let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
                let p = bcx.ins().iadd_imm(ctx_ptr, off);
                gpr_vals[i] = bcx.ins().load(types::I64, flags, p, 0);
                gpr_loaded[i] = true;
            }
        }

        // XMM SSA: [lo0, hi0, lo1, hi1, …]; write-through on stores.
        let mut xmm_vals = [bcx.ins().iconst(types::I64, 0); 32];
        let mut xmm_loaded = [false; 16];
        for (i, &is_live) in live_xmm.iter().enumerate() {
            if is_live {
                load_xmm_pair(&mut bcx, ctx_ptr, flags, i, &mut xmm_vals, &mut xmm_loaded);
            }
        }

        let rflags_ptr = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_RFLAGS));
        let mut rflags_val = if needs_flags || self_loop {
            bcx.ins().load(types::I64, flags, rflags_ptr, 0)
        } else {
            bcx.ins().iconst(types::I64, 0)
        };

        let mut mem_env = MemEnv {
            ctx_ptr,
            load_ref,
            store_ref,
            string_ref,
            f32_ref,
            f64_ref,
            flags,
            exit,
            ucrt_refs,
        };

        // Lazy flags: last ALU result deferred until a flag-reader (jcc/cmov/adc/…).
        let mut pending = PendingFlags::None;

        // Dynamic exit RIP when the block ends with a string op (REP stay).
        let mut string_exit_rip: Option<Value> = None;

        for d in body {
            ensure_gprs_loaded(
                &mut bcx,
                ctx_ptr,
                &mut gpr_vals,
                &mut gpr_loaded,
                &d.instr,
                flags,
            );
            ensure_xmm_loaded(
                &mut bcx,
                ctx_ptr,
                flags,
                &d.instr,
                &mut xmm_vals,
                &mut xmm_loaded,
            );
            if is_string_op(&d.instr) {
                flush_pending(&mut bcx, &mut rflags_val, &mut pending);
                string_exit_rip = Some(lower_string(
                    &mut bcx,
                    &d.instr,
                    &mut gpr_vals,
                    &mut rflags_val,
                    &mut gpr_loaded,
                    &mut mem_env,
                )?);
            } else {
                lower_insn(
                    &mut bcx,
                    &d.instr,
                    &mut gpr_vals,
                    &mut rflags_val,
                    &mut pending,
                    &mut mem_env,
                    &mut xmm_vals,
                )?;
            }
        }

        // Materialize flags before terminator that reads them, or before writeback.
        if matches!(term, Some(BlockTerm::Jcc { .. })) || needs_flags {
            flush_pending(&mut bcx, &mut rflags_val, &mut pending);
        }

        // --- Terminator / exit ---
        // Chain paths call the next compiled block (same host ABI), then return
        // to the dispatcher. Self-loops use IR jump (no host stack growth).
        if let Some(t) = term {
            if let Some(ti) = term_insn {
                ensure_gprs_loaded(
                    &mut bcx,
                    ctx_ptr,
                    &mut gpr_vals,
                    &mut gpr_loaded,
                    &ti.instr,
                    flags,
                );
            }
            // Call/ret always touch RSP (normal call path; fast call does not push).
            if matches!(t, BlockTerm::Call { .. } | BlockTerm::Ret)
                && call_fast.is_none()
                && !gpr_loaded[4]
            {
                let p = bcx.ins().iadd_imm(ctx_ptr, 4 * 8);
                gpr_vals[4] = bcx.ins().load(types::I64, flags, p, 0);
                gpr_loaded[4] = true;
            }
            let term_ip = term_insn.map_or(0, |ti| ti.instr.ip());

            // Fast UCRT: call host import, continue at return_ip (no host-stop).
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
                lower_fast_ucrt(&mut bcx, kind, &mut gpr_vals, rflags_val, &mut mem_env)?;
                let exit_rip = iconst_u64(&mut bcx, return_ip);
                emit_chain_or_exit(
                    &mut bcx,
                    ctx_ptr,
                    flags,
                    &gpr_vals,
                    &gpr_loaded,
                    rflags_val,
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
                    &mut bcx,
                    t,
                    start_rip,
                    loop_header,
                    ctx_ptr,
                    flags,
                    &mut gpr_vals,
                    &gpr_loaded,
                    rflags_val,
                    rflags_ptr,
                    needs_flags,
                    exit,
                    &chain_refs,
                    lookup_ref,
                    block_sig_ref,
                )?;
            } else {
                // Near call: push guest return + shadow stack for ret prediction.
                if let BlockTerm::Call { return_ip, .. } = t {
                    shadow_push(&mut bcx, ctx_ptr, flags, return_ip);
                }
                let exit_rip = lower_term(
                    &mut bcx,
                    t,
                    &mut gpr_vals,
                    rflags_val,
                    &mut mem_env,
                    term_ip,
                )?;
                // Near ret: validate shadow prediction (mismatch → clear stack).
                let exit_rip = if matches!(t, BlockTerm::Ret) {
                    shadow_pop_check(&mut bcx, ctx_ptr, flags, exit_rip)
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
                            &mut bcx,
                            mnemonic,
                            taken,
                            not_taken,
                            t_ref,
                            n_ref,
                            ctx_ptr,
                            flags,
                            &gpr_vals,
                            &gpr_loaded,
                            rflags_val,
                            rflags_ptr,
                            needs_flags,
                            exit,
                            lookup_ref,
                            block_sig_ref,
                        )?;
                    }
                    BlockTerm::Jmp { target } | BlockTerm::Call { target, .. } => {
                        emit_chain_or_exit(
                            &mut bcx,
                            ctx_ptr,
                            flags,
                            &gpr_vals,
                            &gpr_loaded,
                            rflags_val,
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
                        // Dynamic target: always late-bound lookup (shadow aids prediction only).
                        emit_chain_or_exit(
                            &mut bcx,
                            ctx_ptr,
                            flags,
                            &gpr_vals,
                            &gpr_loaded,
                            rflags_val,
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
            // REP stay/exit RIP is dynamic — try late-bound chain.
            emit_chain_or_exit(
                &mut bcx,
                ctx_ptr,
                flags,
                &gpr_vals,
                &gpr_loaded,
                rflags_val,
                rflags_ptr,
                needs_flags,
                exit,
                sr,
                None,
                lookup_ref,
                block_sig_ref,
            );
        } else {
            let exit_rip = iconst_u64(&mut bcx, end_rip);
            emit_chain_or_exit(
                &mut bcx,
                ctx_ptr,
                flags,
                &gpr_vals,
                &gpr_loaded,
                rflags_val,
                rflags_ptr,
                needs_flags,
                exit,
                exit_rip,
                chain_refs.get(&end_rip).copied(),
                lookup_ref,
                block_sig_ref,
            );
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
            if gpr_loaded[i] {
                let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
                let p = bcx.ins().iadd_imm(ctx_ptr, off);
                bcx.ins().store(flags, exit_gpr[i], p, 0);
            }
        }
        if needs_flags || self_loop {
            bcx.ins().store(flags, exit_rflags, rflags_ptr, 0);
        }
        bcx.ins().return_(&[]);
        if self_loop {
            bcx.seal_block(loop_header);
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

    Ok(CompiledBlock {
        func,
        func_id,
        insn_count: u32::try_from(insns.len()).unwrap_or(0),
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

fn writeback_gprs(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    gpr: &[Value; 16],
    gpr_loaded: &[bool; 16],
    rflags: Value,
    rflags_ptr: Value,
    store_flags: bool,
) {
    for i in 0..16 {
        if gpr_loaded[i] {
            let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
            let p = bcx.ins().iadd_imm(ctx_ptr, off);
            bcx.ins().store(flags, gpr[i], p, 0);
        }
    }
    if store_flags {
        bcx.ins().store(flags, rflags, rflags_ptr, 0);
    }
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
/// callable from Rust as `extern "C"`.
fn emit_chain_or_exit(
    bcx: &mut FunctionBuilder<'_>,
    ctx_ptr: Value,
    flags: MemFlagsData,
    gpr: &[Value; 16],
    gpr_loaded: &[bool; 16],
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
    writeback_gprs(
        bcx,
        ctx_ptr,
        flags,
        gpr,
        gpr_loaded,
        rflags,
        rflags_ptr,
        store_flags,
    );
    if let Some(f) = href {
        bcx.ins().call(f, &[ctx_ptr]);
        bcx.ins().return_(&[]);
        return;
    }
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
    bcx.ins().return_(&[]);
    bcx.switch_to_block(miss_blk);
    bcx.seal_block(miss_blk);
    jump_exit(bcx, exit, gpr, rflags);
}

/// Self-loop terminator: writeback + jump to loop header (or chain non-loop edge).
///
/// `loop_header` must **not** be the function entry block — Cranelift rejects
/// edges into entry (`remove_constant_phis` / `edge.block != entry_block`).
fn lower_self_loop_term(
    bcx: &mut FunctionBuilder<'_>,
    term: BlockTerm,
    start_rip: u64,
    loop_header: Block,
    ctx_ptr: Value,
    flags: MemFlagsData,
    gpr: &mut [Value; 16],
    gpr_loaded: &[bool; 16],
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
            writeback_gprs(
                bcx, ctx_ptr, flags, gpr, gpr_loaded, rflags, rflags_ptr, true,
            );
            // Re-enter header (reload GPRs from JitCtx); no block params.
            bcx.ins().jump(loop_header, &[]);
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
                    writeback_gprs(
                        bcx, ctx_ptr, flags, gpr, gpr_loaded, rflags, rflags_ptr, true,
                    );
                    bcx.ins().jump(loop_header, &[]);
                } else {
                    let rv = iconst_u64(bcx, va);
                    emit_chain_or_exit(
                        bcx,
                        ctx_ptr,
                        flags,
                        gpr,
                        gpr_loaded,
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
            Ok(())
        }
        // P3: inline `strlen` as a byte-scan loop in IR.
        FastApiKind::Strlen => lower_inline_strlen(bcx, gpr, rflags, mem),
        FastApiKind::Malloc => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("malloc import")?;
            let call = bcx.ins().call(fref, &[mem.ctx_ptr, rcx]);
            gpr[0] = bcx.inst_results(call)[0];
            check_fault_after_ucrt(bcx, mem, gpr, rflags);
            Ok(())
        }
        FastApiKind::Free => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("free import")?;
            bcx.ins().call(fref, &[mem.ctx_ptr, rcx]);
            gpr[0] = iconst_u64(bcx, 0);
            check_fault_after_ucrt(bcx, mem, gpr, rflags);
            Ok(())
        }
        FastApiKind::Memcpy => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("memcpy import")?;
            let call = bcx.ins().call(fref, &[mem.ctx_ptr, rcx, rdx, r8]);
            gpr[0] = bcx.inst_results(call)[0];
            check_fault_after_ucrt(bcx, mem, gpr, rflags);
            Ok(())
        }
        FastApiKind::Fwrite => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("fwrite import")?;
            let call = bcx.ins().call(fref, &[mem.ctx_ptr, rcx, rdx, r8, r9]);
            gpr[0] = bcx.inst_results(call)[0];
            check_fault_after_ucrt(bcx, mem, gpr, rflags);
            Ok(())
        }
        FastApiKind::Fflush => {
            let fref = mem.ucrt_refs[kind as usize].ok_or("fflush import")?;
            let call = bcx.ins().call(fref, &[rcx]);
            gpr[0] = bcx.inst_results(call)[0];
            Ok(())
        }
    }
}

/// Inline `strlen`: byte loop with load helper until NUL.
fn lower_inline_strlen(
    bcx: &mut FunctionBuilder<'_>,
    gpr: &mut [Value; 16],
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

struct MemEnv {
    ctx_ptr: Value,
    load_ref: Option<cranelift::codegen::ir::FuncRef>,
    store_ref: Option<cranelift::codegen::ir::FuncRef>,
    string_ref: Option<cranelift::codegen::ir::FuncRef>,
    f32_ref: Option<cranelift::codegen::ir::FuncRef>,
    f64_ref: Option<cranelift::codegen::ir::FuncRef>,
    flags: MemFlagsData,
    exit: Block,
    ucrt_refs: [Option<FuncRef>; 7],
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
    let plo = bcx.ins().iadd_imm(ctx_ptr, base);
    let phi = bcx.ins().iadd_imm(ctx_ptr, base + 8);
    xmm[idx * 2] = bcx.ins().load(types::I64, flags, plo, 0);
    xmm[idx * 2 + 1] = bcx.ins().load(types::I64, flags, phi, 0);
    loaded[idx] = true;
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
    let plo = bcx.ins().iadd_imm(mem.ctx_ptr, base);
    let phi = bcx.ins().iadd_imm(mem.ctx_ptr, base + 8);
    bcx.ins().store(mem.flags, lo, plo, 0);
    bcx.ins().store(mem.flags, hi, phi, 0);
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
        return write_gpr(bcx, gpr, r0, lo);
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
        return write_gpr(bcx, gpr, r0, v);
    }
    Err("movd form".into())
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
    let (lo, hi) = match op {
        SseBit::Xor => (bcx.ins().bxor(a_lo, b_lo), bcx.ins().bxor(a_hi, b_hi)),
        SseBit::And => (bcx.ins().band(a_lo, b_lo), bcx.ins().band(a_hi, b_hi)),
        SseBit::Or => (bcx.ins().bor(a_lo, b_lo), bcx.ins().bor(a_hi, b_hi)),
        // andn: ~a & b  (Intel: dest = NOT(dest) AND src)
        SseBit::Andn => {
            let na_lo = bcx.ins().bnot(a_lo);
            let na_hi = bcx.ins().bnot(a_hi);
            (bcx.ins().band(na_lo, b_lo), bcx.ins().band(na_hi, b_hi))
        }
    };
    store_xmm_pair(bcx, mem, xmm, di, lo, hi);
    Ok(())
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
    let op_v = iconst_u64(bcx, op);
    let (new_lo, new_hi) = if is_f64 {
        let fref = mem.f64_ref.ok_or("f64 helper missing")?;
        let call = bcx.ins().call(fref, &[op_v, a_lo, b_lo]);
        let r = bcx.inst_results(call)[0];
        (r, a_hi) // sd merges low 64, keeps high
    } else {
        let fref = mem.f32_ref.ok_or("f32 helper missing")?;
        let call = bcx.ins().call(fref, &[op_v, a_lo, b_lo]);
        let r = bcx.inst_results(call)[0];
        let mask = iconst_u64(bcx, 0xffff_ffff);
        let hi32 = iconst_u64(bcx, 0xffff_ffff_0000_0000);
        let cleared = bcx.ins().band(a_lo, hi32);
        let low = bcx.ins().band(r, mask);
        (bcx.ins().bor(cleared, low), a_hi)
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
        // lanes 0,1 in lo; 2,3 in hi
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
            Mnemonic::Push | Mnemonic::Pop | Mnemonic::Call | Mnemonic::Ret
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
        Mnemonic::Push | Mnemonic::Pop | Mnemonic::Call | Mnemonic::Ret
    ) {
        live[4] = true; // RSP
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
    };
    let of_new = select_flag(bcx, of_cond, rflags::OF);
    let old_of = flag_bit(bcx, old_rflags, rflags::OF);
    let of_merged = bcx.ins().select(is_one, of_new, old_of);

    let mut new_flags = old_rflags;
    let cf_set = bcx.ins().icmp_imm(IntCC::NotEqual, cf_bit, 0);
    let cf_on = select_flag(bcx, cf_set, rflags::CF);
    new_flags = replace_flag(bcx, new_flags, rflags::CF, cf_on);
    new_flags = replace_flag(bcx, new_flags, rflags::OF, of_merged);
    if matches!(kind, ShiftKind::Shl | ShiftKind::Shr | ShiftKind::Sar) {
        new_flags = flags_zs_pf(bcx, new_flags, result, bits);
    }
    // count_mod == 0: architectural flags unchanged
    bcx.ins().select(is_zero, old_rflags, new_flags)
}

fn lower_insn(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: &mut Value,
    pending: &mut PendingFlags,
    mem: &mut MemEnv,
    xmm: &mut [Value; 32],
) -> Result<(), String> {
    match instr.mnemonic() {
        Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 => Ok(()),
        // Non-flag ops: leave pending (may be overwritten later).
        Mnemonic::Mov => lower_mov(bcx, instr, gpr, *rflags, mem),
        Mnemonic::Movzx => lower_movx(bcx, instr, gpr, *rflags, mem, false),
        Mnemonic::Movsx | Mnemonic::Movsxd => lower_movx(bcx, instr, gpr, *rflags, mem, true),
        Mnemonic::Lea => lower_lea(bcx, instr, gpr),
        Mnemonic::Push => lower_push(bcx, instr, gpr, *rflags, mem),
        Mnemonic::Pop => lower_pop(bcx, instr, gpr, *rflags, mem),
        Mnemonic::Xchg => lower_xchg(bcx, instr, gpr, *rflags, mem),
        Mnemonic::Not => lower_not(bcx, instr, gpr, *rflags, mem),
        // Lazy-capable ALU (overwrite pending without materializing).
        Mnemonic::Add => lower_arith_lazy(bcx, instr, gpr, rflags, pending, mem, Arith::Add),
        Mnemonic::Sub => lower_arith_lazy(bcx, instr, gpr, rflags, pending, mem, Arith::Sub),
        Mnemonic::Xor => lower_arith_lazy(bcx, instr, gpr, rflags, pending, mem, Arith::Xor),
        Mnemonic::And => lower_arith_lazy(bcx, instr, gpr, rflags, pending, mem, Arith::And),
        Mnemonic::Or => lower_arith_lazy(bcx, instr, gpr, rflags, pending, mem, Arith::Or),
        Mnemonic::Cmp => lower_cmp_test_lazy(bcx, instr, gpr, rflags, pending, mem, true),
        Mnemonic::Test => lower_cmp_test_lazy(bcx, instr, gpr, rflags, pending, mem, false),
        // Need live CF / complex flags → flush then eager.
        Mnemonic::Adc | Mnemonic::Sbb => {
            flush_pending(bcx, rflags, pending);
            lower_arith(
                bcx,
                instr,
                gpr,
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
        Mnemonic::Inc => lower_inc_dec_lazy(bcx, instr, gpr, rflags, pending, mem, true),
        Mnemonic::Dec => lower_inc_dec_lazy(bcx, instr, gpr, rflags, pending, mem, false),
        Mnemonic::Neg => {
            // Neg is 0-sub; can lazy as Sub{0,a,res}.
            lower_neg_lazy(bcx, instr, gpr, rflags, pending, mem)
        }
        Mnemonic::Imul => {
            flush_pending(bcx, rflags, pending);
            lower_imul(bcx, instr, gpr, rflags, mem)
        }
        // Shift/rotate: compute result now; defer flag packing (unless count_mod==0).
        Mnemonic::Shl | Mnemonic::Sal => {
            lower_shift_lazy(bcx, instr, gpr, rflags, pending, mem, ShiftKind::Shl)
        }
        Mnemonic::Shr => lower_shift_lazy(bcx, instr, gpr, rflags, pending, mem, ShiftKind::Shr),
        Mnemonic::Sar => lower_shift_lazy(bcx, instr, gpr, rflags, pending, mem, ShiftKind::Sar),
        Mnemonic::Rol => lower_shift_lazy(bcx, instr, gpr, rflags, pending, mem, ShiftKind::Rol),
        Mnemonic::Ror => lower_shift_lazy(bcx, instr, gpr, rflags, pending, mem, ShiftKind::Ror),
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
            lower_cmov(bcx, instr, gpr, *rflags, mem, m)
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
            lower_setcc(bcx, instr, gpr, *rflags, mem, m)
        }
        Mnemonic::Movaps
        | Mnemonic::Movups
        | Mnemonic::Movdqa
        | Mnemonic::Movdqu
        | Mnemonic::Movapd
        | Mnemonic::Movupd => lower_sse_mov(bcx, instr, gpr, *rflags, mem, xmm, 16, false),
        Mnemonic::Movss => lower_sse_mov(bcx, instr, gpr, *rflags, mem, xmm, 4, true),
        Mnemonic::Movsd => lower_sse_mov(bcx, instr, gpr, *rflags, mem, xmm, 8, true),
        Mnemonic::Movq => lower_sse_movq(bcx, instr, gpr, *rflags, mem, xmm),
        Mnemonic::Movd => lower_sse_movd(bcx, instr, gpr, *rflags, mem, xmm),
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
        other => Err(format!("not lowerable {other:?}")),
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
    let string_ref = mem.string_ref.ok_or("string helper missing")?;
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
            Ok(iconst_u64(bcx, target))
        }
        BlockTerm::Ret => {
            let rsp = gpr[4];
            let ret = call_load(bcx, mem, gpr, rflags, rsp, 8, term_ip)?;
            gpr[4] = bcx.ins().iadd_imm(rsp, 8);
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
    write_gpr(bcx, &mut gpr_t, reg, src)?;
    gpr[idx] = bcx.ins().select(cond, gpr_t[idx], old);
    Ok(())
}

fn lower_setcc(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: Value,
    mem: &mut MemEnv,
    m: Mnemonic,
) -> Result<(), String> {
    let cond = flag_cond(bcx, rflags, m)?;
    let one = iconst_u64(bcx, 1);
    let zero = iconst_u64(bcx, 0);
    let val = bcx.ins().select(cond, one, zero);
    match instr.op0_kind() {
        OpKind::Register => write_gpr(bcx, gpr, instr.op_register(0), val),
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
    };
    let result = mask_width(bcx, result_raw, bits);
    let final_res = bcx.ins().select(is_zero, dst, result);
    write_op_mem(bcx, instr, 0, gpr, *rflags, mem, final_res, bits)?;

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
    Ok(())
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

fn call_load(
    bcx: &mut FunctionBuilder<'_>,
    mem: &MemEnv,
    gpr: &[Value; 16],
    rflags: Value,
    addr: Value,
    size: u32,
    insn_ip: u64,
) -> Result<Value, String> {
    // Host: 4-way TLB + dense page-table walk on miss.
    // Full IR page-walk was measured ~2× slower on open-rom (branchy IR / icache).
    let load_ref = mem.load_ref.ok_or("load helper missing")?;
    let size_v = bcx.ins().iconst(types::I64, i64::from(size));
    let ip_v = iconst_u64(bcx, insn_ip);
    let call = bcx.ins().call(load_ref, &[mem.ctx_ptr, addr, size_v, ip_v]);
    let val = bcx.inst_results(call)[0];
    let fault_ptr = bcx.ins().iadd_imm(mem.ctx_ptr, i64::from(OFF_FAULT));
    let fault = bcx.ins().load(types::I64, mem.flags, fault_ptr, 0);
    let is_fault = bcx.ins().icmp_imm(IntCC::NotEqual, fault, 0);
    let cont = bcx.create_block();
    let args = exit_args(gpr, rflags);
    bcx.ins().brif(is_fault, mem.exit, &args, cont, &[]);
    bcx.switch_to_block(cont);
    bcx.seal_block(cont);
    Ok(val)
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
    Ok(())
}

fn lower_mov(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
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
            write_gpr(bcx, gpr, instr.op_register(0), val)
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
            write_gpr(bcx, gpr, instr.op_register(0), src)
        }
        _ => Err("mov form".into()),
    }
}

fn lower_movx(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
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
    write_gpr(bcx, gpr, instr.op_register(0), val)
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

fn lower_lea(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
) -> Result<(), String> {
    let addr = effective_addr(bcx, instr, gpr)?;
    write_gpr(bcx, gpr, instr.op_register(0), addr)
}

/// 64-bit push (Intel: value of RSP before decrement is what `push rsp` stores).
fn lower_push(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
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
    Ok(())
}

fn lower_pop(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let size = 8_u32;
    let rsp = gpr[4];
    let val = call_load(bcx, mem, gpr, rflags, rsp, size, instr.ip())?;
    let new_rsp = bcx.ins().iadd_imm(rsp, i64::from(size));
    gpr[4] = new_rsp;
    match instr.op0_kind() {
        OpKind::Register => {
            // pop rsp: write the popped value (already advanced rsp).
            write_gpr(bcx, gpr, instr.op_register(0), val)
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
    write_op_mem(bcx, instr, 0, gpr, *rflags, mem, res_m, bits)?;
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
    write_op_mem(bcx, instr, 0, gpr, *rflags, mem, res_m, bits)?;
    *rflags = match op {
        Arith::Xor | Arith::And | Arith::Or => flags_logic(bcx, *rflags, res_m, bits),
        Arith::Add => flags_add(bcx, *rflags, a, b, res_m, bits),
        Arith::Adc => flags_adc(bcx, *rflags, a, b, cf_val, res_m, bits),
        Arith::Sub => flags_sub(bcx, *rflags, a, b, res_m, bits),
        Arith::Sbb => {
            let borrow = bcx.ins().iadd(b, cf_val);
            let borrow_m = mask_width(bcx, borrow, bits);
            flags_sub(bcx, *rflags, a, borrow_m, res_m, bits)
        }
    };
    Ok(())
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
    write_op_mem(bcx, instr, 0, gpr, *rflags, mem, lo, bits)?;
    let cf_on = select_flag(bcx, overflow, rflags::CF);
    let of_on = select_flag(bcx, overflow, rflags::OF);
    let f = replace_flag(bcx, *rflags, rflags::CF, cf_on);
    *rflags = replace_flag(bcx, f, rflags::OF, of_on);
    Ok(())
}

fn lower_xchg(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
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
            write_gpr(bcx, gpr, r0, v1)?;
            write_gpr(bcx, gpr, r1, v0)
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
            write_gpr(bcx, gpr, reg, mem_v)?;
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
    rflags: Value,
    mem: &mut MemEnv,
    val: Value,
    bits: u32,
) -> Result<(), String> {
    match instr.op_kind(op) {
        OpKind::Register => write_gpr(bcx, gpr, instr.op_register(op), val),
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
    write_op_mem(bcx, instr, 0, gpr, *rflags, mem, res, bits)?;
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
    rflags: Value,
    mem: &mut MemEnv,
) -> Result<(), String> {
    let bits = op_width_bits(instr, 0)?;
    let a_raw = read_op_mem(bcx, instr, 0, gpr, rflags, mem)?;
    let a = mask_width(bcx, a_raw, bits);
    let not_a = bcx.ins().bnot(a);
    let res = mask_width(bcx, not_a, bits);
    write_op_mem(bcx, instr, 0, gpr, rflags, mem, res, bits)
}

fn lower_neg_lazy(
    bcx: &mut FunctionBuilder<'_>,
    instr: &Instruction,
    gpr: &mut [Value; 16],
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
    write_op_mem(bcx, instr, 0, gpr, *rflags, mem, res, bits)?;
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
