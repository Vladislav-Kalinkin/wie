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
use super::block::{BlockTerm, DecodedInsn, mem_width_bytes};
use crate::mem::{GuestMemory, PAGE_SIZE};
use crate::regs::rflags;
use cranelift::codegen::ir::{BlockArg, UserFuncName};
use cranelift::prelude::*;
use cranelift_codegen::ir::MemFlagsData;
use cranelift_module::{Linkage, Module};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

/// Associative guest-page TLB ways (stack vs heap thrashing).
pub(super) const TLB_WAYS: usize = 4;
/// Empty TLB slot marker (`page_key == TLB_EMPTY`).
pub(super) const TLB_EMPTY: u64 = u64::MAX;

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
}

// Byte offsets into [`JitCtx`] used from Cranelift IR (must match `repr(C)`).
// gpr[16] @ 0, rflags @ 128, rip @ 136, mem @ 144, fault @ 152, …
const OFF_RFLAGS: i32 = 16 * 8;
const OFF_RIP: i32 = OFF_RFLAGS + 8;
const OFF_FAULT: i32 = OFF_RIP + 8 + 8; // skip mem ptr

/// Finalized block ready to run.
#[derive(Clone, Copy)]
pub(super) struct CompiledBlock {
    pub func: unsafe extern "C" fn(*mut JitCtx),
    pub insn_count: u32,
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

pub(super) fn compile_block(
    eng: &mut JitEngine,
    start_rip: u64,
    insns: &[DecodedInsn],
    end_rip: u64,
    term: Option<BlockTerm>,
) -> Result<CompiledBlock, String> {
    let _ = start_rip;
    let live = analyze_live_gprs(insns);
    let needs_flags = block_needs_flags(insns, term);
    let has_mem = block_has_mem(insns)
        || matches!(term, Some(BlockTerm::Call { .. } | BlockTerm::Ret));

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
        bcx.seal_block(entry);

        let ctx_ptr = bcx.block_params(entry)[0];
        let flags = MemFlagsData::trusted();

        // Exit: gpr[16] + rflags as block params → store and return.
        let exit = bcx.create_block();
        for _ in 0..16 {
            bcx.append_block_param(exit, types::I64);
        }
        bcx.append_block_param(exit, types::I64);

        let load_ref = if has_mem {
            Some(eng.module.declare_func_in_func(eng.load_id, bcx.func))
        } else {
            None
        };
        let store_ref = if has_mem {
            Some(eng.module.declare_func_in_func(eng.store_id, bcx.func))
        } else {
            None
        };

        let mut gpr_vals = [bcx.ins().iconst(types::I64, 0); 16];
        let mut gpr_loaded = [false; 16];
        for i in 0..16 {
            if live[i] {
                let off = i64::try_from(i.saturating_mul(8)).unwrap_or(0);
                let p = bcx.ins().iadd_imm(ctx_ptr, off);
                gpr_vals[i] = bcx.ins().load(types::I64, flags, p, 0);
                gpr_loaded[i] = true;
            }
        }

        let rflags_ptr = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_RFLAGS));
        let mut rflags_val = if needs_flags {
            bcx.ins().load(types::I64, flags, rflags_ptr, 0)
        } else {
            bcx.ins().iconst(types::I64, 0)
        };

        let mut mem_env = MemEnv {
            ctx_ptr,
            load_ref,
            store_ref,
            flags,
            exit,
        };

        // Lazy flags: last ALU result deferred until a flag-reader (jcc/cmov/adc/…).
        let mut pending = PendingFlags::None;

        for d in body {
            ensure_gprs_loaded(
                &mut bcx,
                ctx_ptr,
                &mut gpr_vals,
                &mut gpr_loaded,
                &d.instr,
                flags,
            );
            lower_insn(
                &mut bcx,
                &d.instr,
                &mut gpr_vals,
                &mut rflags_val,
                &mut pending,
                &mut mem_env,
            )?;
        }

        // Materialize flags before terminator that reads them, or before writeback.
        if matches!(term, Some(BlockTerm::Jcc { .. })) || needs_flags {
            flush_pending(&mut bcx, &mut rflags_val, &mut pending);
        }

        let exit_rip = if let Some(t) = term {
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
            // Call/ret always touch RSP.
            if matches!(t, BlockTerm::Call { .. } | BlockTerm::Ret) && !gpr_loaded[4] {
                let p = bcx.ins().iadd_imm(ctx_ptr, 4 * 8);
                gpr_vals[4] = bcx.ins().load(types::I64, flags, p, 0);
                gpr_loaded[4] = true;
            }
            let term_ip = term_insn.map_or(0, |ti| ti.instr.ip());
            lower_term(
                &mut bcx,
                t,
                &mut gpr_vals,
                rflags_val,
                &mut mem_env,
                term_ip,
            )?
        } else {
            iconst_u64(&mut bcx, end_rip)
        };

        let rip_ptr = bcx.ins().iadd_imm(ctx_ptr, i64::from(OFF_RIP));
        bcx.ins().store(flags, exit_rip, rip_ptr, 0);
        jump_exit(&mut bcx, exit, &gpr_vals, rflags_val);

        bcx.switch_to_block(exit);
        bcx.seal_block(exit);
        // Copy block params out so we can mutably use `bcx` while storing.
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
        if needs_flags {
            bcx.ins().store(flags, exit_rflags, rflags_ptr, 0);
        }
        bcx.ins().return_(&[]);
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
        insn_count: u32::try_from(insns.len()).unwrap_or(0),
    })
}

struct MemEnv {
    ctx_ptr: Value,
    load_ref: Option<cranelift::codegen::ir::FuncRef>,
    store_ref: Option<cranelift::codegen::ir::FuncRef>,
    flags: MemFlagsData,
    exit: Block,
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

fn block_needs_flags(insns: &[DecodedInsn], term: Option<BlockTerm>) -> bool {
    if matches!(term, Some(BlockTerm::Jcc { .. })) {
        return true;
    }
    insns.iter().any(|d| {
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
        if matches!(m, Mnemonic::Push | Mnemonic::Pop | Mnemonic::Call | Mnemonic::Ret) {
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

fn flush_pending(
    bcx: &mut FunctionBuilder<'_>,
    rflags: &mut Value,
    pending: &mut PendingFlags,
) {
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
        other => Err(format!("not lowerable {other:?}")),
    }
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
    let call = bcx
        .ins()
        .call(load_ref, &[mem.ctx_ptr, addr, size_v, ip_v]);
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
        *pending = PendingFlags::Sub {
            a,
            b,
            res,
            bits,
        };
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
