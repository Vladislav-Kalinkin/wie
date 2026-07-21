//! Hand-written host trampolines for 1–3 instruction guest stubs.
//!
//! Ultra-short fake-API bodies (`ret`, `xor eax,eax; ret`, GetLastError, …)
//! skip Cranelift entirely: lower peak init RAM and cut compile tax on every
//! process start. Semantics match the Cranelift-lowered path (guest `ret`,
//! shadow stack, optional late-bound chain).

use super::block::{BlockTerm, DecodedInsn};
use super::lower::{
    CHAIN_SLOTS, JitCtx, MAX_CHAIN_DEPTH, SHADOW_DEPTH, chain_hash, wie_jit_load, wie_jit_store,
};
use iced_x86::{Mnemonic, OpKind, Register};

/// Guest TEB.LastErrorValue mirror (must match `wie_runtime::guest_stubs::TEB_LAST_ERROR_VA`).
const TEB_LAST_ERROR_VA: u64 = 0x68;

/// Recognized micro-stub patterns that have a hand-written host trampoline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MicroStub {
    /// Bare `ret`.
    Ret,
    /// `xor eax,eax` / `xor rax,rax` then `ret`.
    ReturnZero,
    /// `mov rax, rcx` then `ret`.
    IdentityRcx,
    /// `mov eax, imm32` then `ret`.
    ReturnImm32(u32),
    /// `mov rax, imm64; mov eax, [rax]; ret` with imm = TEB last-error VA.
    GetLastError,
    /// `mov rax, imm64; mov [rax], ecx; ret` with imm = TEB last-error VA.
    SetLastError,
}

impl MicroStub {
    /// Host entry for this stub (`extern "C" fn(*mut JitCtx)`).
    #[must_use]
    pub(super) fn func(self) -> unsafe extern "C" fn(*mut super::lower::JitCtx) {
        match self {
            Self::Ret => tramp_ret,
            Self::ReturnZero => tramp_return_zero,
            Self::IdentityRcx => tramp_identity_rcx,
            Self::ReturnImm32(imm) => tramp_return_imm32_dispatch(imm),
            Self::GetLastError => tramp_get_last_error,
            Self::SetLastError => tramp_set_last_error,
        }
    }

    /// GPRs that may change and must be written back to the host regfile.
    #[must_use]
    pub(super) fn dirty_mask(self) -> u16 {
        match self {
            Self::Ret | Self::SetLastError => 1 << 4, // RSP only (store uses ECX)
            Self::ReturnZero | Self::ReturnImm32(_) | Self::GetLastError | Self::IdentityRcx => {
                (1 << 0) | (1 << 4) // RAX, RSP
            }
        }
    }

    #[must_use]
    pub(super) fn insn_count(self) -> u32 {
        match self {
            Self::Ret => 1,
            Self::ReturnZero | Self::IdentityRcx | Self::ReturnImm32(_) => 2,
            Self::GetLastError | Self::SetLastError => 3,
        }
    }
}

/// Match a Pure block against a hand-written micro-stub (body + `ret` terminator).
#[must_use]
pub(super) fn match_micro_stub(
    insns: &[DecodedInsn],
    term: Option<BlockTerm>,
) -> Option<MicroStub> {
    if !matches!(term, Some(BlockTerm::Ret)) {
        return None;
    }
    // Terminator `ret` is included in `insns`.
    let n = insns.len();
    if n == 0 || n > 3 {
        return None;
    }
    if !is_plain_ret(&insns[n - 1].instr) {
        return None;
    }
    match n {
        1 => Some(MicroStub::Ret),
        2 => classify_two_insn(&insns[0].instr),
        3 => classify_three_insn(&insns[0].instr, &insns[1].instr),
        _ => None,
    }
}

fn is_plain_ret(instr: &iced_x86::Instruction) -> bool {
    instr.mnemonic() == Mnemonic::Ret && instr.op_count() == 0
}

fn classify_two_insn(instr: &iced_x86::Instruction) -> Option<MicroStub> {
    // xor eax,eax / xor rax,rax
    if instr.mnemonic() == Mnemonic::Xor
        && instr.op0_kind() == OpKind::Register
        && instr.op1_kind() == OpKind::Register
    {
        let r0 = instr.op_register(0);
        let r1 = instr.op_register(1);
        if r0 == r1 && matches!(r0, Register::EAX | Register::RAX) {
            return Some(MicroStub::ReturnZero);
        }
    }
    // mov rax, rcx
    if instr.mnemonic() == Mnemonic::Mov
        && instr.op0_kind() == OpKind::Register
        && instr.op1_kind() == OpKind::Register
        && instr.op_register(0) == Register::RAX
        && instr.op_register(1) == Register::RCX
    {
        return Some(MicroStub::IdentityRcx);
    }
    // mov eax, imm32
    if instr.mnemonic() == Mnemonic::Mov
        && instr.op0_kind() == OpKind::Register
        && matches!(
            instr.op1_kind(),
            OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64
        )
        && matches!(instr.op_register(0), Register::EAX | Register::RAX)
    {
        let imm = instr.immediate32();
        return Some(MicroStub::ReturnImm32(imm));
    }
    None
}

fn classify_three_insn(a: &iced_x86::Instruction, b: &iced_x86::Instruction) -> Option<MicroStub> {
    // mov rax, imm64
    if a.mnemonic() != Mnemonic::Mov
        || a.op0_kind() != OpKind::Register
        || a.op_register(0) != Register::RAX
        || !matches!(
            a.op1_kind(),
            OpKind::Immediate64 | OpKind::Immediate32 | OpKind::Immediate32to64
        )
    {
        return None;
    }
    let va = a.immediate64();
    if va != TEB_LAST_ERROR_VA {
        return None;
    }
    // mov eax, [rax]
    if b.mnemonic() == Mnemonic::Mov
        && b.op0_kind() == OpKind::Register
        && matches!(b.op_register(0), Register::EAX | Register::RAX)
        && b.op1_kind() == OpKind::Memory
        && b.memory_base() == Register::RAX
        && b.memory_index() == Register::None
        && b.memory_displacement64() == 0
    {
        return Some(MicroStub::GetLastError);
    }
    // mov [rax], ecx
    if b.mnemonic() == Mnemonic::Mov
        && b.op0_kind() == OpKind::Memory
        && b.op1_kind() == OpKind::Register
        && matches!(b.op_register(1), Register::ECX | Register::RCX)
        && b.memory_base() == Register::RAX
        && b.memory_index() == Register::None
        && b.memory_displacement64() == 0
    {
        return Some(MicroStub::SetLastError);
    }
    None
}

// --- Imm32 trampoline table (small fixed set of common constants) ---

/// Common imm32 returns used by guest stubs (TRUE, process/thread ids, tick, locale).
fn tramp_return_imm32_dispatch(imm: u32) -> unsafe extern "C" fn(*mut JitCtx) {
    match imm {
        0 => tramp_return_zero,
        1 => tramp_return_imm_1,
        0x0409 => tramp_return_imm_0409, // LANG_EN_US
        0x1234 => tramp_return_imm_1234,
        0x5678 => tramp_return_imm_5678,
        437 => tramp_return_imm_437,   // GetOEMCP
        1252 => tramp_return_imm_1252, // GetACP
        12_345 => tramp_return_imm_12345,
        // Uncommon imm: still avoid Cranelift via a slow generic path.
        _ => tramp_return_imm32_generic,
    }
}

// SAFETY: each trampoline is only invoked with a live `JitCtx` from `run_compiled`.

unsafe extern "C" fn tramp_ret(ctx: *mut JitCtx) {
    // SAFETY: live ctx for block duration.
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::Ret.dirty_mask());
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_return_zero(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnZero.dirty_mask());
    ctx.gpr[0] = 0;
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_identity_rcx(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::IdentityRcx.dirty_mask());
    ctx.gpr[0] = ctx.gpr[1];
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_return_imm_1(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnImm32(1).dirty_mask());
    ctx.gpr[0] = 1;
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_return_imm_1234(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnImm32(0x1234).dirty_mask());
    ctx.gpr[0] = 0x1234;
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_return_imm_5678(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnImm32(0x5678).dirty_mask());
    ctx.gpr[0] = 0x5678;
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_return_imm_12345(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnImm32(12_345).dirty_mask());
    ctx.gpr[0] = 12_345;
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_return_imm_0409(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnImm32(0x0409).dirty_mask());
    ctx.gpr[0] = 0x0409;
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_return_imm_437(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnImm32(437).dirty_mask());
    ctx.gpr[0] = 437;
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_return_imm_1252(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnImm32(1252).dirty_mask());
    ctx.gpr[0] = 1252;
    guest_ret(ctx);
    chain_tail(ctx);
}

/// Fallback for rare imm32: re-decode guest code at entry RIP (ctx.rip before ret).
unsafe extern "C" fn tramp_return_imm32_generic(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::ReturnImm32(0).dirty_mask());
    // Entry RIP was set by run_compiled; body is `b8 imm32 c3`.
    let entry = ctx.rip;
    let imm = tramp_load_u32(ctx, entry.wrapping_add(1));
    if ctx.fault != 0 {
        return;
    }
    ctx.gpr[0] = u64::from(imm);
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_get_last_error(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::GetLastError.dirty_mask());
    let v = tramp_load_u32(ctx, TEB_LAST_ERROR_VA);
    if ctx.fault != 0 {
        return;
    }
    ctx.gpr[0] = u64::from(v);
    guest_ret(ctx);
    chain_tail(ctx);
}

unsafe extern "C" fn tramp_set_last_error(ctx: *mut JitCtx) {
    let ctx = unsafe { &mut *ctx };
    mark_dirty(ctx, MicroStub::SetLastError.dirty_mask());
    let ecx = ctx.gpr[1] as u32;
    tramp_store_u32(ctx, TEB_LAST_ERROR_VA, ecx);
    if ctx.fault != 0 {
        return;
    }
    guest_ret(ctx);
    chain_tail(ctx);
}

#[inline]
fn mark_dirty(ctx: &mut JitCtx, mask: u16) {
    ctx.gpr_dirty_bits |= u64::from(mask);
}

/// Pop guest return address, update RSP / shadow, set RIP.
fn guest_ret(ctx: &mut JitCtx) {
    if ctx.fault != 0 {
        return;
    }
    let rsp = ctx.gpr[4];
    let ret_va = tramp_load_u64(ctx, rsp);
    if ctx.fault != 0 {
        return;
    }
    ctx.gpr[4] = rsp.wrapping_add(8);
    shadow_pop_check(ctx, ret_va);
    ctx.rip = ret_va;
}

fn shadow_pop_check(ctx: &mut JitCtx, ret_va: u64) {
    let sp = ctx.shadow_sp;
    if sp == 0 {
        return;
    }
    let sp1 = sp.wrapping_sub(1);
    let idx = (sp1 as usize) & (SHADOW_DEPTH - 1);
    let predicted = ctx.shadow_ret[idx];
    if predicted == ret_va {
        ctx.shadow_sp = sp1;
    } else {
        ctx.shadow_sp = 0;
    }
}

/// Late-bound chain into the next Ready block (same host ABI as Cranelift).
fn chain_tail(ctx: &mut JitCtx) {
    if ctx.fault != 0 {
        return;
    }
    // Match Cranelift `emit_chain_or_exit` host-stack cap.
    if ctx.chain_depth >= MAX_CHAIN_DEPTH {
        return;
    }
    let fn_ptr = chain_lookup(ctx, ctx.rip);
    if fn_ptr == 0 {
        return;
    }
    // Successor may be a Cranelift block that dirties arbitrary GPRs without
    // updating `gpr_dirty_bits` — force full host writeback for this session.
    ctx.gpr_dirty_bits = 0xffff;
    ctx.chain_depth = ctx.chain_depth.saturating_add(1);
    // SAFETY: pointer published by chain_table_insert from a finalized block.
    let f: unsafe extern "C" fn(*mut JitCtx) =
        unsafe { std::mem::transmute(fn_ptr as usize as *const u8) };
    unsafe {
        f(ctx);
    }
    ctx.chain_depth = ctx.chain_depth.saturating_sub(1);
}

fn chain_lookup(ctx: &JitCtx, va: u64) -> u64 {
    if va == 0 || ctx.chain_va.is_null() || ctx.chain_fn.is_null() {
        return 0;
    }
    // SAFETY: tables are CHAIN_SLOTS long and live for this call.
    let keys = unsafe { std::slice::from_raw_parts(ctx.chain_va, CHAIN_SLOTS) };
    let fns = unsafe { std::slice::from_raw_parts(ctx.chain_fn, CHAIN_SLOTS) };
    let mut i = chain_hash(va);
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

fn tramp_load_u64(ctx: &mut JitCtx, addr: u64) -> u64 {
    // SAFETY: ctx is live; load helper matches Cranelift host import.
    unsafe { wie_jit_load(std::ptr::from_mut(ctx), addr, 8, ctx.rip) }
}

fn tramp_load_u32(ctx: &mut JitCtx, addr: u64) -> u32 {
    let v = unsafe { wie_jit_load(std::ptr::from_mut(ctx), addr, 4, ctx.rip) };
    v as u32
}

fn tramp_store_u32(ctx: &mut JitCtx, addr: u64, value: u32) {
    unsafe {
        wie_jit_store(std::ptr::from_mut(ctx), addr, 4, u64::from(value), ctx.rip);
    }
}
