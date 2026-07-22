//! Decode a lowerable straight-line block for Cranelift (GPR + simple mem + jcc/jmp term).

use crate::mem::GuestMemory;
use crate::exec::HookWindow;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};

/// Max instructions per compiled block (keeps compile time bounded).
/// Raised to capture longer pure loop bodies in one native frame.
pub(super) const MAX_BLOCK_INSNS: usize = 96;
/// Min instructions before paying Cranelift compile cost (short blocks lose wall).
/// 2 keeps tiny fallthrough fragments eligible once hot (was 4; 7za residual was
/// dominated by already-lowerable Mov/Add fragments that never reached min=4).
pub(super) const MIN_BLOCK_INSNS: usize = 2;

/// One decoded guest insn kept for the lowerer.
#[derive(Debug, Clone)]
pub(super) struct DecodedInsn {
    pub instr: Instruction,
}

/// Block exit control-flow (last insn of a Pure block, if any).
#[derive(Debug, Clone, Copy)]
pub(super) enum BlockTerm {
    /// Unconditional near jump.
    Jmp { target: u64 },
    /// Conditional near jump; fallthrough is `not_taken`.
    Jcc {
        mnemonic: Mnemonic,
        taken: u64,
        not_taken: u64,
    },
    /// Near `call rel` — push `return_ip`, exit at `target`.
    Call { target: u64, return_ip: u64 },
    /// Near `ret` (no imm) — pop exit RIP.
    Ret,
}

/// Result of trying to form a JIT block at `start`.
pub(super) enum BlockKind {
    /// Lowerable body (+ optional terminator) ending at `end_rip` when no term / fallthrough.
    Pure {
        insns: Vec<DecodedInsn>,
        /// Fallthrough RIP when the block has no terminator, or jcc not-taken.
        /// For unconditional `jmp`, equals the jump target.
        end_rip: u64,
        bytes_len: u32,
        term: Option<BlockTerm>,
    },
    /// Needs interpreter (complex mem / call / ret / sse / …).
    NotPure,
}

/// Decode from guest memory until a non-lowerable insn, terminator, or max length.
///
/// A near `jcc`/`jmp` terminator is **included** and ends the block. Other
/// non-lowerable insns are **not** included (interpreter runs them next).
pub(super) fn decode_pure_gpr_block(mem: &GuestMemory, hooks: Option<&HookWindow>, start: u64) -> BlockKind {
    let mut insns = Vec::with_capacity(MAX_BLOCK_INSNS);
    let mut rip = start;
    let mut bytes_len = 0_u32;
    let mut term: Option<BlockTerm> = None;

    if let Some(h) = hooks
        && h.should_host_stop(start)
    {
        return BlockKind::NotPure;
    }

    for _ in 0..MAX_BLOCK_INSNS {
        let mut buf = [0_u8; 15];
        if mem.read(rip, &mut buf).is_err() {
            break;
        }
        let mut decoder = Decoder::with_ip(64, &buf, rip, DecoderOptions::NONE);
        let instr = decoder.decode();
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        let len_u32 = u32::try_from(instr.len()).unwrap_or(0);
        let next = instr.next_ip();

        if let Some(t) = classify_terminator(&instr) {
            // Unconditional jmp to the very next instruction: treat as no-op
            // and keep decoding to merge the fallthrough block into this one.
            if matches!(t, BlockTerm::Jmp { target } if target == next) {
                rip = next;
                bytes_len = bytes_len.saturating_add(len_u32);
                continue;
            }
            insns.push(DecodedInsn { instr });
            bytes_len = bytes_len.saturating_add(len_u32);
            term = Some(t);
            rip = match t {
                BlockTerm::Jmp { target } | BlockTerm::Call { target, .. } => target,
                BlockTerm::Jcc { not_taken, .. } => not_taken,
                // Dynamic; placeholder for decode end only (not used as fallthrough).
                BlockTerm::Ret => next,
            };
            break;
        }

        if !is_lowerable(&instr) {
            break;
        }
        let ends_string = is_string_op(&instr);
        insns.push(DecodedInsn { instr });
        bytes_len = bytes_len.saturating_add(len_u32);
        rip = next;
        // String ops end the block: REP stay needs dynamic exit RIP from the host helper.
        if ends_string {
            break;
        }
    }

    // Short blocks with a terminator are still worth compiling:
    // - call/ret: UCRT fast-path + shadow-stack chaining beats host-stop
    // - jcc/jmp: tight loops (often < MIN_BLOCK_INSNS) must not stay on iced
    // - string ops: bulk REP helper
    // Fallthrough-only fragments keep MIN_BLOCK_INSNS to avoid compile tax.
    let min = if term.is_some() || insns.last().is_some_and(|d| is_string_op(&d.instr)) {
        1
    } else {
        MIN_BLOCK_INSNS
    };
    if insns.len() < min {
        BlockKind::NotPure
    } else {
        BlockKind::Pure {
            insns,
            end_rip: rip,
            bytes_len,
            term,
        }
    }
}

/// True when a Pure block's terminator is a self-loop back to `start`.
#[must_use]
pub(super) fn pure_is_self_loop(kind: &BlockKind, start: u64) -> bool {
    match kind {
        BlockKind::Pure {
            term: Some(BlockTerm::Jmp { target }),
            ..
        } => *target == start,
        BlockKind::Pure {
            term: Some(BlockTerm::Jcc {
                taken, not_taken, ..
            }),
            ..
        } => *taken == start || *not_taken == start,
        _ => false,
    }
}

fn classify_terminator(instr: &Instruction) -> Option<BlockTerm> {
    match instr.mnemonic() {
        Mnemonic::Ret => {
            // `ret imm16` → iced (stack adjust after pop).
            if instr.op_count() >= 1 {
                return None;
            }
            Some(BlockTerm::Ret)
        }
        Mnemonic::Call if is_near_branch(instr) => Some(BlockTerm::Call {
            target: instr.near_branch_target(),
            return_ip: instr.next_ip(),
        }),
        Mnemonic::Jmp if is_near_branch(instr) => Some(BlockTerm::Jmp {
            target: instr.near_branch_target(),
        }),
        m @ (Mnemonic::Je
        | Mnemonic::Jne
        | Mnemonic::Ja
        | Mnemonic::Jae
        | Mnemonic::Jb
        | Mnemonic::Jbe
        | Mnemonic::Jg
        | Mnemonic::Jge
        | Mnemonic::Jl
        | Mnemonic::Jle
        | Mnemonic::Jo
        | Mnemonic::Jno
        | Mnemonic::Js
        | Mnemonic::Jns
        | Mnemonic::Jp
        | Mnemonic::Jnp)
            if is_near_branch(instr) =>
        {
            Some(BlockTerm::Jcc {
                mnemonic: m,
                taken: instr.near_branch_target(),
                not_taken: instr.next_ip(),
            })
        }
        _ => None,
    }
}

fn is_near_branch(instr: &Instruction) -> bool {
    matches!(
        instr.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
}

fn is_lowerable(instr: &Instruction) -> bool {
    match instr.mnemonic() {
        // Nop, endbranch, sign-extension / DF / rflags stack: always lowerable.
        Mnemonic::Nop
        | Mnemonic::Endbr64
        | Mnemonic::Endbr32
        | Mnemonic::Cwde
        | Mnemonic::Cdqe
        | Mnemonic::Cbw
        | Mnemonic::Cwd
        | Mnemonic::Cld
        | Mnemonic::Std
        | Mnemonic::Pushfq
        | Mnemonic::Popfq
        | Mnemonic::Leave => true,
        Mnemonic::Lea => lea_is_simple(instr),
        Mnemonic::Mov => mov_is_lowerable(instr),
        Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => movx_is_lowerable(instr),
        // Push/pop: r64, imm, and simple memory operands.
        Mnemonic::Push => push_is_lowerable(instr),
        Mnemonic::Pop => pop_is_lowerable(instr),
        // Bswap: r32 / r64 only (no memory form).
        Mnemonic::Bswap => {
            matches!(instr.op0_kind(), OpKind::Register)
                && matches!(instr.op_register(0).size(), 4 | 8)
        }
        Mnemonic::Add
        | Mnemonic::Adc
        | Mnemonic::Sub
        | Mnemonic::Sbb
        | Mnemonic::Xor
        | Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Cmp
        | Mnemonic::Test
        | Mnemonic::Bt
        | Mnemonic::Bts
        | Mnemonic::Btr
        | Mnemonic::Btc => alu_is_lowerable(instr),
        Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Not | Mnemonic::Neg => unary_is_lowerable(instr),
        Mnemonic::Imul => imul_is_lowerable(instr),
        Mnemonic::Xchg => xchg_is_lowerable(instr),
        Mnemonic::Shl
        | Mnemonic::Sal
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Rol
        | Mnemonic::Ror
        | Mnemonic::Rcl
        | Mnemonic::Rcr => shift_is_lowerable(instr),
        // Xadd/Cmpxchg: same operand forms (dst reg/mem, src register).
        Mnemonic::Xadd | Mnemonic::Cmpxchg => match (instr.op0_kind(), instr.op1_kind()) {
            (OpKind::Register, OpKind::Register) => true,
            (OpKind::Memory, OpKind::Register) => mem_ea_ok(instr) && mem_size_ok(instr),
            _ => false,
        },
        // Bsr: bit scan reverse — dst reg, src reg/mem.
        Mnemonic::Bsr => match (instr.op0_kind(), instr.op1_kind()) {
            (OpKind::Register, OpKind::Register) => true,
            (OpKind::Register, OpKind::Memory) => mem_ea_ok(instr) && mem_size_ok(instr),
            _ => false,
        },
        Mnemonic::Cmove
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
        | Mnemonic::Cmovnp => cmov_is_lowerable(instr),
        Mnemonic::Sete
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
        | Mnemonic::Setnp => setcc_is_lowerable(instr),
        // SSE: packed/scalar moves + xor (CRT memcpy / zeroing helpers).
        Mnemonic::Movaps | Mnemonic::Movups | Mnemonic::Movdqa | Mnemonic::Movdqu => {
            sse_mov_is_lowerable(instr, 16)
        }
        Mnemonic::Movss => sse_mov_is_lowerable(instr, 4),
        Mnemonic::Movsd if sse_movsd_is_sse(instr) => sse_mov_is_lowerable(instr, 8),
        Mnemonic::Movq => sse_movq_is_lowerable(instr),
        Mnemonic::Movd => sse_movd_is_lowerable(instr),
        Mnemonic::Xorps
        | Mnemonic::Xorpd
        | Mnemonic::Pxor
        | Mnemonic::Andps
        | Mnemonic::Andpd
        | Mnemonic::Pand
        | Mnemonic::Orps
        | Mnemonic::Orpd
        | Mnemonic::Por
        | Mnemonic::Andnps
        | Mnemonic::Andnpd
        | Mnemonic::Pandn => sse_bitwise_is_lowerable(instr),
        Mnemonic::Movapd | Mnemonic::Movupd => sse_mov_is_lowerable(instr, 16),
        // Scalar / packed FP arithmetic (lowered via small host f32/f64 helpers).
        Mnemonic::Addss
        | Mnemonic::Subss
        | Mnemonic::Mulss
        | Mnemonic::Divss
        | Mnemonic::Addsd
        | Mnemonic::Subsd
        | Mnemonic::Mulsd
        | Mnemonic::Divsd => sse_scalar_fp_is_lowerable(instr),
        Mnemonic::Addps
        | Mnemonic::Subps
        | Mnemonic::Mulps
        | Mnemonic::Divps
        | Mnemonic::Addpd
        | Mnemonic::Subpd
        | Mnemonic::Mulpd
        | Mnemonic::Divpd => sse_packed_fp_is_lowerable(instr),
        // String ops (REP bulk via JIT host helper); ends block in decoder.
        Mnemonic::Stosb
        | Mnemonic::Stosw
        | Mnemonic::Stosd
        | Mnemonic::Stosq
        | Mnemonic::Movsb
        | Mnemonic::Movsw
        | Mnemonic::Movsq
        | Mnemonic::Lodsb
        | Mnemonic::Lodsd
        | Mnemonic::Lodsq
        | Mnemonic::Scasb
        | Mnemonic::Scasw
        | Mnemonic::Scasd
        | Mnemonic::Scasq
        | Mnemonic::Cmpsb
        | Mnemonic::Cmpsw
        | Mnemonic::Cmpsd
        | Mnemonic::Cmpsq => string_mnemonic_ok(),
        // Movsd string form only (SSE form handled above).
        Mnemonic::Movsd if !sse_movsd_is_sse(instr) => string_mnemonic_ok(),
        _ => false,
    }
}

#[inline]
const fn string_mnemonic_ok() -> bool {
    true
}

/// True for MOVS/STOS/LODS/SCAS/CMPS (including REP forms).
pub(super) fn is_string_op(instr: &Instruction) -> bool {
    match instr.mnemonic() {
        Mnemonic::Stosb
        | Mnemonic::Stosw
        | Mnemonic::Stosd
        | Mnemonic::Stosq
        | Mnemonic::Movsb
        | Mnemonic::Movsw
        | Mnemonic::Movsq
        | Mnemonic::Lodsb
        | Mnemonic::Lodsd
        | Mnemonic::Lodsq
        | Mnemonic::Scasb
        | Mnemonic::Scasw
        | Mnemonic::Scasd
        | Mnemonic::Scasq
        | Mnemonic::Cmpsb
        | Mnemonic::Cmpsw
        | Mnemonic::Cmpsd
        | Mnemonic::Cmpsq => true,
        Mnemonic::Movsd => !sse_movsd_is_sse(instr),
        _ => false,
    }
}

pub(super) fn string_op_size(instr: &Instruction) -> Option<u32> {
    match instr.mnemonic() {
        Mnemonic::Stosb | Mnemonic::Movsb | Mnemonic::Lodsb | Mnemonic::Scasb | Mnemonic::Cmpsb => {
            Some(1)
        }
        Mnemonic::Stosw | Mnemonic::Movsw | Mnemonic::Scasw | Mnemonic::Cmpsw => Some(2),
        Mnemonic::Stosd | Mnemonic::Lodsd | Mnemonic::Scasd | Mnemonic::Cmpsd => Some(4),
        Mnemonic::Movsd if !sse_movsd_is_sse(instr) => Some(4),
        Mnemonic::Stosq | Mnemonic::Movsq | Mnemonic::Lodsq | Mnemonic::Scasq | Mnemonic::Cmpsq => {
            Some(8)
        }
        _ => None,
    }
}

/// `movsd` mnemonic is shared with string MOVS DWORD — only XMM forms are SSE.
fn sse_movsd_is_sse(instr: &Instruction) -> bool {
    instr.op0_register().is_xmm()
        || instr.op1_register().is_xmm()
        || matches!(
            instr.code(),
            iced_x86::Code::Movsd_xmm_xmmm64 | iced_x86::Code::Movsd_xmmm64_xmm
        )
}

/// movaps/movups/movdqa/movdqu/movss/movsd: xmm↔xmm or xmm↔simple mem.
fn sse_mov_is_lowerable(instr: &Instruction, width: u32) -> bool {
    let _ = width;
    let k0 = instr.op0_kind();
    let k1 = instr.op1_kind();
    match (k0, k1) {
        (OpKind::Register, OpKind::Register) => {
            instr.op_register(0).is_xmm() && instr.op_register(1).is_xmm()
        }
        (OpKind::Register, OpKind::Memory) => {
            instr.op_register(0).is_xmm() && mem_ea_ok(instr) && mem_size_ok_sse(instr)
        }
        (OpKind::Memory, OpKind::Register) => {
            instr.op_register(1).is_xmm() && mem_ea_ok(instr) && mem_size_ok_sse(instr)
        }
        _ => false,
    }
}

/// movq: xmm↔xmm/m64, or xmm↔r64, or r64↔xmm.
fn sse_movq_is_lowerable(instr: &Instruction) -> bool {
    let k0 = instr.op0_kind();
    let k1 = instr.op1_kind();
    let r0 = instr.op_register(0);
    let r1 = instr.op_register(1);
    match (k0, k1) {
        (OpKind::Register, OpKind::Register) => {
            (r0.is_xmm() && r1.is_xmm())
                || (r0.is_xmm() && r1.size() == 8)
                || (r0.size() == 8 && r1.is_xmm())
        }
        (OpKind::Register, OpKind::Memory) => {
            (r0.is_xmm() || r0.size() == 8) && mem_ea_ok(instr) && mem_size_ok_sse(instr)
        }
        (OpKind::Memory, OpKind::Register) => {
            (r1.is_xmm() || r1.size() == 8) && mem_ea_ok(instr) && mem_size_ok_sse(instr)
        }
        _ => false,
    }
}

/// movd: xmm↔r32/m32.
fn sse_movd_is_lowerable(instr: &Instruction) -> bool {
    let k0 = instr.op0_kind();
    let k1 = instr.op1_kind();
    let r0 = instr.op_register(0);
    let r1 = instr.op_register(1);
    match (k0, k1) {
        (OpKind::Register, OpKind::Register) => {
            (r0.is_xmm() && r1.size() == 4) || (r0.size() == 4 && r1.is_xmm())
        }
        (OpKind::Register, OpKind::Memory) => {
            r0.is_xmm() && mem_ea_ok(instr) && mem_size_ok_sse(instr)
        }
        (OpKind::Memory, OpKind::Register) => {
            r1.is_xmm() && mem_ea_ok(instr) && mem_size_ok_sse(instr)
        }
        _ => false,
    }
}

/// xorps/andps/orps/andnps (+ pd / pand forms): xmm, xmm/m128.
fn sse_bitwise_is_lowerable(instr: &Instruction) -> bool {
    if instr.op0_kind() != OpKind::Register || !instr.op_register(0).is_xmm() {
        return false;
    }
    match instr.op1_kind() {
        OpKind::Register => instr.op_register(1).is_xmm(),
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok_sse(instr),
        _ => false,
    }
}

/// addss/subss/… / addsd/…: xmm, xmm/m32|m64.
fn sse_scalar_fp_is_lowerable(instr: &Instruction) -> bool {
    if instr.op0_kind() != OpKind::Register || !instr.op_register(0).is_xmm() {
        return false;
    }
    match instr.op1_kind() {
        OpKind::Register => instr.op_register(1).is_xmm(),
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok_sse(instr),
        _ => false,
    }
}

/// addps/mulpd/…: xmm, xmm/m128.
fn sse_packed_fp_is_lowerable(instr: &Instruction) -> bool {
    sse_bitwise_is_lowerable(instr)
}

/// Memory sizes used by SSE loads/stores (4/8/16).
fn mem_size_ok_sse(instr: &Instruction) -> bool {
    let sz = instr.memory_size().size();
    matches!(sz, 4 | 8 | 16) || mem_size_ok(instr)
}

/// Shift/rotate: dst reg or simple mem; count imm or CL.
fn shift_is_lowerable(instr: &Instruction) -> bool {
    let dst_ok = match instr.op0_kind() {
        OpKind::Register => true,
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    };
    if !dst_ok {
        return false;
    }
    match instr.op1_kind() {
        k if is_imm_kind(k) => true,
        OpKind::Register => {
            // Only CL/RCX count forms in v1.
            matches!(
                instr.op_register(1),
                Register::CL | Register::CX | Register::ECX | Register::RCX
            )
        }
        _ => false,
    }
}

fn cmov_is_lowerable(instr: &Instruction) -> bool {
    // cmov dst, src — both regs, or dst reg / src simple mem.
    if instr.op0_kind() != OpKind::Register {
        return false;
    }
    match instr.op1_kind() {
        OpKind::Register => true,
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    }
}

fn setcc_is_lowerable(instr: &Instruction) -> bool {
    match instr.op0_kind() {
        OpKind::Register => true,
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    }
}

/// `imul` 2-op (dst *= src) or 3-op (dst = src * imm). 1-op RDX:RAX → iced for now.
fn imul_is_lowerable(instr: &Instruction) -> bool {
    match instr.op_count() {
        2 => alu_is_lowerable(instr),
        3 => {
            if instr.op0_kind() != OpKind::Register {
                return false;
            }
            let src_ok = match instr.op1_kind() {
                OpKind::Register => true,
                OpKind::Memory => mem_ea_ok(instr) && mem_size_ok(instr),
                _ => false,
            };
            src_ok && is_imm_kind(instr.op2_kind())
        }
        _ => false,
    }
}

/// `xchg` reg,reg or reg,mem (simple EA).
fn xchg_is_lowerable(instr: &Instruction) -> bool {
    let k0 = instr.op0_kind();
    let k1 = instr.op1_kind();
    match (k0, k1) {
        (OpKind::Register, OpKind::Register) => true,
        (OpKind::Register, OpKind::Memory) | (OpKind::Memory, OpKind::Register) => {
            mem_ea_ok(instr) && mem_size_ok(instr)
        }
        _ => false,
    }
}

/// `push` r64 / imm / simple mem (64-bit stack ops only; 16-bit override → iced).
fn push_is_lowerable(instr: &Instruction) -> bool {
    match instr.op0_kind() {
        OpKind::Register => instr.op_register(0).size() != 2,
        imm if is_imm_kind(imm) => true,
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    }
}

/// `pop` r64 / simple mem (not 16-bit override).
fn pop_is_lowerable(instr: &Instruction) -> bool {
    match instr.op0_kind() {
        OpKind::Register => instr.op_register(0).size() != 2,
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    }
}

/// Binary ALU: reg/reg, reg/imm, reg/mem, mem/reg, mem/imm (simple EA).
fn alu_is_lowerable(instr: &Instruction) -> bool {
    let k0 = instr.op0_kind();
    let k1 = instr.op1_kind();
    match (k0, k1) {
        (OpKind::Register, OpKind::Register) => true,
        (OpKind::Register, imm) if is_imm_kind(imm) => true,
        (OpKind::Register, OpKind::Memory) | (OpKind::Memory, OpKind::Register) => {
            mem_ea_ok(instr) && mem_size_ok(instr)
        }
        (OpKind::Memory, imm) if is_imm_kind(imm) => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    }
}

fn unary_is_lowerable(instr: &Instruction) -> bool {
    match instr.op0_kind() {
        OpKind::Register => true,
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    }
}

/// `mov` reg↔reg, reg←imm, reg←mem, mem←reg, mem←imm (simple EA, size 1/2/4/8).
fn mov_is_lowerable(instr: &Instruction) -> bool {
    let k0 = instr.op0_kind();
    let k1 = instr.op1_kind();
    match (k0, k1) {
        (OpKind::Register, OpKind::Register) => true,
        (OpKind::Register, imm) if is_imm_kind(imm) => true,
        (OpKind::Register, OpKind::Memory) | (OpKind::Memory, OpKind::Register) => {
            mem_ea_ok(instr) && mem_size_ok(instr)
        }
        (OpKind::Memory, imm) if is_imm_kind(imm) => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    }
}

/// `movzx`/`movsx`/`movsxd`: dst reg, src reg or simple mem.
fn movx_is_lowerable(instr: &Instruction) -> bool {
    if instr.op0_kind() != OpKind::Register {
        return false;
    }
    match instr.op1_kind() {
        OpKind::Register => true,
        OpKind::Memory => mem_ea_ok(instr) && mem_size_ok(instr),
        _ => false,
    }
}

fn is_imm_kind(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// Allow full LEA address forms: `[base]`, `[disp]`, `[base+disp]`,
/// `[index*scale+disp]`, `[base+index*scale+disp]`, `[rip+disp]` (scale 1/2/4/8).
fn lea_is_simple(instr: &Instruction) -> bool {
    if instr.op0_kind() != OpKind::Register {
        return false;
    }
    if instr.op1_kind() != OpKind::Memory {
        return false;
    }
    mem_ea_ok(instr)
}

/// EA: optional base + optional index with scale 1/2/4/8 (no segment tricks).
fn mem_ea_ok(instr: &Instruction) -> bool {
    let index = instr.memory_index();
    if index == Register::None {
        return true;
    }
    matches!(instr.memory_index_scale(), 1 | 2 | 4 | 8)
}

fn mem_size_ok(instr: &Instruction) -> bool {
    matches!(
        instr.memory_size(),
        MemorySize::UInt8
            | MemorySize::Int8
            | MemorySize::UInt16
            | MemorySize::Int16
            | MemorySize::UInt32
            | MemorySize::Int32
            | MemorySize::UInt64
            | MemorySize::Int64
            | MemorySize::QwordOffset
            | MemorySize::SegPtr64
    ) || {
        // Fallback: register peer size 1/2/4/8.
        if instr.op0_kind() == OpKind::Register {
            matches!(instr.op_register(0).size(), 1 | 2 | 4 | 8)
        } else if instr.op1_kind() == OpKind::Register {
            matches!(instr.op_register(1).size(), 1 | 2 | 4 | 8)
        } else {
            false
        }
    }
}

/// Pre-compile plan: every memop in the block is `base+disp` on one stack
/// register, base is not mutated, so a **single** entry guard can cover the
/// whole block (Phase 4.1b super-fast path).
#[derive(Debug, Clone, Copy)]
pub(super) struct BlockStackPinPlan {
    /// GPR index of the stack base (4 = RSP, 5 = RBP).
    pub base_idx: usize,
    /// Minimum signed displacement of any access in the block.
    pub min_disp: i64,
    /// Exclusive end offset: `max(disp_i + size_i)` over all accesses.
    pub max_end: i64,
    /// Any access needs data read rights on the pin.
    pub needs_r: bool,
    /// Any access needs data write rights on the pin.
    pub needs_w: bool,
}

/// Analyse body (+ optional term insn) for block-wide stack-pin eligibility.
///
/// Returns `None` when any memop is not simple stack-relative, bases differ,
/// the base register is written, stack ops modify RSP, or there is no memory.
#[must_use]
pub(super) fn analyze_block_stack_pin(
    body: &[DecodedInsn],
    term_insn: Option<&DecodedInsn>,
) -> Option<BlockStackPinPlan> {
    let mut base_reg: Option<Register> = None;
    let mut min_disp = i64::MAX;
    let mut max_end = i64::MIN;
    let mut needs_r = false;
    let mut needs_w = false;
    let mut saw_mem = false;

    let mut consider = |instr: &Instruction| -> Option<()> {
        if insn_modifies_stack_ptr(instr) {
            return None;
        }
        // Reject if this insn writes RSP/RBP before we know which base we need —
        // checked again once base is known.
        if let Some(b) = base_reg
            && insn_writes_full_gpr(instr, b)
        {
            return None;
        }
        for op in 0..instr.op_count() {
            if instr.op_kind(op) != OpKind::Memory {
                continue;
            }
            // LEA is not a memory access (handled as non-mem in lowerable set);
            // still skip if we ever see it tagged as Memory.
            if instr.mnemonic() == Mnemonic::Lea {
                continue;
            }
            let b = instr.memory_base();
            if !is_stack_base_reg(b) || instr.memory_index() != Register::None {
                return None;
            }
            // RIP-relative is not a stack pin.
            if b == Register::RIP || b == Register::EIP {
                return None;
            }
            match base_reg {
                None => base_reg = Some(b),
                Some(prev) if prev != b => return None,
                Some(_) => {}
            }
            if insn_writes_full_gpr(instr, b) {
                return None;
            }
            let disp = mem_disp_i64(instr);
            let size = u64::from(mem_width_bytes(instr).ok()?);
            let size_i = i64::try_from(size).ok()?;
            let end = disp.checked_add(size_i)?;
            min_disp = min_disp.min(disp);
            max_end = max_end.max(end);
            let (r, w) = mem_op_rw(instr, op);
            needs_r |= r;
            needs_w |= w;
            saw_mem = true;
        }
        Some(())
    };

    for d in body {
        consider(&d.instr)?;
    }
    if let Some(t) = term_insn {
        // Call/ret touch the stack — not eligible.
        if matches!(
            t.instr.mnemonic(),
            Mnemonic::Call | Mnemonic::Ret | Mnemonic::Retf
        ) {
            return None;
        }
        consider(&t.instr)?;
    }

    if !saw_mem || min_disp == i64::MAX || max_end == i64::MIN {
        return None;
    }
    // Empty / inverted span (should not happen).
    if max_end <= min_disp {
        return None;
    }
    let base_reg = base_reg?;
    let base_idx = stack_base_gpr_index(base_reg)?;
    Some(BlockStackPinPlan {
        base_idx,
        min_disp,
        max_end,
        needs_r,
        needs_w,
    })
}

#[inline]
fn is_stack_base_reg(r: Register) -> bool {
    // Soft-translate is VA-based: any access whose effective address falls in the
    // stack region is valid for the stack pin / super path, whether addressed via
    // RSP or RBP. (RBP is not a reserved frame pointer on Win64, but the
    // block-wide guard still requires `[base+disp…] ⊆ stack pin`.)
    matches!(
        r,
        Register::RSP | Register::ESP | Register::RBP | Register::EBP
    )
}

#[inline]
fn stack_base_gpr_index(r: Register) -> Option<usize> {
    match r {
        Register::RSP | Register::ESP => Some(4),
        Register::RBP | Register::EBP => Some(5),
        _ => None,
    }
}

/// iced stores displacements as the bit-pattern of a signed offset.
#[inline]
fn mem_disp_i64(instr: &Instruction) -> i64 {
    #[allow(clippy::cast_possible_wrap)]
    {
        instr.memory_displacement64() as i64
    }
}

fn insn_modifies_stack_ptr(instr: &Instruction) -> bool {
    matches!(
        instr.mnemonic(),
        Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Pushfq
            | Mnemonic::Popfq
            | Mnemonic::Pushf
            | Mnemonic::Popf
            | Mnemonic::Call
            | Mnemonic::Ret
            | Mnemonic::Retf
            | Mnemonic::Enter
            | Mnemonic::Leave
    )
}

/// Whether `instr` writes the full 64-bit `reg` (or a GPR that aliases it).
fn insn_writes_full_gpr(instr: &Instruction, reg: Register) -> bool {
    if insn_modifies_stack_ptr(instr)
        && matches!(
            reg,
            Register::RSP | Register::ESP | Register::RBP | Register::EBP
        )
    {
        // PUSH/POP/CALL/RET always update RSP; LEAVE updates RBP+RSP.
        if matches!(instr.mnemonic(), Mnemonic::Leave) {
            return matches!(
                reg,
                Register::RSP | Register::ESP | Register::RBP | Register::EBP
            );
        }
        return matches!(reg, Register::RSP | Register::ESP);
    }
    // Read-only memops / compares never write GPRs as op0.
    if matches!(
        instr.mnemonic(),
        Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Bt
            | Mnemonic::Bts
            | Mnemonic::Btr
            | Mnemonic::Btc
    ) {
        // BTS/BTR/BTC write the mem/reg destination — handle below.
        if matches!(
            instr.mnemonic(),
            Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt
        ) {
            return false;
        }
    }
    if instr.op_count() == 0 {
        return false;
    }
    if instr.op0_kind() != OpKind::Register {
        return false;
    }
    let dst = instr.op_register(0);
    gpr_aliases(dst, reg)
}

fn gpr_aliases(a: Register, b: Register) -> bool {
    if a == b {
        return true;
    }
    // Same full register family (RAX/EAX/AX/AL, …).
    full_gpr(a) == full_gpr(b)
}

fn full_gpr(r: Register) -> Option<Register> {
    // Full 64-bit home for partial GPRs (RAX family, …).
    if matches!(
        r,
        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH
    ) {
        return Some(Register::RAX);
    }
    if matches!(
        r,
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH
    ) {
        return Some(Register::RCX);
    }
    if matches!(
        r,
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH
    ) {
        return Some(Register::RDX);
    }
    if matches!(
        r,
        Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH
    ) {
        return Some(Register::RBX);
    }
    if matches!(
        r,
        Register::RSP | Register::ESP | Register::SP | Register::SPL
    ) {
        return Some(Register::RSP);
    }
    if matches!(
        r,
        Register::RBP | Register::EBP | Register::BP | Register::BPL
    ) {
        return Some(Register::RBP);
    }
    if matches!(
        r,
        Register::RSI | Register::ESI | Register::SI | Register::SIL
    ) {
        return Some(Register::RSI);
    }
    if matches!(
        r,
        Register::RDI | Register::EDI | Register::DI | Register::DIL
    ) {
        return Some(Register::RDI);
    }
    if matches!(
        r,
        Register::R8 | Register::R8D | Register::R8W | Register::R8L
    ) {
        return Some(Register::R8);
    }
    if matches!(
        r,
        Register::R9 | Register::R9D | Register::R9W | Register::R9L
    ) {
        return Some(Register::R9);
    }
    if matches!(
        r,
        Register::R10 | Register::R10D | Register::R10W | Register::R10L
    ) {
        return Some(Register::R10);
    }
    if matches!(
        r,
        Register::R11 | Register::R11D | Register::R11W | Register::R11L
    ) {
        return Some(Register::R11);
    }
    if matches!(
        r,
        Register::R12 | Register::R12D | Register::R12W | Register::R12L
    ) {
        return Some(Register::R12);
    }
    if matches!(
        r,
        Register::R13 | Register::R13D | Register::R13W | Register::R13L
    ) {
        return Some(Register::R13);
    }
    if matches!(
        r,
        Register::R14 | Register::R14D | Register::R14W | Register::R14L
    ) {
        return Some(Register::R14);
    }
    if matches!(
        r,
        Register::R15 | Register::R15D | Register::R15W | Register::R15L
    ) {
        return Some(Register::R15);
    }
    Option::None
}

/// Read/write intent for a memory operand at index `op`.
fn mem_op_rw(instr: &Instruction, op: u32) -> (bool, bool) {
    let m = instr.mnemonic();
    // Pure stores: MOV/MOVZX/… with dest mem — still only write for MOV.
    if op == 0 {
        match m {
            Mnemonic::Mov
            | Mnemonic::Movd
            | Mnemonic::Movq
            | Mnemonic::Movaps
            | Mnemonic::Movapd
            | Mnemonic::Movups
            | Mnemonic::Movupd
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu
            | Mnemonic::Movss
            | Mnemonic::Movsd
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Movzx
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
            | Mnemonic::Setnp => (false, true),
            Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt => (true, false),
            // RMW ALU / shifts / etc.
            _ => (true, true),
        }
    } else {
        // Source memory operand — load.
        (true, false)
    }
}

/// Byte width of a memory operand (1/2/4/8/16).
pub(super) fn mem_width_bytes(instr: &Instruction) -> Result<u32, String> {
    // Prefer iced's size table (covers Packed128_*, Float64, UInt128, …).
    let table_sz = instr.memory_size().size();
    if matches!(table_sz, 1 | 2 | 4 | 8 | 16) {
        return Ok(u32::try_from(table_sz).unwrap_or(0));
    }
    let sz = match instr.memory_size() {
        MemorySize::UInt8 | MemorySize::Int8 => 1,
        MemorySize::UInt16 | MemorySize::Int16 => 2,
        MemorySize::UInt32 | MemorySize::Int32 => 4,
        MemorySize::UInt64 | MemorySize::Int64 | MemorySize::QwordOffset | MemorySize::SegPtr64 => {
            8
        }
        MemorySize::UInt128 | MemorySize::Int128 | MemorySize::Float128 => 16,
        _ => {
            if instr.op0_kind() == OpKind::Register {
                let r = instr.op_register(0);
                if r.is_xmm() { 16 } else { r.size() }
            } else if instr.op1_kind() == OpKind::Register {
                let r = instr.op_register(1);
                if r.is_xmm() { 16 } else { r.size() }
            } else {
                return Err("unsupported mem size".into());
            }
        }
    };
    if matches!(sz, 1 | 2 | 4 | 8 | 16) {
        Ok(u32::try_from(sz).unwrap_or(0))
    } else {
        Err(format!("bad mem width {sz}"))
    }
}
