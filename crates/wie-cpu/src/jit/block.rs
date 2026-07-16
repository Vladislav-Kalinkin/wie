//! Decode a lowerable straight-line block for Cranelift (GPR + simple mem + jcc/jmp term).

use crate::iced_cpu::IcedCpu;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};

/// Max instructions per compiled block (keeps compile time bounded).
pub(super) const MAX_BLOCK_INSNS: usize = 32;
/// Min instructions before paying Cranelift compile cost (short blocks lose wall).
pub(super) const MIN_BLOCK_INSNS: usize = 8;

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
pub(super) fn decode_pure_gpr_block(cpu: &IcedCpu, start: u64) -> BlockKind {
    let mut insns = Vec::new();
    let mut rip = start;
    let mut bytes_len = 0_u32;
    let mut term: Option<BlockTerm> = None;

    for _ in 0..MAX_BLOCK_INSNS {
        // Host-stop addresses must not be entered by JIT.
        if let Some(h) = cpu.hooks_ref()
            && h.should_host_stop(rip)
        {
            break;
        }

        let mut buf = [0_u8; 15];
        if cpu.mem_read_into(rip, &mut buf).is_err() {
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

    // Lone / short blocks ending in bulk string, near-call (UCRT), or near-ret
    // (shadow-stack chaining) are worth compiling — beat iced + host-stop.
    let min = if insns.last().is_some_and(|d| {
        is_string_op(&d.instr)
            || matches!(d.instr.mnemonic(), Mnemonic::Call | Mnemonic::Ret)
    }) {
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
        Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 => true,
        // LEA: all standard SIB forms (base/index*1|2|4|8 + disp) + RIP-relative.
        Mnemonic::Lea => lea_is_simple(instr),
        Mnemonic::Mov => mov_is_lowerable(instr),
        Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => movx_is_lowerable(instr),
        // Push/pop: r64, imm, and simple memory operands.
        Mnemonic::Push => push_is_lowerable(instr),
        Mnemonic::Pop => pop_is_lowerable(instr),
        Mnemonic::Add
        | Mnemonic::Adc
        | Mnemonic::Sub
        | Mnemonic::Sbb
        | Mnemonic::Xor
        | Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Cmp
        | Mnemonic::Test => alu_is_lowerable(instr),
        Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Not | Mnemonic::Neg => unary_is_lowerable(instr),
        Mnemonic::Imul => imul_is_lowerable(instr),
        Mnemonic::Xchg => xchg_is_lowerable(instr),
        Mnemonic::Shl
        | Mnemonic::Sal
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Rol
        | Mnemonic::Ror => shift_is_lowerable(instr),
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
