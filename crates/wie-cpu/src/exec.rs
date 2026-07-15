//! Instruction execution for the iced x86-64 interpreter.
//!
//! Low-level CPU arithmetic intentionally uses wrapping ops, truncating casts,
//! and direct indexing of fixed-size buffers — clippy pedantic is not useful here.

#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::integer_division
)]

use crate::mem::GuestMemory;
use crate::regs::{self, rflags, RegFile};
use crate::CpuError;
use iced_x86::{Instruction, MemorySize, Mnemonic, OpKind, Register};

/// Access type codes matching Unicorn-ish invalid-memory reporting (0=read,1=write,2=fetch).
pub(crate) const ACCESS_READ: i32 = 0;
pub(crate) const ACCESS_WRITE: i32 = 1;
pub(crate) const ACCESS_FETCH: i32 = 16;

#[derive(Debug, Clone, Copy)]
pub(crate) struct InvalidMem {
    pub access_type: i32,
    pub address: u64,
    pub size: i32,
    pub value: i64,
}

#[derive(Debug)]
pub(crate) enum StepResult {
    /// Advanced RIP (or branch) normally.
    Continue,
    /// Hit a host-stop hook address (caller should not execute).
    HostStop { address: u64, size: u32 },
    /// Invalid memory during this step.
    InvalidMemory(InvalidMem),
}

/// Decode + execute one instruction at `regs.rip`.
pub(crate) fn step(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    hook: Option<&HookWindow>,
) -> Result<StepResult, CpuError> {
    let rip = regs.rip;

    if let Some(h) = hook
        && h.should_host_stop(rip)
    {
        // Decode first for accurate size when possible.
        let size = peek_insn_len(mem, rip).unwrap_or(1);
        return Ok(StepResult::HostStop {
            address: rip,
            size,
        });
    }

    let Ok(bytes) = mem.fetch(rip, 15) else {
        return Ok(StepResult::InvalidMemory(InvalidMem {
            access_type: ACCESS_FETCH,
            address: rip,
            size: 1,
            value: 0,
        }));
    };

    let mut decoder = iced_x86::Decoder::with_ip(64, &bytes, rip, iced_x86::DecoderOptions::NONE);
    let instr = decoder.decode();
    if instr.is_invalid() || instr.len() == 0 {
        return Err(CpuError::Message(format!(
            "invalid instruction at {rip:#x}"
        )));
    }

    let next_ip = instr.next_ip();
    // Do not advance RIP until the instruction completes successfully.
    // (Faults must leave RIP at the faulting instruction — Unicorn semantics.)
    match execute_one(mem, regs, &instr, next_ip) {
        Ok(()) => Ok(StepResult::Continue),
        Err(StepExecError::InvalidMemory(inv)) => {
            // Ensure RIP still points at the faulting insn.
            regs.rip = rip;
            Ok(StepResult::InvalidMemory(inv))
        }
        Err(StepExecError::Cpu(e)) => {
            regs.rip = rip;
            Err(e)
        }
    }
}

fn peek_insn_len(mem: &GuestMemory, rip: u64) -> Option<u32> {
    let bytes = mem.fetch(rip, 15).ok()?;
    let mut decoder = iced_x86::Decoder::with_ip(64, &bytes, rip, iced_x86::DecoderOptions::NONE);
    let instr = decoder.decode();
    if instr.is_invalid() || instr.len() == 0 {
        return None;
    }
    u32::try_from(instr.len()).ok()
}

enum StepExecError {
    InvalidMemory(InvalidMem),
    Cpu(CpuError),
}

impl From<CpuError> for StepExecError {
    fn from(e: CpuError) -> Self {
        Self::Cpu(e)
    }
}

/// Hook window + stop bitmap (1 = host stop).
#[derive(Debug, Clone)]
pub(crate) struct HookWindow {
    pub begin: u64,
    pub end: u64,
    pub stop_bitmap: Vec<u8>,
}

impl HookWindow {
    #[must_use]
    pub(crate) fn should_host_stop(&self, address: u64) -> bool {
        if self.stop_bitmap.is_empty() {
            return address >= self.begin && address <= self.end;
        }
        if address < self.begin {
            return false;
        }
        let range_len = self.end.saturating_sub(self.begin).saturating_add(1);
        let offset = address.saturating_sub(self.begin);
        if offset >= range_len {
            return false;
        }
        let bit_index = usize::try_from(offset).unwrap_or(usize::MAX);
        let byte_index = bit_index / 8;
        let bit = bit_index % 8;
        match self.stop_bitmap.get(byte_index) {
            Some(&byte) => (byte & (1_u8 << bit)) != 0,
            None => true,
        }
    }
}

fn execute_one(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    next_ip: u64,
) -> Result<(), StepExecError> {
    // Fall-through RIP; branches / call / ret override. Set only after we know
    // the op will not fault on decode of operands — still set early for LEA/jcc
    // that need next_ip; memory ops that fault restore RIP in `step`.
    regs.rip = next_ip;

    match instr.mnemonic() {
        // No-ops / PE userspace I/O stubs (no real ports).
        Mnemonic::Nop
        | Mnemonic::Fnclex
        | Mnemonic::Fninit
        | Mnemonic::Finit
        | Mnemonic::Endbr64
        | Mnemonic::Endbr32
        | Mnemonic::Out
        | Mnemonic::Outsb
        | Mnemonic::Outsw
        | Mnemonic::Outsd => Ok(()),

        Mnemonic::Mov => exec_mov(mem, regs, instr),
        Mnemonic::Movzx => exec_movzx(mem, regs, instr, false),
        Mnemonic::Movsx | Mnemonic::Movsxd => exec_movzx(mem, regs, instr, true),
        Mnemonic::Lea => exec_lea(regs, instr),

        Mnemonic::Push => exec_push(mem, regs, instr),
        Mnemonic::Pop => exec_pop(mem, regs, instr),

        Mnemonic::Add => exec_arith(mem, regs, instr, ArithOp::Add),
        Mnemonic::Adc => exec_arith(mem, regs, instr, ArithOp::Adc),
        Mnemonic::Sub => exec_arith(mem, regs, instr, ArithOp::Sub),
        Mnemonic::Sbb => exec_arith(mem, regs, instr, ArithOp::Sbb),
        Mnemonic::Xor => exec_arith(mem, regs, instr, ArithOp::Xor),
        Mnemonic::Or => exec_arith(mem, regs, instr, ArithOp::Or),
        Mnemonic::And => exec_arith(mem, regs, instr, ArithOp::And),
        Mnemonic::Cmp => exec_arith(mem, regs, instr, ArithOp::Cmp),
        Mnemonic::Test => exec_test(mem, regs, instr),
        Mnemonic::Inc => exec_inc_dec(mem, regs, instr, true),
        Mnemonic::Dec => exec_inc_dec(mem, regs, instr, false),
        Mnemonic::Neg => exec_neg(mem, regs, instr),
        Mnemonic::Not => exec_not(mem, regs, instr),
        Mnemonic::Imul => exec_imul(mem, regs, instr),
        Mnemonic::Mul => exec_mul(mem, regs, instr),
        Mnemonic::Div => exec_div(mem, regs, instr, false),
        Mnemonic::Idiv => exec_div(mem, regs, instr, true),

        Mnemonic::Shl | Mnemonic::Sal => exec_shift(mem, regs, instr, ShiftKind::Shl),
        Mnemonic::Shr => exec_shift(mem, regs, instr, ShiftKind::Shr),
        Mnemonic::Sar => exec_shift(mem, regs, instr, ShiftKind::Sar),
        Mnemonic::Rol => exec_shift(mem, regs, instr, ShiftKind::Rol),
        Mnemonic::Ror => exec_shift(mem, regs, instr, ShiftKind::Ror),

        Mnemonic::Jmp => exec_jmp(mem, regs, instr),
        Mnemonic::Call => exec_call(mem, regs, instr, next_ip),
        Mnemonic::Ret => exec_ret(mem, regs, instr),

        // iced uses one primary name per condition (Je not Jz, etc.).
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
        | Mnemonic::Jnp) => {
            exec_jcc(regs, instr, cond_from_jcc(m, regs));
            Ok(())
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
        | Mnemonic::Cmovnp) => exec_cmov(mem, regs, instr, cond_from_cmov(m, regs)),

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
        | Mnemonic::Setnp) => exec_setcc(mem, regs, instr, cond_from_setcc(m, regs)),

        Mnemonic::Xchg => exec_xchg(mem, regs, instr),
        Mnemonic::Cmpxchg => exec_cmpxchg(mem, regs, instr),
        Mnemonic::Bswap => exec_bswap(regs, instr),
        Mnemonic::Bt => exec_bit(mem, regs, instr, BitOp::Bt),
        Mnemonic::Bts => exec_bit(mem, regs, instr, BitOp::Bts),
        Mnemonic::Btr => exec_bit(mem, regs, instr, BitOp::Btr),
        Mnemonic::Btc => exec_bit(mem, regs, instr, BitOp::Btc),

        Mnemonic::Cdqe => {
            let eax = regs.rax() as i32;
            regs.set_rax(i64::from(eax) as u64);
            Ok(())
        }
        Mnemonic::Cwde => {
            let ax = regs.rax() as i16;
            regs.write_reg(Register::EAX, i64::from(ax) as u64 & 0xffff_ffff)?;
            Ok(())
        }
        Mnemonic::Cbw => {
            let al = regs.rax() as i8;
            regs.write_reg(Register::AX, i64::from(al) as u64 & 0xffff)?;
            Ok(())
        }
        Mnemonic::Cdq => {
            let eax = regs.rax() as i32;
            regs.set_rdx(if eax < 0 { 0xffff_ffff } else { 0 });
            Ok(())
        }
        Mnemonic::Cwd => {
            let ax = regs.rax() as i16;
            regs.write_reg(Register::DX, if ax < 0 { 0xffff } else { 0 })?;
            Ok(())
        }
        Mnemonic::Cqo => {
            let rax = regs.rax() as i64;
            regs.set_rdx(if rax < 0 { u64::MAX } else { 0 });
            Ok(())
        }
        Mnemonic::Cld => {
            regs.set_flag(rflags::DF, false);
            Ok(())
        }
        Mnemonic::Std => {
            regs.set_flag(rflags::DF, true);
            Ok(())
        }
        Mnemonic::Clc => {
            regs.set_flag(rflags::CF, false);
            Ok(())
        }
        Mnemonic::Stc => {
            regs.set_flag(rflags::CF, true);
            Ok(())
        }
        Mnemonic::Cmc => {
            regs.set_flag(rflags::CF, !regs.flag(rflags::CF));
            Ok(())
        }
        Mnemonic::Pushfq => {
            push_n(mem, regs, regs.rflags, 8)?;
            Ok(())
        }
        Mnemonic::Popfq => {
            let v = pop_n(mem, regs, 8)?;
            // Keep reserved bit 1 set.
            regs.rflags = (v & !rflags::ALWAYS1) | rflags::ALWAYS1;
            Ok(())
        }
        Mnemonic::Leave => {
            regs.set_rsp(regs.rbp());
            let val = pop64(mem, regs)?;
            regs.set_rbp(val);
            Ok(())
        }

        Mnemonic::Stosb => exec_stos(mem, regs, instr, 1),
        Mnemonic::Stosw => exec_stos(mem, regs, instr, 2),
        Mnemonic::Stosd => exec_stos(mem, regs, instr, 4),
        Mnemonic::Stosq => exec_stos(mem, regs, instr, 8),
        Mnemonic::Movsb => exec_movs(mem, regs, instr, 1),
        Mnemonic::Movsw => exec_movs(mem, regs, instr, 2),
        // Movsd is both string (A5) and SSE2 scalar — disambiguate by XMM use.
        Mnemonic::Movsd => {
            if is_sse_movsd(instr) {
                exec_sse_mov(mem, regs, instr, 8, true)
            } else {
                exec_movs(mem, regs, instr, 4)
            }
        }
        Mnemonic::Movsq => exec_movs(mem, regs, instr, 8),
        Mnemonic::Lodsb => exec_lods(mem, regs, instr, 1),
        Mnemonic::Lodsd => exec_lods(mem, regs, instr, 4),
        Mnemonic::Lodsq => exec_lods(mem, regs, instr, 8),
        Mnemonic::Scasb => exec_scas(mem, regs, instr, 1),
        Mnemonic::Scasw => exec_scas(mem, regs, instr, 2),
        Mnemonic::Scasd => exec_scas(mem, regs, instr, 4),
        Mnemonic::Scasq => exec_scas(mem, regs, instr, 8),
        Mnemonic::Cmpsb => exec_cmps(mem, regs, instr, 1),
        Mnemonic::Cmpsw => exec_cmps(mem, regs, instr, 2),
        Mnemonic::Cmpsd => exec_cmps(mem, regs, instr, 4),
        Mnemonic::Cmpsq => exec_cmps(mem, regs, instr, 8),

        // Scalar / packed SSE moves (enough for CRT / memcpy helpers).
        Mnemonic::Movss => exec_sse_mov(mem, regs, instr, 4, true),
        Mnemonic::Movaps | Mnemonic::Movups | Mnemonic::Movdqa | Mnemonic::Movdqu => {
            exec_sse_mov(mem, regs, instr, 16, false)
        }
        Mnemonic::Movq => exec_sse_movq(mem, regs, instr),
        Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor => exec_sse_xor(mem, regs, instr),
        Mnemonic::Movd => exec_sse_movd(mem, regs, instr),

        // Minimal stubs: enough for CRT init that queries the host.
        Mnemonic::Cpuid => {
            // Leaf in EAX; return zeros (guest rarely depends on exact bits at PE entry).
            regs.set_rax(0);
            regs.set_gpr(3, 0); // RBX
            regs.set_rcx(0);
            regs.set_rdx(0);
            Ok(())
        }
        Mnemonic::Rdtsc => {
            // Monotonic-ish host time; not architectural.
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            regs.set_rax(t & 0xffff_ffff);
            regs.set_rdx(t >> 32);
            Ok(())
        }
        // PE userspace: no real I/O ports — zero reads.
        Mnemonic::In => {
            regs.set_rax(0);
            Ok(())
        }
        Mnemonic::Insb | Mnemonic::Insw | Mnemonic::Insd => {
            // REP IN* rarely used; ignore.
            if instr.has_rep_prefix() {
                regs.set_rcx(0);
            }
            Ok(())
        }

        other => Err(StepExecError::Cpu(CpuError::Message(format!(
            "unimplemented mnemonic {other:?} at {:#x}",
            instr.ip()
        )))),
    }
}

#[derive(Clone, Copy)]
enum BitOp {
    Bt,
    Bts,
    Btr,
    Btc,
}

#[derive(Clone, Copy)]
enum ArithOp {
    Add,
    Adc,
    Sub,
    Sbb,
    Xor,
    Or,
    And,
    Cmp,
}

#[derive(Clone, Copy)]
enum ShiftKind {
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
}

fn cond_from_jcc(m: Mnemonic, regs: &RegFile) -> bool {
    match m {
        Mnemonic::Je => regs.flag(rflags::ZF),
        Mnemonic::Jne => !regs.flag(rflags::ZF),
        Mnemonic::Ja => !regs.flag(rflags::CF) && !regs.flag(rflags::ZF),
        Mnemonic::Jae => !regs.flag(rflags::CF),
        Mnemonic::Jb => regs.flag(rflags::CF),
        Mnemonic::Jbe => regs.flag(rflags::CF) || regs.flag(rflags::ZF),
        Mnemonic::Jg => !regs.flag(rflags::ZF) && regs.flag(rflags::SF) == regs.flag(rflags::OF),
        Mnemonic::Jge => regs.flag(rflags::SF) == regs.flag(rflags::OF),
        Mnemonic::Jl => regs.flag(rflags::SF) != regs.flag(rflags::OF),
        Mnemonic::Jle => regs.flag(rflags::ZF) || regs.flag(rflags::SF) != regs.flag(rflags::OF),
        Mnemonic::Jo => regs.flag(rflags::OF),
        Mnemonic::Jno => !regs.flag(rflags::OF),
        Mnemonic::Js => regs.flag(rflags::SF),
        Mnemonic::Jns => !regs.flag(rflags::SF),
        Mnemonic::Jp => regs.flag(rflags::PF),
        Mnemonic::Jnp => !regs.flag(rflags::PF),
        _ => false,
    }
}

fn cond_from_cmov(m: Mnemonic, regs: &RegFile) -> bool {
    match m {
        Mnemonic::Cmove => regs.flag(rflags::ZF),
        Mnemonic::Cmovne => !regs.flag(rflags::ZF),
        Mnemonic::Cmova => !regs.flag(rflags::CF) && !regs.flag(rflags::ZF),
        Mnemonic::Cmovae => !regs.flag(rflags::CF),
        Mnemonic::Cmovb => regs.flag(rflags::CF),
        Mnemonic::Cmovbe => regs.flag(rflags::CF) || regs.flag(rflags::ZF),
        Mnemonic::Cmovg => !regs.flag(rflags::ZF) && regs.flag(rflags::SF) == regs.flag(rflags::OF),
        Mnemonic::Cmovge => regs.flag(rflags::SF) == regs.flag(rflags::OF),
        Mnemonic::Cmovl => regs.flag(rflags::SF) != regs.flag(rflags::OF),
        Mnemonic::Cmovle => regs.flag(rflags::ZF) || regs.flag(rflags::SF) != regs.flag(rflags::OF),
        Mnemonic::Cmovo => regs.flag(rflags::OF),
        Mnemonic::Cmovno => !regs.flag(rflags::OF),
        Mnemonic::Cmovs => regs.flag(rflags::SF),
        Mnemonic::Cmovns => !regs.flag(rflags::SF),
        Mnemonic::Cmovp => regs.flag(rflags::PF),
        Mnemonic::Cmovnp => !regs.flag(rflags::PF),
        _ => false,
    }
}

fn cond_from_setcc(m: Mnemonic, regs: &RegFile) -> bool {
    match m {
        Mnemonic::Sete => regs.flag(rflags::ZF),
        Mnemonic::Setne => !regs.flag(rflags::ZF),
        Mnemonic::Seta => !regs.flag(rflags::CF) && !regs.flag(rflags::ZF),
        Mnemonic::Setae => !regs.flag(rflags::CF),
        Mnemonic::Setb => regs.flag(rflags::CF),
        Mnemonic::Setbe => regs.flag(rflags::CF) || regs.flag(rflags::ZF),
        Mnemonic::Setg => !regs.flag(rflags::ZF) && regs.flag(rflags::SF) == regs.flag(rflags::OF),
        Mnemonic::Setge => regs.flag(rflags::SF) == regs.flag(rflags::OF),
        Mnemonic::Setl => regs.flag(rflags::SF) != regs.flag(rflags::OF),
        Mnemonic::Setle => regs.flag(rflags::ZF) || regs.flag(rflags::SF) != regs.flag(rflags::OF),
        Mnemonic::Seto => regs.flag(rflags::OF),
        Mnemonic::Setno => !regs.flag(rflags::OF),
        Mnemonic::Sets => regs.flag(rflags::SF),
        Mnemonic::Setns => !regs.flag(rflags::SF),
        Mnemonic::Setp => regs.flag(rflags::PF),
        Mnemonic::Setnp => !regs.flag(rflags::PF),
        _ => false,
    }
}

fn exec_mov(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let src = read_op(mem, regs, instr, 1)?;
    write_op(mem, regs, instr, 0, src)?;
    Ok(())
}

fn exec_movzx(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    sign: bool,
) -> Result<(), StepExecError> {
    let src_size = op_size_bytes(instr, 1)?;
    let dst_size = op_size_bytes(instr, 0)?;
    let raw = read_op(mem, regs, instr, 1)?;
    let src_mask = regs::size_mask(src_size);
    let narrow = raw & src_mask;
    let extended = if sign {
        let bits = src_size.saturating_mul(8);
        let shift = 64_u32.saturating_sub(u32::try_from(bits).unwrap_or(64));
        ((narrow as i64) << shift >> shift) as u64
    } else {
        narrow
    };
    // Write with dst size semantics (32-bit zero-extends).
    write_op_sized(mem, regs, instr, 0, extended, dst_size)?;
    Ok(())
}

fn exec_lea(regs: &mut RegFile, instr: &Instruction) -> Result<(), StepExecError> {
    let addr = effective_address(regs, instr)?;
    let dst = instr.op_register(0);
    // LEA writes full register size of dest.
    regs.write_reg(dst, addr)?;
    Ok(())
}

fn exec_push(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let val = read_op(mem, regs, instr, 0)?;
    // In 64-bit mode push is always 64-bit (except rare 16-bit override).
    let size = match instr.op0_kind() {
        OpKind::Register if instr.op_register(0).size() == 2 => 2_usize,
        _ => 8_usize,
    };
    push_n(mem, regs, val, size)
}

fn exec_pop(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let size = match instr.op0_kind() {
        OpKind::Register if instr.op_register(0).size() == 2 => 2_usize,
        _ => 8_usize,
    };
    let val = pop_n(mem, regs, size)?;
    write_op(mem, regs, instr, 0, val)
}

fn exec_arith(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    op: ArithOp,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let dst = read_op(mem, regs, instr, 0)?;
    let src = read_op(mem, regs, instr, 1)?;
    let mask = regs::size_mask(size);
    let d = dst & mask;
    let s = src & mask;
    let cf = u64::from(regs.flag(rflags::CF));
    let result = match op {
        ArithOp::Add => d.wrapping_add(s),
        ArithOp::Adc => d.wrapping_add(s).wrapping_add(cf),
        ArithOp::Sub | ArithOp::Cmp => d.wrapping_sub(s),
        ArithOp::Sbb => d.wrapping_sub(s).wrapping_sub(cf),
        ArithOp::Xor => d ^ s,
        ArithOp::Or => d | s,
        ArithOp::And => d & s,
    };
    match op {
        ArithOp::Add => {
            regs::set_add_flags(regs, d, s, result, size);
            write_op(mem, regs, instr, 0, result & mask)?;
        }
        ArithOp::Adc => {
            // Flags from full add with carry-in.
            let wide = u128::from(d)
                .wrapping_add(u128::from(s))
                .wrapping_add(u128::from(cf));
            regs::set_add_flags(regs, d, s.wrapping_add(cf), result, size);
            regs.set_flag(rflags::CF, wide > u128::from(mask));
            write_op(mem, regs, instr, 0, result & mask)?;
        }
        ArithOp::Sub => {
            regs::set_sub_flags(regs, d, s, result, size);
            write_op(mem, regs, instr, 0, result & mask)?;
        }
        ArithOp::Sbb => {
            let borrow = s.wrapping_add(cf);
            regs::set_sub_flags(regs, d, borrow, result, size);
            write_op(mem, regs, instr, 0, result & mask)?;
        }
        ArithOp::Cmp => {
            regs::set_sub_flags(regs, d, s, result, size);
        }
        ArithOp::Xor | ArithOp::Or | ArithOp::And => {
            regs::set_logic_flags(regs, result, size);
            write_op(mem, regs, instr, 0, result & mask)?;
        }
    }
    Ok(())
}

fn exec_imul(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    // Forms: 1-op (RAX/RDX), 2-op (dst *= src), 3-op (dst = src1 * imm).
    let nops = instr.op_count();
    match nops {
        1 => {
            let size = op_size_bytes(instr, 0)?;
            let src = read_op(mem, regs, instr, 0)? & regs::size_mask(size);
            let a = regs.rax() & regs::size_mask(size);
            let product = i128::from(sign_extend(a, size)) * i128::from(sign_extend(src, size));
            write_imul_product(regs, product, size)?;
            Ok(())
        }
        2 => {
            let size = op_size_bytes(instr, 0)?;
            let dst = read_op(mem, regs, instr, 0)? & regs::size_mask(size);
            let src = read_op(mem, regs, instr, 1)? & regs::size_mask(size);
            let product = i128::from(sign_extend(dst, size)) * i128::from(sign_extend(src, size));
            let lo = (product as u64) & regs::size_mask(size);
            write_op(mem, regs, instr, 0, lo)?;
            set_imul_flags(regs, product, size);
            Ok(())
        }
        3 => {
            let size = op_size_bytes(instr, 0)?;
            let src = read_op(mem, regs, instr, 1)? & regs::size_mask(size);
            let imm = read_op(mem, regs, instr, 2)? & regs::size_mask(size);
            let product = i128::from(sign_extend(src, size)) * i128::from(sign_extend(imm, size));
            let lo = (product as u64) & regs::size_mask(size);
            write_op(mem, regs, instr, 0, lo)?;
            set_imul_flags(regs, product, size);
            Ok(())
        }
        _ => Err(StepExecError::Cpu(CpuError::Message(format!(
            "imul with {nops} operands"
        )))),
    }
}

fn exec_mul(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let src = read_op(mem, regs, instr, 0)? & regs::size_mask(size);
    let a = regs.rax() & regs::size_mask(size);
    let product = u128::from(a).wrapping_mul(u128::from(src));
    match size {
        1 => {
            regs.write_reg(Register::AX, product as u64 & 0xffff)?;
            let hi = (product >> 8) != 0;
            regs.set_flag(rflags::CF, hi);
            regs.set_flag(rflags::OF, hi);
        }
        2 => {
            regs.write_reg(Register::AX, product as u64 & 0xffff)?;
            regs.write_reg(Register::DX, ((product >> 16) as u64) & 0xffff)?;
            let hi = (product >> 16) != 0;
            regs.set_flag(rflags::CF, hi);
            regs.set_flag(rflags::OF, hi);
        }
        4 => {
            regs.write_reg(Register::EAX, product as u64 & 0xffff_ffff)?;
            regs.write_reg(Register::EDX, ((product >> 32) as u64) & 0xffff_ffff)?;
            let hi = (product >> 32) != 0;
            regs.set_flag(rflags::CF, hi);
            regs.set_flag(rflags::OF, hi);
        }
        _ => {
            regs.set_rax(product as u64);
            regs.set_rdx((product >> 64) as u64);
            let hi = (product >> 64) != 0;
            regs.set_flag(rflags::CF, hi);
            regs.set_flag(rflags::OF, hi);
        }
    }
    Ok(())
}

fn write_imul_product(regs: &mut RegFile, product: i128, size: usize) -> Result<(), StepExecError> {
    match size {
        1 => {
            regs.write_reg(Register::AX, product as u64 & 0xffff)?;
        }
        2 => {
            regs.write_reg(Register::AX, product as u64 & 0xffff)?;
            regs.write_reg(Register::DX, ((product >> 16) as u64) & 0xffff)?;
        }
        4 => {
            regs.write_reg(Register::EAX, product as u64 & 0xffff_ffff)?;
            regs.write_reg(Register::EDX, ((product >> 32) as u64) & 0xffff_ffff)?;
        }
        _ => {
            regs.set_rax(product as u64);
            regs.set_rdx((product >> 64) as u64);
        }
    }
    set_imul_flags(regs, product, size);
    Ok(())
}

fn set_imul_flags(regs: &mut RegFile, product: i128, size: usize) {
    // CF/OF set if high half is not sign-extension of low half.
    let bits = size.saturating_mul(8);
    let lo_bits = bits.min(64);
    let lo = product as u64 & if lo_bits >= 64 {
        u64::MAX
    } else {
        (1_u64 << lo_bits).wrapping_sub(1)
    };
    let sign_ext = if (lo >> (lo_bits.saturating_sub(1))) & 1 == 1 {
        // negative: high should be all ones for width
        match size {
            1 => i128::from(lo as i8),
            2 => i128::from(lo as i16),
            4 => i128::from(lo as i32),
            _ => i128::from(lo as i64),
        }
    } else {
        i128::from(lo)
    };
    // For 1-op IMUL the full product width is 2*size; for 2/3-op only low size is stored.
    // CF/OF = product does not fit in size bytes as signed.
    let max = match size {
        1 => i128::from(i8::MAX),
        2 => i128::from(i16::MAX),
        4 => i128::from(i32::MAX),
        _ => i128::from(i64::MAX),
    };
    let min = match size {
        1 => i128::from(i8::MIN),
        2 => i128::from(i16::MIN),
        4 => i128::from(i32::MIN),
        _ => i128::from(i64::MIN),
    };
    let overflow = product < min || product > max;
    let _ = sign_ext;
    regs.set_flag(rflags::CF, overflow);
    regs.set_flag(rflags::OF, overflow);
}

fn sign_extend(value: u64, size: usize) -> i64 {
    let bits = size.saturating_mul(8).min(64);
    let shift = 64_u32.saturating_sub(u32::try_from(bits).unwrap_or(64));
    ((value as i64) << shift) >> shift
}

fn exec_div(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    signed: bool,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let divisor = read_op(mem, regs, instr, 0)? & regs::size_mask(size);
    if divisor == 0 {
        return Err(StepExecError::Cpu(CpuError::Message(format!(
            "{} by zero at {:#x}",
            if signed { "idiv" } else { "div" },
            instr.ip()
        ))));
    }

    match size {
        1 => {
            let dividend = regs.read_reg(Register::AX)? & 0xffff;
            if signed {
                let num = dividend as i16;
                let den = sign_extend(divisor, 1) as i16;
                let q = num.checked_div(den).ok_or_else(|| {
                    StepExecError::Cpu(CpuError::Message("idiv overflow".into()))
                })?;
                let r = num.wrapping_rem(den);
                let ax = u64::from(u16::from(r as u8) << 8 | u16::from(q as u8));
                regs.write_reg(Register::AX, ax)?;
            } else {
                let q = dividend / divisor;
                let r = dividend % divisor;
                if q > 0xff {
                    return Err(StepExecError::Cpu(CpuError::Message(
                        "div overflow".into(),
                    )));
                }
                regs.write_reg(Register::AX, (r & 0xff) << 8 | (q & 0xff))?;
            }
        }
        2 => {
            let lo = regs.read_reg(Register::AX)? & 0xffff;
            let hi = regs.read_reg(Register::DX)? & 0xffff;
            if signed {
                // DX:AX as i32
                let num = (i32::from(hi as i16) << 16) | i32::from(lo as u16);
                let den = sign_extend(divisor, 2) as i32;
                let q = num.checked_div(den).ok_or_else(|| {
                    StepExecError::Cpu(CpuError::Message("idiv overflow".into()))
                })?;
                let r = num.wrapping_rem(den);
                if !(-32768..=32767).contains(&q) {
                    return Err(StepExecError::Cpu(CpuError::Message(
                        "idiv overflow".into(),
                    )));
                }
                regs.write_reg(Register::AX, q as u64 & 0xffff)?;
                regs.write_reg(Register::DX, r as u64 & 0xffff)?;
            } else {
                let dividend = (hi << 16) | lo;
                let q = dividend / divisor;
                let r = dividend % divisor;
                if q > 0xffff {
                    return Err(StepExecError::Cpu(CpuError::Message(
                        "div overflow".into(),
                    )));
                }
                regs.write_reg(Register::AX, q & 0xffff)?;
                regs.write_reg(Register::DX, r & 0xffff)?;
            }
        }
        4 => {
            let lo = regs.read_reg(Register::EAX)? & 0xffff_ffff;
            let hi = regs.read_reg(Register::EDX)? & 0xffff_ffff;
            if signed {
                let num = (i64::from(hi as i32) << 32) | i64::from(lo as u32);
                let den = sign_extend(divisor, 4);
                let q = num.checked_div(den).ok_or_else(|| {
                    StepExecError::Cpu(CpuError::Message("idiv overflow".into()))
                })?;
                let r = num.wrapping_rem(den);
                if !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&q) {
                    return Err(StepExecError::Cpu(CpuError::Message(
                        "idiv overflow".into(),
                    )));
                }
                regs.write_reg(Register::EAX, q as u64 & 0xffff_ffff)?;
                regs.write_reg(Register::EDX, r as u64 & 0xffff_ffff)?;
            } else {
                let dividend = (u128::from(hi) << 32) | u128::from(lo);
                let q = dividend / u128::from(divisor);
                let r = dividend % u128::from(divisor);
                if q > u128::from(u32::MAX) {
                    return Err(StepExecError::Cpu(CpuError::Message(
                        "div overflow".into(),
                    )));
                }
                regs.write_reg(Register::EAX, q as u64 & 0xffff_ffff)?;
                regs.write_reg(Register::EDX, r as u64 & 0xffff_ffff)?;
            }
        }
        _ => {
            let lo = regs.rax();
            let hi = regs.rdx();
            if signed {
                let num = (i128::from(hi as i64) << 64) | i128::from(lo);
                let den = i128::from(sign_extend(divisor, 8));
                let q = num.checked_div(den).ok_or_else(|| {
                    StepExecError::Cpu(CpuError::Message("idiv overflow".into()))
                })?;
                let r = num.wrapping_rem(den);
                if q < i128::from(i64::MIN) || q > i128::from(i64::MAX) {
                    return Err(StepExecError::Cpu(CpuError::Message(
                        "idiv overflow".into(),
                    )));
                }
                regs.set_rax(q as u64);
                regs.set_rdx(r as u64);
            } else {
                let dividend = (u128::from(hi) << 64) | u128::from(lo);
                let q = dividend / u128::from(divisor);
                let r = dividend % u128::from(divisor);
                if q > u128::from(u64::MAX) {
                    return Err(StepExecError::Cpu(CpuError::Message(
                        "div overflow".into(),
                    )));
                }
                regs.set_rax(q as u64);
                regs.set_rdx(r as u64);
            }
        }
    }
    Ok(())
}

fn exec_cmov(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    taken: bool,
) -> Result<(), StepExecError> {
    if taken {
        let src = read_op(mem, regs, instr, 1)?;
        write_op(mem, regs, instr, 0, src)?;
    }
    Ok(())
}

fn exec_setcc(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    taken: bool,
) -> Result<(), StepExecError> {
    write_op(mem, regs, instr, 0, u64::from(taken))?;
    Ok(())
}

fn exec_bswap(regs: &mut RegFile, instr: &Instruction) -> Result<(), StepExecError> {
    let reg = instr.op_register(0);
    let v = regs.read_reg(reg)?;
    let size = reg.size();
    let swapped = match size {
        4 => u64::from((v as u32).swap_bytes()),
        8 => v.swap_bytes(),
        _ => {
            return Err(StepExecError::Cpu(CpuError::Message(format!(
                "bswap size {size}"
            ))));
        }
    };
    regs.write_reg(reg, swapped)?;
    Ok(())
}

fn exec_bit(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    op: BitOp,
) -> Result<(), StepExecError> {
    let bit_offset = read_op(mem, regs, instr, 1)?;
    match instr.op0_kind() {
        OpKind::Register => {
            let size = instr.op_register(0).size();
            let bits = size.saturating_mul(8);
            let idx = (bit_offset as u32) % u32::try_from(bits).unwrap_or(64);
            let val = read_op(mem, regs, instr, 0)? & regs::size_mask(size);
            let mask = 1_u64 << idx;
            let cf = (val & mask) != 0;
            regs.set_flag(rflags::CF, cf);
            let new = match op {
                BitOp::Bt => val,
                BitOp::Bts => val | mask,
                BitOp::Btr => val & !mask,
                BitOp::Btc => val ^ mask,
            };
            if !matches!(op, BitOp::Bt) {
                write_op(mem, regs, instr, 0, new)?;
            }
        }
        OpKind::Memory => {
            // Memory bit string: EA + signed(offset)/8, bit = offset & 7.
            let base = effective_address(regs, instr)?;
            let off = bit_offset as i64;
            let byte_delta = off.div_euclid(8);
            let bit = u32::try_from(off.rem_euclid(8)).unwrap_or(0);
            let addr = base.wrapping_add(byte_delta as u64);
            let mut b = [0_u8; 1];
            match mem.read(addr, &mut b) {
                Ok(()) => {}
                Err(e) => {
                    drop(e);
                    return Err(StepExecError::InvalidMemory(InvalidMem {
                        access_type: ACCESS_READ,
                        address: addr,
                        size: 1,
                        value: 0,
                    }));
                }
            }
            let val = u64::from(b[0]);
            let mask = 1_u64 << bit;
            let cf = (val & mask) != 0;
            regs.set_flag(rflags::CF, cf);
            if !matches!(op, BitOp::Bt) {
                let new = match op {
                    BitOp::Bt => val,
                    BitOp::Bts => val | mask,
                    BitOp::Btr => val & !mask,
                    BitOp::Btc => val ^ mask,
                };
                write_mem_value(mem, addr, new, 1)?;
            }
        }
        other => {
            return Err(StepExecError::Cpu(CpuError::Message(format!(
                "bt op0 kind {other:?}"
            ))));
        }
    }
    Ok(())
}

fn is_sse_movsd(instr: &Instruction) -> bool {
    instr.op0_register().is_xmm()
        || instr.op1_register().is_xmm()
        || matches!(
            instr.code(),
            iced_x86::Code::Movsd_xmm_xmmm64 | iced_x86::Code::Movsd_xmmm64_xmm
        )
}

fn exec_sse_mov(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    nbytes: usize,
    scalar_merge: bool,
) -> Result<(), StepExecError> {
    let val = read_sse_op(mem, regs, instr, 1, nbytes)?;
    write_sse_op(mem, regs, instr, 0, val, nbytes, scalar_merge)
}

fn exec_sse_xor(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let a = read_sse_op(mem, regs, instr, 0, 16)?;
    let b = read_sse_op(mem, regs, instr, 1, 16)?;
    write_sse_op(mem, regs, instr, 0, a ^ b, 16, false)
}

fn exec_sse_movq(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    // movq xmm/m64, xmm/m64 or gpr forms — handle xmm/mem 64-bit.
    if instr.op0_register().is_xmm() || instr.op1_register().is_xmm() {
        return exec_sse_mov(mem, regs, instr, 8, true);
    }
    // GPR form: movq r64, r/m64 is just mov — rare encoding path.
    let v = read_op(mem, regs, instr, 1)?;
    write_op(mem, regs, instr, 0, v)
}

fn exec_sse_movd(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    if instr.op0_register().is_xmm() {
        let v = if instr.op1_kind() == OpKind::Memory {
            read_mem_value(mem, effective_address(regs, instr)?, 4)?
        } else {
            regs.read_reg(instr.op_register(1))? & 0xffff_ffff
        };
        // Zero-extend into XMM.
        regs.write_xmm(instr.op_register(0), u128::from(v as u32))?;
        return Ok(());
    }
    if instr.op1_register().is_xmm() {
        let v = regs.read_xmm(instr.op_register(1))? as u64 & 0xffff_ffff;
        if instr.op0_kind() == OpKind::Memory {
            write_mem_value(mem, effective_address(regs, instr)?, v, 4)?;
        } else {
            regs.write_reg(instr.op_register(0), v)?;
        }
        return Ok(());
    }
    Err(StepExecError::Cpu(CpuError::Message(
        "movd without xmm".into(),
    )))
}

fn read_sse_op(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    op: u32,
    nbytes: usize,
) -> Result<u128, StepExecError> {
    match instr.op_kind(op) {
        OpKind::Register if instr.op_register(op).is_xmm() => {
            let v = regs.read_xmm(instr.op_register(op))?;
            let mask = if nbytes >= 16 {
                u128::MAX
            } else {
                (1u128 << (nbytes.saturating_mul(8))) - 1
            };
            Ok(v & mask)
        }
        OpKind::Memory => {
            let addr = effective_address(regs, instr)?;
            let mut buf = [0_u8; 16];
            let slice = buf.get_mut(..nbytes).ok_or_else(|| {
                StepExecError::Cpu(CpuError::Message("sse read size".into()))
            })?;
            if let Err(e) = mem.read(addr, slice) {
                drop(e);
                return Err(StepExecError::InvalidMemory(InvalidMem {
                    access_type: ACCESS_READ,
                    address: addr,
                    size: i32::try_from(nbytes).unwrap_or(0),
                    value: 0,
                }));
            }
            let mut v = 0_u128;
            for (i, b) in slice.iter().enumerate() {
                v |= u128::from(*b) << (i.saturating_mul(8));
            }
            Ok(v)
        }
        OpKind::Register => {
            // GPR source for movd/movq-like
            Ok(u128::from(regs.read_reg(instr.op_register(op))?))
        }
        other => Err(StepExecError::Cpu(CpuError::Message(format!(
            "sse read op kind {other:?}"
        )))),
    }
}

fn write_sse_op(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    op: u32,
    value: u128,
    nbytes: usize,
    scalar_merge: bool,
) -> Result<(), StepExecError> {
    match instr.op_kind(op) {
        OpKind::Register if instr.op_register(op).is_xmm() => {
            let reg = instr.op_register(op);
            let new = if scalar_merge && nbytes < 16 {
                let old = regs.read_xmm(reg)?;
                let mask = (1u128 << (nbytes.saturating_mul(8))) - 1;
                (old & !mask) | (value & mask)
            } else if nbytes >= 16 {
                value
            } else {
                // Zero upper bits for full vector store of partial (non-merge).
                value & ((1u128 << (nbytes.saturating_mul(8))) - 1)
            };
            // For movsd/movss scalar to xmm: merge low bits, keep upper (SSE legacy).
            // For movaps full: replace all.
            let final_v = if scalar_merge {
                new
            } else if nbytes < 16 {
                value & ((1u128 << (nbytes.saturating_mul(8))) - 1)
            } else {
                value
            };
            regs.write_xmm(reg, final_v)?;
            Ok(())
        }
        OpKind::Memory => {
            let addr = effective_address(regs, instr)?;
            let mut buf = [0_u8; 16];
            for i in 0..nbytes {
                if let Some(b) = buf.get_mut(i) {
                    *b = ((value >> (i.saturating_mul(8))) & 0xff) as u8;
                }
            }
            let slice = buf.get(..nbytes).ok_or_else(|| {
                StepExecError::Cpu(CpuError::Message("sse write size".into()))
            })?;
            if let Err(e) = mem.write(addr, slice) {
                drop(e);
                return Err(StepExecError::InvalidMemory(InvalidMem {
                    access_type: ACCESS_WRITE,
                    address: addr,
                    size: i32::try_from(nbytes).unwrap_or(0),
                    value: 0,
                }));
            }
            Ok(())
        }
        other => Err(StepExecError::Cpu(CpuError::Message(format!(
            "sse write op kind {other:?}"
        )))),
    }
}

/// REP / REPE / REPNE present (F2/F3 string prefixes).
fn has_any_rep(instr: &Instruction) -> bool {
    instr.has_rep_prefix() || instr.has_repe_prefix() || instr.has_repne_prefix()
}

fn df_step(regs: &RegFile, size: usize) -> i64 {
    let s = i64::try_from(size).unwrap_or(1);
    if regs.flag(rflags::DF) {
        -s
    } else {
        s
    }
}

/// Keep RIP on a REP-prefixed string insn (Unicorn `count=1` micro-step).
///
/// Unicorn/QEMU semantics observed for `emu_start(..., count=1)`:
/// - One string iteration per counted step.
/// - After a **productive** iteration, RIP stays on the insn unless REPE/REPNE
///   stops early via ZF (then RIP advances).
/// - RCX exhausting to 0 does **not** advance RIP; the next step is a RCX=0
///   no-op that finally falls through.
/// - Entering with RCX=0 is a pure no-op that advances RIP (handled by callers
///   returning with the fall-through RIP already set in `execute_one`).
fn string_rep_stay(regs: &mut RegFile, instr: &Instruction) {
    if has_any_rep(instr) {
        regs.rip = instr.ip();
    }
}

fn exec_stos(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    size: usize,
) -> Result<(), StepExecError> {
    // REP MOVS/STOS/LODS: F3 may surface as has_rep and/or has_repe in iced.
    let rep = has_any_rep(instr);
    if rep && regs.rcx() == 0 {
        return Ok(());
    }
    let step = df_step(regs, size);
    let val = regs.rax() & regs::size_mask(size);
    let rdi = regs.rdi();
    write_mem_value(mem, rdi, val, size)?;
    regs.set_rdi(rdi.wrapping_add(step as u64));
    if rep {
        regs.set_rcx(regs.rcx().wrapping_sub(1));
        // Always stay after a productive REP STOS/MOVS/LODS iteration.
        string_rep_stay(regs, instr);
    }
    Ok(())
}

fn exec_movs(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    size: usize,
) -> Result<(), StepExecError> {
    let rep = has_any_rep(instr);
    if rep && regs.rcx() == 0 {
        return Ok(());
    }
    let step = df_step(regs, size);
    let rsi = regs.rsi();
    let rdi = regs.rdi();
    let v = read_mem_value(mem, rsi, size)?;
    write_mem_value(mem, rdi, v, size)?;
    regs.set_rsi(rsi.wrapping_add(step as u64));
    regs.set_rdi(rdi.wrapping_add(step as u64));
    if rep {
        regs.set_rcx(regs.rcx().wrapping_sub(1));
        string_rep_stay(regs, instr);
    }
    Ok(())
}

fn exec_lods(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    size: usize,
) -> Result<(), StepExecError> {
    let rep = has_any_rep(instr);
    if rep && regs.rcx() == 0 {
        return Ok(());
    }
    let step = df_step(regs, size);
    let rsi = regs.rsi();
    let v = read_mem_value(mem, rsi, size)?;
    match size {
        1 => regs.write_reg(Register::AL, v)?,
        4 => regs.write_reg(Register::EAX, v)?,
        _ => regs.set_rax(v),
    }
    regs.set_rsi(rsi.wrapping_add(step as u64));
    if rep {
        regs.set_rcx(regs.rcx().wrapping_sub(1));
        string_rep_stay(regs, instr);
    }
    Ok(())
}

fn exec_scas(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    size: usize,
) -> Result<(), StepExecError> {
    let rep = has_any_rep(instr);
    if rep && regs.rcx() == 0 {
        return Ok(());
    }
    let step = df_step(regs, size);
    let acc = regs.rax() & regs::size_mask(size);
    let rdi = regs.rdi();
    let v = read_mem_value(mem, rdi, size)? & regs::size_mask(size);
    let result = acc.wrapping_sub(v);
    regs::set_sub_flags(regs, acc, v, result, size);
    regs.set_rdi(rdi.wrapping_add(step as u64));
    if rep {
        regs.set_rcx(regs.rcx().wrapping_sub(1));
        let zf = regs.flag(rflags::ZF);
        // REPE/REPZ: stop when ZF=0 (mismatch). REPNE/REPNZ: stop when ZF=1 (match).
        let zf_stop = (instr.has_repe_prefix() && !zf) || (instr.has_repne_prefix() && zf);
        // ZF early-exit advances RIP; RCX exhaust stays for a follow-up no-op step.
        if !zf_stop {
            string_rep_stay(regs, instr);
        }
    }
    Ok(())
}

fn exec_cmps(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    size: usize,
) -> Result<(), StepExecError> {
    let rep = has_any_rep(instr);
    if rep && regs.rcx() == 0 {
        return Ok(());
    }
    let step = df_step(regs, size);
    let rsi = regs.rsi();
    let rdi = regs.rdi();
    let a = read_mem_value(mem, rsi, size)? & regs::size_mask(size);
    let b = read_mem_value(mem, rdi, size)? & regs::size_mask(size);
    let result = a.wrapping_sub(b);
    regs::set_sub_flags(regs, a, b, result, size);
    regs.set_rsi(rsi.wrapping_add(step as u64));
    regs.set_rdi(rdi.wrapping_add(step as u64));
    if rep {
        regs.set_rcx(regs.rcx().wrapping_sub(1));
        let zf = regs.flag(rflags::ZF);
        let zf_stop = (instr.has_repe_prefix() && !zf) || (instr.has_repne_prefix() && zf);
        if !zf_stop {
            string_rep_stay(regs, instr);
        }
    }
    Ok(())
}

fn exec_test(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let a = read_op(mem, regs, instr, 0)?;
    let b = read_op(mem, regs, instr, 1)?;
    let result = (a & b) & regs::size_mask(size);
    regs::set_logic_flags(regs, result, size);
    Ok(())
}

fn exec_inc_dec(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    inc: bool,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let dst = read_op(mem, regs, instr, 0)? & regs::size_mask(size);
    let src = 1_u64;
    let result = if inc {
        dst.wrapping_add(src)
    } else {
        dst.wrapping_sub(src)
    };
    let cf = regs.flag(rflags::CF); // INC/DEC do not modify CF
    if inc {
        regs::set_add_flags(regs, dst, src, result, size);
    } else {
        regs::set_sub_flags(regs, dst, src, result, size);
    }
    regs.set_flag(rflags::CF, cf);
    write_op(mem, regs, instr, 0, result & regs::size_mask(size))?;
    Ok(())
}

fn exec_neg(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let dst = read_op(mem, regs, instr, 0)? & regs::size_mask(size);
    let result = 0_u64.wrapping_sub(dst);
    regs::set_sub_flags(regs, 0, dst, result, size);
    // NEG sets CF if operand was non-zero.
    regs.set_flag(rflags::CF, dst != 0);
    write_op(mem, regs, instr, 0, result & regs::size_mask(size))?;
    Ok(())
}

fn exec_not(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let dst = read_op(mem, regs, instr, 0)? & regs::size_mask(size);
    let result = !dst;
    write_op(mem, regs, instr, 0, result & regs::size_mask(size))?;
    Ok(())
}

fn exec_shift(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    kind: ShiftKind,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let bits = size.saturating_mul(8);
    let mask = regs::size_mask(size);
    let dst = read_op(mem, regs, instr, 0)? & mask;
    let count_raw = read_op(mem, regs, instr, 1)? as u32;
    // 64-bit mode: count masked with 0x3F; rotate width further reduces.
    let count_masked = count_raw & 0x3f;
    let width = u32::try_from(bits).unwrap_or(64);
    let count_mod = if width == 64 {
        count_masked
    } else if width == 0 {
        0
    } else {
        count_masked % width
    };
    if count_mod == 0 {
        return Ok(());
    }
    let count_usize = count_mod as usize;
    let (result, cf) = match kind {
        ShiftKind::Shl => {
            let cf_bit = if count_usize <= bits {
                ((dst << (count_usize.saturating_sub(1))) >> bits.saturating_sub(1)) & 1
            } else {
                0
            };
            ((dst << count_mod) & mask, cf_bit != 0)
        }
        ShiftKind::Shr => {
            let cf_bit = (dst >> count_mod.saturating_sub(1)) & 1;
            ((dst >> count_mod) & mask, cf_bit != 0)
        }
        ShiftKind::Sar => {
            let sign_bits = 64_u32.saturating_sub(u32::try_from(bits).unwrap_or(64));
            let signed = ((dst as i64) << sign_bits) >> sign_bits;
            let cf_bit = ((signed as u64) >> count_mod.saturating_sub(1)) & 1;
            let r = ((signed >> count_mod) as u64) & mask;
            (r, cf_bit != 0)
        }
        ShiftKind::Rol => {
            let r = ((dst << count_mod) | (dst >> bits.saturating_sub(count_usize))) & mask;
            let cf_bit = r & 1;
            (r, cf_bit != 0)
        }
        ShiftKind::Ror => {
            let r = ((dst >> count_mod) | (dst << bits.saturating_sub(count_usize))) & mask;
            let cf_bit = (r >> bits.saturating_sub(1)) & 1;
            (r, cf_bit != 0)
        }
    };
    regs.set_flag(rflags::CF, cf);
    // ROL/ROR do not update ZF/SF/PF; SHL/SHR/SAR do.
    if matches!(kind, ShiftKind::Shl | ShiftKind::Shr | ShiftKind::Sar) {
        regs.set_flag(rflags::ZF, result == 0);
        let sign = 1_u64 << bits.saturating_sub(1);
        regs.set_flag(rflags::SF, (result & sign) != 0);
        regs.set_flag(
            rflags::PF,
            (result as u8).count_ones().is_multiple_of(2),
        );
    }
    if count_mod == 1 {
        let sign = 1_u64 << bits.saturating_sub(1);
        let of = match kind {
            ShiftKind::Shl => ((result ^ dst) & sign) != 0,
            ShiftKind::Shr => (dst & sign) != 0,
            ShiftKind::Sar => false,
            ShiftKind::Rol => ((result >> bits.saturating_sub(1)) ^ (result & 1)) != 0,
            ShiftKind::Ror => {
                let b1 = (result >> bits.saturating_sub(1)) & 1;
                let b2 = (result >> bits.saturating_sub(2)) & 1;
                b1 != b2
            }
        };
        regs.set_flag(rflags::OF, of);
    }
    write_op(mem, regs, instr, 0, result)?;
    Ok(())
}

fn exec_jmp(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let target = branch_target(mem, regs, instr)?;
    regs.rip = target;
    Ok(())
}

fn exec_jcc(regs: &mut RegFile, instr: &Instruction, taken: bool) {
    if taken {
        regs.rip = instr.near_branch_target();
    }
}

fn exec_call(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    return_ip: u64,
) -> Result<(), StepExecError> {
    // EA for `call [rsp+…]` must use RSP *before* the return-address push
    // (Intel SDM / Unicorn). Pushing first made us read [rsp+disp-8].
    let target = branch_target(mem, regs, instr)?;
    push_n(mem, regs, return_ip, 8)?;
    regs.rip = target;
    Ok(())
}

fn exec_ret(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let ret = pop_n(mem, regs, 8)?;
    // ret imm16: pop then add imm to RSP
    if instr.op_count() >= 1 && instr.op0_kind() == OpKind::Immediate16 {
        let imm = instr.immediate(0);
        regs.set_rsp(regs.rsp().wrapping_add(imm));
    }
    regs.rip = ret;
    Ok(())
}

fn exec_xchg(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let a = read_op(mem, regs, instr, 0)?;
    let b = read_op(mem, regs, instr, 1)?;
    write_op(mem, regs, instr, 0, b)?;
    write_op(mem, regs, instr, 1, a)?;
    Ok(())
}

/// `CMPXCHG r/m, r` — compare ACC with dest; if equal write src→dest and ZF=1, else dest→ACC and ZF=0.
///
/// Flags follow a CMP of ACC vs dest (same width). `LOCK` is ignored (single-threaded guest).
fn exec_cmpxchg(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, 0)?;
    let mask = regs::size_mask(size);
    let dest = read_op(mem, regs, instr, 0)? & mask;
    let src = read_op(mem, regs, instr, 1)? & mask;
    let acc = accumulator_value(regs, size)? & mask;

    // Flags as if CMP ACC, dest.
    let result = acc.wrapping_sub(dest);
    regs::set_sub_flags(regs, acc, dest, result, size);

    if regs.flag(rflags::ZF) {
        write_op(mem, regs, instr, 0, src)?;
    } else {
        write_accumulator(regs, size, dest)?;
    }
    Ok(())
}

fn accumulator_value(regs: &RegFile, size: usize) -> Result<u64, StepExecError> {
    match size {
        1 => Ok(regs.read_reg(Register::AL)?),
        2 => Ok(regs.read_reg(Register::AX)?),
        4 => Ok(regs.read_reg(Register::EAX)?),
        _ => Ok(regs.rax()),
    }
}

fn write_accumulator(regs: &mut RegFile, size: usize, value: u64) -> Result<(), StepExecError> {
    match size {
        1 => Ok(regs.write_reg(Register::AL, value)?),
        2 => Ok(regs.write_reg(Register::AX, value)?),
        4 => Ok(regs.write_reg(Register::EAX, value)?),
        _ => {
            regs.set_rax(value);
            Ok(())
        }
    }
}

fn branch_target(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
) -> Result<u64, StepExecError> {
    match instr.op0_kind() {
        OpKind::NearBranch64 | OpKind::NearBranch32 | OpKind::NearBranch16 => {
            Ok(instr.near_branch_target())
        }
        OpKind::Register => Ok(regs.read_reg(instr.op_register(0))?),
        OpKind::Memory => read_op(mem, regs, instr, 0),
        other => Err(StepExecError::Cpu(CpuError::Message(format!(
            "unsupported branch op kind {other:?}"
        )))),
    }
}

fn push_n(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    value: u64,
    size: usize,
) -> Result<(), StepExecError> {
    let new_rsp = regs.rsp().wrapping_sub(u64::try_from(size).unwrap_or(8));
    write_mem_value(mem, new_rsp, value, size)?;
    regs.set_rsp(new_rsp);
    Ok(())
}

fn pop_n(mem: &mut GuestMemory, regs: &mut RegFile, size: usize) -> Result<u64, StepExecError> {
    let rsp = regs.rsp();
    let val = read_mem_value(mem, rsp, size)?;
    regs.set_rsp(rsp.wrapping_add(u64::try_from(size).unwrap_or(8)));
    Ok(val)
}

fn pop64(mem: &mut GuestMemory, regs: &mut RegFile) -> Result<u64, StepExecError> {
    pop_n(mem, regs, 8)
}

fn read_op(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    op: u32,
) -> Result<u64, StepExecError> {
    match instr.op_kind(op) {
        OpKind::Register => Ok(regs.read_reg(instr.op_register(op))?),
        OpKind::Memory => {
            let addr = effective_address(regs, instr)?;
            let size = memory_op_size(instr)?;
            read_mem_value(mem, addr, size)
        }
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Ok(instr.immediate(op)),
        other => Err(StepExecError::Cpu(CpuError::Message(format!(
            "unsupported op kind {other:?} for read"
        )))),
    }
}

fn write_op(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    op: u32,
    value: u64,
) -> Result<(), StepExecError> {
    let size = op_size_bytes(instr, op)?;
    write_op_sized(mem, regs, instr, op, value, size)
}

fn write_op_sized(
    mem: &mut GuestMemory,
    regs: &mut RegFile,
    instr: &Instruction,
    op: u32,
    value: u64,
    size: usize,
) -> Result<(), StepExecError> {
    match instr.op_kind(op) {
        OpKind::Register => {
            let reg = instr.op_register(op);
            // write_reg applies 8/16 merge and 32-bit zero-extend from reg.size().
            let _ = size;
            regs.write_reg(reg, value)?;
            Ok(())
        }
        OpKind::Memory => {
            let addr = effective_address(regs, instr)?;
            write_mem_value(mem, addr, value, size)
        }
        other => Err(StepExecError::Cpu(CpuError::Message(format!(
            "unsupported op kind {other:?} for write"
        )))),
    }
}

fn op_size_bytes(instr: &Instruction, op: u32) -> Result<usize, StepExecError> {
    match instr.op_kind(op) {
        OpKind::Register => Ok(instr.op_register(op).size()),
        OpKind::Memory => memory_op_size(instr),
        OpKind::Immediate8 | OpKind::Immediate8_2nd => Ok(1),
        OpKind::Immediate16 | OpKind::Immediate8to16 => Ok(2),
        OpKind::Immediate32 | OpKind::Immediate8to32 => Ok(4),
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => Ok(8),
        other => Err(StepExecError::Cpu(CpuError::Message(format!(
            "cannot size op kind {other:?}"
        )))),
    }
}

fn memory_op_size(instr: &Instruction) -> Result<usize, StepExecError> {
    let sz = match instr.memory_size() {
        MemorySize::UInt8 | MemorySize::Int8 => 1,
        MemorySize::UInt16 | MemorySize::Int16 => 2,
        MemorySize::UInt32 | MemorySize::Int32 => 4,
        MemorySize::UInt64
        | MemorySize::Int64
        | MemorySize::QwordOffset
        | MemorySize::SegPtr64 => 8,
        other => {
            // Fallback: use size of the other operand if register.
            if instr.op_count() > 0 && instr.op0_kind() == OpKind::Register {
                return Ok(instr.op_register(0).size());
            }
            if instr.op_count() > 1 && instr.op1_kind() == OpKind::Register {
                return Ok(instr.op_register(1).size());
            }
            return Err(StepExecError::Cpu(CpuError::Message(format!(
                "unsupported memory size {other:?}"
            ))));
        }
    };
    Ok(sz)
}

fn effective_address(regs: &RegFile, instr: &Instruction) -> Result<u64, StepExecError> {
    // iced stores the absolute address for RIP/EIP-relative in memory_displacement64().
    // For other bases, displacement is a signed offset added to base+index*scale.
    let base = instr.memory_base();
    if base == Register::RIP || base == Register::EIP {
        return Ok(instr.memory_displacement64());
    }

    let mut addr = instr.memory_displacement64();
    // Non-IP-relative: treat displacement as signed when displ size is set.
    // iced keeps mem_displ as unsigned bits of the signed field; for pure disp
    // with base/index, virtual_address adds the raw mem_displ then masks.
    // Mirror iced's virtual_address path for 64-bit addressing:
    if base != Register::None {
        addr = addr.wrapping_add(regs.read_reg(base)?);
    }
    let index = instr.memory_index();
    if index != Register::None {
        let scale = u64::from(instr.memory_index_scale());
        let idx_val = regs.read_reg(index)?;
        addr = addr.wrapping_add(idx_val.wrapping_mul(scale));
    }
    Ok(addr)
}

fn read_mem_value(mem: &GuestMemory, addr: u64, size: usize) -> Result<u64, StepExecError> {
    if size == 0 || size > 8 {
        return Err(StepExecError::Cpu(CpuError::Message(format!(
            "bad mem read size {size}"
        ))));
    }
    let mut buf = [0_u8; 8];
    let slice = buf.get_mut(..size).ok_or_else(|| {
        StepExecError::Cpu(CpuError::Message("mem read buffer".into()))
    })?;
    if let Err(e) = mem.read(addr, slice) {
        drop(e);
        return Err(StepExecError::InvalidMemory(InvalidMem {
            access_type: ACCESS_READ,
            address: addr,
            size: i32::try_from(size).unwrap_or(0),
            value: 0,
        }));
    }
    Ok(match size {
        1 => u64::from(buf[0]),
        2 => u64::from(u16::from_le_bytes([buf[0], buf[1]])),
        4 => u64::from(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
        8 => u64::from_le_bytes(buf),
        _ => 0,
    })
}

fn write_mem_value(
    mem: &mut GuestMemory,
    addr: u64,
    value: u64,
    size: usize,
) -> Result<(), StepExecError> {
    if size == 0 || size > 8 {
        return Err(StepExecError::Cpu(CpuError::Message(format!(
            "bad mem write size {size}"
        ))));
    }
    let bytes = value.to_le_bytes();
    let slice = bytes.get(..size).ok_or_else(|| {
        StepExecError::Cpu(CpuError::Message("mem write buffer".into()))
    })?;
    if let Err(e) = mem.write(addr, slice) {
        drop(e);
        return Err(StepExecError::InvalidMemory(InvalidMem {
            access_type: ACCESS_WRITE,
            address: addr,
            size: i32::try_from(size).unwrap_or(0),
            value: i64::try_from(value).unwrap_or(0),
        }));
    }
    Ok(())
}
