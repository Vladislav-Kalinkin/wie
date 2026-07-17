//! x86-64 GPRs + RFLAGS for the iced interpreter.

#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation // GPR width narrowing (u64 → u8/u16/u32)
)]

use crate::CpuError;
use iced_x86::Register;

/// RFLAGS bit masks (subset used by the interpreter).
pub(crate) mod rflags {
    pub(crate) const CF: u64 = 1;
    pub(crate) const PF: u64 = 1 << 2;
    pub(crate) const AF: u64 = 1 << 4;
    pub(crate) const ZF: u64 = 1 << 6;
    pub(crate) const SF: u64 = 1 << 7;
    pub(crate) const IF: u64 = 1 << 9;
    pub(crate) const DF: u64 = 1 << 10;
    pub(crate) const OF: u64 = 1 << 11;
    /// Architectural reserved bit 1 is always 1.
    pub(crate) const ALWAYS1: u64 = 1 << 1;
    /// Default after reset / process start (IF + reserved bit 1).
    pub(crate) const DEFAULT: u64 = ALWAYS1 | IF;
}

/// General-purpose register file + XMM + RIP + RFLAGS (64-bit mode only).
#[derive(Debug, Clone)]
pub struct RegFile {
    /// RAX..R15 (index = `Register::RAX.number()` …).
    gpr: [u64; 16],
    /// XMM0..XMM15 as 128-bit values (low 64 used by scalar SSE2).
    xmm: [u128; 16],
    pub rip: u64,
    pub rflags: u64,
}

impl Default for RegFile {
    fn default() -> Self {
        Self {
            gpr: [0; 16],
            xmm: [0; 16],
            rip: 0,
            rflags: rflags::DEFAULT,
        }
    }
}

impl RegFile {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn gpr(&self, idx: usize) -> u64 {
        self.gpr.get(idx).copied().unwrap_or(0)
    }

    pub(crate) fn set_gpr(&mut self, idx: usize, value: u64) {
        if let Some(slot) = self.gpr.get_mut(idx) {
            *slot = value;
        }
    }

    #[must_use]
    pub fn rax(&self) -> u64 {
        self.gpr(0)
    }
    pub(crate) fn set_rax(&mut self, v: u64) {
        self.set_gpr(0, v);
    }
    #[must_use]
    pub fn rcx(&self) -> u64 {
        self.gpr(1)
    }
    pub(crate) fn set_rcx(&mut self, v: u64) {
        self.set_gpr(1, v);
    }
    #[must_use]
    pub fn rdx(&self) -> u64 {
        self.gpr(2)
    }
    pub(crate) fn set_rdx(&mut self, v: u64) {
        self.set_gpr(2, v);
    }
    #[must_use]
    pub fn rbx(&self) -> u64 {
        self.gpr(3)
    }
    #[must_use]
    pub fn rsp(&self) -> u64 {
        self.gpr(4)
    }
    pub(crate) fn set_rsp(&mut self, v: u64) {
        self.set_gpr(4, v);
    }
    #[must_use]
    pub fn rbp(&self) -> u64 {
        self.gpr(5)
    }
    pub(crate) fn set_rbp(&mut self, v: u64) {
        self.set_gpr(5, v);
    }
    #[must_use]
    pub fn rsi(&self) -> u64 {
        self.gpr(6)
    }
    pub(crate) fn set_rsi(&mut self, v: u64) {
        self.set_gpr(6, v);
    }
    #[must_use]
    pub fn rdi(&self) -> u64 {
        self.gpr(7)
    }
    pub(crate) fn set_rdi(&mut self, v: u64) {
        self.set_gpr(7, v);
    }
    #[must_use]
    pub fn r8(&self) -> u64 {
        self.gpr(8)
    }
    pub(crate) fn set_r8(&mut self, v: u64) {
        self.set_gpr(8, v);
    }
    #[must_use]
    pub fn r9(&self) -> u64 {
        self.gpr(9)
    }
    pub(crate) fn set_r9(&mut self, v: u64) {
        self.set_gpr(9, v);
    }

    /// Read a GPR / partial register (64-bit mode).
    pub fn read_reg(&self, reg: Register) -> Result<u64, CpuError> {
        if reg == Register::None {
            return Ok(0);
        }
        if reg == Register::RIP {
            return Ok(self.rip);
        }
        if matches!(
            reg,
            Register::AH | Register::CH | Register::DH | Register::BH
        ) {
            let full = reg.full_register();
            let idx = gpr_index(full)?;
            let full_val = self.gpr(idx);
            return Ok((full_val >> 8) & 0xff);
        }
        let size = reg.size();
        let full = reg.full_register();
        let idx = gpr_index(full)?;
        let full_val = self.gpr(idx);
        Ok(match size {
            1 => full_val & 0xff,
            2 => full_val & 0xffff,
            4 => full_val & 0xffff_ffff,
            8 => full_val,
            _ => {
                return Err(CpuError::Message(format!(
                    "unsupported register size {size} for {reg:?}"
                )));
            }
        })
    }

    /// Write a GPR / partial register. 32-bit writes zero-extend the full 64-bit register.
    pub fn write_reg(&mut self, reg: Register, value: u64) -> Result<(), CpuError> {
        if reg == Register::None {
            return Ok(());
        }
        if reg == Register::RIP {
            self.rip = value;
            return Ok(());
        }
        if matches!(
            reg,
            Register::AH | Register::CH | Register::DH | Register::BH
        ) {
            let full = reg.full_register();
            let idx = gpr_index(full)?;
            let old = self.gpr(idx);
            let new = (old & !0xff00) | ((value & 0xff) << 8);
            self.set_gpr(idx, new);
            return Ok(());
        }
        let size = reg.size();
        let full = reg.full_register();
        let idx = gpr_index(full)?;
        let old = self.gpr(idx);
        let new = match size {
            1 => (old & !0xff) | (value & 0xff),
            2 => (old & !0xffff) | (value & 0xffff),
            4 => value & 0xffff_ffff, // zero-extend to 64
            8 => value,
            _ => {
                return Err(CpuError::Message(format!(
                    "unsupported register size {size} for {reg:?}"
                )));
            }
        };
        self.set_gpr(idx, new);
        Ok(())
    }

    #[must_use]
    pub fn flag(&self, mask: u64) -> bool {
        (self.rflags & mask) != 0
    }

    /// Read XMM0–XMM15 (128-bit).
    pub fn read_xmm(&self, reg: Register) -> Result<u128, CpuError> {
        if !reg.is_xmm() {
            return Err(CpuError::Message(format!("not an XMM register: {reg:?}")));
        }
        let n = reg.number();
        self.xmm
            .get(n)
            .copied()
            .ok_or_else(|| CpuError::Message(format!("XMM index {n} OOB")))
    }

    /// Write XMM0–XMM15 (128-bit).
    pub fn write_xmm(&mut self, reg: Register, value: u128) -> Result<(), CpuError> {
        if !reg.is_xmm() {
            return Err(CpuError::Message(format!("not an XMM register: {reg:?}")));
        }
        let n = reg.number();
        let slot = self
            .xmm
            .get_mut(n)
            .ok_or_else(|| CpuError::Message(format!("XMM index {n} OOB")))?;
        *slot = value;
        Ok(())
    }

    /// Read XMM by index 0..15 (JIT snapshot).
    #[must_use]
    pub fn xmm_at(&self, idx: usize) -> u128 {
        self.xmm.get(idx).copied().unwrap_or(0)
    }

    /// Write XMM by index 0..15 (JIT write-back).
    pub fn set_xmm_at(&mut self, idx: usize, value: u128) {
        if let Some(slot) = self.xmm.get_mut(idx) {
            *slot = value;
        }
    }

    pub(crate) fn set_flag(&mut self, mask: u64, on: bool) {
        if on {
            self.rflags |= mask;
        } else {
            self.rflags &= !mask;
        }
        self.rflags |= rflags::ALWAYS1;
    }
}

fn gpr_index(full: Register) -> Result<usize, CpuError> {
    // RAX..R15 map to numbers 0..15.
    let n = full.number();
    if n < 16 && full.size() == 8 {
        Ok(n)
    } else {
        Err(CpuError::Message(format!(
            "not a 64-bit GPR: {full:?} (number={n})"
        )))
    }
}

/// Update ZF/SF/PF from a result of `size` bytes; leave CF/OF/AF to caller.
pub(crate) fn set_logic_flags(regs: &mut RegFile, result: u64, size: usize) {
    let mask = size_mask(size);
    let v = result & mask;
    regs.set_flag(rflags::ZF, v == 0);
    let sign_bit = 1_u64 << ((size.saturating_mul(8)).saturating_sub(1));
    regs.set_flag(rflags::SF, (v & sign_bit) != 0);
    regs.set_flag(rflags::PF, parity_even(v as u8));
    regs.set_flag(rflags::CF, false);
    regs.set_flag(rflags::OF, false);
    // AF undefined for logic; leave unchanged.
}

/// Update flags after ADD.
pub(crate) fn set_add_flags(regs: &mut RegFile, dst: u64, src: u64, result: u64, size: usize) {
    let mask = size_mask(size);
    let d = dst & mask;
    let s = src & mask;
    let r = result & mask;
    let bits = size.saturating_mul(8);
    let sign = 1_u64 << bits.saturating_sub(1);

    let wide = u128::from(d).wrapping_add(u128::from(s));
    regs.set_flag(rflags::CF, wide > u128::from(mask));
    regs.set_flag(rflags::ZF, r == 0);
    regs.set_flag(rflags::SF, (r & sign) != 0);
    regs.set_flag(rflags::PF, parity_even(r as u8));
    // OF: same sign operands, result different sign
    let of = ((d ^ r) & (s ^ r) & sign) != 0;
    regs.set_flag(rflags::OF, of);
    regs.set_flag(rflags::AF, ((d ^ s ^ r) & 0x10) != 0);
}

/// Update flags after SUB / CMP.
pub(crate) fn set_sub_flags(regs: &mut RegFile, dst: u64, src: u64, result: u64, size: usize) {
    let mask = size_mask(size);
    let d = dst & mask;
    let s = src & mask;
    let r = result & mask;
    let bits = size.saturating_mul(8);
    let sign = 1_u64 << bits.saturating_sub(1);

    regs.set_flag(rflags::CF, d < s);
    regs.set_flag(rflags::ZF, r == 0);
    regs.set_flag(rflags::SF, (r & sign) != 0);
    regs.set_flag(rflags::PF, parity_even(r as u8));
    // OF: different sign operands, result sign != dst sign
    let of = ((d ^ s) & (d ^ r) & sign) != 0;
    regs.set_flag(rflags::OF, of);
    regs.set_flag(rflags::AF, ((d ^ s ^ r) & 0x10) != 0);
}

#[must_use]
pub(crate) fn size_mask(size: usize) -> u64 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

#[must_use]
fn parity_even(byte: u8) -> bool {
    byte.count_ones().is_multiple_of(2)
}
