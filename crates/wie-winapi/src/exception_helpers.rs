//! Helpers for building SEH test fixtures without raw-byte manipulation.
//! Only compiled in test configurations.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    clippy::return_self_not_must_use,
    clippy::integer_division,
    clippy::trivially_copy_pass_by_ref
)]

use super::exception::{RuntimeFunction, UnwindCode, UnwindInfo, UnwindContext, uwop};

/// Builder for a single `RUNTIME_FUNCTION`.
pub fn runtime_function(begin: u32, end: u32, unwind: u32) -> RuntimeFunction {
    RuntimeFunction { begin_address: begin, end_address: end, unwind_data: unwind }
}

/// Register a function table in `SyncState` and return the image base.
pub fn register_table(state: &mut crate::sync_obj::SyncState, image_base: u64, entries: Vec<RuntimeFunction>) -> u64 {
    state.function_tables.insert(image_base, entries);
    image_base
}

// ── Unwind code builders ───────────────────────────────────────────────

/// `UWOP_PUSH_NONVOL(register)` — push a nonvolatile register.
pub fn push_nonvol(reg: u8) -> UnwindCode {
    UnwindCode { code_offset: 0, unwind_op: uwop::PUSH_NONVOL, op_info: reg }
}

/// `UWOP_ALLOC_SMALL(size_bytes)` — allocate `n` bytes on the stack (8-128, multiple of 8).
pub fn alloc_small(n_bytes: u8) -> UnwindCode {
    let info = (n_bytes.saturating_sub(8)) / 8;
    UnwindCode { code_offset: 0, unwind_op: uwop::ALLOC_SMALL, op_info: info }
}

/// `UWOP_SET_FPREG(register)` — set frame pointer.
/// The offset is stored in `UNWIND_INFO.frame_offset`, not here.
pub fn set_fpreg(reg: u8) -> UnwindCode {
    UnwindCode { code_offset: 0, unwind_op: uwop::SET_FPREG, op_info: reg }
}

/// `UWOP_SAVE_NONVOL(register)` — save register to stack slot.
pub fn save_nonvol(reg: u8) -> UnwindCode {
    UnwindCode { code_offset: 0, unwind_op: uwop::SAVE_NONVOL, op_info: reg }
}

/// Set the prologue offset on a code entry. Returns `(offset, code)` for use with `unwind_info`.
pub fn at(code: UnwindCode, off: u8) -> (u8, UnwindCode) { (off, code) }

// ── Unwind info builder ────────────────────────────────────────────────

/// Build `UNWIND_INFO` with a list of unwind codes (in STORED order = reverse prologue).
pub fn unwind_info(codes: &[(u8, UnwindCode)], flags: u8, prolog_size: u8, frame_reg: u8, frame_off: u8) -> UnwindInfo {
    UnwindInfo {
        version: 1,
        flags,
        size_of_prolog: prolog_size,
        count_of_codes: codes.len() as u8,
        frame_register: frame_reg,
        frame_offset: frame_off,
    }
}

/// Encode `UNWIND_INFO` + codes into a byte buffer as it would appear in `.xdata`.
pub fn encode_unwind(info: &UnwindInfo, codes: &[(u8, UnwindCode)]) -> Vec<u8> {
    let n = info.count_of_codes as usize;
    let header_size = 4 + n * 2;
    let padded = (header_size + 3) & !3;
    let mut buf = vec![0u8; padded];
    buf[0] = info.version | (info.flags << 3);
    buf[1] = info.size_of_prolog;
    buf[2] = info.count_of_codes;
    buf[3] = info.frame_register | (info.frame_offset << 4);
    for (i, (off, code)) in codes.iter().enumerate() {
        let pos = 4 + i * 2;
        buf[pos] = *off;
        buf[pos + 1] = code.unwind_op | (code.op_info << 4);
    }
    buf
}

// ── Guest memory simulator ─────────────────────────────────────────────

/// A simple guest memory region for testing the unwinder.
pub struct MemSim {
    /// Sparse memory: VA → bytes.  VA ranges act as independent memory regions.
    regions: Vec<(u64, Vec<u8>)>,
}

impl MemSim {
    pub fn new() -> Self {
        Self { regions: Vec::new() }
    }

    /// Map `va..va+len` with zeroed bytes.
    pub fn map(&mut self, va: u64, len: usize) {
        self.regions.push((va, vec![0u8; len]));
    }

    /// Write a u64 at the given VA.
    pub fn write_u64(&mut self, va: u64, val: u64) {
        for (base, data) in &mut self.regions {
            if va >= *base && va + 8 <= *base + data.len() as u64 {
                let off = (va - *base) as usize;
                data[off..off + 8].copy_from_slice(&val.to_le_bytes());
                return;
            }
        }
    }

    /// Write raw bytes at the given VA. VA must be within a mapped region.
    pub fn write_bytes(&mut self, va: u64, bytes: &[u8]) {
        for (base, data) in &mut self.regions {
            if va >= *base && va + bytes.len() as u64 <= *base + data.len() as u64 {
                let off = (va - *base) as usize;
                data[off..off + bytes.len()].copy_from_slice(bytes);
                return;
            }
        }
    }

    /// Read from the simulated memory.  Returns `Err(())` if VA is unmapped.
    pub fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), ()> {
        for (base, data) in &self.regions {
            if va >= *base && va + buf.len() as u64 <= *base + data.len() as u64 {
                let off = (va - *base) as usize;
                buf.copy_from_slice(&data[off..off + buf.len()]);
                return Ok(());
            }
        }
        Err(())
    }

    /// Create a `MemRead` closure for use with `virtual_unwind`.
    pub fn reader(&self) -> impl FnMut(u64, &mut [u8]) -> Result<(), ()> + '_ {
        |va, buf| self.read(va, buf)
    }
}

// ── Unwind context builder ─────────────────────────────────────────────

/// Build an `UnwindContext` with the given RIP, RSP, and optionally set GPRs.
pub fn unwind_ctx(rip: u64, rsp: u64) -> UnwindContext {
    UnwindContext { rip, rsp, gpr: [0; 16], xmm: [0; 16] }
}

impl UnwindContext {
    pub fn with_gpr(mut self, idx: usize, val: u64) -> Self {
        self.gpr[idx] = val;
        self
    }
    pub fn with_rbp(self, val: u64) -> Self { self.with_gpr(Self::RBP, val) }
    pub fn with_rbx(self, val: u64) -> Self { self.with_gpr(3, val) }
}
