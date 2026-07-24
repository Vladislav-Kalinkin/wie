//! Windows x64 exception handling data structures.
//!
//! Layouts match the PE/COFF specification §5 (x64 exception handling):
//! `RUNTIME_FUNCTION` (12 bytes), `UNWIND_INFO` (variable), `UNWIND_CODE` (2 bytes each).
//!
//! These structs describe:
//! - How to find a function's unwind metadata from its RIP (`.pdata` → `RUNTIME_FUNCTION`)
//! - How to reverse the function's prologue during stack unwinding (`UNWIND_INFO` + `UNWIND_CODE`)
//! - Where the language-specific exception handler lives (flags in `UNWIND_INFO`)

// PE / UWOP interpreters use fixed field strides and guest-buffer indexes; saturating
// every intermediate offset would obscure the PE layout. Bounds are checked via
// `get` / `read_mem` failure, not panic-free arithmetic at every step.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::as_conversions,
    clippy::integer_division,
    clippy::match_same_arms,
    clippy::result_unit_err,
    clippy::needless_range_loop,
    clippy::too_many_arguments
)]

/// One entry in the `.pdata` section.  12 bytes.  4-byte aligned.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    /// RVA of the function start (relative to image base).
    pub begin_address: u32,
    /// RVA of the function end (exclusive).
    pub end_address: u32,
    /// RVA of the `UNWIND_INFO` structure.  0 if no unwind data (leaf function).
    pub unwind_data: u32,
}

impl RuntimeFunction {
    pub const SIZE: usize = 12;

    /// Read one entry from a byte slice at `offset`.
    pub fn from_bytes(bytes: &[u8], offset: usize) -> Option<Self> {
        let b = bytes.get(offset..offset + 12)?;
        Some(Self {
            begin_address: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            end_address: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            unwind_data: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        })
    }

    /// The guest VA of the function start, given the image base.
    #[inline]
    pub fn begin_va(&self, image_base: u64) -> u64 {
        image_base.saturating_add(u64::from(self.begin_address))
    }

    /// The guest VA of the function end (exclusive), given the image base.
    #[inline]
    pub fn end_va(&self, image_base: u64) -> u64 {
        image_base.saturating_add(u64::from(self.end_address))
    }

    /// Whether this entry covers the given guest VA.
    #[inline]
    pub fn covers(&self, va: u64, image_base: u64) -> bool {
        va >= self.begin_va(image_base) && va < self.end_va(image_base)
    }
}

// ── Unwind info ────────────────────────────────────────────────────────

/// Header of the `UNWIND_INFO` structure.  Variable-length: followed by
/// `CountOfCodes` × `UNWIND_CODE` (2 bytes each), optionally padded to
/// 4-byte alignment, then the language-specific handler data if
/// `Flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)` is set
/// (4-byte RVA of handler + 4-byte handler data).
#[derive(Debug, Clone, Copy)]
pub struct UnwindInfo {
    /// Version (should be 1 for x64).
    pub version: u8,
    /// Flags: `UNW_FLAG_NHANDLER` (0), `UNW_FLAG_EHANDLER` (1),
    /// `UNW_FLAG_UHANDLER` (2), `UNW_FLAG_CHAININFO` (4).
    pub flags: u8,
    /// Length of the function prologue in bytes.
    pub size_of_prolog: u8,
    /// Number of `UNWIND_CODE` entries that follow.
    pub count_of_codes: u8,
    /// Nonvolatile register used as frame pointer (0 = none).
    pub frame_register: u8,
    /// Scaled offset from frame register to RSP at function entry.
    pub frame_offset: u8,
}

impl UnwindInfo {
    /// `EXCEPTION_EXECUTE_HANDLER`: this frame has a language-specific handler.
    pub const FLAG_EHANDLER: u8 = 1;
    /// `UNW_FLAG_NHANDLER`: no handler — unwind only.
    pub const FLAG_NHANDLER: u8 = 0;
    /// `UNW_FLAG_UHANDLER`: unwind handler (termination).
    pub const FLAG_UHANDLER: u8 = 2;
    /// `UNW_FLAG_CHAININFO`: this unwind info is followed by another.
    pub const FLAG_CHAININFO: u8 = 4;

    /// Read from bytes at `offset`.
    pub fn from_bytes(bytes: &[u8], offset: usize) -> Option<Self> {
        let b = bytes.get(offset..offset + 4)?;
        Some(Self {
            version: b[0] & 0x07,
            flags: b[0] >> 3,
            size_of_prolog: b[1],
            count_of_codes: b[2],
            frame_register: b[3] & 0x0F,
            frame_offset: (b[3] >> 4) & 0x0F,
        })
    }

    /// Total size of the UNWIND_INFO header + unwind codes (padded to 4 bytes).
    #[inline]
    pub fn header_size(&self) -> usize {
        let codes = usize::from(self.count_of_codes) * 2;
        let unpadded = 4 + codes;
        (unpadded + 3) & !3 // round up to 4
    }

    /// Total size including handler RVA + data if any handler flag is set
    /// (`FLAG_EHANDLER`, `FLAG_UHANDLER`, or both).
    #[inline]
    pub fn total_size(&self) -> usize {
        let base = self.header_size();
        if self.flags & (Self::FLAG_EHANDLER | Self::FLAG_UHANDLER) != 0 {
            base + 8 // handler RVA (4) + handler data (4) per PE/COFF §5.2
        } else {
            base
        }
    }
}

/// One unwind code entry — 2 bytes.
#[derive(Debug, Clone, Copy)]
pub struct UnwindCode {
    /// Offset in the prologue where this operation begins.
    pub code_offset: u8,
    /// `UWOP_*` opcode.
    pub unwind_op: u8,
    /// Operation-specific info (register index for push/save, allocation size bits).
    pub op_info: u8,
}

impl UnwindCode {
    pub const SIZE: usize = 2;

    pub fn from_bytes(bytes: &[u8], offset: usize) -> Option<Self> {
        let b = bytes.get(offset..offset + 2)?;
        Some(Self {
            code_offset: b[0],
            unwind_op: b[1] & 0x0F,
            op_info: (b[1] >> 4) & 0x0F,
        })
    }
}

// ── UWOP opcodes ───────────────────────────────────────────────────────

#[allow(dead_code)]
pub mod uwop {
    pub const PUSH_NONVOL: u8 = 0;
    pub const ALLOC_LARGE: u8 = 1;
    pub const ALLOC_SMALL: u8 = 2;
    pub const SET_FPREG: u8 = 3;
    pub const SAVE_NONVOL: u8 = 4;
    pub const SAVE_NONVOL_FAR: u8 = 5;
    pub const SAVE_XMM128: u8 = 6;
    pub const SAVE_XMM128_FAR: u8 = 7;
    pub const PUSH_MACHFRAME: u8 = 8;
}

// ── Function table lookup ──────────────────────────────────────────────

/// Result of `RtlLookupFunctionEntry`: the found entry + its module base.
#[derive(Debug, Clone, Copy)]
pub struct FunctionEntry<'a> {
    pub entry: &'a RuntimeFunction,
    pub image_base: u64,
}

/// Look up the `RUNTIME_FUNCTION` covering `control_pc` from the registered
/// function tables.  Binary search per-module.
pub fn lookup_function_entry(
    tables: &crate::sync_obj::SyncState,
    control_pc: u64,
) -> Option<FunctionEntry<'_>> {
    for (&image_base, entries) in &tables.function_tables {
        if entries.is_empty() {
            continue;
        }
        let first_va = entries[0].begin_va(image_base);
        let last_va = entries.last()?.end_va(image_base);
        if control_pc < first_va || control_pc >= last_va {
            tracing::debug!(control_pc = format_args!("{:#x}", control_pc), first_va = format_args!("{:#x}", first_va), last_va = format_args!("{:#x}", last_va), "lookup: out of range");
            continue;
        }
        let key = (control_pc - image_base) as u32;
        match entries.binary_search_by_key(&key, |e| e.begin_address) {
            Ok(i) => return Some(FunctionEntry { entry: &entries[i], image_base }),
            Err(0) => {
                tracing::debug!(key, "lookup: before first entry");
            }
            Err(i) => {
                let candidate = &entries[i - 1];
                let match_rva = control_pc - image_base;
                tracing::debug!(key, candidate_begin = candidate.begin_address, candidate_end = candidate.end_address, "lookup: binary search miss, checking candidate");
                if match_rva < u64::from(candidate.end_address) {
                    return Some(FunctionEntry { entry: candidate, image_base });
                }
            }
        }
    }
    None
}

/// Parse `.pdata` section bytes into a sorted `Vec<RuntimeFunction>`.
/// Returns an empty vec if the section is empty or malformed.
pub fn parse_pdata(bytes: &[u8]) -> Vec<RuntimeFunction> {
    let count = bytes.len() / RuntimeFunction::SIZE;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        if let Some(e) = RuntimeFunction::from_bytes(bytes, i * RuntimeFunction::SIZE) {
            // Skip null sentinel entries (padding at end of .pdata section).
            if e.begin_address == 0 && e.end_address == 0 && e.unwind_data == 0 {
                continue;
            }
            entries.push(e);
        }
    }
    // .pdata is sorted by the linker — already in begin_address order.
    entries
}

// ── Unwind context ─────────────────────────────────────────────────────

/// Simplified register context for stack unwinding.
/// Uses the same GPR indices as the UWOP register encoding (0=RAX..15=R15).
#[derive(Debug, Clone, Copy)]
pub struct UnwindContext {
    pub rip: u64,
    pub rsp: u64,
    pub gpr: [u64; 16],
    /// Nonvolatile XMM registers (XMM6–XMM15).  Indices 0–15; only 6–15
    /// are restored during unwinding.
    pub xmm: [u128; 16],
}

impl UnwindContext {
    /// Register index constants matching UWOP encoding.
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;
}

/// Result of one unwind step.
#[derive(Debug, Clone, Copy)]
pub struct UnwindResult {
    /// Context of the caller frame.
    pub ctx: UnwindContext,
    /// Handler RVA (relative to image base) of the language-specific handler, if any.
    pub handler_rva: Option<u32>,
    /// Raw DWORD immediately following the handler RVA in `.xdata`.
    ///
    /// ABI interpretation differs:
    /// - **MSVC**: RVA of language data (`FuncInfo` / scope table) relative to image base.
    /// - **Mingw-w64 SEH**: first 4 bytes of the **embedded** LSDA (not an RVA). See
    ///   [`language_data_candidates`].
    pub handler_data: Option<u32>,
    /// Guest VA of `ExceptionData[]` (first byte after the personality RVA in
    /// `UNWIND_INFO`). Mingw embeds the Itanium LSDA here; MSVC stores FuncInfo RVA.
    pub exception_data_va: Option<u64>,
}

/// Candidate guest VAs for language-specific data (LSDA or FuncInfo).
///
/// Order (clean-room PE/COFF + Mingw SEH practice):
/// 1. `exception_data_va` — embedded LSDA (GCC/Mingw `__gxx_personality_seh0`)
/// 2. `image_base + language_data` — MSVC FuncInfo / scope-table RVA
/// 3. `unwind_va + language_data` and low-16 variant — legacy offset packing
///
/// Duplicates are collapsed while preserving order.
pub fn language_data_candidates(
    image_base: u64,
    unwind_va: u64,
    language_data: u32,
    exception_data_va: Option<u64>,
) -> Vec<u64> {
    let full = u64::from(language_data);
    let mut out = Vec::with_capacity(4);
    let push = |v: &mut Vec<u64>, x: u64| {
        if x != 0 && !v.contains(&x) {
            v.push(x);
        }
    };
    if let Some(ed) = exception_data_va {
        push(&mut out, ed);
    }
    push(&mut out, image_base.saturating_add(full));
    push(&mut out, unwind_va.saturating_add(full));
    push(&mut out, unwind_va.saturating_add(full & 0xffff));
    out
}

// ── DWARF EH pointer encodings (Itanium C++ ABI / GCC dwarf2.h) ────────

/// `DW_EH_PE_*` application / format bits used in LSDA headers.
mod dw_eh_pe {
    pub(super) const OMIT: u8 = 0xff;
    pub(super) const ABSPTR: u8 = 0x00;
    pub(super) const ULEB128: u8 = 0x01;
    pub(super) const UDATA2: u8 = 0x02;
    pub(super) const UDATA4: u8 = 0x03;
    pub(super) const UDATA8: u8 = 0x04;
    pub(super) const SLEB128: u8 = 0x09;
    pub(super) const SDATA2: u8 = 0x0a;
    pub(super) const SDATA4: u8 = 0x0b;
    pub(super) const SDATA8: u8 = 0x0c;
    pub(super) const PCREL: u8 = 0x10;
    pub(super) const TEXTREL: u8 = 0x20;
    pub(super) const DATAREL: u8 = 0x30;
    pub(super) const FUNCREL: u8 = 0x40;
    pub(super) const ALIGNED: u8 = 0x50;
    pub(super) const INDIRECT: u8 = 0x80;
}

/// Result of host-side Itanium LSDA call-site + action matching.
#[derive(Debug, Clone, Copy)]
pub struct LandingPadMatch {
    /// Absolute guest VA of the landing pad (or cleanup).
    pub landing_pad: u64,
    /// 1-based action table index from the call-site entry (`0` = no action).
    pub action_index: u64,
    /// Value loaded into RDX at landing-pad entry (handler switch / type filter).
    pub switch_value: i64,
}

// ── Virtual unwinding ──────────────────────────────────────────────────

/// Guest memory reader callback: `fn(guest_va, buffer) -> Result`.
pub type MemRead<'a> = dyn FnMut(u64, &mut [u8]) -> Result<(), ()> + 'a;

/// Reverse one function's prologue.  Given a `ctx` with RIP inside a
/// function, returns the caller's context and any registered handler.
///
/// # Arguments
/// * `read_mem` — callback to read from guest memory.
/// * `image_base` — base address of the module containing the function.
/// * `entry` — the `RUNTIME_FUNCTION` entry for the function.
/// * `ctx` — current register state.
pub fn virtual_unwind(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    entry: &RuntimeFunction,
    mut ctx: UnwindContext,
) -> Result<UnwindResult, ()> {
    let unwind_rva = entry.unwind_data;
    if unwind_rva == 0 {
        // Leaf function: just pop the return address.
        return unwind_leaf(read_mem, ctx);
    }

    let unwind_va = image_base.saturating_add(u64::from(unwind_rva));
    let mut header_buf = [0_u8; 4];
    read_mem(unwind_va, &mut header_buf)?;

    let info = UnwindInfo::from_bytes(&header_buf, 0).ok_or(())?;
    let code_count = usize::from(info.count_of_codes);
    let codes_size = code_count * UnwindCode::SIZE;
    let mut codes_buf = vec![0_u8; codes_size];
    read_mem(unwind_va.saturating_add(4), &mut codes_buf)?;

    // Helper: read a raw 2-byte slot at index `i` (not interpreted as UNWIND_CODE).
    let raw_slot = |i: usize| -> Option<[u8; 2]> {
        codes_buf.get(i * 2..i * 2 + 2).map(|b| [b[0], b[1]])
    };
    let codes: Vec<UnwindCode> = (0..code_count)
        .filter_map(|i| UnwindCode::from_bytes(&codes_buf, i * 2))
        .collect();

    // Pre-compute the entry RSP (before any prologue operations) for
    // SAVE_NONVOL offset resolution when no frame pointer is used.
    // Without a frame pointer, the current ctx.rsp is somewhere inside
    // the function's frame, not at the entry point.  We back-compute
    // the entry RSP by summing all allocations and pushes.
    let mut entry_rsp = ctx.rsp;
    let fp_reg = usize::from(info.frame_register);
    if fp_reg == 0 {
        let mut scan_idx = 0;
        while scan_idx < codes.len() {
            let c = &codes[scan_idx];
            match c.unwind_op {
                uwop::ALLOC_SMALL => {
                    entry_rsp = entry_rsp.saturating_add(u64::from(c.op_info) * 8 + 8);
                    scan_idx += 1;
                }
                uwop::ALLOC_LARGE => {
                    let size: u64 = if c.op_info == 0 {
                        let slot = raw_slot(scan_idx + 1).unwrap_or([0, 0]);
                        u64::from(u16::from_le_bytes(slot)) * 8
                    } else {
                        let a = raw_slot(scan_idx + 1).unwrap_or([0, 0]);
                        let b = raw_slot(scan_idx + 2).unwrap_or([0, 0]);
                        u64::from(u32::from_le_bytes([a[0], a[1], b[0], b[1]]))
                    };
                    entry_rsp = entry_rsp.saturating_add(size);
                    scan_idx += if c.op_info == 0 { 2 } else { 3 };
                }
                uwop::PUSH_NONVOL => {
                    entry_rsp = entry_rsp.saturating_add(8);
                    scan_idx += 1;
                }
                uwop::PUSH_MACHFRAME => {
                    entry_rsp = entry_rsp.saturating_add(if c.op_info == 0 { 24 } else { 32 });
                    scan_idx += 1;
                }
                _ => { scan_idx += 1; }
            }
        }
    }
    let fp_rsp = if fp_reg != 0 {
        ctx.gpr[fp_reg].saturating_sub(u64::from(info.frame_offset) * 16)
    } else {
        entry_rsp
    };

    let mut rsp = ctx.rsp;

    // Process codes in forward order (stored in reverse prologue order;
    // we process them backwards which undoes the prologue correctly).
    let mut code_idx = 0;
    while code_idx < codes.len() {
        let code = &codes[code_idx];
        match code.unwind_op {
            uwop::PUSH_NONVOL => {
                let reg = usize::from(code.op_info);
                let mut val_buf = [0_u8; 8];
                read_mem(rsp, &mut val_buf)?;
                ctx.gpr[reg] = u64::from_le_bytes(val_buf);
                rsp = rsp.saturating_add(8);
                code_idx += 1;
            }
            uwop::ALLOC_LARGE => {
                let size: u64 = if code.op_info == 0 {
                    // Next raw slot is a 16-bit scaled value.
                    let slot = raw_slot(code_idx + 1).unwrap_or([0, 0]);
                    u64::from(u16::from_le_bytes(slot)) * 8
                } else {
                    // Next two raw slots form a 32-bit value.
                    let a = raw_slot(code_idx + 1).unwrap_or([0, 0]);
                    let b = raw_slot(code_idx + 2).unwrap_or([0, 0]);
                    u64::from(u32::from_le_bytes([a[0], a[1], b[0], b[1]]))
                };
                rsp = rsp.saturating_add(size);
                code_idx += if code.op_info == 0 { 2 } else { 3 };
            }
            uwop::ALLOC_SMALL => {
                let size = u64::from(code.op_info) * 8 + 8;
                rsp = rsp.saturating_add(size);
                code_idx += 1;
            }
            uwop::SET_FPREG => {
                code_idx += 1;
            }
            uwop::SAVE_NONVOL => {
                let reg = usize::from(code.op_info);
                let slot = raw_slot(code_idx + 1).unwrap_or([0, 0]);
                let offset = u64::from(u16::from_le_bytes(slot)) * 8;
                let va = fp_rsp.saturating_add(offset);
                let mut val_buf = [0_u8; 8];
                read_mem(va, &mut val_buf)?;
                ctx.gpr[reg] = u64::from_le_bytes(val_buf);
                code_idx += 2;
            }
            uwop::SAVE_NONVOL_FAR => {
                let reg = usize::from(code.op_info);
                let a = raw_slot(code_idx + 1).unwrap_or([0, 0]);
                let b = raw_slot(code_idx + 2).unwrap_or([0, 0]);
                let offset = u64::from(u32::from_le_bytes([a[0], a[1], b[0], b[1]]));
                let va = fp_rsp.saturating_add(offset);
                let mut val_buf = [0_u8; 8];
                read_mem(va, &mut val_buf)?;
                ctx.gpr[reg] = u64::from_le_bytes(val_buf);
                code_idx += 3;
            }
            uwop::SAVE_XMM128 => {
                let reg = usize::from(code.op_info);
                let slot = raw_slot(code_idx + 1).unwrap_or([0, 0]);
                let offset = u64::from(u16::from_le_bytes(slot)) * 16;
                let va = fp_rsp.saturating_add(offset);
                let mut val_buf = [0_u8; 16];
                read_mem(va, &mut val_buf)?;
                ctx.xmm[reg] = u128::from_le_bytes(val_buf);
                code_idx += 2;
            }
            uwop::SAVE_XMM128_FAR => {
                let reg = usize::from(code.op_info);
                let a = raw_slot(code_idx + 1).unwrap_or([0, 0]);
                let b = raw_slot(code_idx + 2).unwrap_or([0, 0]);
                let offset = u64::from(u32::from_le_bytes([a[0], a[1], b[0], b[1]]));
                let va = fp_rsp.saturating_add(offset);
                let mut val_buf = [0_u8; 16];
                read_mem(va, &mut val_buf)?;
                ctx.xmm[reg] = u128::from_le_bytes(val_buf);
                code_idx += 3;
            }
            uwop::PUSH_MACHFRAME => {
                let extra = if code.op_info == 0 { 24 } else { 32 };
                rsp = rsp.saturating_add(extra);
                code_idx += 1;
            }
            _ => {
                code_idx += 1;
            }
        }
    }

    // Pop return address.
    let mut rip_buf = [0_u8; 8];
    read_mem(rsp, &mut rip_buf)?;
    ctx.rip = u64::from_le_bytes(rip_buf);
    rsp = rsp.saturating_add(8);
    ctx.rsp = rsp;

    // Data after the padded codes: for CHAININFO it's a chain pointer (4 bytes);
    // for EHANDLER/UHANDLER it's handler_rva (4 bytes) + handler_data (4 bytes).
    let data_off = unwind_va.saturating_add(info.header_size() as u64);

    if info.flags & UnwindInfo::FLAG_CHAININFO != 0 {
        // Chain info: 4-byte RVA pointing to another UNWIND_INFO.
        let mut chain_buf = [0_u8; 4];
        read_mem(data_off, &mut chain_buf)?;
        let chain_rva = u32::from_le_bytes(chain_buf);
        if chain_rva != 0 {
            let chain_entry = RuntimeFunction {
                begin_address: entry.begin_address,
                end_address: entry.end_address,
                unwind_data: chain_rva,
            };
            let chained = virtual_unwind(read_mem, image_base, &chain_entry, UnwindContext {
                rip: ctx.rip, rsp, ..ctx
            })?;
            // Chain entry may also have EHANDLER/UHANDLER flags;
            // prefer its handler data over any data we'd read here.
            return Ok(UnwindResult {
                ctx: chained.ctx,
                handler_rva: chained.handler_rva,
                handler_data: chained.handler_data,
                exception_data_va: chained.exception_data_va,
            });
        }
        // Chain RVA is 0 — no chain, fall through to handler check.
    }

    // Extract handler info if present (only when CHAININFO is NOT set,
    // otherwise the data at data_off would be interpreted as chain, not
    // as handler info).
    let handler_flags = UnwindInfo::FLAG_EHANDLER | UnwindInfo::FLAG_UHANDLER;
    if info.flags & handler_flags != 0 {
        let mut h_buf = [0_u8; 8];
        read_mem(data_off, &mut h_buf)?;
        let hrva = u32::from_le_bytes([h_buf[0], h_buf[1], h_buf[2], h_buf[3]]);
        // Full language-data DWORD (MSVC: FuncInfo RVA; Mingw: first LSDA dword).
        let hdata = u32::from_le_bytes([h_buf[4], h_buf[5], h_buf[6], h_buf[7]]);
        // ExceptionData starts immediately after the personality RVA.
        let exception_data_va = data_off.saturating_add(4);
        Ok(UnwindResult {
            ctx,
            handler_rva: Some(hrva),
            handler_data: Some(hdata),
            exception_data_va: Some(exception_data_va),
        })
    } else {
        Ok(UnwindResult {
            ctx,
            handler_rva: None,
            handler_data: None,
            exception_data_va: None,
        })
    }
}

// ── LSDA helpers ───────────────────────────────────────────────────────

fn read_uleb128(read_mem: &mut MemRead<'_>, cursor: &mut u64) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let mut b = [0u8; 1];
        read_mem(*cursor, &mut b).ok()?;
        *cursor = cursor.saturating_add(1);
        v |= u64::from(b[0] & 0x7f) << shift;
        if b[0] & 0x80 == 0 {
            return Some(v);
        }
        shift = shift.saturating_add(7);
        if shift > 56 {
            return None;
        }
    }
}

fn read_sleb128(read_mem: &mut MemRead<'_>, cursor: &mut u64) -> Option<i64> {
    let mut v = 0i64;
    let mut shift = 0u32;
    let mut b = [0u8; 1];
    loop {
        read_mem(*cursor, &mut b).ok()?;
        *cursor = cursor.saturating_add(1);
        v |= i64::from(b[0] & 0x7f) << shift;
        shift = shift.saturating_add(7);
        if b[0] & 0x80 == 0 {
            if shift < 64 && (b[0] & 0x40) != 0 {
                v |= -1i64 << shift;
            }
            return Some(v);
        }
        if shift > 56 {
            return None;
        }
    }
}

/// Size in bytes of a fixed-width DWARF EH format nibble, or `None` for LEB/omit/unknown.
fn dw_format_size(format: u8) -> Option<u64> {
    match format {
        dw_eh_pe::ABSPTR | dw_eh_pe::UDATA8 | dw_eh_pe::SDATA8 => Some(8),
        dw_eh_pe::UDATA2 | dw_eh_pe::SDATA2 => Some(2),
        dw_eh_pe::UDATA4 | dw_eh_pe::SDATA4 => Some(4),
        _ => None,
    }
}

fn is_signed_format(format: u8) -> bool {
    matches!(
        format,
        dw_eh_pe::SLEB128 | dw_eh_pe::SDATA2 | dw_eh_pe::SDATA4 | dw_eh_pe::SDATA8
    )
}

/// Read an encoded pointer value; advances `cursor`. Returns the raw numeric
/// value before application of pcrel/datarel/indirect (those need the value's
/// storage address and bases).
fn read_encoded_value(
    read_mem: &mut MemRead<'_>,
    cursor: &mut u64,
    encoding: u8,
) -> Option<(u64, u64)> {
    // Returns (raw_value_as_u64, value_storage_va)
    if encoding == dw_eh_pe::OMIT {
        return Some((0, *cursor));
    }
    let format = encoding & 0x0f;
    let storage = *cursor;
    let raw = match format {
        dw_eh_pe::ULEB128 => read_uleb128(read_mem, cursor)?,
        dw_eh_pe::SLEB128 => read_sleb128(read_mem, cursor)? as u64,
        f => {
            let sz = dw_format_size(f)?;
            let mut buf = [0u8; 8];
            read_mem(*cursor, &mut buf[..sz as usize]).ok()?;
            *cursor = cursor.saturating_add(sz);
            let mut v = 0u64;
            for i in 0..sz as usize {
                v |= u64::from(buf[i]) << (i * 8);
            }
            if is_signed_format(f) {
                let bits = sz * 8;
                let sign = 1u64 << (bits - 1);
                if v & sign != 0 {
                    v |= !((1u64 << bits) - 1);
                }
            }
            v
        }
    };
    Some((raw, storage))
}

/// Apply DW_EH_PE application + optional indirect to a raw encoded value.
fn apply_encoding(
    read_mem: &mut MemRead<'_>,
    encoding: u8,
    raw: u64,
    storage_va: u64,
    image_base: u64,
    func_start: u64,
    data_base: u64,
) -> Option<u64> {
    if encoding == dw_eh_pe::OMIT {
        return Some(0);
    }
    // Zero raw value → null pointer (Itanium type-table catch-all, omit reloc).
    if raw == 0 {
        return Some(0);
    }
    let app = encoding & 0x70;
    let mut addr = match app {
        0x00 => raw, // absptr / absolute
        dw_eh_pe::PCREL => storage_va.wrapping_add(raw),
        dw_eh_pe::TEXTREL => image_base.wrapping_add(raw),
        dw_eh_pe::DATAREL => data_base.wrapping_add(raw),
        dw_eh_pe::FUNCREL => func_start.wrapping_add(raw),
        dw_eh_pe::ALIGNED => raw, // rare; treat as absolute
        _ => raw,
    };
    if encoding & dw_eh_pe::INDIRECT != 0 && addr != 0 {
        let mut buf = [0u8; 8];
        read_mem(addr, &mut buf).ok()?;
        addr = u64::from_le_bytes(buf);
    }
    Some(addr)
}

/// Parse the Itanium LSDA call-site table and find the landing pad for `control_pc`.
///
/// Clean-room Itanium C++ ABI §EH + GCC `dwarf2.h` encodings. Handles:
/// - Embedded Mingw SEH LSDA (`ExceptionData` after personality RVA)
/// - `DW_EH_PE_pcrel` / `datarel` / `funcrel` / `indirect` on LPStart and types
/// - Call-site PC match with **IP−1** when `control_pc` is a return address
///   (standard `_Unwind_GetIPInfo` adjustment for call sites)
///
/// When `thrown_typeinfo` is `Some`, walks the action table and picks the first
/// matching catch (type pointer equality or catch-all). When `None`, accepts the
/// first catch-all / any typed action (used when the throw payload is unknown).
///
/// Returns [`LandingPadMatch`] or `None` if no handler covers the PC.
pub fn find_landing_pad(
    read_mem: &mut MemRead<'_>,
    lsda_va: u64,
    image_base: u64,
    func_start: u64,
    _func_end: u64,
    control_pc: u64,
) -> Option<(u64, u64)> {
    find_landing_pad_ex(
        read_mem,
        lsda_va,
        image_base,
        func_start,
        control_pc,
        None,
    )
    .map(|m| (m.landing_pad, m.action_index))
}

/// Extended LSDA match with optional thrown-typeinfo filtering and switch value.
pub fn find_landing_pad_ex(
    read_mem: &mut MemRead<'_>,
    lsda_va: u64,
    image_base: u64,
    func_start: u64,
    control_pc: u64,
    thrown_typeinfo: Option<u64>,
) -> Option<LandingPadMatch> {
    let mut cursor = lsda_va;

    // LPStart encoding + value
    let mut b1 = [0u8; 1];
    read_mem(cursor, &mut b1).ok()?;
    cursor = cursor.saturating_add(1);
    let lp_enc = b1[0];
    let mut lp_base = func_start;
    if lp_enc != dw_eh_pe::OMIT {
        let (raw, storage) = read_encoded_value(read_mem, &mut cursor, lp_enc)?;
        lp_base = apply_encoding(
            read_mem,
            lp_enc,
            raw,
            storage,
            image_base,
            func_start,
            image_base,
        )?;
        if lp_base == 0 {
            lp_base = func_start;
        }
    }

    // TType encoding + base offset (ULEB128 from after the ULEB itself)
    read_mem(cursor, &mut b1).ok()?;
    cursor = cursor.saturating_add(1);
    let ttype_enc = b1[0];
    let mut ttype_base = 0u64;
    if ttype_enc != dw_eh_pe::OMIT {
        let off = read_uleb128(read_mem, &mut cursor)?;
        ttype_base = cursor.saturating_add(off);
    }

    // Call-site encoding + table length
    read_mem(cursor, &mut b1).ok()?;
    cursor = cursor.saturating_add(1);
    let cs_enc = b1[0];
    let cs_len = read_uleb128(read_mem, &mut cursor)?;
    if cs_len == 0 {
        return None;
    }
    let cs_end = cursor.saturating_add(cs_len);
    let action_table = cs_end;

    // IP-1: exception PC for a CALL is typically the return address (one past
    // the call). GCC call-site ranges cover the call insn only, so match IP-1.
    let match_pc = control_pc.saturating_sub(1);
    let pcs = [match_pc, control_pc];

    let format = cs_enc & 0x0f;
    let abs = format == dw_eh_pe::ABSPTR;

    while cursor < cs_end {
        let site_start_cursor = cursor;
        let (cs_s, cs_len_v, lp_raw, aidx) = if format == dw_eh_pe::ULEB128 {
            (
                read_uleb128(read_mem, &mut cursor)?,
                read_uleb128(read_mem, &mut cursor)?,
                read_uleb128(read_mem, &mut cursor)?,
                read_uleb128(read_mem, &mut cursor)?,
            )
        } else {
            // Validate fixed-width format before reading four fields.
            let _sz = dw_format_size(format)?;
            let mut read_fix = |c: &mut u64| -> Option<u64> {
                let (raw, _) = read_encoded_value(read_mem, c, format)?;
                Some(raw)
            };
            let s = read_fix(&mut cursor)?;
            let len = read_fix(&mut cursor)?;
            let pad = read_fix(&mut cursor)?;
            // action_index is always ULEB128 in the Itanium LSDA.
            let a = read_uleb128(read_mem, &mut cursor)?;
            let _ = site_start_cursor;
            (s, len, pad, a)
        };

        if lp_raw == 0 {
            continue;
        }

        let (rstart, rend) = if abs {
            (cs_s, cs_s.saturating_add(cs_len_v))
        } else {
            (
                lp_base.saturating_add(cs_s),
                lp_base.saturating_add(cs_s).saturating_add(cs_len_v),
            )
        };

        let covers = pcs.iter().any(|&p| p >= rstart && p < rend);
        if !covers {
            continue;
        }

        let landing_va = if abs {
            lp_raw
        } else {
            lp_base.saturating_add(lp_raw)
        };
        if landing_va == 0 {
            continue;
        }

        // action_index == 0 with a landing pad is a **cleanup-only** site
        // (run dtors, then `_Unwind_Resume`). Never treat as a catch during search.
        if aidx == 0 {
            continue;
        }
        // No type table: cannot match typed/catch-all handlers reliably.
        if ttype_enc == dw_eh_pe::OMIT {
            continue;
        }

        // Walk action records (1-based byte offset into action table).
        if let Some(sw) =
            match_action(read_mem, action_table, aidx, ttype_base, ttype_enc, image_base, func_start, thrown_typeinfo)
        {
            return Some(LandingPadMatch {
                landing_pad: landing_va,
                action_index: aidx,
                switch_value: sw,
            });
        }
        // Typed mismatch / cleanup-only action chain: keep searching.
    }
    None
}

/// Find a cleanup-only landing pad for `control_pc` (phase-2 intermediate frames).
///
/// Call-site with `landing_pad != 0` and `action_index == 0`, or an action chain
/// that has no catch (cleanup filters only).
pub fn find_cleanup_landing_pad(
    read_mem: &mut MemRead<'_>,
    lsda_va: u64,
    image_base: u64,
    func_start: u64,
    control_pc: u64,
) -> Option<LandingPadMatch> {
    let mut cursor = lsda_va;
    let mut b1 = [0u8; 1];
    read_mem(cursor, &mut b1).ok()?;
    cursor = cursor.saturating_add(1);
    let lp_enc = b1[0];
    let mut lp_base = func_start;
    if lp_enc != dw_eh_pe::OMIT {
        let (raw, storage) = read_encoded_value(read_mem, &mut cursor, lp_enc)?;
        lp_base = apply_encoding(
            read_mem,
            lp_enc,
            raw,
            storage,
            image_base,
            func_start,
            image_base,
        )?;
        if lp_base == 0 {
            lp_base = func_start;
        }
    }
    read_mem(cursor, &mut b1).ok()?;
    cursor = cursor.saturating_add(1);
    let ttype_enc = b1[0];
    if ttype_enc != dw_eh_pe::OMIT {
        let _off = read_uleb128(read_mem, &mut cursor)?;
    }
    read_mem(cursor, &mut b1).ok()?;
    cursor = cursor.saturating_add(1);
    let cs_enc = b1[0];
    let cs_len = read_uleb128(read_mem, &mut cursor)?;
    if cs_len == 0 {
        return None;
    }
    let cs_end = cursor.saturating_add(cs_len);
    let match_pc = control_pc.saturating_sub(1);
    let pcs = [match_pc, control_pc];
    let format = cs_enc & 0x0f;
    let abs = format == dw_eh_pe::ABSPTR;

    while cursor < cs_end {
        let (cs_s, cs_len_v, lp_raw, aidx) = if format == dw_eh_pe::ULEB128 {
            (
                read_uleb128(read_mem, &mut cursor)?,
                read_uleb128(read_mem, &mut cursor)?,
                read_uleb128(read_mem, &mut cursor)?,
                read_uleb128(read_mem, &mut cursor)?,
            )
        } else {
            let _sz = dw_format_size(format)?;
            let mut read_fix = |c: &mut u64| -> Option<u64> {
                let (raw, _) = read_encoded_value(read_mem, c, format)?;
                Some(raw)
            };
            (
                read_fix(&mut cursor)?,
                read_fix(&mut cursor)?,
                read_fix(&mut cursor)?,
                read_uleb128(read_mem, &mut cursor)?,
            )
        };
        if lp_raw == 0 || aidx != 0 {
            // Only pure cleanups (action 0). Catch sites are handled in search.
            continue;
        }
        let (rstart, rend) = if abs {
            (cs_s, cs_s.saturating_add(cs_len_v))
        } else {
            (
                lp_base.saturating_add(cs_s),
                lp_base.saturating_add(cs_s).saturating_add(cs_len_v),
            )
        };
        if !pcs.iter().any(|&p| p >= rstart && p < rend) {
            continue;
        }
        let landing_va = if abs {
            lp_raw
        } else {
            lp_base.saturating_add(lp_raw)
        };
        if landing_va != 0 {
            return Some(LandingPadMatch {
                landing_pad: landing_va,
                action_index: 0,
                switch_value: 0,
            });
        }
    }
    None
}

/// Walk LSDA action records starting at 1-based `action_index`.
///
/// Two-pass (matches libstdc++ personality preference):
/// 1. Prefer a **typed** catch whose typeinfo equals the thrown type
/// 2. Otherwise accept catch-all (`filter == 0` or null typeinfo entry)
///
/// Returns the handler switch value for RDX (`filter` for typed, `0` for `...`).
fn match_action(
    read_mem: &mut MemRead<'_>,
    action_table: u64,
    action_index: u64,
    ttype_base: u64,
    ttype_enc: u8,
    image_base: u64,
    func_start: u64,
    thrown_typeinfo: Option<u64>,
) -> Option<i64> {
    if action_index == 0 {
        return None; // cleanup-only; not a catch
    }
    let mut catch_all: Option<i64> = None;
    let mut idx = action_index;
    for _ in 0..32 {
        let rec = action_table.saturating_add(idx.saturating_sub(1));
        let mut cursor = rec;
        let filter = read_sleb128(read_mem, &mut cursor)?;
        let next = read_sleb128(read_mem, &mut cursor)?;

        if filter == 0 {
            // Catch-all (`...`). Remember; typed matches win if present later.
            if catch_all.is_none() {
                catch_all = Some(0);
            }
        } else if filter > 0 {
            let slot_ti = resolve_ttype(
                read_mem,
                ttype_base,
                ttype_enc,
                filter as u64,
                image_base,
                func_start,
            );
            match slot_ti {
                Some(0) => {
                    // Null typeinfo entry → catch-all under a non-zero filter.
                    if catch_all.is_none() {
                        catch_all = Some(filter);
                    }
                }
                Some(entry) => {
                    let matched = match thrown_typeinfo {
                        None => true,
                        Some(ti) => entry == ti,
                    };
                    if matched {
                        return Some(filter);
                    }
                }
                None => {}
            }
        }
        // filter < 0: cleanup / exception-spec — skip for catch selection.
        if next == 0 {
            break;
        }
        // `next` is a signed byte displacement from the start of the next field.
        let mut c2 = rec;
        let _f = read_sleb128(read_mem, &mut c2)?;
        let disp_field = c2;
        let next_i = (disp_field as i64).saturating_add(next);
        if next_i <= 0 {
            break;
        }
        let next_va = next_i as u64;
        if next_va < action_table {
            break;
        }
        idx = next_va.saturating_sub(action_table).saturating_add(1);
    }
    catch_all
}

/// Resolve a 1-based type-table index to a typeinfo pointer VA.
fn resolve_ttype(
    read_mem: &mut MemRead<'_>,
    ttype_base: u64,
    ttype_enc: u8,
    index: u64,
    image_base: u64,
    func_start: u64,
) -> Option<u64> {
    if index == 0 || ttype_enc == dw_eh_pe::OMIT {
        return None;
    }
    let format = ttype_enc & 0x0f;
    let entry_size = match format {
        dw_eh_pe::ULEB128 | dw_eh_pe::SLEB128 => return None, // variable — uncommon for ttype
        f => dw_format_size(f).unwrap_or(0),
    };
    if entry_size == 0 {
        return None;
    }
    // Type table grows downward from ttype_base; entry N is at base - N*size.
    let slot = ttype_base.saturating_sub(index.saturating_mul(entry_size));
    let mut cursor = slot;
    let (raw, storage) = read_encoded_value(read_mem, &mut cursor, ttype_enc & 0x0f)?;
    // Re-apply with full encoding (pcrel/indirect use storage = slot).
    apply_encoding(
        read_mem,
        ttype_enc,
        raw,
        storage,
        image_base,
        func_start,
        image_base, // datarel base ≈ image base on PE
    )
}

/// Unwind a leaf function (no unwind info).  Simply pops the return address.
fn unwind_leaf(read_mem: &mut MemRead<'_>, mut ctx: UnwindContext) -> Result<UnwindResult, ()> {
    let mut rip_buf = [0_u8; 8];
    read_mem(ctx.rsp, &mut rip_buf)?;
    ctx.rip = u64::from_le_bytes(rip_buf);
    ctx.rsp = ctx.rsp.saturating_add(8);
    Ok(UnwindResult {
        ctx,
        handler_rva: None,
        handler_data: None,
        exception_data_va: None,
    })
}


