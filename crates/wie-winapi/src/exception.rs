//! Windows x64 exception handling data structures.
//!
//! Layouts match the PE/COFF specification §5 (x64 exception handling):
//! `RUNTIME_FUNCTION` (12 bytes), `UNWIND_INFO` (variable), `UNWIND_CODE` (2 bytes each).
//!
//! These structs describe:
//! - How to find a function's unwind metadata from its RIP (`.pdata` → `RUNTIME_FUNCTION`)
//! - How to reverse the function's prologue during stack unwinding (`UNWIND_INFO` + `UNWIND_CODE`)
//! - Where the language-specific exception handler lives (flags in `UNWIND_INFO`)

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
/// `Flags & UNW_FLAG_EHANDLER` (4-byte RVA of handler + 4-byte handler data).
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
    pub const SIZE: usize = 4;

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

    /// Total size including handler RVA + data if `FLAG_EHANDLER` is set.
    #[inline]
    pub fn total_size(&self) -> usize {
        let base = self.header_size();
        if self.flags & Self::FLAG_EHANDLER != 0 {
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
pub fn lookup_function_entry<'a>(
    tables: &'a crate::sync_obj::SyncState,
    control_pc: u64,
) -> Option<FunctionEntry<'a>> {
    for (&image_base, entries) in &tables.function_tables {
        if entries.is_empty() {
            continue;
        }
        let first_va = entries[0].begin_va(image_base);
        let last_va = entries.last()?.end_va(image_base);
        if control_pc < first_va || control_pc >= last_va {
            continue;
        }
        // Binary search by begin_address (RVA).
        match entries.binary_search_by_key(&((control_pc - image_base) as u32), |e| e.begin_address)
        {
            Ok(i) => return Some(FunctionEntry { entry: &entries[i], image_base }),
            Err(0) => continue, // before the first entry
            Err(i) => {
                let candidate = &entries[i - 1];
                if (control_pc - image_base) < u64::from(candidate.end_address) {
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
            entries.push(e);
        }
    }
    entries.sort_by_key(|e| e.begin_address);
    entries
}


