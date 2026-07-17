//! In-guest machine-code stubs for trivial WinAPI entries.
//!
//! These run entirely inside Unicorn without a host stop when the code hook
//! treats their instruction bytes as passthrough (see `install_runtime_hooks`).

use anyhow::{Context, Result};

/// Kind of in-guest stub to plant at a fake API VA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestStubKind {
    /// `ret` — void stdcall/win64 return.
    VoidRet,
    /// `mov rax, rcx; ret` — identity pointer (Encode/DecodePointer).
    IdentityRcxToRax,
    /// `xor eax, eax; ret` — return 0 / FALSE / NULL.
    ReturnZero,
    /// `mov eax, imm32; ret` — fixed 32-bit return in RAX zero-extended.
    /// Use `ReturnImm32(1)` for TRUE / success.
    ReturnImm32(u32),
    /// `mov rax, imm64; ret` — full 64-bit RAX (fits in 16-byte IAT stride).
    ReturnImm64(u64),
    /// `mov rax, imm64; mov eax, [rax]; ret` — load DWORD from fixed guest VA.
    /// Used for `GetLastError` reading TEB.LastErrorValue (or a mirror at that VA).
    LoadZx32FromVa(u64),
    /// `mov rax, imm64; mov [rax], ecx; ret` — store DWORD to fixed guest VA.
    /// Used for `SetLastError` writing TEB.LastErrorValue.
    StoreEcxToVa(u64),
    /// `FlsGetValue`: index in RCX, table of u64 values at fixed VA.
    /// Out-of-range index returns 0 (matches our host handler).
    FlsGetValue { table_va: u64, max_slots: u32 },
    /// `FlsSetValue`: RCX=index, RDX=value; returns TRUE. OOR → FALSE.
    FlsSetValue { table_va: u64, max_slots: u32 },
    /// `__acrt_iob_func(ix)` → FILE* cookie (stdin/stdout/stderr).
    AcrtIobFunc,
}

impl GuestStubKind {
    /// Encodes the stub body. Most stubs fit the 16-byte IAT stride; `FlsGetValue`
    /// is longer and is planted outside the hooked range with a 12-byte `jmp` at the IAT.
    #[must_use]
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::VoidRet => vec![0xc3],
            Self::IdentityRcxToRax => vec![0x48, 0x89, 0xc8, 0xc3],
            Self::ReturnZero => vec![0x31, 0xc0, 0xc3],
            Self::ReturnImm32(imm) => {
                let mut buf = vec![0xb8, 0, 0, 0, 0, 0xc3];
                buf[1..5].copy_from_slice(&imm.to_le_bytes());
                buf
            }
            Self::ReturnImm64(imm) => {
                let mut buf = vec![0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xc3];
                buf[2..10].copy_from_slice(&imm.to_le_bytes());
                buf
            }
            Self::LoadZx32FromVa(va) => {
                let mut buf = vec![0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x8b, 0x00, 0xc3];
                buf[2..10].copy_from_slice(&va.to_le_bytes());
                buf
            }
            Self::StoreEcxToVa(va) => {
                let mut buf = vec![0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0x08, 0xc3];
                buf[2..10].copy_from_slice(&va.to_le_bytes());
                buf
            }
            Self::FlsGetValue {
                table_va,
                max_slots,
            } => {
                // cmp rcx, imm32 ; jae .zero ; mov rax, table ; mov rax, [rax+rcx*8] ; ret
                // .zero: xor eax,eax ; ret
                let mut buf = Vec::with_capacity(32);
                buf.extend_from_slice(&[0x48, 0x81, 0xf9]);
                buf.extend_from_slice(&max_slots.to_le_bytes());
                let jae_imm = buf.len() + 1;
                buf.extend_from_slice(&[0x73, 0x00]); // jae rel8
                buf.extend_from_slice(&[0x48, 0xb8]);
                buf.extend_from_slice(&table_va.to_le_bytes());
                buf.extend_from_slice(&[0x48, 0x8b, 0x04, 0xc8]); // mov rax, [rax+rcx*8]
                buf.push(0xc3);
                let zero_at = buf.len();
                buf.extend_from_slice(&[0x31, 0xc0, 0xc3]);
                let next_ip = jae_imm + 1;
                let rel = zero_at as isize - next_ip as isize;
                debug_assert!((-128..128).contains(&rel));
                buf[jae_imm] = rel as i8 as u8;
                buf
            }
            Self::FlsSetValue {
                table_va,
                max_slots,
            } => {
                // cmp rcx, max ; jae .fail
                // mov rax, table ; mov [rax+rcx*8], rdx ; mov eax, 1 ; ret
                // .fail: xor eax,eax ; ret
                let mut buf = Vec::with_capacity(40);
                buf.extend_from_slice(&[0x48, 0x81, 0xf9]);
                buf.extend_from_slice(&max_slots.to_le_bytes());
                let jae_imm = buf.len() + 1;
                buf.extend_from_slice(&[0x73, 0x00]);
                buf.extend_from_slice(&[0x48, 0xb8]);
                buf.extend_from_slice(&table_va.to_le_bytes());
                buf.extend_from_slice(&[0x48, 0x89, 0x14, 0xc8]); // mov [rax+rcx*8], rdx
                buf.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
                buf.push(0xc3);
                let fail_at = buf.len();
                buf.extend_from_slice(&[0x31, 0xc0, 0xc3]);
                let next_ip = jae_imm + 1;
                let rel = fail_at as isize - next_ip as isize;
                debug_assert!((-128..128).contains(&rel));
                buf[jae_imm] = rel as i8 as u8;
                buf
            }
            Self::AcrtIobFunc => {
                // Fits 16-byte IAT stride (no bounds check; CRT only passes 0/1/2):
                // mov eax, 0x68000000 ; shl ecx, 8 ; add eax, ecx ; ret
                // (32-bit ops zero-extend into RAX)
                let mut buf = vec![0xb8, 0x00, 0x00, 0x00, 0x68]; // mov eax, 0x68000000
                buf.extend_from_slice(&[0xc1, 0xe1, 0x08]); // shl ecx, 8
                buf.extend_from_slice(&[0x01, 0xc8]); // add eax, ecx
                buf.push(0xc3); // ret
                buf
            }
        }
    }

    /// Whether the body must be planted outside the IAT slot (jmp trampoline at entry).
    #[must_use]
    pub(crate) fn needs_out_of_line_helper(self) -> bool {
        matches!(self, Self::FlsGetValue { .. } | Self::FlsSetValue { .. })
    }
}

/// x64 TEB.LastErrorValue offset (also used as our guest mirror VA when TEB base is 0).
pub const TEB_LAST_ERROR_VA: u64 = 0x68;

/// Guest FLS table slot count (index 0..N-1 accelerated).
pub const GUEST_FLS_SLOT_COUNT: u32 = 256;

/// Classify a library/export as an in-guest stub when safe.
///
/// Only pure functions with no guest-memory side effects and fixed results
/// (or results fully published into guest memory by the host).
#[must_use]
pub(crate) fn classify_guest_stub(
    library: &str,
    name: &str,
    fls_table_va: u64,
) -> Option<GuestStubKind> {
    // UCRT pure helpers: cover indirect `call reg` paths that miss the JIT near-call
    // fast path (still no host-stop). Matches FILE* cookies / CRT slots in `wie_winapi::ucrt`.
    if wie_winapi::ucrt::is_ucrt_library(library) {
        const CRT: u64 = 0x0000_0000_6800_0000;
        let n = name;
        if n.eq_ignore_ascii_case("__acrt_iob_func") {
            return Some(GuestStubKind::AcrtIobFunc);
        }
        // No-op / fixed-success CRT init (host handlers only returned 0).
        if n.eq_ignore_ascii_case("fflush")
            || n.eq_ignore_ascii_case("setvbuf")
            || n.eq_ignore_ascii_case("_crt_atexit")
            || n.eq_ignore_ascii_case("_set_invalid_parameter_handler")
            || n.eq_ignore_ascii_case("_set_app_type")
            || n.eq_ignore_ascii_case("_set_new_mode")
            || n.eq_ignore_ascii_case("_initterm")
            || n.eq_ignore_ascii_case("_initterm_e")
            || n.eq_ignore_ascii_case("_configure_narrow_argv")
            || n.eq_ignore_ascii_case("_initialize_narrow_environment")
            || n.eq_ignore_ascii_case("__setusermatherr")
            || n.eq_ignore_ascii_case("_configthreadlocale")
            || n.eq_ignore_ascii_case("_cexit")
            || n.eq_ignore_ascii_case("signal")
        {
            return Some(GuestStubKind::ReturnZero);
        }
        // __p__* → pointer to pre-mapped CRT guest slots (session maps 0x68000000 page).
        if n.eq_ignore_ascii_case("__p__environ") {
            return Some(GuestStubKind::ReturnImm64(CRT + 0x300));
        }
        if n.eq_ignore_ascii_case("__p___argv") {
            return Some(GuestStubKind::ReturnImm64(CRT + 0x308));
        }
        if n.eq_ignore_ascii_case("__p___argc") {
            return Some(GuestStubKind::ReturnImm64(CRT + 0x310));
        }
        if n.eq_ignore_ascii_case("__p__commode") {
            return Some(GuestStubKind::ReturnImm64(CRT + 0x318));
        }
        if n.eq_ignore_ascii_case("__p__fmode") {
            return Some(GuestStubKind::ReturnImm64(CRT + 0x320));
        }
        if n.eq_ignore_ascii_case("__p__acmdln") {
            return Some(GuestStubKind::ReturnImm64(CRT + 0x328));
        }
        // malloc/free/memcpy/strlen/fwrite stay on JIT import / host path.
        return None;
    }

    if !library.eq_ignore_ascii_case("KERNEL32.dll") && !library.eq_ignore_ascii_case("ntdll.dll") {
        // Keep USER32/GDI out of guest stubs for now (window state matters).
        return None;
    }

    let n = name;
    if n.eq_ignore_ascii_case("EncodePointer") || n.eq_ignore_ascii_case("DecodePointer") {
        return Some(GuestStubKind::IdentityRcxToRax);
    }
    if n.eq_ignore_ascii_case("EnterCriticalSection")
        || n.eq_ignore_ascii_case("LeaveCriticalSection")
        || n.eq_ignore_ascii_case("DeleteCriticalSection")
    {
        return Some(GuestStubKind::VoidRet);
    }
    // InitializeCriticalSection* stays on host (writes RTL_CRITICAL_SECTION).
    // GetLastError / SetLastError: TEB.LastErrorValue at guest VA 0x68. Host handlers
    // publish `state.last_error` there after every stop so coherence is preserved.
    if n.eq_ignore_ascii_case("GetLastError") {
        return Some(GuestStubKind::LoadZx32FromVa(TEB_LAST_ERROR_VA));
    }
    if n.eq_ignore_ascii_case("SetLastError") {
        return Some(GuestStubKind::StoreEcxToVa(TEB_LAST_ERROR_VA));
    }
    if n.eq_ignore_ascii_case("FlsGetValue") {
        return Some(GuestStubKind::FlsGetValue {
            table_va: fls_table_va,
            max_slots: GUEST_FLS_SLOT_COUNT,
        });
    }
    if n.eq_ignore_ascii_case("FlsSetValue") {
        return Some(GuestStubKind::FlsSetValue {
            table_va: fls_table_va,
            max_slots: GUEST_FLS_SLOT_COUNT,
        });
    }

    if n.eq_ignore_ascii_case("SetHandleCount")
        || n.eq_ignore_ascii_case("OutputDebugStringA")
        || n.eq_ignore_ascii_case("OutputDebugStringW")
    {
        return Some(GuestStubKind::VoidRet);
    }
    if n.eq_ignore_ascii_case("GetTickCount") {
        return Some(GuestStubKind::ReturnImm32(12_345));
    }
    if n.eq_ignore_ascii_case("GetCurrentProcessId") {
        return Some(GuestStubKind::ReturnImm32(0x1234));
    }
    if n.eq_ignore_ascii_case("GetCurrentThreadId") {
        return Some(GuestStubKind::ReturnImm32(0x5678));
    }
    if n.eq_ignore_ascii_case("IsDebuggerPresent") {
        return Some(GuestStubKind::ReturnZero);
    }
    if n.eq_ignore_ascii_case("Sleep") {
        // Treat all Sleep as no-op (including non-zero); fine for editor path.
        return Some(GuestStubKind::VoidRet);
    }
    if n.eq_ignore_ascii_case("GetACP") {
        return Some(GuestStubKind::ReturnImm32(1252));
    }
    if n.eq_ignore_ascii_case("GetOEMCP") {
        return Some(GuestStubKind::ReturnImm32(437));
    }
    if n.eq_ignore_ascii_case("GetCurrentProcess") {
        // Windows process pseudohandle (HANDLE)(LONG_PTR)-1.
        return Some(GuestStubKind::ReturnImm64(u64::MAX));
    }
    if n.eq_ignore_ascii_case("GetProcessHeap") {
        // Matches RuntimeMemoryLayout::process_heap_handle default 0x5000_0000.
        return Some(GuestStubKind::ReturnImm64(0x0000_0000_5000_0000));
    }

    None
}

/// Writes guest stubs into the fake-API mapping and builds a stop-bit mask.
///
/// Bitmap: bit=1 means "host must stop here", bit=0 means passthrough (guest stub).
/// Initialized to all-ones (stop everywhere), then cleared over each stub body.
///
/// `helper_code_base` / `helper_code_size` is a region **outside** the fake-API
/// hook range for out-of-line helpers (e.g. FlsGetValue body).
pub(crate) fn plant_guest_stubs(
    engine: &mut dyn wie_cpu::CpuEngine,
    entries: &[crate::hooks::RuntimeFakeApiEntry],
    fake_api_base: u64,
    fake_api_size: usize,
    fls_table_va: u64,
    helper_code_base: u64,
    helper_code_size: usize,
) -> Result<Vec<u8>> {
    let mut stop_bitmap = vec![0xff_u8; fake_api_size.div_ceil(8)];

    let mut planted = 0_usize;
    let mut helper_cursor = helper_code_base;
    let helper_end = helper_code_base.saturating_add(helper_code_size as u64);

    for entry in entries {
        let Some(kind) = classify_guest_stub(&entry.library, &entry.name, fls_table_va) else {
            continue;
        };
        let body = kind.encode();
        let va = entry.fake_target_va;
        if va < fake_api_base {
            continue;
        }
        let offset = usize::try_from(va - fake_api_base)
            .context("guest stub VA offset does not fit usize")?;

        if kind.needs_out_of_line_helper() {
            // Plant body outside hook range; IAT slot gets mov rax,imm64; jmp rax.
            let body_len = body.len() as u64;
            if helper_cursor
                .checked_add(body_len)
                .is_none_or(|end| end > helper_end)
            {
                tracing::warn!(
                    name = %entry.name,
                    "guest stub helper region full; leaving host path"
                );
                continue;
            }
            engine
                .mem_write(helper_cursor, &body)
                .context("failed to write out-of-line guest stub body")?;
            let mut jmp = [0_u8; 12];
            jmp[0] = 0x48;
            jmp[1] = 0xb8;
            jmp[2..10].copy_from_slice(&helper_cursor.to_le_bytes());
            jmp[10] = 0xff;
            jmp[11] = 0xe0;
            if offset.checked_add(12).is_none_or(|end| end > fake_api_size) {
                continue;
            }
            engine
                .mem_write(va, &jmp)
                .context("failed to write guest stub entry jmp")?;
            for byte_off in offset..offset.saturating_add(12) {
                clear_bit(&mut stop_bitmap, byte_off);
            }
            helper_cursor = helper_cursor.saturating_add(body_len.saturating_add(15) & !15);
        } else {
            let len = body.len();
            if offset
                .checked_add(len)
                .is_none_or(|end| end > fake_api_size)
            {
                continue;
            }
            engine
                .mem_write(va, &body)
                .context("failed to write guest API stub bytes")?;
            for byte_off in offset..offset.saturating_add(len) {
                clear_bit(&mut stop_bitmap, byte_off);
            }
        }
        planted = planted.saturating_add(1);
    }

    tracing::debug!(planted, "planted in-guest WinAPI stubs");
    Ok(stop_bitmap)
}

fn clear_bit(bitmap: &mut [u8], bit_index: usize) {
    let byte = bit_index / 8;
    let bit = bit_index % 8;
    if let Some(slot) = bitmap.get_mut(byte) {
        *slot &= !(1_u8 << bit);
    }
}
