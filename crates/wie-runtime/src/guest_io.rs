//! Universal guest-side file I/O acceleration (cache layer for KERNEL32 file APIs).
//!
//! ## Why this layer exists
//!
//! Small sequential `ReadFile` / `SetFilePointer` calls dominate host-stop count for
//! any PE that streams files (ROM loaders, resource readers, installers). A
//! ROM-specific hack would not scale; instead we accelerate the **generic**
//! KERNEL32 handle path that every Win32 program already uses.
//!
//! ## Architecture (program-agnostic)
//!
//! ```text
//!   CreateFile*  ──host──►  mirror bytes → guest arena
//!                           publish slot  → guest handle table
//!   ReadFile IAT ──jmp───►  guest helper (outside stop-bitmap)
//!        │                    ├─ known handle  → in-guest memcpy / cursor update
//!        └─ unknown ─────────► host fallback VA (hooked) → full host handler
//! ```
//!
//! 1. **Host remains source of truth** for open/create/close and non-mirrored ops.
//! 2. **Guest table** is a fixed-layout cache (handle → data_va, size, cursor, flags).
//! 3. **Helpers** live outside the fake-API stop range so Unicorn never exits the
//!    guest on the hot path; ABI-compliant (preserve RBX/RBP/RSI/RDI).
//! 4. **Fallback VAs** keep correctness for unregistered handles, bad seeks, etc.
//! 5. **Dual-path sync**: host Read/Seek refresh guest slots; host Read pulls cursor
//!    from the guest table before serving (if a mixed path is used).
//!
//! Scaling to other programs: same table + helpers apply to any PE whose IAT imports
//! these KERNEL32 exports. No per-ROM or per-app special cases.
//!
//! ## Wall-clock / CPU policy (`/usr/bin/time -lp`, user/real ≈ 99%)
//!
//! Host bulk `ReadFile` wins wall+user CPU vs in-guest `rep movsq`. Default:
//! **ReadFile host**, **Seek+GetFileSize guest**. `WIE_GUEST_IO=all` enables guest
//! Read too (large ≥64 B still hybrid→host). `WIE_GUEST_IO=0` → all host.

use crate::hooks::RuntimeFakeApiEntry;
use crate::memory::RuntimeMemoryLayout;
use anyhow::{Context, Result};
use std::collections::HashMap;
use wie_winapi::{resolve_winapi_id, WinApiId};

/// Maximum simultaneously accelerated open files.
pub const GUEST_IO_MAX_SLOTS: usize = 128;

/// Bytes per slot in the guest-visible table.
/// handle, data_va, size, cursor, flags — 5 × u64.
pub const GUEST_IO_SLOT_SIZE: usize = 40;

/// Guest-side I/O services configuration (also stored on `WinApiState` via layout).
#[derive(Debug, Clone)]
pub struct GuestIoConfig {
    pub table_va: u64,
    pub code_base: u64,
    pub file_data_base: u64,
    pub file_data_size: usize,
    pub readfile_impl_va: u64,
    pub setfp_impl_va: u64,
    pub getfs_impl_va: u64,
    pub readfile_fallback_va: u64,
    pub setfp_fallback_va: u64,
    pub getfs_fallback_va: u64,
}

impl GuestIoConfig {
    #[must_use]
    pub fn from_layout(layout: &RuntimeMemoryLayout) -> Self {
        let code_base = layout.guest_io_code_base;
        Self {
            table_va: layout.guest_io_table_base,
            code_base,
            file_data_base: layout.guest_file_data_base,
            file_data_size: layout.guest_file_data_size,
            // Code layout inside the helper region (fixed offsets).
            readfile_impl_va: code_base,
            setfp_impl_va: code_base + 0x200,
            getfs_impl_va: code_base + 0x400,
            // Fallbacks live in the hooked fake-API range (host must stop).
            readfile_fallback_va: layout.fake_api_base + 0xF100,
            setfp_fallback_va: layout.fake_api_base + 0xF110,
            getfs_fallback_va: layout.fake_api_base + 0xF120,
        }
    }
}

/// When false, still plants helpers/table (for host register path) but keeps
/// KERNEL32 ReadFile/SetFilePointer/GetFileSize on the host-stop path.
/// Override with `WIE_GUEST_IO=0` to force host path (debug A/B).
#[derive(Clone, Copy, Debug)]
struct GuestIoRewire {
    read: bool,
    seek: bool,
    size: bool,
}

fn guest_io_rewire() -> GuestIoRewire {
    // Wall/CPU default: host ReadFile; guest Seek+GetFileSize.
    // WIE_GUEST_IO=all|1 → guest Read too (hybrid large→host); =0 → all host.
    match std::env::var("WIE_GUEST_IO") {
        Ok(v) if matches!(v.as_str(), "0" | "false" | "off" | "no") => GuestIoRewire {
            read: false,
            seek: false,
            size: false,
        },
        Ok(v) if matches!(v.as_str(), "1" | "true" | "on" | "yes" | "all") => GuestIoRewire {
            read: true,
            seek: true,
            size: true,
        },
        Ok(v) => {
            let lower = v.to_ascii_lowercase();
            let parts: Vec<_> = lower.split([',', '+']).map(str::trim).collect();
            GuestIoRewire {
                read: parts.iter().any(|p| *p == "read" || *p == "readfile"),
                seek: parts.iter().any(|p| *p == "seek" || *p == "setfilepointer"),
                size: parts.iter().any(|p| *p == "size" || *p == "getfilesize"),
            }
        }
        _ => GuestIoRewire {
            read: false,
            seek: true,
            size: true,
        },
    }
}

/// Installs guest I/O helpers and rewires KERNEL32 file APIs to jump into them.
///
/// Extends `fake_api_entries` with host-fallback VAs and clears stop-bitmap bits for
/// the entry-point `jmp` stubs so Unicorn never leaves the guest for the fast path.
pub(crate) fn install_guest_io(
    engine: &mut dyn wie_cpu::CpuEngine,
    entries: &mut Vec<RuntimeFakeApiEntry>,
    by_va: &mut HashMap<u64, usize>,
    stop_bitmap: &mut [u8],
    layout: &RuntimeMemoryLayout,
) -> Result<GuestIoConfig> {
    let config = GuestIoConfig::from_layout(layout);

    // Zero the handle table.
    let table_bytes = vec![0_u8; GUEST_IO_MAX_SLOTS * GUEST_IO_SLOT_SIZE];
    engine
        .mem_write(config.table_va, &table_bytes)
        .context("failed to zero guest I/O handle table")?;

    // Write helper implementations.
    write_readfile_impl(engine, &config)?;
    write_setfilepointer_impl(engine, &config)?;
    write_getfilesize_impl(engine, &config)?;

    // Register host fallbacks (same handlers as the public exports).
    register_fallback(
        entries,
        by_va,
        config.readfile_fallback_va,
        "KERNEL32.dll",
        "ReadFile",
    );
    register_fallback(
        entries,
        by_va,
        config.setfp_fallback_va,
        "KERNEL32.dll",
        "SetFilePointer",
    );
    register_fallback(
        entries,
        by_va,
        config.getfs_fallback_va,
        "KERNEL32.dll",
        "GetFileSize",
    );

    let rewire = guest_io_rewire();
    let mut api = crate::guest_rewire::FakeApiRewire {
        engine,
        entries,
        stop_bitmap,
        fake_api_base: layout.fake_api_base,
        fake_api_size: layout.fake_api_size,
    };
    if rewire.read {
        api.rewire("KERNEL32.dll", "ReadFile", config.readfile_impl_va)?;
    }
    if rewire.seek {
        api.rewire("KERNEL32.dll", "SetFilePointer", config.setfp_impl_va)?;
    }
    if rewire.size {
        api.rewire("KERNEL32.dll", "GetFileSize", config.getfs_impl_va)?;
    }
    tracing::debug!(
        ?rewire,
        table = format_args!("{:#x}", config.table_va),
        code = format_args!("{:#x}", config.code_base),
        "installed guest I/O acceleration"
    );

    Ok(config)
}

fn register_fallback(
    entries: &mut Vec<RuntimeFakeApiEntry>,
    by_va: &mut HashMap<u64, usize>,
    va: u64,
    library: &str,
    name: &str,
) {
    if by_va.contains_key(&va) {
        return;
    }
    let winapi_id = resolve_winapi_id(library, name);
    let mut traits = winapi_id.map(WinApiId::traits).unwrap_or_default();
    // Fallbacks are host paths for I/O — mark noisy like the primary exports.
    if name.eq_ignore_ascii_case("ReadFile")
        || name.eq_ignore_ascii_case("SetFilePointer")
        || name.eq_ignore_ascii_case("GetFileSize")
    {
        traits.set_noisy(true);
    }
    let index = entries.len();
    entries.push(RuntimeFakeApiEntry {
        fake_target_va: va,
        library: library.to_owned(),
        name: name.to_owned(),
        iat_slot_va: 0,
        winapi_id,
        traits,
    });
    by_va.insert(va, index);
}

// ---------------------------------------------------------------------------
// Guest helpers (x86-64 / Win64 ABI)
// ---------------------------------------------------------------------------
//
// Win64 entry: RCX, RDX, R8, R9, stack; return in RAX; callee may clobber
// RAX,RCX,RDX,R8-R11. We also use RBX/RSI/RDI and save them.
//
// Table slot layout (40 bytes):
//   +0  handle
//   +8  data_va
//   +16 size
//   +24 cursor
//   +32 flags

fn write_readfile_impl(engine: &mut dyn wie_cpu::CpuEngine, config: &GuestIoConfig) -> Result<()> {
    let code = build_readfile_bytes(
        config.table_va,
        config.readfile_fallback_va,
        GUEST_IO_MAX_SLOTS as u64,
        GUEST_IO_SLOT_SIZE as u64,
    );
    engine
        .mem_write(config.readfile_impl_va, &code)
        .context("failed to write guest ReadFile impl")?;
    Ok(())
}

fn build_readfile_bytes(table: u64, fallback: u64, max_slots: u64, slot_size: u64) -> Vec<u8> {
    // Register plan:
    // r10 = handle (saved RCX)
    // r11 = buffer (saved RDX)
    // r8  = requested count (unchanged)
    // r9  = pBytesRead (unchanged)
    // rbx = index
    // rbp = &slot when found
    //
    // push rbx; push rbp; push rsi; push rdi
    // Wall-clock policy: large reads use host bulk mem_write (native memcpy).
    // Small reads stay in-guest (avoid stop tax). Threshold tunable via env later.
    const LARGE_READ_HOST_THRESHOLD: u32 = 64;

    let mut c = Vec::new();
    c.extend_from_slice(&[0x53, 0x55, 0x56, 0x57]); // push rbx,rbp,rsi,rdi
    c.extend_from_slice(&[0x49, 0x89, 0xca]); // mov r10, rcx
    c.extend_from_slice(&[0x49, 0x89, 0xd3]); // mov r11, rdx

    // if r8d >= THRESH → host fallback (before freelist scan)
    c.extend_from_slice(&[0x41, 0x81, 0xf8]); // cmp r8d, imm32
    c.extend_from_slice(&LARGE_READ_HOST_THRESHOLD.to_le_bytes());
    let jae_large_host = c.len();
    c.extend_from_slice(&[0x0f, 0x83, 0, 0, 0, 0]); // jae fallback

    c.extend_from_slice(&[0x31, 0xdb]); // xor ebx, ebx

    // loop:
    let loop_pos = c.len();
    // cmp rbx, imm32 max
    c.extend_from_slice(&[0x48, 0x81, 0xfb]);
    c.extend_from_slice(&(max_slots as u32).to_le_bytes());
    // jae fallback_abs via mov+jmp
    // We'll use: j <short> to end_loop_fail at bottom
    let jae_site = c.len();
    c.extend_from_slice(&[0x0f, 0x83, 0, 0, 0, 0]); // jae rel32 → fallback_path

    // rax = rbx * slot_size
    c.extend_from_slice(&[0x48, 0x89, 0xd8]); // mov rax, rbx
    debug_assert!(slot_size <= 127);
    c.extend_from_slice(&[0x48, 0x6b, 0xc0, slot_size as u8]); // imul rax, imm8
                                                               // rbp = table + rax
    c.extend_from_slice(&[0x48, 0xbd]); // mov rbp, imm64
    c.extend_from_slice(&table.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x01, 0xc5]); // add rbp, rax

    // cmp [rbp], r10
    c.extend_from_slice(&[0x4c, 0x39, 0x55, 0x00]); // cmp qword [rbp+0], r10
    let jne_site = c.len();
    c.extend_from_slice(&[0x75, 0x00]); // jne next

    // test byte/flags [rbp+32], 1
    c.extend_from_slice(&[0x48, 0xf7, 0x45, 0x20, 0x01, 0x00, 0x00, 0x00]); // test qword [rbp+32], 1
    let jz_site = c.len();
    c.extend_from_slice(&[0x74, 0x00]); // jz next

    // FOUND: rbp = &slot
    // rsi = data_va + cursor
    c.extend_from_slice(&[0x48, 0x8b, 0x75, 0x08]); // mov rsi, [rbp+8]
    c.extend_from_slice(&[0x48, 0x8b, 0x45, 0x18]); // mov rax, [rbp+24] cursor
    c.extend_from_slice(&[0x48, 0x01, 0xc6]); // add rsi, rax
                                              // rcx = size - cursor = avail
    c.extend_from_slice(&[0x48, 0x8b, 0x4d, 0x10]); // mov rcx, [rbp+16]
    c.extend_from_slice(&[0x48, 0x29, 0xc1]); // sub rcx, rax
                                              // if avail==0 or negative (JB): zero read
    let jb_zero = c.len();
    c.extend_from_slice(&[0x72, 0x00]); // jb zero_read (unsigned below)

    // n = min(r8d zero-extended, rcx) — nNumberOfBytesToRead is DWORD
    c.extend_from_slice(&[0x44, 0x89, 0xc0]); // mov eax, r8d
    c.extend_from_slice(&[0x48, 0x39, 0xc8]); // cmp rax, rcx
    c.extend_from_slice(&[0x76, 0x03]); // jbe 3
    c.extend_from_slice(&[0x48, 0x89, 0xc8]); // mov rax, rcx
                                              // rax = n; if n==0 → zero
    c.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax,rax
    let jz_zero = c.len();
    c.extend_from_slice(&[0x74, 0x00]);

    // memcpy dst=r11, src=rsi, n=rax — qword bulk + byte tail (Unicorn-friendly).
    //   push n; rdi=dst; rcx=n/8; rep movsq; rcx=n&7; rep movsb; pop n
    c.push(0x50); // push rax (n)
    c.extend_from_slice(&[0x4c, 0x89, 0xdf]); // mov rdi, r11
    c.extend_from_slice(&[0x48, 0x89, 0xc1]); // mov rcx, rax
    c.extend_from_slice(&[0x48, 0xc1, 0xe9, 0x03]); // shr rcx, 3
    c.push(0xfc); // cld
    c.extend_from_slice(&[0xf3, 0x48, 0xa5]); // rep movsq
    c.extend_from_slice(&[0x48, 0x8b, 0x0c, 0x24]); // mov rcx, [rsp] ; n
    c.extend_from_slice(&[0x48, 0x83, 0xe1, 0x07]); // and rcx, 7
    c.extend_from_slice(&[0xf3, 0xa4]); // rep movsb
    c.push(0x58); // pop rax (n)

    // cursor += n
    c.extend_from_slice(&[0x48, 0x01, 0x45, 0x18]); // add [rbp+24], rax

    // if r9 != 0: *r9 = n (32-bit)
    c.extend_from_slice(&[0x4d, 0x85, 0xc9]); // test r9, r9
    c.extend_from_slice(&[0x74, 0x03]); // jz skip
    c.extend_from_slice(&[0x41, 0x89, 0x01]); // mov [r9], eax
                                              // return TRUE
    c.extend_from_slice(&[0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00]); // mov rax, 1
                                                                      // epilogue
    let epilogue_pos = c.len();
    c.extend_from_slice(&[0x5f, 0x5e, 0x5d, 0x5b, 0xc3]); // pop rdi,rsi,rbp,rbx; ret

    // zero_read: n=0, still success
    let zero_pos = c.len();
    c.extend_from_slice(&[0x4d, 0x85, 0xc9]); // test r9,r9
    c.extend_from_slice(&[0x74, 0x07]); // skip 7-byte mov dword
    c.extend_from_slice(&[0x41, 0xc7, 0x01, 0x00, 0x00, 0x00, 0x00]); // mov dword [r9], 0
    c.extend_from_slice(&[0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00]); // mov rax, 1
                                                                      // jmp epilogue
    let jmp_epi1 = c.len();
    c.extend_from_slice(&[0xeb, 0x00]);

    // next:
    let next_pos = c.len();
    c.extend_from_slice(&[0x48, 0xff, 0xc3]); // inc rbx
                                              // jmp loop
    let jmp_loop = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]);

    // fallback_path:
    let fallback_pos = c.len();
    c.extend_from_slice(&[0x5f, 0x5e, 0x5d, 0x5b]); // pop
                                                    // restore args: rcx=handle was r10, rdx=buffer was r11
    c.extend_from_slice(&[0x4c, 0x89, 0xd1]); // mov rcx, r10
    c.extend_from_slice(&[0x4c, 0x89, 0xda]); // mov rdx, r11
                                              // r8, r9 unchanged
                                              // mov rax, fallback; jmp rax
    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&fallback.to_le_bytes());
    c.extend_from_slice(&[0xff, 0xe0]);

    // Patch relative offsets
    patch_rel32(&mut c, jae_large_host + 2, jae_large_host + 6, fallback_pos);
    patch_rel32(&mut c, jae_site + 2, jae_site + 6, fallback_pos);
    patch_rel8(&mut c, jne_site + 1, jne_site + 2, next_pos);
    patch_rel8(&mut c, jz_site + 1, jz_site + 2, next_pos);
    patch_rel8(&mut c, jb_zero + 1, jb_zero + 2, zero_pos);
    patch_rel8(&mut c, jz_zero + 1, jz_zero + 2, zero_pos);
    patch_rel8(&mut c, jmp_epi1 + 1, jmp_epi1 + 2, epilogue_pos);
    patch_rel32(&mut c, jmp_loop + 1, jmp_loop + 5, loop_pos);

    c
}

fn patch_rel32(code: &mut [u8], imm_at: usize, next_ip: usize, target: usize) {
    let rel = target as i32 - next_ip as i32;
    code[imm_at..imm_at + 4].copy_from_slice(&rel.to_le_bytes());
}

fn patch_rel8(code: &mut [u8], imm_at: usize, next_ip: usize, target: usize) {
    let rel = target as isize - next_ip as isize;
    assert!((-128..128).contains(&rel), "rel8 out of range {rel}");
    code[imm_at] = rel as i8 as u8;
}

fn write_setfilepointer_impl(
    engine: &mut dyn wie_cpu::CpuEngine,
    config: &GuestIoConfig,
) -> Result<()> {
    // RCX=handle, RDX=distance (signed low), R8=pHigh (optional), R9=method (0/1/2)
    //
    // Win64 non-volatile regs we touch: RBX, RBP, RSI — must save/restore.
    // Distance lives in RSI (signed); method in R11D; handle in R10.
    let table = config.table_va;
    let fallback = config.setfp_fallback_va;
    let max_slots = GUEST_IO_MAX_SLOTS as u64;
    let slot_size = GUEST_IO_SLOT_SIZE as u64;

    let mut c = Vec::new();
    // push rbx; push rbp; push rsi
    c.extend_from_slice(&[0x53, 0x55, 0x56]);
    // mov r10, rcx ; handle
    c.extend_from_slice(&[0x49, 0x89, 0xca]);
    // mov r11d, r9d ; method (low 32)
    c.extend_from_slice(&[0x45, 0x89, 0xcb]);
    // movsxd rsi, edx ; signed 32-bit distance → 64-bit
    c.extend_from_slice(&[0x48, 0x63, 0xf2]);
    // r8 = pHigh, r9 = method (kept for host fallback)

    // xor ebx,ebx
    c.extend_from_slice(&[0x31, 0xdb]);
    let loop_pos = c.len();
    c.extend_from_slice(&[0x48, 0x81, 0xfb]);
    c.extend_from_slice(&(max_slots as u32).to_le_bytes());
    let jae_fb = c.len();
    c.extend_from_slice(&[0x0f, 0x83, 0, 0, 0, 0]);

    c.extend_from_slice(&[0x48, 0x89, 0xd8]);
    c.extend_from_slice(&[0x48, 0x6b, 0xc0, slot_size as u8]);
    c.extend_from_slice(&[0x48, 0xbd]);
    c.extend_from_slice(&table.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x01, 0xc5]); // rbp = slot

    c.extend_from_slice(&[0x4c, 0x39, 0x55, 0x00]); // cmp [rbp], r10
    let jne = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    c.extend_from_slice(&[0x48, 0xf7, 0x45, 0x20, 0x01, 0x00, 0x00, 0x00]);
    let jz = c.len();
    c.extend_from_slice(&[0x74, 0x00]);

    // found: method in r11d: 0=BEGIN, 1=CURRENT, 2=END
    c.extend_from_slice(&[0x41, 0x83, 0xfb, 0x00]); // cmp r11d, 0
    let jne_not_begin = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    // BEGIN: new = distance
    c.extend_from_slice(&[0x48, 0x89, 0xf0]); // mov rax, rsi
    let jmp_store = c.len();
    c.extend_from_slice(&[0xeb, 0x00]);

    let not_begin = c.len();
    c.extend_from_slice(&[0x41, 0x83, 0xfb, 0x01]); // cmp r11d, 1
    let jne_not_cur = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    // CURRENT: cursor + distance
    c.extend_from_slice(&[0x48, 0x8b, 0x45, 0x18]);
    c.extend_from_slice(&[0x48, 0x01, 0xf0]); // add rax, rsi
    let jmp_store2 = c.len();
    c.extend_from_slice(&[0xeb, 0x00]);

    let not_cur = c.len();
    c.extend_from_slice(&[0x41, 0x83, 0xfb, 0x02]); // cmp r11d, 2
    let jne_bad = c.len();
    c.extend_from_slice(&[0x75, 0x00]); // bad method → fallback
                                        // END: size + distance
    c.extend_from_slice(&[0x48, 0x8b, 0x45, 0x10]); // mov rax, [size]
    c.extend_from_slice(&[0x48, 0x01, 0xf0]);

    let store = c.len();
    // Reject negative positions (match host SetFilePointer).
    c.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax, rax
    let js_fb = c.len();
    c.extend_from_slice(&[0x78, 0x00]); // js fallback
                                        // store cursor
    c.extend_from_slice(&[0x48, 0x89, 0x45, 0x18]); // mov [rbp+24], rax
                                                    // if r8 != 0: *r8 = high 32 bits of cursor
    c.extend_from_slice(&[0x4d, 0x85, 0xc0]); // test r8,r8
    c.extend_from_slice(&[0x74, 0x0a]); // skip 10 bytes
    c.extend_from_slice(&[0x48, 0x89, 0xc1]); // mov rcx, rax
    c.extend_from_slice(&[0x48, 0xc1, 0xe9, 0x20]); // shr rcx, 32
    c.extend_from_slice(&[0x41, 0x89, 0x08]); // mov [r8], ecx
                                              // return low 32 bits in eax (zero-extend)
    c.extend_from_slice(&[0x89, 0xc0]); // mov eax, eax
                                        // epilogue — restore RSI, RBP, RBX
    let epi = c.len();
    c.extend_from_slice(&[0x5e, 0x5d, 0x5b, 0xc3]); // pop rsi,rbp,rbx; ret

    let next = c.len();
    c.extend_from_slice(&[0x48, 0xff, 0xc3]); // inc rbx
    let jmp_loop = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]);

    let fb = c.len();
    c.extend_from_slice(&[0x5e, 0x5d, 0x5b]); // pop rsi,rbp,rbx
    c.extend_from_slice(&[0x4c, 0x89, 0xd1]); // mov rcx, r10
                                              // rdx still distance; r8 pHigh; r9 method — still valid
    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&fallback.to_le_bytes());
    c.extend_from_slice(&[0xff, 0xe0]);

    patch_rel32(&mut c, jae_fb + 2, jae_fb + 6, fb);
    patch_rel8(&mut c, jne + 1, jne + 2, next);
    patch_rel8(&mut c, jz + 1, jz + 2, next);
    patch_rel8(&mut c, jne_not_begin + 1, jne_not_begin + 2, not_begin);
    patch_rel8(&mut c, jmp_store + 1, jmp_store + 2, store);
    patch_rel8(&mut c, jne_not_cur + 1, jne_not_cur + 2, not_cur);
    patch_rel8(&mut c, jmp_store2 + 1, jmp_store2 + 2, store);
    patch_rel8(&mut c, jne_bad + 1, jne_bad + 2, fb);
    patch_rel8(&mut c, js_fb + 1, js_fb + 2, fb);
    patch_rel32(&mut c, jmp_loop + 1, jmp_loop + 5, loop_pos);
    let _ = epi;

    engine
        .mem_write(config.setfp_impl_va, &c)
        .context("failed to write guest SetFilePointer impl")?;
    Ok(())
}

fn write_getfilesize_impl(
    engine: &mut dyn wie_cpu::CpuEngine,
    config: &GuestIoConfig,
) -> Result<()> {
    // RCX=handle, RDX=pFileSizeHigh optional
    let table = config.table_va;
    let fallback = config.getfs_fallback_va;
    let max_slots = GUEST_IO_MAX_SLOTS as u64;
    let slot_size = GUEST_IO_SLOT_SIZE as u64;

    let mut c = Vec::new();
    c.extend_from_slice(&[0x53, 0x55]); // push rbx, rbp
    c.extend_from_slice(&[0x49, 0x89, 0xca]); // mov r10, rcx
    c.extend_from_slice(&[0x49, 0x89, 0xd3]); // mov r11, rdx  (pHigh)
    c.extend_from_slice(&[0x31, 0xdb]);
    let loop_pos = c.len();
    c.extend_from_slice(&[0x48, 0x81, 0xfb]);
    c.extend_from_slice(&(max_slots as u32).to_le_bytes());
    let jae_fb = c.len();
    c.extend_from_slice(&[0x0f, 0x83, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x48, 0x89, 0xd8]);
    c.extend_from_slice(&[0x48, 0x6b, 0xc0, slot_size as u8]);
    c.extend_from_slice(&[0x48, 0xbd]);
    c.extend_from_slice(&table.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x01, 0xc5]);
    c.extend_from_slice(&[0x4c, 0x39, 0x55, 0x00]);
    let jne = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    c.extend_from_slice(&[0x48, 0xf7, 0x45, 0x20, 0x01, 0x00, 0x00, 0x00]);
    let jz = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    // found
    c.extend_from_slice(&[0x48, 0x8b, 0x45, 0x10]); // mov rax, [size]
    c.extend_from_slice(&[0x4d, 0x85, 0xdb]); // test r11, r11
    c.extend_from_slice(&[0x74, 0x0a]); // skip 10 bytes
    c.extend_from_slice(&[0x48, 0x89, 0xc1]);
    c.extend_from_slice(&[0x48, 0xc1, 0xe9, 0x20]);
    c.extend_from_slice(&[0x41, 0x89, 0x0b]); // mov [r11], ecx
    c.extend_from_slice(&[0x89, 0xc0]); // mov eax,eax low
    let epi = c.len();
    c.extend_from_slice(&[0x5d, 0x5b, 0xc3]);
    let next = c.len();
    c.extend_from_slice(&[0x48, 0xff, 0xc3]);
    let jmp_loop = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]);
    let fb = c.len();
    c.extend_from_slice(&[0x5d, 0x5b]);
    c.extend_from_slice(&[0x4c, 0x89, 0xd1]); // rcx = handle
    c.extend_from_slice(&[0x4c, 0x89, 0xda]); // rdx = pHigh
    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&fallback.to_le_bytes());
    c.extend_from_slice(&[0xff, 0xe0]);

    patch_rel32(&mut c, jae_fb + 2, jae_fb + 6, fb);
    patch_rel8(&mut c, jne + 1, jne + 2, next);
    patch_rel8(&mut c, jz + 1, jz + 2, next);
    patch_rel32(&mut c, jmp_loop + 1, jmp_loop + 5, loop_pos);
    let _ = epi;

    engine
        .mem_write(config.getfs_impl_va, &c)
        .context("failed to write guest GetFileSize impl")?;
    Ok(())
}
