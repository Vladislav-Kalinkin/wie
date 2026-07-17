//! In-guest process-heap acceleration (program-agnostic).
//!
//! ## Design
//!
//! KERNEL32 `HeapAlloc` / `HeapFree` for the process heap are hot on every PE that
//! uses the CRT. Rather than a Lunar Magic special case we accelerate the common
//! Win32 pattern:
//!
//! 1. A **control block** in guest memory holds the bump cursor and 24 freelist heads
//!    (same size classes as `wie_winapi::GuestHeap`).
//! 2. Every block has an 8-byte **size header** immediately before the payload.
//! 3. Guest helpers service class-sized alloc/free without a host stop.
//! 4. Host `GuestHeap` uses the same control block when an engine is available so
//!    GDI/D3D allocations cannot collide with guest-side ones.
//! 5. Large sizes / wrong heap handle / exotic flags fall back to the hooked host path.

use crate::hooks::RuntimeFakeApiEntry;
use crate::memory::RuntimeMemoryLayout;
use anyhow::{Context, Result};
use std::collections::HashMap;
use wie_winapi::{WinApiId, resolve_winapi_id};

/// Must match `wie_winapi::guest_heap` size classes.
const HEAP_SIZE_CLASS_COUNT: usize = 24;
const SIZE_CLASSES: [u64; HEAP_SIZE_CLASS_COUNT] = [
    16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192,
    12288, 16384, 24576, 32768, 49152, 65536,
];
const LARGE_THRESHOLD: u64 = 65_536;

/// Control block: bump (u64) + freelist heads (24 × u64).
pub const HEAP_CTRL_SIZE: usize = 8 + HEAP_SIZE_CLASS_COUNT * 8;

#[derive(Debug, Clone)]
pub struct GuestHeapAccelConfig {
    pub ctrl_va: u64,
    pub heap_base: u64,
    pub heap_end: u64,
    pub process_heap_handle: u64,
    pub alloc_impl_va: u64,
    pub free_impl_va: u64,
    pub alloc_fallback_va: u64,
    pub free_fallback_va: u64,
}

impl GuestHeapAccelConfig {
    #[must_use]
    pub fn from_layout(layout: &RuntimeMemoryLayout) -> Self {
        let code = layout.guest_heap_code_base;
        let heap_end = layout
            .process_heap_base
            .saturating_add(layout.process_heap_size as u64);
        Self {
            ctrl_va: layout.guest_heap_ctrl_base,
            heap_base: layout.process_heap_base,
            heap_end,
            process_heap_handle: layout.process_heap_handle,
            alloc_impl_va: code,
            free_impl_va: code + 0x400,
            alloc_fallback_va: layout.fake_api_base + 0xF200,
            free_fallback_va: layout.fake_api_base + 0xF210,
        }
    }
}

/// Install guest HeapAlloc/HeapFree helpers and rewire process-heap IAT entries.
pub(crate) fn install_guest_heap_accel(
    engine: &mut dyn wie_cpu::CpuEngine,
    entries: &mut Vec<RuntimeFakeApiEntry>,
    by_va: &mut HashMap<u64, usize>,
    stop_bitmap: &mut [u8],
    layout: &RuntimeMemoryLayout,
) -> Result<GuestHeapAccelConfig> {
    let config = GuestHeapAccelConfig::from_layout(layout);

    // Zero control block; bump starts at heap_base.
    let mut ctrl = vec![0_u8; HEAP_CTRL_SIZE];
    ctrl[0..8].copy_from_slice(&config.heap_base.to_le_bytes());
    engine
        .mem_write(config.ctrl_va, &ctrl)
        .context("failed to init guest heap control block")?;

    write_heap_alloc_impl(engine, &config)?;
    write_heap_free_impl(engine, &config)?;

    register_fallback(
        entries,
        by_va,
        config.alloc_fallback_va,
        "KERNEL32.dll",
        "HeapAlloc",
    );
    register_fallback(
        entries,
        by_va,
        config.free_fallback_va,
        "KERNEL32.dll",
        "HeapFree",
    );

    // Default OFF for wall/CPU: host freelist is cheaper than dual guest path.
    // Opt in with WIE_GUEST_HEAP=1. Control block still planted for coherent host.
    let rewire = matches!(
        std::env::var("WIE_GUEST_HEAP").as_deref(),
        Ok("1" | "true" | "on" | "yes")
    );
    if rewire {
        let mut api = crate::guest_rewire::FakeApiRewire {
            engine,
            entries,
            stop_bitmap,
            fake_api_base: layout.fake_api_base,
            fake_api_size: layout.fake_api_size,
        };
        api.rewire("KERNEL32.dll", "HeapAlloc", config.alloc_impl_va)?;
        api.rewire("KERNEL32.dll", "HeapFree", config.free_impl_va)?;
    }

    tracing::debug!(
        rewire,
        ctrl = format_args!("{:#x}", config.ctrl_va),
        "installed guest heap acceleration"
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
    traits.set_noisy(true);
    let index = entries.len();
    entries.push(RuntimeFakeApiEntry {
        fake_target_va: va,
        library: library.into(),
        name: name.into(),
        iat_slot_va: 0,
        winapi_id,
        traits,
    });
    by_va.insert(va, index);
}

fn patch_rel32(code: &mut [u8], imm_at: usize, next_ip: usize, target: usize) {
    let rel = target as i32 - next_ip as i32;
    code[imm_at..imm_at + 4].copy_from_slice(&rel.to_le_bytes());
}

// --- HeapAlloc guest implementation ------------------------------------------------

fn write_heap_alloc_impl(
    engine: &mut dyn wie_cpu::CpuEngine,
    config: &GuestHeapAccelConfig,
) -> Result<()> {
    // RCX = hHeap, RDX = flags, R8 = size
    // Preserve: RBX, RBP, RSI, RDI (Win64 non-volatile)
    let mut c = Vec::new();
    c.extend_from_slice(&[0x53, 0x55, 0x56, 0x57]); // push rbx,rbp,rsi,rdi

    // Save args: r10=heap, r11=flags, use r8 size later as eax
    c.extend_from_slice(&[0x49, 0x89, 0xca]); // mov r10, rcx
    c.extend_from_slice(&[0x49, 0x89, 0xd3]); // mov r11, rdx

    // if heap != process_heap_handle → fallback
    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&config.process_heap_handle.to_le_bytes());
    c.extend_from_slice(&[0x4c, 0x39, 0xd0]); // cmp rax, r10
    let jne_fb1 = c.len();
    c.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jne fallback

    // size == 0 → return 0 (Windows may return non-null; we match host GuestHeap)
    c.extend_from_slice(&[0x4d, 0x85, 0xc0]); // test r8, r8
    let jz_zero = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz return_zero

    // rbx = rounded size (max(size,1) then class)
    c.extend_from_slice(&[0x4c, 0x89, 0xc3]); // mov rbx, r8
    // if size > LARGE_THRESHOLD → fallback (host handles large)
    c.extend_from_slice(&[0x48, 0x81, 0xfb]);
    c.extend_from_slice(&(LARGE_THRESHOLD as u32).to_le_bytes());
    let ja_large = c.len();
    c.extend_from_slice(&[0x0f, 0x87, 0, 0, 0, 0]); // ja fallback

    // Round up to size class into rbx; class index into ebp.
    // Use jbe rel32 — the unrolled table is larger than rel8 range.
    let mut class_jcc_sites: Vec<(usize, usize)> = Vec::new(); // (imm_at, class_i)
    let mut set_sites: Vec<usize> = Vec::new();
    for (i, &sz) in SIZE_CLASSES.iter().enumerate() {
        c.extend_from_slice(&[0x49, 0x81, 0xf8]); // cmp r8, imm32
        c.extend_from_slice(&(sz as u32).to_le_bytes());
        let jbe = c.len();
        c.extend_from_slice(&[0x0f, 0x86, 0, 0, 0, 0]); // jbe rel32 set_i
        class_jcc_sites.push((jbe + 2, i));
    }
    let ja_no_class = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp fallback

    let mut set_labels = [0_usize; HEAP_SIZE_CLASS_COUNT];
    for (i, &sz) in SIZE_CLASSES.iter().enumerate() {
        if let Some(slot) = set_labels.get_mut(i) {
            *slot = c.len();
        }
        c.extend_from_slice(&[0xbb]);
        c.extend_from_slice(&(sz as u32).to_le_bytes()); // mov ebx, class_size
        c.extend_from_slice(&[0xbd]);
        c.extend_from_slice(&(i as u32).to_le_bytes()); // mov ebp, class_index
        let jmp_done = c.len();
        c.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp rounded_done
        set_sites.push(jmp_done);
    }
    for (imm_at, i) in &class_jcc_sites {
        if let Some(&target) = set_labels.get(*i) {
            patch_rel32(&mut c, *imm_at, *imm_at + 4, target);
        }
    }

    let rounded_done = c.len();
    for jmp in &set_sites {
        patch_rel32(&mut c, jmp + 1, jmp + 5, rounded_done);
    }

    // rbp/ctrl: mov rsi, ctrl_va
    c.extend_from_slice(&[0x48, 0xbe]);
    c.extend_from_slice(&config.ctrl_va.to_le_bytes());
    // head = freelist[class] at ctrl+8+ebp*8
    c.extend_from_slice(&[0x48, 0x89, 0xe8]); // mov rax, rbp
    c.extend_from_slice(&[0x48, 0xc1, 0xe0, 0x03]); // shl rax, 3
    c.extend_from_slice(&[0x48, 0x8b, 0x4c, 0x06, 0x08]); // mov rcx, [rsi+rax+8]
    // if head == 0 → bump
    c.extend_from_slice(&[0x48, 0x85, 0xc9]); // test rcx, rcx
    let jz_bump = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz bump

    // Validate head ∈ [heap_base, heap_end) before dereferencing.
    c.extend_from_slice(&[0x48, 0xba]);
    c.extend_from_slice(&config.heap_base.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x39, 0xd1]); // cmp rcx, base
    let jb_bad_head = c.len();
    c.extend_from_slice(&[0x0f, 0x82, 0, 0, 0, 0]); // jb bump (corrupt head)
    c.extend_from_slice(&[0x48, 0xba]);
    c.extend_from_slice(&config.heap_end.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x39, 0xd1]); // cmp rcx, end
    let jae_bad_head = c.len();
    c.extend_from_slice(&[0x0f, 0x83, 0, 0, 0, 0]); // jae bump

    // pop freelist: next = [head]; freelist[class]=next; rdi=head
    c.extend_from_slice(&[0x48, 0x8b, 0x11]); // mov rdx, [rcx]
    c.extend_from_slice(&[0x48, 0x89, 0x54, 0x06, 0x08]); // mov [rsi+rax+8], rdx
    c.extend_from_slice(&[0x48, 0x89, 0xcf]); // mov rdi, rcx
    // ensure header size
    c.extend_from_slice(&[0x48, 0x89, 0x5f, 0xf8]); // mov [rdi-8], rbx
    let jmp_ret = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp ret_ptr

    // bump path
    let bump_pos = c.len();
    // rax = bump = [rsi]
    c.extend_from_slice(&[0x48, 0x8b, 0x06]); // mov rax, [rsi]
    // payload = align16(bump + 8)
    c.extend_from_slice(&[0x48, 0x83, 0xc0, 0x08]); // add rax, 8
    c.extend_from_slice(&[0x48, 0x83, 0xc0, 0x0f]); // add rax, 15
    c.extend_from_slice(&[0x48, 0x83, 0xe0, 0xf0]); // and rax, ~15
    c.extend_from_slice(&[0x48, 0x89, 0xc7]); // mov rdi, rax  ; payload
    // end = payload + rounded
    c.extend_from_slice(&[0x48, 0x89, 0xf9]); // mov rcx, rdi
    c.extend_from_slice(&[0x48, 0x01, 0xd9]); // add rcx, rbx
    // if end > heap_end → fallback (OOM)
    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&config.heap_end.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x39, 0xc1]); // cmp rcx, heap_end
    let ja_oom = c.len();
    c.extend_from_slice(&[0x0f, 0x87, 0, 0, 0, 0]); // ja fallback
    // write bump = end
    c.extend_from_slice(&[0x48, 0x89, 0x0e]); // mov [rsi], rcx
    // write size header
    c.extend_from_slice(&[0x48, 0x89, 0x5f, 0xf8]); // mov [rdi-8], rbx

    // Skip HEAP_ZERO_MEMORY: host path ignores zeroing too; Unicorn rep-stos is costly.
    let ret_ptr = c.len();
    c.extend_from_slice(&[0x48, 0x89, 0xf8]); // mov rax, rdi
    c.extend_from_slice(&[0x5f, 0x5e, 0x5d, 0x5b, 0xc3]); // pop; ret

    let return_zero = c.len();
    c.extend_from_slice(&[0x31, 0xc0]); // xor eax,eax
    c.extend_from_slice(&[0x5f, 0x5e, 0x5d, 0x5b, 0xc3]);

    let fallback = c.len();
    c.extend_from_slice(&[0x5f, 0x5e, 0x5d, 0x5b]); // pop
    c.extend_from_slice(&[0x4c, 0x89, 0xd1]); // mov rcx, r10
    c.extend_from_slice(&[0x4c, 0x89, 0xda]); // mov rdx, r11
    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&config.alloc_fallback_va.to_le_bytes());
    c.extend_from_slice(&[0xff, 0xe0]);

    patch_rel32(&mut c, jne_fb1 + 2, jne_fb1 + 6, fallback);
    patch_rel32(&mut c, jz_zero + 2, jz_zero + 6, return_zero);
    patch_rel32(&mut c, ja_large + 2, ja_large + 6, fallback);
    patch_rel32(&mut c, ja_no_class + 1, ja_no_class + 5, fallback);
    patch_rel32(&mut c, jz_bump + 2, jz_bump + 6, bump_pos);
    patch_rel32(&mut c, jb_bad_head + 2, jb_bad_head + 6, bump_pos);
    patch_rel32(&mut c, jae_bad_head + 2, jae_bad_head + 6, bump_pos);
    patch_rel32(&mut c, jmp_ret + 1, jmp_ret + 5, ret_ptr);
    patch_rel32(&mut c, ja_oom + 2, ja_oom + 6, fallback);

    engine
        .mem_write(config.alloc_impl_va, &c)
        .context("failed to write guest HeapAlloc impl")?;
    if c.len() >= 0x400 {
        anyhow::bail!("HeapAlloc guest impl too large: {} bytes", c.len());
    }
    Ok(())
}

fn write_heap_free_impl(
    engine: &mut dyn wie_cpu::CpuEngine,
    config: &GuestHeapAccelConfig,
) -> Result<()> {
    // RCX=hHeap, RDX=flags, R8=mem — r8 kept intact for host fallback.
    let mut c = Vec::new();
    c.extend_from_slice(&[0x53, 0x55, 0x56, 0x57]); // push rbx,rbp,rsi,rdi
    c.extend_from_slice(&[0x49, 0x89, 0xca]); // r10=heap
    c.extend_from_slice(&[0x49, 0x89, 0xd3]); // r11=flags
    c.extend_from_slice(&[0x4c, 0x89, 0xc7]); // rdi=mem

    c.extend_from_slice(&[0x48, 0x85, 0xff]); // test rdi,rdi
    let jz_ok = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz success

    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&config.process_heap_handle.to_le_bytes());
    c.extend_from_slice(&[0x4c, 0x39, 0xd0]); // cmp rax, r10
    let jne_fb = c.len();
    c.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);

    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&config.heap_base.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x39, 0xc7]); // cmp rdi, base
    let jb_fb = c.len();
    c.extend_from_slice(&[0x0f, 0x82, 0, 0, 0, 0]);

    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&config.heap_end.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x39, 0xc7]);
    let jae_fb = c.len();
    c.extend_from_slice(&[0x0f, 0x83, 0, 0, 0, 0]);

    c.extend_from_slice(&[0x48, 0x8b, 0x5f, 0xf8]); // rbx = [rdi-8] size
    c.extend_from_slice(&[0x48, 0x85, 0xdb]);
    let jz_fb = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x48, 0x81, 0xfb]);
    c.extend_from_slice(&(LARGE_THRESHOLD as u32).to_le_bytes());
    let ja_fb = c.len();
    c.extend_from_slice(&[0x0f, 0x87, 0, 0, 0, 0]);

    // Exact size-class match only (je) — refuse free of non-heap headers.
    let mut jbes: Vec<(usize, usize)> = Vec::new();
    for (i, &sz) in SIZE_CLASSES.iter().enumerate() {
        c.extend_from_slice(&[0x48, 0x81, 0xfb]);
        c.extend_from_slice(&(sz as u32).to_le_bytes());
        let je = c.len();
        c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // je rel32
        jbes.push((je + 2, i));
    }
    let jmp_fb2 = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]);

    let mut setc = [0_usize; HEAP_SIZE_CLASS_COUNT];
    let mut jmp_push = Vec::new();
    for (i, slot) in setc.iter_mut().enumerate() {
        *slot = c.len();
        c.extend_from_slice(&[0xbd]);
        c.extend_from_slice(&(u32::try_from(i).unwrap_or(0)).to_le_bytes());
        let j = c.len();
        c.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp push_free rel32
        jmp_push.push(j);
    }
    for (imm, i) in &jbes {
        if let Some(&target) = setc.get(*i) {
            patch_rel32(&mut c, *imm, *imm + 4, target);
        }
    }

    let push_free = c.len();
    for j in &jmp_push {
        patch_rel32(&mut c, j + 1, j + 5, push_free);
    }

    c.extend_from_slice(&[0x48, 0xbe]);
    c.extend_from_slice(&config.ctrl_va.to_le_bytes());
    c.extend_from_slice(&[0x48, 0x89, 0xe8]); // mov rax, rbp
    c.extend_from_slice(&[0x48, 0xc1, 0xe0, 0x03]); // shl rax, 3
    c.extend_from_slice(&[0x48, 0x8b, 0x4c, 0x06, 0x08]); // mov rcx, [rsi+rax+8]
    c.extend_from_slice(&[0x48, 0x89, 0x0f]); // mov [rdi], rcx
    c.extend_from_slice(&[0x48, 0x89, 0x7c, 0x06, 0x08]); // mov [rsi+rax+8], rdi
    // Zero size header so a second free (or host free_coherent) sees double-free.
    c.extend_from_slice(&[0x48, 0xc7, 0x47, 0xf8, 0x00, 0x00, 0x00, 0x00]); // mov qword [rdi-8], 0

    let success = c.len();
    c.extend_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]);
    c.extend_from_slice(&[0x5f, 0x5e, 0x5d, 0x5b, 0xc3]);

    let fallback = c.len();
    c.extend_from_slice(&[0x5f, 0x5e, 0x5d, 0x5b]);
    c.extend_from_slice(&[0x4c, 0x89, 0xd1]); // rcx = heap
    c.extend_from_slice(&[0x4c, 0x89, 0xda]); // rdx = flags
    // r8 still original mem
    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&config.free_fallback_va.to_le_bytes());
    c.extend_from_slice(&[0xff, 0xe0]);

    patch_rel32(&mut c, jz_ok + 2, jz_ok + 6, success);
    patch_rel32(&mut c, jne_fb + 2, jne_fb + 6, fallback);
    patch_rel32(&mut c, jb_fb + 2, jb_fb + 6, fallback);
    patch_rel32(&mut c, jae_fb + 2, jae_fb + 6, fallback);
    patch_rel32(&mut c, jz_fb + 2, jz_fb + 6, fallback);
    patch_rel32(&mut c, ja_fb + 2, ja_fb + 6, fallback);
    patch_rel32(&mut c, jmp_fb2 + 1, jmp_fb2 + 5, fallback);

    engine
        .mem_write(config.free_impl_va, &c)
        .context("failed to write guest HeapFree impl")?;
    if c.len() >= 0x400 {
        anyhow::bail!("HeapFree guest impl too large: {} bytes", c.len());
    }
    Ok(())
}
