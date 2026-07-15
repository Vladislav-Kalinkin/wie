//! Guest acceleration for `MultiByteToWideChar` (single-byte code pages).
//!
//! ## Design (program-agnostic)
//!
//! Many PE binaries call `MultiByteToWideChar` heavily for ACP/ANSI paths. For
//! single-byte code pages (CP_ACP=0, 1252, 437) each input byte maps to one
//! UTF-16 code unit via zero-extension. Multi-byte pages (CP_UTF8=65001, …)
//! fall back to the host handler.

use crate::hooks::RuntimeFakeApiEntry;
use crate::memory::RuntimeMemoryLayout;
use anyhow::{Context, Result};
use std::collections::HashMap;
use wie_winapi::{resolve_winapi_id, WinApiId};

#[derive(Debug, Clone)]
pub struct GuestMbwcConfig {
    pub impl_va: u64,
    pub fallback_va: u64,
}

impl GuestMbwcConfig {
    #[must_use]
    pub fn from_layout(layout: &RuntimeMemoryLayout) -> Self {
        Self {
            impl_va: layout.guest_mbwc_code_base,
            fallback_va: layout.fake_api_base + 0xF300,
        }
    }
}

pub(crate) fn install_guest_mbwc(
    engine: &mut dyn wie_cpu::CpuEngine,
    entries: &mut Vec<RuntimeFakeApiEntry>,
    by_va: &mut HashMap<u64, usize>,
    stop_bitmap: &mut [u8],
    layout: &RuntimeMemoryLayout,
) -> Result<GuestMbwcConfig> {
    let config = GuestMbwcConfig::from_layout(layout);
    write_mbwc_impl(engine, &config)?;

    register_fallback(
        entries,
        by_va,
        config.fallback_va,
        "KERNEL32.dll",
        "MultiByteToWideChar",
    );

    // Default OFF: per-character expand in Unicorn is slower wall-clock than one
    // host stop + bulk mem_write for WIE's CP_UTF8 traffic. Opt in with WIE_GUEST_MBWC=1.
    let rewire = matches!(
        std::env::var("WIE_GUEST_MBWC").as_deref(),
        Ok("1" | "true" | "on" | "yes")
    );
    if rewire {
        crate::guest_rewire::FakeApiRewire {
            engine,
            entries,
            stop_bitmap,
            fake_api_base: layout.fake_api_base,
            fake_api_size: layout.fake_api_size,
        }
        .rewire("KERNEL32.dll", "MultiByteToWideChar", config.impl_va)?;
    }

    tracing::debug!(
        rewire,
        impl_va = format_args!("{:#x}", config.impl_va),
        "installed guest MultiByteToWideChar acceleration"
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
        library: library.to_owned(),
        name: name.to_owned(),
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

fn patch_rel8(code: &mut [u8], imm_at: usize, next_ip: usize, target: usize) {
    let rel = target as isize - next_ip as isize;
    assert!((-128..128).contains(&rel), "rel8 out of range {rel}");
    code[imm_at] = rel as i8 as u8;
}

fn write_mbwc_impl(engine: &mut dyn wie_cpu::CpuEngine, config: &GuestMbwcConfig) -> Result<()> {
    // Win64: RCX=CodePage, RDX=dwFlags, R8=lpMultiByteStr, R9=cbMultiByte
    // stack @ entry: lpWideCharStr +0x28, cchWideChar +0x30
    // push rbx,rsi,rdi,r12 → +0x20 → args at +0x48 / +0x50
    // r10d=codepage, r12=cbMultiByte, r11b=1 if UTF-8 needs ASCII check

    let mut c = Vec::new();
    c.extend_from_slice(&[0x53, 0x56, 0x57, 0x41, 0x54]); // rbx rsi rdi r12
    c.extend_from_slice(&[0x41, 0x89, 0xca]); // r10d = ecx
    c.extend_from_slice(&[0x4d, 0x89, 0xcc]); // r12 = r9

    // Classify CP → r11b: 0=SBCS ok, 1=UTF-8 (ASCII-only), else fallback
    c.extend_from_slice(&[0x41, 0x83, 0xfa, 0x04]); // cmp r10d, 4
    let jb_sbcs = c.len();
    c.extend_from_slice(&[0x0f, 0x82, 0, 0, 0, 0]); // jb → sbcs_flag
    c.extend_from_slice(&[0x41, 0x81, 0xfa]);
    c.extend_from_slice(&1252_u32.to_le_bytes());
    let je_1252 = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x41, 0x81, 0xfa]);
    c.extend_from_slice(&437_u32.to_le_bytes());
    let je_437 = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x41, 0x81, 0xfa]);
    c.extend_from_slice(&65001_u32.to_le_bytes());
    let je_utf8 = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);
    let j_fb0 = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]);

    let sbcs_flag = c.len();
    c.extend_from_slice(&[0x41, 0xb3, 0x00]); // mov r11b, 0
    let j_got_flag = c.len();
    c.extend_from_slice(&[0xeb, 0x00]);

    let utf8_flag = c.len();
    c.extend_from_slice(&[0x41, 0xb3, 0x01]); // mov r11b, 1

    let got_flag = c.len();
    c.extend_from_slice(&[0x4c, 0x89, 0xc6]); // rsi = r8 src
    c.extend_from_slice(&[0x48, 0x85, 0xf6]);
    let jz_src0 = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);

    c.extend_from_slice(&[0x41, 0x83, 0xfc, 0xff]); // cmp r12d, -1
    let jne_fixed = c.len();
    c.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]);

    c.extend_from_slice(&[0x31, 0xdb]);
    let sl_loop = c.len();
    c.extend_from_slice(&[0x0f, 0xb6, 0x04, 0x1e]);
    c.extend_from_slice(&[0x48, 0xff, 0xc3]);
    c.extend_from_slice(&[0x84, 0xc0]);
    let jnz_sl = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    c.extend_from_slice(&[0x48, 0x81, 0xfb]);
    c.extend_from_slice(&32768_u32.to_le_bytes());
    let ja_long = c.len();
    c.extend_from_slice(&[0x0f, 0x87, 0, 0, 0, 0]);
    let j_hlen = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]);

    let fixed = c.len();
    c.extend_from_slice(&[0x45, 0x85, 0xe4]);
    let js_neg = c.len();
    c.extend_from_slice(&[0x0f, 0x88, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x44, 0x89, 0xe3]);
    c.extend_from_slice(&[0x85, 0xdb]);
    let jz_zlen = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);

    let hlen = c.len();
    // UTF-8: reject if any high bit in [rsi, rsi+rbx)
    c.extend_from_slice(&[0x45, 0x84, 0xdb]); // test r11b, r11b
    let jz_skip_ascii = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x51]); // push rcx
    c.extend_from_slice(&[0x48, 0x89, 0xd9]); // rcx = len
    c.extend_from_slice(&[0x48, 0x89, 0xf0]); // rax = src
    let asc = c.len();
    c.extend_from_slice(&[0xf6, 0x00, 0x80]); // test byte [rax], 0x80
    let jnz_non_ascii = c.len();
    c.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jnz → pop+fallback
    c.extend_from_slice(&[0x48, 0xff, 0xc0]); // inc rax
    c.extend_from_slice(&[0x48, 0xff, 0xc9]); // dec rcx
    let jnz_asc = c.len();
    c.extend_from_slice(&[0x75, 0x00]);
    c.push(0x59); // pop rcx
    let j_after_asc = c.len();
    c.extend_from_slice(&[0xeb, 0x00]);

    let non_ascii = c.len();
    c.push(0x59); // pop rcx
    let j_fb_utf8 = c.len();
    c.extend_from_slice(&[0xe9, 0, 0, 0, 0]);

    let after_asc = c.len();
    // dest / cch
    c.extend_from_slice(&[0x4c, 0x8b, 0x4c, 0x24, 0x48]);
    c.extend_from_slice(&[0x44, 0x8b, 0x5c, 0x24, 0x50]);

    c.extend_from_slice(&[0x4d, 0x85, 0xc9]);
    let jz_rlen = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x45, 0x85, 0xdb]);
    let jz_rlen2 = c.len();
    c.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]);

    c.extend_from_slice(&[0x44, 0x39, 0xdb]);
    let ja_small = c.len();
    c.extend_from_slice(&[0x0f, 0x87, 0, 0, 0, 0]);

    c.extend_from_slice(&[0x48, 0x89, 0xd9]);
    c.extend_from_slice(&[0x4c, 0x89, 0xcf]);
    c.push(0xfc);
    let exp = c.len();
    c.extend_from_slice(&[0x0f, 0xb6, 0x06]);
    c.extend_from_slice(&[0x48, 0xff, 0xc6]);
    c.extend_from_slice(&[0x66, 0xab]);
    c.extend_from_slice(&[0x48, 0xff, 0xc9]);
    let jnz_exp = c.len();
    c.extend_from_slice(&[0x75, 0x00]);

    let rlen = c.len();
    c.extend_from_slice(&[0x89, 0xd8]);
    c.extend_from_slice(&[0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3]);

    let r0 = c.len();
    c.extend_from_slice(&[0x31, 0xc0]);
    c.extend_from_slice(&[0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3]);

    let fb = c.len();
    c.extend_from_slice(&[0x44, 0x89, 0xd1]); // ecx = codepage
    c.extend_from_slice(&[0x4d, 0x89, 0xe1]); // r9 = cb
    c.extend_from_slice(&[0x41, 0x5c, 0x5f, 0x5e, 0x5b]);
    c.extend_from_slice(&[0x48, 0xb8]);
    c.extend_from_slice(&config.fallback_va.to_le_bytes());
    c.extend_from_slice(&[0xff, 0xe0]);

    patch_rel32(&mut c, jb_sbcs + 2, jb_sbcs + 6, sbcs_flag);
    patch_rel32(&mut c, je_1252 + 2, je_1252 + 6, sbcs_flag);
    patch_rel32(&mut c, je_437 + 2, je_437 + 6, sbcs_flag);
    patch_rel32(&mut c, je_utf8 + 2, je_utf8 + 6, utf8_flag);
    patch_rel32(&mut c, j_fb0 + 1, j_fb0 + 5, fb);
    patch_rel8(&mut c, j_got_flag + 1, j_got_flag + 2, got_flag);
    patch_rel32(&mut c, jz_src0 + 2, jz_src0 + 6, r0);
    patch_rel32(&mut c, jne_fixed + 2, jne_fixed + 6, fixed);
    patch_rel8(&mut c, jnz_sl + 1, jnz_sl + 2, sl_loop);
    patch_rel32(&mut c, ja_long + 2, ja_long + 6, fb);
    patch_rel32(&mut c, j_hlen + 1, j_hlen + 5, hlen);
    patch_rel32(&mut c, js_neg + 2, js_neg + 6, fb);
    patch_rel32(&mut c, jz_zlen + 2, jz_zlen + 6, r0);
    patch_rel32(&mut c, jz_skip_ascii + 2, jz_skip_ascii + 6, after_asc);
    patch_rel32(&mut c, jnz_non_ascii + 2, jnz_non_ascii + 6, non_ascii);
    patch_rel8(&mut c, jnz_asc + 1, jnz_asc + 2, asc);
    patch_rel8(&mut c, j_after_asc + 1, j_after_asc + 2, after_asc);
    patch_rel32(&mut c, j_fb_utf8 + 1, j_fb_utf8 + 5, fb);
    patch_rel32(&mut c, jz_rlen + 2, jz_rlen + 6, rlen);
    patch_rel32(&mut c, jz_rlen2 + 2, jz_rlen2 + 6, rlen);
    patch_rel32(&mut c, ja_small + 2, ja_small + 6, r0);
    patch_rel8(&mut c, jnz_exp + 1, jnz_exp + 2, exp);

    engine
        .mem_write(config.impl_va, &c)
        .context("failed to write guest MultiByteToWideChar impl")?;
    if c.len() >= 0x400 {
        anyhow::bail!("MBWC guest impl too large: {} bytes", c.len());
    }
    Ok(())
}
