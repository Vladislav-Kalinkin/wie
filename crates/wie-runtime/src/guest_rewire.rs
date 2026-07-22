//! Shared helpers: plant IAT jmp trampolines and clear stop-bitmap bits.
//!
//! Used by guest I/O / heap / MBWC accelerators so each module does not
//! reimplement the same rewire dance.

use crate::hooks::RuntimeFakeApiEntry;
use anyhow::{Context, Result};
use wie_winapi::{encode_export, resolve_winapi_id};

/// Context for rewriting one fake-API export to an in-guest implementation.
pub(crate) struct FakeApiRewire<'a> {
    pub engine: &'a mut dyn wie_cpu::CpuEngine,
    pub entries: &'a [RuntimeFakeApiEntry],
    pub stop_bitmap: &'a mut [u8],
    pub fake_api_base: u64,
    pub fake_api_size: usize,
}

impl FakeApiRewire<'_> {
    /// Plant `mov rax,imm64; jmp rax` at the dense fake VA for `library!name`.
    pub(crate) fn rewire(&mut self, library: &str, name: &str, target_va: u64) -> Result<()> {
        let from =
            if let Some(id) = resolve_winapi_id(library, name) {
                encode_export(id)
            } else if let Some(entry) = self.entries.iter().find(|e| {
                e.library.eq_ignore_ascii_case(library) && e.name.eq_ignore_ascii_case(name)
            }) {
                entry.fake_target_va
            } else {
                tracing::debug!(library, name, "guest rewire: export not in IAT, skip");
                return Ok(());
            };

        plant_jmp_abs64(self.engine, from, target_va)?;
        // 12-byte absolute jmp: mark all bytes as guest passthrough.
        clear_stop_bits(
            self.stop_bitmap,
            self.fake_api_base,
            self.fake_api_size,
            from,
            12,
        );
        Ok(())
    }
}

/// `mov rax, imm64; jmp rax` (12 bytes) — works across the full 64-bit VA space.
pub(crate) fn plant_jmp_abs64(
    engine: &mut dyn wie_cpu::CpuEngine,
    from_va: u64,
    to_va: u64,
) -> Result<()> {
    let mut bytes = [0_u8; 12];
    bytes[0] = 0x48; // REX.W
    bytes[1] = 0xb8; // mov rax, imm64
    bytes[2..10].copy_from_slice(&to_va.to_le_bytes());
    bytes[10] = 0xff;
    bytes[11] = 0xe0; // jmp rax
    engine
        .mem_write(from_va, &bytes)
        .with_context(|| format!("failed to plant jmp at {from_va:#x} -> {to_va:#x}"))?;
    Ok(())
}

/// Clear `len` bits in the stop bitmap starting at guest `va` (1 = host stop).
pub(crate) fn clear_stop_bits(
    stop_bitmap: &mut [u8],
    fake_api_base: u64,
    fake_api_size: usize,
    va: u64,
    len: usize,
) {
    if va < fake_api_base {
        return;
    }
    let Ok(offset) = usize::try_from(va - fake_api_base) else {
        return;
    };
    for i in 0..len {
        let bit_index = offset.saturating_add(i);
        if bit_index >= fake_api_size {
            break;
        }
        let byte = bit_index >> 3;
        let bit = bit_index & 7;
        if let Some(slot) = stop_bitmap.get_mut(byte) {
            *slot &= !(1_u8 << bit);
        }
    }
}
