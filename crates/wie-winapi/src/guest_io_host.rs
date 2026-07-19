//! Host-side maintenance of the guest I/O handle table and file mirrors.
//!
//! Paired with the guest helpers installed by `wie-runtime::guest_io`.

use crate::WinApiState;
use anyhow::{Context, Result};

/// Maximum simultaneously accelerated open files (must match guest helper).
pub const GUEST_IO_MAX_SLOTS: usize = 128;

/// Bytes per slot (must match guest helper).
pub const GUEST_IO_SLOT_SIZE: usize = 40;

/// Slot flag: valid for guest fast path.
pub const GUEST_IO_FLAG_VALID: u64 = 1;

/// Publishes an open file into the guest handle table and file-data arena.
///
/// Looks up the file content inside `state` to avoid the caller having to clone
/// the (potentially large) byte Vec across a borrow boundary.
pub fn register_open_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    handle: u64,
) -> Result<()> {
    let Some(cfg) = state.guest_io.clone() else {
        return Ok(());
    };

    let size = match state.open_files.get(&handle) {
        Some(f) if f.streaming => return Ok(()), // large host streams stay on host path
        Some(f) => f.bytes.len(),
        None => return Ok(()),
    };

    if size == 0 {
        return Ok(());
    }

    let size_u64 = u64::try_from(size).context("file size does not fit u64")?;
    let aligned_size = size_u64.wrapping_add(15) & !15_u64;
    let data_va = state.guest_file_data_next;
    let file_end = cfg
        .file_data_base
        .checked_add(u64::try_from(cfg.file_data_size).unwrap_or(u64::MAX))
        .context("guest file arena end overflow")?;
    let Some(new_next) = data_va.checked_add(aligned_size.max(16)) else {
        return Ok(());
    };
    if new_next > file_end {
        tracing::debug!(handle, "guest I/O file arena full; host path only");
        return Ok(());
    }

    if let Some(file) = state.open_files.get(&handle) {
        engine
            .mem_write(data_va, &file.bytes)
            .context("failed to mirror file bytes into guest I/O arena")?;
    }

    let mut slot_index: Option<usize> = None;
    for i in 0..GUEST_IO_MAX_SLOTS {
        let Some(slot_va) = slot_va_at(cfg.table_va, i) else {
            continue;
        };
        let mut handle_bytes = [0_u8; 8];
        engine.mem_read(slot_va, &mut handle_bytes)?;
        let existing = u64::from_le_bytes(handle_bytes);
        if existing == 0 || existing == handle {
            slot_index = Some(i);
            break;
        }
    }
    let Some(i) = slot_index else {
        tracing::debug!(handle, "guest I/O handle table full; host path only");
        return Ok(());
    };

    let Some(slot_va) = slot_va_at(cfg.table_va, i) else {
        return Ok(());
    };
    write_u64(engine, slot_va, handle)?;
    write_u64(engine, slot_va.wrapping_add(8), data_va)?;
    write_u64(engine, slot_va.wrapping_add(16), size_u64)?;
    write_u64(engine, slot_va.wrapping_add(24), 0)?;
    write_u64(engine, slot_va.wrapping_add(32), GUEST_IO_FLAG_VALID)?;

    state.guest_file_data_next = new_next;

    if let Some(file) = state.open_files.get_mut(&handle) {
        file.guest_data_va = Some(data_va);
        file.guest_slot_index = Some(u32::try_from(i).unwrap_or(u32::MAX));
    }

    Ok(())
}

/// Clears a handle from the guest table.
pub fn unregister_open_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    handle: u64,
) -> Result<()> {
    let Some(cfg) = state.guest_io.as_ref() else {
        return Ok(());
    };
    let table_va = cfg.table_va;
    for i in 0..GUEST_IO_MAX_SLOTS {
        let Some(slot_va) = slot_va_at(table_va, i) else {
            continue;
        };
        let mut handle_bytes = [0_u8; 8];
        engine.mem_read(slot_va, &mut handle_bytes)?;
        if u64::from_le_bytes(handle_bytes) == handle {
            engine.mem_write(slot_va, &[0_u8; GUEST_IO_SLOT_SIZE])?;
            break;
        }
    }
    if let Some(file) = state.open_files.get_mut(&handle) {
        file.guest_data_va = None;
        file.guest_slot_index = None;
    }
    Ok(())
}

/// Syncs guest table cursor/size (and optional mirror bytes) from host state.
pub fn sync_slot_from_host(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    handle: u64,
) -> Result<()> {
    let Some(file) = state.open_files.get(&handle) else {
        return Ok(());
    };
    let Some(slot_i) = file.guest_slot_index else {
        return Ok(());
    };
    let Some(cfg) = state.guest_io.as_ref() else {
        return Ok(());
    };
    let Ok(slot_usize) = usize::try_from(slot_i) else {
        return Ok(());
    };
    let Some(slot_va) = slot_va_at(cfg.table_va, slot_usize) else {
        return Ok(());
    };
    let size = u64::try_from(file.bytes.len()).unwrap_or(0);
    write_u64(engine, slot_va.wrapping_add(16), size)?;
    write_u64(engine, slot_va.wrapping_add(24), file.cursor)?;
    if let Some(data_va) = file.guest_data_va
        && !file.bytes.is_empty()
    {
        engine.mem_write(data_va, &file.bytes)?;
    }
    Ok(())
}

fn write_u64(engine: &mut dyn wie_cpu::CpuEngine, va: u64, value: u64) -> Result<()> {
    engine
        .mem_write(va, &value.to_le_bytes())
        .with_context(|| format!("failed to write guest I/O u64 at {va:#x}"))
}

fn slot_va_at(table_va: u64, index: usize) -> Option<u64> {
    let offset = index.checked_mul(GUEST_IO_SLOT_SIZE)?;
    let offset_u64 = u64::try_from(offset).ok()?;
    table_va.checked_add(offset_u64)
}

/// Pulls cursor from guest table into host `OpenGuestFile` (before host fallback I/O).
pub fn sync_host_cursor_from_guest(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    handle: u64,
) -> Result<()> {
    let Some(cfg) = state.guest_io.clone() else {
        return Ok(());
    };
    let Some(file) = state.open_files.get_mut(&handle) else {
        return Ok(());
    };
    let Some(slot_i) = file.guest_slot_index else {
        return Ok(());
    };
    let Ok(slot_usize) = usize::try_from(slot_i) else {
        return Ok(());
    };
    let Some(slot_va) = slot_va_at(cfg.table_va, slot_usize) else {
        return Ok(());
    };
    let mut cursor_bytes = [0_u8; 8];
    engine.mem_read(slot_va.wrapping_add(24), &mut cursor_bytes)?;
    file.cursor = u64::from_le_bytes(cursor_bytes);
    Ok(())
}
