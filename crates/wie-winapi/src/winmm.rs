use anyhow::{Context, Result};

use crate::{WinApiHandlerResult, WinApiState};

/// Handles `WINMM.dll!timeGetTime`.
pub fn handle_time_get_time(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = state.tick_count;

    state.tick_count = state
        .tick_count
        .checked_add(16)
        .context("timeGetTime tick count overflow")?;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from timeGetTime")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}
