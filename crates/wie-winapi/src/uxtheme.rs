use anyhow::{Context, Result};

use crate::WinApiHandlerResult;

/// Handles dynamic `UXTHEME.dll!SetWindowTheme`.
pub fn handle_set_window_theme(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetWindowTheme")?;

    let _sub_app_name_ptr = engine
        .read_rdx()
        .context("failed to read RDX for SetWindowTheme")?;

    let _sub_id_list_ptr = engine
        .read_r8()
        .context("failed to read R8 for SetWindowTheme")?;

    // HRESULT S_OK.
    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetWindowTheme")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}
