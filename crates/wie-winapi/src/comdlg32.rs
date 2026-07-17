//! Common dialog stubs (`comdlg32.dll`) for open/save file simulation.

use crate::guest_memory::{
    checked_field_address, read_u32 as read_guest_u32, read_u64 as read_guest_u64,
    write_u16 as write_guest_u16,
};
use crate::guest_string::{write_ansi_c_string, write_utf16_c_string};
use crate::{FileDialogPolicy, WinApiHandlerResult, WinApiState};
use anyhow::{Context, Result};

/// `OPENFILENAME` field offsets on Win64 (8-byte pointer alignment).
const OFN_LPSTR_FILE: u64 = 48;
const OFN_NMAX_FILE: u64 = 56;
const OFN_LPSTR_FILE_TITLE: u64 = 64;
const OFN_NMAX_FILE_TITLE: u64 = 72;
const OFN_FLAGS: u64 = 96;
const OFN_NFILE_OFFSET: u64 = 100;
const OFN_NFILE_EXTENSION: u64 = 102;

/// No extended common-dialog error.
const CDERR_NONE: u32 = 0;

/// Handles `comdlg32.dll!GetOpenFileNameA`.
pub fn handle_get_open_file_name_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    handle_get_file_name(engine, state, false, "GetOpenFileNameA")
}

/// Handles `comdlg32.dll!GetOpenFileNameW`.
pub fn handle_get_open_file_name_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    handle_get_file_name(engine, state, true, "GetOpenFileNameW")
}

/// Handles `comdlg32.dll!GetSaveFileNameA`.
pub fn handle_get_save_file_name_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    handle_get_file_name(engine, state, false, "GetSaveFileNameA")
}

/// Handles `comdlg32.dll!GetSaveFileNameW`.
pub fn handle_get_save_file_name_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    handle_get_file_name(engine, state, true, "GetSaveFileNameW")
}

/// Handles `comdlg32.dll!CommDlgExtendedError`.
pub fn handle_comm_dlg_extended_error(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = u64::from(state.comm_dlg_extended_error);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from CommDlgExtendedError")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `comdlg32.dll!ChooseColorA` (simulates accept with black color).
pub fn handle_choose_color_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let choose_color_ptr = engine
        .read_rcx()
        .context("failed to read RCX for ChooseColorA")?;

    state.comm_dlg_extended_error = CDERR_NONE;

    // CHOOSECOLORA has rgbResult at offset 0x10 (after lStructSize + hwndOwner + hInstance).
    if choose_color_ptr != 0 {
        // Write default RGB color (black) into rgbResult field.
        let rgb_field = choose_color_ptr.wrapping_add(0x10);
        drop(crate::guest_memory::write_u32(
            engine, rgb_field, 0x00_00_00,
        ));
    }

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from ChooseColorA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

fn handle_get_file_name(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    unicode: bool,
    api_name: &str,
) -> Result<WinApiHandlerResult> {
    let ofn_ptr = engine
        .read_rcx()
        .with_context(|| format!("failed to read RCX for {api_name}"))?;

    if ofn_ptr == 0 {
        state.comm_dlg_extended_error = CDERR_NONE;
        let return_address = engine
            .return_from_win64_api(0)
            .with_context(|| format!("failed to return from {api_name}"))?;

        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    let file_buffer_ptr = read_guest_u64(
        engine,
        checked_field_address(ofn_ptr, OFN_LPSTR_FILE, "OPENFILENAME.lpstrFile")?,
    )
    .with_context(|| format!("failed to read lpstrFile for {api_name}"))?;

    let max_file = read_guest_u32(
        engine,
        checked_field_address(ofn_ptr, OFN_NMAX_FILE, "OPENFILENAME.nMaxFile")?,
    )
    .with_context(|| format!("failed to read nMaxFile for {api_name}"))?;

    let file_title_ptr = read_guest_u64(
        engine,
        checked_field_address(ofn_ptr, OFN_LPSTR_FILE_TITLE, "OPENFILENAME.lpstrFileTitle")?,
    )
    .with_context(|| format!("failed to read lpstrFileTitle for {api_name}"))?;

    let max_file_title = read_guest_u32(
        engine,
        checked_field_address(ofn_ptr, OFN_NMAX_FILE_TITLE, "OPENFILENAME.nMaxFileTitle")?,
    )
    .with_context(|| format!("failed to read nMaxFileTitle for {api_name}"))?;

    let return_value = match &state.file_dialog_policy {
        FileDialogPolicy::Cancel => {
            state.comm_dlg_extended_error = CDERR_NONE;
            tracing::debug!(api = api_name, "file dialog cancelled by policy");
            0
        }

        FileDialogPolicy::Accept { path } => {
            if file_buffer_ptr == 0 || max_file == 0 {
                state.comm_dlg_extended_error = CDERR_NONE;
                tracing::warn!(
                    api = api_name,
                    "file dialog accept policy but lpstrFile/nMaxFile invalid"
                );
                0
            } else {
                write_selected_path(
                    engine,
                    &SelectedPathWrite {
                        ofn_ptr,
                        file_buffer_ptr,
                        max_file,
                        file_title_ptr,
                        max_file_title,
                        path,
                        unicode,
                    },
                )
                .with_context(|| format!("failed to write selected path for {api_name}"))?;

                state.comm_dlg_extended_error = CDERR_NONE;
                state.last_file_dialog_path = Some(path.clone());

                tracing::info!(api = api_name, %path, unicode, "file dialog accepted");
                1
            }
        }
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .with_context(|| format!("failed to return from {api_name}"))?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

struct SelectedPathWrite<'a> {
    ofn_ptr: u64,
    file_buffer_ptr: u64,
    max_file: u32,
    file_title_ptr: u64,
    max_file_title: u32,
    path: &'a str,
    unicode: bool,
}

fn write_selected_path(
    engine: &mut dyn wie_cpu::CpuEngine,
    request: &SelectedPathWrite<'_>,
) -> Result<()> {
    let max_file_chars =
        usize::try_from(request.max_file).context("OPENFILENAME.nMaxFile does not fit usize")?;

    if request.unicode {
        write_utf16_c_string(
            engine,
            request.file_buffer_ptr,
            max_file_chars,
            request.path,
        )
        .context("failed to write Unicode lpstrFile")?;
    } else {
        write_ansi_c_string(
            engine,
            request.file_buffer_ptr,
            max_file_chars,
            request.path,
        )
        .context("failed to write ANSI lpstrFile")?;
    }

    let (file_name, file_offset, extension_offset) = split_path_components(request.path);

    if request.file_title_ptr != 0 && request.max_file_title != 0 {
        let max_title_chars = usize::try_from(request.max_file_title)
            .context("OPENFILENAME.nMaxFileTitle does not fit usize")?;

        if request.unicode {
            write_utf16_c_string(engine, request.file_title_ptr, max_title_chars, file_name)
                .context("failed to write Unicode lpstrFileTitle")?;
        } else {
            write_ansi_c_string(engine, request.file_title_ptr, max_title_chars, file_name)
                .context("failed to write ANSI lpstrFileTitle")?;
        }
    }

    write_guest_u16(
        engine,
        checked_field_address(
            request.ofn_ptr,
            OFN_NFILE_OFFSET,
            "OPENFILENAME.nFileOffset",
        )?,
        file_offset,
    )?;

    write_guest_u16(
        engine,
        checked_field_address(
            request.ofn_ptr,
            OFN_NFILE_EXTENSION,
            "OPENFILENAME.nFileExtension",
        )?,
        extension_offset,
    )?;

    // Leave Flags as the guest provided them; only offsets/title/path are updated.
    let _flags = read_guest_u32(
        engine,
        checked_field_address(request.ofn_ptr, OFN_FLAGS, "OPENFILENAME.Flags")?,
    )?;

    Ok(())
}

/// Returns `(file_name, nFileOffset, nFileExtension)` for an OPENFILENAME result.
fn split_path_components(path: &str) -> (&str, u16, u16) {
    let separator = path.rfind(['\\', '/']);
    let file_start = separator.map_or(0, |index| index.saturating_add(1));
    let file_name = path.get(file_start..).unwrap_or(path);

    let extension_start_in_file = file_name.rfind('.').map_or(file_name.len(), |index| {
        // nFileExtension points at the character after the dot when present.
        index.saturating_add(1)
    });

    let file_offset = u16::try_from(file_start).unwrap_or(u16::MAX);
    let extension_offset =
        u16::try_from(file_start.saturating_add(extension_start_in_file)).unwrap_or(u16::MAX);

    (file_name, file_offset, extension_offset)
}

#[cfg(test)]
mod tests {
    use super::split_path_components;

    #[test]
    fn split_windows_path() {
        let (name, file_off, ext_off) = split_path_components(r"C:\Games\level.smc");
        assert_eq!(name, "level.smc");
        assert_eq!(file_off, 9);
        assert_eq!(ext_off, 15);
    }

    #[test]
    fn split_path_without_extension() {
        let (name, file_off, ext_off) = split_path_components(r"C:\Games\level");
        assert_eq!(name, "level");
        assert_eq!(file_off, 9);
        assert_eq!(ext_off, 14);
    }
}
