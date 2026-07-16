use anyhow::{Context, Result};

use crate::guest_memory::{checked_field_address, write_u32 as write_guest_u32};
use crate::{WinApiHandlerResult, WinApiState};

const S_OK: u64 = 0;
const FAKE_IMAGE_LIST_HANDLE: u64 = 0x0000_0000_6900_0001;
const CLR_NONE: u32 = 0xffff_ffff;

/// Handles dynamic `COMCTL32.dll!DllGetVersion`.
pub fn handle_dll_get_version(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let version_info_ptr = engine
        .read_rcx()
        .context("failed to read RCX for DllGetVersion")?;

    if version_info_ptr != 0 {
        // DLLVERSIONINFO:
        // DWORD cbSize;          offset 0
        // DWORD dwMajorVersion;  offset 4
        // DWORD dwMinorVersion;  offset 8
        // DWORD dwBuildNumber;   offset 12
        // DWORD dwPlatformID;    offset 16
        //
        // Common Controls v6-ish fake version.
        write_guest_u32(engine, version_info_ptr, 20)?;
        write_guest_u32(
            engine,
            checked_field_address(version_info_ptr, 4, "dwMajorVersion")?,
            6,
        )?;
        write_guest_u32(
            engine,
            checked_field_address(version_info_ptr, 8, "dwMinorVersion")?,
            0,
        )?;
        write_guest_u32(
            engine,
            checked_field_address(version_info_ptr, 12, "dwBuildNumber")?,
            7600,
        )?;
        write_guest_u32(
            engine,
            checked_field_address(version_info_ptr, 16, "dwPlatformID")?,
            1,
        )?;
    }

    let return_address = engine
        .return_from_win64_api(S_OK)
        .context("failed to return from DllGetVersion")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: S_OK,
    })
}

/// Handles `COMCTL32.dll!InitCommonControls` imported as ordinal 17.
pub fn handle_init_common_controls(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from InitCommonControls")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles dynamic `COMCTL32.dll!InitCommonControlsEx`.
pub fn handle_init_common_controls_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let init_common_controls_ex_ptr = engine
        .read_rcx()
        .context("failed to read RCX for InitCommonControlsEx")?;

    let return_value = u64::from(init_common_controls_ex_ptr != 0);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from InitCommonControlsEx")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `COMCTL32.dll!ImageList_Create`.
pub fn handle_image_list_create(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _icon_width = engine
        .read_rcx()
        .context("failed to read RCX for ImageList_Create")?;

    let _icon_height = engine
        .read_rdx()
        .context("failed to read RDX for ImageList_Create")?;

    let _flags = engine
        .read_r8()
        .context("failed to read R8 for ImageList_Create")?;

    let _initial_count = engine
        .read_r9()
        .context("failed to read R9 for ImageList_Create")?;

    if let Some((_, count)) = state
        .image_list_counts
        .iter_mut()
        .find(|(handle, _)| *handle == FAKE_IMAGE_LIST_HANDLE)
    {
        *count = 0;
    } else {
        state.image_list_counts.push((FAKE_IMAGE_LIST_HANDLE, 0));
    }

    let return_address = engine
        .return_from_win64_api(FAKE_IMAGE_LIST_HANDLE)
        .context("failed to return from ImageList_Create")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_IMAGE_LIST_HANDLE,
    })
}

/// Handles `COMCTL32.dll!ImageList_AddMasked`.
pub fn handle_image_list_add_masked(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let image_list_handle = engine
        .read_rcx()
        .context("failed to read RCX for ImageList_AddMasked")?;

    let bitmap_handle = engine
        .read_rdx()
        .context("failed to read RDX for ImageList_AddMasked")?;

    let _mask_color = engine
        .read_r8()
        .context("failed to read R8 for ImageList_AddMasked")?;

    let return_value = if image_list_handle == FAKE_IMAGE_LIST_HANDLE && bitmap_handle != 0 {
        let count = state
            .image_list_counts
            .iter_mut()
            .find(|(handle, _)| *handle == image_list_handle)
            .map(|(_, count)| count)
            .context("ImageList_AddMasked received an unregistered image list")?;

        let image_index = *count;

        *count = count
            .checked_add(1)
            .context("image list item count overflow")?;

        image_index
    } else {
        u64::MAX
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from ImageList_AddMasked")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `COMCTL32.dll!ImageList_SetBkColor`.
pub fn handle_image_list_set_bk_color(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let image_list_handle = engine
        .read_rcx()
        .context("failed to read RCX for ImageList_SetBkColor")?;

    let background_color_raw = engine
        .read_rdx()
        .context("failed to read RDX for ImageList_SetBkColor")?;

    let background_color = u32::try_from(background_color_raw)
        .context("ImageList_SetBkColor color does not fit u32")?;

    let image_list_exists = state
        .image_list_counts
        .iter()
        .any(|(handle, _)| *handle == image_list_handle);

    let return_value = if image_list_exists {
        if let Some((_, stored_color)) = state
            .image_list_background_colors
            .iter_mut()
            .find(|(handle, _)| *handle == image_list_handle)
        {
            let previous_color = *stored_color;
            *stored_color = background_color;
            u64::from(previous_color)
        } else {
            state
                .image_list_background_colors
                .push((image_list_handle, background_color));

            u64::from(CLR_NONE)
        }
    } else {
        u64::from(CLR_NONE)
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from ImageList_SetBkColor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `COMCTL32.dll!ImageList_Destroy`.
pub fn handle_image_list_destroy(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let image_list_handle = engine
        .read_rcx()
        .context("failed to read RCX for ImageList_Destroy")?;

    let existed = state
        .image_list_counts
        .iter()
        .any(|(handle, _)| *handle == image_list_handle);

    if existed {
        state
            .image_list_counts
            .retain(|(handle, _)| *handle != image_list_handle);

        state
            .image_list_background_colors
            .retain(|(handle, _)| *handle != image_list_handle);
    }

    let return_value = u64::from(existed);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from ImageList_Destroy")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}
