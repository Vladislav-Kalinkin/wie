use anyhow::{Context, Result};

use crate::guest_memory::{
    checked_field_address, read_i32 as read_guest_i32, read_u16 as read_guest_u16,
    write_i32 as write_guest_i32, write_u16 as write_guest_u16, write_u32 as write_guest_u32,
    write_u64 as write_guest_u64,
};
use crate::{WinApiHandlerResult, WinApiState};

const FAKE_PREVIOUS_GDI_OBJECT_HANDLE: u64 = 0x0000_0000_6800_0001;
const BITMAP_STRUCT_SIZE: u64 = 32;
const FAKE_COMPATIBLE_DC_HANDLE: u64 = 0x0000_0000_6800_0100;
const FAKE_PIXEL_COLOR: u64 = 0x0000_0000_00ff_00ff;
const FAKE_GDI_BITMAP_HANDLE_BASE: u64 = 0x0000_0000_6800_2000;
const FAKE_GDI_FONT_HANDLE_BASE: u64 = 0x0000_0000_6800_3000;

/// Handles `GDI32.dll!GetObjectA`.
pub fn handle_get_object_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let object_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetObjectA")?;

    let buffer_size = engine
        .read_rdx()
        .context("failed to read RDX for GetObjectA")?;

    let object_buffer_ptr = engine
        .read_r8()
        .context("failed to read R8 for GetObjectA")?;

    let can_write_bitmap =
        object_handle != 0 && object_buffer_ptr != 0 && buffer_size >= BITMAP_STRUCT_SIZE;

    let return_value = if object_buffer_ptr == 0 && object_handle != 0 {
        BITMAP_STRUCT_SIZE
    } else if can_write_bitmap {
        // Win64 BITMAP:
        // LONG   bmType;       offset 0
        // LONG   bmWidth;      offset 4
        // LONG   bmHeight;     offset 8
        // LONG   bmWidthBytes; offset 12
        // WORD   bmPlanes;     offset 16
        // WORD   bmBitsPixel;  offset 18
        // padding              offset 20..23
        // LPVOID bmBits;       offset 24

        write_guest_i32(engine, object_buffer_ptr, 0)
            .context("failed to write BITMAP.bmType")?;

        write_guest_i32(
            engine,
            checked_field_address(object_buffer_ptr, 4, "BITMAP.bmWidth")?,
            16,
        )
        .context("failed to write BITMAP.bmWidth")?;

        write_guest_i32(
            engine,
            checked_field_address(object_buffer_ptr, 8, "BITMAP.bmHeight")?,
            16,
        )
        .context("failed to write BITMAP.bmHeight")?;

        write_guest_i32(
            engine,
            checked_field_address(object_buffer_ptr, 12, "BITMAP.bmWidthBytes")?,
            64,
        )
        .context("failed to write BITMAP.bmWidthBytes")?;

        write_guest_u16(
            engine,
            checked_field_address(object_buffer_ptr, 16, "BITMAP.bmPlanes")?,
            1,
        )
        .context("failed to write BITMAP.bmPlanes")?;

        write_guest_u16(
            engine,
            checked_field_address(object_buffer_ptr, 18, "BITMAP.bmBitsPixel")?,
            32,
        )
        .context("failed to write BITMAP.bmBitsPixel")?;

        write_guest_u32(
            engine,
            checked_field_address(object_buffer_ptr, 20, "BITMAP padding")?,
            0,
        )
        .context("failed to write BITMAP padding")?;

        write_guest_u64(
            engine,
            checked_field_address(object_buffer_ptr, 24, "BITMAP.bmBits")?,
            0,
        )
        .context("failed to write BITMAP.bmBits")?;

        BITMAP_STRUCT_SIZE
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetObjectA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `GDI32.dll!SelectObject`.
pub fn handle_select_object(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _device_context_handle = engine
        .read_rcx()
        .context("failed to read RCX for SelectObject")?;

    let _gdi_object_handle = engine
        .read_rdx()
        .context("failed to read RDX for SelectObject")?;

    // SelectObject returns the object previously selected into the device
    // context. A stable non-null fake handle allows callers to restore it.
    let return_address = engine
        .return_from_win64_api(FAKE_PREVIOUS_GDI_OBJECT_HANDLE)
        .context("failed to return from SelectObject")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_PREVIOUS_GDI_OBJECT_HANDLE,
    })
}

/// Handles `GDI32.dll!GetTextExtentPoint32A`.
pub fn handle_get_text_extent_point_32_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_get_text_extent_point_32(engine, "GetTextExtentPoint32A")
}

/// Handles `GDI32.dll!GetTextExtentPoint32W`.
pub fn handle_get_text_extent_point_32_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_get_text_extent_point_32(engine, "GetTextExtentPoint32W")
}

fn handle_get_text_extent_point_32(
    engine: &mut dyn wie_cpu::CpuEngine,
    api_name: &str,
) -> Result<WinApiHandlerResult> {
    let _device_context_handle = engine
        .read_rcx()
        .with_context(|| format!("failed to read RCX for {api_name}"))?;

    let _text_ptr = engine
        .read_rdx()
        .with_context(|| format!("failed to read RDX for {api_name}"))?;

    let character_count = engine
        .read_r8()
        .with_context(|| format!("failed to read R8 for {api_name}"))?;

    let size_ptr = engine
        .read_r9()
        .with_context(|| format!("failed to read R9 for {api_name}"))?;

    let width = character_count
        .checked_mul(8)
        .with_context(|| format!("{api_name} width overflow"))?;

    let width = u32::try_from(width)
        .with_context(|| format!("{api_name} width does not fit in u32"))?;

    if size_ptr != 0 {
        write_guest_u32(engine, size_ptr, width)
            .with_context(|| format!("failed to write SIZE.cx for {api_name}"))?;

        write_guest_u32(
            engine,
            checked_field_address(size_ptr, 4, "SIZE.cy")?,
            16,
        )
        .with_context(|| format!("failed to write SIZE.cy for {api_name}"))?;
    }

    let return_value = u64::from(size_ptr != 0);

    let return_address = engine
        .return_from_win64_api(return_value)
        .with_context(|| format!("failed to return from {api_name}"))?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `GDI32.dll!ExtTextOutW` (success stub).
pub fn handle_ext_text_out_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for ExtTextOutW")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from ExtTextOutW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `GDI32.dll!CreateCompatibleDC`.
pub fn handle_create_compatible_dc(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _source_device_context = engine
        .read_rcx()
        .context("failed to read RCX for CreateCompatibleDC")?;

    let return_address = engine
        .return_from_win64_api(FAKE_COMPATIBLE_DC_HANDLE)
        .context("failed to return from CreateCompatibleDC")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_COMPATIBLE_DC_HANDLE,
    })
}

/// Handles `GDI32.dll!GetDeviceCaps`.
///
/// Returns plausible values for a 1920×1080 32-bpp desktop so Lunar Magic's
/// display-mode probes succeed without real GDI.
pub fn handle_get_device_caps(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for GetDeviceCaps")?;

    let index = engine
        .read_rdx()
        .context("failed to read RDX for GetDeviceCaps")?;

    // Common GetDeviceCaps indices from wingdi.h.
    // Identical return values are intentionally merged (clippy match_same_arms).
    let return_value = match index {
        0 => 0x4000,                      // DRIVERVERSION
        2 | 26 | 112 | 113 | 119 | 121 => 0, // TECHNOLOGY, PDEVICESIZE, offsets, BLTALIGNMENT, COLORMGMTCAPS
        4 => 508,                         // HORZSIZE mm (~20")
        6 => 286,                         // VERTSIZE mm
        8 | 110 | 118 => 1920,            // HORZRES / PHYSICALWIDTH / DESKTOPHORZRES
        10 | 111 | 117 => 1080,           // VERTRES / PHYSICALHEIGHT / DESKTOPVERTRES
        12 => 32,                         // BITSPIXEL
        14 | 16 | 18 | 20 | 22 | 36 => 1, // PLANES, NUMBRUSHES/PENS/MARKERS/FONTS, CLIPCAPS
        24 => u64::MAX,                   // NUMCOLORS (-1 for >8bpp, sign-extended int)
        28 => 0x1ff,                      // CURVECAPS
        30 => 0xfe,                       // LINECAPS
        32 => 0xff,                       // POLYGONALCAPS
        34 => 0x7007,                     // TEXTCAPS
        38 => 0x7e99,                     // RASTERCAPS
        40 | 42 => 36,                    // ASPECTX / ASPECTY
        44 => 51,                         // ASPECTXY
        88 | 90 => 96,                    // LOGPIXELSX / LOGPIXELSY
        104 => 256,                       // SIZEPALETTE
        106 => 20,                        // NUMRESERVED
        108 => 24,                        // COLORRES
        114 | 115 => 100,                 // SCALINGFACTORX / Y
        116 => 60,                        // VREFRESH
        120 => 3,                         // SHADEBLENDCAPS
        _ => {
            tracing::debug!(index, "GetDeviceCaps unknown index; returning 0");
            0
        }
    };

    tracing::debug!(index, return_value, "GetDeviceCaps");

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetDeviceCaps")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `GDI32.dll!GetPixel`.
pub fn handle_get_pixel(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _device_context_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetPixel")?;

    let _x = engine
        .read_rdx()
        .context("failed to read RDX for GetPixel")?;

    let _y = engine.read_r8().context("failed to read R8 for GetPixel")?;

    let return_address = engine
        .return_from_win64_api(FAKE_PIXEL_COLOR)
        .context("failed to return from GetPixel")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_PIXEL_COLOR,
    })
}

/// Handles `GDI32.dll!DeleteDC`.
pub fn handle_delete_dc(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let device_context_handle = engine
        .read_rcx()
        .context("failed to read RCX for DeleteDC")?;

    let return_value = u64::from(device_context_handle != 0);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from DeleteDC")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `GDI32.dll!DeleteObject`.
pub fn handle_delete_object(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let object_handle = engine
        .read_rcx()
        .context("failed to read RCX for DeleteObject")?;

    let return_value = u64::from(object_handle != 0);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from DeleteObject")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `GDI32.dll!CreateDIBSection`.
///
/// Allocates a guest pixel buffer from the process heap and returns a fake
/// `HBITMAP`. Pixel contents are zeroed; rendering is not implemented.
pub fn handle_create_dib_section(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for CreateDIBSection")?;

    let bmi_ptr = engine
        .read_rdx()
        .context("failed to read RDX for CreateDIBSection")?;

    let _usage = engine
        .read_r8()
        .context("failed to read R8 for CreateDIBSection")?;

    let bits_out_ptr = engine
        .read_r9()
        .context("failed to read R9 for CreateDIBSection")?;

    let (width, height, bit_count) = if bmi_ptr != 0 {
        // BITMAPINFOHEADER: biWidth@4, biHeight@8, biBitCount@14
        let width = read_guest_i32(engine, checked_field_address(bmi_ptr, 4, "biWidth")?)
            .context("failed to read CreateDIBSection biWidth")?
            .unsigned_abs();
        let height = read_guest_i32(engine, checked_field_address(bmi_ptr, 8, "biHeight")?)
            .context("failed to read CreateDIBSection biHeight")?
            .unsigned_abs();
        let bit_count =
            u32::from(read_guest_u16(engine, checked_field_address(bmi_ptr, 14, "biBitCount")?)
                .context("failed to read CreateDIBSection biBitCount")?);
        (width.max(1), height.max(1), bit_count.max(1))
    } else {
        (16, 16, 32)
    };

    let bytes_per_pixel = bit_count.div_ceil(8);
    // DIB rows are DWORD-aligned.
    let stride = width
        .checked_mul(bytes_per_pixel)
        .context("CreateDIBSection stride overflow")?
        .div_ceil(4)
        .checked_mul(4)
        .context("CreateDIBSection stride align overflow")?;
    let image_size = u64::from(stride)
        .checked_mul(u64::from(height))
        .context("CreateDIBSection image size overflow")?;

    let bits_ptr = allocate_gdi_heap_block(engine, state, image_size.max(16));
    if bits_ptr == 0 {
        tracing::warn!(
            width,
            height,
            bit_count,
            image_size,
            "CreateDIBSection heap allocation failed"
        );
        let return_address = engine
            .return_from_win64_api(0)
            .context("failed to return from CreateDIBSection")?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    // Zero the pixel buffer so guest reads are defined.
    if image_size > 0 {
        let zero = vec![0_u8; usize::try_from(image_size).unwrap_or(0)];
        if !zero.is_empty() {
            engine
                .mem_write(bits_ptr, &zero)
                .context("failed to zero CreateDIBSection bits")?;
        }
    }

    if bits_out_ptr != 0 {
        write_guest_u64(engine, bits_out_ptr, bits_ptr)
            .context("failed to write CreateDIBSection *ppvBits")?;
    }

    let handle = next_gdi_bitmap_handle(state)?;

    tracing::debug!(
        handle,
        bits_ptr,
        width,
        height,
        bit_count,
        image_size,
        "CreateDIBSection"
    );

    let return_address = engine
        .return_from_win64_api(handle)
        .context("failed to return from CreateDIBSection")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

/// Handles `GDI32.dll!CreateCompatibleBitmap`.
pub fn handle_create_compatible_bitmap(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for CreateCompatibleBitmap")?;

    let width = engine
        .read_rdx()
        .context("failed to read RDX for CreateCompatibleBitmap")?;

    let height = engine
        .read_r8()
        .context("failed to read R8 for CreateCompatibleBitmap")?;

    let handle = if width == 0 || height == 0 {
        0
    } else {
        next_gdi_bitmap_handle(state)?
    };

    tracing::debug!(handle, width, height, "CreateCompatibleBitmap");

    let return_address = engine
        .return_from_win64_api(handle)
        .context("failed to return from CreateCompatibleBitmap")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

fn next_gdi_bitmap_handle(state: &mut WinApiState) -> Result<u64> {
    // Use bump-heap high bits as a cheap monotonic discriminator.
    let live = u64::try_from(state.heap.live_count()).unwrap_or(0);
    let index = (state.heap.bump_cursor() >> 4).wrapping_add(live);
    let handle = FAKE_GDI_BITMAP_HANDLE_BASE
        .checked_add(index)
        .context("GDI bitmap handle overflow")?;
    Ok(handle)
}

/// Handles `GDI32.dll!CreateFontA` / font creation (returns a unique fake HFONT).
pub fn handle_create_font_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    // CreateFontA has many stack args; we only need a non-null HFONT.
    let _height = engine
        .read_rcx()
        .context("failed to read RCX for CreateFontA")?;

    let handle = next_gdi_font_handle(state)?;

    tracing::debug!(handle, "CreateFontA");

    let return_address = engine
        .return_from_win64_api(handle)
        .context("failed to return from CreateFontA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

/// Handles `GDI32.dll!CreateFontW`.
pub fn handle_create_font_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _height = engine
        .read_rcx()
        .context("failed to read RCX for CreateFontW")?;

    let handle = next_gdi_font_handle(state)?;

    tracing::debug!(handle, "CreateFontW");

    let return_address = engine
        .return_from_win64_api(handle)
        .context("failed to return from CreateFontW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

/// Handles `GDI32.dll!CreateFontIndirectA`.
pub fn handle_create_font_indirect_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let logfont_ptr = engine
        .read_rcx()
        .context("failed to read RCX for CreateFontIndirectA")?;

    let handle = if logfont_ptr == 0 {
        0
    } else {
        next_gdi_font_handle(state)?
    };

    tracing::debug!(handle, logfont_ptr, "CreateFontIndirectA");

    let return_address = engine
        .return_from_win64_api(handle)
        .context("failed to return from CreateFontIndirectA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

fn next_gdi_font_handle(state: &mut WinApiState) -> Result<u64> {
    let live = u64::try_from(state.heap.live_count()).unwrap_or(0);
    let index = (state.heap.bump_cursor() >> 4)
        .wrapping_add(live)
        .wrapping_add(state.next_file_handle & 0xffff)
        .wrapping_add(1);
    FAKE_GDI_FONT_HANDLE_BASE
        .checked_add(index)
        .context("GDI font handle overflow")
}

/// Handles `GDI32.dll!GetTextMetricsA`.
///
/// Fills a plausible `TEXTMETRICA` for a 16px UI font.
pub fn handle_get_text_metrics_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for GetTextMetricsA")?;

    let metrics_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetTextMetricsA")?;

    let success = metrics_ptr != 0;
    if success {
        // TEXTMETRICA layout (all LONG / BYTE fields packed):
        // tmHeight 0, tmAscent 4, tmDescent 8, tmInternalLeading 12,
        // tmExternalLeading 16, tmAveCharWidth 20, tmMaxCharWidth 24,
        // tmWeight 28, tmOverhang 32, tmDigitizedAspectX 36,
        // tmDigitizedAspectY 40, tmFirstChar 44, tmLastChar 45,
        // tmDefaultChar 46, tmBreakChar 47, tmItalic 48, tmUnderlined 49,
        // tmStruckOut 50, tmPitchAndFamily 51, tmCharSet 52
        write_guest_i32(engine, metrics_ptr, 16)?; // tmHeight
        write_guest_i32(engine, checked_field_address(metrics_ptr, 4, "tmAscent")?, 13)?;
        write_guest_i32(engine, checked_field_address(metrics_ptr, 8, "tmDescent")?, 3)?;
        write_guest_i32(
            engine,
            checked_field_address(metrics_ptr, 12, "tmInternalLeading")?,
            3,
        )?;
        write_guest_i32(
            engine,
            checked_field_address(metrics_ptr, 16, "tmExternalLeading")?,
            0,
        )?;
        write_guest_i32(
            engine,
            checked_field_address(metrics_ptr, 20, "tmAveCharWidth")?,
            8,
        )?;
        write_guest_i32(
            engine,
            checked_field_address(metrics_ptr, 24, "tmMaxCharWidth")?,
            16,
        )?;
        write_guest_i32(engine, checked_field_address(metrics_ptr, 28, "tmWeight")?, 400)?;
        write_guest_i32(engine, checked_field_address(metrics_ptr, 32, "tmOverhang")?, 0)?;
        write_guest_i32(
            engine,
            checked_field_address(metrics_ptr, 36, "tmDigitizedAspectX")?,
            96,
        )?;
        write_guest_i32(
            engine,
            checked_field_address(metrics_ptr, 40, "tmDigitizedAspectY")?,
            96,
        )?;
        // BYTE fields at end
        engine
            .mem_write(checked_field_address(metrics_ptr, 44, "tmFirstChar")?, &[0x20])?;
        engine
            .mem_write(checked_field_address(metrics_ptr, 45, "tmLastChar")?, &[0xff])?;
        engine
            .mem_write(checked_field_address(metrics_ptr, 46, "tmDefaultChar")?, &[0x3f])?;
        engine
            .mem_write(checked_field_address(metrics_ptr, 47, "tmBreakChar")?, &[0x20])?;
        engine
            .mem_write(checked_field_address(metrics_ptr, 48, "tmItalic")?, &[0])?;
        engine
            .mem_write(checked_field_address(metrics_ptr, 49, "tmUnderlined")?, &[0])?;
        engine
            .mem_write(checked_field_address(metrics_ptr, 50, "tmStruckOut")?, &[0])?;
        engine
            .mem_write(checked_field_address(metrics_ptr, 51, "tmPitchAndFamily")?, &[0x31])?;
        engine
            .mem_write(checked_field_address(metrics_ptr, 52, "tmCharSet")?, &[0])?; // ANSI_CHARSET
    }

    let return_value = u64::from(success);
    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetTextMetricsA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `GDI32.dll!SetTextColor` (returns previous color).
pub fn handle_set_text_color(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for SetTextColor")?;
    let _color = engine
        .read_rdx()
        .context("failed to read RDX for SetTextColor")?;

    // Previous color: black.
    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from SetTextColor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `GDI32.dll!SetBkColor`.
pub fn handle_set_bk_color(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for SetBkColor")?;
    let color = engine
        .read_rdx()
        .context("failed to read RDX for SetBkColor")?;

    // Return previous (white).
    let previous = 0x00ff_ffff_u64;
    let _ = color;
    let return_address = engine
        .return_from_win64_api(previous)
        .context("failed to return from SetBkColor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: previous,
    })
}

/// Handles `GDI32.dll!SetBkMode` (TRANSPARENT=1, OPAQUE=2).
pub fn handle_set_bk_mode(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for SetBkMode")?;
    let _mode = engine
        .read_rdx()
        .context("failed to read RDX for SetBkMode")?;

    // Previous mode OPAQUE.
    let return_address = engine
        .return_from_win64_api(2)
        .context("failed to return from SetBkMode")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 2,
    })
}

/// Handles `GDI32.dll!TextOutA` (success stub).
pub fn handle_text_out_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for TextOutA")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from TextOutA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `GDI32.dll!BitBlt` (success stub; no real blit).
pub fn handle_bit_blt(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for BitBlt")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from BitBlt")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `GDI32.dll!StretchBlt` (success stub).
pub fn handle_stretch_blt(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for StretchBlt")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from StretchBlt")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `GDI32.dll!PatBlt` (success stub).
pub fn handle_pat_blt(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for PatBlt")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from PatBlt")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

fn allocate_gdi_heap_block(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    size: u64,
) -> u64 {
    state.heap.alloc_coherent(engine, size)
}
