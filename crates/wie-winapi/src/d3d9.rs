use anyhow::{Context, Result};

use crate::guest_memory::{
    read_u32 as read_guest_u32, read_u64 as read_guest_u64, write_u32 as write_guest_u32,
    write_u64 as write_guest_u64,
};
use crate::{WinApiHandlerResult, WinApiState};

/// Expected `D3D_SDK_VERSION` for Direct3D 9.
const D3D_SDK_VERSION: u64 = 32;

/// Size reserved for one fake `IDirect3D9` vtable and object.
const IDIRECT3D9_ALLOCATION_SIZE: u64 = 0x100;

/// Offset of the COM object after its vtable.
const IDIRECT3D9_OBJECT_OFFSET: u64 = 0x90;

/// Named `IDirect3D9` method slots.
///
/// Slot order must match the real Direct3D 9 COM interface. Addresses are the
/// single source of truth for both vtable construction and runtime dispatch.
pub const IDIRECT3D9_METHODS: &[(u64, &str)] = &[
    (0x0000_7000_0000_9000, "IDirect3D9::QueryInterface"),
    (0x0000_7000_0000_9010, "IDirect3D9::AddRef"),
    (0x0000_7000_0000_9020, "IDirect3D9::Release"),
    (0x0000_7000_0000_9030, "IDirect3D9::RegisterSoftwareDevice"),
    (0x0000_7000_0000_9040, "IDirect3D9::GetAdapterCount"),
    (0x0000_7000_0000_9050, "IDirect3D9::GetAdapterIdentifier"),
    (0x0000_7000_0000_9060, "IDirect3D9::GetAdapterModeCount"),
    (0x0000_7000_0000_9070, "IDirect3D9::EnumAdapterModes"),
    (0x0000_7000_0000_9080, "IDirect3D9::GetAdapterDisplayMode"),
    (0x0000_7000_0000_9090, "IDirect3D9::CheckDeviceType"),
    (0x0000_7000_0000_90a0, "IDirect3D9::CheckDeviceFormat"),
    (
        0x0000_7000_0000_90b0,
        "IDirect3D9::CheckDeviceMultiSampleType",
    ),
    (0x0000_7000_0000_90c0, "IDirect3D9::CheckDepthStencilMatch"),
    (
        0x0000_7000_0000_90d0,
        "IDirect3D9::CheckDeviceFormatConversion",
    ),
    (0x0000_7000_0000_90e0, "IDirect3D9::GetDeviceCaps"),
    (0x0000_7000_0000_90f0, "IDirect3D9::GetAdapterMonitor"),
    (0x0000_7000_0000_9100, "IDirect3D9::CreateDevice"),
];

const FAKE_MONITOR_HANDLE: u64 = 0x0000_0000_6600_0010;

const D3D_OK: u64 = 0;
const D3DERR_INVALIDCALL: u64 = 0x8876_086c;

const D3DDEVTYPE_HAL: u64 = 1;
const D3DDEVTYPE_REF: u64 = 2;
const D3DDEVTYPE_SW: u64 = 3;

const D3DCAPS9_SIZE: usize = 304;

const D3DVS_VERSION_2_0: u32 = 0xfffe_0200;
const D3DPS_VERSION_2_0: u32 = 0xffff_0200;

const D3DFMT_X8R8G8B8: u32 = 22;

/// Number of methods in the `IDirect3DDevice9` vtable.
pub const IDIRECT3DDEVICE9_METHOD_COUNT: usize = 119;

/// First fake executable address used by `IDirect3DDevice9` methods.
pub const IDIRECT3DDEVICE9_METHOD_BASE: u64 = 0x0000_7000_0000_a000;

/// Byte spacing between consecutive `IDirect3DDevice9` method stubs.
pub const IDIRECT3DDEVICE9_METHOD_STRIDE: u64 = 0x10;

/// Space reserved for the device vtable and COM object.
const IDIRECT3DDEVICE9_ALLOCATION_SIZE: u64 = 0x400;

/// Offset of the COM object after its 119-entry vtable.
const IDIRECT3DDEVICE9_OBJECT_OFFSET: u64 = 0x3c0;

const D3DCREATE_SOFTWARE_VERTEXPROCESSING: u32 = 0x0000_0020;
const D3DCREATE_HARDWARE_VERTEXPROCESSING: u32 = 0x0000_0040;
const D3DCREATE_MIXED_VERTEXPROCESSING: u32 = 0x0000_0080;

/// Fake target VA for `IDirect3DDevice9` vtable slot `slot`.
pub fn idirect3ddevice9_method_va(slot: usize) -> Result<u64> {
    let slot_u64 = u64::try_from(slot).context("IDirect3DDevice9 slot does not fit u64")?;

    let byte_offset = slot_u64
        .checked_mul(IDIRECT3DDEVICE9_METHOD_STRIDE)
        .context("IDirect3DDevice9 method offset overflow")?;

    IDIRECT3DDEVICE9_METHOD_BASE
        .checked_add(byte_offset)
        .context("IDirect3DDevice9 method target overflow")
}

/// Dispatch name for `IDirect3DDevice9` vtable slot `slot`.
#[must_use]
pub fn idirect3ddevice9_method_name(slot: usize) -> String {
    match slot {
        2 => "IDirect3DDevice9::Release".to_owned(),
        57 => "IDirect3DDevice9::SetRenderState".to_owned(),
        67 => "IDirect3DDevice9::SetTextureStageState".to_owned(),
        69 => "IDirect3DDevice9::SetSamplerState".to_owned(),
        89 => "IDirect3DDevice9::SetFVF".to_owned(),
        92 => "IDirect3DDevice9::SetVertexShader".to_owned(),
        _ => format!("IDirect3DDevice9::Slot{slot:03}"),
    }
}

/// Handles dynamically resolved `D3D9.dll!Direct3DCreate9`.
pub fn handle_direct3d_create9(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let sdk_version = engine
        .read_rcx()
        .context("failed to read RCX for Direct3DCreate9")?;

    let return_value = if sdk_version == D3D_SDK_VERSION {
        let vtable_address =
            allocate_direct3d_block(engine, state, IDIRECT3D9_ALLOCATION_SIZE, "IDirect3D9");

        if vtable_address == 0 {
            0
        } else {
            for (slot, &(method_address, _)) in IDIRECT3D9_METHODS.iter().enumerate() {
                let slot_u64 =
                    u64::try_from(slot).context("IDirect3D9 vtable slot does not fit u64")?;

                let byte_offset = slot_u64
                    .checked_mul(8)
                    .context("IDirect3D9 vtable offset overflow")?;

                let entry_address = vtable_address
                    .checked_add(byte_offset)
                    .context("IDirect3D9 vtable entry address overflow")?;

                write_guest_u64(engine, entry_address, method_address)?;
            }

            let object_address = vtable_address
                .checked_add(IDIRECT3D9_OBJECT_OFFSET)
                .context("IDirect3D9 object address overflow")?;

            // A COM object starts with a pointer to its vtable.
            write_guest_u64(engine, object_address, vtable_address)?;

            state.d3d9_object_address = object_address;
            state.d3d9_ref_count = 1;

            object_address
        }
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from Direct3DCreate9")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3D9::GetAdapterCount`.
pub fn handle_get_adapter_count(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3D9::GetAdapterCount")?;

    // Expose one deterministic display adapter.
    let return_value = 1;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3D9::GetAdapterCount")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3D9::GetAdapterMonitor`.
pub fn handle_get_adapter_monitor(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3D9::GetAdapterMonitor")?;

    let adapter = engine
        .read_rdx()
        .context("failed to read RDX for IDirect3D9::GetAdapterMonitor")?;

    let return_value = if adapter == 0 { FAKE_MONITOR_HANDLE } else { 0 };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3D9::GetAdapterMonitor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn write_caps_u32(
    engine: &mut dyn wie_cpu::CpuEngine,
    caps_address: u64,
    offset: u64,
    value: u32,
    field_name: &str,
) -> Result<()> {
    let field_address = caps_address
        .checked_add(offset)
        .with_context(|| format!("D3DCAPS9 field address overflow: {field_name}"))?;

    write_guest_u32(engine, field_address, value)
        .with_context(|| format!("failed to write D3DCAPS9 field: {field_name}"))
}

/// Handles `IDirect3D9::GetDeviceCaps`.
pub fn handle_get_device_caps(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3D9::GetDeviceCaps")?;

    let adapter = engine
        .read_rdx()
        .context("failed to read RDX for IDirect3D9::GetDeviceCaps")?;

    let device_type = engine
        .read_r8()
        .context("failed to read R8 for IDirect3D9::GetDeviceCaps")?;

    let caps_address = engine
        .read_r9()
        .context("failed to read R9 for IDirect3D9::GetDeviceCaps")?;

    let valid_device_type = matches!(device_type, D3DDEVTYPE_HAL | D3DDEVTYPE_REF | D3DDEVTYPE_SW);

    let return_value = if adapter != 0 || !valid_device_type || caps_address == 0 {
        D3DERR_INVALIDCALL
    } else {
        let zeroed_caps = [0_u8; D3DCAPS9_SIZE];

        engine
            .mem_write(caps_address, &zeroed_caps)
            .context("failed to clear D3DCAPS9 structure")?;

        let device_type_u32 =
            u32::try_from(device_type).context("D3D device type does not fit u32")?;

        // D3DDEVTYPE DeviceType
        write_caps_u32(engine, caps_address, 0, device_type_u32, "DeviceType")?;

        // UINT AdapterOrdinal
        write_caps_u32(engine, caps_address, 4, 0, "AdapterOrdinal")?;

        // MaxTextureWidth / MaxTextureHeight
        write_caps_u32(engine, caps_address, 88, 4096, "MaxTextureWidth")?;
        write_caps_u32(engine, caps_address, 92, 4096, "MaxTextureHeight")?;

        // MaxVolumeExtent
        write_caps_u32(engine, caps_address, 96, 256, "MaxVolumeExtent")?;

        // MaxTextureRepeat
        write_caps_u32(engine, caps_address, 100, 8192, "MaxTextureRepeat")?;

        // MaxTextureAspectRatio
        write_caps_u32(engine, caps_address, 104, 4096, "MaxTextureAspectRatio")?;

        // MaxAnisotropy
        write_caps_u32(engine, caps_address, 108, 1, "MaxAnisotropy")?;

        // MaxVertexW = 1.0f
        write_caps_u32(engine, caps_address, 112, 1.0_f32.to_bits(), "MaxVertexW")?;

        // MaxTextureBlendStages
        write_caps_u32(engine, caps_address, 148, 8, "MaxTextureBlendStages")?;

        // MaxSimultaneousTextures
        write_caps_u32(engine, caps_address, 152, 8, "MaxSimultaneousTextures")?;

        // MaxActiveLights
        write_caps_u32(engine, caps_address, 160, 8, "MaxActiveLights")?;

        // MaxUserClipPlanes
        write_caps_u32(engine, caps_address, 164, 6, "MaxUserClipPlanes")?;

        // MaxVertexBlendMatrices
        write_caps_u32(engine, caps_address, 168, 4, "MaxVertexBlendMatrices")?;

        // MaxPointSize = 64.0f
        write_caps_u32(
            engine,
            caps_address,
            176,
            64.0_f32.to_bits(),
            "MaxPointSize",
        )?;

        // MaxPrimitiveCount
        write_caps_u32(engine, caps_address, 180, 1_048_575, "MaxPrimitiveCount")?;

        // MaxVertexIndex
        write_caps_u32(engine, caps_address, 184, 1_048_575, "MaxVertexIndex")?;

        // MaxStreams
        write_caps_u32(engine, caps_address, 188, 16, "MaxStreams")?;

        // MaxStreamStride
        write_caps_u32(engine, caps_address, 192, 255, "MaxStreamStride")?;

        // VertexShaderVersion
        write_caps_u32(
            engine,
            caps_address,
            196,
            D3DVS_VERSION_2_0,
            "VertexShaderVersion",
        )?;

        // MaxVertexShaderConst
        write_caps_u32(engine, caps_address, 200, 256, "MaxVertexShaderConst")?;

        // PixelShaderVersion
        write_caps_u32(
            engine,
            caps_address,
            204,
            D3DPS_VERSION_2_0,
            "PixelShaderVersion",
        )?;

        // PixelShader1xMaxValue = 8.0f
        write_caps_u32(
            engine,
            caps_address,
            208,
            8.0_f32.to_bits(),
            "PixelShader1xMaxValue",
        )?;

        // MasterAdapterOrdinal
        write_caps_u32(engine, caps_address, 224, 0, "MasterAdapterOrdinal")?;

        // AdapterOrdinalInGroup
        write_caps_u32(engine, caps_address, 228, 0, "AdapterOrdinalInGroup")?;

        // NumberOfAdaptersInGroup
        write_caps_u32(engine, caps_address, 232, 1, "NumberOfAdaptersInGroup")?;

        // NumSimultaneousRTs
        write_caps_u32(engine, caps_address, 240, 4, "NumSimultaneousRTs")?;

        D3D_OK
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3D9::GetDeviceCaps")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3D9::GetAdapterDisplayMode`.
pub fn handle_get_adapter_display_mode(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3D9::GetAdapterDisplayMode")?;

    let adapter = engine
        .read_rdx()
        .context("failed to read RDX for IDirect3D9::GetAdapterDisplayMode")?;

    let display_mode_address = engine
        .read_r8()
        .context("failed to read R8 for IDirect3D9::GetAdapterDisplayMode")?;

    let return_value = if adapter != 0 || display_mode_address == 0 {
        D3DERR_INVALIDCALL
    } else {
        let width = u32::try_from(state.window_width)
            .context("D3D display width is negative or does not fit u32")?;

        let height = u32::try_from(state.window_height)
            .context("D3D display height is negative or does not fit u32")?;

        write_guest_u32(engine, display_mode_address, width)
            .context("failed to write D3DDISPLAYMODE.Width")?;

        let height_address = display_mode_address
            .checked_add(4)
            .context("D3DDISPLAYMODE.Height address overflow")?;

        write_guest_u32(engine, height_address, height)
            .context("failed to write D3DDISPLAYMODE.Height")?;

        let refresh_rate_address = display_mode_address
            .checked_add(8)
            .context("D3DDISPLAYMODE.RefreshRate address overflow")?;

        write_guest_u32(engine, refresh_rate_address, 60)
            .context("failed to write D3DDISPLAYMODE.RefreshRate")?;

        let format_address = display_mode_address
            .checked_add(12)
            .context("D3DDISPLAYMODE.Format address overflow")?;

        write_guest_u32(engine, format_address, D3DFMT_X8R8G8B8)
            .context("failed to write D3DDISPLAYMODE.Format")?;

        D3D_OK
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3D9::GetAdapterDisplayMode")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn allocate_direct3d_block(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    size: u64,
    _allocation_name: &str,
) -> u64 {
    state.heap.alloc_coherent(engine, size)
}

fn read_stack_argument(
    engine: &mut dyn wie_cpu::CpuEngine,
    offset: u64,
    argument_name: &str,
) -> Result<u64> {
    let stack_pointer = engine
        .read_rsp()
        .with_context(|| format!("failed to read RSP for {argument_name}"))?;

    let argument_address = stack_pointer
        .checked_add(offset)
        .with_context(|| format!("{argument_name} stack address overflow"))?;

    read_guest_u64(engine, argument_address)
}

fn normalize_presentation_parameters(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    parameters_address: u64,
    focus_window: u64,
) -> Result<()> {
    let width =
        read_guest_u32(engine, parameters_address).context("failed to read BackBufferWidth")?;

    let height_address = parameters_address
        .checked_add(4)
        .context("BackBufferHeight address overflow")?;

    let height =
        read_guest_u32(engine, height_address).context("failed to read BackBufferHeight")?;

    if width == 0 {
        let fallback_width = u32::try_from(state.window_width)
            .context("window width is negative or does not fit u32")?;

        write_guest_u32(engine, parameters_address, fallback_width)
            .context("failed to write fallback BackBufferWidth")?;
    }

    if height == 0 {
        let fallback_height = u32::try_from(state.window_height)
            .context("window height is negative or does not fit u32")?;

        write_guest_u32(engine, height_address, fallback_height)
            .context("failed to write fallback BackBufferHeight")?;
    }

    // On Win64, hDeviceWindow is at offset 32 because HWND is 64-bit aligned.
    let device_window_address = parameters_address
        .checked_add(32)
        .context("hDeviceWindow address overflow")?;

    let device_window =
        read_guest_u64(engine, device_window_address).context("failed to read hDeviceWindow")?;

    if device_window == 0 && focus_window != 0 {
        write_guest_u64(engine, device_window_address, focus_window)
            .context("failed to write fallback hDeviceWindow")?;
    }

    Ok(())
}

/// Handles `IDirect3D9::CreateDevice`.
pub fn handle_create_device(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3D9::CreateDevice")?;

    let adapter = engine
        .read_rdx()
        .context("failed to read RDX for IDirect3D9::CreateDevice")?;

    let device_type = engine
        .read_r8()
        .context("failed to read R8 for IDirect3D9::CreateDevice")?;

    let focus_window = engine
        .read_r9()
        .context("failed to read R9 for IDirect3D9::CreateDevice")?;

    let behavior_flags_raw =
        read_stack_argument(engine, 0x28, "IDirect3D9::CreateDevice BehaviorFlags")?;

    let presentation_parameters_address = read_stack_argument(
        engine,
        0x30,
        "IDirect3D9::CreateDevice pPresentationParameters",
    )?;

    let returned_device_address = read_stack_argument(
        engine,
        0x38,
        "IDirect3D9::CreateDevice ppReturnedDeviceInterface",
    )?;

    let behavior_flags_low = behavior_flags_raw & u64::from(u32::MAX);

    let behavior_flags =
        u32::try_from(behavior_flags_low).context("CreateDevice behavior flags do not fit u32")?;

    let valid_device_type = matches!(device_type, D3DDEVTYPE_HAL | D3DDEVTYPE_REF | D3DDEVTYPE_SW);

    let vertex_processing_flags = D3DCREATE_SOFTWARE_VERTEXPROCESSING
        | D3DCREATE_HARDWARE_VERTEXPROCESSING
        | D3DCREATE_MIXED_VERTEXPROCESSING;

    let has_vertex_processing_flag = behavior_flags & vertex_processing_flags != 0;

    let valid_arguments = adapter == 0
        && valid_device_type
        && has_vertex_processing_flag
        && presentation_parameters_address != 0
        && returned_device_address != 0;

    let return_value = if valid_arguments {
        normalize_presentation_parameters(
            engine,
            state,
            presentation_parameters_address,
            focus_window,
        )?;

        let vtable_address = allocate_direct3d_block(
            engine,
            state,
            IDIRECT3DDEVICE9_ALLOCATION_SIZE,
            "IDirect3DDevice9",
        );

        if vtable_address == 0 {
            write_guest_u64(engine, returned_device_address, 0)
                .context("failed to clear returned IDirect3DDevice9 pointer")?;

            D3DERR_INVALIDCALL
        } else {
            for slot in 0..IDIRECT3DDEVICE9_METHOD_COUNT {
                let slot_u64 =
                    u64::try_from(slot).context("IDirect3DDevice9 vtable slot does not fit u64")?;

                let vtable_offset = slot_u64
                    .checked_mul(8)
                    .context("IDirect3DDevice9 vtable offset overflow")?;

                let entry_address = vtable_address
                    .checked_add(vtable_offset)
                    .context("IDirect3DDevice9 vtable entry address overflow")?;

                let method_address = idirect3ddevice9_method_va(slot)?;

                write_guest_u64(engine, entry_address, method_address).with_context(|| {
                    format!("failed to write IDirect3DDevice9 vtable slot {slot}")
                })?;
            }

            let object_address = vtable_address
                .checked_add(IDIRECT3DDEVICE9_OBJECT_OFFSET)
                .context("IDirect3DDevice9 object address overflow")?;

            write_guest_u64(engine, object_address, vtable_address)
                .context("failed to initialize IDirect3DDevice9 object")?;

            write_guest_u64(engine, returned_device_address, object_address)
                .context("failed to return IDirect3DDevice9 pointer")?;

            state.d3d9_device_object_address = object_address;
            state.d3d9_device_ref_count = 1;

            D3D_OK
        }
    } else {
        if returned_device_address != 0 {
            write_guest_u64(engine, returned_device_address, 0)
                .context("failed to clear invalid IDirect3DDevice9 output pointer")?;
        }

        D3DERR_INVALIDCALL
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3D9::CreateDevice")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3DDevice9::SetVertexShader`.
pub fn handle_set_vertex_shader(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3DDevice9::SetVertexShader")?;

    let vertex_shader = engine
        .read_rdx()
        .context("failed to read RDX for IDirect3DDevice9::SetVertexShader")?;

    state.d3d9_current_vertex_shader = vertex_shader;

    let return_value = D3D_OK;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3DDevice9::SetVertexShader")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3DDevice9::SetFVF`.
pub fn handle_set_fvf(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3DDevice9::SetFVF")?;

    let fvf_raw = engine
        .read_rdx()
        .context("failed to read RDX for IDirect3DDevice9::SetFVF")?;

    let fvf_low = fvf_raw & u64::from(u32::MAX);

    let fvf = u32::try_from(fvf_low).context("IDirect3DDevice9::SetFVF value does not fit u32")?;

    state.d3d9_current_fvf = fvf;

    let return_value = D3D_OK;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3DDevice9::SetFVF")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3DDevice9::SetRenderState`.
pub fn handle_set_render_state(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3DDevice9::SetRenderState")?;

    let render_state_raw = engine
        .read_rdx()
        .context("failed to read RDX for IDirect3DDevice9::SetRenderState")?;

    let value_raw = engine
        .read_r8()
        .context("failed to read R8 for IDirect3DDevice9::SetRenderState")?;

    let render_state = u32::try_from(render_state_raw & u64::from(u32::MAX))
        .context("SetRenderState state identifier does not fit u32")?;

    let value = u32::try_from(value_raw & u64::from(u32::MAX))
        .context("SetRenderState value does not fit u32")?;

    if let Some(entry) = state
        .d3d9_render_states
        .iter_mut()
        .find(|(stored_state, _)| *stored_state == render_state)
    {
        entry.1 = value;
    } else {
        state.d3d9_render_states.push((render_state, value));
    }

    let return_value = D3D_OK;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3DDevice9::SetRenderState")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3DDevice9::SetTextureStageState`.
pub fn handle_set_texture_stage_state(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3DDevice9::SetTextureStageState")?;

    let stage_raw = engine
        .read_rdx()
        .context("failed to read RDX for IDirect3DDevice9::SetTextureStageState")?;

    let state_type_raw = engine
        .read_r8()
        .context("failed to read R8 for IDirect3DDevice9::SetTextureStageState")?;

    let value_raw = engine
        .read_r9()
        .context("failed to read R9 for IDirect3DDevice9::SetTextureStageState")?;

    let stage = u32::try_from(stage_raw & u64::from(u32::MAX))
        .context("SetTextureStageState stage does not fit u32")?;

    let state_type = u32::try_from(state_type_raw & u64::from(u32::MAX))
        .context("SetTextureStageState state type does not fit u32")?;

    let value = u32::try_from(value_raw & u64::from(u32::MAX))
        .context("SetTextureStageState value does not fit u32")?;

    if let Some(entry) = state
        .d3d9_texture_stage_states
        .iter_mut()
        .find(|(stored_stage, stored_type, _)| *stored_stage == stage && *stored_type == state_type)
    {
        entry.2 = value;
    } else {
        state
            .d3d9_texture_stage_states
            .push((stage, state_type, value));
    }

    let return_value = D3D_OK;

    let return_address = engine.return_from_win64_api(return_value).context(
        "failed to return from \
             IDirect3DDevice9::SetTextureStageState",
    )?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3DDevice9::SetSamplerState`.
pub fn handle_set_sampler_state(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _this = engine
        .read_rcx()
        .context("failed to read RCX for SetSamplerState")?;

    let sampler = u32::try_from(engine.read_rdx()? & u64::from(u32::MAX))
        .context("sampler does not fit u32")?;

    let state_type = u32::try_from(engine.read_r8()? & u64::from(u32::MAX))
        .context("state type does not fit u32")?;

    let value =
        u32::try_from(engine.read_r9()? & u64::from(u32::MAX)).context("value does not fit u32")?;

    if let Some(entry) = state
        .d3d9_sampler_states
        .iter_mut()
        .find(|(s, t, _)| *s == sampler && *t == state_type)
    {
        entry.2 = value;
    } else {
        state.d3d9_sampler_states.push((sampler, state_type, value));
    }

    let return_value = D3D_OK;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetSamplerState")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3DDevice9::Release`.
pub fn handle_device_release(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3DDevice9::Release")?;

    let valid_object = this_pointer != 0 && this_pointer == state.d3d9_device_object_address;

    let return_value = if valid_object {
        state.d3d9_device_ref_count = state.d3d9_device_ref_count.saturating_sub(1);

        let remaining_references = state.d3d9_device_ref_count;

        if remaining_references == 0 {
            let allocation_address = this_pointer
                .checked_sub(IDIRECT3DDEVICE9_OBJECT_OFFSET)
                .context("IDirect3DDevice9 allocation address underflow")?;

            let _ = state.heap.free_coherent(engine, allocation_address);

            state.d3d9_device_object_address = 0;
            state.d3d9_current_vertex_shader = 0;
            state.d3d9_current_fvf = 0;
            state.d3d9_render_states.clear();
            state.d3d9_texture_stage_states.clear();
            state.d3d9_sampler_states.clear();
        }

        u64::from(remaining_references)
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3DDevice9::Release")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `IDirect3D9::Release`.
pub fn handle_direct3d9_release(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let this_pointer = engine
        .read_rcx()
        .context("failed to read RCX for IDirect3D9::Release")?;

    let valid_object = this_pointer != 0 && this_pointer == state.d3d9_object_address;

    let return_value = if valid_object {
        state.d3d9_ref_count = state.d3d9_ref_count.saturating_sub(1);

        let remaining_references = state.d3d9_ref_count;

        if remaining_references == 0 {
            let allocation_address = this_pointer
                .checked_sub(IDIRECT3D9_OBJECT_OFFSET)
                .context("IDirect3D9 allocation address underflow")?;

            let _ = state.heap.free_coherent(engine, allocation_address);

            state.d3d9_object_address = 0;
        }

        u64::from(remaining_references)
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IDirect3D9::Release")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}
