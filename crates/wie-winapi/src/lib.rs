//! WinAPI dispatcher model for WIE (generic PE64 userspace).

pub mod advapi32;
pub mod bottle;
pub mod comctl32;
pub mod comdlg32;
pub mod d3d9;
pub mod dynamic_apis;
pub mod gdi32;
pub mod guest_heap;
pub mod guest_io_host;
mod guest_memory;
mod guest_string;
pub mod kernel32;
pub mod ucrt;
pub mod user32;
pub mod uxtheme;
pub mod winmm;
pub use bottle::{bottle_root_from_env, guest_path_to_host};
pub use guest_heap::GuestHeap;
pub use kernel32::WinApiHandlerResult;

/// Runtime environment values visible to WinAPI handlers.
#[derive(Debug, Clone, Copy)]
pub struct WinApiEnvironment {
    /// Main module image base.
    pub image_base: u64,

    /// Pointer to ANSI command line string in emulated memory.
    pub command_line_a_ptr: u64,

    /// Pointer to UTF-16 command line string in emulated memory.
    pub command_line_w_ptr: u64,

    /// Pointer to UTF-16 environment strings block in emulated memory.
    pub environment_strings_w_ptr: u64,

    /// Pointer to ANSI module file name string in emulated memory.
    pub module_file_name_a_ptr: u64,

    /// Pointer to UTF-16 module file name string in emulated memory.
    pub module_file_name_w_ptr: u64,

    /// Fake process heap handle.
    pub process_heap_handle: u64,
}

#[derive(Debug, Clone)]
pub struct WinApiState {
    /// Process heap: segregated freelist + bump (see [`GuestHeap`]).
    pub heap: GuestHeap,

    /// Next fake `FLS` index.
    pub next_fls_index: u32,

    /// Fake `FLS` slots.
    pub fls_slots: Vec<FlsSlot>,

    /// Last WinAPI error value.
    pub last_error: u32,

    /// Next fake registry key handle.
    pub next_registry_key_handle: u64,

    /// Fake registry key handles.
    pub registry_keys: Vec<RegistryKey>,

    /// Next fake find-file handle.
    pub next_find_handle: u64,

    /// Active fake find-file handles.
    pub find_handles: Vec<FindHandle>,

    /// Size of the executable file visible through fake file handles.
    pub executable_file_size: u64,

    /// Bytes of the executable file visible through fake file handles.
    pub executable_file_bytes: Vec<u8>,

    /// Basename of the main PE (`heap_alloc.exe`, `Lunar Magic.exe`, …).
    pub main_module_file_name: String,

    /// Guest full path of the main PE (`C:\App\…`).
    pub main_module_path: String,

    /// Process TLS slots for `TlsAlloc` / `TlsGetValue` / `TlsSetValue`.
    pub tls_slots: Vec<u64>,

    /// Optional bottle root: guest `C:\…` maps to `{root}/drive_c/…` on the host.
    ///
    /// Set via `WIE_ROOT` / session. When set, CreateFile create/open uses real host files.
    pub bottle_root: Option<std::path::PathBuf>,

    /// Current cursor for the fake executable file handle.
    ///
    /// Deprecated for multi-file I/O: prefer `open_files`. Kept so the main
    /// executable still has a stable content source at session start.
    pub executable_file_cursor: u64,

    /// Host files mounted into the guest path namespace.
    pub host_file_mounts: Vec<HostFileMount>,

    /// Guest-visible virtual files created at runtime (ini/sidecars/temps).
    pub virtual_files: Vec<VirtualGuestFile>,

    /// Currently open guest file handles.
    pub open_files: Vec<OpenGuestFile>,

    /// Next handle value for `CreateFile*`.
    pub next_file_handle: u64,

    /// Next fake resource handle.
    pub next_resource_handle: u64,

    /// Fake resource records.
    pub resources: Vec<ResourceRecord>,

    pub current_directory_wide: Vec<u16>,

    pub window_long_ptr_values: Vec<(u64, i64, u64)>,

    pub image_list_counts: Vec<(u64, u64)>,

    /// Background colors associated with fake image lists.
    pub image_list_background_colors: Vec<(u64, u32)>,

    /// Whether the fake main window is visible.
    pub window_visible: bool,

    /// Whether the fake main window is enabled.
    pub window_enabled: bool,

    /// Current fake active window.
    pub active_window_handle: u64,

    /// Current fake foreground window.
    pub foreground_window_handle: u64,

    /// Current fake keyboard-focus window.
    pub focus_window_handle: u64,

    /// Current fake mouse-capture window.
    pub capture_window_handle: u64,

    /// Current fake cursor handle.
    pub cursor_handle: u64,

    /// Title of the current fake main window.
    pub window_title: String,

    /// X coordinate of the current fake main window.
    pub window_x: i32,

    /// Y coordinate of the current fake main window.
    pub window_y: i32,

    /// Width of the current fake main window.
    pub window_width: i32,

    /// Height of the current fake main window.
    pub window_height: i32,

    /// Whether the current fake main window has a pending repaint.
    pub window_invalidated: bool,

    /// Monotonic fake millisecond counter.
    pub tick_count: u64,

    /// State of the 256 virtual keyboard keys.
    pub keyboard_state: [u8; 256],

    /// Next automatically generated USER32 timer identifier.
    pub next_timer_id: u64,

    /// Active fake USER32 timers.
    pub timers: Vec<TimerRecord>,

    /// Next fake global atom identifier.
    pub next_global_atom: u16,

    /// Fake global atom table.
    pub global_atoms: Vec<GlobalAtomRecord>,

    /// Next fake USER32 hook handle.
    pub next_windows_hook_handle: u64,

    /// Registered fake USER32 hooks.
    pub windows_hooks: Vec<WindowsHookRecord>,

    /// Currently bound fake Direct3D 9 vertex shader.
    pub d3d9_current_vertex_shader: u64,

    /// Currently selected Direct3D 9 flexible vertex format.
    pub d3d9_current_fvf: u32,

    /// Direct3D 9 render-state values indexed by `D3DRENDERSTATETYPE`.
    pub d3d9_render_states: Vec<(u32, u32)>,

    /// Direct3D 9 texture-stage states stored as `(stage, state_type, value)`.
    pub d3d9_texture_stage_states: Vec<(u32, u32, u32)>,

    /// Direct3D 9 sampler states stored as `(sampler, state_type, value)`.
    pub d3d9_sampler_states: Vec<(u32, u32, u32)>,

    /// USER32 menu item enable-state records stored as
    /// `(menu_handle, item, flags)`.
    pub menu_item_states: Vec<(u64, u32, u32)>,

    /// USER32 menu item check-state records stored as
    /// `(menu_handle, item, flags)`.
    pub menu_item_check_states: Vec<(u64, u32, u32)>,

    /// Pending USER32 messages in FIFO order.
    pub message_queue: Vec<QueuedWindowMessage>,

    /// Monotonic fake USER32 message timestamp.
    pub next_message_time: u32,

    /// Guest address of the current fake `IDirect3DDevice9` object.
    pub d3d9_device_object_address: u64,

    /// COM reference count of the current fake `IDirect3DDevice9` object.
    pub d3d9_device_ref_count: u32,

    /// Guest address of the current fake `IDirect3D9` object.
    pub d3d9_object_address: u64,

    /// COM reference count of the current fake `IDirect3D9` object.
    pub d3d9_ref_count: u32,

    /// Policy used when `GetMessageA` finds no matching queued message.
    pub message_queue_idle_policy: MessageQueueIdlePolicy,

    /// Next atom returned for a registered window class.
    pub next_window_class_atom: u16,

    /// Registered USER32 window classes.
    pub window_classes: Vec<WindowClassRecord>,

    /// Next runtime-owned fake HWND.
    pub next_window_handle: u64,

    /// Windows created through `CreateWindowExA/W`.
    pub windows: Vec<WindowRecord>,

    /// Cached `GetProcAddress` resolutions keyed by export name (ASCII lower).
    pub get_proc_address_cache: std::collections::HashMap<String, GetProcAddressCacheEntry>,

    /// Policy applied when the guest opens a common file dialog.
    pub file_dialog_policy: FileDialogPolicy,

    /// Last path accepted by a simulated file dialog (if any).
    pub last_file_dialog_path: Option<String>,

    /// Value returned by `CommDlgExtendedError`.
    pub comm_dlg_extended_error: u32,

    /// Next fake HMENU value for `CreateMenu` / `CreatePopupMenu`.
    pub next_menu_handle: u64,

    /// Guest I/O acceleration config (None until runtime installs helpers).
    pub guest_io: Option<GuestIoRuntimeConfig>,

    /// Next free VA in the guest file-data mirror arena.
    pub guest_file_data_next: u64,

    /// Guest VA of the FLS value table (u64 slots), 0 if not installed.
    pub guest_fls_table_va: u64,
}

/// Runtime-published guest I/O layout (filled by `wie-runtime` at session start).
#[derive(Debug, Clone)]
pub struct GuestIoRuntimeConfig {
    /// Guest VA of the open-file handle table.
    pub table_va: u64,
    /// Guest VA of the file-content mirror arena base.
    pub file_data_base: u64,
    /// Size in bytes of the file-content mirror arena.
    pub file_data_size: usize,
}

/// Host-side decision for `GetOpenFileName` / `GetSaveFileName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDialogPolicy {
    /// Simulate the user cancelling the dialog (`return FALSE`).
    Cancel,

    /// Simulate the user accepting `path` (`return TRUE` and fill `lpstrFile`).
    Accept {
        /// Absolute or relative Windows-style path written into the dialog buffer.
        path: String,
    },
}

/// One host file exposed to the guest under one or more Windows paths.
#[derive(Debug, Clone)]
pub struct HostFileMount {
    /// Preferred guest path (Windows-style), e.g. `C:\LunarMagic\game.sfc`.
    pub guest_path: String,

    /// Absolute path on the host filesystem.
    pub host_path: std::path::PathBuf,
}

/// One open guest file handle returned by `CreateFile*`.
#[derive(Debug, Clone)]
pub struct OpenGuestFile {
    /// Fake handle value.
    pub handle: u64,

    /// Guest path used to open the file.
    pub path: String,

    /// File contents (working buffer; flushed to `host_path` when set).
    pub bytes: Vec<u8>,

    /// Current read/write cursor.
    pub cursor: u64,

    /// When set, file is bottle/mount-backed and must be flushed to this host path.
    pub host_path: Option<std::path::PathBuf>,

    /// Guest VA of mirrored file bytes for in-guest ReadFile (if registered).
    pub guest_data_va: Option<u64>,

    /// Index into the guest I/O handle table (if registered).
    pub guest_slot_index: Option<u32>,
}

/// A pure-guest virtual file (not backed by a host path).
#[derive(Debug, Clone)]
pub struct VirtualGuestFile {
    /// Guest Windows path.
    pub guest_path: String,

    /// Mutable contents.
    pub bytes: Vec<u8>,
}

/// One cached `GetProcAddress` resolution.
#[derive(Debug, Clone)]
pub struct GetProcAddressCacheEntry {
    /// Normalized (lowercase) export name.
    pub name: String,

    /// Module handle that first requested this export.
    pub module_handle: u64,

    /// Resolved fake target VA (may be zero for probed-but-absent exports).
    pub address: u64,

    /// How many times this export was resolved.
    pub hit_count: u64,
}

/// Registered fake USER32 window class.
#[derive(Debug, Clone)]
pub struct WindowClassRecord {
    /// Atom returned by `RegisterClassExA/W`.
    pub atom: u16,

    /// Registered class name.
    pub class_name: String,

    /// Guest address of the class window procedure.
    pub window_proc: u64,

    /// Class style flags.
    pub style: u32,

    /// Module instance associated with the class.
    pub instance_handle: u64,

    /// Default icon handle.
    pub icon_handle: u64,

    /// Default cursor handle.
    pub cursor_handle: u64,

    /// Background brush handle.
    pub background_brush: u64,

    /// Small icon handle.
    pub small_icon_handle: u64,

    /// Whether the class was registered through the Unicode API.
    pub unicode: bool,
}

/// USER32 window created inside the compatibility runtime.
#[derive(Debug, Clone)]
pub struct WindowRecord {
    /// Runtime-owned fake HWND.
    pub handle: u64,

    /// Registered class atom.
    pub class_atom: u16,

    /// Registered class name.
    pub class_name: String,

    /// Guest address of the window procedure.
    pub window_proc: u64,

    /// Whether the class uses the Unicode window procedure contract.
    pub unicode: bool,

    /// Window title.
    pub title: String,

    /// Standard window style flags.
    pub style: u32,

    /// Extended window style flags.
    pub extended_style: u32,

    /// Parent or owner window.
    pub parent_handle: u64,

    /// Menu handle or child-window identifier.
    pub menu_handle: u64,

    /// Module instance passed to `CreateWindowExA/W`.
    pub instance_handle: u64,

    /// Initial horizontal position.
    pub x: i32,

    /// Initial vertical position.
    pub y: i32,

    /// Initial width.
    pub width: i32,

    /// Initial height.
    pub height: i32,

    /// Current visibility state.
    pub visible: bool,

    /// Current enabled state.
    pub enabled: bool,
}

/// Request to invoke a function located inside guest executable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestCallbackRequest {
    /// Guest address of the callback function.
    pub callback_address: u64,

    /// Target runtime-owned window handle.
    pub window_handle: u64,

    /// Numeric Windows message identifier.
    pub message: u32,

    /// Message word parameter.
    pub word_parameter: u64,

    /// Message long parameter.
    pub long_parameter: u64,

    /// Whether the target window class uses the Unicode contract.
    pub unicode: bool,
}

/// A queued fake USER32 message.
#[derive(Debug, Clone)]
pub struct QueuedWindowMessage {
    /// Target window handle.
    pub window_handle: u64,

    /// Numeric Windows message identifier.
    pub message: u32,

    /// Message word parameter.
    pub word_parameter: u64,

    /// Message long parameter.
    pub long_parameter: u64,

    /// Deterministic fake message timestamp.
    pub time: u32,

    /// Fake cursor X coordinate.
    pub point_x: i32,

    /// Fake cursor Y coordinate.
    pub point_y: i32,
}

/// Registered fake USER32 hook.
#[derive(Debug, Clone)]
pub struct WindowsHookRecord {
    /// Fake hook handle returned to the guest.
    pub handle: u64,

    /// Hook type such as `WH_CBT` or `WH_CALLWNDPROC`.
    pub hook_type: i32,

    /// Guest hook procedure address.
    pub callback_address: u64,

    /// Optional module handle supplied by the guest.
    pub module_handle: u64,

    /// Target thread identifier, or zero for a global hook.
    pub thread_id: u32,
}

/// Fake global atom table entry.
#[derive(Debug, Clone)]
pub struct GlobalAtomRecord {
    /// Atom identifier.
    pub atom: u16,

    /// Stored ANSI atom name.
    pub name: String,
}

/// Fake USER32 timer record.
#[derive(Debug, Clone)]
pub struct TimerRecord {
    /// Window associated with the timer, or zero for a thread timer.
    pub window_handle: u64,

    /// Timer identifier.
    pub timer_id: u64,

    /// Requested timer interval in milliseconds.
    pub interval_ms: u32,

    /// Optional guest timer callback address.
    pub callback_address: u64,
}

/// Fake resource record.
#[derive(Debug, Clone)]
pub struct ResourceRecord {
    /// Fake resource handle.
    pub handle: u64,

    /// Fake loaded resource handle.
    pub loaded_handle: u64,

    /// Pointer to fake resource bytes.
    pub data_ptr: u64,

    /// Resource size.
    pub size: u32,
}

/// Fake find-file handle.
#[derive(Debug, Clone)]
pub struct FindHandle {
    /// Fake find handle.
    pub handle: u64,

    /// Search pattern/path.
    pub pattern: String,

    /// Whether first result was already consumed.
    pub consumed: bool,
}

/// Fake registry key.
#[derive(Debug, Clone)]
pub struct RegistryKey {
    /// Fake registry key handle.
    pub handle: u64,

    /// Parent key handle.
    pub parent: u64,

    /// Subkey path.
    pub subkey: String,
}

/// Fake heap allocation record.
#[derive(Debug, Clone)]
pub struct HeapAllocation {
    /// Allocation base address.
    pub address: u64,

    /// Allocation size in bytes.
    pub size: u64,
}

/// Fake `FLS` slot.
#[derive(Debug, Clone)]
pub struct FlsSlot {
    /// Slot index.
    pub index: u32,

    /// Slot value.
    pub value: u64,
}

/// Behavior of `GetMessageA` when no matching message is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageQueueIdlePolicy {
    /// Produce a synthetic `WM_QUIT`.
    ///
    /// This preserves the deterministic bootstrap regression path.
    ExitOnIdle,

    /// Yield execution back to the runtime without modifying the guest `MSG`.
    ///
    /// This will be used by the persistent interactive runtime.
    YieldOnIdle,
}

/// Non-error control signal emitted by a WinAPI handler.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum WinApiControlSignal {
    /// `GetMessageA` cannot continue until a message becomes available.
    #[error("waiting for a window message")]
    WaitingForMessage,

    /// `DispatchMessageA/W` requires execution of a guest window procedure.
    #[error("guest window callback requested: {request:?}")]
    GuestCallbackRequested {
        /// Description of the pending guest callback.
        request: GuestCallbackRequest,
    },
}

mod dispatch_table;
pub use dispatch_table::{
    WINAPI_ID_COUNT, WinApiId, WinApiTraits, dispatch_winapi, dispatch_winapi_id,
    is_winapi_implemented, resolve_winapi_id,
};
