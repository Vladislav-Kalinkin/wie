//! Clean-room Windows 10 userspace VFS facade for WIE.
//!
//! - **C:** bottle (`{root}/drive_c/…`) — isolated guest workspace + synthetic skeleton
//! - **D:** optional host bridge (`WIE_DRIVE_D` / `--drive-d`)
//! - No Wine-style System32 PE payload; DLLs stay fake LoadLibrary handles

pub mod backend;
pub mod encoding;
pub mod path;
pub mod volume;

pub use backend::{
    BUFFER_SIZE_THRESHOLD, DEFAULT_SYNTHETIC_DIRS, DirEntry, FILE_ATTRIBUTE_ARCHIVE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, PathKind, PathStat, ResolveCtx, copy_host,
    create_host_file, host_file_len, host_read_at, host_set_len, host_write_at, list_dir,
    list_dir_filtered, mkdir_host, read_all_host, remove_dir_host, remove_file_host, rename_host,
    stat_path,
};
pub use encoding::{
    CP_ACP, CP_OEMCP, CP_UTF8, decode_acp, encode_acp, multibyte_to_wide, wide_to_multibyte,
};
pub use path::{
    guest_basename, guest_parent, is_windows_absolute_path, normalize_windows_path_components,
    normalize_windows_path_separators, paths_equal_ci, resolve_full_windows_path,
    split_find_pattern, strip_extended_prefix, wildcard_match,
};
pub use volume::{
    BOTTLE_SKELETON_DIRS, DRIVE_FIXED, DRIVE_NO_ROOT_DIR, GUEST_SYSTEM_DIR, GUEST_TEMP_PATH,
    GUEST_WINDOWS_DIR, HostMap, VolumeConfig, bottle_root_from_env, drive_d_from_env,
    ensure_bottle_skeleton, get_drive_type, guest_path_to_host, guest_path_to_host_bottle,
    logical_drives_mask,
};
