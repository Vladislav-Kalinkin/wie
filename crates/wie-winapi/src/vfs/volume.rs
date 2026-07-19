//! Volume table: bottle C: + optional host-bridge D:.

use super::path::{drive_letter, normalize_windows_path_separators};
use std::path::{Path, PathBuf};

/// Synthetic Win10-ish skeleton under bottle `drive_c` (no PE/DLL payloads).
pub const BOTTLE_SKELETON_DIRS: &[&str] = &[
    "App",
    "Windows/System32",
    "Windows/SysWOW64",
    "Users/WIE/AppData/Local/Temp",
    "Temp",
    "ProgramData",
];

/// Guest TEMP path (env + GetTempPath).
pub const GUEST_TEMP_PATH: &str = r"C:\Users\WIE\AppData\Local\Temp";

/// Guest Windows directory.
pub const GUEST_WINDOWS_DIR: &str = r"C:\Windows";

/// Guest System32 directory.
pub const GUEST_SYSTEM_DIR: &str = r"C:\Windows\System32";

/// Volume / path mapping configuration on `WinApiState`.
#[derive(Debug, Clone, Default)]
pub struct VolumeConfig {
    /// Bottle root: `C:\…` → `{root}/drive_c/…`.
    pub bottle_root: Option<PathBuf>,
    /// Optional host root for `D:\…`.
    pub drive_d_root: Option<PathBuf>,
}

impl VolumeConfig {
    #[must_use]
    pub fn from_parts(bottle_root: Option<PathBuf>, drive_d_root: Option<PathBuf>) -> Self {
        Self {
            bottle_root,
            drive_d_root,
        }
    }

    /// Whether guest drive D: is mounted.
    #[must_use]
    pub fn has_drive_d(&self) -> bool {
        self.drive_d_root.is_some()
    }
}

/// Successful guest → host path map.
#[derive(Debug, Clone)]
pub struct HostMap {
    pub host: PathBuf,
    pub drive: char,
}

/// Map guest Windows path to host path under C bottle and/or D bridge.
///
/// Rejects raw `..` components (fail-closed, no bottle escape) and unmapped drives.
/// Case of components preserved.
#[must_use]
pub fn guest_path_to_host(volumes: &VolumeConfig, guest_path: &str) -> Option<HostMap> {
    let trimmed = guest_path.trim().trim_matches('"');
    // Work on separator-normalized form *without* collapsing `..` so escape
    // probes like `C:\App\..\..\etc\passwd` are rejected (legacy bottle rule).
    let sep_norm = normalize_windows_path_separators(trimmed);
    let drive = drive_letter(&sep_norm)?;
    let relative = relative_after_drive(&sep_norm, drive)?;

    if relative.split('\\').any(|c| c == "..") {
        return None;
    }

    let host_root = match drive {
        'C' => {
            let bottle = volumes.bottle_root.as_ref()?;
            bottle.join("drive_c")
        }
        'D' => volumes.drive_d_root.clone()?,
        _ => return None,
    };

    let mut host = host_root;
    for component in relative.split('\\').filter(|c| !c.is_empty() && *c != ".") {
        if component.contains('/') || component.contains('\\') {
            return None;
        }
        host.push(component);
    }
    Some(HostMap { host, drive })
}

fn relative_after_drive(normalized: &str, drive: char) -> Option<&str> {
    let lower = normalized.to_ascii_lowercase();
    let prefix = format!("{}:\\", drive.to_ascii_lowercase());
    if lower.starts_with(&prefix) {
        return normalized.get(3..);
    }
    let bare = format!("{}:", drive.to_ascii_lowercase());
    if lower == bare {
        return Some("");
    }
    None
}

/// Legacy helper: C: only under bottle root (kept for bottle.rs compatibility).
#[must_use]
pub fn guest_path_to_host_bottle(bottle_root: &Path, guest_path: &str) -> Option<PathBuf> {
    let volumes = VolumeConfig {
        bottle_root: Some(bottle_root.to_path_buf()),
        drive_d_root: None,
    };
    guest_path_to_host(&volumes, guest_path).map(|m| m.host)
}

/// Resolve bottle root from `WIE_ROOT`.
#[must_use]
pub fn bottle_root_from_env() -> Option<PathBuf> {
    std::env::var_os("WIE_ROOT").map(PathBuf::from)
}

/// Resolve D: host root from `WIE_DRIVE_D`.
///
/// - unset / empty → None
/// - `auto` → current host working directory
/// - otherwise path
#[must_use]
pub fn drive_d_from_env() -> Option<PathBuf> {
    let val = std::env::var_os("WIE_DRIVE_D")?;
    if val.is_empty() {
        return None;
    }
    if val == "auto" {
        return std::env::current_dir().ok();
    }
    Some(PathBuf::from(val))
}

/// Create synthetic skeleton directories under the bottle (no files).
pub fn ensure_bottle_skeleton(bottle_root: &Path) -> std::io::Result<()> {
    let drive_c = bottle_root.join("drive_c");
    for rel in BOTTLE_SKELETON_DIRS {
        let path = drive_c.join(rel);
        std::fs::create_dir_all(&path)?;
    }
    Ok(())
}

/// GetDriveType values (Microsoft Learn).
pub const DRIVE_NO_ROOT_DIR: u32 = 1;
pub const DRIVE_FIXED: u32 = 3;

/// `GetDriveType` for a root like `C:\` or path.
#[must_use]
pub fn get_drive_type(volumes: &VolumeConfig, root_path: &str) -> u32 {
    let norm = normalize_windows_path_separators(root_path.trim());
    let letter = drive_letter(&norm).or_else(|| {
        // `C:` without slash
        let b = norm.as_bytes();
        if b.len() >= 2
            && b.get(1) == Some(&b':')
            && b.first().is_some_and(u8::is_ascii_alphabetic)
        {
            b.first().map(|c| char::from(*c).to_ascii_uppercase())
        } else {
            None
        }
    });
    match letter {
        Some('C') => {
            // Bottle or pure virtual C: always FIXED for guest probes.
            DRIVE_FIXED
        }
        Some('D') => {
            if volumes.has_drive_d() {
                DRIVE_FIXED
            } else {
                DRIVE_NO_ROOT_DIR
            }
        }
        Some(_) | None => DRIVE_NO_ROOT_DIR,
    }
}

/// Bitmask for `GetLogicalDrives` (bit 0 = A:).
#[must_use]
pub fn logical_drives_mask(volumes: &VolumeConfig) -> u32 {
    let mut mask = 1u32 << 2; // C:
    if volumes.has_drive_d() {
        mask |= 1u32 << 3; // D:
    }
    mask
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn maps_c_and_rejects_escape() {
        let v = VolumeConfig {
            bottle_root: Some(PathBuf::from("/tmp/bottle")),
            drive_d_root: None,
        };
        let m = guest_path_to_host(&v, r"C:\App\out.txt").expect("map");
        assert_eq!(m.host, PathBuf::from("/tmp/bottle/drive_c/App/out.txt"));
        assert!(guest_path_to_host(&v, r"C:\App\..\..\etc\passwd").is_none());
        assert!(guest_path_to_host(&v, r"D:\x").is_none());
    }

    #[test]
    fn maps_d_when_configured() {
        let v = VolumeConfig {
            bottle_root: Some(PathBuf::from("/tmp/bottle")),
            drive_d_root: Some(PathBuf::from("/Users/me/data")),
        };
        let m = guest_path_to_host(&v, r"D:\archive\a.7z").expect("d");
        assert_eq!(m.host, PathBuf::from("/Users/me/data/archive/a.7z"));
        assert_eq!(logical_drives_mask(&v), (1 << 2) | (1 << 3));
        assert_eq!(get_drive_type(&v, r"D:\"), DRIVE_FIXED);
    }
}
