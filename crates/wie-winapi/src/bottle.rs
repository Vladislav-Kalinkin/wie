//! Bottle v1: thin wrappers over [`crate::vfs`] volume mapping.
//!
//! Clean room: `{root}/drive_c/<path-after-C:>` for C:; optional D: via `VolumeConfig`.

use crate::vfs::{VolumeConfig, guest_path_to_host as vfs_guest_path_to_host};
use std::path::{Path, PathBuf};

/// Map a guest Windows path to a host path under `bottle_root` (C: only).
#[must_use]
pub fn guest_path_to_host(bottle_root: &Path, guest_path: &str) -> Option<PathBuf> {
    let volumes = VolumeConfig {
        bottle_root: Some(bottle_root.to_path_buf()),
        drive_d_root: None,
    };
    vfs_guest_path_to_host(&volumes, guest_path).map(|m| m.host)
}

/// Resolve bottle root from environment (`WIE_ROOT`).
#[must_use]
pub fn bottle_root_from_env() -> Option<PathBuf> {
    crate::vfs::bottle_root_from_env()
}

/// Resolve optional D: host root from `WIE_DRIVE_D`.
#[must_use]
pub fn drive_d_from_env() -> Option<PathBuf> {
    crate::vfs::drive_d_from_env()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_c_drive_under_drive_c() {
        let root = Path::new("/tmp/bottle");
        assert_eq!(
            guest_path_to_host(root, r"C:\App\out.txt"),
            Some(PathBuf::from("/tmp/bottle/drive_c/App/out.txt"))
        );
    }

    #[test]
    fn drive_letter_case_insensitive() {
        let root = Path::new("/tmp/bottle");
        assert_eq!(
            guest_path_to_host(root, r"c:\App\out.txt"),
            Some(PathBuf::from("/tmp/bottle/drive_c/App/out.txt"))
        );
    }

    #[test]
    fn rejects_dotdot() {
        let root = Path::new("/tmp/bottle");
        assert!(guest_path_to_host(root, r"C:\App\..\..\etc\passwd").is_none());
    }

    #[test]
    fn rejects_non_c_without_d() {
        let root = Path::new("/tmp/bottle");
        assert!(guest_path_to_host(root, r"D:\App\x").is_none());
    }
}
