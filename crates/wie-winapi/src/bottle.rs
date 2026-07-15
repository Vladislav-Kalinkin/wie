//! Bottle v0: host workspace root for guest `C:\…` paths.
//!
//! Clean room: simple map only — `{root}/drive_c/<path-after-C:>`.
//! Not a Wine/ReactOS prefix clone.

use std::path::{Path, PathBuf};

/// Map a guest Windows path to a host path under `bottle_root`.
///
/// Rules (v0):
/// - Accepts `C:\…` / `c:/…` (drive C only; drive letter case-insensitive).
/// - Host path is `{bottle_root}/drive_c/<relative>` with **path component case preserved**.
/// - Rejects `..` components (no escape from root).
/// - Returns `None` if the path is not a mappable C: path.
#[must_use]
pub fn guest_path_to_host(bottle_root: &Path, guest_path: &str) -> Option<PathBuf> {
    let trimmed = guest_path.trim().trim_matches('"').replace('/', "\\");
    let lower = trimmed.to_ascii_lowercase();

    let relative = relative_after_drive_c(&trimmed, &lower)?;

    if relative
        .split('\\')
        .any(|component| component == ".." || component.eq_ignore_ascii_case(".."))
    {
        return None;
    }

    let mut host = bottle_root.join("drive_c");
    for component in relative.split('\\').filter(|c| !c.is_empty() && *c != ".") {
        if component.contains('/') || component.contains('\\') {
            return None;
        }
        host.push(component);
    }
    Some(host)
}

/// Returns the relative path after `C:\` with original case preserved.
fn relative_after_drive_c<'a>(trimmed: &'a str, lower: &str) -> Option<&'a str> {
    if lower.starts_with("c:\\") {
        // ASCII prefixes only (`C:\` / `c:\`).
        return trimmed.get(3..);
    }
    if lower == "c:" {
        return Some("");
    }
    None
}

/// Resolve bottle root from environment (`WIE_ROOT`).
#[must_use]
pub fn bottle_root_from_env() -> Option<PathBuf> {
    std::env::var_os("WIE_ROOT").map(PathBuf::from)
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
    fn rejects_non_c() {
        let root = Path::new("/tmp/bottle");
        assert!(guest_path_to_host(root, r"D:\App\x").is_none());
    }
}
