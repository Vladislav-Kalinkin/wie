//! Windows path normalize / resolve (clean room, Microsoft Learn path forms).

/// Strip `\\?\` / `//?/` extended prefix when present.
#[must_use]
pub fn strip_extended_prefix(path: &str) -> &str {
    let p = path.trim();
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        return rest;
    }
    if let Some(rest) = p.strip_prefix("//?/") {
        return rest;
    }
    // `\\?\UNC\server\share` left as-is for now (not bottle-mapped).
    if p.strip_prefix(r"\\?\UNC\").is_some() {
        return p;
    }
    p
}

#[must_use]
pub fn normalize_windows_path_separators(path: &str) -> String {
    path.chars()
        .map(|character| if character == '/' { '\\' } else { character })
        .collect()
}

#[must_use]
pub fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let has_drive_prefix = bytes.get(1).is_some_and(|value| *value == b':')
        && bytes
            .get(2)
            .is_some_and(|value| *value == b'\\' || *value == b'/');
    let has_unc_prefix = bytes.first() == Some(&b'\\') && bytes.get(1) == Some(&b'\\');
    has_drive_prefix || has_unc_prefix
}

#[must_use]
pub fn join_windows_path(base: &str, relative: &str) -> String {
    let mut joined = base.trim_end_matches(['\\', '/']).to_owned();
    if !joined.is_empty() {
        joined.push('\\');
    }
    joined.push_str(relative);
    joined
}

/// Collapse `.` / `..` components; never walk above drive/UNC prefix.
#[must_use]
pub fn normalize_windows_path_components(path: &str) -> String {
    let normalized = normalize_windows_path_separators(path);
    let mut prefix = String::new();
    let mut remainder = normalized.as_str();
    let bytes = normalized.as_bytes();

    if bytes.get(1).is_some_and(|value| *value == b':') {
        if let Some(drive) = normalized.get(..2) {
            // Canonical drive letter: uppercase ASCII.
            for ch in drive.chars() {
                prefix.push(ch.to_ascii_uppercase());
            }
        }
        remainder = normalized.get(2..).unwrap_or_default();
        if remainder.starts_with('\\') {
            prefix.push('\\');
            remainder = remainder.trim_start_matches('\\');
        }
    } else if normalized.starts_with("\\\\") {
        prefix.push_str("\\\\");
        remainder = normalized.strip_prefix("\\\\").unwrap_or_default();
    }

    let mut components = Vec::<String>::new();
    for component in remainder.split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                let _removed = components.pop();
            }
            _ => components.push(component.to_owned()),
        }
    }

    let mut result = prefix;
    for component in components {
        if !result.is_empty() && !result.ends_with('\\') {
            result.push('\\');
        }
        result.push_str(&component);
    }
    result
}

/// Resolve a Windows path against the process current directory.
///
/// - Absolute: `C:\…`, `\\server\share\…`, `\\?\C:\…`
/// - Drive-relative / relative: `file`, `.\file`, `subdir\file`, `..\file`
/// - Rooted on current drive: `\file` → `{drive}:\file`
/// - Drive-relative without slash: `D:foo` → `{D: cwd or D:\}` + `foo` (v1: `D:\foo`)
#[must_use]
pub fn resolve_full_windows_path(current_directory: &str, input_path: &str) -> String {
    let stripped = strip_extended_prefix(input_path.trim().trim_matches('"'));
    let normalized_input = normalize_windows_path_separators(stripped);
    let cwd = normalize_windows_path_separators(current_directory);

    let combined = if is_windows_absolute_path(&normalized_input) {
        normalized_input
    } else if looks_like_drive_relative(&normalized_input) {
        // `D:foo` — relative to root of that drive (v1 simplification).
        let drive = normalized_input.get(..2).unwrap_or("C:");
        let rest = normalized_input.get(2..).unwrap_or("");
        if rest.starts_with('\\') {
            format!("{drive}{rest}")
        } else if rest.is_empty() {
            format!("{drive}\\")
        } else {
            format!("{drive}\\{rest}")
        }
    } else if normalized_input.starts_with('\\') {
        let drive = cwd
            .get(..2)
            .filter(|d| d.as_bytes().get(1) == Some(&b':'))
            .unwrap_or("C:");
        format!("{drive}{normalized_input}")
    } else {
        join_windows_path(&cwd, &normalized_input)
    };

    normalize_windows_path_components(&combined)
}

fn looks_like_drive_relative(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() >= 2
        && b.get(1) == Some(&b':')
        && b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.get(2).is_none_or(|c| *c != b'\\')
}

/// Case-insensitive full path equality (ASCII fold).
#[must_use]
pub fn paths_equal_ci(a: &str, b: &str) -> bool {
    let na = normalize_windows_path_components(a).to_ascii_lowercase();
    let nb = normalize_windows_path_components(b).to_ascii_lowercase();
    na == nb
}

/// Basename after last `\` or `/`.
#[must_use]
pub fn guest_basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Parent directory of a Windows path (drive root stays drive root).
#[must_use]
pub fn guest_parent(path: &str) -> String {
    let norm = normalize_windows_path_components(path);
    if let Some(idx) = norm.rfind('\\') {
        let parent = norm.get(..=idx).unwrap_or(norm.as_str());
        if parent.len() <= 3 && parent.as_bytes().get(1) == Some(&b':') {
            // `C:\`
            return parent.trim_end_matches('\\').to_owned() + "\\";
        }
        return parent.trim_end_matches('\\').to_owned();
    }
    norm
}

/// Split a find pattern into directory + file mask.
///
/// `C:\App\*.txt` → (`C:\App`, `*.txt`); `C:\App\` → (`C:\App`, `*`);
/// `file.txt` (no sep after resolve) handled by caller after full resolve.
#[must_use]
pub fn split_find_pattern(full_pattern: &str) -> (String, String) {
    let norm = normalize_windows_path_components(full_pattern);
    if let Some(idx) = norm.rfind('\\') {
        let dir = if idx <= 2 {
            // `C:\*`
            norm.get(..=idx).unwrap_or(norm.as_str()).to_owned()
        } else {
            norm.get(..idx).unwrap_or("").to_owned()
        };
        let mask_start = idx.saturating_add(1);
        let mask = norm.get(mask_start..).unwrap_or("").to_owned();
        let mask = if mask.is_empty() {
            "*".to_owned()
        } else {
            mask
        };
        (dir, mask)
    } else {
        (".".to_owned(), norm)
    }
}

/// Simple case-insensitive `*` / `?` wildcard match (Win32-ish, not full DOS 8.3).
#[must_use]
pub fn wildcard_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let text: Vec<char> = name.to_ascii_lowercase().chars().collect();
    match_glob(&pat, &text)
}

fn match_glob(pat: &[char], text: &[char]) -> bool {
    let mut pi = 0_usize;
    let mut ti = 0_usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0_usize;
    while ti < text.len() {
        let pat_ch = pat.get(pi).copied();
        let text_ch = text.get(ti).copied();
        if pat_ch.is_some_and(|p| p == '?' || Some(p) == text_ch) {
            pi = pi.saturating_add(1);
            ti = ti.saturating_add(1);
        } else if pat_ch == Some('*') {
            star_pi = Some(pi);
            star_ti = ti;
            pi = pi.saturating_add(1);
        } else if let Some(sp) = star_pi {
            pi = sp.saturating_add(1);
            star_ti = star_ti.saturating_add(1);
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pat.get(pi) == Some(&'*') {
        pi = pi.saturating_add(1);
    }
    pi == pat.len()
}

/// Drive letter from `C:\…` form, uppercase, if any.
#[must_use]
pub fn drive_letter(path: &str) -> Option<char> {
    let norm = normalize_windows_path_separators(path);
    let b = norm.as_bytes();
    if b.len() >= 2 && b.get(1) == Some(&b':') && b.first().is_some_and(u8::is_ascii_alphabetic) {
        let letter = char::from(*b.first()?);
        Some(letter.to_ascii_uppercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_and_dotdot() {
        assert_eq!(
            resolve_full_windows_path(r"C:\App", r".\config.ini"),
            r"C:\App\config.ini"
        );
        assert_eq!(
            resolve_full_windows_path(r"C:\App\data", r"..\config.ini"),
            r"C:\App\config.ini"
        );
        assert_eq!(
            resolve_full_windows_path(r"C:\App", r"\Windows\win.ini"),
            r"C:\Windows\win.ini"
        );
        assert_eq!(
            resolve_full_windows_path(r"C:\App", r"D:\other\file.txt"),
            r"D:\other\file.txt"
        );
    }

    #[test]
    fn extended_prefix() {
        assert_eq!(
            resolve_full_windows_path(r"C:\App", r"\\?\C:\Temp\x"),
            r"C:\Temp\x"
        );
    }

    #[test]
    fn drive_relative_v1() {
        assert_eq!(resolve_full_windows_path(r"C:\App", r"D:foo"), r"D:\foo");
    }

    #[test]
    fn wildcard_basic() {
        assert!(wildcard_match("*.txt", "a.txt"));
        assert!(wildcard_match("*.*", "a.txt"));
        assert!(wildcard_match("*", "anything"));
        assert!(!wildcard_match("*.txt", "a.bin"));
        assert!(wildcard_match("file?.dat", "file1.dat"));
    }

    #[test]
    fn split_pattern() {
        let (d, m) = split_find_pattern(r"C:\App\*.7z");
        assert_eq!(d, r"C:\App");
        assert_eq!(m, "*.7z");
    }
}
