//! Host / virtual FS backend ops for the guest path namespace.

use super::path::{guest_basename, paths_equal_ci, wildcard_match};
use super::volume::{VolumeConfig, guest_path_to_host};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Win32-ish file attributes we surface.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

/// Open fully into memory when size ≤ this (also gates guest I/O mirror).
pub const BUFFER_SIZE_THRESHOLD: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    NotFound,
    File,
    Directory,
}

#[derive(Debug, Clone)]
pub struct PathStat {
    pub kind: PathKind,
    pub size: u64,
    pub attributes: u32,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub attributes: u32,
    pub size: u64,
}

/// Context for resolving existence across bottle/D/mounts/virtual/main PE.
pub struct ResolveCtx<'a> {
    pub volumes: &'a VolumeConfig,
    pub main_module_path: &'a str,
    pub main_module_file_name: &'a str,
    pub host_file_mounts: &'a [(String, PathBuf)],
    pub virtual_files: &'a [(String, usize)],
    /// Synthetic directories that always exist as dirs (skeleton / known probes).
    pub synthetic_dirs: &'a [&'a str],
}

impl ResolveCtx<'_> {
    pub fn path_is_main_module(&self, path: &str) -> bool {
        paths_equal_ci(path, self.main_module_path)
            || guest_basename(path).eq_ignore_ascii_case(self.main_module_file_name)
    }
}

/// Stat a guest path.
pub fn stat_path(ctx: &ResolveCtx<'_>, full_path: &str) -> PathStat {
    if full_path.is_empty() {
        return not_found();
    }

    // Drive root and synthetic dirs.
    let norm = full_path.trim_end_matches('\\');
    if is_drive_root(full_path) || is_synthetic_dir(ctx, full_path) {
        return PathStat {
            kind: PathKind::Directory,
            size: 0,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
        };
    }

    if ctx.path_is_main_module(full_path) {
        return PathStat {
            kind: PathKind::File,
            size: 0, // caller may fill from executable bytes
            attributes: FILE_ATTRIBUTE_ARCHIVE,
        };
    }

    for (guest, host) in ctx.host_file_mounts {
        if paths_equal_ci(full_path, guest) {
            return stat_host_path(host);
        }
    }

    for (guest, size) in ctx.virtual_files {
        if paths_equal_ci(full_path, guest) {
            return PathStat {
                kind: PathKind::File,
                size: u64::try_from(*size).unwrap_or(0),
                attributes: FILE_ATTRIBUTE_ARCHIVE,
            };
        }
    }

    if let Some(map) = guest_path_to_host(ctx.volumes, full_path) {
        return stat_host_path(&map.host);
    }

    // Without bottle, treat synthetic dirs only; files unknown.
    // Also: trailing slash → directory probe of parent name.
    if full_path.ends_with('\\') || full_path.ends_with('/') {
        let parent = norm;
        if is_synthetic_dir(ctx, parent) {
            return PathStat {
                kind: PathKind::Directory,
                size: 0,
                attributes: FILE_ATTRIBUTE_DIRECTORY,
            };
        }
    }

    not_found()
}

fn not_found() -> PathStat {
    PathStat {
        kind: PathKind::NotFound,
        size: 0,
        attributes: 0,
    }
}

fn is_drive_root(path: &str) -> bool {
    let p = path.trim_end_matches(['\\', '/']);
    let b = p.as_bytes();
    b.len() == 2 && b.get(1) == Some(&b':') && b.first().is_some_and(u8::is_ascii_alphabetic)
}

fn is_synthetic_dir(ctx: &ResolveCtx<'_>, path: &str) -> bool {
    let trimmed = path.trim_end_matches(['\\', '/']);
    for d in ctx.synthetic_dirs {
        if paths_equal_ci(trimmed, d) {
            return true;
        }
    }
    // Prefix of any synthetic path that is a directory component chain.
    // e.g. C:\Users, C:\Users\WIE, C:\Windows
    let lower = trimmed.to_ascii_lowercase();
    for d in ctx.synthetic_dirs {
        let dl = d.trim_end_matches('\\').to_ascii_lowercase();
        if dl.starts_with(&lower)
            && (dl.len() == lower.len() || dl.as_bytes().get(lower.len()) == Some(&b'\\'))
        {
            return true;
        }
    }
    false
}

fn stat_host_path(host: &Path) -> PathStat {
    match fs::metadata(host) {
        Ok(meta) if meta.is_dir() => PathStat {
            kind: PathKind::Directory,
            size: 0,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
        },
        Ok(meta) if meta.is_file() => PathStat {
            kind: PathKind::File,
            size: meta.len(),
            attributes: FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL,
        },
        _ => not_found(),
    }
}

/// List directory entries for a guest path (not pattern-filtered).
pub fn list_dir(ctx: &ResolveCtx<'_>, dir_path: &str) -> Vec<DirEntry> {
    let mut entries = Vec::new();

    // Always include . and .. for real/synthetic dirs that exist.
    let st = stat_path(ctx, dir_path);
    if st.kind != PathKind::Directory {
        return entries;
    }

    entries.push(DirEntry {
        name: ".".to_owned(),
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        size: 0,
    });
    entries.push(DirEntry {
        name: "..".to_owned(),
        attributes: FILE_ATTRIBUTE_DIRECTORY,
        size: 0,
    });

    if let Some(map) = guest_path_to_host(ctx.volumes, dir_path)
        && map.host.is_dir()
        && let Ok(rd) = fs::read_dir(&map.host)
    {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            let meta = ent.metadata().ok();
            let is_dir = meta.as_ref().is_some_and(std::fs::Metadata::is_dir);
            let size = meta.as_ref().map_or(0, std::fs::Metadata::len);
            entries.push(DirEntry {
                name,
                attributes: if is_dir {
                    FILE_ATTRIBUTE_DIRECTORY
                } else {
                    FILE_ATTRIBUTE_ARCHIVE
                },
                size,
            });
        }
    }

    // Virtual files whose parent is this dir.
    let dir_norm = dir_path.trim_end_matches('\\');
    for (guest, size) in ctx.virtual_files {
        let parent = super::path::guest_parent(guest);
        if paths_equal_ci(&parent, dir_norm) || paths_equal_ci(&parent, dir_path) {
            entries.push(DirEntry {
                name: guest_basename(guest).to_owned(),
                attributes: FILE_ATTRIBUTE_ARCHIVE,
                size: u64::try_from(*size).unwrap_or(0),
            });
        }
    }

    // Mounts in this dir.
    for (guest, host) in ctx.host_file_mounts {
        let parent = super::path::guest_parent(guest);
        if paths_equal_ci(&parent, dir_norm) || paths_equal_ci(&parent, dir_path) {
            let size = fs::metadata(host).map_or(0, |m| m.len());
            entries.push(DirEntry {
                name: guest_basename(guest).to_owned(),
                attributes: FILE_ATTRIBUTE_ARCHIVE,
                size,
            });
        }
    }

    // Main module if under dir.
    if !ctx.main_module_path.is_empty() {
        let parent = super::path::guest_parent(ctx.main_module_path);
        if paths_equal_ci(&parent, dir_norm) || paths_equal_ci(&parent, dir_path) {
            let name = ctx.main_module_file_name.to_owned();
            if !entries.iter().any(|e| e.name.eq_ignore_ascii_case(&name)) {
                entries.push(DirEntry {
                    name,
                    attributes: FILE_ATTRIBUTE_ARCHIVE,
                    size: 0,
                });
            }
        }
    }

    // Child synthetic dirs one level below.
    let dir_lower = dir_norm.to_ascii_lowercase();
    for d in ctx.synthetic_dirs {
        let dl = d.trim_end_matches('\\').to_ascii_lowercase();
        if let Some(rest) = dl.strip_prefix(&dir_lower) {
            let rest = rest.trim_start_matches('\\');
            if rest.is_empty() {
                continue;
            }
            if !rest.contains('\\') {
                let name = guest_basename(d).to_owned();
                if !entries.iter().any(|e| e.name.eq_ignore_ascii_case(&name)) {
                    entries.push(DirEntry {
                        name,
                        attributes: FILE_ATTRIBUTE_DIRECTORY,
                        size: 0,
                    });
                }
            }
        }
    }

    entries
}

/// Filter list_dir by wildcard mask.
pub fn list_dir_filtered(ctx: &ResolveCtx<'_>, dir_path: &str, mask: &str) -> Vec<DirEntry> {
    let mask = if mask.is_empty() || mask == "*.*" {
        "*"
    } else {
        mask
    };
    list_dir(ctx, dir_path)
        .into_iter()
        .filter(|e| wildcard_match(mask, &e.name))
        .collect()
}

/// Read entire host/virtual file bytes (for small buffered opens).
pub fn read_all_host(path: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(path)
}

/// Create parent dirs and empty file on host.
pub fn create_host_file(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    File::create(path)?;
    Ok(())
}

pub fn mkdir_host(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

pub fn remove_file_host(path: &Path) -> std::io::Result<()> {
    fs::remove_file(path)
}

pub fn remove_dir_host(path: &Path) -> std::io::Result<()> {
    fs::remove_dir(path)
}

pub fn rename_host(from: &Path, to: &Path) -> std::io::Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::rename(from, to)
}

pub fn copy_host(from: &Path, to: &Path) -> std::io::Result<u64> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(from, to)
}

/// Streamed read at offset from host path.
pub fn host_read_at(path: &Path, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    f.read(buf)
}

/// Streamed write at offset (extends file as needed).
pub fn host_write_at(path: &Path, offset: u64, data: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(data)?;
    Ok(())
}

pub fn host_file_len(path: &Path) -> std::io::Result<u64> {
    Ok(fs::metadata(path)?.len())
}

pub fn host_set_len(path: &Path, len: u64) -> std::io::Result<()> {
    let f = OpenOptions::new().write(true).open(path)?;
    f.set_len(len)
}

/// Default synthetic directory list for Win10 skeleton probes.
pub const DEFAULT_SYNTHETIC_DIRS: &[&str] = &[
    r"C:\",
    r"C:\App",
    r"C:\Windows",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Users",
    r"C:\Users\WIE",
    r"C:\Users\WIE\AppData",
    r"C:\Users\WIE\AppData\Local",
    r"C:\Users\WIE\AppData\Local\Temp",
    r"C:\Temp",
    r"C:\ProgramData",
];
