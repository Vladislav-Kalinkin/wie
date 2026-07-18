//! Windows `PAGE_*` protection constants and software access checks (Phase 3).
//!
//! Guest correctness uses these constants at 4 KiB granularity. Host `mprotect`
//! is optional defense-in-depth and must never be the sole permission oracle
//! under the guest-4K / host-16K clinch on Apple Silicon.
//!
//! Values match Microsoft Learn memory-protection constants.

/// No access (committed or reserved placeholder).
pub const PAGE_NOACCESS: u32 = 0x01;
/// Read-only.
pub const PAGE_READONLY: u32 = 0x02;
/// Read + write.
pub const PAGE_READWRITE: u32 = 0x04;
/// Execute only (no data read/write).
pub const PAGE_EXECUTE: u32 = 0x10;
/// Execute + read.
pub const PAGE_EXECUTE_READ: u32 = 0x20;
/// Execute + read + write.
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// Kind of guest memory access for software permission checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessKind {
    /// Data load / `mem_read`.
    Read,
    /// Data store / `mem_write`.
    Write,
    /// Instruction fetch (interpreter + JIT decode source).
    Execute,
}

/// Whether `protect` (a Windows `PAGE_*` value) allows a data read.
#[inline]
#[must_use]
pub fn allows_read(protect: u32) -> bool {
    matches!(
        protect,
        PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
    )
}

/// Whether `protect` allows a data write.
#[inline]
#[must_use]
pub fn allows_write(protect: u32) -> bool {
    matches!(protect, PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
}

/// Whether `protect` allows instruction fetch / execute.
#[inline]
#[must_use]
pub fn allows_execute(protect: u32) -> bool {
    matches!(
        protect,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
    )
}

/// Whether `protect` allows the given access kind.
#[inline]
#[must_use]
pub fn allows(protect: u32, kind: AccessKind) -> bool {
    match kind {
        AccessKind::Read => allows_read(protect),
        AccessKind::Write => allows_write(protect),
        AccessKind::Execute => allows_execute(protect),
    }
}

/// Convert legacy Unicorn-style rwx bits (`perm::READ|WRITE|EXEC`) to a Windows `PAGE_*`.
///
/// | rwx bits | Result |
/// |----------|--------|
/// | 7 (rwx)  | `PAGE_EXECUTE_READWRITE` |
/// | 5 (r-x)  | `PAGE_EXECUTE_READ` |
/// | 6 (rw-)  | `PAGE_READWRITE` |
/// | 1 (r--)  | `PAGE_READONLY` |
/// | 4 (--x)  | `PAGE_EXECUTE` |
/// | 0        | `PAGE_NOACCESS` |
#[must_use]
pub fn page_protect_from_rwx(rwx: u32) -> u32 {
    let r = (rwx & crate::perm::READ) != 0;
    let w = (rwx & crate::perm::WRITE) != 0;
    let x = (rwx & crate::perm::EXEC) != 0;
    match (r, w, x) {
        // Windows has no write-only / write+exec-without-read; map those to RW(X).
        (true | false, true, true) => PAGE_EXECUTE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (true | false, true, false) => PAGE_READWRITE,
        (true, false, false) => PAGE_READONLY,
        (false, false, true) => PAGE_EXECUTE,
        (false, false, false) => PAGE_NOACCESS,
    }
}

/// Convert a Windows `PAGE_*` value to Unicorn-style rwx bits.
#[must_use]
pub fn rwx_from_page_protect(protect: u32) -> u32 {
    let mut bits = 0_u32;
    if allows_read(protect) {
        bits |= crate::perm::READ;
    }
    if allows_write(protect) {
        bits |= crate::perm::WRITE;
    }
    if allows_execute(protect) {
        bits |= crate::perm::EXEC;
    }
    bits
}

/// True if `value` is one of the Phase 3 primary protect constants.
#[must_use]
pub fn is_supported_protect(value: u32) -> bool {
    matches!(
        value,
        PAGE_NOACCESS
            | PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perm;

    #[test]
    fn rwx_all_roundtrips_to_erw() {
        let p = page_protect_from_rwx(perm::ALL);
        assert_eq!(p, PAGE_EXECUTE_READWRITE);
        assert!(allows_read(p) && allows_write(p) && allows_execute(p));
        assert_eq!(rwx_from_page_protect(p), perm::ALL);
    }

    #[test]
    fn readonly_denies_write_and_exec() {
        let p = page_protect_from_rwx(perm::READ);
        assert_eq!(p, PAGE_READONLY);
        assert!(allows_read(p));
        assert!(!allows_write(p));
        assert!(!allows_execute(p));
    }

    #[test]
    fn execute_read_allows_fetch_not_write() {
        let p = page_protect_from_rwx(perm::READ | perm::EXEC);
        assert_eq!(p, PAGE_EXECUTE_READ);
        assert!(allows(p, AccessKind::Read));
        assert!(allows(p, AccessKind::Execute));
        assert!(!allows(p, AccessKind::Write));
    }

    #[test]
    fn execute_only_allows_fetch_not_data_read() {
        let p = PAGE_EXECUTE;
        assert!(allows_execute(p));
        assert!(!allows_read(p));
        assert!(!allows_write(p));
    }
}
