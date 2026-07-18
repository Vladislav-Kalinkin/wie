//! Single source of truth for APIs resolved through `GetProcAddress`.
//!
//! Addresses are dense-encoded via [`crate::fake_va`] so IAT and GPA never drift.

use crate::fake_va::{encode_export, encode_unresolved};
use crate::resolve_winapi_id;

/// One dynamically resolvable fake WinAPI entry (name → encode).
#[derive(Debug, Clone, Copy)]
pub struct DynamicFakeApi {
    /// DLL name used for runtime dispatch (`library!name`).
    pub library: &'static str,

    /// Export / method name used for runtime dispatch.
    pub name: &'static str,
}

/// Dynamic exports resolvable via `GetProcAddress` (generic PE64 + legacy apps).
///
/// Order is stable; lookup is by `name` (case-insensitive).
/// Clean room: names are our fake dispatch map, not copied from other projects.
pub const DYNAMIC_FAKE_APIS: &[DynamicFakeApi] = &[
    DynamicFakeApi {
        library: "KERNEL32.dll",
        name: "EncodePointer",
    },
    DynamicFakeApi {
        library: "KERNEL32.dll",
        name: "DecodePointer",
    },
    DynamicFakeApi {
        library: "KERNEL32.dll",
        name: "InitializeCriticalSectionAndSpinCount",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "SetProcessDPIAware",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "TrackMouseEvent",
    },
    DynamicFakeApi {
        library: "COMCTL32.dll",
        name: "DllGetVersion",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "GetSystemMetrics",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "MonitorFromWindow",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "GetMonitorInfoA",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "GetMonitorInfoW",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "MonitorFromRect",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "MonitorFromPoint",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "EnumDisplayMonitors",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "EnumDisplayDevicesA",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "EnumDisplayDevicesW",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "GetDpiForWindow",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "GetSystemMetricsForDpi",
    },
    DynamicFakeApi {
        library: "USER32.dll",
        name: "AdjustWindowRectExForDpi",
    },
    DynamicFakeApi {
        library: "COMCTL32.dll",
        name: "InitCommonControlsEx",
    },
    DynamicFakeApi {
        library: "UXTHEME.dll",
        name: "SetWindowTheme",
    },
    DynamicFakeApi {
        library: "D3D9.dll",
        name: "Direct3DCreate9",
    },
];

/// Names intentionally resolved to NULL by `GetProcAddress`.
const NULL_GET_PROC_NAMES: &[&str] = &[
    "corexitprocess",
    "getthreadpreferreduilanguages",
    "getprocesspreferreduilanguages",
    "getuserpreferreduilanguages",
    "getsystempreferreduilanguages",
    "getuserdefaultuilanguage",
    "getsystemdefaultuilanguage",
];

/// Resolve a catalogued dynamic export to its dense fake VA.
#[must_use]
pub fn dynamic_fake_target_va(library: &str, name: &str) -> Option<u64> {
    if let Some(id) = resolve_winapi_id(library, name) {
        return Some(encode_export(id));
    }
    // Soft slot reserved for known dynamic names without a dense id yet.
    DYNAMIC_FAKE_APIS
        .iter()
        .position(|e| e.library.eq_ignore_ascii_case(library) && e.name.eq_ignore_ascii_case(name))
        .and_then(|idx| u16::try_from(idx).ok())
        .map(encode_unresolved)
}

/// Resolves a `GetProcAddress` export name to a fake target VA.
///
/// Returns `Some(0)` for known-but-unsupported optional exports that the
/// guest expects to probe. Returns `None` for completely unknown names.
#[must_use]
pub fn resolve_get_proc_address(proc_name: &str) -> Option<u64> {
    let lower = proc_name.to_ascii_lowercase();

    if NULL_GET_PROC_NAMES.contains(&lower.as_str()) {
        return Some(0);
    }

    DYNAMIC_FAKE_APIS
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(proc_name))
        .and_then(|entry| dynamic_fake_target_va(entry.library, entry.name))
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fake_va::decode;
    use crate::{FakeVa, WinApiId};

    #[test]
    fn dynamic_fake_api_addresses_are_unique() {
        let mut addresses: Vec<u64> = DYNAMIC_FAKE_APIS
            .iter()
            .filter_map(|entry| dynamic_fake_target_va(entry.library, entry.name))
            .collect();

        let original_len = addresses.len();
        addresses.sort_unstable();
        addresses.dedup();

        assert_eq!(
            addresses.len(),
            original_len,
            "duplicate fake_target_va values in DYNAMIC_FAKE_APIS"
        );
    }

    #[test]
    fn dynamic_fake_api_names_are_unique_case_insensitive() {
        let mut names: Vec<String> = DYNAMIC_FAKE_APIS
            .iter()
            .map(|entry| entry.name.to_ascii_lowercase())
            .collect();

        let original_len = names.len();
        names.sort_unstable();
        names.dedup();

        assert_eq!(
            names.len(),
            original_len,
            "duplicate export names in DYNAMIC_FAKE_APIS"
        );
    }

    #[test]
    fn get_proc_encode_pointer_is_export() {
        let va = resolve_get_proc_address("EncodePointer").expect("EncodePointer");
        assert_eq!(
            decode(va),
            Some(FakeVa::Export(WinApiId::Kernel32Encodepointer))
        );
    }
}
