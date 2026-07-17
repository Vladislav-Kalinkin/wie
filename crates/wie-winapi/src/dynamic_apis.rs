//! Single source of truth for APIs resolved through `GetProcAddress`.
//!
//! Runtime fake-API registration and `KERNEL32!GetProcAddress` both consult
//! this table so addresses cannot drift apart.

/// One dynamically resolvable fake WinAPI entry.
#[derive(Debug, Clone, Copy)]
pub struct DynamicFakeApi {
    /// Fake executable target address returned by `GetProcAddress`.
    pub fake_target_va: u64,

    /// DLL name used for runtime dispatch (`library!name`).
    pub library: &'static str,

    /// Export / method name used for runtime dispatch.
    pub name: &'static str,
}

/// Dynamic exports resolvable via `GetProcAddress` (generic PE64 + legacy apps).
///
/// Order is stable for readability only; lookup is by `name` (case-insensitive).
/// Clean room: names/addresses are our fake dispatch map, not copied from other projects.
pub const DYNAMIC_FAKE_APIS: &[DynamicFakeApi] = &[
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8000,
        library: "KERNEL32.dll",
        name: "EncodePointer",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8010,
        library: "KERNEL32.dll",
        name: "DecodePointer",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8020,
        library: "KERNEL32.dll",
        name: "InitializeCriticalSectionAndSpinCount",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8030,
        library: "USER32.dll",
        name: "SetProcessDPIAware",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8040,
        library: "USER32.dll",
        name: "TrackMouseEvent",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8050,
        library: "COMCTL32.dll",
        name: "DllGetVersion",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8060,
        library: "USER32.dll",
        name: "GetSystemMetrics",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8070,
        library: "USER32.dll",
        name: "MonitorFromWindow",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8080,
        library: "USER32.dll",
        name: "GetMonitorInfoA",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8090,
        library: "USER32.dll",
        name: "GetMonitorInfoW",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_80a0,
        library: "USER32.dll",
        name: "MonitorFromRect",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_80b0,
        library: "USER32.dll",
        name: "MonitorFromPoint",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_80c0,
        library: "USER32.dll",
        name: "EnumDisplayMonitors",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_80d0,
        library: "USER32.dll",
        name: "EnumDisplayDevicesA",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_80e0,
        library: "USER32.dll",
        name: "EnumDisplayDevicesW",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_80f0,
        library: "USER32.dll",
        name: "GetDpiForWindow",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8100,
        library: "USER32.dll",
        name: "GetSystemMetricsForDpi",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8110,
        library: "USER32.dll",
        name: "AdjustWindowRectExForDpi",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8120,
        library: "COMCTL32.dll",
        name: "InitCommonControlsEx",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8130,
        library: "UXTHEME.dll",
        name: "SetWindowTheme",
    },
    DynamicFakeApi {
        fake_target_va: 0x0000_7000_0000_8140,
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
        .map(|entry| entry.fake_target_va)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_fake_api_addresses_are_unique() {
        let mut addresses: Vec<u64> = DYNAMIC_FAKE_APIS
            .iter()
            .map(|entry| entry.fake_target_va)
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
    fn resolve_known_and_null_exports() {
        assert_eq!(
            resolve_get_proc_address("EncodePointer"),
            Some(0x0000_7000_0000_8000)
        );
        assert_eq!(
            resolve_get_proc_address("direct3dcreate9"),
            Some(0x0000_7000_0000_8140)
        );
        assert_eq!(
            resolve_get_proc_address("GetUserDefaultUILanguage"),
            Some(0)
        );
        assert_eq!(resolve_get_proc_address("DefinitelyNotAnExport"), None);
    }
}
