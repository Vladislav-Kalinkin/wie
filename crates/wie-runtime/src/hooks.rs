//! Fake API registration and lookup for the runtime hook range.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use wie_winapi::{WinApiId, WinApiTraits, resolve_winapi_id};

/// Runtime fake API dispatch entry.
#[derive(Debug, Clone)]
pub struct RuntimeFakeApiEntry {
    /// Fake API target virtual address.
    pub fake_target_va: u64,

    /// Imported library name.
    pub library: Arc<str>,

    /// Imported function name.
    pub name: Arc<str>,

    /// Runtime `IAT` slot virtual address.
    pub iat_slot_va: u64,

    /// Pre-resolved dense handler id (None = unimplemented / special-cased).
    pub winapi_id: Option<WinApiId>,

    /// Hot-path classification resolved once at table build.
    pub traits: WinApiTraits,
}

fn make_entry(
    fake_target_va: u64,
    library: String,
    name: String,
    iat_slot_va: u64,
) -> RuntimeFakeApiEntry {
    let winapi_id = resolve_winapi_id(&library, &name);
    let mut traits = winapi_id.map(WinApiId::traits).unwrap_or_default();
    // ExitProcess / CRT exit: handled specially in the session loop.
    if (library.eq_ignore_ascii_case("KERNEL32.dll") && name.eq_ignore_ascii_case("ExitProcess"))
        || (wie_winapi::ucrt::is_ucrt_library(&library)
            && (name.eq_ignore_ascii_case("exit")
                || name.eq_ignore_ascii_case("_exit")
                || name.eq_ignore_ascii_case("abort")))
    {
        traits = WinApiTraits::EMPTY.with_exit_process();
    }
    // Align traits with planted guest stubs even if WinApiId map is incomplete.
    if crate::guest_stubs::classify_guest_stub(&library, &name, 0).is_some() {
        traits.set_guest_stub(true);
        traits.set_noisy(true);
    }

    RuntimeFakeApiEntry {
        fake_target_va,
        library: library.into(),
        name: name.into(),
        iat_slot_va,
        winapi_id,
        traits,
    }
}

fn build_runtime_fake_api_entries(
    patched_imports: &[wie_pe::PePatchedImport],
) -> Vec<RuntimeFakeApiEntry> {
    patched_imports
        .iter()
        .map(|import| {
            make_entry(
                import.fake_target_va,
                import.library.clone(),
                import.name.clone(),
                import.iat_slot_va,
            )
        })
        .collect()
}

/// Builds the complete fake-API table: IAT imports + dynamic exports + D3D vtables.
pub(crate) fn build_all_runtime_fake_api_entries(
    patched_imports: &[wie_pe::PePatchedImport],
) -> Result<(Vec<RuntimeFakeApiEntry>, HashMap<u64, usize>)> {
    let mut fake_api_entries = build_runtime_fake_api_entries(patched_imports);

    for entry in wie_winapi::dynamic_apis::DYNAMIC_FAKE_APIS {
        fake_api_entries.push(make_entry(
            entry.fake_target_va,
            entry.library.to_owned(),
            entry.name.to_owned(),
            0,
        ));
    }

    for &(fake_target_va, name) in wie_winapi::d3d9::IDIRECT3D9_METHODS {
        fake_api_entries.push(make_entry(
            fake_target_va,
            "D3D9.dll".to_owned(),
            name.to_owned(),
            0,
        ));
    }

    for slot in 0..wie_winapi::d3d9::IDIRECT3DDEVICE9_METHOD_COUNT {
        fake_api_entries.push(make_entry(
            wie_winapi::d3d9::idirect3ddevice9_method_va(slot)?,
            "D3D9.dll".to_owned(),
            wie_winapi::d3d9::idirect3ddevice9_method_name(slot),
            0,
        ));
    }

    let mut by_va = HashMap::with_capacity(fake_api_entries.len());
    for (index, entry) in fake_api_entries.iter().enumerate() {
        by_va.insert(entry.fake_target_va, index);
    }

    Ok((fake_api_entries, by_va))
}

pub(crate) fn find_fake_api_entry<'a>(
    entries: &'a [RuntimeFakeApiEntry],
    by_va: &HashMap<u64, usize>,
    fake_target_va: u64,
) -> Option<&'a RuntimeFakeApiEntry> {
    by_va.get(&fake_target_va).map(|&index| &entries[index])
}
