//! Real DLL loader for WIE: reads PE DLL files from host, maps into guest
//! memory, relocates, resolves imports, calls DllMain.
//!
//! ## Module handle space
//!
//! Real loaded modules use handles starting at `REAL_MODULE_HANDLE_BASE`
//! (above the fake handle range `0x6100_xxxx`). Fake modules (kernel32,
//! user32, etc.) keep their existing handles — the loader skips them.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};
use wie_cpu::CpuEngine;
use wie_pe::rva_to_file_offset;

/// Parsed export directory contents.
#[derive(Debug, Clone, Default)]
pub struct DllExports {
    /// Name → RVA (relative to image_base).
    pub by_name: HashMap<String, u64>,
    /// Ordinal → RVA.
    pub by_ordinal: HashMap<u16, u64>,
    /// Ordinal base from the export directory.
    pub ordinal_base: u16,
    /// Total number of export entries.
    pub export_count: u16,
}

/// Base address for real loaded module handles (above fake handle range).
pub const REAL_MODULE_HANDLE_BASE: u64 = 0x0000_0000_6f00_0000;

/// One real loaded DLL module.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    /// Module handle (also the guest base of the module data structure).
    pub handle: u64,
    /// Absolute guest VA where the PE image is mapped.
    pub image_base: u64,
    /// Size of the mapped image (SizeOfImage).
    pub image_size: usize,
    /// Entry point RVA (zero for DLLs with no entry point).
    pub entry_rva: u64,
    /// Module base name for diagnostics ("user32.dll").
    pub name: String,
    /// Full guest path used to load the module.
    pub guest_path: String,
    /// Host filesystem path where the DLL was found.
    pub host_path: std::path::PathBuf,
    /// Reference count (LoadLibrary increments, FreeLibrary decrements).
    pub ref_count: u64,
    /// Parsed export directory: name → RVA (relative to image_base).
    pub exports_by_name: HashMap<String, u64>,
    /// Parsed export directory: ordinal → RVA.
    pub exports_by_ordinal: HashMap<u16, u64>,
    /// Ordinal base from the export directory.
    pub ordinal_base: u16,
    /// Number of export entries.
    pub export_count: u16,
}

impl LoadedModule {
    /// Look up an export by name, returning the absolute guest VA.
    ///
    /// Exports are stored with lowercase keys (Windows PE convention).
    pub fn get_export_va(&self, name: &str) -> Option<u64> {
        let rva = self
            .exports_by_name
            .get(&name.to_ascii_lowercase())
            .copied()?;
        // RVA 0 indicates a forwarder or unsupported export.
        if rva == 0 {
            return None;
        }
        Some(self.image_base.wrapping_add(rva))
    }

    /// Look up an export by ordinal, returning the absolute guest VA.
    pub fn get_export_va_by_ordinal(&self, ordinal: u16) -> Option<u64> {
        let rva = self.exports_by_ordinal.get(&ordinal).copied()?;
        if rva == 0 {
            return None;
        }
        Some(self.image_base.wrapping_add(rva))
    }
}

/// Parse the export directory of a parsed PE image.
///
/// Returns `DllExports::default()` when the image has no export directory.
/// Export names are lowercased for case-insensitive lookup.
///
/// `pe_bytes` must be the raw file bytes (not the mapped image).
pub fn parse_dll_exports(
    pe: &goblin::pe::PE<'_>,
    pe_bytes: &[u8],
) -> Result<DllExports> {
    let header = pe
        .header
        .optional_header
        .as_ref()
        .context("no optional header")?;
    let data_dirs = &header.data_directories;
    let export_dir = data_dirs.get_export_table().context("no export directory")?;

    if export_dir.virtual_address == 0 {
        return Ok(DllExports::default());
    }

    // Read the export directory table from the file.
    let export_rva = export_dir.virtual_address;
    let export_offset = rva_to_file_offset(pe, export_rva)
        .with_context(|| format!("export dir RVA {export_rva:#x} outside file"))?;

    // Parse the IMAGE_EXPORT_DIRECTORY (40 bytes total).
    let export_slice = &pe_bytes[export_offset..];

    // Read fields manually from the IMAGE_EXPORT_DIRECTORY structure (Win64).
    // Layout (all little-endian):
    //   +0x00: u32 Characteristics (reserved)
    //   +0x04: u32 TimeDateStamp
    //   +0x08: u16 MajorVersion
    //   +0x0a: u16 MinorVersion
    //   +0x0c: u32 Name (RVA of DLL name)
    //   +0x10: u32 OrdinalBase
    //   +0x14: u32 AddressOfFunctions (RVA of export address table)
    //   +0x18: u32 NumberOfFunctions
    //   +0x1c: u32 NumberOfNames
    //   +0x20: u32 AddressOfNames (RVA of name pointer table)
    //   +0x24: u32 AddressOfNameOrdinals (RVA of ordinal table)
    if export_slice.len() < 40 {
        bail!("export directory too short: {} bytes", export_slice.len());
    }

    let read_u32_at = |off: usize| -> u32 {
        u32::from_le_bytes(export_slice[off..off + 4].try_into().unwrap_or([0; 4]))
    };

    let _name_rva = read_u32_at(0x0c);
    let ordinal_base = read_u32_at(0x10);
    let address_table_rva = read_u32_at(0x14);
    let number_of_functions = read_u32_at(0x18);
    let number_of_names = read_u32_at(0x1c);
    let name_pointer_rva = read_u32_at(0x20);
    let ordinal_table_rva = read_u32_at(0x24);

    let num_functions = number_of_functions as usize;
    let num_names = number_of_names as usize;

    let mut by_name = HashMap::with_capacity(num_names);
    let mut by_ordinal = HashMap::with_capacity(num_functions);

    // Compute the export directory's RVA range to detect forwarders.
    // A forwarder has an RVA that points into the export directory itself
    // (where the forwarder string lives). We zero those out so callers
    // can treat RVA 0 as "unresolvable".
    let export_dir_end = u64::from(export_rva).saturating_add(u64::from(export_dir.size));

    // Build the address table in host memory by reading 4-byte RVA entries
    // from the file (each entry is an RVA or 0 for unused/forwarder).
    let mut address_table: Vec<u64> = Vec::with_capacity(num_functions);
    for i in 0..num_functions {
        let entry_file_off = rva_to_file_offset(
            pe,
            address_table_rva.wrapping_add((i as u32) * 4),
        )
        .ok();
        let rva = match entry_file_off {
            Some(off) if off + 4 <= pe_bytes.len() => {
                u32::from_le_bytes(pe_bytes[off..off + 4].try_into().unwrap()) as u64
            }
            _ => 0,
        };
        // If the RVA falls within the export directory, it's a forwarder
        // string, not a real export address.
        let rva = if rva != 0 && rva >= u64::from(export_rva) && rva < export_dir_end {
            0
        } else {
            rva
        };
        address_table.push(rva);
    }

    // Read name-pointer table entries.
    for i in 0..num_names {
        // Read ordinal entry: AddressOfNameOrdinals is an array of u16.
        let ordinal_file_off = rva_to_file_offset(
            pe,
            ordinal_table_rva.wrapping_add((i as u32) * 2),
        )
        .ok();
        let name_ptr_file_off = rva_to_file_offset(
            pe,
            name_pointer_rva.wrapping_add((i as u32) * 4),
        )
        .ok();

        if let (Some(ord_off), Some(np_off)) = (ordinal_file_off, name_ptr_file_off) {
            if ord_off + 2 > pe_bytes.len() || np_off + 4 > pe_bytes.len() {
                continue;
            }
            let name_rva = u32::from_le_bytes(
                pe_bytes[np_off..np_off + 4].try_into().unwrap_or([0; 4]),
            ) as u64;
            let ordinal_idx = u16::from_le_bytes(
                pe_bytes[ord_off..ord_off + 2].try_into().unwrap_or([0; 2]),
            );

            let ordinal = (ordinal_base as u16).wrapping_add(ordinal_idx);
            let function_rva = address_table
                .get(ordinal_idx as usize)
                .copied()
                .unwrap_or(0);

            // Read the export name (C string at name_rva in file).
            if let Ok(name_off) = rva_to_file_offset(pe, name_rva as u32) {
                let name_bytes = pe_bytes[name_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|end| &pe_bytes[name_off..name_off + end])
                    .unwrap_or(&[]);
                if !name_bytes.is_empty() {
                    if let Ok(name) = std::str::from_utf8(name_bytes) {
                        // Only store non-zero RVAs (forwarders and unused
                        // slots are stored as 0 and excluded here).
                        if function_rva != 0 {
                            by_name.insert(name.to_ascii_lowercase(), function_rva);
                        }
                    }
                }
            }

            // Only store non-zero function RVAs for ordinal lookup
            // (forwarders are stored with RVA 0 and handled separately).
            if function_rva != 0 {
                by_ordinal.insert(ordinal, function_rva);
            }
        }
    }

    Ok(DllExports {
        by_name,
        by_ordinal,
        ordinal_base: ordinal_base as u16,
        export_count: num_functions as u16,
    })
}

/// Normalize a DLL name: strip path, lowercase, ensure .dll extension.
fn normalize_dll_name(name: &str) -> String {
    let clean = name.trim().trim_matches('"');
    let basename = clean
        .rsplit(|c: char| c == '/' || c == '\\')
        .next()
        .unwrap_or(clean)
        .to_ascii_lowercase();
    if !basename.ends_with(".dll") && !basename.ends_with(".ocx") {
        format!("{basename}.dll")
    } else {
        basename
    }
}

/// Build the list of directories to search for a DLL, in order.
///
/// Standard Windows search order (subset):
/// 1. Application directory (directory of the main module)
/// 2. System directory (C:\Windows\System32)
/// 3. Windows directory (C:\Windows)
/// 4. Current directory
///
/// Each guest directory is resolved to a host path via the volume config.
fn search_directories(
    main_module_path: &str,
    volumes: &crate::vfs::VolumeConfig,
) -> Vec<std::path::PathBuf> {
    use crate::vfs::guest_path_to_host;

    let mut dirs: Vec<std::path::PathBuf> = Vec::new();

    let mut push_if_new = |path: std::path::PathBuf| {
        if !dirs.contains(&path) {
            dirs.push(path);
        }
    };

    // 1. Application directory.
    if let Some(parent) = std::path::Path::new(main_module_path).parent() {
        if let Some(map) = guest_path_to_host(volumes, &parent.to_string_lossy()) {
            push_if_new(map.host);
        }
    }

    // 2. System directory (C:\Windows\System32).
    if let Some(map) = guest_path_to_host(volumes, crate::vfs::GUEST_SYSTEM_DIR) {
        push_if_new(map.host);
    }

    // 3. Windows directory (C:\Windows).
    if let Some(map) = guest_path_to_host(volumes, crate::vfs::GUEST_WINDOWS_DIR) {
        push_if_new(map.host);
    }

    // 4. Current directory (same as app dir, may already be added).
    if let Some(parent) = std::path::Path::new(main_module_path).parent() {
        if let Some(map) = guest_path_to_host(volumes, &parent.to_string_lossy()) {
            push_if_new(map.host);
        }
    }

    dirs
}

/// Search for a DLL file across standard Windows search locations.
///
/// Returns the host path of the best match, or `None` if not found.
///
/// `dll_name` is the name as passed by the guest (e.g. "myplugin.dll"
/// or "C:\\App\\lib.dll" or just "sqlite3").
pub fn resolve_dll_path(
    dll_name: &str,
    main_module_path: &str,
    volumes: &crate::vfs::VolumeConfig,
) -> Option<std::path::PathBuf> {
    let clean = dll_name.trim().trim_matches('"');
    if clean.is_empty() {
        return None;
    }

    let search_name = normalize_dll_name(clean);

    // If the name contains a path separator or drive letter, resolve it directly.
    if clean.contains('\\') || clean.contains('/') || clean.contains(':') {
        // Try direct guest-path resolution.
        if let Some(map) = crate::vfs::guest_path_to_host(volumes, clean) {
            if map.host.is_file() {
                return Some(map.host);
            }
        }
        // Check if the clean path already ends with the target name
        // (case-insensitive to handle e.g. "LIB.DLL" → "lib.dll").
        if clean.to_ascii_lowercase().ends_with(&search_name) {
            return None;
        }
        // Try appending .dll to the original path.
        let with_ext = format!("{clean}.dll");
        if let Some(map) = crate::vfs::guest_path_to_host(volumes, &with_ext) {
            if map.host.is_file() {
                return Some(map.host);
            }
        }
        return None;
    }

    // Search standard locations.
    let dirs = search_directories(main_module_path, volumes);
    for dir in &dirs {
        let candidate = dir.join(&search_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

/// Apply PE base relocations when a DLL is loaded at a different base than
/// its preferred ImageBase.
///
/// `image_bytes` is a mutable view of the loaded image (already in guest
/// memory or a local buffer). `pe_bytes` is the raw file bytes (for reading
/// the relocation directory from file offsets).
///
/// `delta` = actual_base - preferred_base. Zero means no relocation needed.
/// `image_base_actual` is the absolute VA where the image was loaded.
///
/// ## Supported relocation types (PE64/x64)
/// - `IMAGE_REL_BASED_ABSOLUTE` (0): no-op alignment padding
/// - `IMAGE_REL_BASED_HIGHLOW` (3): 4-byte delta (PE32 / x86)
/// - `IMAGE_REL_BASED_DIR64` (10): 8-byte delta (x64 native)
///
/// All other types return an error (unsupported).
pub fn apply_relocations(
    pe: &goblin::pe::PE<'_>,
    pe_bytes: &[u8],
    image_bytes: &mut [u8],
    delta: i64,
) -> Result<()> {
    if delta == 0 {
        return Ok(()); // Loaded at preferred base — no relocation needed.
    }

    // Locate the base relocation directory (.reloc).
    let Some(header) = pe.header.optional_header.as_ref() else {
        bail!("no optional header for relocation processing");
    };
    let reloc_dir = header.data_directories.get_base_relocation_table()
        .context("no base relocation directory")?;

    if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
        bail!("DLL has no relocation table; cannot load at a different base");
    }

    // Map the relocation data from file offsets.
    let reloc_offset = rva_to_file_offset(pe, reloc_dir.virtual_address)
        .context("relocation table RVA outside file")?;
    let reloc_size = reloc_dir.size as usize;
    let reloc_data = pe_bytes.get(reloc_offset..reloc_offset + reloc_size)
        .context("relocation data extends beyond file")?;

    let mut offset = 0_usize;

    loop {
        if offset + 8 > reloc_data.len() {
            break;
        }

        let page_rva = u32::from_le_bytes(
            reloc_data[offset..offset + 4].try_into().unwrap(),
        );
        let block_size = u32::from_le_bytes(
            reloc_data[offset + 4..offset + 8].try_into().unwrap(),
        ) as usize;

        if block_size == 0 {
            break;
        }
        if block_size < 8 {
            bail!("invalid relocation block size: {block_size}");
        }

        let entry_count = (block_size - 8) / 2;
        let entries_base = offset + 8;

        for i in 0..entry_count {
            let entry_off = entries_base + i * 2;
            if entry_off + 2 > reloc_data.len() {
                bail!("relocation entry at offset {entry_off} exceeds block data");
            }

            let entry = u16::from_le_bytes(
                reloc_data[entry_off..entry_off + 2].try_into().unwrap(),
            );
            let type_ = entry >> 12;
            let rva_offset = u32::from(entry & 0x0fff);
            let target_rva = page_rva.wrapping_add(rva_offset);

            match type_ {
                0 => {
                    // IMAGE_REL_BASED_ABSOLUTE — no-op alignment padding.
                }
                3 => {
                    // IMAGE_REL_BASED_HIGHLOW — 32-bit delta (4-byte field).
                    let target_file_off = match rva_to_file_offset(pe, target_rva) {
                        Ok(off) => off,
                        Err(_) => continue,
                    };
                    if target_file_off + 4 > pe_bytes.len() {
                        continue;
                    }
                    let original = i32::from_le_bytes(
                        pe_bytes[target_file_off..target_file_off + 4].try_into().unwrap(),
                    );
                    let adjusted = original.wrapping_add(delta as i32);
                    let image_off = target_rva as usize;
                    if image_off + 4 > image_bytes.len() {
                        continue;
                    }
                    image_bytes[image_off..image_off + 4]
                        .copy_from_slice(&adjusted.to_le_bytes());
                }
                10 => {
                    // IMAGE_REL_BASED_DIR64 — 64-bit delta (8-byte field).
                    let target_file_off = match rva_to_file_offset(pe, target_rva) {
                        Ok(off) => off,
                        Err(_) => continue,
                    };
                    if target_file_off + 8 > pe_bytes.len() {
                        continue;
                    }
                    let original = i64::from_le_bytes(
                        pe_bytes[target_file_off..target_file_off + 8].try_into().unwrap(),
                    );
                    let adjusted = original.wrapping_add(delta);
                    let image_off = target_rva as usize;
                    if image_off + 8 > image_bytes.len() {
                        continue;
                    }
                    image_bytes[image_off..image_off + 8]
                        .copy_from_slice(&adjusted.to_le_bytes());
                }
                _ => {
                    bail!("unsupported relocation type {type_} at RVA {target_rva:#x}");
                }
            }
        }

        offset += block_size;
        if offset >= reloc_data.len() {
            break;
        }
    }

    Ok(())
}

/// Result of loading a DLL into guest memory.
#[derive(Debug)]
pub struct DllLoadResult {
    /// The loaded module descriptor.
    pub module: LoadedModule,
    /// Guest image base where the DLL was mapped.
    pub image_base: u64,
    /// Names of DLLs this module depends on (for recursive loading).
    pub dependencies: Vec<String>,
}

/// Apply PE section-level page protections from a map plan at a given base.
///
/// Mirrors the logic in `wie-runtime::session::apply_pe_section_protects` but
/// works for any image base (not just the main PE).
fn apply_pe_section_protects(
    engine: &mut dyn CpuEngine,
    plan: &wie_pe::PeMapPlan,
    image_base: u64,
) -> Result<()> {
    let image_size = usize::try_from(plan.size_of_image).context("size_of_image")?;
    if image_size == 0 {
        return Ok(());
    }

    // Gap pages: NOACCESS so VirtualQuery sees image space.
    engine
        .virtual_protect(image_base, image_size, wie_cpu::protect::PAGE_NOACCESS)
        .context("DLL gap NOACCESS protect")?;

    // Headers: READONLY.
    let header_len = u64::from(plan.header_size);
    if let Some((start, end)) = wie_pe::page_align_image_range(0, header_len, plan.size_of_image) {
        let len = usize::try_from(end.saturating_sub(start)).context("header range")?;
        if len > 0 {
            engine
                .virtual_protect(
                    image_base.saturating_add(start),
                    len,
                    wie_cpu::protect::PAGE_READONLY,
                )
                .context("DLL headers protect")?;
        }
    }

    // Sections: per-characteristics protect.
    for sec in &plan.sections {
        let rva = u64::from(sec.va);
        let vsize = u64::from(sec.virtual_size);
        if vsize == 0 {
            continue;
        }
        let Some((start, end)) = wie_pe::page_align_image_range(rva, vsize, plan.size_of_image)
        else {
            continue;
        };
        let len = usize::try_from(end.saturating_sub(start)).context("section range")?;
        if len == 0 {
            continue;
        }
        engine
            .virtual_protect(image_base.saturating_add(start), len, sec.final_protect)
            .with_context(|| format!("DLL section {} protect", sec.name))?;
    }

    Ok(())
}

/// Load a PE DLL file from the host path into guest memory.
///
/// ## Steps performed
/// 1. Read and parse the PE DLL file.
/// 2. Generate a unique module handle.
/// 3. Map guest memory for the image (temporary RWX).
/// 4. Copy headers and sections into guest memory.
/// 5. Apply base relocations if loading at a non-preferred address.
/// 6. Resolve imports via the provided callback.
/// 7. Parse exports and build the module descriptor.
/// 8. Apply final section-level page protections.
///
/// `resolve_import` is called for each IAT slot: `(library, name, iat_slot_va)`
/// returns the fake-API VA to write into the slot. The caller (wie-runtime)
/// provides the actual resolution via `SoftApiTable`.
pub fn load_dll(
    engine: &mut dyn CpuEngine,
    state: &mut crate::WinApiState,
    host_path: &std::path::Path,
    guest_path: &str,
    resolve_import: &mut dyn FnMut(&str, &str, u64) -> Result<u64>,
) -> Result<DllLoadResult> {
    // Step 1: Read and parse.
    let pe_bytes = std::fs::read(host_path)
        .with_context(|| format!("failed to read DLL: {}", host_path.display()))?;
    let pe = goblin::pe::PE::parse(&pe_bytes).context("failed to parse PE DLL")?;

    if !pe.is_64 {
        bail!("expected PE64 DLL, got PE32");
    }

    let identity =
        wie_pe::pe_identity_from_bytes(host_path, &pe_bytes).context("failed to parse PE identity")?;
    let preferred_base = identity.image_base;
    let size_of_image = usize::try_from(identity.size_of_image).context("size_of_image does not fit usize")?;
    let entry_rva = identity.entry_rva;

    // Step 2: Allocate a module handle.
    let handle = state.next_module_handle;
    state.next_module_handle = state
        .next_module_handle
        .checked_add(0x1000)
        .context("module handle overflow")?;

    // Step 3: Map guest memory. Try preferred base first.
    let load_base = preferred_base;
    let image_base = match engine.mem_map(load_base, size_of_image, wie_cpu::perm::ALL) {
        Ok(()) => load_base,
        Err(_) => {
            // Preferred base unavailable — allocate from an alternative region.
            // Use a VA derived from the handle (above fake module range).
            let alt_base = handle & !0xfff;
            engine
                .mem_map(alt_base, size_of_image, wie_cpu::perm::ALL)
                .context("failed to map DLL image memory at alternative base")?;
            alt_base
        }
    };

    let delta = image_base as i64 - preferred_base as i64;

    // Step 4: Build the map plan for section protections.
    let map_plan = wie_pe::pe_map_plan_from_bytes(&pe_bytes).context("failed to build DLL map plan")?;

    // Write headers to guest memory.
    let header_size = usize::try_from(identity.size_of_headers)
        .context("size_of_headers")?
        .min(pe_bytes.len());
    if header_size > 0 {
        engine
            .mem_write(image_base, &pe_bytes[..header_size])
            .context("failed to write DLL headers")?;
    }

    // Write sections directly into guest memory.
    for section in &pe.sections {
        let virtual_address = u64::from(section.virtual_address);
        let raw_offset = usize::try_from(section.pointer_to_raw_data).context("section raw offset")?;
        let raw_size = usize::try_from(section.size_of_raw_data).context("section raw size")?;
        let virtual_size = usize::try_from(section.virtual_size).unwrap_or(0);

        let va = image_base.wrapping_add(virtual_address);

        if raw_size > 0 {
            let end = raw_offset.saturating_add(raw_size).min(pe_bytes.len());
            engine
                .mem_write(va, &pe_bytes[raw_offset..end])
                .with_context(|| format!("failed to write section {}", section.name().unwrap_or("?")))?;
        }

        // Zero-fill the BSS tail (virtual_size > raw_size).
        let raw_size_rounded = raw_size.max(1);
        if virtual_size > raw_size_rounded {
            let fill_va = va.wrapping_add(raw_size_rounded as u64);
            let fill_len = virtual_size.saturating_sub(raw_size_rounded);
            let zeros = vec![0_u8; fill_len];
            engine
                .mem_write(fill_va, &zeros)
                .with_context(|| format!("failed to zero-fill section {}", section.name().unwrap_or("?")))?;
        }
    }

    // Step 5: Apply relocations if needed.
    if delta != 0 {
        let mut image_buf = vec![0_u8; size_of_image];
        engine
            .mem_read(image_base, &mut image_buf)
            .context("failed to read back DLL image for relocation")?;
        apply_relocations(&pe, &pe_bytes, &mut image_buf, delta)?;
        engine
            .mem_write(image_base, &image_buf)
            .context("failed to write relocated DLL image")?;
    }

    // Step 6: Resolve imports.
    let imports = wie_pe::inspect_pe_imports_bytes(&pe_bytes).context("failed to parse DLL imports")?;
    let mut dependencies: Vec<String> = Vec::new();
    let mut seen_libs: HashSet<String> = HashSet::new();

    for import in &imports {
        let lib_lower = import.library.to_ascii_lowercase();
        if seen_libs.insert(lib_lower) {
            dependencies.push(import.library.clone());
        }

        let name = if import.name.is_empty() {
            format!("ORDINAL {}", import.ordinal)
        } else {
            import.name.clone()
        };

        let iat_va = image_base.wrapping_add(import.iat_slot_rva);
        let target_va = resolve_import(&import.library, &name, iat_va)
            .with_context(|| format!("failed to resolve import {}!{}", import.library, name))?;
        engine
            .mem_write(iat_va, &target_va.to_le_bytes())
            .context("failed to patch DLL IAT slot")?;
    }

    // Step 7: Parse exports.
    let exports = parse_dll_exports(&pe, &pe_bytes).context("failed to parse DLL exports")?;

    let module_name = host_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.dll")
        .to_ascii_lowercase();

    let module = LoadedModule {
        handle,
        image_base,
        image_size: size_of_image,
        entry_rva,
        name: module_name.clone(),
        guest_path: guest_path.to_owned(),
        host_path: host_path.to_owned(),
        ref_count: 1,
        exports_by_name: exports.by_name,
        exports_by_ordinal: exports.by_ordinal,
        ordinal_base: exports.ordinal_base,
        export_count: exports.export_count,
    };

    state.loaded_modules.insert(module_name, module.clone());

    // Step 8: Apply section protections.
    apply_pe_section_protects(engine, &map_plan, image_base)
        .context("failed to apply DLL section protects")?;

    Ok(DllLoadResult {
        module,
        image_base,
        dependencies,
    })
}

// ---------------------------------------------------------------------------
// DllMain support
// ---------------------------------------------------------------------------

/// Reason codes for DllMain (Microsoft Learn: dllmain.h).
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;
pub const DLL_PROCESS_DETACH: u32 = 0;

/// Set up guest CPU state to call a DLL's entry point (DllMain).
///
/// This function pushes a return address, sets the calling convention
/// registers (RCX/RDX/R8), and updates RIP to the DLL entry point.
/// The caller (runtime session) must execute guest code until the
/// return address is hit, then handle the result.
///
/// # DllMain signature (Win64)
/// ```text
/// BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
/// ```
///
/// # Arguments
/// * `engine` - CPU engine to modify guest state.
/// * `module` - The loaded DLL module descriptor.
/// * `reason` - DllMain reason code (DLL_PROCESS_ATTACH, etc.).
/// * `reserved` - Reserved parameter (0 for dynamic loads, 1 for static).
/// * `fake_return_va` - A fake VA in the host-stop hook range that the
///   runtime will intercept when DllMain returns.
///
/// # Returns
/// * `Ok(())` if the call state was prepared (or if the DLL has no entry point).
/// * `Err` if guest state could not be modified.
pub fn prepare_dll_main_call(
    engine: &mut dyn CpuEngine,
    module: &LoadedModule,
    reason: u32,
    reserved: u64,
    fake_return_va: u64,
) -> Result<()> {
    if module.entry_rva == 0 {
        return Ok(()); // No entry point — nothing to call.
    }

    let entry_va = module.image_base.wrapping_add(module.entry_rva);

    // Push the fake return address onto the guest stack.
    let rsp = engine.read_rsp().context("failed to read RSP for DllMain")?;
    let new_rsp = rsp.wrapping_sub(8);
    engine
        .mem_write(new_rsp, &fake_return_va.to_le_bytes())
        .context("failed to push DllMain return address")?;
    engine
        .write_rsp(new_rsp)
        .context("failed to write RSP for DllMain")?;

    // Set calling convention registers (Microsoft x64 calling convention).
    engine
        .write_rcx(module.image_base)
        .context("failed to write RCX (hinstDLL) for DllMain")?;
    engine
        .write_rdx(u64::from(reason))
        .context("failed to write RDX (fdwReason) for DllMain")?;
    engine
        .write_r8(reserved)
        .context("failed to write R8 (lpvReserved) for DllMain")?;

    // Set RIP to the DLL entry point.
    engine
        .write_rip(entry_va)
        .context("failed to write RIP for DllMain")?;

    Ok(())
}