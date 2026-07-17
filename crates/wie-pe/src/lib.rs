//! PE64 inspection and loading helpers for WIE (generic PE64 userspace).

use anyhow::{Context, Result, bail};
use goblin::pe::PE;
use serde::Serialize;
use std::path::Path;

/// Loader identity of a PE64 image: fields the runtime must take from the file,
/// not from Lunar Magic constants.
///
/// Entry VA is `image_base + entry_rva` (`AddressOfEntryPoint` in the optional header).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeIdentity {
    /// Host path used when the image was opened (display / diagnostics).
    pub path: String,

    /// Preferred `ImageBase` from the optional header.
    pub image_base: u64,

    /// `AddressOfEntryPoint` RVA.
    pub entry_rva: u64,

    /// Absolute entry VA: `image_base + entry_rva`.
    pub entry_va: u64,

    /// `SizeOfImage`.
    pub size_of_image: u64,

    /// `SizeOfHeaders`.
    pub size_of_headers: u32,

    /// COFF `Machine`.
    pub machine: u16,

    /// Always true for images accepted by this crate (PE32+ only).
    pub is_pe64: bool,

    /// Number of sections.
    pub section_count: usize,
}

/// Guest-visible process identity derived from the host PE path.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// Basename used for command line / module file name (e.g. `heap_alloc.exe`).
    pub module_file_name: String,

    /// Guest full path of the main module (e.g. `C:\App\heap_alloc.exe`).
    pub module_path: String,

    /// Guest current directory (parent of `module_path`, e.g. `C:\App`).
    pub current_directory: String,

    /// Default command line (module basename, Windows-style).
    pub command_line: String,
}

/// Builds guest process identity from a host PE path (no PE parsing).
#[must_use]
pub fn process_identity_from_host_path(host_path: &Path) -> ProcessIdentity {
    let module_file_name = host_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("app.exe")
        .to_owned();
    let module_path = format!(r"C:\App\{module_file_name}");
    let current_directory = r"C:\App".to_owned();
    let command_line = module_file_name.clone();
    ProcessIdentity {
        module_file_name,
        module_path,
        current_directory,
        command_line,
    }
}

/// Parses PE64 bytes and returns loader identity (image base + entry).
pub fn pe_identity_from_bytes(path: &Path, bytes: &[u8]) -> Result<PeIdentity> {
    let pe = PE::parse(bytes).context("failed to parse PE image")?;

    if !pe.is_64 {
        bail!("expected PE64 image, got PE32");
    }

    let image_base = u64::try_from(pe.image_base).context("image base does not fit into u64")?;
    let entry_rva = u64::try_from(pe.entry).context("entry point does not fit into u64")?;
    let entry_va = image_base
        .checked_add(entry_rva)
        .context("entry point VA overflow")?;

    let optional_header = pe
        .header
        .optional_header
        .as_ref()
        .context("PE image has no optional header")?;

    let size_of_image = u64::from(optional_header.windows_fields.size_of_image);
    let size_of_headers = optional_header.windows_fields.size_of_headers;

    Ok(PeIdentity {
        path: path.display().to_string(),
        image_base,
        entry_rva,
        entry_va,
        size_of_image,
        size_of_headers,
        machine: pe.header.coff_header.machine,
        is_pe64: true,
        section_count: pe.sections.len(),
    })
}

/// Reads a PE64 file and returns loader identity.
pub fn pe_identity_from_file(path: &Path) -> Result<PeIdentity> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read PE file: {}", path.display()))?;
    pe_identity_from_bytes(path, &bytes)
}

/// Basic `PE` image information needed before loading the executable.
#[derive(Debug, Clone, Serialize)]
pub struct PeImageSummary {
    /// Input file path.
    pub path: String,

    /// Whether the image is `PE64`.
    pub is_pe64: bool,

    /// `COFF` machine field.
    pub machine: u16,

    /// Preferred image base.
    pub image_base: u64,

    /// `AddressOfEntryPoint` RVA.
    pub entry_rva: u64,

    /// Absolute entry point virtual address (`image_base + entry_rva`).
    pub entry_point_va: u64,

    /// Number of sections.
    pub section_count: usize,

    /// Number of imported libraries.
    pub library_count: usize,

    /// Number of imported functions.
    pub import_count: usize,
}

/// `PE` section metadata needed for image mapping.
#[derive(Debug, Clone, Serialize)]
pub struct PeSectionSummary {
    /// Section name.
    pub name: String,

    /// Section virtual address relative to image base.
    pub virtual_address: u32,

    /// Section virtual size.
    pub virtual_size: u32,

    /// Section raw file offset.
    pub pointer_to_raw_data: u32,

    /// Section raw file size.
    pub size_of_raw_data: u32,

    /// Absolute section virtual address.
    pub virtual_address_va: u64,
}

/// Imported `PE` function metadata.
#[derive(Debug, Clone, Serialize)]
pub struct PeImportSummary {
    /// Imported library name.
    pub library: String,

    /// Imported function name.
    pub name: String,

    /// Imported ordinal. Zero usually means name import.
    pub ordinal: u16,

    /// Import address table slot virtual address.
    pub iat_slot_va: u64,

    /// Import address table slot relative virtual address.
    pub iat_slot_rva: u64,

    /// Hint/name table relative virtual address.
    pub hint_name_rva: Option<u64>,
}

/// Loaded `PE` image layout prepared for runtime mapping.
#[derive(Debug, Clone, Serialize)]
pub struct PeLoadedImageSummary {
    /// Preferred image base (from PE optional header).
    pub image_base: u64,

    /// `AddressOfEntryPoint` RVA (from PE optional header).
    pub entry_rva: u64,

    /// Absolute entry point virtual address (`image_base + entry_rva`).
    pub entry_point_va: u64,

    /// Total image size in memory.
    pub image_size: usize,

    /// Number of copied header bytes.
    pub header_size: usize,

    /// Number of sections copied into the memory image.
    pub section_count: usize,
}

impl PeLoadedImageSummary {
    /// Loader identity view of this loaded image (path optional).
    #[must_use]
    pub fn identity(&self, path: &Path) -> PeIdentity {
        PeIdentity {
            path: path.display().to_string(),
            image_base: self.image_base,
            entry_rva: self.entry_rva,
            entry_va: self.entry_point_va,
            size_of_image: u64::try_from(self.image_size).unwrap_or(u64::MAX),
            size_of_headers: u32::try_from(self.header_size).unwrap_or(u32::MAX),
            machine: 0,
            is_pe64: true,
            section_count: self.section_count,
        }
    }
}

/// Patched fake import entry.
#[derive(Debug, Clone, Serialize)]
pub struct PePatchedImport {
    /// Imported library name.
    pub library: String,

    /// Imported function name, or an `ORDINAL` label.
    pub name: String,

    /// Runtime `IAT` slot virtual address.
    pub iat_slot_va: u64,

    /// Runtime `IAT` slot relative virtual address.
    pub iat_slot_rva: u64,

    /// Fake API target virtual address written into the `IAT` slot.
    pub fake_target_va: u64,
}

/// Fake API lookup entry used by the runtime dispatcher.
#[derive(Debug, Clone, Serialize)]
pub struct PeFakeApiEntry {
    /// Fake API target virtual address.
    pub fake_target_va: u64,

    /// Imported library name.
    pub library: String,

    /// Imported function name, or an `ORDINAL` label.
    pub name: String,

    /// Runtime `IAT` slot virtual address.
    pub iat_slot_va: u64,

    /// Runtime `IAT` slot relative virtual address.
    pub iat_slot_rva: u64,
}

/// Reads and inspects a `PE` image from disk.
pub fn inspect_pe_file(path: &Path) -> Result<PeImageSummary> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read PE file: {}", path.display()))?;

    inspect_pe_bytes(path, &bytes)
}

/// Inspects a `PE` image from bytes.
pub fn inspect_pe_bytes(path: &Path, bytes: &[u8]) -> Result<PeImageSummary> {
    let pe = PE::parse(bytes).context("failed to parse PE image")?;

    if !pe.is_64 {
        bail!("expected PE64 image, got PE32");
    }

    let identity = pe_identity_from_bytes(path, bytes)?;

    Ok(PeImageSummary {
        path: identity.path,
        is_pe64: identity.is_pe64,
        machine: identity.machine,
        image_base: identity.image_base,
        entry_rva: identity.entry_rva,
        entry_point_va: identity.entry_va,
        section_count: identity.section_count,
        library_count: pe.libraries.len(),
        import_count: pe.imports.len(),
    })
}

/// Reads section metadata from a `PE` image on disk.
pub fn inspect_pe_sections(path: &Path) -> Result<Vec<PeSectionSummary>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read PE file: {}", path.display()))?;

    inspect_pe_sections_bytes(&bytes)
}

/// Reads section metadata from `PE` bytes.
pub fn inspect_pe_sections_bytes(bytes: &[u8]) -> Result<Vec<PeSectionSummary>> {
    let pe = PE::parse(bytes).context("failed to parse PE image")?;

    if !pe.is_64 {
        bail!("expected PE64 image, got PE32");
    }

    let image_base = u64::try_from(pe.image_base).context("image base does not fit into u64")?;
    let mut sections = Vec::with_capacity(pe.sections.len());

    for section in &pe.sections {
        let name = section
            .name()
            .context("failed to read section name")?
            .to_owned();

        let section_rva = u64::from(section.virtual_address);
        let virtual_address_va = image_base
            .checked_add(section_rva)
            .context("section VA overflow")?;

        sections.push(PeSectionSummary {
            name,
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            pointer_to_raw_data: section.pointer_to_raw_data,
            size_of_raw_data: section.size_of_raw_data,
            virtual_address_va,
        });
    }

    Ok(sections)
}

/// Reads import metadata from a `PE` image on disk.
pub fn inspect_pe_imports(path: &Path) -> Result<Vec<PeImportSummary>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read PE file: {}", path.display()))?;

    inspect_pe_imports_bytes(&bytes)
}

/// Reads import metadata from `PE` bytes.
pub fn inspect_pe_imports_bytes(bytes: &[u8]) -> Result<Vec<PeImportSummary>> {
    let pe = PE::parse(bytes).context("failed to parse PE image")?;

    if !pe.is_64 {
        bail!("expected PE64 image, got PE32");
    }

    let image_base = u64::try_from(pe.image_base).context("image base does not fit into u64")?;
    let import_directory = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|optional| optional.data_directories.get_import_table())
        .context("PE image has no import directory")?;

    if import_directory.virtual_address == 0 {
        return Ok(Vec::new());
    }

    let mut imports = Vec::new();
    let mut descriptor_rva = import_directory.virtual_address;

    loop {
        let descriptor_offset = rva_to_file_offset(&pe, descriptor_rva).with_context(|| {
            format!("failed to map import descriptor RVA {descriptor_rva:#010x}")
        })?;

        let original_first_thunk = read_u32(bytes, descriptor_offset)?;
        let _time_date_stamp = read_u32(bytes, checked_add_usize(descriptor_offset, 4)?)?;
        let _forwarder_chain = read_u32(bytes, checked_add_usize(descriptor_offset, 8)?)?;
        let name_rva = read_u32(bytes, checked_add_usize(descriptor_offset, 12)?)?;
        let first_thunk = read_u32(bytes, checked_add_usize(descriptor_offset, 16)?)?;

        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let library = read_c_string_at_rva(&pe, bytes, name_rva)
            .with_context(|| format!("failed to read DLL name at RVA {name_rva:#010x}"))?;

        let lookup_thunk = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };

        read_import_thunks(
            &pe,
            bytes,
            image_base,
            &library,
            lookup_thunk,
            first_thunk,
            &mut imports,
        )?;

        descriptor_rva = descriptor_rva
            .checked_add(20)
            .context("import descriptor RVA overflow")?;
    }

    Ok(imports)
}

fn read_import_thunks(
    pe: &PE<'_>,
    bytes: &[u8],
    image_base: u64,
    library: &str,
    lookup_thunk_rva: u32,
    first_thunk_rva: u32,
    imports: &mut Vec<PeImportSummary>,
) -> Result<()> {
    let mut index = 0_u64;

    loop {
        let lookup_entry_rva = u64::from(lookup_thunk_rva)
            .checked_add(
                index
                    .checked_mul(8)
                    .context("lookup thunk index overflow")?,
            )
            .context("lookup thunk RVA overflow")?;

        let lookup_entry_offset = rva_to_file_offset_u64(pe, lookup_entry_rva)
            .with_context(|| format!("failed to map lookup thunk RVA {lookup_entry_rva:#010x}"))?;

        let thunk_value = read_u64(bytes, lookup_entry_offset)?;

        if thunk_value == 0 {
            break;
        }

        let iat_slot_rva = u64::from(first_thunk_rva)
            .checked_add(index.checked_mul(8).context("IAT index overflow")?)
            .context("IAT slot RVA overflow")?;

        let iat_slot_va = image_base
            .checked_add(iat_slot_rva)
            .context("IAT slot VA overflow")?;

        let ordinal_flag = 0x8000_0000_0000_0000_u64;

        if (thunk_value & ordinal_flag) != 0 {
            let ordinal =
                u16::try_from(thunk_value & 0xffff).context("ordinal does not fit u16")?;
            imports.push(PeImportSummary {
                library: library.to_owned(),
                name: String::new(),
                ordinal,
                iat_slot_va,
                iat_slot_rva,
                hint_name_rva: None,
            });
        } else {
            let hint_name_rva_u32 =
                u32::try_from(thunk_value).context("hint/name RVA does not fit u32")?;
            let hint_name_offset =
                rva_to_file_offset(pe, hint_name_rva_u32).with_context(|| {
                    format!("failed to map hint/name RVA {hint_name_rva_u32:#010x}")
                })?;

            let hint = read_u16(bytes, hint_name_offset)?;
            let name_offset = checked_add_usize(hint_name_offset, 2)?;
            let name = read_c_string_at_offset(bytes, name_offset)?;

            imports.push(PeImportSummary {
                library: library.to_owned(),
                name,
                ordinal: hint,
                iat_slot_va,
                iat_slot_rva,
                hint_name_rva: Some(u64::from(hint_name_rva_u32)),
            });
        }

        index = index
            .checked_add(1)
            .context("import thunk index overflow")?;
    }

    Ok(())
}

fn rva_to_file_offset(pe: &PE<'_>, rva: u32) -> Result<usize> {
    rva_to_file_offset_u64(pe, u64::from(rva))
}

fn rva_to_file_offset_u64(pe: &PE<'_>, rva: u64) -> Result<usize> {
    for section in &pe.sections {
        let section_rva = u64::from(section.virtual_address);
        let virtual_size = u64::from(section.virtual_size);
        let raw_size = u64::from(section.size_of_raw_data);
        let mapped_size = virtual_size.max(raw_size);

        let section_end = section_rva
            .checked_add(mapped_size)
            .context("section RVA range overflow")?;

        if rva >= section_rva && rva < section_end {
            let delta = rva
                .checked_sub(section_rva)
                .context("RVA delta underflow")?;
            let raw_offset = u64::from(section.pointer_to_raw_data)
                .checked_add(delta)
                .context("raw file offset overflow")?;

            return usize::try_from(raw_offset).context("raw file offset does not fit usize");
        }
    }

    bail!("RVA {rva:#010x} is not inside any section")
}

fn read_c_string_at_rva(pe: &PE<'_>, bytes: &[u8], rva: u32) -> Result<String> {
    let offset = rva_to_file_offset(pe, rva)?;
    read_c_string_at_offset(bytes, offset)
}

fn read_c_string_at_offset(bytes: &[u8], offset: usize) -> Result<String> {
    let tail = bytes
        .get(offset..)
        .context("string offset is outside file")?;

    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .context("unterminated C string")?;

    let string_bytes = tail.get(..end).context("failed to slice C string bytes")?;

    let value = std::str::from_utf8(string_bytes).context("C string is not valid UTF-8")?;

    Ok(value.to_owned())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = read_array::<2>(bytes, offset)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = read_array::<4>(bytes, offset)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw = read_array::<8>(bytes, offset)?;
    Ok(u64::from_le_bytes(raw))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).context("read range overflow")?;
    let slice = bytes
        .get(offset..end)
        .context("read range is outside file")?;

    <[u8; N]>::try_from(slice).context("failed to convert slice into fixed-size array")
}

fn checked_add_usize(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).context("usize addition overflow")
}

/// Builds a Windows-loader-like memory image from a `PE64` file.
pub fn build_loaded_image(path: &Path) -> Result<(Vec<u8>, PeLoadedImageSummary)> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read PE file: {}", path.display()))?;

    build_loaded_image_bytes(&bytes)
}

/// Builds a Windows-loader-like memory image from `PE64` bytes.
pub fn build_loaded_image_bytes(bytes: &[u8]) -> Result<(Vec<u8>, PeLoadedImageSummary)> {
    let pe = PE::parse(bytes).context("failed to parse PE image")?;

    if !pe.is_64 {
        bail!("expected PE64 image, got PE32");
    }

    // Path is only for diagnostics in identity; bytes carry all header fields.
    let identity = pe_identity_from_bytes(Path::new("<memory>"), bytes)?;

    let image_size =
        usize::try_from(identity.size_of_image).context("size_of_image does not fit usize")?;
    let header_size =
        usize::try_from(identity.size_of_headers).context("size_of_headers does not fit usize")?;

    if header_size > bytes.len() {
        bail!("size_of_headers is larger than file size");
    }

    let mut image = vec![0_u8; image_size];

    let headers_dst = image
        .get_mut(..header_size)
        .context("failed to slice image headers")?;
    let headers_src = bytes
        .get(..header_size)
        .context("failed to slice source headers")?;
    headers_dst.copy_from_slice(headers_src);

    for section in &pe.sections {
        copy_section(bytes, &mut image, section)?;
    }

    let summary = PeLoadedImageSummary {
        image_base: identity.image_base,
        entry_rva: identity.entry_rva,
        entry_point_va: identity.entry_va,
        image_size,
        header_size,
        section_count: identity.section_count,
    };

    Ok((image, summary))
}

fn copy_section(
    source: &[u8],
    image: &mut [u8],
    section: &goblin::pe::section_table::SectionTable,
) -> Result<()> {
    let raw_offset = usize::try_from(section.pointer_to_raw_data)
        .context("section raw offset does not fit usize")?;
    let raw_size =
        usize::try_from(section.size_of_raw_data).context("section raw size does not fit usize")?;
    let virtual_address = usize::try_from(section.virtual_address)
        .context("section virtual address does not fit usize")?;
    let virtual_size =
        usize::try_from(section.virtual_size).context("section virtual size does not fit usize")?;

    let bytes_to_copy = raw_size.min(virtual_size.max(raw_size));

    if bytes_to_copy == 0 {
        return Ok(());
    }

    let source_end = raw_offset
        .checked_add(bytes_to_copy)
        .context("section source range overflow")?;
    let image_end = virtual_address
        .checked_add(bytes_to_copy)
        .context("section image range overflow")?;

    let source_slice = source
        .get(raw_offset..source_end)
        .context("section raw range is outside file")?;
    let image_slice = image
        .get_mut(virtual_address..image_end)
        .context("section virtual range is outside image")?;

    image_slice.copy_from_slice(source_slice);

    Ok(())
}

/// Builds a loaded image and patches `IAT` slots with fake API addresses.
pub fn build_loaded_image_with_fake_imports(
    path: &Path,
) -> Result<(Vec<u8>, PeLoadedImageSummary, Vec<PePatchedImport>)> {
    let (mut image, summary) = build_loaded_image(path)?;
    let imports = inspect_pe_imports(path)?;
    let patched = patch_loaded_image_imports(&mut image, &imports)?;

    Ok((image, summary, patched))
}

/// Patches `IAT` slots in an already loaded image.
pub fn patch_loaded_image_imports(
    image: &mut [u8],
    imports: &[PeImportSummary],
) -> Result<Vec<PePatchedImport>> {
    const FAKE_API_BASE: u64 = 0x0000_7000_0000_0000;
    const FAKE_API_STRIDE: u64 = 0x10;

    let mut patched = Vec::with_capacity(imports.len());

    for (index, import) in imports.iter().enumerate() {
        let index_u64 = u64::try_from(index).context("import index does not fit u64")?;
        let fake_target_va = FAKE_API_BASE
            .checked_add(
                index_u64
                    .checked_mul(FAKE_API_STRIDE)
                    .context("fake API index multiplication overflow")?,
            )
            .context("fake API address overflow")?;

        let slot_offset =
            usize::try_from(import.iat_slot_rva).context("IAT slot RVA does not fit usize")?;

        let slot_end = slot_offset
            .checked_add(8)
            .context("IAT slot write range overflow")?;

        let slot = image
            .get_mut(slot_offset..slot_end)
            .context("IAT slot is outside loaded image")?;

        slot.copy_from_slice(&fake_target_va.to_le_bytes());

        let name = if import.name.is_empty() {
            format!("ORDINAL {}", import.ordinal)
        } else {
            import.name.clone()
        };

        patched.push(PePatchedImport {
            library: import.library.clone(),
            name,
            iat_slot_va: import.iat_slot_va,
            iat_slot_rva: import.iat_slot_rva,
            fake_target_va,
        });
    }

    Ok(patched)
}

/// Converts patched imports into fake API dispatcher lookup entries.
#[must_use]
pub fn build_fake_api_lookup(patched: &[PePatchedImport]) -> Vec<PeFakeApiEntry> {
    patched
        .iter()
        .map(|import| PeFakeApiEntry {
            fake_target_va: import.fake_target_va,
            library: import.library.clone(),
            name: import.name.clone(),
            iat_slot_va: import.iat_slot_va,
            iat_slot_rva: import.iat_slot_rva,
        })
        .collect()
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn process_identity_uses_host_basename() {
        let path = Path::new(r"/tmp/games/heap_alloc.exe");
        let id = process_identity_from_host_path(path);
        assert_eq!(id.module_file_name, "heap_alloc.exe");
        assert_eq!(id.module_path, r"C:\App\heap_alloc.exe");
        assert_eq!(id.current_directory, r"C:\App");
        assert_eq!(id.command_line, "heap_alloc.exe");
    }

    #[test]
    fn process_identity_no_basename_falls_back() {
        let path = Path::new(r"");
        let id = process_identity_from_host_path(path);
        assert_eq!(id.module_file_name, "app.exe");
    }

    #[test]
    fn process_identity_no_extension() {
        let path = Path::new(r"my_binary");
        let id = process_identity_from_host_path(path);
        assert_eq!(id.module_file_name, "my_binary");
    }

    #[test]
    fn process_identity_does_not_parse_pe() {
        let path = Path::new(r"/tmp/some_random_file.xyz");
        let id = process_identity_from_host_path(path);
        assert_eq!(id.module_file_name, "some_random_file.xyz");
    }

    #[test]
    fn pe_identity_rejects_invalid_bytes() {
        let result = pe_identity_from_bytes(Path::new("test.exe"), b"not a PE");
        assert!(result.is_err());
    }

    #[test]
    fn pe_identity_from_micro_heap_alloc_if_present() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("micro-exes/out/heap_alloc.exe");
        if !path.is_file() {
            return;
        }
        let id = pe_identity_from_file(&path).expect("parse micro PE");
        assert!(id.is_pe64);
        assert_eq!(id.entry_va, id.image_base.saturating_add(id.entry_rva));
        assert_eq!(id.image_base, 0x0000_0001_4000_0000);
        assert_eq!(id.entry_rva, 0x1000);
    }
}
