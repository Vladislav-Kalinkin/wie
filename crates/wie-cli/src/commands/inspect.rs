//! PE inspection and static analysis commands.

use super::util::write_line;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::path::Path;

/// Prints basic PE64 metadata.
pub(crate) fn inspect(path: &Path) -> Result<()> {
    let summary = wie_pe::inspect_pe_file(path)?;

    println!("file: {}", summary.path);
    println!("format: {}", format_pe_kind(summary.is_pe64));
    println!("machine: {}", format_machine(summary.machine));
    println!("image_base: {:#018x}", summary.image_base);
    println!("entry_rva: {:#010x}", summary.entry_rva);
    println!("entry_point: {:#018x}", summary.entry_point_va);
    println!("sections: {}", summary.section_count);
    println!("import_libraries: {}", summary.library_count);
    println!("import_functions: {}", summary.import_count);

    Ok(())
}

fn format_pe_kind(is_pe64: bool) -> &'static str {
    if is_pe64 { "PE64" } else { "PE32" }
}

fn format_machine(machine: u16) -> String {
    match machine {
        0x8664 => "AMD64 (0x8664)".to_owned(),
        0x014c => "I386 (0x014c)".to_owned(),
        other => format!("unknown ({other:#06x})"),
    }
}

/// Prints PE section layout.
pub(crate) fn sections(path: &Path) -> Result<()> {
    let sections = wie_pe::inspect_pe_sections(path)?;

    for section in sections {
        println!(
            "{:<8} va={:#018x} rva={:#010x} vsize={:#010x} raw={:#010x} raw_size={:#010x}",
            section.name,
            section.virtual_address_va,
            section.virtual_address,
            section.virtual_size,
            section.pointer_to_raw_data,
            section.size_of_raw_data
        );
    }

    Ok(())
}

/// Prints the import address table, optionally filtered.
pub(crate) fn imports(path: &Path, find: Option<&str>) -> Result<()> {
    let imports = wie_pe::inspect_pe_imports(path)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let normalized_filter = find.map(str::to_lowercase);

    for import in imports {
        let imported_name = format_import_name(&import.name, import.ordinal);
        let full_name = format!("{}!{}", import.library, imported_name);

        if let Some(filter) = &normalized_filter {
            let normalized_full_name = full_name.to_lowercase();
            if !normalized_full_name.contains(filter) {
                continue;
            }
        }

        let line = format!(
            "{:#018x} rva={:#010x} {:<16} {}",
            import.iat_slot_va, import.iat_slot_rva, import.library, imported_name
        );

        if !write_line(&mut output, &line)? {
            return Ok(());
        }
    }

    Ok(())
}

fn format_import_name(name: &str, ordinal: u16) -> String {
    if name.is_empty() {
        format!("ORDINAL {ordinal}")
    } else {
        name.to_owned()
    }
}

/// Builds and prints a Windows-loader-like image summary.
pub(crate) fn image(path: &Path) -> Result<()> {
    let (_image, summary) = wie_pe::build_loaded_image(path)?;

    println!("image_base: {:#018x}", summary.image_base);
    println!("entry_rva: {:#010x}", summary.entry_rva);
    println!("entry_point: {:#018x}", summary.entry_point_va);
    println!("image_size: {:#010x}", summary.image_size);
    println!("header_size: {:#010x}", summary.header_size);
    println!("sections: {}", summary.section_count);

    Ok(())
}

/// Writes a text map of imported WinAPI functions and handler coverage.
pub(crate) fn winapi_map(path: &Path, out: Option<&Path>) -> Result<()> {
    let imports = wie_pe::inspect_pe_imports(path)?;

    let mut by_library: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut implemented_count = 0_usize;
    let mut todo_count = 0_usize;

    for import in &imports {
        let name = if import.name.is_empty() {
            format!("ORDINAL {}", import.ordinal)
        } else {
            import.name.clone()
        };

        let implemented = wie_winapi::is_winapi_implemented(&import.library, &name);

        if implemented {
            implemented_count = implemented_count
                .checked_add(1)
                .context("implemented count overflow")?;
        } else {
            todo_count = todo_count.checked_add(1).context("todo count overflow")?;
        }

        let status = if implemented { "DONE" } else { "TODO" };

        let line = format!(
            "[{status}] iat={:#018x} rva={:#010x} {}!{}",
            import.iat_slot_va, import.iat_slot_rva, import.library, name
        );

        by_library
            .entry(import.library.clone())
            .or_default()
            .push(line);
    }

    let mut text = String::new();

    text.push_str("WIE WinAPI Import Map\n");
    text.push_str("====================\n\n");

    writeln!(text, "file: {}", path.display()).context("failed to write file line")?;
    writeln!(text, "total_imports: {}", imports.len()).context("failed to write import count")?;
    writeln!(text, "implemented: {implemented_count}")
        .context("failed to write implemented count")?;
    writeln!(text, "todo: {todo_count}\n").context("failed to write todo count")?;

    for (library, lines) in by_library {
        writeln!(text, "{library}").context("failed to write library heading")?;
        text.push_str("----------------------------------------\n");

        for line in lines {
            text.push_str(&line);
            text.push('\n');
        }

        text.push('\n');
    }

    if let Some(output_path) = out {
        std::fs::write(output_path, text)
            .with_context(|| format!("failed to write WinAPI map: {}", output_path.display()))?;
    } else {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        output
            .write_all(text.as_bytes())
            .context("failed to write WinAPI map to stdout")?;
    }

    Ok(())
}
