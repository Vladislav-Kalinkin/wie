//! Entry-point API tracing command.

use super::util::write_entry_trace_summary;
use anyhow::Result;
use std::io;
use std::path::Path;

/// Controlled entry-point API trace (first N host stops).
pub(crate) fn entry_trace(path: &Path, max_api: usize) -> Result<()> {
    let summary = wie_runtime::entry_trace(path, max_api)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_entry_trace_summary(&mut output, &summary)
}
