//! Shared CLI output helpers.

use anyhow::{Context, Result};
use std::io::{ErrorKind, Write};

/// Writes one line to `output`.
///
/// Returns `Ok(false)` on a broken pipe so callers can exit cleanly when
/// stdout is closed by a pager (`head`, `less`, …).
pub(crate) fn write_line(output: &mut impl Write, line: &str) -> Result<bool> {
    match writeln!(output, "{line}") {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::BrokenPipe => Ok(false),
        Err(error) => Err(error).context("failed to write stdout"),
    }
}

/// Formats an optional address for trace output (`"-"` when absent).
pub(crate) fn format_optional_hex(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |v| format!("{v:#018x}"))
}

/// Formats one entry-trace API event.
pub(crate) fn format_entry_trace_event(event: &wie_runtime::EntryTraceEvent) -> String {
    let status = if event.handled {
        "handled"
    } else {
        "unsupported"
    };

    format!(
        "api[{}] {} fake={:#018x} ret={} resume={} {}!{}",
        event.index,
        status,
        event.fake_target_va,
        format_optional_hex(event.return_value),
        format_optional_hex(event.return_address),
        event.library,
        event.name,
    )
}

/// Writes a full entry-trace style summary (used by several smokes).
pub(crate) fn write_entry_trace_summary(
    output: &mut impl Write,
    summary: &wie_runtime::EntryTraceSummary,
) -> Result<()> {
    let header = format!(
        "entry={:#018x} initial_rsp={:#018x} termination={:?} final_rip={:#018x} final_rsp={:#018x}",
        summary.entry_point_va,
        summary.initial_rsp,
        summary.termination,
        summary.final_rip,
        summary.final_rsp,
    );
    if !write_line(output, &header)? {
        return Ok(());
    }
    for event in &summary.events {
        if !write_line(output, &format_entry_trace_event(event))? {
            return Ok(());
        }
    }
    Ok(())
}
