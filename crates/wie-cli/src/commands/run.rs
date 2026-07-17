//! Runtime run and smoke commands.

use super::util::write_entry_trace_summary;
use anyhow::{Result, bail};
use std::io;
use std::path::Path;
/// Runs a freestanding / micro PE until `ExitProcess` and checks the exit code.
pub(crate) fn run_micro(
    path: &Path,
    max_api: usize,
    expect_code: u32,
    bottle_root: Option<&Path>,
) -> Result<()> {
    let root = bottle_root
        .map(std::path::Path::to_path_buf)
        .or_else(wie_winapi::bottle_root_from_env);
    if let Some(ref r) = root {
        println!("bottle_root: {}", r.display());
    }
    let summary = wie_runtime::run_micro_exe_with_root(path, max_api, root)?;

    println!("run_micro: path={}", summary.path);
    println!("cpu_backend: {}", summary.cpu_backend);
    println!(
        "entry={:#018x} initial_rsp={:#018x}",
        summary.entry_point_va, summary.initial_rsp
    );
    println!(
        "events={} termination={:?}",
        summary.run.events.len(),
        summary.run.termination
    );

    for event in &summary.run.events {
        println!(
            "  [{:>4}] {}!{} handled={} ret={:?}",
            event.index, event.library.as_ref(), event.name.as_ref(), event.handled, event.return_value
        );
    }

    if let Some(profile) = &summary.profile {
        println!("{}", profile.report());
    }

    match summary.exit_code {
        Some(code) if code == expect_code => {
            println!("run_micro: ok exit={code}");
            Ok(())
        }
        Some(code) => {
            bail!("run_micro: exit={code} expected={expect_code}");
        }
        None => {
            bail!(
                "run_micro: did not reach ExitProcess (termination={:?})",
                summary.run.termination
            );
        }
    }
}

/// Runs a PE until the persistent runtime yields (or exits).
pub(crate) fn run_until_yield(path: &Path, max_api: usize) -> Result<()> {
    let summary = wie_runtime::run_persistent_until_yield(path, max_api)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_entry_trace_summary(&mut output, &summary)
}
