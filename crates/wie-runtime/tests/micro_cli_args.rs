//! Integration: guest argv + console stdin/stdout for pseudo-CLI micro-PE.
//!
//! Inject path uses non-empty `stdin_bytes` (no live host block). Interactive
//! live path is exercised by the micro-suite via pipe (no `--stdin`).

use std::path::PathBuf;

fn cli_args_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../micro-exes/out/cli_args.exe")
        .canonicalize()
        .expect("build micro-exes/out/cli_args.exe first (make -C micro-exes)")
}

#[test]
fn cli_args_flags_and_stdin_inject() {
    let path = cli_args_exe();
    let summary = wie_runtime::run_micro_exe_with_options(
        &path,
        256,
        wie_runtime::MicroRunOptions {
            bottle_root: None,
            guest_args: vec![
                "-n".into(),
                "3".into(),
                "-m".into(),
                "hi".into(),
                "-i".into(),
            ],
            // Non-empty inject: deterministic, no TTY hang.
            stdin_bytes: b"hello-inject\n".to_vec(),
        },
    )
    .expect("run_micro_exe_with_options");

    assert_eq!(
        summary.exit_code,
        Some(0),
        "termination={:?} events={:?}",
        summary.run.termination,
        summary.run.events
    );
}

#[test]
fn cli_args_missing_flag_exits_2() {
    let path = cli_args_exe();
    let summary = wie_runtime::run_micro_exe_with_options(
        &path,
        256,
        wie_runtime::MicroRunOptions {
            bottle_root: None,
            guest_args: vec!["-m".into(), "only".into()],
            // No -i: guest never reads stdin.
            stdin_bytes: b"unused\n".to_vec(),
        },
    )
    .expect("run_micro_exe_with_options");

    assert_eq!(summary.exit_code, Some(2));
}

#[test]
fn cli_args_flags_only_no_stdin_flag() {
    let path = cli_args_exe();
    let summary = wie_runtime::run_micro_exe_with_options(
        &path,
        256,
        wie_runtime::MicroRunOptions {
            bottle_root: None,
            guest_args: vec!["-n".into(), "3".into(), "-m".into(), "hi".into()],
            stdin_bytes: Vec::new(),
        },
    )
    .expect("run_micro_exe_with_options");

    assert_eq!(summary.exit_code, Some(0));
}
