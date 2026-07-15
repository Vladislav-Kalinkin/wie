//! N1 micro-suite: process ids + heap core (freestanding PE64).
//!
//! Binaries from `make -C micro-exes`. Skips if missing (no mingw).

use std::path::PathBuf;

fn micro_exe(name: &str) -> Option<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("micro-exes/out");
    path.push(name);
    path.is_file().then_some(path)
}

fn run_expect_zero(name: &str) {
    let Some(path) = micro_exe(name) else {
        eprintln!("skip: micro-exes/out/{name} not built (run make -C micro-exes)");
        return;
    };
    let summary = wie_runtime::run_micro_exe(&path, 256).expect("run_micro_exe");
    assert_eq!(
        summary.exit_code,
        Some(0),
        "{name}: termination={:?} backend={}",
        summary.run.termination,
        summary.cpu_backend
    );
}

#[test]
fn n1_process_ids_exits_zero() {
    run_expect_zero("process_ids.exe");
}

#[test]
fn n1_heap_alloc_exits_zero() {
    run_expect_zero("heap_alloc.exe");
}

#[test]
fn n1_heap_core_exits_zero() {
    run_expect_zero("heap_core.exe");
}
