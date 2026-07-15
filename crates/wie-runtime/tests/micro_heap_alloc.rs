//! Integration: freestanding HeapAlloc micro-PE reaches ExitProcess(0).
//!
//! Binary is produced by `make -C micro-exes` (mingw). If missing, the test is
//! skipped so `cargo test` on machines without a cross toolchain still works.

use std::path::PathBuf;

fn heap_alloc_exe() -> Option<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/
    path.pop(); // repo root
    path.push("micro-exes/out/heap_alloc.exe");
    path.is_file().then_some(path)
}

#[test]
fn micro_heap_alloc_exits_zero() {
    let Some(path) = heap_alloc_exe() else {
        eprintln!("skip: micro-exes/out/heap_alloc.exe not built (run make -C micro-exes)");
        return;
    };

    let summary = wie_runtime::run_micro_exe(&path, 256).expect("run_micro_exe");
    assert_eq!(
        summary.exit_code,
        Some(0),
        "termination={:?} backend={}",
        summary.run.termination,
        summary.cpu_backend
    );
}
