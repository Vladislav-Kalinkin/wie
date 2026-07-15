//! N2 micro-suite: bottle v0 write/read (freestanding PE64).

use std::path::PathBuf;

fn micro_exe(name: &str) -> Option<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("micro-exes/out");
    path.push(name);
    path.is_file().then_some(path)
}

#[test]
fn n2_write_and_read_file_in_bottle() {
    let Some(write_pe) = micro_exe("write_file.exe") else {
        eprintln!("skip: write_file.exe not built");
        return;
    };
    let Some(read_pe) = micro_exe("read_file.exe") else {
        eprintln!("skip: read_file.exe not built");
        return;
    };

    let bottle = std::env::temp_dir().join(format!("wie-bottle-test-{}", std::process::id()));
    let app = bottle.join("drive_c/App");
    std::fs::create_dir_all(&app).expect("mkdir bottle");
    std::fs::write(app.join("n2_in.txt"), b"hello-n2").expect("seed n2_in");

    let write_summary = wie_runtime::run_micro_exe_with_root(&write_pe, 256, Some(bottle.clone()))
        .expect("write_file run");
    assert_eq!(
        write_summary.exit_code,
        Some(0),
        "{:?}",
        write_summary.run.termination
    );

    let out = app.join("n2_out.txt");
    let bytes = std::fs::read(&out).expect("n2_out on host");
    assert_eq!(bytes, b"WIE_N2");

    let read_summary = wie_runtime::run_micro_exe_with_root(&read_pe, 256, Some(bottle.clone()))
        .expect("read_file run");
    assert_eq!(
        read_summary.exit_code,
        Some(0),
        "{:?}",
        read_summary.run.termination
    );

    let _ = std::fs::remove_dir_all(&bottle);
}
