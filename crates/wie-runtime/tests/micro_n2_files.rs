//! N2 micro-suite: bottle write/read + VFS volume helpers (freestanding PE64).

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

    // Skeleton dirs from ensure_bottle_skeleton.
    assert!(bottle.join("drive_c/Windows/System32").is_dir());
    assert!(bottle.join("drive_c/Users/WIE/AppData/Local/Temp").is_dir());

    let _ = std::fs::remove_dir_all(&bottle);
}

#[test]
fn vfs_drive_d_maps_host_tree() {
    let bottle = std::env::temp_dir().join(format!("wie-bottle-d-{}", std::process::id()));
    let drive_d = std::env::temp_dir().join(format!("wie-drive-d-{}", std::process::id()));
    std::fs::create_dir_all(&bottle).unwrap();
    std::fs::create_dir_all(&drive_d).unwrap();
    std::fs::write(drive_d.join("sample.txt"), b"from-d").unwrap();

    let volumes = wie_winapi::VolumeConfig::from_parts(Some(bottle.clone()), Some(drive_d.clone()));
    let map = wie_winapi::vfs::guest_path_to_host(&volumes, r"D:\sample.txt").expect("D map");
    assert_eq!(std::fs::read(&map.host).unwrap(), b"from-d");
    assert_eq!(
        wie_winapi::vfs::logical_drives_mask(&volumes),
        (1 << 2) | (1 << 3)
    );
    assert_eq!(
        wie_winapi::vfs::get_drive_type(&volumes, r"D:\"),
        wie_winapi::vfs::DRIVE_FIXED
    );

    let _ = std::fs::remove_dir_all(&bottle);
    let _ = std::fs::remove_dir_all(&drive_d);
}
