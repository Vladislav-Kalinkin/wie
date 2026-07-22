//! Final VFS gate before real binaries: host D: ↔ bottle C: UTF-8 round-trip.
//!
//! Layout (matches production `--root` / `--drive-d`):
//! - `drive_d` host tree ≈ macOS user dir (Downloads, etc.)
//! - bottle `drive_c` = guest `C:\`
//! - PE reads `D:\…`, copies to `C:\App\…`, writes modified file back to `D:\…`

use std::path::{Path, PathBuf};

fn micro_exe(name: &str) -> Option<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("micro-exes/out");
    path.push(name);
    path.is_file().then_some(path)
}

fn fixture_utf8() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("micro-exes/vfs_roundtrip/fixture_utf8.txt");
    path
}

fn assert_utf8_has_en_ru_cjk(text: &str, label: &str) {
    assert!(
        text.contains("Hello") || text.contains("English") || text.contains("en:OK"),
        "{label}: missing English fragment: {text:?}"
    );
    assert!(
        text.contains("Привет") || text.contains("Русский"),
        "{label}: missing Russian: {text:?}"
    );
    assert!(
        text.contains("你好") || text.contains("日本語") || text.contains("漢字"),
        "{label}: missing CJK: {text:?}"
    );
}

#[test]
fn vfs_roundtrip_host_d_to_bottle_c_and_back() {
    let Some(pe) = micro_exe("vfs_roundtrip.exe") else {
        eprintln!("skip: vfs_roundtrip.exe not built (make -C micro-exes vfs_roundtrip)");
        return;
    };

    let pid = std::process::id();
    let bottle = std::env::temp_dir().join(format!("wie-vfs-bottle-{pid}"));
    // Simulates a macOS user directory (e.g. ~/Downloads) bridged as D:.
    let host_user = std::env::temp_dir().join(format!("wie-vfs-downloads-{pid}"));
    let app = bottle.join("drive_c/App");
    std::fs::create_dir_all(&app).expect("mkdir bottle App");
    std::fs::create_dir_all(&host_user).expect("mkdir host user dir");

    let fixture_path = fixture_utf8();
    let original = std::fs::read(&fixture_path).expect("read fixture_utf8.txt");
    assert!(!original.is_empty(), "fixture must be non-empty");
    let original_text = std::str::from_utf8(&original).expect("fixture is UTF-8");
    assert_utf8_has_en_ru_cjk(original_text, "fixture");

    std::fs::write(host_user.join("vfs_in.txt"), &original).expect("seed D:\\vfs_in.txt");

    let summary = wie_runtime::run_micro_exe_with_options(
        &pe,
        512,
        wie_runtime::MicroRunOptions {
            bottle_root: Some(bottle.clone()),
            drive_d_root: Some(host_user.clone()),
            guest_args: vec![],
            stdin_bytes: vec![],
        },
    )
    .expect("run vfs_roundtrip");

    assert_eq!(
        summary.exit_code,
        Some(0),
        "exit={:?} term={:?}",
        summary.exit_code,
        summary.run.termination
    );

    // Bottle has an exact copy of the host input (not a stub).
    let bottle_copy = std::fs::read(app.join("vfs_copy.txt")).expect("C:\\App\\vfs_copy.txt");
    assert_eq!(
        bottle_copy, original,
        "bottle copy must be byte-identical to host input"
    );
    let bottle_text = std::str::from_utf8(&bottle_copy).expect("bottle UTF-8");
    assert_utf8_has_en_ru_cjk(bottle_text, "bottle copy");

    // Host receives a *modified* file: original + stamp with EN/RU/CJK.
    let host_out = std::fs::read(host_user.join("vfs_out.txt")).expect("D:\\vfs_out.txt");
    assert!(
        host_out.len() > original.len(),
        "output must be longer than input (stamp appended)"
    );
    assert!(
        host_out.starts_with(&original),
        "output must start with original UTF-8 bytes"
    );
    let out_text = std::str::from_utf8(&host_out).expect("output UTF-8");
    assert!(
        out_text.contains("---WIE_VFS---"),
        "missing stamp marker: {out_text:?}"
    );
    assert!(
        out_text.contains("Привет"),
        "stamp must include Russian: {out_text:?}"
    );
    assert!(
        out_text.contains("你好"),
        "stamp must include Chinese: {out_text:?}"
    );
    assert!(
        out_text.contains("日本語"),
        "stamp must include Japanese: {out_text:?}"
    );
    // Original languages still present after modification.
    assert_utf8_has_en_ru_cjk(out_text, "host output");

    let _ = std::fs::remove_dir_all(&bottle);
    let _ = std::fs::remove_dir_all(&host_user);
}

#[test]
fn vfs_roundtrip_custom_paths_via_guest_flags() {
    let Some(pe) = micro_exe("vfs_roundtrip.exe") else {
        eprintln!("skip: vfs_roundtrip.exe not built");
        return;
    };

    let pid = std::process::id();
    let bottle = std::env::temp_dir().join(format!("wie-vfs-bottle-flags-{pid}"));
    let host_user = std::env::temp_dir().join(format!("wie-vfs-dl-flags-{pid}"));
    std::fs::create_dir_all(bottle.join("drive_c/App")).unwrap();
    std::fs::create_dir_all(&host_user).unwrap();

    let original =
        b"Hello\n\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82\n\xe4\xbd\xa0\xe5\xa5\xbd\n";
    std::fs::write(host_user.join("custom_in.txt"), original).unwrap();

    let summary = wie_runtime::run_micro_exe_with_options(
        &pe,
        512,
        wie_runtime::MicroRunOptions {
            bottle_root: Some(bottle.clone()),
            drive_d_root: Some(host_user.clone()),
            guest_args: vec![
                "-i".into(),
                r"D:\custom_in.txt".into(),
                "-c".into(),
                r"C:\App\custom_copy.txt".into(),
                "-o".into(),
                r"D:\custom_out.txt".into(),
            ],
            stdin_bytes: vec![],
        },
    )
    .expect("run with flags");

    assert_eq!(summary.exit_code, Some(0), "{:?}", summary.run.termination);

    let copy = std::fs::read(bottle.join("drive_c/App/custom_copy.txt")).unwrap();
    assert_eq!(copy.as_slice(), original.as_slice());

    let out = std::fs::read(host_user.join("custom_out.txt")).unwrap();
    assert!(out.starts_with(original.as_slice()));
    let out_text = std::str::from_utf8(&out).expect("custom out UTF-8");
    assert!(
        out_text.contains("---WIE_VFS---"),
        "missing stamp: {out_text:?}"
    );
    assert!(
        out_text.contains("Привет") && out_text.contains("你好"),
        "missing RU/CJK stamp: {out_text:?}"
    );

    let _ = std::fs::remove_dir_all(&bottle);
    let _ = std::fs::remove_dir_all(&host_user);
}

/// Optional live check against a real macOS user dir when WIE_VFS_DOWNLOADS=1.
/// Seeds ~/Downloads/wie_vfs_in.txt, runs PE with --drive-d ~/Downloads, checks out file.
#[test]
fn vfs_roundtrip_optional_real_downloads() {
    if std::env::var_os("WIE_VFS_DOWNLOADS").is_none() {
        eprintln!("skip: set WIE_VFS_DOWNLOADS=1 to exercise real ~/Downloads");
        return;
    }
    let Some(pe) = micro_exe("vfs_roundtrip.exe") else {
        eprintln!("skip: vfs_roundtrip.exe not built");
        return;
    };

    let downloads = dirs_downloads().expect("HOME/Downloads");
    if !downloads.is_dir() {
        eprintln!("skip: Downloads missing: {}", downloads.display());
        return;
    }

    let pid = std::process::id();
    let bottle = std::env::temp_dir().join(format!("wie-vfs-bottle-dl-{pid}"));
    std::fs::create_dir_all(bottle.join("drive_c/App")).unwrap();

    let fixture = std::fs::read(fixture_utf8()).unwrap();
    let in_name = format!("wie_vfs_in_{pid}.txt");
    let out_name = format!("wie_vfs_out_{pid}.txt");
    let copy_name = format!("wie_vfs_copy_{pid}.txt");
    let in_host = downloads.join(&in_name);
    let out_host = downloads.join(&out_name);

    std::fs::write(&in_host, &fixture).expect("write Downloads input");

    let summary = wie_runtime::run_micro_exe_with_options(
        &pe,
        512,
        wie_runtime::MicroRunOptions {
            bottle_root: Some(bottle.clone()),
            drive_d_root: Some(downloads.clone()),
            guest_args: vec![
                "-i".into(),
                format!(r"D:\{in_name}"),
                "-c".into(),
                format!(r"C:\App\{copy_name}"),
                "-o".into(),
                format!(r"D:\{out_name}"),
            ],
            stdin_bytes: vec![],
        },
    )
    .expect("run against Downloads");

    assert_eq!(summary.exit_code, Some(0), "{:?}", summary.run.termination);

    let bottle_copy = std::fs::read(bottle.join("drive_c/App").join(&copy_name)).unwrap();
    assert_eq!(bottle_copy, fixture);

    let out = std::fs::read(&out_host).expect("Downloads output");
    assert!(out.starts_with(&fixture));
    assert!(std::str::from_utf8(&out).unwrap().contains("---WIE_VFS---"));

    // Cleanup Downloads artifacts.
    let _ = std::fs::remove_file(&in_host);
    let _ = std::fs::remove_file(&out_host);
    let _ = std::fs::remove_dir_all(&bottle);
}

fn dirs_downloads() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(Path::new(&home).join("Downloads"))
}
