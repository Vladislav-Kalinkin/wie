#!/usr/bin/env bash
# Run all micro-EXE gates. Exit non-zero on first failure.
# Clean room suite: freestanding kernel32 micros (Microsoft Learn semantics).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${CLI:-$ROOT/target/release/wie-cli}"
CPU="${WIE_CPU:-jit}"

if [[ ! -x "$CLI" ]]; then
  echo "building wie-cli (release)…"
  cargo build -p wie-cli --release --manifest-path "$ROOT/Cargo.toml"
fi

make -C "$ROOT/micro-exes"

export WIE_CPU="$CPU"
echo "=== micro-suite WIE_CPU=$WIE_CPU ==="

run_one() {
  local pe="$1"
  shift
  echo "--- run $pe $* ---"
  "$CLI" run "$pe" "$@"
}

# N1 — no bottle required
run_one "$ROOT/micro-exes/out/process_ids.exe"
run_one "$ROOT/micro-exes/out/tls_basic.exe"
run_one "$ROOT/micro-exes/out/cs_reenter.exe"
run_one "$ROOT/micro-exes/out/thread_create_join.exe"
run_one "$ROOT/micro-exes/out/cs_two_threads.exe"
run_one "$ROOT/micro-exes/out/event_handshake.exe"
run_one "$ROOT/micro-exes/out/interlocked_basic.exe"
# MT stress (Interlocked + CS + heap); gated so WIE_MT=0 still runs the rest.
if [[ "${WIE_MT:-1}" != "0" ]]; then
  run_one "$ROOT/micro-exes/out/mt_stress.exe"
else
  echo "--- skip mt_stress (WIE_MT=0) ---"
fi
run_one "$ROOT/micro-exes/out/heap_alloc.exe"
run_one "$ROOT/micro-exes/out/heap_core.exe"
run_one "$ROOT/micro-exes/out/winapi_heap.exe"
run_one "$ROOT/micro-exes/out/modules.exe"
# long_loop is a 100M-iteration compute loop; skip under iced (slice budget) or when WIE_SKIP_LONG_LOOP=1.
if [[ "${WIE_SKIP_LONG_LOOP:-0}" != "1" ]]; then
  run_one "$ROOT/micro-exes/out/long_loop.exe"
else
  echo "--- skip long_loop (WIE_SKIP_LONG_LOOP=1) ---"
fi
run_one "$ROOT/micro-exes/out/cpu_string.exe"
run_one "$ROOT/micro-exes/out/cpu_math.exe"
run_one "$ROOT/micro-exes/out/cpu_fp.exe"
run_one "$ROOT/micro-exes/out/crt_hello.exe"

# Pseudo-CLI: flags + stdin (no bottle)
# 1) Inject path (deterministic; never blocks on TTY)
CLI_STDIN="$(mktemp "${TMPDIR:-/tmp}/wie-cli-stdin.XXXXXX")"
printf 'CLI_IN\n' >"$CLI_STDIN"
run_one "$ROOT/micro-exes/out/cli_args.exe" --stdin "$CLI_STDIN" -- -n 3 -m hi -i
rm -f "$CLI_STDIN"
# 2) Live host stdin path via pipe (no --stdin ⇒ stdin_live)
echo "--- run cli_args.exe (live pipe stdin) ---"
printf 'hello-live\n' | "$CLI" run "$ROOT/micro-exes/out/cli_args.exe" -- -n 3 -m hi -i

# N2 — bottle v0
BOTTLE="$(mktemp -d "${TMPDIR:-/tmp}/wie-bottle.XXXXXX")"
mkdir -p "$BOTTLE/drive_c/App"
printf 'hello-n2' >"$BOTTLE/drive_c/App/n2_in.txt"
echo "bottle: $BOTTLE"

run_one "$ROOT/micro-exes/out/write_file.exe" --root "$BOTTLE"
if [[ ! -f "$BOTTLE/drive_c/App/n2_out.txt" ]]; then
  echo "FAIL: n2_out.txt not created on host" >&2
  exit 1
fi
if ! grep -q 'WIE_N2' "$BOTTLE/drive_c/App/n2_out.txt"; then
  echo "FAIL: n2_out.txt content mismatch" >&2
  exit 1
fi
echo "host write ok: $BOTTLE/drive_c/App/n2_out.txt"

run_one "$ROOT/micro-exes/out/read_file.exe" --root "$BOTTLE"

run_one "$ROOT/micro-exes/out/relative_path.exe" --root "$BOTTLE"
if [[ ! -f "$BOTTLE/drive_c/App/n2_rel_out.txt" ]]; then
  echo "FAIL: n2_rel_out.txt not created (relative path resolve)" >&2
  exit 1
fi
if ! grep -q 'REL_OK' "$BOTTLE/drive_c/App/n2_rel_out.txt"; then
  echo "FAIL: n2_rel_out.txt content mismatch" >&2
  exit 1
fi
echo "relative path write ok: $BOTTLE/drive_c/App/n2_rel_out.txt"

# Final VFS gate: host user dir as D: ↔ bottle C: UTF-8 round-trip
DRIVE_D="$(mktemp -d "${TMPDIR:-/tmp}/wie-drive-d.XXXXXX")"
FIXTURE="$ROOT/micro-exes/vfs_roundtrip/fixture_utf8.txt"
cp "$FIXTURE" "$DRIVE_D/vfs_in.txt"
echo "drive_d (host user bridge): $DRIVE_D"

run_one "$ROOT/micro-exes/out/vfs_roundtrip.exe" --root "$BOTTLE" --drive-d "$DRIVE_D"

if [[ ! -f "$BOTTLE/drive_c/App/vfs_copy.txt" ]]; then
  echo "FAIL: vfs_copy.txt not created in bottle" >&2
  exit 1
fi
if ! cmp -s "$FIXTURE" "$BOTTLE/drive_c/App/vfs_copy.txt"; then
  echo "FAIL: bottle copy is not byte-identical to fixture" >&2
  exit 1
fi
if [[ ! -f "$DRIVE_D/vfs_out.txt" ]]; then
  echo "FAIL: vfs_out.txt not written back to host D:" >&2
  exit 1
fi
# BSD grep (macOS) treats a pattern that starts with `-` as options unless
# `--` or `-e` is used. Stamp is `---WIE_VFS---` — fixed-string + end-of-opts.
if ! grep -Fq -- '---WIE_VFS---' "$DRIVE_D/vfs_out.txt"; then
  echo "FAIL: vfs_out.txt missing stamp" >&2
  exit 1
fi
# Unicode must survive (UTF-8 substrings).
if ! grep -Fq -- 'Привет' "$DRIVE_D/vfs_out.txt"; then
  echo "FAIL: Russian missing in host output" >&2
  exit 1
fi
if ! grep -Fq -- '你好' "$DRIVE_D/vfs_out.txt"; then
  echo "FAIL: Chinese missing in host output" >&2
  exit 1
fi
if ! grep -Fq -- '日本語' "$DRIVE_D/vfs_out.txt"; then
  echo "FAIL: Japanese missing in host output" >&2
  exit 1
fi
echo "vfs_roundtrip ok: bottle copy + host D: modified export (EN/RU/CJK)"

rm -rf "$BOTTLE" "$DRIVE_D"
echo "=== micro-suite: ok ==="
