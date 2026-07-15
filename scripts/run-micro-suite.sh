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
  echo "--- run-micro $pe $* ---"
  "$CLI" run-micro "$pe" "$@"
}

# N1 — no bottle required
run_one "$ROOT/micro-exes/out/process_ids.exe"
run_one "$ROOT/micro-exes/out/heap_alloc.exe"
run_one "$ROOT/micro-exes/out/heap_core.exe"
run_one "$ROOT/micro-exes/out/modules.exe"

# N5 — ordinary CRT-linked hello (drives UCRT + more kernel32)
run_one "$ROOT/micro-exes/out/crt_hello.exe" --max-api 8000

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

rm -rf "$BOTTLE"
echo "=== micro-suite: ok ==="
