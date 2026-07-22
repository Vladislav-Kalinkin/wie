#!/usr/bin/env bash
# Optional JIT matrix: run the micro-suite under alternate memory/CPU backends.
# Useful when touching memory lower, chaining, or CPU dispatch.
# Exits non-zero on first failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUITE="$ROOT/scripts/run-micro-suite.sh"

echo "=== JIT matrix: WIE_JIT_MEM=slow ==="
WIE_JIT_MEM=slow "$SUITE"

echo "=== JIT matrix: WIE_JIT_MEM=pin ==="
WIE_JIT_MEM=pin "$SUITE"

echo "=== JIT matrix: WIE_CPU=iced (skip long_loop — slice budget) ==="
WIE_SKIP_LONG_LOOP=1 WIE_CPU=iced "$SUITE"

echo "=== JIT matrix: all backends passed ==="
