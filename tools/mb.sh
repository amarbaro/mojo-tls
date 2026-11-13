#!/usr/bin/env bash
# Build one Mojo main against src/: tools/mb.sh <main.mojo> <out-binary>. Removes the old binary first so a failed build never runs stale code.
set -euo pipefail
cd "$(dirname "$0")/.."
src="$1"; out="$2"
rm -f "$out"
timeout 300 "${MOJO:-$PWD/.venv/bin/mojo}" build -I "${SRC:-src}" "$src" -o "$out" 2>&1 | grep -v -E '^(warning|\s+\^|\s*$)' | head -${MB_LINES:-40} || true
[ -x "$out" ] || { echo "FAIL build $src: no binary"; exit 1; }
