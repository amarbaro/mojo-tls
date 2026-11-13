#!/usr/bin/env bash
# Dev helper: build the gate binary and print limbo disagreements (build + limbo only, ~30 s).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .work/gate
rm -f .work/gate/gate
timeout 300 $PWD/.venv/bin/mojo build -I src tests/x509_gate.mojo -o .work/gate/gate 2>&1 | grep -E "error" -A4 && { echo "FAIL build"; exit 1; } || true
[ -x .work/gate/gate ] || { echo "FAIL build: no binary"; exit 1; }
timeout 300 .work/gate/gate limbo .work/limbo/cases.txt > .work/gate/limbo_out.txt
tail -1 .work/gate/limbo_out.txt
grep '^DIFF' .work/gate/limbo_out.txt | cut -c1-${W:-170} | grep -E "${PAT:-.}"
