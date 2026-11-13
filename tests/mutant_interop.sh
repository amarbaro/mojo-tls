#!/usr/bin/env bash
# Mutant check for the interop gate: apply one sed edit to a copy of src/, build both interop programs against it and run
# tests/interop.py; at least one case must FAIL (real openssl/curl/python peers reject the mutated bytes).
# usage: mutant_interop.sh <file under src/> <sed expression>
set -euo pipefail
cd "$(dirname "$0")/.."
MOJO=${MOJO:-$PWD/.venv/bin/mojo}
file="$1"; expr="$2"
rm -rf .work/mutI; mkdir -p .work/mutI; cp -r src .work/mutI/src
sed -i "$expr" ".work/mutI/src/$file"
if cmp -s "src/$file" ".work/mutI/src/$file"; then echo "FAIL mutant: the edit changed nothing in $file: $expr"; exit 2; fi
for p in interop_server interop_client; do
  if ! timeout 300 "$MOJO" build -I .work/mutI/src -I tests "tests/$p.mojo" -o ".work/mutI/$p" > ".work/mutI/$p.log" 2>&1; then
    echo "FAIL mutant: build error, see .work/mutI/$p.log"; exit 2
  fi
done
if timeout 300 python3 -I tests/interop.py .work/mutI/interop_server .work/mutI/interop_client > .work/mutI/run.log 2>&1; then
  echo "FAIL mutant survived: $file: $expr"; exit 1
fi
if [ "$(grep -c '^FAIL interop' .work/mutI/run.log)" = 0 ]; then
  echo "FAIL mutant: interop.py died without a FAIL line, see .work/mutI/run.log"; exit 2
fi
echo "PASS mutant killed by interop: $file: $expr ($(grep -c '^FAIL' .work/mutI/run.log) of $(grep -c 'interop:' .work/mutI/run.log) cases fail)"
