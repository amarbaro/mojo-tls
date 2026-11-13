#!/usr/bin/env bash
# Mutant check: copy src/ to .work/mut, apply one sed edit, build a test against the copy, and require it to FAIL.
# usage: mutant.sh <tests/test_x.mojo> <file under src/> <sed expression>
set -euo pipefail
cd "$(dirname "$0")/.."
MOJO=${MOJO:-$PWD/.venv/bin/mojo}
test="$1"; file="$2"; expr="$3"
rm -rf .work/mut; mkdir -p .work/mut; cp -r src .work/mut/src
sed -i "$expr" ".work/mut/src/$file"
if cmp -s "src/$file" ".work/mut/src/$file"; then echo "FAIL mutant: the edit changed nothing in $file: $expr"; exit 2; fi
bin=.work/mut/test_bin
if ! timeout 300 "$MOJO" build -I .work/mut/src -I tests "$test" -o "$bin" > .work/mut/build.log 2>&1; then
  echo "FAIL mutant: build error, see .work/mut/build.log"; exit 2
fi
rc=0; timeout 120 "$bin" > .work/mut/run.log 2>&1 || rc=$?
if [ "$rc" = 0 ]; then echo "FAIL mutant survived: $file: $expr"; exit 1; fi
# A crash (signal exit 128+, or timeout 124) is not a check: only a checked error (exit 1 with FAIL or an Error) kills a mutant.
if [ "$rc" -ge 124 ]; then echo "FAIL mutant crashed (exit $rc), no check caught it: $file: $expr"; exit 1; fi
echo "PASS mutant killed: $file: $expr ($(grep -c '^FAIL' .work/mut/run.log) FAIL lines)"
