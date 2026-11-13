#!/usr/bin/env bash
# build.sh: build the matrix harness binaries into .work/matrix-bin (msrv, mcli). Prints FAIL <step>: <reason> on error.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
MOJO="${MOJO:-$PWD/.venv/bin/mojo}"
AIO="${AIO:-$PWD/.work/deps/mojo-aio/src}"
mkdir -p .work/matrix-bin
for b in ${@:-msrv mcli}; do
  rm -f ".work/matrix-bin/$b"
  timeout 300 "$MOJO" build -I src -I "$AIO" -I tests/matrix "tests/matrix/$b.mojo" -o ".work/matrix-bin/$b" >".work/matrix-bin/$b.build" 2>&1 \
    || { echo "FAIL build $b: $(grep -m3 error ".work/matrix-bin/$b.build" | tr '\n' ' ')"; exit 1; }
done
echo "PASS build: $root/.work/matrix-bin"
