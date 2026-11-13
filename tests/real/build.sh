#!/usr/bin/env bash
# build.sh: build real_server and real_client (TLS_SERVER_BIN / TLS_CLIENT_BIN for tests/interop/run.sh) over
# RealCrypto (src/tls/tls12/realcrypto.mojo: lanes 1-3). Prints the two binary paths on success.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
MOJO="${MOJO:-$root/.venv/bin/mojo}"
AIO="${AIO:-$PWD/.work/deps/mojo-aio/src}"
mkdir -p .work/real-bin
for b in real_server real_client; do
  rm -f ".work/real-bin/$b"
  timeout 300 "$MOJO" build -I src -I "$AIO" -I tests/real "tests/real/$b.mojo" -o ".work/real-bin/$b" >".work/real-bin/$b.build" 2>&1 \
    || { echo "FAIL build $b: $(grep -m3 error ".work/real-bin/$b.build")"; exit 1; }
  echo "$root/.work/real-bin/$b"
done
