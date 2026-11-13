#!/usr/bin/env bash
# CI entry point, same on a GitHub runner and a local Ubuntu VM: install, fetch the public test data, run the fast gates.
# Not here: the lab matrix (tests/matrix.sh: browsers, tlsfuzzer, testssl) and the mutant sweeps; they need machines CI does not have.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v uv >/dev/null || { echo "FAIL setup: uv not installed"; exit 1; }
command -v openssl >/dev/null || { echo "FAIL setup: openssl not installed (oracle and interop peer)"; exit 1; }
uv sync || { echo "FAIL setup: uv sync"; exit 1; }
export MOJO="${MOJO:-$PWD/.venv/bin/mojo}" PATH="$PWD/.venv/bin:$PATH"
scripts/deps.sh
[ -d .work/wycheproof/testvectors_v1 ] || git clone -q --depth 1 https://github.com/C2SP/wycheproof .work/wycheproof \
  || { echo "FAIL setup: clone wycheproof"; exit 1; }
n=0
gate() { n=$((n + 1)); echo "== $*"; bash "$@" || { echo "FAIL $n/6: $*"; exit 1; }; }
gate tests/sym_gate.sh vec
gate tests/gate_asym.sh
gate tests/gate_x509.sh
gate tests/gate_tls13.sh
gate tests/check.sh
gate scripts/example.sh
echo "PASS $n/6 gates"
