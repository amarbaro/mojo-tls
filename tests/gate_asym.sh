#!/usr/bin/env bash
# Lane 2 gate (src/tls/asym): Wycheproof vectors, RFC/known-answer + round-trip checks, openssl cross-checks, mutants.
# usage: tests/gate_asym.sh [wycheproof-dir]   (default .work/wycheproof, a shallow clone of github.com/C2SP/wycheproof)
set -euo pipefail
cd "$(dirname "$0")/.."
wyc=${1:-.work/wycheproof}
fail() { echo "FAIL $1: $2"; exit 1; }
[ -d "$wyc/testvectors_v1" ] || fail wycheproof "no $wyc/testvectors_v1 (git clone --depth 1 https://github.com/C2SP/wycheproof $wyc)"
mkdir -p .work
python3 -I tools/wyc2cases.py "$wyc/testvectors_v1" .work/vectors.txt >/dev/null || fail cases "converter"
for t in vectors kat tool ct fuzz; do
  [ -f "tests/$t.mojo" ] || continue
  tools/mb.sh "tests/$t.mojo" ".work/$t" || fail "build $t" "see output"
done
.work/vectors .work/vectors.txt || fail wycheproof "see FAIL lines"
[ ! -x .work/kat ] || .work/kat || fail kat "see FAIL lines"
.work/fuzz .work/vectors.txt || fail fuzz "see FAIL lines"
[ ! -f tests/oracle.sh ] || tests/oracle.sh || fail oracle "see FAIL lines"
# dudect-style timing check, pinned to one core; up to three tries absorb a noisy neighbour (a real leak fails all three)
if [ -x .work/ct ] && [ -f .work/oracle/rsa2048.pem ]; then
  parts=$(python3 -I tools/rsa_parts.py .work/oracle/rsa2048.pem)
  # shellcheck disable=SC2086
  for try in 1 2 3; do taskset -c "${CT_CPU:-5}" .work/ct "${CT_N:-20000}" $parts && break; [ $try = 3 ] && fail ct "timing leak suspected in 3 tries"; echo "ct: try $try failed, retrying"; done
fi
tests/mutants_asym.sh || fail mutants "survivor"
echo "PASS gate"
