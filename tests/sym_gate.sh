#!/bin/bash
# Lane 1 gate: official + oracle vectors against src/tls/sym, then every mutant in tests/mutants_sym.txt must make it fail.
#   tests/sym_gate.sh            vectors (hardware and software AES builds) + mutants
#   tests/sym_gate.sh vec        vectors only
# Needs python3 + cryptography and openssl (oracles only), and .work/wyche for a refresh of tests/vec.
set -euo pipefail
cd "$(dirname "$0")/.."
MOJO=${MOJO:-$PWD/.venv/bin/mojo}
mkdir -p .work/vec .work/gate
[ -f .work/vec/random-chacha.txt ] || python3 -I tools/gen_vec.py random .work/vec
VECS=(${SYM_VECS:-tests/vec/*.txt .work/vec/random-*.txt})

build() {  # build SRCDIR OUT [flags]
  local src=$1 out=$2; shift 2
  rm -f "$out"
  timeout 300 "$MOJO" build -I "$src" "$@" tests/sym_check.mojo -o "$out" > "$out.log" 2>&1 || { echo "FAIL build $out: $(grep -m1 error "$out.log")"; return 1; }
}

run() {  # run BIN LABEL
  if ! "$1" "${VECS[@]}" > "$1.out" 2>&1; then echo "FAIL $2: vectors"; head -30 "$1.out"; return 1; fi
  sed "s/^/[$2] /" "$1.out"
}

build src .work/gate/hw
run .work/gate/hw hw
build src .work/gate/soft -D TLS_SOFT_AES=true
run .work/gate/soft soft
[ "${1:-}" = vec ] && { echo "PASS vectors"; exit 0; }

mutant() {  # mutant LINE: name|file|sed expression[|build flags]
  local name file expr flags
  IFS='@' read -r name file expr flags <<< "$1"
  local d=.work/gate/m-$name
  rm -rf "$d"; mkdir -p "$d"; cp -r src "$d/src"
  sed -i -E "$expr" "$d/src/$file"
  if cmp -s "src/$file" "$d/src/$file"; then echo "FAIL mutant $name: sed changed nothing"; return 1; fi
  build "$d/src" "$d/bin" ${flags:-} || { echo "FAIL mutant $name: does not build"; return 1; }
  local rc=0
  "$d/bin" "${VECS[@]}" > "$d/out" 2>&1 || rc=$?
  if [ "$rc" = 0 ]; then echo "FAIL mutant $name: survived"; return 1; fi
  # A crash (SIGILL from a bounds trap, SIGSEGV, 124 timeout) is not a check: only a checked error (exit 1) kills a mutant.
  if [ "$rc" -ge 124 ]; then echo "FAIL mutant $name: crashed (exit $rc), no check caught it"; return 1; fi
  echo "ok mutant $name killed: $(grep -m1 -E "^FAIL|rror" "$d/out")"
}

pids=()
while IFS= read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  mutant "$line" > ".work/gate/m-${line%%@*}.log" 2>&1 &
  pids+=($!)
  while [ "$(jobs -r | wc -l)" -ge 8 ]; do sleep 0.5; done
done < "${MUTANTS:-tests/mutants_sym.txt}"
bad=0
for p in "${pids[@]}"; do wait "$p" || bad=1; done
cat .work/gate/m-*.log
[ "$bad" = 0 ] || { echo "FAIL gate: a mutant survived"; exit 1; }
echo "PASS gate"
