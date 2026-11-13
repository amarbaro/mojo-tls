#!/usr/bin/env bash
# Mutation check: each line of tests/mutants_x509.txt is `name | file under src/ | perl substitution | stage`.
# The mutated copy of src/ is built and gated; the gate MUST fail, otherwise the mutant survived (FAIL).
# Mutants run in parallel in .work/mut/<name>/. Usage: tests/mutants_x509.sh [name ...]
set -euo pipefail
cd "$(dirname "$0")/.."
list=tests/mutants_x509.txt
only=("$@")
run_one() {
  local name=$1 file=$2 sub=$3 stage=$4 d=.work/mut/$1
  rm -rf $d && mkdir -p $d && cp -r src $d/src
  perl -0pi -e "$sub" $d/src/$file
  if cmp -s src/$file $d/src/$file; then echo "FAIL mutant $name: substitution changed nothing"; return 1; fi
  if SRC=$d/src BIN=$d/gate W=$d tests/gate_x509.sh $stage > $d/out.txt 2>&1; then
    echo "FAIL mutant $name: SURVIVED (gate stage $stage passed)"; return 1
  fi
  echo "PASS mutant $name: caught by stage $stage: $(grep -m1 '^FAIL' $d/out.txt | cut -c1-110)"
}
pids=()
bad=0
while IFS='|' read -r name file sub stage; do
  name=$(echo $name); file=$(echo $file); stage=$(echo $stage); sub=$(echo "$sub" | sed 's/^ *//; s/ *$//')
  [ -z "$name" ] && continue
  case "$name" in \#*) continue ;; esac
  if [ ${#only[@]} -gt 0 ] && [[ ! " ${only[*]} " =~ " $name " ]]; then continue; fi
  run_one "$name" "$file" "$sub" "$stage" &
  pids+=($!)
done < $list
for p in "${pids[@]}"; do wait $p || bad=1; done
exit $bad
