#!/usr/bin/env bash
# Best (minimum) microseconds per row over several runs of tests/bench, for a box shared with other jobs.
# usage: tools/bench-min.sh [runs] ; needs .work/bench (tools/mb.sh tests/bench.mojo .work/bench) and .work/oracle/rsa{2048,4096}.pem
set -euo pipefail
cd "$(dirname "$0")/.."
runs=${1:-6}
for bits in 2048 4096; do
  parts=$(python3 -I tools/rsa_parts.py .work/oracle/rsa$bits.pem)
  for i in $(seq "$runs"); do
    # shellcheck disable=SC2086
    taskset -c $((i % 8 + 2)) .work/bench $parts | sed "s/^/rsa$bits:/"
  done
done | python3 -I -c '
import sys, re
best = {}
for l in sys.stdin:
    m = re.match(r"(rsa\d+):(.*): ([\d.]+) us", l)
    k = m.group(2) if m.group(2).startswith(("p", "x")) else m.group(1) + " " + m.group(2)
    best[k] = min(best.get(k, 1e9), float(m.group(3)))
for k, v in best.items():
    print(f"{v:9.1f} us  {k}")
'
