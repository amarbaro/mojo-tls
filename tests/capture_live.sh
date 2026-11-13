#!/usr/bin/env bash
# Captures the served chain of each host into tests/data/live_<host>.pem and appends a case to tests/data/chain_real.txt.
# Usage: tests/capture_live.sh host:expect [host:expect ...]   (expect = ok | fail; the gate checks it against openssl too)
# Needs network once; the gate itself runs on the committed files. `now` is the capture time.
set -euo pipefail
cd "$(dirname "$0")/data"
touch chain_real.txt
for spec in "$@"; do
  host=${spec%%:*}; expect=${spec##*:}
  f=live_$host.pem
  timeout 15 openssl s_client -connect $host:443 -servername $host -showcerts </dev/null 2>/dev/null \
    | awk '/BEGIN CERTIFICATE/{p=1} p{print} /END CERTIFICATE/{p=0}' > $f || true
  [ -s $f ] || { echo "skip $host: no certificates"; rm -f $f; continue; }
  { grep -v "^live_$host " chain_real.txt || true; } > chain_real.tmp
  mv chain_real.tmp chain_real.txt
  echo "live_$host $expect $(date +%s) $host @system $f" >> chain_real.txt
  echo "captured $host: $(grep -c 'BEGIN CERT' $f) certificates"
done
