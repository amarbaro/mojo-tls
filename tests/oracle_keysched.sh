#!/usr/bin/env bash
# Oracle for the SHA-384 key schedule and KeyUpdate: openssl kdf (HKDF, TLS13-KDF) vs test_keysched output.
# usage: oracle_keysched.sh <test_keysched output file>
set -euo pipefail
out="$1"
x() { tr -d ':\n' | tr A-F a-f; }
ext() { openssl kdf -keylen "$1" -kdfopt "digest:$2" -kdfopt mode:EXTRACT_ONLY -kdfopt "hexkey:$3" -kdfopt "hexsalt:$4" HKDF | x; }
exp() { openssl kdf -keylen "$1" -kdfopt "digest:$2" -kdfopt mode:EXPAND_ONLY -kdfopt "hexkey:$3" -kdfopt "prefix:tls13 " -kdfopt "label:$4" -kdfopt "hexdata:$5" TLS13-KDF | x; }
rep() { printf "$1%.0s" $(seq "$2"); }
z48=$(rep 00 48); e384=$(openssl dgst -sha384 </dev/null | sed "s/.*= //")
early=$(ext 48 SHA384 "$z48" "$z48")
derived=$(exp 48 SHA384 "$early" derived "$e384")
hs=$(ext 48 SHA384 "$(rep 11 48)" "$derived")
chs=$(exp 48 SHA384 "$hs" "c hs traffic" "$(rep 5a 48)")
key=$(exp 32 SHA384 "$hs" key "")
upd=$(exp 48 SHA384 "$hs" "traffic upd" "")
shs=b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38
upd256=$(exp 32 SHA256 "$shs" "traffic upd" "")
bad=0
chk() { if [ "$(grep "^$1 " "$out" | cut -d' ' -f2)" = "$2" ]; then echo "PASS openssl oracle: $1"; else echo "FAIL openssl oracle: $1"; bad=1; fi; }
chk SHA384-HS "$hs"; chk SHA384-CHS "$chs"; chk SHA384-KEY "$key"; chk SHA384-UPD "$upd"; chk SHA256-UPD "$upd256"
exit $bad
