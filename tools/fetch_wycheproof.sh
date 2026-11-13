#!/bin/bash
# Fetch the Wycheproof vectors this lane gates on into .work/wyche (C2SP/wycheproof, testvectors_v1).
set -euo pipefail
d=${1:-.work/wyche}
mkdir -p "$d"
for f in aes_gcm chacha20_poly1305 hkdf_sha256 hkdf_sha384 hmac_sha256 hmac_sha384 hmac_sha512; do
  gh api -H "Accept: application/vnd.github.raw" "repos/C2SP/wycheproof/contents/testvectors_v1/${f}_test.json" > "$d/${f}_test.json" || { echo "FAIL fetch $f"; exit 1; }
done
ls -l "$d"
