#!/usr/bin/env bash
# Oracle for the CertificateVerify content: the RFC 8448 section 3 RSA-PSS signature must verify with openssl over the
# content test_flight built (64 spaces, context string, 0x00, transcript hash). A wrong transcript or string fails here.
# usage: oracle_cv.sh <test_flight output file>
set -euo pipefail
cd "$(dirname "$0")/.."
out="$1"; d=.work/oracle; mkdir -p "$d"
cert=$(awk -F' [|] ' '$1==3 && $2 ~ /construct a Certificate handshake/ && $3=="Certificate" {print $4; exit}' tests/vectors/rfc8448.txt)
cv=$(awk -F' [|] ' '$1==3 && $2 ~ /construct a CertificateVerify/ && $3=="CertificateVerify" {print $4; exit}' tests/vectors/rfc8448.txt)
hex2bin() { python3 -I -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))' "$1"; }
hex2bin "${cert:22:864}" > "$d/cert.der"   # 4 header + 1 context + 3 list + 3 cert length = 11 bytes, then 432
hex2bin "${cv:16:256}" > "$d/sig.bin"      # 4 header + 2 scheme + 2 length = 8 bytes, then 128
hex2bin "$(grep -m1 '^CVCONTENT ' "$out" | cut -d' ' -f2)" > "$d/content.bin"
openssl x509 -inform DER -in "$d/cert.der" -pubkey -noout > "$d/pub.pem"
if openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -verify "$d/pub.pem" -signature "$d/sig.bin" "$d/content.bin" > "$d/verify.txt" 2>&1; then
  echo "PASS openssl oracle: RFC 8448 CertificateVerify signature verifies over the content built by lane 4 ($(cat "$d/verify.txt"))"
else
  echo "FAIL openssl oracle: CertificateVerify signature does not verify: $(cat "$d/verify.txt")"; exit 1
fi
