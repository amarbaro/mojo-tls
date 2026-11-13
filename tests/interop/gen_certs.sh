#!/usr/bin/env bash
# gen_certs.sh OUTDIR: one test CA and three leaf certs (SAN localhost, 127.0.0.1) for the interop harness.
# Output: ca.pem, {p256,p384,rsa}.crt.pem (leaf only; clients trust ca.pem), {p256,p384,rsa}.key.pem (PKCS#8).
# Keys are throwaway test keys, never reuse them outside OUTDIR (under .work/).
set -euo pipefail
out="${1:?usage: gen_certs.sh OUTDIR}"
command -v openssl >/dev/null || { echo "FAIL gen_certs: openssl missing"; exit 1; }
mkdir -p "$out"
cd "$out"
if [[ -f rsa.crt.pem && -f p384.crt.pem && -f p256.crt.pem && -f ca.pem ]]; then exit 0; fi
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem \
  -subj "/CN=mojo-tls test CA" -days 30 -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > ext.cnf
leaf() { # name, genpkey args...
  local n="$1"; shift
  openssl genpkey "$@" -out "$n.key.pem" 2>/dev/null
  openssl req -new -key "$n.key.pem" -subj "/CN=localhost" -out "$n.csr" 2>/dev/null
  openssl x509 -req -in "$n.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile ext.cnf -out "$n.crt.pem" 2>/dev/null
}
leaf p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
leaf rsa -algorithm RSA -pkeyopt rsa_keygen_bits:2048
echo "PASS gen_certs: $out"
