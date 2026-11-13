#!/usr/bin/env bash
# gen_certs.sh OUTDIR: one test CA, default leaves {p256,rsa} (SAN localhost, 127.0.0.1) and SNI leaves {alt-p256,alt-rsa}
# (SAN alt.test). Files: ca.pem, NAME.crt.pem, NAME.key.pem (PKCS#8). Throwaway keys, never leave OUTDIR (under .work/).
set -euo pipefail
out="${1:?usage: gen_certs.sh OUTDIR}"
mkdir -p "$out"; cd "$out"
[[ -f ca.pem && -f p256.crt.pem && -f rsa.crt.pem && -f alt-p256.crt.pem && -f alt-rsa.crt.pem && -f cli-p256.crt.pem \
   && -f cli-rsa.crt.pem && -f cli-serverauth.crt.pem && -f cli-evil.crt.pem ]] && exit 0
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -subj "/CN=mojo-tls matrix CA" \
  -days 30 -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
leaf() { # name san genpkey-args...
  local n="$1" san="$2"; shift 2
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' "$san" > "$n.ext"
  openssl genpkey "$@" -out "$n.key.pem" 2>/dev/null
  openssl req -new -key "$n.key.pem" -subj "/CN=$n" -out "$n.csr" 2>/dev/null
  openssl x509 -req -in "$n.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile "$n.ext" -out "$n.crt.pem" 2>/dev/null
}
leaf p256 "DNS:localhost,IP:127.0.0.1" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf rsa "DNS:localhost,IP:127.0.0.1" -algorithm RSA -pkeyopt rsa_keygen_bits:2048
leaf alt-p256 "DNS:alt.test" -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf alt-rsa "DNS:alt.test" -algorithm RSA -pkeyopt rsa_keygen_bits:2048
client() { # name eku ca cakey genpkey-args...   (client certificate: no SAN)
  local n="$1" eku="$2" ca="$3" cak="$4"; shift 4
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%s\n' "$eku" > "$n.ext"
  openssl genpkey "$@" -out "$n.key.pem" 2>/dev/null
  openssl req -new -key "$n.key.pem" -subj "/CN=$n" -out "$n.csr" 2>/dev/null
  openssl x509 -req -in "$n.csr" -CA "$ca" -CAkey "$cak" -CAcreateserial -days 30 -extfile "$n.ext" -out "$n.crt.pem" 2>/dev/null
}
client cli-p256 clientAuth ca.pem ca.key -algorithm EC -pkeyopt ec_paramgen_curve:P-256
client cli-rsa clientAuth ca.pem ca.key -algorithm RSA -pkeyopt rsa_keygen_bits:2048
client cli-serverauth serverAuth ca.pem ca.key -algorithm EC -pkeyopt ec_paramgen_curve:P-256  # right CA, wrong purpose
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout evil-ca.key -out evil-ca.pem -subj "/CN=mojo-tls evil CA" \
  -days 30 -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
client cli-evil clientAuth evil-ca.pem evil-ca.key -algorithm EC -pkeyopt ec_paramgen_curve:P-256  # right purpose, CA we do not trust
for f in *.pem; do  # DER copies for tests/test_clientauth.mojo: certificates and PKCS#8 keys
  case $f in *.key.pem) openssl pkey -in "$f" -outform DER -out "${f%.pem}.der" 2>/dev/null;; *) openssl x509 -in "$f" -outform DER -out "${f%.pem}.der" 2>/dev/null;; esac
done
echo "PASS gen_certs: $out"
