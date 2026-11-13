#!/usr/bin/env bash
# example.sh  Build examples/server.mojo and examples/client.mojo, make a throwaway P-256 CA + localhost certificate with
# openssl, serve it, fetch a page over TLS 1.3 with the example client (checked against that CA) and with
# `openssl s_client -tls1_2` (the same server answers TLS 1.2). Prints PASS example / FAIL <step>: <reason>.
set -euo pipefail
cd "$(dirname "$0")/.."
MOJO="${MOJO:-$PWD/.venv/bin/mojo}"; AIO="${AIO:-$PWD/.work/deps/mojo-aio/src}"
W=.work/example; rm -rf "$W"; mkdir -p "$W"
for b in server client; do
  timeout 300 "$MOJO" build -I src -I "$AIO" "examples/$b.mojo" -o "$W/$b" > "$W/$b.build" 2>&1 || { echo "FAIL build $b: $(grep -m3 error "$W/$b.build")"; exit 1; }
done
openssl ecparam -name prime256v1 -genkey -noout -out "$W/ca.key" 2>/dev/null
openssl req -x509 -new -key "$W/ca.key" -subj /CN=example-ca -days 2 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out "$W/ca.pem" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/leaf.key" 2>/dev/null
openssl req -new -key "$W/leaf.key" -subj /CN=localhost -out "$W/leaf.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\nbasicConstraints=CA:FALSE\n' > "$W/ext"
openssl x509 -req -in "$W/leaf.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -days 2 -extfile "$W/ext" -out "$W/leaf.pem" 2>/dev/null
"$W/server" "$W/leaf.pem" "$W/leaf.key" 0 > "$W/server.log" 2>&1 &
pid=$!; trap 'kill $pid 2>/dev/null || true' EXIT
for _ in $(seq 50); do grep -q LISTENING "$W/server.log" && break; sleep 0.1; done
port=$(sed -n 's/^LISTENING //p' "$W/server.log")
[[ -n $port ]] || { echo "FAIL start: server did not listen: $(cat "$W/server.log")"; exit 1; }
out=$(TLS_ROOTS="$W/ca.pem" timeout 20 "$W/client" localhost 127.0.0.1 "$port") || { echo "FAIL client: $out"; exit 1; }
[[ $out == *"hello from mojo-tls over TLS 1.3"* ]] || { echo "FAIL client: unexpected reply: $out"; exit 1; }
out12=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | timeout 20 openssl s_client -tls1_2 -connect "127.0.0.1:$port" -servername localhost -CAfile "$W/ca.pem" -verify_return_error -quiet 2>&1) || true
[[ $out12 == *"hello from mojo-tls over TLS 1.2"* ]] || { echo "FAIL tls1.2: unexpected reply: $out12"; exit 1; }
bad=$(TLS_ROOTS="$W/ca.pem" timeout 20 "$W/client" wrong.example 127.0.0.1 "$port" 2>&1) && { echo "FAIL negative: a wrong host name was accepted: $bad"; exit 1; }
echo "PASS example: TLS 1.3 client and TLS 1.2 openssl got the page, a wrong host name was refused"
