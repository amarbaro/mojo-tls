#!/usr/bin/env bash
# run.sh [peers|ours|all]  TLS 1.2 interop matrix. Every cell prints PASS, FAIL <step>: <reason> or SKIP <why>.
#   peers  self-test of the harness: openssl s_client, curl, python ssl and headless Vivaldi against `openssl s_server`
#          (a known good TLS 1.2 server). Proves each probe can tell success from failure before we trust it on ours.
#   ours   the same probes against OUR server ($TLS_SERVER_BIN), and OUR client ($TLS_CLIENT_BIN) against s_server.
#   all    both (default).
# Server binary contract:  $TLS_SERVER_BIN --cert CRT_PEM --key KEY_PEM [--port 0]  prints "LISTENING <port>" on stdout,
#   answers any GET with 200 and the body `mojo-tls-ok`. Client binary contract: $TLS_CLIENT_BIN HOST PORT CAFILE
#   prints the response body. Unset binary -> SKIP wave2 (they need lane 1-3 crypto). A skip never counts as a pass.
# Browser: headless Vivaldi driven over CDP by browser_probe.py (stdlib only, no Playwright). The iTools names
#   cdp-headless/page-shot do not exist on this machine, and `vivaldi --dump-dom` never exits here.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
mode="${1:-all}"
W="$root/.work/interop"; C="$W/certs"
mkdir -p "$W/www"; printf 'HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\nmojo-tls-ok\n' > "$W/www/marker.txt"  # s_server -HTTP sends the file as the whole response
"$here/gen_certs.sh" "$C" >/dev/null
for t in openssl curl python3; do command -v "$t" >/dev/null || { echo "FAIL setup: $t missing"; exit 1; }; done
pass=0; skip=0; fail=0; SRV=""
ok()   { echo "PASS $1"; pass=$((pass+1)); }
no()   { echo "FAIL $1: $2"; fail=$((fail+1)); }
sk()   { echo "SKIP $1"; skip=$((skip+1)); }
stop() { [[ -n "$SRV" ]] && { kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; SRV=""; }; return 0; }
trap stop EXIT

declare -A KSUITES=(
  [p256]="ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305"
  [p384]="ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305"
  [rsa]="ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-CHACHA20-POLY1305")

freeport() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

# start_server KIND SUITE: sets PORT and SRV. peers -> openssl s_server, ours -> $TLS_SERVER_BIN.
start_server() {
  local who="$1" kind="$2" suite="$3"; KIND="$kind"; stop
  if [[ "$who" == peers ]]; then
    PORT="$(freeport)"
    (cd "$W/www" && exec openssl s_server -tls1_2 -accept "$PORT" -cert "$C/$kind.crt.pem" -key "$C/$kind.key.pem" \
      -HTTP -cipher "$suite" -no_ticket >"$W/srv.log" 2>&1) &
    SRV=$!
    for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break; sleep 0.1; done
  else
    "$TLS_SERVER_BIN" --cert "$C/$kind.crt.pem" --key "$C/$kind.key.pem" --port 0 >"$W/srv.out" 2>"$W/srv.log" &
    SRV=$!
    PORT=""
    for _ in $(seq 50); do PORT="$(sed -n 's/^LISTENING //p' "$W/srv.out" | head -1)"; [[ -n "$PORT" ]] && break; sleep 0.1; done
    [[ -n "$PORT" ]] || return 1
  fi
}

# Probes: print "<cipher> <body>" on success, exit non-zero on failure. $1 port, $2 suite.
p_sclient() {
  { printf 'GET /marker.txt HTTP/1.0\r\n\r\n'; sleep 1; } | timeout 20 openssl s_client -connect "127.0.0.1:$1" -tls1_2 -servername localhost \
    -CAfile "$C/ca.pem" -verify_return_error -verify_hostname localhost -cipher "$2" -alpn http/1.1 -brief 2>&1 \
    | awk '/^Ciphersuite: /{c=$2} /mojo-tls-ok/{b="mojo-tls-ok"} END{if(!b||!c)exit 1; print c, b}'
}
p_curl() {
  { timeout 20 curl -sSv --tls-max 1.2 --tlsv1.2 --cacert "$C/ca.pem" --resolve "localhost:$1:127.0.0.1" --ciphers "$2" \
    "https://localhost:$1/marker.txt" 2>&1 || true; } \
    | awk '/SSL connection using/{split($0,f," / "); c=f[2]} /mojo-tls-ok/{b="mojo-tls-ok"} END{if(!b||!c)exit 1; print c, b}'
}
p_python() {
  timeout 20 python3 -I - "$1" "$2" "$C/ca.pem" <<'PY'
import socket, ssl, sys
port, suite, ca = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context(cafile=ca)
ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.set_ciphers(suite)
with socket.create_connection(("127.0.0.1", port), 10) as raw, ctx.wrap_socket(raw, server_hostname="localhost") as s:
    s.sendall(b"GET /marker.txt HTTP/1.0\r\n\r\n")
    data = b""
    while (d := s.recv(4096)): data += d
    if b"mojo-tls-ok" not in data: sys.exit(1)
    print(s.cipher()[0], "mojo-tls-ok")
PY
}
p_vivaldi() { # no suite control: Chromium picks; checks the page loads over TLS 1.2 only, prints "<proto> <cipher> marker"
  local spki; spki="$(openssl x509 -in "$C/$KIND.crt.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
  PROBE_TMP="$W" timeout 90 python3 -I "$here/browser_probe.py" "https://localhost:$1/marker.txt" "$spki" mojo-tls-ok
}

# one matrix: server kind x suite x client probe. $1 who.
have_kind() { [[ "$1" == peers || " ${TLS_KINDS:-p256 p384 rsa} " == *" $2 "* ]]; }
matrix() {
  local who="$1" kind suite probe out
  for kind in p256 p384 rsa; do
    have_kind "$who" "$kind" || { sk "$who/$kind: key type not supported by this binary (TLS_KINDS=${TLS_KINDS:-})"; continue; }
    for suite in ${KSUITES[$kind]}; do
    start_server "$who" "$kind" "$suite" || { no "$who/start/$kind/$suite" "server did not start: $(head -c 300 "$W/srv.log")"; continue; }
    for probe in sclient curl python; do
      if out="$(p_$probe "$PORT" "$suite" 2>&1)" && [[ "$out" == "$suite mojo-tls-ok" ]]; then ok "$who/$probe/$kind/$suite"
      else no "$who/$probe/$kind/$suite" "got: $(echo "$out" | tail -c 200)"; fi
    done
  done; done
  # browser: one cell per key type (suite chosen by the browser)
  if ! command -v vivaldi >/dev/null; then sk "$who/browser: vivaldi not installed"; return; fi
  for kind in p256 rsa; do
    have_kind "$who" "$kind" || continue
    start_server "$who" "$kind" "ALL" || { no "$who/start/$kind/browser" "server did not start"; continue; }
    if out="$(p_vivaldi "$PORT" 2>&1)"; then ok "$who/vivaldi/$kind"; else no "$who/vivaldi/$kind" "page marker missing: $out"; fi
  done
}

# negatives: the server must refuse these. A negative only counts when the client really connected and the handshake
# then failed: an option typo or a closed port must not look like a refusal. $1 who
refused() { # args to s_client; returns 0 when TCP connected (CONNECTED) and no TLS session was established
  local o; o="$(printf 'x' | timeout 20 openssl s_client -connect "127.0.0.1:$PORT" "$@" -brief 2>&1 || true)"
  [[ "$o" == *"CONNECTION ESTABLISHED"* ]] && return 1
  [[ "$o" == *"Connecting to"* && "$o" != *"Unknown option"* && "$o" != *"Connection refused"* ]]
}
negatives() {
  local who="$1"
  start_server "$who" p256 "ECDHE-ECDSA-AES128-GCM-SHA256" || { no "$who/start/neg" "server did not start"; return; }
  # CBC and RSA key exchange are out of scope: the handshake must fail
  if refused -tls1_2 -cipher 'AES128-SHA:ECDHE-ECDSA-AES128-SHA' -CAfile "$C/ca.pem"; then ok "$who/neg/cbc"; else no "$who/neg/cbc" "handshake with a CBC suite succeeded, or the client did not run"; fi
  # TLS 1.1 (needs seclevel 0 to even send it)
  local o; o="$(printf 'x' | timeout 20 openssl s_client -connect "127.0.0.1:$PORT" -tls1_1 -cipher 'ALL@SECLEVEL=0' -brief 2>&1 || true)"
  if echo "$o" | grep -q -i 'no protocols available'; then sk "$who/neg/tls11: client build cannot send TLS 1.1"
  elif echo "$o" | grep -q 'Protocol version: TLSv1.1'; then no "$who/neg/tls11" "TLS 1.1 handshake succeeded"; else ok "$who/neg/tls11"; fi
  # a client that offers no extended_master_secret: our policy refuses (s_server accepts, so peers mode skips)
  if [[ "$who" == peers ]]; then sk "peers/neg/no-ems: s_server accepts it, policy of our server only"
  elif refused -tls1_2 -no_ems -CAfile "$C/ca.pem"; then ok "$who/neg/no-ems"; else no "$who/neg/no-ems" "handshake without EMS succeeded, or the client did not run"; fi
}

run_peers() { matrix peers; negatives peers; }
run_ours() {
  # wave 1, real peer, fake crypto: OpenSSL accepts our ServerHello and Certificate framing (hello_probe.sh)
  local l; while IFS= read -r l; do
    echo "$l"; case "$l" in PASS*) pass=$((pass+1));; FAIL*) fail=$((fail+1));; SKIP*) skip=$((skip+1));; esac
  done < <("$here/hello_probe.sh" 2>&1 || true)
  if [[ -z "${TLS_SERVER_BIN:-}" || ! -x "${TLS_SERVER_BIN:-/nonexistent}" ]]; then
    sk "wave2: ours/server x {s_client,curl,python,vivaldi} x {p256,p384,rsa} x 3 suites + negatives: TLS_SERVER_BIN unset (needs lane 1-3 crypto: ECDHE, PRF, AEAD, ECDSA/RSA sign, PEM keys)"
  else matrix ours; negatives ours; fi
  if [[ -z "${TLS_CLIENT_BIN:-}" || ! -x "${TLS_CLIENT_BIN:-/nonexistent}" ]]; then
    sk "wave2: ours/client x s_server x 3 suites x {p256,p384,rsa}: TLS_CLIENT_BIN unset (needs lane 1-3 crypto + chain validation)"
  else
    local kind suite out
    for kind in p256 p384 rsa; do for suite in ${KSUITES[$kind]}; do
      have_kind ours "$kind" || { sk "ours/client/$kind/$suite: key type not supported by this binary"; continue; }
      start_server peers "$kind" "$suite"
      if out="$(timeout 30 "$TLS_CLIENT_BIN" 127.0.0.1 "$PORT" "$C/ca.pem" 2>&1)" && [[ "$out" == *mojo-tls-ok* ]]; then ok "ours/client/$kind/$suite"
      else no "ours/client/$kind/$suite" "$(echo "$out" | tail -c 200)"; fi
    done; done
    if have_kind ours p256; then
      start_server peers p256 "${KSUITES[p256]%% *}"
      if out="$(timeout 30 "$TLS_CLIENT_BIN" 127.0.0.1 "$PORT" /etc/ssl/certs/ca-certificates.crt 2>&1)" || [[ "$out" == *mojo-tls-ok* ]]; then no "ours/client/wrong-ca refused" "connected to a chain outside its roots"
      else ok "ours/client/wrong-ca refused"; fi
    fi
  fi
}

case "$mode" in peers) run_peers;; ours) run_ours;; all) run_peers; run_ours;; *) echo "FAIL usage: run.sh [peers|ours|all]"; exit 2;; esac
stop
echo "RESULT pass=$pass skip=$skip fail=$fail"
[[ "$fail" -eq 0 ]]
