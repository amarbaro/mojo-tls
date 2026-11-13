#!/usr/bin/env bash
# capture.sh: regenerate tests/vectors/ch_*.hex (first ClientHello record of real clients). Run rarely; the files are committed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
port=$(python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
cap() { # name, command...
  local n="$1"; shift
  python3 -I "$here/capture.py" "$port" "$here/ch_$n.hex" &
  local p=$!; sleep 0.4
  "$@" >/dev/null 2>&1 || true
  wait "$p"
  echo "captured ch_$n ($(wc -c < "$here/ch_$n.hex") hex chars)"
}
cap openssl12 timeout 5 openssl s_client -connect "127.0.0.1:$port" -tls1_2 -servername localhost -alpn http/1.1 </dev/null
cap openssl13 timeout 5 openssl s_client -connect "127.0.0.1:$port" -servername localhost -alpn h2,http/1.1 </dev/null
cap curl12 timeout 5 curl -sk --tls-max 1.2 "https://localhost:$port/"
cap curl13 timeout 5 curl -sk "https://localhost:$port/"
cap python timeout 5 python3 -I -c "import socket,ssl;c=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE;c.set_alpn_protocols(['h2','http/1.1']);c.wrap_socket(socket.create_connection(('127.0.0.1',$port)),server_hostname='localhost')"
cap vivaldi timeout 20 vivaldi --headless=new --disable-vivaldi --disable-gpu --no-sandbox --user-data-dir="$here/../../.work/vcap" "https://localhost:$port/"
pkill -f -- "^/opt/vivaldi.*vcap" 2>/dev/null || true
