#!/usr/bin/env bash
# hello_probe.sh: wave-1 interop with a real peer, no crypto needed. Our TlsServer (fake crypto, tests/net_server)
# answers `openssl s_client -msg`; OpenSSL must accept our ServerHello (version, suite, extensions: SNI ack,
# renegotiation_info, EMS, ec_point_formats, ALPN) and parse our Certificate message framing. It then stops at the
# fake certificate with a fatal bad_certificate alert, which is the expected end of this probe.
# A refused hello (no EMS) must end in handshake_failure with no ServerHello.
# Needs: bash tests/check.sh (or tests/net.sh) has built .work/net/net_server. Prints PASS/FAIL/SKIP lines.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
SRVBIN="${SRVBIN:-$root/.work/net/net_server}"
[[ -x "$SRVBIN" ]] || { echo "SKIP hello: $SRVBIN not built (run tests/net.sh first)"; exit 0; }
command -v openssl >/dev/null || { echo "SKIP hello: openssl missing"; exit 0; }
out="$root/.work/interop"; mkdir -p "$out"
fail=0
variants=(
  "default|-tls1_2|c02b|bad_certificate"
  "chacha|-tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305|cca9|bad_certificate"
  "aes256|-tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384|c02c|bad_certificate"
  "unknown-sni|-tls1_2 -servername nope.test|c02b|bad_certificate"
  "p256-only|-tls1_2 -curves P-256|c02b|bad_certificate"
  "no-ems|-tls1_2 -no_ems|none|handshake_failure"
  "rsa-suite-only|-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256|none|handshake_failure"
)
for v in "${variants[@]}"; do
  IFS='|' read -r name args suite alert <<<"$v"
  "$SRVBIN" 0 5000 5000 1 >"$out/hp.srv" 2>&1 &
  pid=$!
  port=""; for _ in $(seq 30); do port="$(sed -n 's/^LISTENING //p' "$out/hp.srv" | head -1)"; [[ -n "$port" ]] && break; sleep 0.1; done
  # shellcheck disable=SC2086
  printf 'x' | timeout 10 openssl s_client -connect "127.0.0.1:$port" -servername localhost -alpn http/1.1 -msg $args >"$out/hp.msg" 2>&1 || true
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  got_suite="none"
  if grep -q ", ServerHello" "$out/hp.msg"; then
    hex="$(awk '/, ServerHello/{f=1;next} /^(<<<|>>>)/{f=0} f' "$out/hp.msg" | tr -d ' \n')"
    got_suite="${hex:78:4}"  # 4 hdr + 2 version + 32 random + 1 session id length, in hex digits
  fi
  if [[ "$got_suite" == "$suite" ]] && grep -q "fatal $alert" "$out/hp.msg"; then echo "PASS hello/$name: ServerHello suite $got_suite, then fatal $alert"
  else echo "FAIL hello/$name: suite $got_suite (want $suite), alert: $(grep -m1 -o 'fatal [a-z_ ]*' "$out/hp.msg" || echo none) (want $alert)"; fail=1; fi
done
exit "$fail"
