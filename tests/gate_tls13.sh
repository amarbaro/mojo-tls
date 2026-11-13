#!/usr/bin/env bash
# Lane 4 gate (TLS 1.3 record layer, codecs, key schedule, client and server state machines).
# usage: tests/gate_tls13.sh [--mutants]      run from anywhere; output is kept in .work/gate/
# Builds each test (timeout 300), runs it, runs the openssl oracles and the interop matrix, optionally the mutants.
set -euo pipefail
cd "$(dirname "$0")/.."
MOJO=${MOJO:-$PWD/.venv/bin/mojo}
G=.work/gate; B=.work/bin
mkdir -p "$G" "$B"
bad=0
fail() { echo "FAIL $1: $2"; bad=1; }

build() {  # build <name> <source> : rm the old binary first so a failed build cannot run a stale one
  rm -f "$B/$1"
  if ! timeout 300 "$MOJO" build -I src -I tests "$2" -o "$B/$1" > "$G/build-$1.log" 2>&1; then
    fail "build $1" "see $G/build-$1.log"; return 1
  fi
}

bash tests/matrix/gen_certs.sh .work/gate/certs > /dev/null || fail "gen_certs" "openssl"  # real client certificates for test_clientauth and test_conn
for t in keysched record codec flight conn clientauth; do
  if build "test_$t" "tests/test_$t.mojo"; then
    set +e; timeout 300 "$B/test_$t" > "$G/test_$t.out" 2>&1; rc=$?; set -e
    if [ "$rc" = 0 ]; then echo "PASS test_$t: $(tail -1 "$G/test_$t.out")"; else fail "test_$t" "exit $rc, $(grep -m3 '^FAIL' "$G/test_$t.out" | tr '\n' ';')"; fi
  fi
done

# RecordReader buffer compaction (use-after-free fixed 2026-11-12, docs/heap-grow.md): natively the freed
# block stays readable, so the bug only shows when free unmaps it. heaptide's preload does that; skipped (not passed) without it.
if build rr_grow tests/rr_grow.mojo; then
  "$B/rr_grow" > "$G/rr_grow.out" 2>&1 && echo "PASS rr_grow native" || fail rr_grow "native, see $G/rr_grow.out"
  HT=${HEAPTIDE:-$HOME/Projects/tools/heaptide/heaptide}
  if [ -x "$HT" ]; then
    "$HT" run --out "$G/ht-rr" -- "$B/rr_grow" > "$G/rr_grow-heaptide.out" 2>&1 && echo "PASS rr_grow heaptide" || fail rr_grow "under heaptide (freed buffer read?), see $G/rr_grow-heaptide.out"
  else echo "SKIP rr_grow heaptide: no heaptide at $HT"; fi
fi

[ -s "$G/test_keysched.out" ] && bash tests/oracle_keysched.sh "$G/test_keysched.out" || fail "oracle keysched" "openssl kdf disagrees"
[ -s "$G/test_flight.out" ] && bash tests/oracle_cv.sh "$G/test_flight.out" || fail "oracle certificate_verify" "openssl rejects the signature"

if build interop_server tests/interop_server.mojo && build interop_client tests/interop_client.mojo; then
  set +e; timeout 600 python3 -I tests/interop.py "$B/interop_server" "$B/interop_client" > "$G/interop.out" 2>&1; rc=$?; set -e
  cat "$G/interop.out"
  [ "$rc" = 0 ] || fail "interop" "exit $rc"
fi

if [ "${1:-}" = "--mutants" ]; then
  m() { bash tests/mutant.sh "$@" || { echo "FAIL mutant: $2 $3"; bad=1; }; }
  m tests/test_keysched.mojo tls/tls13/keysched.mojo 's/"derived"/"derivex"/'
  m tests/test_record.mojo tls/tls13/record.mojo 's/self.nonce\[4 + i\] ^= /self.nonce[3 + i] ^= /'
  m tests/test_record.mojo tls/tls13/record.mojo 's/while i >= 0 and pt\[i\] == 0:/while False:/'
  m tests/test_codec.mojo tls/tls13/messages.mojo 's/if e.t == t:/if e.t == -1:/'
  m tests/test_codec.mojo tls/tls13/messages.mojo 's/if len(chain) == MAX_CHAIN:/if len(chain) == MAX_CHAIN + 1:/'
  m tests/test_codec.mojo tls/tls13/wire.mojo 's/if n < 0 or n > len(self.b) - self.p:/if n < 0 or n > len(self.b) - self.p + 1:/'
  m tests/test_flight.mojo tls/tls13/messages.mojo 's/^comptime H_MSGHASH = 254/comptime H_MSGHASH = 253/'
  m tests/test_flight.mojo tls/tls13/keysched.mojo 's/server CertificateVerify/server CertificateVerifx/'
  m tests/test_flight.mojo tls/tls13/server.mojo 's/if not ct_equal(parse_fin(m, h), finished_mac(h, self.c.chs, self.c.th())):/if False:/'
  m tests/test_flight.mojo tls/tls13/client.mojo 's/if not ct_equal(parse_fin(m, h), finished_mac(h, self.c.shs, self.c.th())):/if False:/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/if ci < 0 or not ct_equal(p_cookie(ch.exts\[ci\].d), self.cfg.cookie):/if False:/'
  m tests/test_conn.mojo tls/tls13/conn.mojo 's/if self.tx.seq >= self.key_limit:/if False:/'
  m tests/test_conn.mojo tls/tls13/conn.mojo 's/            if typ != APP:/            if False:/'
  m tests/test_conn.mojo tls/tls13/conn.mojo 's/        if len(self.hs) != 0:/        if False:/'
  m tests/test_conn.mojo tls/tls13/conn.mojo 's/self.install_rx(next_secret(self.h, self.rx_secret))/self.install_rx(next_secret(self.h, self.tx_secret))/'
  m tests/test_conn.mojo tls/tls13/client.mojo 's/return p384_ecdh(qp, peer)/return p384_ecdh(yp, peer)/'
  m tests/test_conn.mojo tls/tls13/client.mojo 's/return x448(yp, peer)/return x448(qp, peer)/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/if not ct_equal(binder_of(self.c.h, st.psk, th), p\[1\]\[i\]):/if False:/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/if now < st.issued or now - st.issued > st.lifetime or age_ms > st.lifetime \* 1000:/if False:/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/ or age_ms > st.lifetime \* 1000:/:/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/if now < st.issued or /if /'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/if st.suite != self.c.suite or st.alpn != self.alpn or st.sni != self.sni:/if False:/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/ or 1 not in p_psk_modes(ch.exts\[mi\].d)/ or False/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/if pi != len(ch.exts) - 1:/if False:/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/self.c.skip = 65536/self.c.skip = 0/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/if e.t == X_EARLY:/if e.t == -1:/'
  m tests/test_conn.mojo tls/tls13/conn.mojo 's/if self.state != S_WAIT_FIN or self.skip < used:/if False:/'
  m tests/test_conn.mojo tls/tls13/conn.mojo 's/                if self.skip < used:/                if False:/'
  m tests/test_conn.mojo tls/tls13/conn.mojo 's/var used = max(1, len(rec) - 5)/var used = len(rec) - 5/'
  m tests/test_conn.mojo tls/tls13/client.mojo 's/for j in range(h):/for j in range(h - 1):/'
  m tests/test_conn.mojo tls/tls13/messages.mojo 's/if name\[i\] >= 65 and name\[i\] <= 90:/if False:/'
  m tests/test_conn.mojo tls/tls13/client.mojo 's/if e.t != X_SNI and e.t != X_GROUPS and e.t != X_ALPN and e.t != X_EARLY and e.t != X_RSL:/if False:/'
  m tests/test_clientauth.mojo tls/tls13/clientauth.mojo 's/ok = p256_verify(leaf.key_a, sha256(signed), sig)/ok = True/'
  m tests/test_clientauth.mojo tls/tls13/clientauth.mojo 's/    if not ok:/    if False:/'
  m tests/test_clientauth.mojo tls/tls13/clientauth.mojo 's/verify_chain(certs, "", now, rs, True)/verify_chain(certs, "", now, rs, False)/'
  m tests/test_clientauth.mojo tls/x509/chain.mojo 's/if not (leaf.eku_client if client else leaf.eku_server):/if False:/'
  m tests/test_clientauth.mojo tls/x509/chain.mojo 's/if not client and not host_matches(/if not host_matches(/'
  m tests/test_clientauth.mojo tls/x509/cert.mojo 's/hex_is(k, "2b06010505070302")/hex_is(k, "2b06010505070399")/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/raise bad(\"certificate_required\", \"the client sent no certificate\")/pass/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/if cv\[0\] not in \[0x0403, 0x0503, 0x0804, 0x0805\]:/if False:/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/self.client_cert = self.cchain\[0\].copy()/pass/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/ or self.cfg.require_client_cert or 1 not in/ or 1 not in/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/ and not self.cfg.require_client_cert:/:/'
  m tests/test_conn.mojo tls/tls13/server.mojo 's/cv_content(True, self.th_cert)/cv_content(False, self.th_cert)/'
  bash tests/mutant_interop.sh tls/tls13/keysched.mojo 's/"traffic upd"/"traffic upx"/' || { echo "FAIL mutant: interop traffic upd"; bad=1; }
fi

if [ "$bad" = 0 ]; then echo "PASS lane 4 gate"; else echo "FAIL lane 4 gate: see lines above"; exit 1; fi
