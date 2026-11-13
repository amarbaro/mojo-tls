#!/usr/bin/env bash
# check.sh [mutants]  Lane 5 gate: build and run every test over the fake crypto, then (with "mutants") prove each
# test file can fail: a mutant of the source that breaks one rule must turn a named test red.
# Prints PASS <step> / FAIL <step>: <reason>; exit 1 on any failure.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
MOJO="${MOJO:-$PWD/.venv/bin/mojo}"
AIO="${AIO:-$PWD/.work/deps/mojo-aio/src}"
W="$root/.work/check"; mkdir -p "$W"
fail=0
bad() { echo "FAIL $1: $2"; fail=1; }

build() { # name srcdir -> $W/name (rm first: a stale binary must never run)
  local name="$1" src="$2" out="$W/$1"
  rm -f "$out"
  timeout 300 "$MOJO" build -I "$src" -I "$AIO" -I tests "tests/$name.mojo" -o "$out" >"$W/$name.build" 2>&1 || { bad "build $name" "$(grep -m3 error "$W/$name.build")"; return 1; }
}
runt() { # name binary -> runs, echoes the RESULT line
  local out; out="$(timeout 120 "$2" 2>&1)" || { echo "$out" | grep -m5 -E "^FAIL|error" || true; return 1; }
  echo "$out" | grep -E "^RESULT"
}

bash tests/matrix/gen_certs.sh .work/gate/certs >/dev/null || { echo "FAIL gen_certs: openssl"; exit 1; }  # real client certificates for t_flow
tests=(t_flow t_hello)
for t in "${tests[@]}"; do
  if build "$t" src && r="$(runt "$t" "$W/$t")"; then echo "PASS $t: $r"; else bad "$t" "see output above"; fi
done

if r="$(tests/net.sh 2>&1)"; then echo "PASS net.sh: $(echo "$r" | grep -E '^INFO' | cut -c1-200)"; else echo "$r" | grep -E "^FAIL"; bad net.sh "see output above"; fi

if r="$(tests/interop/hello_probe.sh 2>&1)"; then echo "PASS hello_probe: $(echo "$r" | grep -c '^PASS') variants, OpenSSL accepts our ServerHello"; else echo "$r" | grep -E "^FAIL"; bad hello_probe "see output above"; fi

# real peers against our engines, with the temporary crypto of lane 4 (tests/real); SKIP when that tree is absent
if bins="$(tests/real/build.sh 2>&1)"; then
  srvbin="$(echo "$bins" | sed -n 1p)"; clbin="$(echo "$bins" | sed -n 2p)"
  r="$(TLS_SERVER_BIN="$srvbin" TLS_CLIENT_BIN="$clbin" TLS_KINDS="p256 p384 rsa" tests/interop/run.sh ours 2>&1 || true)"
  echo "$r" | grep -E "^(FAIL|RESULT)" || true
  if echo "$r" | grep -q "^FAIL"; then bad interop "see FAIL lines above"; else echo "PASS interop: $(echo "$r" | grep '^RESULT')  (P-256, P-384 and RSA keys)"; fi
else echo "SKIP interop: $(echo "$bins" | head -1)"; fi

if [[ "${1:-}" == mutants ]]; then
  # name | file | sed expression | test that must go red
  mutants=(
    "finished-unchecked|src/tls/tls12/server.mojo|s/if not ct_eq(body, self.cn.finished(\"client finished\")):/if False:/"
    "ems-optional|src/tls/tls12/server.mojo|s/if not ch.ems:/if False:/"
    "no-sentinel|src/tls/tls12/server.mojo|s/if self.cfg\[\].tls13:  # RFC 8446 4.1.3/if False:  # RFC 8446 4.1.3/"
    "write-seq-wrap|src/tls/tls12/conn.mojo|s/if self.wr.on and self.wr.seq == UInt64.MAX:/if False:/"
    "read-seq-wrap|src/tls/tls12/conn.mojo|s/if self.rd.seq == UInt64.MAX:/if False:/"
    "feed-no-compact|src/tls/tls12/conn.mojo|s/elif self.inp > 65536:/elif False:/"
    "empty-certs-ok|src/tls/net/server.mojo|s/if len(cfg.certs) == 0:/if False:/"
    "alpn-str-unsafe|src/tls/tls12/wire.mojo|s/        s += chr(Int(c))/        s += String(unsafe_from_utf8=Span([c]))/"
    "record-cap-gone|src/tls/tls12/conn.mojo|s/if n > MAX_REC + (2048 if self.rd.on else 0):/if False:/"
    "read-seq-frozen|src/tls/tls12/conn.mojo|s/self.rd.seq += 1/pass/"
    "alpn-any|src/tls/tls12/server.mojo|s/if self.alpn.byte_length() == 0:/if False:/"
    "msg-cap-gone|src/tls/tls12/conn.mojo|s/if l > MAX_MSG:/if False:/"
    "ri-ignored|src/tls/tls12/server.mojo|s/if ch.ri_bad:/if False:/"
    "ccs-anywhere|src/tls/tls12/server.mojo|s/if self.st != 2:/if False:/"
    "unknown-ext-fatal|src/tls/tls12/msg.mojo|s/d.p = len(d.d)  # unknown or GREASE: skipped/raise Error(\"tls: unknown extension\")/"
    "chacha-nonce-no-xor|src/tls/tls12/conn.mojo|s/self.nonce\[4 + i\] = self.iv\[4 + i\] ^ b/self.nonce[4 + i] = self.iv[4 + i]/"
    "aad-seq-zero|src/tls/tls12/conn.mojo|s/self.aad\[i\] = b$/self.aad[i] = 0/"
    "cauth-cv-skipped|src/tls/tls12/server.mojo|s/self.st = 6 if self.cfg\[\].require_client_cert else 2/self.st = 2/"
    "cauth-empty-cert-ok|src/tls/tls12/server.mojo|s/raise self.cn.fatal(A_HANDSHAKE, \"the client sent no certificate\")/pass/"
    "cauth-transcript-cut|src/tls/tls12/server.mojo|s/var cut = len(self.cn.tx) - 4 - len(self.cn.ev_body)/var cut = len(self.cn.tx)/"
    "cauth-roots-ignored|src/tls/tls12/server.mojo|s/self.cfg\[\].client_roots, unix_now()/List[List[UInt8]](), unix_now()/"
  )
  netmutants=(
    "net-timer-off|src/tls/net/server.mojo|s/self.loop.after(self.cfg\[\].handshake_ms, tok)/pass/"
    "net-never-arm-out|src/tls/net/server.mojo|s/var want_out = queued > 0/var want_out = False/"
    "net-fd-leak|src/tls/net/server.mojo|s/^        aio.close(Int32(fd))$/        pass/"
    "net-error-keeps-open|src/tls/net/server.mojo|s/p.closing = True  # the engine queued the alert/pass/"
  )
  pids=()
  for m in "${netmutants[@]}"; do
    IFS='|' read -r name file expr <<<"$m"
    (
      d="$W/mut-$name"; rm -rf "$d"; mkdir -p "$d"; cp -r src "$d/src"
      sed -i "$expr" "$d/$file"
      if cmp -s "$file" "$d/$file"; then echo "FAIL mutant $name: sed changed nothing"; exit 0; fi
      if out="$(SRC="$d/src" OUT="$d/out" tests/net.sh 2>&1)"; then echo "FAIL mutant $name: net.sh still passes"
      else echo "PASS mutant $name killed by: $(echo "$out" | grep -m1 -E '^FAIL')"; fi
    ) >"$W/mut-$name.out" 2>&1 &
    pids+=($!)
  done
  for m in "${mutants[@]}"; do
    IFS='|' read -r name file expr <<<"$m"
    (
      d="$W/mut-$name"; rm -rf "$d"; mkdir -p "$d"; cp -r src "$d/src"
      sed -i "$expr" "$d/$file"
      if cmp -s "$file" "$d/$file"; then echo "FAIL mutant $name: sed changed nothing"; exit 0; fi
      killed=""
      for t in "${tests[@]}"; do
        rm -f "$d/$t"
        if ! timeout 300 "$MOJO" build -I "$d/src" -I "$AIO" -I tests "tests/$t.mojo" -o "$d/$t" >"$d/build.log" 2>&1; then
          echo "FAIL mutant $name: does not build: $(grep -m1 error "$d/build.log")"; exit 0; fi
        if ! out="$(timeout 60 "$d/$t" 2>&1)"; then killed="$t: $(echo "$out" | grep -m1 '^FAIL' || echo "crash: $(echo "$out" | tail -1)")"; break; fi
      done
      if [[ -n "$killed" ]]; then echo "PASS mutant $name killed by $killed"; else echo "FAIL mutant $name: tests still pass"; fi
    ) >"$W/mut-$name.out" 2>&1 &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p" || true; done
  for m in "${mutants[@]}" "${netmutants[@]}"; do IFS='|' read -r name _ <<<"$m"; cat "$W/mut-$name.out"; grep -q "^FAIL" "$W/mut-$name.out" && fail=1; done
fi
[[ "$fail" -eq 0 ]] && echo "PASS gate" || { echo "FAIL gate: see above"; exit 1; }
