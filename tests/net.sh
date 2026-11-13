#!/usr/bin/env bash
# net.sh: TlsServer (mojo-aio, nonblocking) against TlsStream clients over real loopback sockets, fake crypto.
#   200 echo connections from 8 parallel client processes, 3 x 1 MiB echoes, one 4 MiB echo to a reader with a 4 KiB receive buffer (partial writes, EPOLLOUT, read pause and resume),
#   a silent peer and a half-handshake peer (handshake timeout), a peer idle after the handshake (idle timeout),
#   20 garbage peers (fatal alerts). Then: every connection counted, no fd left open, wall time.
# SRC=dir overrides the source tree (mutants); prints PASS/FAIL <step>: <reason>; exit 1 on failure.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; cd "$root"
SRC="${SRC:-src}"; OUT="${OUT:-$root/.work/net}"; mkdir -p "$OUT"
MOJO="${MOJO:-$PWD/.venv/bin/mojo}"
AIO="${AIO:-$PWD/.work/deps/mojo-aio/src}"
HS_MS=1500; IDLE_MS=2500; TOTAL=$((200 + 3 + 1 + 1 + 1 + 1 + 20 + 2))  # + 2 tiny first records (a legal 2-byte fragment: the server waits, then times out, and must not crash)
for b in net_server net_client; do
  rm -f "$OUT/$b"
  timeout 300 "$MOJO" build -I "$SRC" -I "$AIO" -I tests "tests/$b.mojo" -o "$OUT/$b" >"$OUT/$b.build" 2>&1 || { echo "FAIL build $b: $(grep -m2 error "$OUT/$b.build")"; exit 1; }
done
rm -f "$OUT/srv.out"
TIME=(); [ -x /usr/bin/time ] && TIME=(/usr/bin/time -f "RSS_KB %M")  # RSS is info only; a bare runner (ubuntu image) has no /usr/bin/time
"${TIME[@]}" timeout 90 "$OUT/net_server" 0 "$HS_MS" "$IDLE_MS" "$TOTAL" >"$OUT/srv.out" 2>"$OUT/srv.err" &
srv=$!
port=""; for _ in $(seq 50); do port="$(sed -n 's/^LISTENING //p' "$OUT/srv.out" 2>/dev/null | head -1)"; [[ -n "$port" ]] && break; sleep 0.1; done
[[ -n "$port" ]] || { echo "FAIL start: server printed no LISTENING: $(head -c 300 "$OUT/srv.err")"; kill "$srv" 2>/dev/null || true; exit 1; }
t0=$(date +%s.%N)
pids=(); names=()
run() { names+=("$1"); shift; timeout 60 "$OUT/net_client" "$port" "$@" >"$OUT/cl.${#pids[@]}.out" 2>&1 & pids+=($!); }
for i in 1 2 3 4 5 6 7 8; do run "echo$i" echo 25; done
run big big 3
run slow slow 4096
run silent silent "$HS_MS"
run halfhs halfhs "$HS_MS"
run idle idle 1
run garbage garbage 20
run tiny tiny 2
fail=0
for i in "${!pids[@]}"; do
  if wait "${pids[$i]}"; then echo "PASS client ${names[$i]}: $(head -1 "$OUT/cl.$i.out")"
  else echo "FAIL client ${names[$i]}: $(head -c 200 "$OUT/cl.$i.out") (killed by timeout = server never closed it)"; fail=1; fi
done
t1=$(date +%s.%N)
wait "$srv" || { echo "FAIL server: exited non-zero or timed out before $TOTAL connections ended"; fail=1; }
stats="$(grep '^STATS' "$OUT/srv.out" || true)"
get() { sed -n "s/.* $1=\([0-9]*\).*/\1/p" <<<"$stats"; }
[[ -n "$stats" ]] || { echo "FAIL stats: none printed"; exit 1; }
chk() { if [[ "$2" == "$3" ]]; then echo "PASS $1 = $3"; else echo "FAIL $1: got $2, want $3"; fail=1; fi; }
chk handshakes "$(get handshakes)" 205
chk "failed before handshake end" "$(get failed)" 24
chk "timeouts (silent, half-handshake, idle, 2 tiny)" "$(get timeouts)" 5
[[ "$(get fds)" -le 8 ]] && echo "PASS fds at exit = $(get fds) (stdio, epoll, listener: no leak)" || { echo "FAIL fds: $(get fds) open at exit"; fail=1; }
echo "INFO wall $(awk "BEGIN{printf \"%.2f\", $t1-$t0}") s for $TOTAL connections incl. two ~${HS_MS} ms timeouts; server $(grep RSS_KB "$OUT/srv.err" || echo RSS unknown); $stats"
[[ "$fail" -eq 0 ]] && echo "PASS net" || { echo "FAIL net: see above"; exit 1; }
