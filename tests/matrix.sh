#!/usr/bin/env bash
# matrix.sh [REGEX]  Step 3 test matrix. One line per cell: PASS <cell>, FAIL <cell>: <reason>, SKIP <cell>: <reason>.
# Exit 1 when any cell FAILs; a SKIP never counts as a pass (the RESULT line counts them apart).
#   cells (name prefix):
#     sc/<ver>/<kind>/sni-<on|off>/alpn-<on|off>   openssl s_client -> our server (msrv), 16 cells + suites + SNI selection
#     ss/...                                       our client (mcli) -> openssl s_server, same axes
#     ours/...                                     our client -> our server
#     neg/...                                      refused handshakes (wrong version, ALPN mismatch, CBC, TLS 1.1)
#     tlsfuzzer/<script>, testssl/<scan>           tools installed under .work/tools (venv / clone, never system-wide)
#     firefox|chromium|vivaldi/<ver>/<kind>/sni-<..>/alpn-<..>   headless browsers -> our server
#   ver 13|12, kind p256|rsa (key of the default certificate). SNI off = connect to 127.0.0.1 (no server_name), on = localhost.
# Server alpn: http/1.1 only (we serve no h2). Browsers: the ALPN axis is the SERVER config (browsers always offer h2,http/1.1).
# Ports 4970-4989; every server started here is stopped by PID on exit. Browser trust: a throwaway NSS db (HOME / profile
# under .work/matrix), never the system store or a real profile. MATRIX_JOBS=8 parallel cells. REGEX filters cell names.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD; W=$ROOT/.work/matrix; BIN=$ROOT/.work/matrix-bin; T=$ROOT/.work/tools; CERTS=$W/certs; CELLS=$W/cells
HOME_REAL=$HOME; FILTER=${1:-}; JOBS=${MATRIX_JOBS:-8}
rm -rf "$CELLS" "$W/ports"; mkdir -p "$CELLS" "$W/ports" "$W/www"
for tool in openssl certutil python3; do command -v "$tool" >/dev/null || { echo "FAIL setup: $tool missing"; exit 1; }; done
tests/matrix/gen_certs.sh "$CERTS" >/dev/null
if [[ ! -x $BIN/msrv || ! -x $BIN/mcli ]] || [[ -n $(find src tests/matrix -name '*.mojo' -newer "$BIN/msrv" -print -quit) ]]; then
  tests/matrix/build.sh | sed 's/^/build: /'
fi
printf 'HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\nmojo-tls-ok\n' > "$W/www/index.html"  # s_server -HTTP sends the file as the whole reply

# ---- servers: msrv per (kind, mode, alpn); the SNI name alt.test selects the other key type ----
declare -A PORT=( [p256,both,on]=4970 [rsa,both,on]=4971 [p256,12,on]=4972 [rsa,12,on]=4973 [p256,both,off]=4974 [rsa,both,off]=4975
                  [p256,12,off]=4976 [rsa,12,off]=4977 [p256,13,on]=4978 [p256,both,cauth]=4979 [rsa,both,cauth]=4969 )
SRVPIDS=(); CELLPIDS=()
stop_all() { for p in "${SRVPIDS[@]:-}"; do [[ -n $p ]] && kill "$p" 2>/dev/null || true; done; return 0; }
trap stop_all EXIT
for key in "${!PORT[@]}"; do
  IFS=, read -r kind mode alpn <<< "$key"; port=${PORT[$key]}
  alt=alt-rsa; [[ $kind == rsa ]] && alt=alt-p256
  a=(); [[ $alpn == on ]] && a=(--alpn http/1.1); [[ $alpn == cauth ]] && a=(--client-ca "$CERTS/ca.pem")  # cauth: asks for a client certificate
  "$BIN/msrv" --mode "$mode" --port "$port" "${a[@]}" --cert "$CERTS/$kind.crt.pem" --key "$CERTS/$kind.key.pem" \
    --cert "$CERTS/$alt.crt.pem" --key "$CERTS/$alt.key.pem" --name alt.test > "$W/srv-$port.log" 2>&1 &
  SRVPIDS+=($!)
done
for port in "${PORT[@]}"; do
  for _ in $(seq 50); do grep -q LISTENING "$W/srv-$port.log" 2>/dev/null && break; sleep 0.1; done
  grep -q LISTENING "$W/srv-$port.log" || { echo "FAIL setup: msrv on $port did not start: $(head -c 300 "$W/srv-$port.log")"; exit 1; }
done

# ---- cell runner: FUNC prints "PASS", "FAIL <why>" or "SKIP <why>" as its last line ----
cell() { # NAME FUNC ARGS...
  local name=$1; shift
  [[ -z $FILTER || $name =~ $FILTER ]] || return 0
  while [[ $(running) -ge $JOBS ]]; do sleep 0.2; done
  ( set +e; r=$("$@" 2>&1 | tail -n 1 | cut -c1-400); [[ $r =~ ^(PASS|FAIL|SKIP) ]] || r="FAIL no verdict: $r"
    case $r in PASS*) echo "PASS $name";; *) echo "${r%% *} $name: ${r#* }";; esac > "$CELLS/${name//\//_}.txt" ) &
  CELLPIDS+=($!)
}
running() { local n=0 p; for p in "${CELLPIDS[@]:-}"; do [[ -n $p ]] && kill -0 "$p" 2>/dev/null && n=$((n+1)); done; echo $n; }
take_port() { local p; while :; do for p in $(seq 4980 4989); do mkdir "$W/ports/$p" 2>/dev/null && { echo "$p"; return; }; done; sleep 0.2; done; }
give_port() { rmdir "$W/ports/$1" 2>/dev/null || true; }
cn_of() { echo "$1"; }                                           # CN of the default certificate = its kind name
alt_of() { [[ $1 == p256 ]] && echo alt-rsa || echo alt-p256; }  # CN of the certificate alt.test selects

# ---- openssl s_client -> our server ----
sclient() { # VER KIND SNI ALPN HOST WANT_CN [extra s_client args]  (env WANT_SUITE optional)
  local ver=$1 kind=$2 sni=$3 alpn=$4 host=$5 cn=$6; shift 6
  local port=${PORT[$kind,both,on]} a o ws wa
  a=(-connect "127.0.0.1:$port" -CAfile "$CERTS/ca.pem" -brief)
  [[ $ver == 13 ]] && a+=(-tls1_3) || a+=(-tls1_2)
  if [[ $sni == on ]]; then a+=(-servername "$host" -verify_hostname "$host"); ws=$host; else a+=(-noservername -verify_ip 127.0.0.1); ws=; fi
  if [[ $alpn == on ]]; then a+=(-alpn http/1.1); wa=http/1.1; else wa=; fi
  o=$({ printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1; } | timeout 20 openssl s_client "${a[@]}" "$@" 2>&1 | tr -d '\r' || true)
  grep -q "^Protocol version: TLSv1.$((ver == 13 ? 3 : 2))" <<< "$o" || { echo "FAIL protocol: $(head -c 250 <<< "$o" | tr '\n' ' ')"; return; }
  grep -q '^Verification: OK' <<< "$o" || { echo "FAIL certificate verification: $(grep -m1 -i 'verif' <<< "$o")"; return; }
  grep -qx "Peer certificate: CN=$cn" <<< "$o" || { echo "FAIL wrong certificate: $(grep -m1 'Peer certificate' <<< "$o") want CN=$cn"; return; }
  [[ -z ${WANT_SUITE:-} ]] || grep -qx "Ciphersuite: $WANT_SUITE" <<< "$o" || { echo "FAIL suite: $(grep -m1 Ciphersuite <<< "$o") want $WANT_SUITE"; return; }
  grep -qxF "mojo-tls-ok ver=$ver sni=$ws alpn=$wa" <<< "$o" || { echo "FAIL reply: $(grep -m1 'mojo-tls-ok' <<< "$o" || echo none) want ver=$ver sni=$ws alpn=$wa"; return; }
  echo PASS
}
sclient_noalpn() { # VER KIND: the client offers http/1.1, the server (port ...,off) has none: handshake must work, reply alpn empty
  local ver=$1 kind=$2 o; o=$({ printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1; } | timeout 20 openssl s_client -connect "127.0.0.1:${PORT[$kind,both,off]}" -CAfile "$CERTS/ca.pem" -brief \
    -servername localhost -verify_hostname localhost -alpn http/1.1 "-tls1_$((ver == 13 ? 3 : 2))" 2>&1 | tr -d '\r' || true)
  grep -qxF "mojo-tls-ok ver=$ver sni=localhost alpn=" <<< "$o" && echo PASS || echo "FAIL $(head -c 250 <<< "$o" | tr '\n' ' ')"
}
refused() { # PORT s_client args: PASS when TCP connected, the handshake failed with an alert, and no session was established
  local port=$1; shift
  local o; o=$(printf 'x' | timeout 20 openssl s_client -connect "127.0.0.1:$port" -CAfile "$CERTS/ca.pem" -brief "$@" 2>&1 || true)
  [[ $o == *"Connecting to"* && $o != *"Unknown option"* && $o != *"Connection refused"* ]] || { echo "FAIL client did not run: $(head -c 200 <<< "$o" | tr '\n' ' ')"; return; }
  [[ $o != *"CONNECTION ESTABLISHED"* ]] || { echo "FAIL a handshake succeeded"; return; }
  [[ $o == *"alert"* ]] || { echo "FAIL no alert from the server: $(tail -c 200 <<< "$o" | tr '\n' ' ')"; return; }
  echo PASS
}

# ---- our client -> openssl s_server / our server ----
mcli_check() { # VER ALPN HOST PORT BODY_WANT [PATH]: run mcli, compare
  local ver=$1 alpn=$2 host=$3 port=$4 want=$5 path=${6:-/} o wa=; [[ $alpn == on ]] && wa=http/1.1
  o=$(timeout 30 "$BIN/mcli" --v "$ver" --host "$host" --port "$port" --ca "$CERTS/ca.pem" --path "$path" --alpn "$([[ $alpn == on ]] && echo http/1.1 || echo none)" 2>&1 | tail -1)
  [[ $o == "mcli-ok ver=$ver alpn=$wa body=$want" ]] && echo PASS || echo "FAIL got: $o  want: mcli-ok ver=$ver alpn=$wa body=$want"
}
sserver() { # VER KIND ALPN HOST  (host chooses the certificate: localhost / 127.0.0.1 = default, alt.test = cert2 by SNI)
  local ver=$1 kind=$2 alpn=$3 host=$4 port pid a r
  port=$(take_port)
  a=(-accept "$port" -cert "$CERTS/$kind.crt.pem" -key "$CERTS/$kind.key.pem" -cert2 "$CERTS/$(alt_of "$kind").crt.pem" -key2 "$CERTS/$(alt_of "$kind").key.pem"
     -servername alt.test -HTTP -no_ticket); [[ $ver == 13 ]] && a+=(-tls1_3) || a+=(-tls1_2); [[ $alpn == on ]] && a+=(-alpn http/1.1)
  ( cd "$W/www" && exec openssl s_server "${a[@]}" > "$W/ss-$port.log" 2>&1 ) & pid=$!
  for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break; sleep 0.1; done
  kill -0 "$pid" 2>/dev/null || { give_port "$port"; echo "FAIL s_server did not start on $port: $(tail -c 200 "$W/ss-$port.log" | tr '\n' ' ')"; return; }
  r=$(mcli_check "$ver" "$alpn" "$host" "$port" mojo-tls-ok /index.html); kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; give_port "$port"
  echo "$r"
}
ours() { # VER KIND SNI ALPN HOST
  local ver=$1 kind=$2 sni=$3 alpn=$4 host=$5 ws wa=; [[ $sni == on ]] && ws=$host || ws=; [[ $alpn == on ]] && wa=http/1.1
  mcli_check "$ver" "$alpn" "$host" "${PORT[$kind,both,on]}" "mojo-tls-ok ver=$ver sni=$ws alpn=$wa"
}

# ---- tlsfuzzer, testssl ----
tlsfuzzer() { # SCRIPT PORT [args]
  local s=$1 port=$2; shift 2
  [[ -f $T/tlsfuzzer/scripts/$s.py && -x $T/venv/bin/python ]] || { echo "SKIP tlsfuzzer not installed under .work/tools"; return; }
  local xf=() n; while IFS=$'\t' read -r sc n mode _; do [[ $sc == "$s" ]] && xf+=("-$mode" "$n"); done < <(grep -v '^#' tests/matrix/tf_xfail.txt)
  local o rc=0; o=$(PYTHONPATH=$T/tlsfuzzer timeout 280 "$T/venv/bin/python" "$T/tlsfuzzer/scripts/$s.py" -h 127.0.0.1 -p "$port" -n 0 "${xf[@]}" "$@" 2>&1) || rc=$?
  echo "$o" > "$W/tf-$s.out"
  [[ $rc == 0 ]] && echo PASS || echo "FAIL rc=$rc $(grep -E '^(TOTAL|PASS|FAIL|XFAIL|XPASS|SKIP):' <<< "$o" | tr '\n' ' ') see .work/matrix/tf-$s.out"
}
testssl() { # PORT SCAN(proto|ciphers)
  local port=$1 scan=$2 j=$W/testssl-$1-$2.json
  [[ -x $T/testssl/testssl.sh ]] || { echo "SKIP testssl.sh not installed under .work/tools"; return; }
  rm -f "$j"
  local flags=(-p); [[ $scan == ciphers ]] && flags=(-e)
  timeout 280 "$T/testssl/testssl.sh" --quiet --color 0 --warnings off --openssl-timeout 5 --jsonfile "$j" "${flags[@]}" "127.0.0.1:$port" > "$W/testssl-$port-$scan.out" 2>&1 || true
  [[ -s $j ]] || { echo "FAIL testssl produced no JSON: $(tail -c 200 "$W/testssl-$port-$scan.out" | tr '\n' ' ')"; return; }
  python3 -I - "$j" "$scan" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1])); scan = sys.argv[2]
ok13 = {"1301", "1302", "1303"}; ok12 = {"c02b", "c02c", "c02f", "c030", "cca8", "cca9"}
if scan == "proto":
    f = {r["id"]: r["finding"] for r in rows}
    need = {"SSLv2": "not offered", "SSLv3": "not offered", "TLS1": "not offered", "TLS1_1": "not offered", "TLS1_3": "offered"}  # TLS 1.2 is not asserted: testssl's probes carry no extended_master_secret and our policy refuses them
    bad = [f"{k}: {f.get(k)!r}" for k, v in need.items() if not str(f.get(k, "")).startswith(v)]
    print("PASS" if not bad else "FAIL " + "; ".join(bad))
else:
    offered = {r["id"][8:].lower() for r in rows if r["id"].startswith("cipher_x") and r.get("finding")}
    extra, miss = sorted(offered - ok13 - ok12), sorted(ok13 - offered)  # only the TLS 1.3 suites show: see testssl/tls12
    print("FAIL no cipher rows" if not offered else "FAIL unexpected suites offered: " + ",".join(extra) if extra else "FAIL TLS 1.3 suites not offered: " + ",".join(miss) if miss else "PASS")
PY
}

# ---- browsers ----
firefox_cell() { # VER KIND SNI ALPN
  local ver=$1 kind=$2 sni=$3 alpn=$4 mode=both host=localhost wa=
  command -v firefox >/dev/null || { echo "SKIP firefox not installed"; return; }
  command -v tesseract >/dev/null || { echo "SKIP tesseract missing (reads the Firefox screenshot)"; return; }
  [[ $ver == 12 ]] && mode=12; [[ $sni == off ]] && host=127.0.0.1; [[ $alpn == on ]] && wa=http/1.1
  local port=${PORT[$kind,$mode,$alpn]} d=$W/ff-$ver-$kind-$sni-$alpn
  rm -rf "$d"; mkdir -p "$d/profile" "$d/home"
  certutil -N -d "sql:$d/profile" --empty-password >/dev/null 2>&1 && certutil -A -n mojoCA -t "C,," -i "$CERTS/ca.pem" -d "sql:$d/profile" >/dev/null 2>&1 \
    || { echo "FAIL could not build the NSS profile"; return; }
  cat > "$d/profile/user.js" <<'JS'
user_pref("app.update.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("network.proxy.type", 0);
JS
  HOME="$d/home" MOZ_HEADLESS=1 timeout 90 firefox --headless --no-remote --profile "$d/profile" --window-size 1400,200 --screenshot "$d/shot.png" "https://$host:$port/" > "$d/ff.log" 2>&1 || true
  [[ -s $d/shot.png ]] || { echo "FAIL no screenshot: $(tail -c 200 "$d/ff.log" | tr '\n' ' ')"; return; }
  local t want; t=$(tesseract "$d/shot.png" - 2>/dev/null | tr -s ' \n' ' ')
  want="mojo-tls-ok ver=$ver sni=$([[ $sni == on ]] && echo localhost) alpn=$wa"
  t=${t//[=-]/_}  # tesseract reads "=" as "-"
  [[ $t == *"${want//[=-]/_}"* ]] && echo PASS || echo "FAIL page text via OCR: '${t:0:160}' want '$want'"
}
chrome_cell() { # BROWSER(chromium|vivaldi) VER KIND SNI ALPN
  local br=$1 ver=$2 kind=$3 sni=$4 alpn=$5 mode=both host=localhost wa=
  [[ $br == vivaldi && ! -x /usr/bin/vivaldi-stable ]] && { echo "SKIP vivaldi not installed"; return; }
  [[ -x $T/venv/bin/python ]] || { echo "SKIP playwright venv missing under .work/tools"; return; }
  [[ $ver == 12 ]] && mode=12; [[ $sni == off ]] && host=127.0.0.1; [[ $alpn == on ]] && wa=http/1.1
  local port=${PORT[$kind,$mode,$alpn]} d=$W/$br-$ver-$kind-$sni-$alpn
  rm -rf "$d"; mkdir -p "$d/home/.pki/nssdb"
  certutil -N -d "sql:$d/home/.pki/nssdb" --empty-password >/dev/null 2>&1 && certutil -A -n mojoCA -t "C,," -i "$CERTS/ca.pem" -d "sql:$d/home/.pki/nssdb" >/dev/null 2>&1 \
    || { echo "FAIL could not build the NSS db"; return; }
  local o env=(HOME="$d/home" XDG_CONFIG_HOME="$d/home/.config" XDG_CACHE_HOME="$d/home/.cache" PLAYWRIGHT_BROWSERS_PATH=$HOME_REAL/.cache/ms-playwright)
  if [[ $br == vivaldi ]]; then
    local cdp; cdp=$(take_port)
    o=$(env "${env[@]}" timeout 90 python3 -I tests/matrix/vivaldi_probe.py "https://$host:$port/" "$cdp" "$d/udd" 2>&1 | tail -1); give_port "$cdp"
  else
    o=$(env "${env[@]}" timeout 90 "$T/venv/bin/python" -I tests/matrix/browser.py "https://$host:$port/" 2>&1 | tail -1)
  fi
  echo "$o" > "$d/result.json"
  python3 -I - "$o" "$ver" "$sni" "$wa" <<'PY'
import json, sys
try: r = json.loads(sys.argv[1])
except Exception: print("FAIL unparsable: " + sys.argv[1][:200]); sys.exit()
ver, sni, wa = sys.argv[2:5]
if "error" in r: print("FAIL " + r["error"]); sys.exit()
want = f"mojo-tls-ok ver={ver} sni={'localhost' if sni == 'on' else ''} alpn={wa}"
proto = {"13": "TLS 1.3", "12": "TLS 1.2"}[ver]
print("PASS" if r["text"].strip() == want and r["protocol"] == proto else f"FAIL text={r['text'].strip()!r} protocol={r['protocol']!r} want {want!r} {proto}")
PY
}

# ---- the cells ----
for ver in 13 12; do for kind in p256 rsa; do for sni in on off; do for alpn in on off; do
  n=$ver/$kind/sni-$sni/alpn-$alpn; h=localhost; [[ $sni == off ]] && h=127.0.0.1
  cell "sc/$n" sclient "$ver" "$kind" "$sni" "$alpn" localhost "$(cn_of "$kind")"
  cell "ss/$n" sserver "$ver" "$kind" "$alpn" "$h"
  cell "ours/$n" ours "$ver" "$kind" "$sni" "$alpn" "$h"
  cell "firefox/$n" firefox_cell "$ver" "$kind" "$sni" "$alpn"
  cell "chromium/$n" chrome_cell chromium "$ver" "$kind" "$sni" "$alpn"
  cell "vivaldi/$n" chrome_cell vivaldi "$ver" "$kind" "$sni" "$alpn"
done; done; done; done
suite_cell() { WANT_SUITE=$1 sclient "${@:2}"; }
for kind in p256 rsa; do
  ec=ECDHE-ECDSA; [[ $kind == rsa ]] && ec=ECDHE-RSA
  for suite in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    cell "sc/13/$kind/suite-$suite" suite_cell "$suite" 13 "$kind" on on localhost "$(cn_of "$kind")" -ciphersuites "$suite"
  done
  for sfx in AES128-GCM-SHA256 AES256-GCM-SHA384 CHACHA20-POLY1305; do
    cell "sc/12/$kind/suite-$ec-$sfx" suite_cell "$ec-$sfx" 12 "$kind" on on localhost "$(cn_of "$kind")" -cipher "$ec-$sfx"
  done
  for ver in 13 12; do   # a server with no ALPN configured ignores a client's ALPN offer (RFC 7301)
    cell "sc/$ver/$kind/server-no-alpn" sclient_noalpn "$ver" "$kind"
  done
  for ver in 13 12; do   # SNI picks the other key type's certificate
    cell "sc/$ver/$kind/sni-select" sclient "$ver" "$kind" on on alt.test "$(alt_of "$kind")"
    cell "ss/$ver/$kind/sni-select" sserver "$ver" "$kind" off alt.test  # s_server runs its ALPN callback on the default context only
    cell "ours/$ver/$kind/sni-select" mcli_check "$ver" on alt.test "${PORT[$kind,both,on]}" "mojo-tls-ok ver=$ver sni=alt.test alpn=http/1.1"
  done
done
cauth() { # WANT VER [CERT]: s_client against the client-certificate server; WANT "ok" = served, else a substring of the alert text
  local want=$1 ver=$2 cert=${3:-} port=${PORT[p256,both,cauth]} a o
  a=(-connect "127.0.0.1:$port" -CAfile "$CERTS/ca.pem" -servername localhost -verify_hostname localhost)
  [[ $ver == 13 ]] && a+=(-tls1_3) || a+=(-tls1_2)
  [[ -z $cert ]] || a+=(-cert "$CERTS/$cert.crt.pem" -key "$CERTS/$cert.key.pem")
  o=$({ printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1.5; } | timeout 20 openssl s_client "${a[@]}" 2>&1 | tr -d '\r' || true)
  if [[ $want == ok ]]; then
    grep -q "mojo-tls-ok ver=$ver" <<< "$o" && echo PASS || echo "FAIL not served: $(grep -m2 -iE 'alert|error' <<< "$o" | tr '\n' ' ')"
  else
    grep -q 'mojo-tls-ok' <<< "$o" && { echo "FAIL served without a valid client certificate"; return; }
    grep -qi "$want" <<< "$o" && echo PASS || echo "FAIL wrong refusal (want '$want'): $(grep -m2 -iE 'alert|error' <<< "$o" | tr '\n' ' ')"
  fi
}
oursauth() { # VER CERT: our client presents CERT (or none) to the client-certificate server; none must be refused
  local ver=$1 cert=${2:-} port=${PORT[p256,both,cauth]} a o
  a=(--v "$ver" --host localhost --port "$port" --ca "$CERTS/ca.pem" --alpn none)
  [[ -z $cert ]] || a+=(--cert "$CERTS/$cert.crt.pem" --key "$CERTS/$cert.key.pem")
  o=$(timeout 30 "$BIN/mcli" "${a[@]}" 2>&1 | tail -1)
  if [[ -n $cert ]]; then [[ $o == "mcli-ok ver=$ver "* ]] && echo PASS || echo "FAIL got: $o"
  else [[ $o == mcli-fail* || $o != mcli-ok* ]] && echo PASS || echo "FAIL served without a certificate: $o"; fi
}
resume13() { # KIND: s_client saves the session (-sess_out), a second connection offers it (-sess_in) and must say "Reused"
  local port=${PORT[$1,both,on]} f="$W/sess-$1.pem" a o
  a=(-connect "127.0.0.1:$port" -CAfile "$CERTS/ca.pem" -tls1_3 -servername localhost -verify_hostname localhost -brief); rm -f "$f"
  o=$({ printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1.5; } | timeout 20 openssl s_client "${a[@]}" -sess_out "$f" 2>&1 | tr -d '\r' || true)
  [[ -s $f ]] || { echo "FAIL no session saved (no NewSessionTicket): $(head -c 200 <<< "$o" | tr '\n' ' ')"; return; }
  o=$({ printf 'GET / HTTP/1.0\r\n\r\n'; sleep 1.5; } | timeout 20 openssl s_client "${a[@]/-brief/-ign_eof}" -sess_in "$f" 2>&1 | tr -d '\r' || true)
  grep -q '^Reused, TLSv1.3' <<< "$o" || { echo "FAIL the second connection was a full handshake: $(grep -m1 -E '^(New|Reused)' <<< "$o")"; return; }
  grep -q 'Verification: OK\|Verify return code: 0' <<< "$o" || { echo "FAIL resumed handshake: $(head -c 200 <<< "$o" | tr '\n' ' ')"; return; }
  grep -q 'mojo-tls-ok ver=13' <<< "$o" || { echo "FAIL reply after resumption"; return; }
  echo PASS
}
for kind in p256 rsa; do cell "sc/13/$kind/resume" resume13 "$kind"; done
cell cauth/13/p256-cert cauth ok 13 cli-p256
for v in 12 13; do cell ours/cauth/$v/p256 oursauth $v cli-p256; cell ours/cauth/$v/rsa oursauth $v cli-rsa; cell ours/cauth/$v/none oursauth $v; done
cell cauth/13/rsa-cert cauth ok 13 cli-rsa
cell cauth/13/no-cert cauth "certificate required" 13
cell cauth/13/untrusted-ca cauth "bad certificate" 13 cli-evil
cell cauth/13/serverauth-only cauth "bad certificate" 13 cli-serverauth
cell cauth/12/p256-cert cauth ok 12 cli-p256
cell cauth/12/rsa-cert cauth ok 12 cli-rsa
cell cauth/12/no-cert cauth "handshake failure" 12
cell cauth/12/untrusted-ca cauth "bad certificate" 12 cli-evil
cell cauth/12/serverauth-only cauth "bad certificate" 12 cli-serverauth
cell neg/tls13-client-vs-tls12-server refused "${PORT[p256,12,on]}" -tls1_3
cell neg/tls12-client-vs-tls13-server refused "${PORT[p256,13,on]}" -tls1_2
cell neg/alpn-mismatch-13 refused "${PORT[p256,both,on]}" -tls1_3 -alpn nope
cell neg/alpn-mismatch-12 refused "${PORT[p256,both,on]}" -tls1_2 -alpn nope
cell neg/cbc-12 refused "${PORT[p256,both,on]}" -tls1_2 -cipher 'ECDHE-ECDSA-AES128-SHA'
cell neg/tls11 refused "${PORT[p256,both,on]}" -tls1_1 -cipher 'ALL@SECLEVEL=0'


TF13=(test-tls13-conversation test-tls13-finished test-tls13-hrr test-tls13-keyupdate test-tls13-empty-alert test-tls13-legacy-version
      test-tls13-signature-algorithms test-tls13-zero-length-data test-tls13-version-negotiation test-tls13-invalid-ciphers
      test-tls13-record-padding test-tls13-lengths test-tls13-unrecognised-groups test-tls13-serverhello-random test-tls13-ccs
      test-tls13-finished-plaintext test-tls13-unencrypted-alert test-tls13-zero-content-type test-tls13-record-layer-limits
      test-tls13-ecdsa-in-certificate-verify test-tls13-certificate-verify test-tls13-session-resumption test-tls13-count-tickets test-tls13-0rtt-garbage)
TF12=(test-conversation test-extended-master-secret-extension test-record-layer-fragmentation test-invalid-content-type
      test-message-skipping test-truncating-of-finished test-downgrade-protection test-serverhello-random test-alpn-negotiation)
skip_ts() { echo "SKIP $*"; }
skip12() { echo "SKIP the script's own sanity handshake sends no extended_master_secret and mostly CBC/RSA-kex suites; our server refuses both by policy (docs/tls12.md), so it cannot reach its tests. TLS 1.2 is covered by sc/12, ours/12, browsers and the t_flow policy tests"; }
for s in "${TF13[@]}"; do
  case $s in
    test-tls13-ecdsa-in-certificate-verify) cell "tlsfuzzer/$s" tlsfuzzer "$s" "${PORT[p256,both,cauth]}" -k "$CERTS/cli-p256.key.pem" -c "$CERTS/cli-p256.crt.pem" -s "ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384";;
    test-tls13-version-negotiation) cell "tlsfuzzer/$s" skip_ts "197 of 202 cases fall back to a TLS 1.2 handshake without extended_master_secret, which our policy refuses (docs/tls12.md)";;
    test-tls13-lengths)  # 16384 lengths (about 280 s in one process): four cells of 4096, every case runs
      for q in 0 1 2 3; do mapfile -t names < <(seq $((q * 4096 + 1)) $((q * 4096 + 4096)) | sed 's/^/length: /')
        cell "tlsfuzzer/$s/part$q" tlsfuzzer "$s" "${PORT[rsa,both,on]}" -n 0 "${names[@]}"; done;;
    test-tls13-certificate-verify) cell "tlsfuzzer/$s" tlsfuzzer "$s" "${PORT[rsa,both,cauth]}" -k "$CERTS/cli-rsa.key.pem" -c "$CERTS/cli-rsa.crt.pem" -s "ecdsa_secp256r1_sha256 ecdsa_secp384r1_sha384 rsa_pss_rsae_sha256 rsa_pss_rsae_sha384";;
    test-tls13-count-tickets) cell "tlsfuzzer/$s" tlsfuzzer "$s" "${PORT[rsa,both,on]}" -t 1;;  # we send exactly one NewSessionTicket per connection
    *) cell "tlsfuzzer/$s" tlsfuzzer "$s" "${PORT[rsa,both,on]}";;
  esac
done
for s in "${TF12[@]}"; do cell "tlsfuzzer/$s" skip12; done
cell testssl/protocols testssl "${PORT[rsa,both,on]}" proto
cell testssl/tls12 skip_ts "testssl's TLS 1.2 probes carry no extended_master_secret, which our policy refuses (it reports 'not offered'); the TLS 1.2 suite set is checked by sc/12/*/suite-* and neg/cbc-12"
cell testssl/ciphers testssl "${PORT[rsa,both,on]}" ciphers
for p in "${CELLPIDS[@]:-}"; do [[ -n $p ]] && wait "$p" || true; done  # the servers are children too: wait for the cells only

# ---- report ----
pass=0; skip=0; fail=0
while IFS= read -r l; do
  echo "$l"; case $l in PASS*) pass=$((pass+1));; SKIP*) skip=$((skip+1));; *) fail=$((fail+1));; esac
done < <(cat "$CELLS"/*.txt 2>/dev/null | sort -k2)
echo "VERSIONS openssl=$(openssl version | cut -d' ' -f2) firefox=$(firefox --version 2>/dev/null | cut -d' ' -f3) vivaldi=$(/usr/bin/vivaldi-stable --version 2>/dev/null | cut -d' ' -f2) chromium(playwright)=$(cat "$W"/chromium-*/result.json 2>/dev/null | grep -o '"version": "[^"]*"' | head -1 | cut -d'"' -f4) tlsfuzzer=$(git -C "$T/tlsfuzzer" log -1 --format=%h 2>/dev/null) testssl=$(git -C "$T/testssl" describe --tags --always 2>/dev/null)"
echo "RESULT pass=$pass skip=$skip fail=$fail"
[[ $fail -eq 0 ]] || { echo "FAIL matrix: $fail cell(s)"; exit 1; }
echo "PASS matrix"
