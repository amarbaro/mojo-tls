#!/usr/bin/env bash
# Lane 3 gate: builds tests/x509_gate.mojo once, runs every stage, compares against openssl oracles.
# Usage: tests/gate_x509.sh [stage ...]   stages: parse chain keys limbo roots bench   (default: parse chain keys limbo)
# Prints PASS/FAIL <stage>: <reason>; exits non-zero on any failure. Artifacts in .work/gate/.
set -euo pipefail
cd "$(dirname "$0")/.."
MOJO=${MOJO:-$PWD/.venv/bin/mojo}
W=${W:-.work/gate}
BIN=${BIN:-$W/gate}
BUNDLE=${BUNDLE:-/etc/ssl/certs/ca-certificates.crt}
mkdir -p $W
fail() { echo "FAIL $1: $2"; exit 1; }

build() {
  [ -n "${NOBUILD:-}" ] && return 0
  rm -f $BIN
  timeout 300 $MOJO build -I ${SRC:-src} tests/x509_gate.mojo -o $BIN 2>&1 | grep -E "error" -A4 && fail build "mojo build failed" || true
  [ -x $BIN ] || fail build "no binary"
}

stage_parse() {
  timeout 60 $BIN unit || fail parse "unit vectors"
  timeout 120 $BIN fuzz $BUNDLE 200 || fail parse "fuzz"
  local dir=$W/bundle n=0
  rm -rf $dir && mkdir -p $dir
  awk -v d=$dir '/BEGIN CERTIFICATE/{n++; f=sprintf("%s/%03d.pem", d, n)} f != "" {print > f}' $BUNDLE
  : > $W/bundle_oracle.txt
  for f in $dir/*.pem; do
    local nb na ser key
    nb=$(date -u -d "$(openssl x509 -in $f -noout -startdate | cut -d= -f2)" +%s)
    na=$(date -u -d "$(openssl x509 -in $f -noout -enddate | cut -d= -f2)" +%s)
    ser=$(openssl x509 -in $f -noout -serial | cut -d= -f2 | tr A-Z a-z)
    if openssl x509 -in $f -noout -modulus 2>/dev/null | grep -qE '^Modulus=[0-9A-F]+$'; then
      key=$(openssl x509 -in $f -noout -modulus | cut -d= -f2 | tr A-Z a-z)
    else
      local txt
      txt=$(openssl x509 -in $f -noout -pubkey | openssl pkey -pubin -noout -text 2>/dev/null)
      if echo "$txt" | grep -qE 'ASN1 OID: (prime256v1|secp384r1)'; then
        key=$(echo "$txt" | sed -n '/^pub:/,/^ASN1 OID/p' | grep -v -e '^pub:' -e '^ASN1' | tr -d ' :\n')
      else
        key=-
      fi
    fi
    echo "$nb $na $ser $key" >> $W/bundle_oracle.txt
    n=$((n + 1))
  done
  $BIN bundle $BUNDLE > $W/bundle_ours.txt || fail parse "bundle parse"
  local want have
  want=$(grep -c 'BEGIN CERTIFICATE' $BUNDLE)
  have=$(wc -l < $W/bundle_ours.txt)
  [ "$want" = "$have" ] || fail parse "parsed $have of $want bundle certs"
  diff <(cat $W/bundle_oracle.txt) <(cat $W/bundle_ours.txt) > $W/bundle.diff || { head -5 $W/bundle.diff; fail parse "fields differ from openssl on $(grep -c '^<' $W/bundle.diff) certs"; }
  echo "PASS parse: all $have certs of $BUNDLE parse; not_before, not_after, serial and key bytes equal openssl's"
}

oracle_cases() {  # manifest; prints "total agree div" to $W/oracle.txt
  local agree=0 div=0 total=0 d=tests/data
  while read -r name expect now host roots chain; do
    [ -z "$name" ] && continue
    ( cd $d && cat $(echo "$chain" | tr ',' ' ') ) > $W/all.pem
    awk '/BEGIN CERTIFICATE/{n++} n==1{print}' $W/all.pem > $W/leaf.pem
    local ca=$BUNDLE ho=()
    if [ "$roots" != "@system" ]; then
      ( cd $d && cat $(echo "$roots" | tr ',' ' ') ) > $W/roots.pem; ca=$W/roots.pem
    fi
    if [ "$host" != "-" ]; then
      if [[ "$host" == *:* || "$host" =~ ^[0-9.]+$ ]]; then ho=(-verify_ip "$host"); else ho=(-verify_hostname "$host"); fi
    fi
    local oss=fail
    if openssl verify -CAfile $ca -untrusted $W/all.pem -purpose sslserver -attime "$now" "${ho[@]}" $W/leaf.pem > /dev/null 2>&1; then oss=ok; fi
    total=$((total + 1))
    if grep -q "^$name " $d/divergences.txt; then
      div=$((div + 1))
      [ "$oss" != "$expect" ] || echo "note chain: $name is listed as divergent but openssl agrees"
    elif [ "$oss" != "$expect" ]; then
      fail chain "$name: openssl says $oss, expected $expect (fixture wrong or undocumented divergence)"
    else
      agree=$((agree + 1))
    fi
  done < $1
  echo "$total $agree $div" > $W/oracle.txt
}

stage_chain() {
  timeout 120 $BIN chain tests/data/chain_cases.txt || fail chain "synthetic verdicts differ from the expected ones"
  timeout 300 $BIN fuzzchain 3000 || fail chain "mutated certificates verified or crashed the verifier"
  timeout 120 $BIN chain tests/data/chain_real.txt || fail chain "real-site verdicts differ from the expected ones"
  local t1 a1 d1 t2 a2 d2
  oracle_cases tests/data/chain_cases.txt; read -r t1 a1 d1 < $W/oracle.txt
  oracle_cases tests/data/chain_real.txt; read -r t2 a2 d2 < $W/oracle.txt
  echo "PASS chain: $t1 synthetic + $t2 real-site cases give the expected verdict; $((a1 + a2)) agree with openssl verify -purpose sslserver, $((d1 + d2)) documented divergences"
}

stage_keys() {
  local k=$W/keys d=tests/data
  rm -rf $k && mkdir -p $k
  timeout 120 $BIN keys $d/key_cases.txt $k > $k/out.txt || { cat $k/out.txt | grep -E '^FAIL' | head -5; fail keys "key loading or corruption checks"; }
  cat $k/out.txt | grep -E '^keys:|^note' || true
  local good=0
  while read -r name expect file cert; do
    [ "$expect" = ok ] || continue
    local want got
    local dg=sha256
    if grep -q "^key $name kind 3 " $k/out.txt; then
      dg=sha384
      want=$(openssl pkey -in $d/$file -pubout -outform DER | tail -c 97 | od -An -tx1 -v | tr -d ' \n')
      got=$(grep "^key $name kind 3 " $k/out.txt | sed 's/.* pub \([0-9a-f]*\) .*/\1/')
    elif grep -q "^key $name kind 2 " $k/out.txt; then
      want=$(openssl pkey -in $d/$file -pubout -outform DER | tail -c 65 | od -An -tx1 -v | tr -d ' \n')
      got=$(grep "^key $name kind 2 " $k/out.txt | sed 's/.* pub \([0-9a-f]*\) .*/\1/')
    else
      want=$(openssl rsa -in $d/$file -noout -modulus | cut -d= -f2 | tr A-Z a-z)
      got=$(grep "^key $name kind 1 " $k/out.txt | sed 's/.* pub \([0-9a-f]*\) .*/\1/')
    fi
    [ "$want" = "$got" ] || fail keys "$name: public key differs from openssl's"
    openssl pkey -in $d/$file -pubout -out $k/pub_$name.pem
    local sig=$k/sig_$name.der
    [ -f $sig ] || sig=$k/sig_$name.bin
    openssl dgst -$dg -verify $k/pub_$name.pem -signature $sig $k/msg.txt > /dev/null || fail keys "$name: openssl rejects our signature"
    good=$((good + 1))
  done < $d/key_cases.txt
  echo "PASS keys: $good keys (P-256 PKCS#8/SEC1, P-384 PKCS#8, RSA 2048/3072 PKCS#8/PKCS#1) load with openssl's public key bytes and our signatures verify under openssl; encrypted, Ed25519, RSA-1024 refused; $(grep -c 'all refused' $k/out.txt) encodings survive every single-byte corruption test"
}

stage_bench() {
  timeout 300 $BIN bench | grep '^bench' || fail bench "bench failed"
  echo "PASS bench: numbers above (resident process, median of 5 batches)"
}

stage_limbo() {
  # x509-limbo. A valid chain rejected must match a line of tests/limbo_known.txt: `<id or glob><TAB><reason>`.
  # An invalid chain accepted is a failure unless a `!<id or glob><TAB><reason>` line pins it, and only the
  # webpki::cn:: class (the CN is never read, RFC 9525) and rfc5280::ski::root-missing-ski (a trust anchor is
  # path-validation input, RFC 5280 6.1.1 d; user decision 2026-11-12 for TWCA Global Root CA) may be pinned that way.
  local L=.work/limbo
  [ -f $L/cases.txt ] || tools/limbo_fetch.sh > /dev/null 2>&1 || { echo "SKIP limbo: no .work/limbo/cases.txt and tools/limbo_fetch.sh failed (needs network); NOT a pass"; return 0; }
  timeout 300 $BIN limbo $L/cases.txt > $L/out_$$.txt || fail limbo "limbo run crashed"
  local sum; sum=$(grep '^limbo:' $L/out_$$.txt)
  mv $L/out_$$.txt $W/limbo_out.txt
  local pat reason pats=() apats=() id
  while IFS=$'\t' read -r pat reason; do
    [ -z "$pat" ] && continue
    [ -n "$reason" ] || fail limbo "tests/limbo_known.txt: '$pat' has no reason"
    if [ "${pat:0:1}" = '!' ]; then
      [[ ${pat:1} == webpki::cn::* || ${pat:1} == rfc5280::ski::root-missing-ski ]] || fail limbo "tests/limbo_known.txt: '$pat' pins an invalid chain outside the two policy classes (webpki::cn::*, rfc5280::ski::root-missing-ski)"
      apats+=("${pat:1}")
    else
      pats+=("$pat")
    fi
  done < tests/limbo_known.txt
  declare -A hit=()
  local nr=0 na=0 unknown=0 found
  while read -r _ id _ _ _ got _; do
    found=0
    for pat in "${pats[@]}"; do if [[ $id == $pat ]]; then found=1; hit[$pat]=1; break; fi; done
    nr=$((nr + 1)); [ $found = 1 ] || { unknown=$((unknown + 1)); echo "  new valid chain rejected: $id"; }
  done < <(grep '^DIFF .* expected ok got fail' $W/limbo_out.txt)
  while read -r _ id _; do
    found=0
    for pat in "${apats[@]}"; do if [[ $id == $pat ]]; then found=1; hit[!$pat]=1; break; fi; done
    na=$((na + 1)); [ $found = 1 ] || { unknown=$((unknown + 1)); echo "  INVALID chain ACCEPTED: $id"; }
  done < <(grep '^DIFF .* expected fail got ok' $W/limbo_out.txt)
  [ "$unknown" = 0 ] || fail limbo "$unknown disagreements with limbo that tests/limbo_known.txt does not explain (an accepted invalid chain is a security bug)"
  for pat in "${pats[@]}"; do [ -n "${hit[$pat]:-}" ] || echo "note limbo: '$pat' matches no disagreement any more; delete it from tests/limbo_known.txt"; done
  for pat in "${apats[@]}"; do [ -n "${hit[!$pat]:-}" ] || echo "note limbo: '!$pat' matches no disagreement any more; delete it from tests/limbo_known.txt"; done
  echo "PASS limbo: ${sum#limbo: }; $na invalid accepted (all pinned policy: webpki::cn::*, rfc5280::ski::root-missing-ski), $nr valid rejected, explained by $((${#pats[@]} + ${#apats[@]})) lines of tests/limbo_known.txt"
}

stage_roots() {
  # the system bundle against the trust-anchor profile; informational, the bundle differs per machine
  local out; out=$(timeout 60 $BIN roots $BUNDLE) || fail roots "roots audit crashed"
  echo "$out" | grep '^ROOT' | sed 's/^/note roots: /' | cut -c1-200 || true
  echo "PASS roots: $(echo "$out" | grep '^roots:' | cut -d: -f2-)"
}

build
stages=("$@")
[ ${#stages[@]} -eq 0 ] && stages=(parse chain keys limbo)
for s in "${stages[@]}"; do "stage_$s"; done
