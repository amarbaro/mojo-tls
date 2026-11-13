#!/usr/bin/env bash
# openssl cross-checks of tls.asym on random inputs (openssl is the oracle, tests/tool.mojo is the code under test).
# ORACLE_N = random cases per primitive (default 8); RSA keys of 2048/3072/4096 bits are generated once into .work/oracle/.
set -euo pipefail
cd "$(dirname "$0")/.."
N=${ORACLE_N:-8}
O=${ORACLE_DIR:-.work/oracle}; mkdir -p $O
T=${T:-.work/tool}
[ -x $T ] || tools/mb.sh tests/tool.mojo $T
bad=0
ok() { if [ "$2" = 1 ]; then echo "PASS oracle $1"; else echo "FAIL oracle $1: $3"; bad=1; fi; }
hexb() { od -An -v -tx1 | tr -d ' \n'; echo; }
unhexb() { perl -ne 'chomp; print pack("H*",$_)'; }
hexrand() { openssl rand -hex "$1"; }
flip() { local s=$1; local last=${s: -1}; if [ "$last" = 0 ]; then echo "${s%?}1"; else echo "${s%?}0"; fi; }

# X25519: public key and shared secret against openssl
good=1
for i in $(seq "$N"); do
  a=$(hexrand 32); b=$(hexrand 32)
  printf '302e020100300506032b656e04220420%s' "$a" | unhexb > $O/a.der; openssl pkey -inform DER -in $O/a.der -out $O/a.pem
  printf '302e020100300506032b656e04220420%s' "$b" | unhexb > $O/b.der; openssl pkey -inform DER -in $O/b.der -out $O/b.pem
  apub=$(openssl pkey -in $O/a.pem -pubout -outform DER | tail -c 32 | hexb)
  bpub=$(openssl pkey -in $O/b.pem -pubout -outform DER | tail -c 32 | hexb)
  openssl pkey -in $O/b.pem -pubout -out $O/bpub.pem
  [ "$($T x25519-base "$a")" = "$apub" ] || good=0
  [ "$($T x25519 "$a" "$bpub")" = "$(openssl pkeyutl -derive -inkey $O/a.pem -peerkey $O/bpub.pem | hexb)" ] || good=0
done
ok "x25519 pub+shared vs openssl x$N" $good "mismatch"

# P-256: public key, ECDH, our signature verified by openssl, openssl signature verified by us
sec1() { printf '30310201010420%sa00a06082a8648ce3d030107' "$1" | unhexb > $O/k.der; openssl ec -inform DER -in $O/k.der -out "$2" 2>/dev/null; }
good=1; goodv=1; goodo=1
for i in $(seq "$N"); do
  d1="7f$(hexrand 31)"; d2="3c$(hexrand 31)"
  sec1 "$d1" $O/k1.pem; sec1 "$d2" $O/k2.pem
  openssl ec -in $O/k1.pem -pubout -out $O/k1pub.pem 2>/dev/null; openssl ec -in $O/k2.pem -pubout -out $O/k2pub.pem 2>/dev/null
  p1=$(openssl ec -in $O/k1.pem -pubout -outform DER 2>/dev/null | tail -c 65 | hexb)
  p2=$(openssl ec -in $O/k2.pem -pubout -outform DER 2>/dev/null | tail -c 65 | hexb)
  [ "$($T p256-pub "$d1")" = "$p1" ] || good=0
  [ "$($T p256-ecdh "$d1" "$p2")" = "$(openssl pkeyutl -derive -inkey $O/k1.pem -peerkey $O/k2pub.pem | hexb)" ] || good=0
  h=$(hexrand 32); echo "$h" | unhexb > $O/h.bin
  $T p256-sign "$d1" "$h" | unhexb > $O/ours.der
  openssl pkeyutl -verify -pubin -inkey $O/k1pub.pem -in $O/h.bin -sigfile $O/ours.der >/dev/null 2>&1 || goodv=0
  echo "$h" | unhexb | openssl pkeyutl -sign -inkey $O/k1.pem -out $O/theirs.der
  [ "$($T p256-verify "$p1" "$h" "$(hexb < $O/theirs.der)")" = 1 ] || goodo=0
  [ "$($T p256-verify "$p1" "$(flip "$h")" "$(hexb < $O/theirs.der)")" = 0 ] || goodo=0
done
ok "p256 pub+ecdh vs openssl x$N" $good "mismatch"
ok "p256 our signatures verify in openssl x$N" $goodv "openssl rejected"
ok "p256 openssl signatures verify here, tampered rejected x$N" $goodo "mismatch"

# P-384 verify, and our signature verified by openssl (audit #4)
good=1; goods=1
for i in $(seq "$N"); do
  openssl ecparam -name secp384r1 -genkey -noout -out $O/k384.pem
  p=$(openssl ec -in $O/k384.pem -pubout -outform DER 2>/dev/null | tail -c 97 | hexb)
  h=$(hexrand 48); echo "$h" | unhexb | openssl pkeyutl -sign -inkey $O/k384.pem -out $O/s384.der
  s=$(hexb < $O/s384.der)
  [ "$($T p384-verify "$p" "$h" "$s")" = 1 ] && [ "$($T p384-verify "$p" "$(flip "$h")" "$s")" = 0 ] || good=0
  d=$(openssl ec -in $O/k384.pem -outform DER 2>/dev/null | tail -c +9 | head -c 48 | hexb)  # SEC1: 30 81 a4 02 01 01 04 30 <d>
  echo "$h" | unhexb > $O/h384.bin
  $T p384-sign "$d" "$h" | unhexb > $O/ours384.der
  openssl pkeyutl -verify -pubin -inkey <(openssl ec -in $O/k384.pem -pubout 2>/dev/null) -in $O/h384.bin -sigfile $O/ours384.der >/dev/null 2>&1 || goods=0
done
ok "p384 openssl signatures verify here, tampered rejected x$N" $good "mismatch"
ok "p384 our signatures verify in openssl x$N" $goods "openssl rejected"

# RSA: keys cached; PSS sign here -> openssl verify; openssl PSS/PKCS#1 sign -> verify here
for bits in 2048 3072 4096; do
  [ -f $O/rsa$bits.pem ] || openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$bits -out $O/rsa$bits.pem 2>/dev/null
  openssl rsa -in $O/rsa$bits.pem -pubout -out $O/rsa$bits.pub 2>/dev/null
  read -r n e p q dp dq qi < <(python3 -I tools/rsa_parts.py $O/rsa$bits.pem)
  good=1; goodo=1
  for alg in 256 384 512; do
    for i in $(seq 3); do
      openssl rand 100 > $O/msg.bin
      h=$(openssl dgst -sha$alg -binary $O/msg.bin | hexb); echo "$h" | unhexb > $O/h.bin
      sl=$((alg / 8))
      $T rsa-sign-pss $alg "$h" "$n" "$e" "$p" "$q" "$dp" "$dq" "$qi" > $O/sig.hex
      unhexb < $O/sig.hex > $O/sig.bin
      openssl pkeyutl -verify -pubin -inkey $O/rsa$bits.pub -in $O/h.bin -sigfile $O/sig.bin -pkeyopt digest:sha$alg -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$sl -pkeyopt rsa_mgf1_md:sha$alg >/dev/null 2>&1 || good=0
      [ "$($T rsa-verify-pss $alg "$h" "$n" "$e" "$(cat $O/sig.hex)")" = 1 ] || good=0
      [ "$($T rsa-verify-pss $alg "$(flip "$h")" "$n" "$e" "$(cat $O/sig.hex)")" = 0 ] || good=0
      openssl pkeyutl -sign -inkey $O/rsa$bits.pem -in $O/h.bin -out $O/o.bin -pkeyopt digest:sha$alg -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:$sl -pkeyopt rsa_mgf1_md:sha$alg
      [ "$($T rsa-verify-pss $alg "$h" "$n" "$e" "$(hexb < $O/o.bin)")" = 1 ] || goodo=0
      openssl pkeyutl -sign -inkey $O/rsa$bits.pem -in $O/h.bin -out $O/o.bin -pkeyopt digest:sha$alg -pkeyopt rsa_padding_mode:pkcs1
      [ "$($T rsa-verify-pkcs1 $alg "$h" "$n" "$e" "$(hexb < $O/o.bin)")" = 1 ] || goodo=0
      [ "$($T rsa-sign-pkcs1 $alg "$h" "$n" "$e" "$p" "$q" "$dp" "$dq" "$qi")" = "$(hexb < $O/o.bin)" ] || good=0  # deterministic: byte equal to openssl
      [ "$($T rsa-verify-pkcs1 $alg "$(flip "$h")" "$n" "$e" "$(hexb < $O/o.bin)")" = 0 ] || goodo=0
    done
  done
  ok "rsa$bits our PSS signatures verify in openssl, ours accepts them, tampered rejected (sha256/384/512 x3)" $good "mismatch"
  ok "rsa$bits openssl PSS and PKCS#1 signatures verify here (sha256/384/512 x3)" $goodo "mismatch"
done
exit $bad
