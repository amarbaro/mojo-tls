#!/usr/bin/env bash
# Regenerates tests/data/: chain fixtures, private keys and tests/data/chain_cases.txt with openssl only.
# Every case line: name expect now host roots chain   (roots/chain: comma-separated files in tests/data, chain leaf first)
# A case whose openssl verdict legitimately differs from ours is listed in tests/data/divergences.txt with the reason.
set -euo pipefail
cd "$(dirname "$0")/data"
find . -maxdepth 1 -name '*.pem' ! -name 'live_*' -delete
rm -f *.key *.csr *.srl *.der chain_cases.txt divergences.txt
G=$(date +%s)
NOW=$((G + 3600))
EC="-algorithm EC -pkeyopt ec_paramgen_curve:P-256"
CASES=chain_cases.txt
: > $CASES

# issue OUT CN SIGNER KEYTYPE EXTS [days] [digest opts...]; KEYTYPE: ec | ec384 | rsa | rsa1024 | existing:<keyfile>
# SIGNER "self" makes a self-signed certificate. EXTS is the extension file body.
issue() {
  local out=$1 cn=$2 signer=$3 kt=$4 exts=$5 days=${6:-36500}; shift 6 || shift $#
  case $kt in
    ec) openssl genpkey $EC -out $out.key 2>/dev/null ;;
    ec384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $out.key 2>/dev/null ;;
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $out.key 2>/dev/null ;;
    rsa1024) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out $out.key 2>/dev/null ;;
  esac
  openssl req -new -key $out.key -subj "$([ "$cn" = - ] && echo / || echo "/CN=$cn")" -out $out.csr
  if [ "$signer" = self ]; then
    openssl x509 -req -in $out.csr -signkey $out.key -days $days -extfile <(printf '%b' "$exts") -out $out.pem "$@" 2>/dev/null
  else
    openssl x509 -req -in $out.csr -CA $signer.pem -CAkey $signer.key -CAcreateserial -days $days \
      -extfile <(printf '%b' "$exts") -out $out.pem "$@" 2>/dev/null
  fi
  rm -f $out.csr
}
CA='basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
CA0='basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n'
SRV='basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n'
san() { printf 'subjectAltName=%s\\n' "$1"; }
cs() { echo "$1 $2 $3 $4 $5 $6" >> $CASES; }
div() { echo "$1 $2" >> divergences.txt; }
: > divergences.txt

# --- EC family
issue ec_root "EC Root" self ec "$CA"
issue ec_root2 "Other Root" self ec "$CA"
issue ec_inter "EC Inter" ec_root ec "$CA0"
issue ec_leaf "leaf" ec_inter ec "$SRV$(san DNS:a.example.com,DNS:example.com,IP:192.0.2.7,IP:2001:db8::1)"
cs ok_ec_chain ok $NOW a.example.com ec_root.pem ec_leaf.pem,ec_inter.pem
cs ok_root_in_chain ok $NOW a.example.com ec_root.pem ec_leaf.pem,ec_inter.pem,ec_root.pem
cs ok_apex ok $NOW example.com ec_root.pem ec_leaf.pem,ec_inter.pem
cs ok_upper_case_host ok $NOW A.Example.COM ec_root.pem ec_leaf.pem,ec_inter.pem
cs ok_trailing_dot ok $NOW a.example.com. ec_root.pem ec_leaf.pem,ec_inter.pem
div ok_trailing_dot "openssl does not strip a trailing dot; browsers do"
cs ok_ip4 ok $NOW 192.0.2.7 ec_root.pem ec_leaf.pem,ec_inter.pem
cs ok_ip6 ok $NOW 2001:db8::1 ec_root.pem ec_leaf.pem,ec_inter.pem
cs bad_ip4 fail $NOW 192.0.2.8 ec_root.pem ec_leaf.pem,ec_inter.pem
cs bad_host fail $NOW b.other.org ec_root.pem ec_leaf.pem,ec_inter.pem
cs bad_host_suffix fail $NOW xa.example.com ec_root.pem ec_leaf.pem,ec_inter.pem
cs bad_host_empty fail $NOW - ec_root.pem ec_leaf.pem,ec_inter.pem
div bad_host_empty "openssl verify is given no name to check"
cs bad_missing_inter fail $NOW a.example.com ec_root.pem ec_leaf.pem
cs bad_wrong_root fail $NOW a.example.com ec_root2.pem ec_leaf.pem,ec_inter.pem
cs bad_no_roots fail $NOW a.example.com ec_root2.pem ec_leaf.pem,ec_inter.pem,ec_root2.pem
# dns SAN only, IP host
issue ec_dnsonly "d" ec_inter ec "$SRV$(san DNS:192.0.2.7)"
cs bad_ip_vs_dns_san fail $NOW 192.0.2.7 ec_root.pem ec_dnsonly.pem,ec_inter.pem
# wildcard
issue ec_wild "w" ec_inter ec "$SRV$(san 'DNS:*.wild.example.com,DNS:*.com,DNS:f*.example.org,DNS:x.*.example.net')"
issue ec_wild_ok "w" ec_inter ec "$SRV$(san DNS:*.wild.example.com)"
cs ok_wild ok $NOW x.wild.example.com ec_root.pem ec_wild_ok.pem,ec_inter.pem
cs bad_wild_apex fail $NOW wild.example.com ec_root.pem ec_wild.pem,ec_inter.pem
cs bad_wild_two_labels fail $NOW a.b.wild.example.com ec_root.pem ec_wild.pem,ec_inter.pem
cs bad_wild_tld fail $NOW foo.com ec_root.pem ec_wild.pem,ec_inter.pem
cs bad_wild_partial fail $NOW fa.example.org ec_root.pem ec_wild.pem,ec_inter.pem
div bad_wild_partial "openssl accepts partial-label wildcards"
cs bad_wild_middle fail $NOW x.y.example.net ec_root.pem ec_wild.pem,ec_inter.pem
# resource caps: 256 name constraint subtrees, 1024 SAN names (cert.mojo MAX_NC_SUBTREES, MAX_SAN_NAMES)
subtrees() { local n=$1 o=permitted\;DNS:good.example i; for ((i = 1; i < n; i++)); do o+=,permitted\;DNS:d$i.example; done; printf '%s' "$o"; }
names() { local n=$1 o=DNS:n0.good.example i; for ((i = 1; i < n; i++)); do o+=,DNS:n$i.good.example; done; printf '%s' "$o"; }
issue caps_root256 "Caps256" ec_root ec "$CA"'nameConstraints=critical,'"$(subtrees 256)"'\n'
issue caps_root257 "Caps257" ec_root ec "$CA"'nameConstraints=critical,'"$(subtrees 257)"'\n'
issue caps_leaf1024 "l" caps_root256 ec "$SRV$(san "$(names 1024)")"
issue caps_leaf1025 "l" caps_root256 ec "$SRV$(san "$(names 1025)")"
cs ok_caps_at_limit ok $NOW n1023.good.example ec_root.pem caps_leaf1024.pem,caps_root256.pem
issue caps_leaf257 "l" caps_root257 ec "$SRV$(san DNS:n0.good.example)"
cs bad_nc_257_subtrees fail $NOW n0.good.example ec_root.pem caps_leaf257.pem,caps_root257.pem
div bad_nc_257_subtrees "openssl has no cap on name constraint subtrees; we refuse more than 256 (DoS bound, limbo pathological::nc-dos)"
cs bad_san_1025_names fail $NOW n0.good.example ec_root.pem caps_leaf1025.pem,caps_root256.pem
div bad_san_1025_names "openssl has no cap on SAN entries; we refuse more than 1024 (DoS bound, limbo pathological::nc-dos)"
# a CA certificate in leaf position (all leaf extensions otherwise fine), and a malformed SAN in an intermediate under constraints
issue ec_leaf_isca "ca" ec_inter ec "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\nextendedKeyUsage=serverAuth\n$(san DNS:leafca.example.com)"
cs bad_leaf_is_ca fail $NOW leafca.example.com ec_root.pem ec_leaf_isca.pem,ec_inter.pem
div bad_leaf_is_ca "openssl does not refuse a CA certificate in leaf position; CA/B BR profile (limbo webpki::ca-as-leaf) does"
issue ec_inter_nosubj - ec_root ec "$CA"
issue ec_leaf_nosubj "l" ec_inter_nosubj ec "$SRV$(san DNS:nosubj.example.com)"
cs bad_ca_empty_subject fail $NOW nosubj.example.com ec_root.pem ec_leaf_nosubj.pem,ec_inter_nosubj.pem
div bad_ca_empty_subject "openssl accepts an intermediate with an empty subject name"
# CN only
issue ec_cn_victim "victim.example" ec_inter ec "$SRV$(san DNS:other.example)"
cs bad_cn_victim fail $NOW victim.example ec_root.pem ec_cn_victim.pem,ec_inter.pem
cs ok_cn_victim_san ok $NOW other.example ec_root.pem ec_cn_victim.pem,ec_inter.pem
issue ec_cnonly "cn.example.com" ec_inter ec "$SRV"
cs bad_cn_only fail $NOW cn.example.com ec_root.pem ec_cnonly.pem,ec_inter.pem
div bad_cn_only "openssl falls back to the subject CN when there is no SAN; RFC 9525 forbids it"
# validity
issue ec_short "s" ec_inter ec "$SRV$(san DNS:a.example.com)" 30
cs ok_short_valid ok $NOW a.example.com ec_root.pem ec_short.pem,ec_inter.pem
cs bad_expired fail $((G + 40 * 86400)) a.example.com ec_root.pem ec_short.pem,ec_inter.pem
cs bad_not_yet_valid fail $((G - 365 * 86400)) a.example.com ec_root.pem ec_leaf.pem,ec_inter.pem
# CA constraints: issuer-is-CA, pathLen, KU, EKU
issue ec_leaf2 "l2" ec_leaf ec "$SRV$(san DNS:evil.example.com)"
cs bad_nonca_issuer fail $NOW evil.example.com ec_root.pem ec_leaf2.pem,ec_leaf.pem,ec_inter.pem
issue ec_inter2 "I2" ec_inter ec "$CA"
issue ec_leaf3 "l3" ec_inter2 ec "$SRV$(san DNS:deep.example.com)"
cs bad_pathlen0 fail $NOW deep.example.com ec_root.pem ec_leaf3.pem,ec_inter2.pem,ec_inter.pem
issue ec_inter_p1 "Ip1" ec_root ec 'basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign\n'
issue ec_inter_p1b "Ip1b" ec_inter_p1 ec "$CA"
issue ec_inter_p1c "Ip1c" ec_inter_p1b ec "$CA"
issue ec_leaf_p1 "lp1" ec_inter_p1b ec "$SRV$(san DNS:p1.example.com)"
issue ec_leaf_p1c "lp1c" ec_inter_p1c ec "$SRV$(san DNS:p1c.example.com)"
cs ok_pathlen1 ok $NOW p1.example.com ec_root.pem ec_leaf_p1.pem,ec_inter_p1b.pem,ec_inter_p1.pem
cs bad_pathlen1_exceeded fail $NOW p1c.example.com ec_root.pem ec_leaf_p1c.pem,ec_inter_p1c.pem,ec_inter_p1b.pem,ec_inter_p1.pem
cs ok_out_of_order ok $NOW p1.example.com ec_root.pem ec_leaf_p1.pem,ec_inter_p1.pem,ec_inter_p1b.pem
issue ec_ca_false "Inoca" ec_root ec 'basicConstraints=critical,CA:FALSE\n'
issue ec_leaf4 "l4" ec_ca_false ec "$SRV$(san DNS:noca.example.com)"
cs bad_inter_not_ca fail $NOW noca.example.com ec_root.pem ec_leaf4.pem,ec_ca_false.pem
issue ec_noca_noku "Inoku" ec_root ec 'basicConstraints=CA:FALSE\n'
issue ec_leaf4c "l4c" ec_noca_noku ec "$SRV$(san DNS:noku.example.com)"
cs bad_inter_not_ca_no_ku fail $NOW noku.example.com ec_root.pem ec_leaf4c.pem,ec_noca_noku.pem
issue ec_ca_nobc "Inobc" ec_root ec 'keyUsage=critical,keyCertSign\n'
issue ec_leaf4b "l4b" ec_ca_nobc ec "$SRV$(san DNS:nobc.example.com)"
cs bad_inter_no_bc fail $NOW nobc.example.com ec_root.pem ec_leaf4b.pem,ec_ca_nobc.pem
issue ec_ca_noks "Inoks" ec_root ec 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n'
issue ec_leaf5 "l5" ec_ca_noks ec "$SRV$(san DNS:noks.example.com)"
cs bad_inter_no_certsign fail $NOW noks.example.com ec_root.pem ec_leaf5.pem,ec_ca_noks.pem
issue ec_leaf_cli "c" ec_inter ec "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n$(san DNS:cli.example.com)"
cs bad_eku_client fail $NOW cli.example.com ec_root.pem ec_leaf_cli.pem,ec_inter.pem
issue ec_leaf_anyeku "a" ec_inter ec "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=anyExtendedKeyUsage\n$(san DNS:any.example.com)"
cs ok_eku_any ok $NOW any.example.com ec_root.pem ec_leaf_anyeku.pem,ec_inter.pem
div ok_eku_any "openssl treats a leaf with only anyExtendedKeyUsage as unsuitable for sslserver; Go and Chromium accept it"
issue ec_leaf_noeku "n" ec_inter ec "basicConstraints=CA:FALSE\n$(san DNS:noeku.example.com)"
cs bad_no_eku fail $NOW noeku.example.com ec_root.pem ec_leaf_noeku.pem,ec_inter.pem
div bad_no_eku "openssl accepts a leaf without extendedKeyUsage; CA/B BR 7.1.2.7.6 requires one (limbo webpki::eku::ee-without-eku)"
issue ec_leaf_ku "k" ec_inter ec "basicConstraints=CA:FALSE\nkeyUsage=critical,keyEncipherment\n$(san DNS:ku.example.com)"
cs bad_ku_no_signature fail $NOW ku.example.com ec_root.pem ec_leaf_ku.pem,ec_inter.pem
div bad_ku_no_signature "openssl -purpose sslserver accepts keyEncipherment (RSA key transport); our suites cannot use it"
issue ec_inter_eku "Ieku" ec_root ec "$CA"'extendedKeyUsage=clientAuth\n'
issue ec_leaf_ieku "ie" ec_inter_eku ec "$SRV$(san DNS:ieku.example.com)"
cs bad_inter_eku fail $NOW ieku.example.com ec_root.pem ec_leaf_ieku.pem,ec_inter_eku.pem
issue ec_leaf_crit "c" ec_inter ec "$SRV$(san DNS:crit.example.com)"'1.2.3.4=critical,ASN1:UTF8String:x\n'
cs bad_unknown_critical fail $NOW crit.example.com ec_root.pem ec_leaf_crit.pem,ec_inter.pem
issue ec_leaf_ncrit "c" ec_inter ec "$SRV$(san DNS:ncrit.example.com)"'1.2.3.4=ASN1:UTF8String:x\n'
cs ok_unknown_noncritical ok $NOW ncrit.example.com ec_root.pem ec_leaf_ncrit.pem,ec_inter.pem
# name constraints
issue nc_dns "NC dns" ec_root ec "$CA"'nameConstraints=critical,permitted;DNS:good.example\n'
issue nc_dns_leaf_ok "g" nc_dns ec "$SRV$(san DNS:www.good.example)"
issue nc_dns_leaf_bad "b" nc_dns ec "$SRV$(san DNS:www.bad.example)"
issue nc_dns_leaf_mixed "m" nc_dns ec "$SRV$(san DNS:www.good.example,DNS:www.bad.example)"
cs ok_nc_dns_permitted ok $NOW www.good.example ec_root.pem nc_dns_leaf_ok.pem,nc_dns.pem
cs bad_nc_dns_not_permitted fail $NOW www.bad.example ec_root.pem nc_dns_leaf_bad.pem,nc_dns.pem
cs bad_nc_dns_mixed fail $NOW www.good.example ec_root.pem nc_dns_leaf_mixed.pem,nc_dns.pem
issue nc_dnsx "NC dnsx" ec_root ec "$CA"'nameConstraints=critical,permitted;DNS:good.example,excluded;DNS:sub.good.example\n'
issue nc_dnsx_apex "a" nc_dnsx ec "$SRV$(san DNS:good.example)"
issue nc_dnsx_sub "s" nc_dnsx ec "$SRV$(san DNS:x.sub.good.example)"
issue nc_dnsx_oth "o" nc_dnsx ec "$SRV$(san DNS:x.other.good.example)"
issue nc_dnsx_sfx "f" nc_dnsx ec "$SRV$(san DNS:notgood.example)"
cs ok_nc_apex_permitted ok $NOW good.example ec_root.pem nc_dnsx_apex.pem,nc_dnsx.pem
cs bad_nc_excluded fail $NOW x.sub.good.example ec_root.pem nc_dnsx_sub.pem,nc_dnsx.pem
cs ok_nc_sub_permitted ok $NOW x.other.good.example ec_root.pem nc_dnsx_oth.pem,nc_dnsx.pem
cs bad_nc_suffix_not_label fail $NOW notgood.example ec_root.pem nc_dnsx_sfx.pem,nc_dnsx.pem
issue nc_ip "NC ip" ec_root ec "$CA"'nameConstraints=critical,permitted;IP:192.0.2.0/255.255.255.0,excluded;IP:192.0.2.128/255.255.255.128\n'
issue nc_ip_ok "i" nc_ip ec "$SRV$(san IP:192.0.2.7)"
issue nc_ip_excl "i" nc_ip ec "$SRV$(san IP:192.0.2.200)"
issue nc_ip_out "i" nc_ip ec "$SRV$(san IP:198.51.100.1)"
issue nc_ip_v6 "i" nc_ip ec "$SRV$(san IP:2001:db8::1)"
cs ok_nc_ip_permitted ok $NOW 192.0.2.7 ec_root.pem nc_ip_ok.pem,nc_ip.pem
cs bad_nc_ip_excluded fail $NOW 192.0.2.200 ec_root.pem nc_ip_excl.pem,nc_ip.pem
cs bad_nc_ip_outside fail $NOW 198.51.100.1 ec_root.pem nc_ip_out.pem,nc_ip.pem
cs bad_nc_ip_v6_not_permitted fail $NOW 2001:db8::1 ec_root.pem nc_ip_v6.pem,nc_ip.pem
issue nc_mail "NC mail" ec_root ec "$CA"'nameConstraints=critical,permitted;email:good.example\n'
issue nc_mail_leaf "m" nc_mail ec "$SRV$(san DNS:www.example.com,email:a@bad.example)"
cs bad_nc_unsupported_type_used fail $NOW www.example.com ec_root.pem nc_mail_leaf.pem,nc_mail.pem
issue nc_mail_leaf2 "m" nc_mail ec "$SRV$(san DNS:www.example.com)"
cs ok_nc_unsupported_type_unused ok $NOW www.example.com ec_root.pem nc_mail_leaf2.pem,nc_mail.pem
# SHA-1 and other digests
issue ec_sha1 "s1" ec_inter ec "$SRV$(san DNS:sha1.example.com)" 36500 -sha1
cs bad_sha1_leaf fail $NOW sha1.example.com ec_root.pem ec_sha1.pem,ec_inter.pem
div bad_sha1_leaf "openssl security level decides; we always reject SHA-1 signatures"
issue ec_sha512 "s5" ec_inter ec "$SRV$(san DNS:sha512.example.com)" 36500 -sha512
issue ec_sha384 "s3" ec_inter ec "$SRV$(san DNS:sha384.example.com)" 36500 -sha384
cs ok_ecdsa_sha512 ok $NOW sha512.example.com ec_root.pem ec_sha512.pem,ec_inter.pem
cs ok_ecdsa_sha384_on_p256 ok $NOW sha384.example.com ec_root.pem ec_sha384.pem,ec_inter.pem
issue ec384_root "P384 Root" self ec384 "$CA" 36500 -sha384
issue ec384_inter "P384 Inter" ec384_root ec384 "$CA0" 36500 -sha384
issue ec384_leaf "l" ec384_inter ec384 "$SRV$(san DNS:p384.example.com)" 36500 -sha384
issue ec384_leaf_p256 "l" ec384_inter ec "$SRV$(san DNS:p384b.example.com)" 36500 -sha384
cs ok_p384_chain ok $NOW p384.example.com ec384_root.pem ec384_leaf.pem,ec384_inter.pem
cs ok_p384_signs_p256_leaf ok $NOW p384b.example.com ec384_root.pem ec384_leaf_p256.pem,ec384_inter.pem
# self-signed leaf as trust anchor
issue ss_leaf "ss" self ec "$SRV$(san DNS:ss.example.com)"
cs ok_selfsigned_trusted ok $NOW ss.example.com ss_leaf.pem ss_leaf.pem
cs bad_selfsigned_untrusted fail $NOW ss.example.com ec_root.pem ss_leaf.pem
# chain length cap (MAX_CHAIN = 40)
prev=ec_root
for i in $(seq 1 40); do issue ec_c$i "C$i" $prev ec "$CA"; prev=ec_c$i; done
issue ec_lc39 "l" ec_c39 ec "$SRV$(san DNS:long.example.com)"
issue ec_lc40 "l" ec_c40 ec "$SRV$(san DNS:long.example.com)"
c39=$(for i in $(seq 39 -1 1); do printf 'ec_c%s.pem,' $i; done)
c40=$(for i in $(seq 40 -1 1); do printf 'ec_c%s.pem,' $i; done)
cs ok_chain_40 ok $NOW long.example.com ec_root.pem "ec_lc39.pem,${c39%,}"
cs bad_chain_41 fail $NOW long.example.com ec_root.pem "ec_lc40.pem,${c40%,}"
div bad_chain_41 "openssl's default depth is 100; we cap chains at 40 certificates"
# self-issued intermediates (RFC 5280 6.1.4 l and 6.1.3 name constraints): subject == issuer, different key
issue ec_p1_si "Ip1" ec_inter_p1 ec "$CA"
issue ec_p1_si_b "Ip1si-b" ec_p1_si ec "$CA"
issue ec_leaf_si "lsi" ec_p1_si_b ec "$SRV$(san DNS:si.example.com)"
cs ok_selfissued_not_counted ok $NOW si.example.com ec_root.pem ec_leaf_si.pem,ec_p1_si_b.pem,ec_p1_si.pem,ec_inter_p1.pem
issue nc_dns_si "NC dns" nc_dns ec "$CA$(san DNS:evil.example)"
issue nc_dns_si_leaf "x" nc_dns_si ec "$SRV$(san DNS:www.good.example)"
cs ok_nc_skips_selfissued_intermediate ok $NOW www.good.example ec_root.pem nc_dns_si_leaf.pem,nc_dns_si.pem,nc_dns.pem
issue nc_dns_mal "NC mal" nc_dns ec "$CA$(san DNS:.good.example)"
issue nc_dns_mal_leaf "x" nc_dns_mal ec "$SRV$(san DNS:www.good.example)"
cs bad_nc_malformed_inter_san fail $NOW www.good.example ec_root.pem nc_dns_mal_leaf.pem,nc_dns_mal.pem,nc_dns.pem
div bad_nc_malformed_inter_san "openssl accepts a leading-dot dNSName SAN that satisfies the constraint textually"
# wildcard SAN against excluded subtrees (CVE-2025-61727 class)
issue nc_wild_x "NC wildx" ec_root ec "$CA"'nameConstraints=critical,permitted;DNS:example.net,excluded;DNS:bar.example.net\n'
issue nc_wild_p "NC wildp" ec_root ec "$CA"'nameConstraints=critical,permitted;DNS:example.net\n'
issue nc_wild_x_leaf "w" nc_wild_x ec "$SRV$(san DNS:*.example.net)"
issue nc_wild_p_leaf "w" nc_wild_p ec "$SRV$(san DNS:*.example.net)"
cs bad_nc_wildcard_covers_excluded fail $NOW foo.example.net ec_root.pem nc_wild_x_leaf.pem,nc_wild_x.pem
div bad_nc_wildcard_covers_excluded "openssl compares the wildcard SAN literally against the excluded name"
cs ok_nc_wildcard_permitted ok $NOW foo.example.net ec_root.pem nc_wild_p_leaf.pem,nc_wild_p.pem
issue nc_dns_leaf_dot "d" nc_dns ec "$SRV$(san DNS:.good.example,DNS:www.good.example)"
cs bad_nc_malformed_san fail $NOW www.good.example ec_root.pem nc_dns_leaf_dot.pem,nc_dns.pem
div bad_nc_malformed_san "openssl accepts a leading-dot dNSName SAN that satisfies the constraint textually"
# key usage and key size consistency
issue ec_leaf_cadig "k" ec_inter ec "basicConstraints=CA:TRUE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n$(san DNS:cadig.example.com)"
cs bad_ca_leaf_without_keycertsign fail $NOW cadig.example.com ec_root.pem ec_leaf_cadig.pem,ec_inter.pem
div bad_ca_leaf_without_keycertsign "openssl verify does not cross-check keyCertSign against basicConstraints on a leaf"
issue ec_leaf_ksnoca "k" ec_inter ec "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyCertSign\nextendedKeyUsage=serverAuth\n$(san DNS:ksnoca.example.com)"
cs bad_keycertsign_without_ca fail $NOW ksnoca.example.com ec_root.pem ec_leaf_ksnoca.pem,ec_inter.pem
div bad_keycertsign_without_ca "openssl verify does not cross-check keyCertSign against basicConstraints on a leaf"
issue rsa1024_leaf2 "l" ec_inter rsa1024 "$SRV$(san DNS:weak.example.com)"
cs bad_rsa_1024_leaf fail $NOW weak.example.com ec_root.pem rsa1024_leaf2.pem,ec_inter.pem
div bad_rsa_1024_leaf "openssl security level 1 accepts a 1024-bit leaf key; CA/B BR 6.1.5 and browsers do not"

# --- RSA family
issue rsa_root "RSA Root" self rsa "$CA" 36500 -sha256
issue rsa_inter "RSA Inter" rsa_root rsa "$CA0" 36500 -sha256
issue rsa_leaf "l" rsa_inter rsa "$SRV$(san DNS:rsa.example.com)" 36500 -sha256
issue rsa_leaf_ec "l" rsa_inter ec "$SRV$(san DNS:rsaec.example.com)" 36500 -sha384
cs ok_rsa_chain ok $NOW rsa.example.com rsa_root.pem rsa_leaf.pem,rsa_inter.pem
cs ok_rsa_signs_ec_leaf_sha384 ok $NOW rsaec.example.com rsa_root.pem rsa_leaf_ec.pem,rsa_inter.pem
issue rsa_leaf_512 "l" rsa_inter ec "$SRV$(san DNS:rsa512.example.com)" 36500 -sha512
cs ok_rsa_sha512 ok $NOW rsa512.example.com rsa_root.pem rsa_leaf_512.pem,rsa_inter.pem
issue rsa_leaf_pss32 "l" rsa_inter ec "$SRV$(san DNS:pss32.example.com)" 36500 -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32
issue rsa_leaf_pss20 "l" rsa_inter ec "$SRV$(san DNS:pss20.example.com)" 36500 -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20
issue rsa_leaf_pss48 "l" rsa_inter ec "$SRV$(san DNS:pss48.example.com)" 36500 -sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:48
cs ok_rsa_pss_salt32 ok $NOW pss32.example.com rsa_root.pem rsa_leaf_pss32.pem,rsa_inter.pem
cs ok_rsa_pss_salt20 ok $NOW pss20.example.com rsa_root.pem rsa_leaf_pss20.pem,rsa_inter.pem
cs ok_rsa_pss_sha384 ok $NOW pss48.example.com rsa_root.pem rsa_leaf_pss48.pem,rsa_inter.pem
issue rsa_sha1_inter "RSA Inter1" rsa_root rsa "$CA" 36500 -sha1
issue rsa_sha1_leaf "l" rsa_sha1_inter ec "$SRV$(san DNS:rsa1.example.com)" 36500 -sha256
cs bad_rsa_sha1_inter fail $NOW rsa1.example.com rsa_root.pem rsa_sha1_leaf.pem,rsa_sha1_inter.pem
div bad_rsa_sha1_inter "openssl security level decides; we always reject SHA-1 signatures"
issue rsa1024_root "RSA1024 Root" self rsa1024 "$CA" 36500 -sha256
issue rsa1024_leaf "l" rsa1024_root ec "$SRV$(san DNS:small.example.com)" 36500 -sha256
cs bad_rsa_1024_issuer fail $NOW small.example.com rsa1024_root.pem rsa1024_leaf.pem
div bad_rsa_1024_issuer "openssl security level 1 accepts 1024-bit RSA; browsers and CA/B BR 6.1.5 do not"
# a tampered certificate: flip a byte of the signature
openssl x509 -in ec_leaf.pem -outform DER -out tampered.der
off=$(( $(stat -c %s tampered.der) - 5 ))
byte=$(od -An -tu1 -j$off -N1 tampered.der)
printf "\\x$(printf %02x $((byte ^ 1)))" | dd of=tampered.der bs=1 seek=$off conv=notrunc 2>/dev/null
{ echo '-----BEGIN CERTIFICATE-----'; base64 -w64 tampered.der; echo '-----END CERTIFICATE-----'; } > tampered.pem
rm -f tampered.der
cs bad_tampered_signature fail $NOW a.example.com ec_root.pem tampered.pem,ec_inter.pem

# --- private keys
rm -f key_*.pem
openssl genpkey $EC -out key_ec_pkcs8.pem 2>/dev/null
openssl ec -in key_ec_pkcs8.pem -out key_ec_sec1.pem 2>/dev/null
openssl ec -in key_ec_pkcs8.pem -no_public -out key_ec_sec1_nopub.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out key_ec_sec1_noparams.pem 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key_rsa_pkcs8.pem 2>/dev/null
openssl rsa -in key_rsa_pkcs8.pem -traditional -out key_rsa_pkcs1.pem 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out key_rsa3072_pkcs8.pem 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out key_rsa1024_pkcs8.pem 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out key_ec384_pkcs8.pem 2>/dev/null
openssl genpkey -algorithm ED25519 -out key_ed25519_pkcs8.pem 2>/dev/null
openssl genpkey $EC -aes-128-cbc -pass pass:x -out key_ec_encrypted.pem 2>/dev/null
openssl ec -in key_ec_pkcs8.pem -aes128 -passout pass:x -out key_ec_sec1_encrypted.pem 2>/dev/null
openssl rsa -in key_rsa_pkcs8.pem -traditional -aes128 -passout pass:x -out key_rsa_pkcs1_encrypted.pem 2>/dev/null
openssl req -new -x509 -key key_ec_pkcs8.pem -subj /CN=key-ec -days 36500 -out cert_key_ec.pem
openssl req -new -x509 -key key_rsa_pkcs8.pem -subj /CN=key-rsa -days 36500 -out cert_key_rsa.pem
# key_cases.txt (name expect file cert) is hand-written and kept
echo "generated at $G (now column = G + 3600)"
