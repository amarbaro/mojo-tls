#!/usr/bin/env python3
# Test tool, not part of the library: turns x509-limbo's limbo.json into one line per case for `x509_gate limbo`.
# Fetch: tools/limbo_fetch.sh   Run: python3 -I tools/limbo_convert.py .work/limbo/limbo.json .work/limbo/cases.txt NOW
# Line: id expect now host trusted_b64,.. chain_b64,..   (chain = peer certificate first, then untrusted intermediates)
# Cases a TLS server-auth verifier is not asked to decide are skipped and counted: client validation, CRLs, online,
# restricted signature algorithms, custom key usages, depth limits, no peer name.
import json, sys, collections

src, dst, now = sys.argv[1], sys.argv[2], sys.argv[3]
cases = json.load(open(src))['testcases']
skipped = collections.Counter()
n = 0


def b64(pem):
    return ''.join(l for l in pem.strip().splitlines() if not l.startswith('-----'))


with open(dst, 'w') as out:
    for t in cases:
        if t['validation_kind'] != 'SERVER':
            skipped['client'] += 1
        elif t['crls']:
            skipped['crl'] += 1
        elif t['id'].startswith('online::'):
            skipped['online'] += 1
        elif t['signature_algorithms']:
            skipped['signature_algorithms'] += 1
        elif t['key_usage'] or t['extended_key_usage']:
            skipped['key_usage'] += 1
        elif t['max_chain_depth'] is not None:
            skipped['max_chain_depth'] += 1
        elif not t.get('expected_peer_name') or t['expected_peer_name']['kind'] not in ('DNS', 'IP'):
            skipped['peer_name'] += 1
        else:
            host = t['expected_peer_name']['value']
            tm = int(now)
            if t['validation_time']:
                import datetime
                tm = int(datetime.datetime.fromisoformat(t['validation_time'].replace('Z', '+00:00')).timestamp())
            roots = ','.join(b64(p) for p in t['trusted_certs'])
            chain = ','.join(b64(p) for p in [t['peer_certificate']] + t['untrusted_intermediates'])
            out.write('%s %s %d %s %s %s\n' % (t['id'], 'ok' if t['expected_result'] == 'SUCCESS' else 'fail', tm, host or '-', roots, chain))
            n += 1
print('limbo: %d cases written, skipped %s' % (n, dict(skipped)))
