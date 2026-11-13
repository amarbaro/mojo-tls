#!/usr/bin/env python3
"""Wycheproof JSON -> one flat case file for tests/vectors.mojo (oracle side only, never imported by the library).
usage: wyc2cases.py <wycheproof/testvectors_v1> <out.txt>
line: kind|tcid|result|hex fields...   result in valid/invalid/acceptable"""
import hashlib, json, sys

src, out = sys.argv[1], sys.argv[2]
H = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
lines = []


def load(name):
    return json.load(open(f"{src}/{name}"))


def be(h, n):
    """hex integer (possibly with sign byte or odd length) -> n bytes big-endian"""
    v = int(h, 16) if h else 0
    return v.to_bytes(max(n, (v.bit_length() + 7) // 8), "big").hex()


for g in load("x25519_test.json")["testGroups"]:
    for t in g["tests"]:
        lines.append(f"x25519|{t['tcId']}|{t['result']}|{t['private']}|{t['public']}|{t['shared']}")

for g in load("x448_test.json")["testGroups"]:
    for t in g["tests"]:
        lines.append(f"x448|{t['tcId']}|{t['result']}|{t['private']}|{t['public']}|{t['shared']}")

for kind, name, n in (("ecdh", "ecdh_secp256r1_ecpoint_test.json", 32), ("ecdh384", "ecdh_secp384r1_ecpoint_test.json", 48)):
    for g in load(name)["testGroups"]:
        for t in g["tests"]:
            lines.append(f"{kind}|{t['tcId']}|{t['result']}|{be(t['private'], n)}|{t['public']}|{t['shared']}")

for name, bits in (("ecdsa_secp256r1_sha256_test.json", 256), ("ecdsa_secp384r1_sha384_test.json", 384)):
    for g in load(name)["testGroups"]:
        h = H[g["sha"]]
        for t in g["tests"]:
            d = h(bytes.fromhex(t["msg"])).hexdigest()
            lines.append(f"ecdsa|{t['tcId']}|{t['result']}|{bits}|{g['publicKey']['uncompressed']}|{d}|{t['sig']}")

for bits in (2048, 3072, 4096):
    for sha in (256, 384, 512):
        try:
            d = load(f"rsa_signature_{bits}_sha{sha}_test.json")
        except FileNotFoundError:
            continue
        for g in d["testGroups"]:
            h = H[g["sha"]]
            for t in g["tests"]:
                dg = h(bytes.fromhex(t["msg"])).hexdigest()
                lines.append(f"rsa_pkcs1|{t['tcId']}|{t['result']}|{sha}|{g['publicKey']['modulus']}|{g['publicKey']['publicExponent']}|{dg}|{t['sig']}")

for name in ("rsa_pss_2048_sha256_mgf1_32_test.json", "rsa_pss_3072_sha256_mgf1_32_test.json", "rsa_pss_4096_sha256_mgf1_32_test.json",
             "rsa_pss_2048_sha384_mgf1_48_test.json", "rsa_pss_4096_sha384_mgf1_48_test.json", "rsa_pss_4096_sha512_mgf1_64_test.json"):
    d = load(name)
    for g in d["testGroups"]:
        h = H[g["sha"]]
        sha = int(g["sha"].split("-")[1])
        assert g["mgfSha"] == g["sha"] and g["sLen"] == sha // 8, name
        for t in g["tests"]:
            dg = h(bytes.fromhex(t["msg"])).hexdigest()
            lines.append(f"rsa_pss|{t['tcId']}|{t['result']}|{sha}|{g['publicKey']['modulus']}|{g['publicKey']['publicExponent']}|{dg}|{t['sig']}")

open(out, "w").write("\n".join(lines) + "\n")
print(f"{len(lines)} cases -> {out}")
