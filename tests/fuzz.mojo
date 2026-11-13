# Parser fuzz for every peer-controlled input of tls.asym: mutate valid (key, hash, signature) triples and feed random bytes.
# Never crashes or hangs, never accepts a mutation. usage: fuzz <cases.txt from tools/wyc2cases.py>
from std.sys import argv
from tls.asym import *
from tls.asym.ec import unhex
from tls.asym.sha2 import sha2


def find(path: String, kind: String, sha: String) raises -> List[String]:
    """Fields (after the result) of the first valid case of this kind whose first field is `sha`; RSA: 2048-bit only."""
    for line in open(path, "r").read().split("\n"):
        var f = List[String]()
        for p in line.split("|"):
            f.append(String(p))
        if len(f) > 4 and f[0] == kind and f[2] == "valid" and f[3] == sha and (kind == "ecdsa" or f[4].byte_length() == 514):
            return List[String](f[4:])
    raise Error("fuzz: no valid " + kind + " case")


def strip0(b: List[UInt8]) -> List[UInt8]:
    var i = 0
    while i < len(b) - 1 and b[i] == 0:
        i += 1
    return List[UInt8](Span(b)[i:])


def noisy(n: Int) raises -> List[UInt8]:
    var r = random_bytes(n)
    if n > 2 and r[0] & 1 == 0:
        r[0] = 0x30  # often a plausible DER SEQUENCE header, so the parser goes deeper
        r[1] = UInt8(n - 2)
    return r^


def rsa_ok(pss: Bool, pk: RsaPublic, h: List[UInt8], s: List[UInt8]) -> Bool:
    return pk.verify_pss(256, h, s) if pss else pk.verify_pkcs1(256, h, s)


def report(name: String, runs: Int, accepted: Int) -> Int:
    print(("PASS" if accepted == 0 else "FAIL") + " fuzz " + name + ": " + String(runs) + " inputs, " + String(accepted) + " accepted")
    return accepted


def main() raises:
    var path = String(argv()[1])
    var bad = 0
    # P-256: every byte of a valid signature flipped three ways, every public key byte flipped, every truncation and extension
    var key = P256Key.generate()
    var h = sha2(256, "fuzz".as_bytes())
    var sig = key.sign_sha256(h)
    var pub = key.public_bytes()
    var runs = 0
    var acc = 0
    for i in range(len(sig)):
        for m in [1, 0x80, 0xFF]:
            var s = sig.copy()
            s[i] ^= UInt8(m)
            runs += 1
            acc += 1 if p256_verify(pub, h, s) else 0
    for i in range(len(pub)):
        var p = pub.copy()
        p[i] ^= 1
        runs += 1
        acc += 1 if p256_verify(p, h, sig) else 0
    for n in range(len(sig) + 4):
        var s = List[UInt8](Span(sig)[: min(n, len(sig))])
        while len(s) < n:
            s.append(0)
        runs += 1
        acc += 1 if (n != len(sig) and p256_verify(pub, h, s)) else 0
    bad += report("p256 verify mutations", runs, acc)
    # P-384, from a Wycheproof valid case
    var f = find(path, "ecdsa", "384")
    var p384pub = unhex(f[0])
    var p384h = unhex(f[1])
    var p384sig = unhex(f[2])
    if not p384_verify(p384pub, p384h, p384sig):
        raise Error("fuzz: p384 base case does not verify")
    runs = 0
    acc = 0
    for i in range(len(p384sig)):
        var s = p384sig.copy()
        s[i] ^= 1
        runs += 1
        acc += 1 if p384_verify(p384pub, p384h, s) else 0
    for i in range(len(p384pub)):
        var p = p384pub.copy()
        p[i] ^= 1
        runs += 1
        acc += 1 if p384_verify(p, p384h, p384sig) else 0
    bad += report("p384 verify mutations", runs, acc)
    # random garbage of random length: neither crash nor accept
    runs = 0
    acc = 0
    for _ in range(3000):
        var g = noisy(Int(random_bytes(1)[0]) % 101)
        var pk = noisy(Int(random_bytes(1)[0]) % 100)
        runs += 4
        acc += 1 if (p256_verify(pub, h, g) or p256_verify(pk, h, sig) or p384_verify(p384pub, p384h, g) or p384_verify(pk, p384h, p384sig)) else 0
    bad += report("ec garbage", runs, acc)
    # RSA-2048: PSS and PKCS#1 valid cases, every byte flipped two ways, odd lengths, random signatures
    runs = 0
    acc = 0
    for pss in [True, False]:
        var c = find(path, "rsa_pss" if pss else "rsa_pkcs1", "256")
        var pk = RsaPublic(strip0(unhex(c[0])), strip0(unhex(c[1])))
        var rh = unhex(c[2])
        var rs = unhex(c[3])
        if not rsa_ok(pss, pk, rh, rs):
            raise Error("fuzz: rsa base case does not verify")
        for i in range(len(rs)):
            for m in [1, 0x80]:
                var s = rs.copy()
                s[i] ^= UInt8(m)
                runs += 1
                acc += 1 if rsa_ok(pss, pk, rh, s) else 0
        for n in [0, 1, 255, 257, 300]:
            var s = List[UInt8](Span(rs)[: min(n, len(rs))])
            while len(s) < n:
                s.append(1)
            runs += 1
            acc += 1 if rsa_ok(pss, pk, rh, s) else 0
        for z in [1, 44]:  # the valid signature behind zero bytes: same number, wrong length (RFC 8017 8.2.2 step 1)
            var s = List[UInt8](length=z, fill=0)
            s.extend(Span(rs))
            runs += 1
            acc += 1 if rsa_ok(pss, pk, rh, s) else 0
        for _ in range(200):
            runs += 1
            acc += 1 if rsa_ok(pss, pk, rh, random_bytes(256)) else 0
    bad += report("rsa verify mutations", runs, acc)
    if bad > 0:
        raise Error("fuzz: mutation accepted")
