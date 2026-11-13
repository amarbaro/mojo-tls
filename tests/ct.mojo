# dudect-style timing check (Reparaz, Balasch, Verbauwhede 2017): fixed vs random secret input, classes interleaved at random,
# Welch t-test on the raw times and on the fastest 98/95/90/80% (crops against scheduler noise). Max |t| > 4.5 = leak suspected.
# usage: ct <samples-per-primitive> [n e p q dp dq qinv]   (RSA rows need the private key parts in hex)
from std.sys import argv
from std.time import perf_counter_ns
from std.math import sqrt
from tls.asym import *
from tls.asym.ec import unhex, from_be, ecdh, p256
from tls.asym.sha2 import sha2


def welch(t: List[Float64], cls: List[Int], cut: Float64) -> Float64:
    var n = List[Float64](length=2, fill=0.0)
    var mean = List[Float64](length=2, fill=0.0)
    var m2 = List[Float64](length=2, fill=0.0)
    for i in range(len(t)):
        if t[i] <= cut:
            var c = cls[i]
            n[c] += 1.0
            var d = t[i] - mean[c]
            mean[c] += d / n[c]
            m2[c] += d * (t[i] - mean[c])
    var den = sqrt(m2[0] / (n[0] - 1.0) / n[0] + m2[1] / (n[1] - 1.0) / n[1])
    return (mean[0] - mean[1]) / den


def report(name: String, t: List[Float64], cls: List[Int]) -> Bool:
    var sorted = t.copy()
    sort(sorted)
    var worst = 0.0
    var out = name + ": |t| ="
    for pct in [100, 98, 95, 90, 80]:
        var cut = sorted[(len(sorted) - 1) * pct // 100]
        var v = welch(t, cls, cut)
        if v < 0.0:
            v = -v
        out += " " + String(Float64(Int(v * 100)) / 100.0) + "(" + String(pct) + "%)"
        if v > worst:
            worst = v
    var ok = worst < 4.5
    print(("PASS ct " if ok else "FAIL ct ") + out + "  max " + String(Float64(Int(worst * 100)) / 100.0))
    return ok


def classes(n: Int) raises -> List[Int]:
    var r = random_bytes(n)
    var c = List[Int]()
    for i in range(n):
        c.append(Int(r[i] & 1))
    return c^


def main() raises:
    var a = List[String]()
    for v in argv():
        a.append(String(v))
    var n = Int(a[1])
    var good = True
    var cls = classes(n)
    var t = List[Float64]()
    # X25519: scalar all-zero (clamps to a single set bit) vs random
    var base = x25519_base(random_bytes(32))
    var zero = List[UInt8](length=32, fill=0)
    for i in range(n):
        var k = zero.copy() if cls[i] == 0 else random_bytes(32)
        var t0 = perf_counter_ns()
        _ = x25519(k, base)
        t.append(Float64(perf_counter_ns() - t0))
    good = report("x25519 scalar", t, cls) and good
    # X448: scalar all-zero (clamps to two set bits) vs random
    var base4 = x448_base(random_bytes(56))
    var zero4 = List[UInt8](length=56, fill=0)
    cls = classes(n)
    t = List[Float64]()
    for i in range(n):
        var k = zero4.copy() if cls[i] == 0 else random_bytes(56)
        var t0 = perf_counter_ns()
        _ = x448(k, base4)
        t.append(Float64(perf_counter_ns() - t0))
    good = report("x448 scalar", t, cls) and good
    # P-256 scalar mult (ECDH core): scalar 1 vs random
    var peer = P256Key.generate().public_bytes()
    cls = classes(n)
    t = List[Float64]()
    var c = p256()
    for i in range(n):
        var k = from_be[4](unhex("00" * 31 + "01") if cls[i] == 0 else unhex("7f") + random_bytes(31))
        var t0 = perf_counter_ns()
        _ = ecdh(k, peer, c)
        t.append(Float64(perf_counter_ns() - t0))
    good = report("p256 scalar mult", t, cls) and good
    # ECDSA sign: fixed key, message hash fixed vs random (the RFC 6979 nonce follows the hash)
    var key = P256Key.generate()
    var fixed = sha2(256, "fixed".as_bytes())
    cls = classes(n)
    t = List[Float64]()
    for i in range(n):
        var h = fixed.copy() if cls[i] == 0 else sha2(256, random_bytes(16))
        var t0 = perf_counter_ns()
        _ = key.sign_sha256(h)
        t.append(Float64(perf_counter_ns() - t0))
    good = report("p256 ecdsa sign", t, cls) and good
    if len(a) == 9:
        var rk = RsaPrivate(unhex(a[2]), unhex(a[3]), unhex(a[4]), unhex(a[5]), unhex(a[6]), unhex(a[7]), unhex(a[8]))
        var m = n // 4
        cls = classes(m)
        t = List[Float64]()
        for i in range(m):
            var h = fixed.copy() if cls[i] == 0 else sha2(256, random_bytes(16))
            var t0 = perf_counter_ns()
            _ = rk.sign_pss(256, h)
            t.append(Float64(perf_counter_ns() - t0))
        good = report("rsa pss sign (CRT)", t, cls) and good
    if not good:
        raise Error("ct: leak suspected")
