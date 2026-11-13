# Speed of tls.asym in one resident process: median of 7 batches, microseconds per operation.
# usage: bench [n e p q dp dq qinv]   (RSA private key parts in hex; RSA rows are skipped without them)
from std.sys import argv
from std.time import perf_counter_ns
from tls.asym import *
from tls.asym.ec import unhex
from tls.asym.sha2 import sha2


def med(mut v: List[Float64]) -> Float64:
    sort(v)
    return v[len(v) // 2]


def row(name: String, mut v: List[Float64]):
    var m = med(v)
    print(name + ": " + String(Float64(Int(m * 10)) / 10.0) + " us, " + String(Int(1e6 / m)) + " ops/s")


def main() raises:
    var key = P256Key.generate()
    var peer = P256Key.generate().public_bytes()
    var h = sha2(256, "bench".as_bytes())
    var sig = key.sign_sha256(h)
    var pub = key.public_bytes()
    var k32 = random_bytes(32)
    var u = x25519_base(random_bytes(32))
    var k384 = unhex("04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
    var s384 = unhex("3065023100" + "e1" * 48 + "02304c" + "00" * 47)  # a well-formed but invalid signature: times the full verify path
    var h384 = sha2(384, "bench".as_bytes())
    var t = List[Float64]()
    var x = x25519(k32, u)
    for _ in range(7):
        var t0 = perf_counter_ns()
        for _ in range(30):
            _ = x25519(k32, u)
        t.append(Float64(perf_counter_ns() - t0) / 30000.0)
    row("x25519 scalar mult", t)
    t = List[Float64]()
    for _ in range(7):
        var t0 = perf_counter_ns()
        for _ in range(30):
            _ = key.sign_sha256(h)
        t.append(Float64(perf_counter_ns() - t0) / 30000.0)
    row("p256 ecdsa sign", t)
    t = List[Float64]()
    for _ in range(7):
        var t0 = perf_counter_ns()
        for _ in range(30):
            _ = p256_verify(pub, h, sig)
        t.append(Float64(perf_counter_ns() - t0) / 30000.0)
    row("p256 ecdsa verify", t)
    t = List[Float64]()
    for _ in range(7):
        var t0 = perf_counter_ns()
        for _ in range(30):
            _ = key.ecdh(peer)
        t.append(Float64(perf_counter_ns() - t0) / 30000.0)
    row("p256 ecdh", t)
    t = List[Float64]()
    for _ in range(7):
        var t0 = perf_counter_ns()
        for _ in range(10):
            _ = p384_verify(k384, h384, s384)
        t.append(Float64(perf_counter_ns() - t0) / 10000.0)
    row("p384 verify (full path, signature rejected at the end)", t)
    var a = List[String]()
    for v in argv():
        a.append(String(v))
    if len(a) == 8:
        var rk = RsaPrivate(unhex(a[1]), unhex(a[2]), unhex(a[3]), unhex(a[4]), unhex(a[5]), unhex(a[6]), unhex(a[7]))
        var rp = rk.public()
        var hh = sha2(256, "bench".as_bytes())
        var rs = rk.sign_pss(256, hh)
        t = List[Float64]()
        for _ in range(7):
            var t0 = perf_counter_ns()
            for _ in range(5):
                _ = rk.sign_pss(256, hh)
            t.append(Float64(perf_counter_ns() - t0) / 5000.0)
        row("rsa pss sign (CRT, blinded, fault-checked)", t)
        t = List[Float64]()
        for _ in range(7):
            var t0 = perf_counter_ns()
            for _ in range(30):
                _ = rp.verify_pss(256, hh, rs)
            t.append(Float64(perf_counter_ns() - t0) / 30000.0)
        row("rsa pss verify", t)
