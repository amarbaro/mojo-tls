# Bench (one resident process): record seal/open throughput per suite on 16 KiB records, and complete in-memory
# handshakes per second (client + server state machines, x25519, fixed-signature signer, so the ECDSA/RSA cost of
# lane 2 is not in the number). usage: bench_tls13 [records] [handshakes]
from std.sys import argv
from std.time import perf_counter_ns
from tls.asym import x25519_base
from tls.tls13.client import Client13, default_hello
from tls.tls13.conn import EV_DONE
from tls.tls13.record import Cipher, APP
from tls.tls13.server import Server13, ServerConfig
from rec import RecSigner, RecVerifier


def fill(n: Int, b: Int) -> List[UInt8]:
    return List[UInt8](length=n, fill=UInt8(b))


def records(suite: Int, klen: Int, n: Int) raises:
    """Best of 7 rounds: the machine is shared, the fastest round is the least disturbed."""
    var key = fill(klen, 7)
    var iv = fill(12, 9)
    var s = Cipher()
    s.set(suite, key, iv)
    var o = Cipher()
    o.set(suite, key, iv)
    var data = fill(16384, 0x5A)
    var out = List[UInt8](capacity=16384 + 64)
    s.seal(APP, data, 0, 16384, out)
    var best_seal = Int.MAX
    var best_open = Int.MAX
    for _ in range(7):
        var t0 = perf_counter_ns()
        for _ in range(n):
            out.clear()
            s.seal(APP, data, 0, 16384, out)
        best_seal = min(best_seal, perf_counter_ns() - t0)
        out.clear()
        s.seq = 0
        s.seal(APP, data, 0, 16384, out)
        var t2 = perf_counter_ns()
        for _ in range(n):
            o.seq = 0
            _ = o.open(out)
        best_open = min(best_open, perf_counter_ns() - t2)
    var mb = Float64(n) * 16384.0 / 1e6
    print(
        "suite " + hex(suite) + ": seal " + String(Int(mb / (Float64(best_seal) / 1e9))) + " MB/s ("
        + String(Int(best_seal / n)) + " ns per 16 KiB record), open " + String(Int(mb / (Float64(best_open) / 1e9)))
        + " MB/s (" + String(Int(best_open / n)) + " ns)"
    )


def handshakes(suite: Int, n: Int) raises:
    var chain = List[List[UInt8]]()
    chain.append(fill(300, 0x30))
    var best = Int.MAX
    var ok = 0
    for _ in range(5):
        var t0 = perf_counter_ns()
        ok = one_round(suite, n // 5, chain)
        best = min(best, perf_counter_ns() - t0)
    var m = n // 5
    print("suite " + hex(suite) + ": " + String(ok) + "/" + String(m) + " handshakes per round, best of 5: " + String(Int(Float64(m) / (Float64(best) / 1e9))) + " per second (" + String(Int(best / m / 1000)) + " us each, client and server)")


def one_round(suite: Int, n: Int, chain: List[List[UInt8]]) raises -> Int:
    var ok = 0
    for _ in range(n):
        var cfg = ServerConfig(fill(32, 0x77), fill(32, 0x21), fill(32, 0x12))
        cfg.suites = [suite]
        var srv = Server13[RecSigner](cfg^, RecSigner(chain, fill(64, 0x55), 0x0403, List[UInt8]()))
        var h = default_hello("example.com", fill(32, 0x99), fill(32, 0x31), x25519_base(fill(32, 0x42)), List[String]())
        var cli = Client13[RecVerifier](h, "example.com", fill(32, 0x42), fill(32, 0x13), RecVerifier(chain, fill(64, 0x55), 0x0403, List[UInt8](), "example.com"))
        var so = srv.feed(Span(cli.start()))
        var co = cli.feed(Span(so.send))
        var sd = srv.feed(Span(co.send))
        if co.has(EV_DONE) and sd.has(EV_DONE):
            ok += 1
    return ok


def x25519_rate(n: Int) raises:
    var k = fill(32, 0x42)
    var best = Int.MAX
    for _ in range(5):
        var t0 = perf_counter_ns()
        for _ in range(n):
            k = x25519_base(k)
        best = min(best, perf_counter_ns() - t0)
    print("x25519, best of 5: " + String(Int(Float64(n) / (Float64(best) / 1e9))) + " scalar mults per second (" + String(Int(best / n / 1000)) + " us each)")


def main() raises:
    var a = argv()
    var n = atol(String(a[1])) if len(a) > 1 else 2000
    var hs = atol(String(a[2])) if len(a) > 2 else 300
    x25519_rate(100)
    records(0x1301, 16, n)
    records(0x1302, 32, n)
    records(0x1303, 32, n)
    handshakes(0x1301, hs)
    handshakes(0x1302, hs)
    handshakes(0x1303, hs)
