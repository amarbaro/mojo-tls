# Heap profile workload (run it under `heaptide run`): N full TLS 1.3 handshakes, each followed by 1 MiB of application
# data from the client and 1 MiB back, client and server engines in one process (sans-IO, fixed-signature signer, so the
# ECDSA/RSA cost is not here). Prints the bytes that crossed and exits 1 when any byte went missing.
# usage: heap_xfer [handshakes [bytes each way, default 1 MiB]]
from std.sys import argv
from tls.asym import x25519_base
from tls.tls13.client import Client13, default_hello
from tls.tls13.conn import EV_DONE
from tls.tls13.server import Server13, ServerConfig
from rec import RecSigner, RecVerifier


def fill(n: Int, b: Int) -> List[UInt8]:
    return List[UInt8](length=n, fill=UInt8(b))


def main() raises:
    var a = argv()
    var n = Int(String(a[1])) if len(a) > 1 else 20
    var chain = List[List[UInt8]]()
    chain.append(fill(300, 0x30))
    var up = 0
    var down = 0
    var size = Int(String(a[2])) if len(a) > 2 else (1 << 20)
    var mib = fill(size, 0x5A)
    for _ in range(n):
        var cfg = ServerConfig(fill(32, 0x77), fill(32, 0x21), fill(32, 0x12))
        var srv = Server13[RecSigner](cfg^, RecSigner(chain, fill(64, 0x55), 0x0403, List[UInt8]()))
        var h = default_hello("example.com", fill(32, 0x99), fill(32, 0x31), x25519_base(fill(32, 0x42)), List[String]())
        var cli = Client13[RecVerifier](h, "example.com", fill(32, 0x42), fill(32, 0x13), RecVerifier(chain, fill(64, 0x55), 0x0403, List[UInt8](), "example.com"))
        var so = srv.feed(Span(cli.start()))
        var co = cli.feed(Span(so.send))
        var sd = srv.feed(Span(co.send))
        if not (co.has(EV_DONE) and sd.has(EV_DONE)):
            raise Error("handshake did not finish")
        var w1 = cli.write(mib)
        var d1 = srv.feed(Span(w1))
        up += len(d1.data)
        var w2 = srv.write(mib)
        var d2 = cli.feed(Span(w2))
        down += len(d2.data)
    print("handshakes", n, "up", up, "down", down)
    if up != n * size or down != n * size:
        raise Error("FAIL: data lost")
