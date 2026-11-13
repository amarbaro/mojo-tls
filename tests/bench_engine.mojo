"""bench_engine: what the sans-IO engines cost on top of crypto. NullCrypto does no work (hash and PRF return
zeros, seal/open only add or check the 16 tag bytes), so the numbers are framing, parsing, key plumbing, buffer
copies and allocation only: an upper bound on handshakes/s per core and on record MB/s without the cipher.
Run from the repo root: bench_engine [handshakes] [MiB per round]."""
from std.sys import argv
from std.time import perf_counter_ns
from std.memory import ArcPointer
from tls.net.config import TlsConfig, CertEntry
from tls.tls12.client import Client12
from tls.tls12.crypto import Crypto12, K_P256
from tls.tls12.server import Server12
from tls.tls12.wire import bytes_of


struct NullCrypto(Crypto12):
    def __init__(out self):
        pass

    def random(self, n: Int) raises -> List[UInt8]:
        return List[UInt8](length=n, fill=7)

    def hash(self, sha384: Bool, data: List[UInt8]) -> List[UInt8]:
        return List[UInt8](length=48 if sha384 else 32, fill=1)

    def prf(self, sha384: Bool, secret: List[UInt8], label: String, seed: List[UInt8], n: Int) -> List[UInt8]:
        return List[UInt8](length=n, fill=2)

    def keygen(self, group: Int) raises -> Tuple[List[UInt8], List[UInt8]]:
        return (List[UInt8](length=32, fill=3), List[UInt8](length=32 if group == 0x1D else 65, fill=4))

    def ecdh(self, group: Int, secret: List[UInt8], peer: List[UInt8]) raises -> List[UInt8]:
        return List[UInt8](length=32, fill=5)

    def sign(self, kind: Int, key_der: List[UInt8], scheme: Int, msg: List[UInt8]) raises -> List[UInt8]:
        return List[UInt8](length=64, fill=6)

    def verify(self, chain: List[List[UInt8]], host: String, scheme: Int, msg: List[UInt8], sig: List[UInt8]) raises:
        pass

    def seal(self, aead: Int, key: List[UInt8], nonce: List[UInt8], aad: List[UInt8], mut buf: List[UInt8], start: Int) raises:
        for _ in range(16):
            buf.append(0)

    def open(self, aead: Int, key: List[UInt8], nonce: List[UInt8], aad: List[UInt8], mut buf: List[UInt8], start: Int, end: Int) raises:
        pass


def main() raises:
    var a = argv()
    var n = Int(a[1]) if len(a) > 1 else 20000
    var mib = Int(a[2]) if len(a) > 2 else 64
    var c = TlsConfig()
    var chain = List[List[UInt8]]()
    chain.append(bytes_of("cert"))
    c.certs.append(CertEntry(["localhost"], chain^, bytes_of("key"), K_P256))
    c.alpn = ["http/1.1"]
    var cfg = ArcPointer(c^)
    var best = 1 << 62
    for _ in range(5):
        var t0 = Int(perf_counter_ns())
        for _ in range(n):
            var cl = Client12[NullCrypto]("localhost", ["http/1.1"])
            cl.start()
            var sv = Server12[NullCrypto](cfg)
            for _ in range(8):
                var x = cl.cn.take_output()
                var y = sv.cn.take_output()
                if len(x) == 0 and len(y) == 0:
                    break
                if len(x) > 0:
                    sv.feed(x)
                if len(y) > 0:
                    cl.feed(y)
            if not (cl.cn.established and sv.cn.established):
                raise Error("FAIL handshake did not complete")
        best = min(best, Int(perf_counter_ns()) - t0)
    print("handshake engine overhead (both sides, no crypto):", String(best // n // 1000) + "." + String(best // n % 1000 // 100), "us =", n * 1_000_000_000 // best, "handshakes/s per core")
    var cl = Client12[NullCrypto]("localhost", [])
    cl.start()
    var sv = Server12[NullCrypto](cfg)
    for _ in range(8):
        var x = cl.cn.take_output()
        var y = sv.cn.take_output()
        if len(x) > 0:
            sv.feed(x)
        if len(y) > 0:
            cl.feed(y)
    var blk = List[UInt8](length=65536, fill=9)
    var best2 = 1 << 62
    for _ in range(5):
        var t0 = Int(perf_counter_ns())
        var got = 0
        for _ in range(mib * 16):
            cl.cn.write_app(blk)
            sv.feed(cl.cn.take_output())
            got += len(sv.cn.take_app())
        if got != mib << 20:
            raise Error("FAIL record path lost bytes")
        best2 = min(best2, Int(perf_counter_ns()) - t0)
    print("record path overhead (seal + open + copies, no cipher):", (mib << 20) * 1000 // best2, "MB/s per core")
