"""Test server for tests/net.sh: TlsServer over the fake crypto, echoing every byte.
net_server PORT HANDSHAKE_MS IDLE_MS STOP_AFTER: prints LISTENING <port>, exits after STOP_AFTER connections ended
and prints STATS (completed handshakes, failures, timeouts, open fds at exit)."""
from std.os import listdir
from std.sys import argv
from fake_crypto import FakeCrypto
from tls.net.config import TlsConfig, CertEntry
from tls.net.server import TlsServer, TlsHandler, ConnInfo
from tls.tls12.crypto import K_P256
from tls.tls12.wire import bytes_of


struct Echo(TlsHandler):
    var bytes: Int

    def __init__(out self):
        self.bytes = 0

    def handle(mut self, fd: Int, info: ConnInfo, data: List[UInt8], mut reply: List[UInt8]) raises -> Bool:
        self.bytes += len(data)
        reply.extend(data.copy())
        return False


def main() raises:
    var a = argv()
    var cfg = TlsConfig()
    var chain = List[List[UInt8]]()
    chain.append(bytes_of("cert:key-p256"))
    cfg.certs.append(CertEntry(["localhost"], chain^, bytes_of("key-p256"), K_P256))
    cfg.alpn = ["http/1.1"]
    cfg.handshake_ms = Int(a[2])
    cfg.idle_ms = Int(a[3])
    cfg.max_out = 256 * 1024
    var stop_after = Int(a[4])
    var srv = TlsServer[FakeCrypto](cfg^, Int(a[1]))
    print("LISTENING", srv.port(), flush=True)
    var h = Echo()
    while srv.closed < stop_after:
        srv.step(h, 100)
    var fds = len(listdir("/proc/self/fd"))
    srv.close()
    print("STATS handshakes=" + String(srv.handshakes), "failed=" + String(srv.failed), "timeouts=" + String(srv.timeouts), "echoed=" + String(h.bytes), "fds=" + String(fds), flush=True)
