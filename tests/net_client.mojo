"""Test client for tests/net.sh: TlsStream over the fake crypto against net_server.
net_client PORT MODE N
  echo N      N sequential connections, each echoes a different-sized payload (1..3000 bytes) and checks it
  big N       N connections, each echoes 1 MiB in 64 KiB steps
  silent MS   raw TCP, no bytes; waits for the server to close it, prints how long that took
  garbage N   N raw connections, each sends 600 patterned bytes and waits for the close
  slow N      TLS with a 4 KiB receive buffer: writes N KiB without reading, sleeps, then reads it all back
              (the server must queue, pause reading, resume once drained)
  idle N      one TLS connection, then silence; waits for the server's idle timeout to close it
  halfhs MS   raw TCP, sends 20 bytes of a ClientHello then nothing; waits for the close
Prints OK <mode> ... and exits 0, or FAIL <mode>: <why> and exits 1."""
from std.sys import argv
from std.time import perf_counter_ns, sleep
from fake_crypto import FakeCrypto
from tls.net.stream import TlsStream, tls_connect, tcp_connect
from tls.tls12.wire import bl
import aio


def payload(n: Int, salt: Int) -> List[UInt8]:
    var p = List[UInt8]()
    for i in range(n):
        p.append(UInt8((i * 31 + salt) & 255))
    return p^


def echo(mut s: TlsStream[FakeCrypto], data: List[UInt8], step: Int) raises -> Bool:
    var got = List[UInt8]()
    var off = 0
    while off < len(data):
        var n = min(step, len(data) - off)
        s.write(List[UInt8](Span(data)[off : off + n]))
        off += n
        while len(got) < off:
            if s.read(got) == 0:
                return False
    return got == data


def wait_closed(fd: Int32, limit_ms: Int) -> Int:
    """Milliseconds until the server closed fd (read returns 0 or an error); the socket is blocking, so net.sh
    supplies the timeout for a server that never closes."""
    var t0 = Int(perf_counter_ns())
    var b = List[UInt8](length=4096, fill=0)
    while (Int(perf_counter_ns()) - t0) // 1_000_000 < limit_ms:
        var n = aio.read(fd, b)
        if n == 0 or n == -2:
            return (Int(perf_counter_ns()) - t0) // 1_000_000
    return -1


def main() raises:
    var a = argv()
    var port = Int(a[1])
    var mode = String(a[2])
    var n = Int(a[3])
    if mode == "echo" or mode == "big":
        for i in range(n):
            var s = tls_connect[FakeCrypto]("localhost", port, ["http/1.1"], "127.0.0.1")
            var ok = echo(s, payload(1 + (i * 97) % 3000, i), 1000) if mode == "echo" else echo(s, payload(1 << 20, i), 65536)
            s.close()
            if not ok:
                print("FAIL " + mode + ": echo mismatch on connection " + String(i))
                raise Error("fail")
        print("OK " + mode + " " + String(n))
    elif mode == "slow":
        var s = tls_connect[FakeCrypto]("localhost", port, [], "127.0.0.1", 4096)
        var data = payload(n * 1024, 5)
        for off in range(0, len(data), 65536):
            s.write(List[UInt8](Span(data)[off : min(off + 65536, len(data))]))
        sleep(0.6)
        var got = List[UInt8]()
        while len(got) < len(data):
            if s.read(got) == 0:
                break
        s.close()
        if got != data:
            print("FAIL slow: got " + String(len(got)) + " of " + String(len(data)) + " bytes back")
            raise Error("fail")
        print("OK slow " + String(n) + " KiB")
    elif mode == "idle":
        var s = tls_connect[FakeCrypto]("localhost", port, [], "127.0.0.1")
        var t0 = Int(perf_counter_ns())
        var got = List[UInt8]()
        if s.read(got) != 0:
            print("FAIL idle: unexpected data")
            raise Error("fail")
        print("OK idle closed after " + String((Int(perf_counter_ns()) - t0) // 1_000_000) + " ms")
    elif mode == "silent" or mode == "halfhs":
        var fd = tcp_connect("127.0.0.1", port)
        if mode == "halfhs":
            _ = aio.write(fd, bl(22, 3, 1, 1, 0, 0, 0, 1, 2, 3, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2))
        var ms = wait_closed(fd, n + 3000)
        aio.close(fd)
        if ms < 0:
            print("FAIL " + mode + ": server never closed")
            raise Error("fail")
        print("OK " + mode + " closed after " + String(ms) + " ms")
    elif mode == "tiny":  # a complete first record too short to hold a ClientHello: the server must alert and live on
        for i in range(n):
            var fd = tcp_connect("127.0.0.1", port)
            _ = aio.write(fd, [UInt8(22), 3, 1, 0, 2, 1, 0])
            var ms = wait_closed(fd, 3000)
            aio.close(fd)
            if ms < 0:
                print("FAIL tiny: server never closed connection " + String(i))
                raise Error("fail")
        print("OK tiny " + String(n))
    elif mode == "garbage":
        for i in range(n):
            var fd = tcp_connect("127.0.0.1", port)
            _ = aio.write(fd, payload(600, i * 13))
            var ms = wait_closed(fd, 3000)
            aio.close(fd)
            if ms < 0:
                print("FAIL garbage: server never closed connection " + String(i))
                raise Error("fail")
        print("OK garbage " + String(n))
