# Interop client: Client13 over stdin/stdout (a relay in tests/interop.py joins it to a TCP socket for openssl s_server,
# python). After the handshake it sends an HTTP request, prints the reply to stderr and closes.
# usage: interop_client <cert.der pinned> <suite hex|any> <host>
from std.sys import argv, stderr
from tls.asym import x25519_base, random_bytes
from tls.tls13.client import Client13, default_hello
from tls.tls13.conn import EV_CLOSE, EV_DONE
from tls.tls13.wire import bytes_of, str_of
from interop_common import P256Pinned, read_file, fd_read, fd_write


def main() raises:
    var a = argv()
    var host = String(a[3])
    var x = random_bytes(32)
    var h = default_hello(host, random_bytes(32), random_bytes(32), x25519_base(x), [String("http/1.1")])
    if String(a[2]) != "any":
        h.suites = [atol(String(a[2]), base=16)]
    var cli = Client13[P256Pinned](h, host, x, random_bytes(32), P256Pinned(read_file(String(a[1]))))
    _ = fd_write(1, cli.start())
    var buf = List[UInt8](length=16384, fill=0)
    var got = List[UInt8]()
    while True:
        var n = fd_read(0, buf)
        if n <= 0:
            break
        var o = cli.feed(Span(buf)[0:n])
        _ = fd_write(1, o.send)
        if o.has(EV_DONE):
            print("CLIENT handshake done suite=" + String(cli.c.suite) + " group=" + String(cli.group) + " alpn=" + cli.alpn, file=stderr)
            _ = fd_write(1, cli.key_update())
            _ = fd_write(1, cli.write(bytes_of("GET / HTTP/1.0\r\n\r\n")))
        got.extend(Span(o.data))
        if o.error.byte_length() > 0:
            print("CLIENT error: " + o.error, file=stderr)
            break
        if o.has(EV_CLOSE):
            break
    print("CLIENT reply " + String(len(got)) + " bytes", file=stderr)
    print(str_of(got), file=stderr)
    _ = fd_write(1, cli.close())
