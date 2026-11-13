# Interop server: Server13 over stdin/stdout (a relay in tests/interop.py joins it to a TCP socket for openssl s_client,
# curl, python ssl). Echoes "echo: <data>". usage: interop_server <cert.der> <key.hex> <suite hex|any> <plain|hrr>
from std.sys import argv, stderr
from tls.asym import random_bytes
from tls.tls13.conn import EV_CLOSE, EV_DONE
from tls.tls13.messages import G_P256
from tls.tls13.server import Server13, ServerConfig
from tls.tls13.wire import bytes_of
from interop_common import P256Signer, read_file, read_hex_file, fd_read, fd_write


def main() raises:
    var a = argv()
    var cfg = ServerConfig(random_bytes(32), random_bytes(32), random_bytes(32))
    if String(a[3]) != "any":
        cfg.suites = [atol(String(a[3]), base=16)]
    if String(a[4]) == "hrr":
        cfg.groups = [G_P256]
    cfg.alpn = [String("http/1.1")]
    var srv = Server13[P256Signer](cfg^, P256Signer(read_hex_file(String(a[2])), read_file(String(a[1]))))
    var buf = List[UInt8](length=16384, fill=0)
    while True:
        var n = fd_read(0, buf)
        if n <= 0:
            break
        var o = srv.feed(Span(buf)[0:n])
        _ = fd_write(1, o.send)
        if o.has(EV_DONE):
            print("SERVER handshake done suite=" + String(srv.c.suite) + " group=" + String(srv.group) + " sni=" + srv.sni + " alpn=" + srv.alpn, file=stderr)
            _ = fd_write(1, srv.key_update())  # the peer must answer and both sides switch keys before any data
        if len(o.data) > 0 and not o.has(EV_CLOSE):
            var reply = bytes_of("echo: ")
            reply.extend(Span(o.data))
            if len(o.data) > 4 and o.data[0] == 0x47 and o.data[1] == 0x45 and o.data[2] == 0x54:  # "GET": answer as HTTP/1.0 and close
                var http = bytes_of("HTTP/1.0 200 OK\r\nContent-Length: " + String(len(reply)) + "\r\n\r\n")
                http.extend(Span(reply))
                reply = http^
            _ = fd_write(1, srv.write(reply))
            if reply[0] == 0x48:
                _ = fd_write(1, srv.close())
        if o.error.byte_length() > 0:
            print("SERVER error: " + o.error, file=stderr)
            break
        if o.has(EV_CLOSE):
            print("SERVER close_notify received", file=stderr)
            break
