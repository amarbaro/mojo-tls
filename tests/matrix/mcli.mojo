"""Matrix test client: GET over TLS 1.2 or 1.3 with chain validation against TLS_ROOTS=<ca file>.
  mcli --v 12|13 --host NAME --addr IP --port N --ca CA.pem [--alpn http/1.1] [--path /] [--cert CRT.pem --key KEY.pem]
Prints one line: "mcli-ok ver=<..> alpn=<..> body=<first line>"; any failure prints "mcli-fail <reason>" and exits 1."""
from std.sys import argv, exit
from std.os import setenv
import aio
from tls.asym import x25519_base, random_bytes
from tls.net.stream import TlsStream, tcp_connect
from tls.tls12.client import Client12
from tls.tls12.realcrypto import RealCrypto
from tls.tls12.wire import bytes_of, str_of
from tls.tls13.client import Client13, default_hello
from tls.tls13.conn import EV_CLOSE, EV_DONE
from mcommon import *


def first_line(b: List[UInt8]) -> String:
    var s = str_of(b)
    var at = s.find("mojo-tls-ok")
    if at < 0:
        return String("no-marker")
    var end = s.find("\n", at)
    return String(s[byte = at : end if end > 0 else s.byte_length()])


def run12(host: String, addr: String, port: Int, alpn: List[String], path: String, cert: String, key: String) raises:
    var eng = Client12[RealCrypto](host, alpn)
    if cert.byte_length() > 0:
        eng.set_client_cert([pem_der(cert)], pem_der(key))
    var s = TlsStream[RealCrypto](tcp_connect(addr, port), eng^)
    s.handshake()
    s.write(bytes_of("GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
    var got = List[UInt8]()
    while s.read(got) > 0:
        pass
    print("mcli-ok ver=12 alpn=" + s.eng.negotiated + " body=" + first_line(got))
    s.close()


def run13(host: String, addr: String, port: Int, alpn: List[String], path: String, cert: String, key: String) raises:
    var fd = Int(tcp_connect(addr, port))
    var x = random_bytes(32)
    var h = default_hello(host, random_bytes(32), random_bytes(32), x25519_base(x), alpn)
    var cli = Client13[Verify13](h, host, x, random_bytes(32), Verify13())
    if cert.byte_length() > 0:
        cli.set_client_cert([pem_der(cert)], pem_der(key))
    _ = fd_write(fd, cli.start())
    var buf = List[UInt8](length=16384, fill=0)
    var got = List[UInt8]()
    var sent = False
    while True:
        var n = fd_read(fd, buf)
        if n <= 0:
            break
        var o = cli.feed(Span(buf)[0:n])
        _ = fd_write(fd, o.send)
        if o.has(EV_DONE) and not sent:
            sent = True
            _ = fd_write(fd, cli.write(bytes_of("GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\n\r\n")))
        got.extend(Span(o.data))
        if o.error.byte_length() > 0:
            raise Error(o.error)
        if o.has(EV_CLOSE):
            break
    if not sent:
        raise Error("connection closed during the handshake")
    print("mcli-ok ver=13 alpn=" + cli.alpn + " body=" + first_line(got))
    _ = fd_write(fd, cli.close())
    aio.close(Int32(fd))


def main() raises:
    var a = argv()
    var v = 13
    var host = String("localhost")
    var addr = String("127.0.0.1")
    var port = 0
    var alpn = List[String]()
    var path = String("/")
    var cert = String()
    var key = String()
    var i = 1
    while i + 1 < len(a):
        var k = String(a[i])
        var x = String(a[i + 1])
        if k == "--v":
            v = Int(x)
        elif k == "--host":
            host = x
        elif k == "--addr":
            addr = x
        elif k == "--port":
            port = Int(x)
        elif k == "--ca":
            _ = setenv("TLS_ROOTS", x)
        elif k == "--cert":
            cert = x
        elif k == "--key":
            key = x
        elif k == "--path":
            path = x
        elif k == "--alpn":
            alpn = [x] if x != "none" else List[String]()
        i += 2
    try:
        if v == 12:
            run12(host, addr, port, alpn, path, cert, key)
        else:
            run13(host, addr, port, alpn, path, cert, key)
    except e:
        print("mcli-fail " + String(e))
        exit(1)
