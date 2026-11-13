"""HTTPS client over TLS 1.3. usage: client HOST ADDR PORT
HOST is the name the certificate must match, ADDR the IPv4 address to connect to. The server certificate is checked
against the system roots, or against the PEM file named by TLS_ROOTS (a private CA)."""
from std.sys import argv
import aio
from tls.asym import x25519_base, random_bytes
from tls.net.stream import tcp_connect
from tls.tls12.realcrypto import RealCrypto
from tls.tls13.client import Client13, default_hello
from tls.tls13.conn import EV_CLOSE, EV_DONE
from tls.tls13.verify import Verifier


struct Check(Verifier):
    """Chain and signature checks of the shipped crypto: chain to the roots, host name, CertificateVerify."""

    def __init__(out self):
        pass

    def verify(mut self, chain: List[List[UInt8]], scheme: Int, signed: List[UInt8], sig: List[UInt8], host: String) raises:
        RealCrypto().verify(chain, host, scheme, signed, sig)


def send(fd: Int32, data: List[UInt8]) raises:
    var done = 0
    while done < len(data):
        var n = aio.write(fd, Span(data)[done:])
        if n <= 0:
            raise Error("write failed")
        done += n


def main() raises:
    var a = argv()
    if len(a) < 4:
        raise Error("usage: client HOST ADDR PORT")
    var host = String(a[1])
    var fd = tcp_connect(String(a[2]), Int(String(a[3])))
    var secret = random_bytes(32)
    var hello = default_hello(host, random_bytes(32), random_bytes(32), x25519_base(secret), ["http/1.1"])
    var cli = Client13[Check](hello, host, secret, random_bytes(32), Check())
    send(fd, cli.start())
    var buf = List[UInt8](length=16384, fill=0)
    var reply = List[UInt8]()
    var asked = False
    while True:
        var n = aio.read(fd, buf)
        if n <= 0:
            break
        var o = cli.feed(Span(buf)[0:n])
        send(fd, o.send)
        if o.error.byte_length() > 0:
            raise Error(o.error)
        if o.has(EV_DONE) and not asked:  # handshake finished: the application data keys are installed
            asked = True
            var req = String("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
            send(fd, cli.write(List[UInt8](req.as_bytes())))
        reply.extend(Span(o.data))
        if o.has(EV_CLOSE):
            break
    if not asked:
        raise Error("connection closed during the handshake")
    print(String(unsafe_from_utf8=Span(reply)), end="")
    print("-- TLS 1.3, ALPN", cli.alpn)
    send(fd, cli.close())
    aio.close(fd)
