"""HTTPS server: TLS 1.3 and 1.2 on one port. usage: server CERT.pem KEY.pem [PORT]  (PORT 0 = any free port)
CERT.pem holds the certificate chain, leaf first; KEY.pem a PKCS#8 or SEC1 key (P-256) or an RSA key (2048+)."""
from std.sys import argv
from tls.net.config import TlsConfig, CertEntry
from tls.net.server import TlsServer, TlsHandler, ConnInfo
from tls.tls12.realcrypto import RealCrypto
from tls.tls12.crypto import K_P256, K_RSA
from tls.x509.cert import KEY_P256
from tls.x509.der import view
from tls.x509.key import load_private_key_der
from tls.x509.pem import pem_blocks


struct Hello(TlsHandler):
    """Answers every request with one small page, then closes the connection."""

    def __init__(out self):
        pass

    def handle(mut self, fd: Int, info: ConnInfo, data: List[UInt8], mut reply: List[UInt8]) raises -> Bool:
        var body = String("hello from mojo-tls over TLS 1.") + ("3" if info.ver == 13 else "2") + "\n"
        var head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: " + String(body.byte_length()) + "\r\n\r\n"
        reply.extend(Span((head + body).as_bytes()))
        return True  # close after the reply


def read_pem(path: String, label_has: String) raises -> List[List[UInt8]]:
    """The DER bodies of every PEM block in the file whose label contains label_has."""
    var raw: List[UInt8]
    with open(path, "r") as f:
        raw = f.read_bytes()
    var out = List[List[UInt8]]()
    for b in pem_blocks(view(raw)):
        if label_has in b.label:
            out.append(b.der.copy())
    _ = len(raw)
    return out^


def main() raises:
    var a = argv()
    if len(a) < 3:
        raise Error("usage: server CERT.pem KEY.pem [PORT]")
    var chain = read_pem(String(a[1]), "CERTIFICATE")
    var keys = read_pem(String(a[2]), "PRIVATE KEY")
    if len(chain) == 0 or len(keys) != 1:
        raise Error("need a certificate chain and exactly one private key")
    var kind = K_P256 if load_private_key_der(keys[0]).kind == KEY_P256 else K_RSA
    var cfg = TlsConfig()
    cfg.alpn.append("http/1.1")
    cfg.certs.append(CertEntry([String("localhost")], chain^, keys[0].copy(), kind))  # the first entry is the default
    var srv = TlsServer[RealCrypto](cfg^, Int(String(a[3])) if len(a) > 3 else 0, "127.0.0.1", True)
    print("LISTENING", srv.port(), flush=True)
    var h = Hello()
    srv.run(h)
