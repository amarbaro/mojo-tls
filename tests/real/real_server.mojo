"""TLS_SERVER_BIN for tests/interop/run.sh TlsServer over RealCrypto (P-256, P-384 and RSA keys).
real_server --cert CERT.pem --key KEY.pem [--port N]: prints "LISTENING <port>", answers every request with 200 and
the body mojo-tls-ok, then closes. PEM files are decoded here (lane 3 owns the real loader)."""
from std.sys import argv
from tls.tls12.realcrypto import RealCrypto
from tls.net.config import TlsConfig, CertEntry
from tls.net.server import TlsServer, TlsHandler, ConnInfo
from tls.tls12.crypto import K_P256, K_P384, K_RSA
from tls.x509.key import load_private_key_der
from tls.x509.cert import KEY_P384, KEY_RSA
from tls.tls12.wire import bytes_of


def pem_der(path: String) raises -> List[UInt8]:
    var text = open(path, "r").read()
    var o = List[UInt8]()
    var acc = 0
    var bits = 0
    var in_body = False
    for line in text.split("\n"):
        if line.startswith("-----BEGIN"):
            in_body = True
            continue
        if line.startswith("-----END"):
            break
        if not in_body:
            continue
        for c in line.as_bytes():
            var v = -1
            if c >= 65 and c <= 90:
                v = Int(c) - 65
            elif c >= 97 and c <= 122:
                v = Int(c) - 71
            elif c >= 48 and c <= 57:
                v = Int(c) + 4
            elif c == 43:
                v = 62
            elif c == 47:
                v = 63
            if v < 0:
                continue
            acc = (acc << 6) | v
            bits += 6
            if bits >= 8:
                bits -= 8
                o.append(UInt8((acc >> bits) & 255))
    return o^


struct Hello(TlsHandler):
    def __init__(out self):
        pass

    def handle(mut self, fd: Int, info: ConnInfo, data: List[UInt8], mut reply: List[UInt8]) raises -> Bool:
        reply.extend(bytes_of("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nmojo-tls-ok\n"))
        return True


def main() raises:
    var a = argv()
    var cert = String()
    var key = String()
    var port = 0
    var i = 1
    while i + 1 < len(a):
        if a[i] == "--cert":
            cert = String(a[i + 1])
        elif a[i] == "--key":
            key = String(a[i + 1])
        elif a[i] == "--port":
            port = Int(a[i + 1])
        i += 2
    var cfg = TlsConfig()
    var chain = List[List[UInt8]]()
    chain.append(pem_der(cert))
    var der = pem_der(key)
    var kk = load_private_key_der(der).kind  # the certificate kind follows the key, not a constant
    cfg.certs.append(CertEntry(["localhost"], chain^, der^, K_P384 if kk == KEY_P384 else (K_RSA if kk == KEY_RSA else K_P256)))
    cfg.alpn = ["http/1.1"]
    var srv = TlsServer[RealCrypto](cfg^, port)
    print("LISTENING", srv.port(), flush=True)
    var h = Hello()
    srv.run(h)
