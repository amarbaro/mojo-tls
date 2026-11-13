"""Matrix harness glue: PEM decoding, a TLS 1.3 Signer and Verifier over RealCrypto (lanes 1-3), blocking fd I/O."""
import aio
from tls.tls12.realcrypto import RealCrypto
from tls.tls12.crypto import Crypto12, K_P256, K_RSA
from tls.tls13.verify import Signer, Verifier
from tls.x509.key import load_private_key_der
from tls.x509.cert import KEY_P256


def pem_der(path: String) raises -> List[UInt8]:
    """First PEM block of a file as DER."""
    var o = List[UInt8]()
    var acc = 0
    var bits = 0
    var in_body = False
    for line in open(path, "r").read().split("\n"):
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


def key_kind(key_der: List[UInt8]) raises -> Int:
    return K_P256 if load_private_key_der(key_der).kind == KEY_P256 else K_RSA


struct Sign13(Signer):
    var kind: Int
    var key: List[UInt8]
    var certs: List[List[UInt8]]

    def __init__(out self, kind: Int, key: List[UInt8], var certs: List[List[UInt8]]):
        self.kind = kind
        self.key = key.copy()
        self.certs = certs^

    def schemes(self) -> List[Int]:
        return [0x0403] if self.kind == K_P256 else [0x0804]

    def chain(self) -> List[List[UInt8]]:
        return self.certs.copy()

    def sign(self, scheme: Int, content: List[UInt8]) raises -> List[UInt8]:
        return RealCrypto().sign(self.kind, self.key, scheme, content)


struct Verify13(Verifier):
    def __init__(out self):
        pass

    def verify(
        mut self, chain: List[List[UInt8]], scheme: Int, signed: List[UInt8], sig: List[UInt8], host: String
    ) raises:
        RealCrypto().verify(chain, host, scheme, signed, sig)


def fd_read(fd: Int, mut buf: List[UInt8]) -> Int:
    return aio.read(Int32(fd), buf)


def fd_write(fd: Int, data: List[UInt8]) -> Int:
    var done = 0
    while done < len(data):
        var n = aio.write(Int32(fd), Span(data)[done:])
        if n <= 0:
            return -1
        done += n
    return done


def has_end(b: List[UInt8]) -> Bool:
    """The request is complete: CRLF CRLF seen."""
    for i in range(len(b) - 3):
        if b[i] == 13 and b[i + 1] == 10 and b[i + 2] == 13 and b[i + 3] == 10:
            return True
    return False
