"""Test-only Crypto12: deterministic, symmetric and NOT secure. It lets the protocol logic (framing, ordering, caps,
alerts, key derivation plumbing, SNI/ALPN, record layer sequence numbers) run end to end without real crypto.
DH is XOR with a constant, a signature is a hash of key||scheme||msg, a certificate is "cert:" + key."""
from tls.asym import random_bytes
from tls.tls12.crypto import Crypto12
from tls.tls12.wire import bl, bytes_of, cat, wipe

comptime DHK = 0x5A


def mix(data: List[UInt8], n: Int) -> List[UInt8]:
    var h = UInt64(0xCBF29CE484222325)
    for b in data:
        h = (h ^ UInt64(b)) * 0x100000001B3
    var o = List[UInt8]()
    for i in range(n):
        h = (h ^ (h >> 29)) * 0xBF58476D1CE4E5B9 + UInt64(i) + 1
        o.append(UInt8((h >> 32) & 255))
    return o^


struct FakeCrypto(Crypto12):
    def __init__(out self):
        pass

    def random(self, n: Int) raises -> List[UInt8]:
        return random_bytes(n)

    def hash(self, sha384: Bool, data: List[UInt8]) -> List[UInt8]:
        return mix(cat(data, bytes_of("H384" if sha384 else "H256")), 48 if sha384 else 32)

    def prf(self, sha384: Bool, secret: List[UInt8], label: String, seed: List[UInt8], n: Int) -> List[UInt8]:
        return mix(cat(secret, bytes_of(label), seed, bytes_of("P384" if sha384 else "P256")), n)

    def keygen(self, group: Int) raises -> Tuple[List[UInt8], List[UInt8]]:
        var s = self.random(32)
        var p = List[UInt8]()
        if group != 0x001D:
            p.append(4)
        for b in s:
            p.append(b ^ UInt8(DHK))
        if group != 0x001D:
            for _ in range(32):
                p.append(0)
        return (s^, p^)

    def ecdh(self, group: Int, secret: List[UInt8], peer: List[UInt8]) raises -> List[UInt8]:
        var o = 0 if group == 0x001D else 1
        if len(peer) != (32 if group == 0x001D else 65) or (o == 1 and peer[0] != 4):
            raise Error("bad point")
        var acc = UInt8(0)
        var r = List[UInt8]()
        for i in range(32):
            acc |= peer[o + i]
            r.append(secret[i] ^ peer[o + i])
        if acc == 0:
            raise Error("low order point")
        return r^

    def sign(self, kind: Int, key_der: List[UInt8], scheme: Int, msg: List[UInt8]) raises -> List[UInt8]:
        return mix(cat(key_der, bl(scheme >> 8, scheme & 255), msg), 64)

    def verify(self, chain: List[List[UInt8]], host: String, scheme: Int, msg: List[UInt8], sig: List[UInt8]) raises:
        var key = List[UInt8](Span(chain[0])[5:])
        if mix(cat(key, bl(scheme >> 8, scheme & 255), msg), 64) != sig:
            raise Error("bad signature")

    def seal(self, aead: Int, key: List[UInt8], nonce: List[UInt8], aad: List[UInt8], mut buf: List[UInt8], start: Int) raises:
        var ks = mix(cat(key, nonce), len(buf) - start)
        for i in range(len(ks)):
            buf[start + i] ^= ks[i]
        var tag = mix(cat(key, nonce, aad, List[UInt8](Span(buf)[start:])), 16)
        buf.extend(tag^)

    def open(self, aead: Int, key: List[UInt8], nonce: List[UInt8], aad: List[UInt8], mut buf: List[UInt8], start: Int, end: Int) raises:
        var tag = mix(cat(key, nonce, aad, List[UInt8](Span(buf)[start : end - 16])), 16)
        if tag != List[UInt8](Span(buf)[end - 16 : end]):
            raise Error("bad tag")
        var ks = mix(cat(key, nonce), end - 16 - start)
        for i in range(len(ks)):
            buf[start + i] ^= ks[i]
