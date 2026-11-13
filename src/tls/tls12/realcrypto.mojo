"""Crypto12 over lanes 1-3: lane 1 hashes, PRF and AEADs; lane 2 x25519, P-256 and RSA; lane 3 keys, certificate
parsing and chain validation (client side, against the system roots, or the PEM file named by TLS_ROOTS). Server keys: P-256 (ecdsa_secp256r1_sha256), P-384 (ecdsa_secp384r1_sha384) and
RSA (rsa_pss_rsae_sha256/384, rsa_pkcs1_sha256/384). aead: 0 AES-128-GCM, 1 AES-256-GCM, 2 ChaCha20-Poly1305."""
from std.ffi import external_call
from tls.tls12.crypto import Crypto12, K_P256, K_P384, K_RSA
from tls.sym.aead import dup
from tls.sym import Sha256, Sha384, sha256, sha384, prf12, AesGcm, ChaCha20Poly1305
from tls.asym import x25519, x25519_base, P256Key, p384_public, p384_ecdh, p384_sign, p256_verify, p384_verify, RsaPublic, RsaPrivate, random_bytes
from tls.x509.cert import Certificate, KEY_P256, KEY_P384, KEY_RSA
from std.os import getenv
from tls.x509.chain import verify_chain, load_system_roots, load_roots_pem
from tls.x509.key import load_private_key_der
from tls.x509.der import view

comptime X25519 = 0x001D
comptime SECP256R1 = 0x0017
comptime SECP384R1 = 0x0018


def _hash_of(scheme: Int) raises -> Int:
    """SHA bits of a TLS SignatureScheme we sign or verify with."""
    if scheme == 0x0403 or scheme == 0x0804 or scheme == 0x0401:
        return 256
    if scheme == 0x0805 or scheme == 0x0501 or scheme == 0x0503:
        return 384
    raise Error("tls: unsupported signature scheme")


def _digest(bits: Int, msg: List[UInt8]) -> List[UInt8]:
    return sha384(msg) if bits == 384 else sha256(msg)


def _roots() raises -> List[Certificate]:
    """TLS_ROOTS=<PEM file> replaces the system bundle (private CAs, tests)."""
    var p = getenv("TLS_ROOTS")
    if p.byte_length() == 0:
        return load_system_roots()
    var raw: List[UInt8]
    with open(p, "r") as f:
        raw = f.read_bytes()
    var dropped = 0
    var r = load_roots_pem(view(raw), dropped)
    _ = len(raw)
    if len(r) == 0 or dropped > 0:
        raise Error("tls: TLS_ROOTS has unparseable or no certificates")
    return r^


struct RealCrypto(Crypto12):
    def __init__(out self):
        pass

    def random(self, n: Int) raises -> List[UInt8]:
        return random_bytes(n)

    def hash(self, sha384: Bool, data: List[UInt8]) -> List[UInt8]:
        return _digest(384 if sha384 else 256, data)

    def prf(self, sha384: Bool, secret: List[UInt8], label: String, seed: List[UInt8], n: Int) -> List[UInt8]:
        return prf12[Sha384](secret, label, seed, n) if sha384 else prf12[Sha256](secret, label, seed, n)

    def keygen(self, group: Int) raises -> Tuple[List[UInt8], List[UInt8]]:
        var k = random_bytes(32)
        if group == X25519:
            return (k.copy(), x25519_base(k))
        if group == SECP256R1:
            return (k.copy(), P256Key(k).public_bytes())
        if group == SECP384R1:
            var q = random_bytes(48)
            return (q.copy(), p384_public(q))
        raise Error("tls: key exchange group not supported")

    def ecdh(self, group: Int, secret: List[UInt8], peer: List[UInt8]) raises -> List[UInt8]:
        if group == X25519:
            return x25519(secret, peer)
        if group == SECP256R1:
            return P256Key(secret).ecdh(peer)
        if group == SECP384R1:
            return p384_ecdh(secret, peer)
        raise Error("tls: key exchange group not supported")

    def sign(self, kind: Int, key_der: List[UInt8], scheme: Int, msg: List[UInt8]) raises -> List[UInt8]:
        var k = load_private_key_der(key_der)
        var bits = _hash_of(scheme)
        if kind == K_P256 and k.kind == KEY_P256 and scheme == 0x0403:
            return P256Key(k.d).sign_sha256(sha256(msg))
        if kind == K_P384 and k.kind == KEY_P384 and scheme == 0x0503:
            return p384_sign(k.d, sha384(msg))
        if kind == K_RSA and k.kind == KEY_RSA:
            var r = RsaPrivate(k.pub, k.e, k.p, k.q, k.dp, k.dq, k.qinv)
            if scheme == 0x0804 or scheme == 0x0805:
                return r.sign_pss(bits, _digest(bits, msg))
            if scheme == 0x0401 or scheme == 0x0501:
                return r.sign_pkcs1(bits, _digest(bits, msg))
        raise Error("tls: key and signature scheme do not match")

    def verify(self, chain: List[List[UInt8]], host: String, scheme: Int, msg: List[UInt8], sig: List[UInt8]) raises:
        if len(chain) == 0:
            raise Error("tls: empty certificate chain")
        var certs = List[Certificate]()
        for c in chain:
            certs.append(Certificate.parse(c.copy()))
        verify_chain(certs, host, Int(external_call["time", Int64](Int64(0))), _roots())
        ref leaf = certs[0]
        var bits = _hash_of(scheme)
        var ok: Bool
        if (scheme == 0x0403 or scheme == 0x0503) and leaf.key_kind == KEY_P256:  # TLS 1.2 binds no curve to the scheme: s_server signs a P-384 certificate with 0x0403
            ok = p256_verify(leaf.key_a, _digest(bits, msg), sig)
        elif (scheme == 0x0403 or scheme == 0x0503) and leaf.key_kind == KEY_P384:
            ok = p384_verify(leaf.key_a, _digest(bits, msg), sig)
        elif leaf.key_kind == KEY_RSA and (scheme == 0x0804 or scheme == 0x0805):
            ok = RsaPublic(leaf.key_a, leaf.key_b).verify_pss(bits, _digest(bits, msg), sig)
        elif leaf.key_kind == KEY_RSA and (scheme == 0x0401 or scheme == 0x0501):
            ok = RsaPublic(leaf.key_a, leaf.key_b).verify_pkcs1(bits, _digest(bits, msg), sig)
        else:
            raise Error("tls: certificate key and signature scheme do not match")
        if not ok:
            raise Error("tls: ServerKeyExchange signature")

    def seal(self, aead: Int, key: List[UInt8], nonce: List[UInt8], aad: List[UInt8], mut buf: List[UInt8], start: Int) raises:
        var body = dup(Span(buf)[start:])
        if aead == 2:
            ChaCha20Poly1305(key).seal(nonce, aad, body)
        else:
            AesGcm(key).seal(nonce, aad, body)
        buf.shrink(start)
        buf.extend(Span(body))

    def open(self, aead: Int, key: List[UInt8], nonce: List[UInt8], aad: List[UInt8], mut buf: List[UInt8], start: Int, end: Int) raises:
        var body = dup(Span(buf)[start:end])
        if aead == 2:
            ChaCha20Poly1305(key).open(nonce, aad, body)
        else:
            AesGcm(key).open(nonce, aad, body)
        if len(body) > 0:
            _ = external_call["memcpy", Int](Int(buf.unsafe_ptr()) + start, Int(body.unsafe_ptr()), len(body))
        _ = body^  # keeps body alive past the memcpy: an Int() pointer does not (use-after-free class, FINDING-heap-grow.md)
