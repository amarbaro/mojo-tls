# mojo-tls wave 3b: client certificates (RFC 8446 4.3.2, 4.4.2, 4.4.3). Server side: the chain must be a clientAuth chain to
# the configured roots (no host name) and the CertificateVerify signature must verify under the leaf key. Client side: the
# schemes a private key can sign and the signing itself.
from tls.asym import P256Key, RsaPrivate, RsaPublic, p256_verify, p384_verify
from tls.sym import sha256, sha384
from tls.tls13.wire import bad
from tls.x509.cert import Certificate, KEY_P256, KEY_P384, KEY_RSA
from tls.x509.chain import verify_chain
from tls.x509.key import load_private_key_der


def verify_client(
    chain: List[List[UInt8]], roots: List[List[UInt8]], now: Int, scheme: Int, signed: List[UInt8], sig: List[UInt8]
) raises:
    """bad_certificate unless `chain` validates for clientAuth against `roots` at `now`; decrypt_error unless `sig`
    (scheme over `signed`) is the leaf key's signature; illegal_parameter for a scheme the leaf key cannot use."""
    var certs = List[Certificate]()
    try:
        for c in chain:
            certs.append(Certificate.parse(c.copy()))
        var rs = List[Certificate]()
        for r in roots:
            rs.append(Certificate.parse(r.copy()))
        verify_chain(certs, "", now, rs, True)
    except e:
        raise bad("bad_certificate", String(e))
    ref leaf = certs[0]
    var ok: Bool
    if scheme == 0x0403 and leaf.key_kind == KEY_P256:
        ok = p256_verify(leaf.key_a, sha256(signed), sig)
    elif scheme == 0x0503 and leaf.key_kind == KEY_P384:
        ok = p384_verify(leaf.key_a, sha384(signed), sig)
    elif leaf.key_kind == KEY_RSA and (scheme == 0x0804 or scheme == 0x0805):
        var bits = 256 if scheme == 0x0804 else 384
        ok = RsaPublic(leaf.key_a, leaf.key_b).verify_pss(bits, sha256(signed) if bits == 256 else sha384(signed), sig)
    elif leaf.key_kind == KEY_RSA and (scheme == 0x0401 or scheme == 0x0501):  # TLS 1.2 only: the 1.3 server never lets these through
        var bits = 256 if scheme == 0x0401 else 384
        ok = RsaPublic(leaf.key_a, leaf.key_b).verify_pkcs1(bits, sha256(signed) if bits == 256 else sha384(signed), sig)
    else:
        raise bad("illegal_parameter", "CertificateVerify scheme does not fit the certificate key")
    if not ok:
        raise bad("decrypt_error", "client CertificateVerify signature does not verify")


def key_schemes(key_der: List[UInt8]) raises -> List[Int]:
    """TLS 1.3 signature schemes the PKCS#8/SEC1 key signs with, preferred first."""
    var k = load_private_key_der(key_der)
    return [0x0403] if k.kind == KEY_P256 else [0x0804, 0x0805]


def sign_with_key(key_der: List[UInt8], scheme: Int, content: List[UInt8]) raises -> List[UInt8]:
    var k = load_private_key_der(key_der)
    if k.kind == KEY_P256 and scheme == 0x0403:
        return P256Key(k.d).sign_sha256(sha256(content))
    if k.kind == KEY_RSA and (scheme == 0x0804 or scheme == 0x0805):
        var bits = 256 if scheme == 0x0804 else 384
        return RsaPrivate(k.pub, k.e, k.p, k.q, k.dp, k.dq, k.qinv).sign_pss(bits, sha256(content) if bits == 256 else sha384(content))
    if k.kind == KEY_RSA and (scheme == 0x0401 or scheme == 0x0501):  # TLS 1.2 only
        var bits = 256 if scheme == 0x0401 else 384
        return RsaPrivate(k.pub, k.e, k.p, k.q, k.dp, k.dq, k.qinv).sign_pkcs1(bits, sha256(content) if bits == 256 else sha384(content))
    raise bad("internal_error", "key and signature scheme do not match")
