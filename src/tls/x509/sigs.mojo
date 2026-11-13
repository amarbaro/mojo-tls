# Certificate signature verification: picks the hash and padding from the certificate's own algorithm and checks
# it with the issuer's key. SHA-1 and unknown algorithms are refused. Hashes from lane 1, RSA and ECDSA from lane 2.
from tls.x509.cert import *
from tls.x509.der import Der, Bytes, view, copy_of
from tls.sym import sha256, sha384, sha512
from tls.asym import RsaPublic, p256_verify, p384_verify

comptime MIN_RSA_BITS = 2048


def rsa_bits(n: List[UInt8]) -> Int:
    if len(n) == 0:
        return 0
    var top = Int(n[0])
    var b = 0
    while top > 0:
        b += 1
        top >>= 1
    return (len(n) - 1) * 8 + b


def verify_sig(c: Certificate, issuer: Certificate) raises:
    """Raises unless `c` carries a valid signature by `issuer`'s key."""
    var a = c.sig_alg
    var hid = 0  # 0 sha256, 1 sha384, 2 sha512
    if a == SIG_RSA_SHA256 or a == SIG_ECDSA_SHA256 or a == SIG_PSS_SHA256:
        hid = 0
    elif a == SIG_RSA_SHA384 or a == SIG_ECDSA_SHA384 or a == SIG_PSS_SHA384:
        hid = 1
    elif a == SIG_RSA_SHA512 or a == SIG_ECDSA_SHA512 or a == SIG_PSS_SHA512:
        hid = 2
    elif a == SIG_RSA_SHA1 or a == SIG_ECDSA_SHA1:
        raise Error("tls: x509: sha1 signature refused")
    else:
        raise Error("tls: x509: unsupported signature algorithm")
    var tbs = copy_of(c.tbs())
    var h = sha256(tbs) if hid == 0 else (sha384(tbs) if hid == 1 else sha512(tbs))
    var sig = copy_of(c.signature())
    var ecdsa = a >= SIG_ECDSA_SHA256 and a <= SIG_ECDSA_SHA512
    if not ecdsa:
        if issuer.key_kind != KEY_RSA or rsa_bits(issuer.key_a) < MIN_RSA_BITS:
            raise Error("tls: x509: issuer key is not RSA of at least 2048 bits")
        var pk = RsaPublic(issuer.key_a, issuer.key_b)
        var bits = 256 + 128 * hid
        var ok = pk.verify_pss(bits, h, sig, c.pss_salt) if a >= SIG_PSS_SHA256 else pk.verify_pkcs1(bits, h, sig)
        if not ok:
            raise Error("tls: x509: bad rsa signature")
        return
    var ok: Bool
    if issuer.key_kind == KEY_P256:
        ok = p256_verify(issuer.key_a, h, sig)
    elif issuer.key_kind == KEY_P384:
        ok = p384_verify(issuer.key_a, h, sig)
    else:
        raise Error("tls: x509: issuer key is not P-256 or P-384")
    if not ok:
        raise Error("tls: x509: bad ecdsa signature")
