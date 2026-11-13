# Private key loading: PKCS#8, SEC1 and PKCS#1 from PEM. P-256, P-384 and RSA (>= 2048 bits, two primes) only.
# Secret handling: base64 is branchless, every buffer holding key bytes is zeroed on success and failure
# (explicit_bzero, which the compiler may not drop), the EC scalar is range-checked and multiplied in constant time,
# errors never carry key bytes. The RSA consistency check uses variable-time bigint code: it runs once at load,
# offline, with no peer in the loop.
from std.ffi import external_call
from tls.x509.cert import Certificate, KEY_RSA, KEY_P256, KEY_P384
from tls.x509.der import Der, Bytes, view, copy_of, same, hex_is
from tls.x509.pem import pem_spans, b64_decode
from tls.x509.sigs import rsa_bits, MIN_RSA_BITS
from tls.sym import sha256
from tls.asym import P256Key, p384_public, RsaPrivate, rsa_d_ok


def wipe(mut l: List[UInt8]):
    if len(l) > 0:
        _ = external_call["explicit_bzero", Int](l.unsafe_ptr(), len(l))


struct PrivateKey(Movable):
    var kind: Int  # KEY_P256, KEY_P384 or KEY_RSA
    var d: List[UInt8]  # EC scalar (32 bytes P-256, 48 bytes P-384) or RSA private exponent
    var pub: List[UInt8]  # EC: uncompressed point (65 or 97 bytes); RSA: modulus
    var e: List[UInt8]
    var p: List[UInt8]
    var q: List[UInt8]
    var dp: List[UInt8]
    var dq: List[UInt8]
    var qinv: List[UInt8]

    def __init__(out self, kind: Int):
        self.kind = kind
        self.d = List[UInt8]()
        self.pub = List[UInt8]()
        self.e = List[UInt8]()
        self.p = List[UInt8]()
        self.q = List[UInt8]()
        self.dp = List[UInt8]()
        self.dq = List[UInt8]()
        self.qinv = List[UInt8]()

    def __deinit__(deinit self):
        wipe(self.d)
        wipe(self.p)
        wipe(self.q)
        wipe(self.dp)
        wipe(self.dq)
        wipe(self.qinv)

    def matches(self, c: Certificate) -> Bool:
        """True when `c` certifies this key's public half."""
        return c.key_kind == self.kind and same(c.key_a, self.pub)


def _rsa_ok(k: PrivateKey) -> Bool:
    """A CRT signature verifies under (n, e) and 2^(de) == 2: ties every field of the key together."""
    try:
        if not rsa_d_ok(k.pub, k.e, k.d):
            return False
        var r = RsaPrivate(k.pub, k.e, k.p, k.q, k.dp, k.dq, k.qinv)
        var h = sha256("mojo-tls key check".as_bytes())
        var ok = r.pk.verify_pkcs1(256, h, r.sign_pkcs1(256, h))
        return ok
    except:
        return False


def _rsa(mut s: Der) raises -> PrivateKey:
    var ver = s.small_int()
    if ver == 1:
        raise Error("tls: key: unsupported multi-prime RSA key")
    if ver != 0:
        raise Error("tls: key: invalid key")
    var k = PrivateKey(KEY_RSA)
    k.pub = copy_of(s.int_bytes())
    k.e = copy_of(s.int_bytes())
    k.d = copy_of(s.int_bytes())
    k.p = copy_of(s.int_bytes())
    k.q = copy_of(s.int_bytes())
    k.dp = copy_of(s.int_bytes())
    k.dq = copy_of(s.int_bytes())
    k.qinv = copy_of(s.int_bytes())
    s.end()
    if rsa_bits(k.pub) < MIN_RSA_BITS:
        raise Error("tls: key: unsupported RSA key below 2048 bits")
    if not _rsa_ok(k):
        raise Error("tls: key: invalid key")
    return k^


def _ec(mut s: Der, var curve: List[UInt8]) raises -> PrivateKey:
    if s.small_int() != 1:
        raise Error("tls: key: invalid key")
    var raw = copy_of(s.octets())
    var given = List[UInt8]()
    if s.peek() == 0xA0:
        var w = Der(s.next(0xA0))
        curve = copy_of(w.oid())
        w.end()
    if s.peek() == 0xA1:
        var w = Der(s.next(0xA1))
        given = copy_of(w.bits())
        if w.unused != 0:
            raise Error("tls: key: invalid key")
        w.end()
    s.end()
    var p384 = hex_is(curve, "2b81040022")
    if (len(curve) > 0 and not p384 and not hex_is(curve, "2a8648ce3d030107")) or len(raw) > (48 if p384 else 32):
        wipe(raw)
        raise Error("tls: key: unsupported curve (only P-256 and P-384)")
    var n = 48 if p384 else 32
    var k = PrivateKey(KEY_P384 if p384 else KEY_P256)
    k.d = List[UInt8](length=n - len(raw), fill=0)
    k.d.extend(raw.copy())
    wipe(raw)
    try:
        if p384:
            k.pub = p384_public(k.d)
        else:
            var pk = P256Key(k.d)
            k.pub = pk.public_bytes()
            pk.zeroize()
    except:
        raise Error("tls: key: invalid key")
    if len(given) > 0 and not same(given, k.pub):
        raise Error("tls: key: invalid key")
    return k^


def _parse(fmt: Int, der: Bytes) raises -> PrivateKey:
    var top = Der(der)
    var s = top.seq()
    top.end()
    if fmt == 2:
        return _rsa(s)
    if fmt == 1:
        return _ec(s, List[UInt8]())
    var ver = s.small_int()
    if ver != 0:
        raise Error("tls: key: unsupported PKCS#8 version")
    var alg = s.seq()
    var oid = alg.oid()
    var is_rsa = hex_is(oid, "2a864886f70d010101")
    if not is_rsa and not hex_is(oid, "2a8648ce3d0201"):
        raise Error("tls: key: unsupported key algorithm")
    var inner = Der(s.octets())
    if s.peek() == 0xA0:
        _ = s.next()
    s.end()
    var body = inner.seq()
    inner.end()
    if is_rsa:
        return _rsa(body)
    return _ec(body, copy_of(alg.oid()))


def load_private_key(pem: Span[UInt8, _]) raises -> PrivateKey:
    """First PRIVATE KEY / EC PRIVATE KEY / RSA PRIVATE KEY block of `pem`. Encrypted keys are refused."""
    var text = view(pem)
    for ref sp in pem_spans(text):
        var fmt = 0
        if same(sp[0], "PRIVATE KEY".as_bytes()):
            fmt = 8
        elif same(sp[0], "EC PRIVATE KEY".as_bytes()):
            fmt = 1
        elif same(sp[0], "RSA PRIVATE KEY".as_bytes()):
            fmt = 2
        elif same(sp[0], "ENCRYPTED PRIVATE KEY".as_bytes()):
            raise Error("tls: key: unsupported encrypted private key")
        else:
            continue
        var body = sp[1]
        var i = 0
        while i < len(body) and (body[i] == 10 or body[i] == 13 or body[i] == 32):
            i += 1
        if len(body) - i > 10 and same(body[i : i + 10], "Proc-Type:".as_bytes()):
            raise Error("tls: key: unsupported encrypted private key")
        var der = b64_decode(body)
        try:
            var k = _parse(fmt, view(der))
            wipe(der)
            return k^
        except e:
            wipe(der)
            if String(e).startswith("tls: key: unsupported"):
                raise e
            raise Error("tls: key: invalid key")
    raise Error("tls: key: no private key block")


def load_private_key_file(path: String) raises -> PrivateKey:
    """Read `path`, load the key, zero the file buffer."""
    var raw: List[UInt8]
    with open(path, "r") as f:
        raw = f.read_bytes()
    try:
        var k = load_private_key(raw)
        wipe(raw)
        return k^
    except e:
        wipe(raw)
        raise e


def load_private_key_der(der: Span[UInt8, _]) raises -> PrivateKey:
    """A DER private key: PKCS#8, SEC1 (EC PRIVATE KEY) or PKCS#1 (RSA PRIVATE KEY), tried in that order."""
    for fmt in range(3):
        try:
            return _parse(fmt, view(der))
        except:
            pass
    raise Error("tls: key: not a PKCS#8, SEC1 or PKCS#1 private key")
