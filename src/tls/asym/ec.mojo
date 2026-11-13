# P-256 and P-384 over the generic Montgomery field of bn.mojo: ECDH, ECDSA sign (RFC 6979) and verify.
# Complete projective formulas for a = -3 (Renes-Costello-Batina 2016, Algorithms 4 and 6) as in
# Mosaad-M-tls crypto/ec_ct.mojo (MIT, (c) 2026 mmosaad): no identity or P == Q branches.
from .bn import *
from .random import random_bytes
from .sha2 import hmac


def unhex(h: StringSlice) -> List[UInt8]:
    var raw = h.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw) - 1, 2):
        var a = Int(raw[i])
        var b = Int(raw[i + 1])
        out.append(UInt8(((a - 48) if a <= 57 else ((a | 32) - 87)) * 16 + ((b - 48) if b <= 57 else ((b | 32) - 87))))
    return out^


def wipe(mut v: List[UInt8]):
    for i in range(len(v)):
        v[i] = 0


struct Point[N: Int](Copyable, Movable):
    var x: Fe[Self.N]
    var y: Fe[Self.N]
    var z: Fe[Self.N]

    def __init__(out self, x: Fe[Self.N], y: Fe[Self.N], z: Fe[Self.N]):
        self.x = x.copy()
        self.y = y.copy()
        self.z = z.copy()


struct Curve[N: Int](Copyable, Movable):
    var f: Modulus[Self.N]  # field prime
    var o: Modulus[Self.N]  # group order
    var b: Fe[Self.N]  # Montgomery form
    var g: Point[Self.N]

    def __init__(out self, p: StringSlice, n: StringSlice, b: StringSlice, gx: StringSlice, gy: StringSlice):
        self.f = Modulus[Self.N](from_be[Self.N](unhex(p)))
        self.o = Modulus[Self.N](from_be[Self.N](unhex(n)))
        self.b = to_mont(from_be[Self.N](unhex(b)), self.f)
        self.g = Point[Self.N](
            to_mont(from_be[Self.N](unhex(gx)), self.f), to_mont(from_be[Self.N](unhex(gy)), self.f), mont_one(self.f)
        )


def p256() -> Curve[4]:
    return Curve[4](
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    )


def p384() -> Curve[6]:
    return Curve[6](
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
    )


def identity[N: Int](f: Modulus[N]) -> Point[N]:
    return Point[N](zero[N](), mont_one(f), zero[N]())


def point_add[N: Int](p1: Point[N], p2: Point[N], b: Fe[N], md: Modulus[N]) -> Point[N]:
    var t0 = mont_mul(p1.x, p2.x, md)
    var t1 = mont_mul(p1.y, p2.y, md)
    var t2 = mont_mul(p1.z, p2.z, md)
    var t3 = add(p1.x, p1.y, md)
    var t4 = add(p2.x, p2.y, md)
    t3 = mont_mul(t3, t4, md)
    t4 = add(t0, t1, md)
    t3 = sub(t3, t4, md)
    t4 = add(p1.y, p1.z, md)
    var x3 = add(p2.y, p2.z, md)
    t4 = mont_mul(t4, x3, md)
    x3 = add(t1, t2, md)
    t4 = sub(t4, x3, md)
    x3 = add(p1.x, p1.z, md)
    var y3 = add(p2.x, p2.z, md)
    x3 = mont_mul(x3, y3, md)
    y3 = add(t0, t2, md)
    y3 = sub(x3, y3, md)
    var z3 = mont_mul(b, t2, md)
    x3 = sub(y3, z3, md)
    z3 = add(x3, x3, md)
    x3 = add(x3, z3, md)
    z3 = sub(t1, x3, md)
    x3 = add(t1, x3, md)
    y3 = mont_mul(b, y3, md)
    t1 = add(t2, t2, md)
    t2 = add(t1, t2, md)
    y3 = sub(y3, t2, md)
    y3 = sub(y3, t0, md)
    t1 = add(y3, y3, md)
    y3 = add(t1, y3, md)
    t1 = add(t0, t0, md)
    t0 = add(t1, t0, md)
    t0 = sub(t0, t2, md)
    t1 = mont_mul(t4, y3, md)
    t2 = mont_mul(t0, y3, md)
    y3 = mont_mul(x3, z3, md)
    y3 = add(y3, t2, md)
    x3 = mont_mul(t3, x3, md)
    x3 = sub(x3, t1, md)
    z3 = mont_mul(t4, z3, md)
    t1 = mont_mul(t3, t0, md)
    z3 = add(z3, t1, md)
    return Point[N](x3, y3, z3)


def point_double[N: Int](p: Point[N], b: Fe[N], md: Modulus[N]) -> Point[N]:
    var t0 = mont_mul(p.x, p.x, md)
    var t1 = mont_mul(p.y, p.y, md)
    var t2 = mont_mul(p.z, p.z, md)
    var t3 = mont_mul(p.x, p.y, md)
    t3 = add(t3, t3, md)
    var z3 = mont_mul(p.x, p.z, md)
    z3 = add(z3, z3, md)
    var y3 = mont_mul(b, t2, md)
    y3 = sub(y3, z3, md)
    var x3 = add(y3, y3, md)
    y3 = add(x3, y3, md)
    x3 = sub(t1, y3, md)
    y3 = add(t1, y3, md)
    y3 = mont_mul(x3, y3, md)
    x3 = mont_mul(x3, t3, md)
    t3 = add(t2, t2, md)
    t2 = add(t2, t3, md)
    z3 = mont_mul(b, z3, md)
    z3 = sub(z3, t2, md)
    z3 = sub(z3, t0, md)
    t3 = add(z3, z3, md)
    z3 = add(z3, t3, md)
    t3 = add(t0, t0, md)
    t0 = add(t3, t0, md)
    t0 = sub(t0, t2, md)
    t0 = mont_mul(t0, z3, md)
    y3 = add(y3, t0, md)
    t0 = mont_mul(p.y, p.z, md)
    t0 = add(t0, t0, md)
    z3 = mont_mul(t0, z3, md)
    x3 = sub(x3, z3, md)
    z3 = mont_mul(t0, t1, md)
    z3 = add(z3, z3, md)
    z3 = add(z3, z3, md)
    return Point[N](x3, y3, z3)


def scalar_mult[N: Int](k: Fe[N], p: Point[N], c: Curve[N]) -> Point[N]:
    """k*p, constant time: fixed 4-bit windows over all 64N bits, the 16-entry table read by full scan."""
    var tab = List[Point[N]](capacity=16)
    tab.append(identity(c.f))
    tab.append(p.copy())
    for i in range(2, 16):
        tab.append(point_double(tab[i // 2], c.b, c.f) if i % 2 == 0 else point_add(tab[i - 1], p, c.b, c.f))
    var r = identity(c.f)
    for w in range(16 * N - 1, -1, -1):
        for _ in range(4):
            r = point_double(r, c.b, c.f)
        var nib = Int((k[w >> 4] >> UInt64(4 * (w & 15))) & 15)
        var sel = Point[N](zero[N](), zero[N](), zero[N]())
        for j in range(16):
            var mask = eq_mask(j, nib)
            for i in range(N):
                sel.x[i] |= tab[j].x[i] & mask
                sel.y[i] |= tab[j].y[i] & mask
                sel.z[i] |= tab[j].z[i] & mask
        r = point_add(r, sel, c.b, c.f)
    return r^


def affine_x[N: Int](p: Point[N], c: Curve[N]) raises -> Fe[N]:
    """x of p in normal form; raises for the identity (checked on the public result)."""
    var x = from_mont(mont_mul(p.x, mont_inv(p.z, c.f), c.f), c.f)
    if is_zero(p.z) == 1:
        raise Error("tls: ec point at infinity")
    return x^


def valid_pub[N: Int](pub: Span[UInt8, _], c: Curve[N]) -> Bool:
    """Uncompressed point 04||X||Y with coordinates below p, on the curve: y^2 = x^3 - 3x + b."""
    if len(pub) != 1 + 16 * N or pub[0] != 4:
        return False
    var x = from_be[N](pub[1 : 1 + 8 * N])
    var y = from_be[N](pub[1 + 8 * N : 1 + 16 * N])
    if lt(x, c.f.m) == 0 or lt(y, c.f.m) == 0:
        return False
    var xm = to_mont(x, c.f)
    var ym = to_mont(y, c.f)
    var x3 = mont_mul(mont_mul(xm, xm, c.f), xm, c.f)
    var rhs = add(sub(x3, add(add(xm, xm, c.f), xm, c.f), c.f), c.b, c.f)
    return is_zero(sub(mont_mul(ym, ym, c.f), rhs, c.f)) == 1


def pub_bytes[N: Int](d: Fe[N], c: Curve[N]) raises -> List[UInt8]:
    var r = scalar_mult(d, c.g, c)
    var zi = mont_inv(r.z, c.f)
    var x = to_be(from_mont(mont_mul(r.x, zi, c.f), c.f))
    var y = to_be(from_mont(mont_mul(r.y, zi, c.f), c.f))
    var out = List[UInt8](capacity=1 + 16 * N)
    out.append(4)
    out.extend(Span(x))
    out.extend(Span(y))
    return out^


def in_range[N: Int](d: Fe[N], md: Modulus[N]) -> Bool:
    """1 <= d < order."""
    return (lt(d, md.m) & (is_zero(d) ^ 1)) == 1


def ecdh[N: Int](d: Fe[N], peer: Span[UInt8, _], c: Curve[N]) raises -> List[UInt8]:
    if not valid_pub(peer, c):
        raise Error("tls: invalid ec public key")
    var q = Point[N](
        to_mont(from_be[N](peer[1 : 1 + 8 * N]), c.f), to_mont(from_be[N](peer[1 + 8 * N :]), c.f), mont_one(c.f)
    )
    return to_be(affine_x(scalar_mult(d, q, c), c))


def _hash_int[N: Int](h: Span[UInt8, _]) -> Fe[N]:
    """bits2int for qlen = 64N: the leftmost 8N bytes, a shorter hash right-aligned."""
    return from_be[N](h[: min(len(h), 8 * N)])


def _der_int(v: Span[UInt8, _]) -> List[UInt8]:
    var i = 0
    while i < len(v) - 1 and v[i] == 0:
        i += 1
    var out = List[UInt8]()
    out.append(2)
    out.append(UInt8(len(v) - i + (1 if v[i] >= 0x80 else 0)))
    if v[i] >= 0x80:
        out.append(0)
    out.extend(v[i:])
    return out^


def ecdsa_sign[N: Int](d: Fe[N], h1: Span[UInt8, _], c: Curve[N]) raises -> List[UInt8]:
    """Deterministic ECDSA (RFC 6979 section 3.2, HMAC with the hash of the curve as the DRBG: SHA-256 for P-256,
    SHA-384 for P-384). Returns DER. No low-s normalisation: the output equals the RFC vectors."""
    comptime hbits = 256 if N == 4 else 384
    comptime hl = hbits // 8
    var e = reduce_once(_hash_int[N](h1), 0, c.o)  # bits2int(h1) mod n, which is also bits2octets
    var x = to_be(d)
    var hb = to_be(e)
    var v = List[UInt8](length=hl, fill=1)
    var kk = List[UInt8](length=hl, fill=0)
    for tag in range(2):
        var m = v.copy()
        m.append(UInt8(tag))
        m.extend(Span(x))
        m.extend(Span(hb))
        kk = hmac(hbits, kk, m)
        v = hmac(hbits, kk, v)
        wipe(m)
    var dm = to_mont(d, c.o)
    var em = to_mont(e, c.o)
    while True:
        var t = List[UInt8]()
        while len(t) < 8 * N:
            v = hmac(hbits, kk, v)
            t.extend(Span(v))
        var k = from_be[N](t[: 8 * N])
        wipe(t)
        if in_range(k, c.o):
            var r = reduce_once(affine_x(scalar_mult(k, c.g, c), c), 0, c.o)
            var rm = to_mont(r, c.o)
            var s = from_mont(
                mont_mul(mont_inv(to_mont(k, c.o), c.o), add(em, mont_mul(rm, dm, c.o), c.o), c.o), c.o
            )
            if is_zero(r) == 0 and is_zero(s) == 0:
                var ri = _der_int(to_be(r))
                var si = _der_int(to_be(s))
                var out = List[UInt8]()
                out.append(0x30)
                out.append(UInt8(len(ri) + len(si)))
                out.extend(Span(ri))
                out.extend(Span(si))
                wipe(x)
                wipe(kk)
                wipe(v)
                return out^
        var m = v.copy()
        m.append(0)
        kk = hmac(hbits, kk, m)
        v = hmac(hbits, kk, v)


def _der_pos_int(s: Span[UInt8, _], mut i: Int, end: Int, mut out: Fe[8]) -> Bool:
    """Strict DER INTEGER at s[i]: positive, minimal, then advance i. Value left-aligned into out (at most 8 limbs)."""
    if i + 2 > end or s[i] != 2:
        return False
    var n = Int(s[i + 1])
    if n == 0 or n >= 0x80 or i + 2 + n > end:
        return False
    var b = s[i + 2 : i + 2 + n]
    if b[0] >= 0x80 or (b[0] == 0 and (n == 1 or b[1] < 0x80)):
        return False
    var v = b[1:] if b[0] == 0 else b
    if len(v) > 64:
        return False
    out = from_be[8](v)
    i += 2 + n
    return True


def ecdsa_verify[N: Int](pub: Span[UInt8, _], h: Span[UInt8, _], sig: Span[UInt8, _], c: Curve[N]) -> Bool:
    """ECDSA verify of a strict-DER signature; variable time (all inputs are public)."""
    if len(sig) < 8 or sig[0] != 0x30 or Int(sig[1]) != len(sig) - 2 or not valid_pub(pub, c):
        return False
    var rw = Fe[8](fill=0)
    var sw = Fe[8](fill=0)
    var i = 2
    if not _der_pos_int(sig, i, len(sig), rw) or not _der_pos_int(sig, i, len(sig), sw) or i != len(sig):
        return False
    for k in range(N, 8):
        if rw[k] != 0 or sw[k] != 0:
            return False
    var r = Fe[N](fill=0)
    var s = Fe[N](fill=0)
    for k in range(N):
        r[k] = rw[k]
        s[k] = sw[k]
    if is_zero(r) == 1 or lt(r, c.o.m) == 0 or is_zero(s) == 1 or lt(s, c.o.m) == 0:
        return False
    var e = reduce_once(_hash_int[N](h), 0, c.o)
    var w = mont_inv(to_mont(s, c.o), c.o)
    var u1 = from_mont(mont_mul(to_mont(e, c.o), w, c.o), c.o)
    var u2 = from_mont(mont_mul(to_mont(r, c.o), w, c.o), c.o)
    var q = Point[N](
        to_mont(from_be[N](pub[1 : 1 + 8 * N]), c.f), to_mont(from_be[N](pub[1 + 8 * N :]), c.f), mont_one(c.f)
    )
    var gq = point_add(c.g, q, c.b, c.f)
    var acc = identity(c.f)
    for i in range(64 * N - 1, -1, -1):
        acc = point_double(acc, c.b, c.f)
        var b1 = (u1[i >> 6] >> UInt64(i & 63)) & 1
        var b2 = (u2[i >> 6] >> UInt64(i & 63)) & 1
        if b1 == 1 and b2 == 1:
            acc = point_add(acc, gq, c.b, c.f)
        elif b1 == 1:
            acc = point_add(acc, c.g, c.b, c.f)
        elif b2 == 1:
            acc = point_add(acc, q, c.b, c.f)
    if is_zero(acc.z) == 1:
        return False
    var x = from_mont(mont_mul(acc.x, mont_inv(acc.z, c.f), c.f), c.f)
    return is_zero(sub(reduce_once(x, 0, c.o), r, c.o)) == 1


struct P256Key(Movable):
    var d: List[UInt8]
    var pub: List[UInt8]

    def __init__(out self, d: Span[UInt8, _]) raises:
        var c = p256()
        if len(d) != 32 or not in_range(from_be[4](d), c.o):
            raise Error("tls: p256 private key out of range")
        self.d = List[UInt8](d)
        self.pub = pub_bytes(from_be[4](d), c)

    @staticmethod
    def generate() raises -> Self:
        var c = p256()
        while True:
            var d = random_bytes(32)
            if in_range(from_be[4](d), c.o):
                return Self(d)

    def public_bytes(self) -> List[UInt8]:
        return self.pub.copy()

    def ecdh(self, peer: Span[UInt8, _]) raises -> List[UInt8]:
        return ecdh(from_be[4](self.d), peer, p256())

    def sign_sha256(self, msg_hash: Span[UInt8, _]) raises -> List[UInt8]:
        if len(msg_hash) != 32:
            raise Error("tls: sign_sha256 needs a 32-byte hash")
        return ecdsa_sign(from_be[4](self.d), msg_hash, p256())

    def zeroize(mut self):
        wipe(self.d)


def p256_verify(pub: Span[UInt8, _], hash: Span[UInt8, _], der_sig: Span[UInt8, _]) -> Bool:
    return ecdsa_verify(pub, hash, der_sig, p256())


def p384_verify(pub: Span[UInt8, _], hash: Span[UInt8, _], der_sig: Span[UInt8, _]) -> Bool:
    return ecdsa_verify(pub, hash, der_sig, p384())


def p384_sign(d: Span[UInt8, _], hash: Span[UInt8, _]) raises -> List[UInt8]:
    """ECDSA P-384 signature (DER) over a 48-byte SHA-384 digest with the 48-byte private scalar `d`."""
    var c = p384()
    if len(d) != 48 or not in_range(from_be[6](d), c.o) or len(hash) != 48:
        raise Error("tls: p384 sign needs a 48-byte key in range and a 48-byte hash")
    return ecdsa_sign(from_be[6](d), hash, c)


def p384_public(d: Span[UInt8, _]) raises -> List[UInt8]:
    """Uncompressed public point of the 48-byte private scalar `d` (ephemeral ECDH, secp384r1)."""
    var c = p384()
    if len(d) != 48 or not in_range(from_be[6](d), c.o):
        raise Error("tls: p384 private key out of range")
    return pub_bytes(from_be[6](d), c)


def p384_ecdh(d: Span[UInt8, _], peer: Span[UInt8, _]) raises -> List[UInt8]:
    if len(d) != 48:
        raise Error("tls: p384 private key out of range")
    return ecdh(from_be[6](d), peer, p384())
