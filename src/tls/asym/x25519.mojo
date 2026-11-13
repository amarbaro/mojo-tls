# X25519 (RFC 7748 section 5): Montgomery ladder over GF(2^255-19) using the generic Montgomery field of bn.mojo.
from .bn import *


def _field() -> Modulus[4]:
    var m = Fe[4](fill=0xFFFFFFFFFFFFFFFF)
    m[0] = 0xFFFFFFFFFFFFFFED
    m[3] = 0x7FFFFFFFFFFFFFFF
    return Modulus[4](m)


def _le(b: Span[UInt8, _]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b) - 1, -1, -1):
        out.append(b[i])
    return out^


def ladder[N: Int](
    var k: List[UInt8], bits: Int, point: Span[UInt8, _], md: Modulus[N], a24v: UInt64
) raises -> List[UInt8]:
    """RFC 7748 section 5 ladder over `md` (k already clamped, `bits` ladder steps, u little endian, 8N bytes).
    Raises on an all-zero result (low-order input), as RFC 8446 section 7.4.2 requires of TLS."""
    var x1 = reduce_once(from_be[N](_le(point)), 0, md)  # u < 2^(64N) < 2p
    x1 = to_mont(x1, md)
    var one = mont_one(md)
    var a24 = to_mont(small[N](a24v), md)
    var x2 = one.copy()
    var z2 = zero[N]()
    var x3 = x1.copy()
    var z3 = one.copy()
    var swap: UInt64 = 0
    for t in range(bits - 1, -1, -1):
        var kt = UInt64((k[t >> 3] >> UInt8(t & 7)) & 1)
        swap ^= kt
        cswap(x2, x3, swap)
        cswap(z2, z3, swap)
        swap = kt
        var a = add(x2, z2, md)
        var aa = mont_mul(a, a, md)
        var b = sub(x2, z2, md)
        var bb = mont_mul(b, b, md)
        var e = sub(aa, bb, md)
        var c = add(x3, z3, md)
        var d = sub(x3, z3, md)
        var da = mont_mul(d, a, md)
        var cb = mont_mul(c, b, md)
        var s = add(da, cb, md)
        var df = sub(da, cb, md)
        x3 = mont_mul(s, s, md)
        z3 = mont_mul(x1, mont_mul(df, df, md), md)
        x2 = mont_mul(aa, bb, md)
        z2 = mont_mul(e, add(aa, mont_mul(a24, e, md), md), md)
    cswap(x2, x3, swap)
    cswap(z2, z3, swap)
    var r = from_mont(mont_mul(x2, mont_inv(z2, md), md), md)
    var out = _le(to_be(r))
    var acc: UInt8 = 0
    for i in range(8 * N):
        acc |= out[i]
    for i in range(len(k)):
        k[i] = 0
    if acc == 0:
        raise Error("tls: low-order point")
    return out^


def x25519(scalar: Span[UInt8, _], point: Span[UInt8, _]) raises -> List[UInt8]:
    """Scalar mult of the u-coordinate `point` (32 bytes LE, bit 255 ignored)."""
    if len(scalar) != 32 or len(point) != 32:
        raise Error("tls: x25519 needs 32-byte inputs")
    var k = List[UInt8](scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    var u = List[UInt8](point)
    u[31] &= 127
    return ladder(k^, 255, u, _field(), 121665)


def x25519_base(scalar: Span[UInt8, _]) raises -> List[UInt8]:
    var nine = List[UInt8](length=32, fill=0)
    nine[0] = 9
    return x25519(scalar, nine)
