# Constant-time Montgomery arithmetic over N x 64-bit limbs, generic in N.
# Design and the CIOS loop follow Mosaad-M-tls crypto/ec_ct.mojo (MIT, (c) 2026 mmosaad);
# Montgomery constants are computed here, never hard-coded.
# Secret-dependent code never branches or indexes on a secret: masks and fixed loops only.

comptime Fe[N: Int] = Array[UInt64, N]


@always_inline
def adc(a: UInt64, b: UInt64, c: UInt64) -> Tuple[UInt64, UInt64]:
    var s = UInt128(a) + UInt128(b) + UInt128(c)
    return (UInt64(s), UInt64(s >> 64))


@always_inline
def sbb(a: UInt64, b: UInt64, c: UInt64) -> Tuple[UInt64, UInt64]:
    var d = UInt128(a) - UInt128(b) - UInt128(c)
    return (UInt64(d), UInt64(d >> 127))


@always_inline
def mac(t: UInt64, a: UInt64, b: UInt64, c: UInt64) -> Tuple[UInt64, UInt64]:
    var s = UInt128(t) + UInt128(a) * UInt128(b) + UInt128(c)
    return (UInt64(s), UInt64(s >> 64))


def zero[N: Int]() -> Fe[N]:
    return Fe[N](fill=0)


def small[N: Int](v: UInt64) -> Fe[N]:
    var a = Fe[N](fill=0)
    a[0] = v
    return a^


def from_be[N: Int](b: Span[UInt8, _]) -> Fe[N]:
    """Big-endian bytes to limbs, right-aligned. Leading zero bytes beyond 8N are skipped; any other byte beyond 8N
    gives all-ones (at least every modulus, so callers that compare with a modulus reject it) instead of a write out of bounds.
    """
    var a = Fe[N](fill=0)
    var n = len(b)
    for i in range(n):
        var k = n - 1 - i
        if k >= 8 * N:
            if b[i] != 0:
                return Fe[N](fill=~UInt64(0))
            continue
        a[k >> 3] |= UInt64(b[i]) << UInt64(8 * (k & 7))
    return a^


def to_be[N: Int](a: Fe[N]) -> List[UInt8]:
    var out = List[UInt8](capacity=8 * N)
    for k in range(8 * N - 1, -1, -1):
        out.append(UInt8((a[k >> 3] >> UInt64(8 * (k & 7))) & 0xFF))
    return out^


def eq_mask(a: Int, b: Int) -> UInt64:
    """All ones when a == b (both in [0, 2^63)), else 0, by arithmetic only so no compiler turns it into a branch."""
    return UInt64(0) - (((UInt64(a) ^ UInt64(b)) - 1) >> 63)


def is_zero[N: Int](a: Fe[N]) -> UInt64:
    var acc: UInt64 = 0
    comptime for i in range(N):
        acc |= a[i]
    return ((acc | (UInt64(0) - acc)) >> 63) ^ 1


def lt[N: Int](a: Fe[N], b: Fe[N]) -> UInt64:
    """1 if a < b."""
    var br: UInt64 = 0
    comptime for i in range(N):
        br = sbb(a[i], b[i], br)[1]
    return br


def select[N: Int](mask: UInt64, a: Fe[N], b: Fe[N]) -> Fe[N]:
    """a where mask is all ones, else b."""
    var r = Fe[N](fill=0)
    comptime for i in range(N):
        r[i] = (a[i] & mask) | (b[i] & ~mask)
    return r^


def cswap[N: Int](mut a: Fe[N], mut b: Fe[N], bit: UInt64):
    var mask = UInt64(0) - bit
    comptime for i in range(N):
        var t = (a[i] ^ b[i]) & mask
        a[i] ^= t
        b[i] ^= t


struct Modulus[N: Int](Copyable, Movable):
    """Odd modulus m of 64N bits with R = 2^(64N): m0inv = -m^-1 mod 2^64, r2 = R^2 mod m."""
    var m: Fe[Self.N]
    var r2: Fe[Self.N]
    var m0inv: UInt64

    def __init__(out self, m: Fe[Self.N]):
        self.m = m.copy()
        self.r2 = Fe[Self.N](fill=0)
        var inv = m[0]
        for _ in range(6):
            inv *= 2 - m[0] * inv
        self.m0inv = UInt64(0) - inv
        # R^2 = 2^(128N): double up to 2^(64N + k0), then Montgomery-square k0 -> 2^6 * N
        var k0 = Self.N
        var sq = 6
        while k0 & 1 == 0:
            k0 >>= 1
            sq += 1
        var x = Fe[Self.N](fill=0)  # R mod m = (R - m) minus m while it is >= m (m is public or only its size is used)
        var br: UInt64 = 0
        for i in range(Self.N):
            var d = sbb(0, m[i], br)
            x[i] = d[0]
            br = d[1]
        while lt(x, m) == 0:
            br = 0
            for i in range(Self.N):
                var d = sbb(x[i], m[i], br)
                x[i] = d[0]
                br = d[1]
        for _ in range(k0):
            x = add(x, x, self)
        for _ in range(sq):
            x = mont_mul(x, x, self)
        self.r2 = x^


def reduce_once[N: Int](a: Fe[N], hi: UInt64, md: Modulus[N]) -> Fe[N]:
    """(a + hi*R) mod m for a + hi*R < 2m, one masked subtraction."""
    var d = Fe[N](fill=0)
    var br: UInt64 = 0
    comptime for i in range(N):
        var s = sbb(a[i], md.m[i], br)
        d[i] = s[0]
        br = s[1]
    return select(UInt64(0) - (hi | (br ^ 1)), d, a)


def add[N: Int](a: Fe[N], b: Fe[N], md: Modulus[N]) -> Fe[N]:
    var r = Fe[N](fill=0)
    var c: UInt64 = 0
    comptime for i in range(N):
        var s = adc(a[i], b[i], c)
        r[i] = s[0]
        c = s[1]
    return reduce_once(r, c, md)


def sub[N: Int](a: Fe[N], b: Fe[N], md: Modulus[N]) -> Fe[N]:
    var r = Fe[N](fill=0)
    var br: UInt64 = 0
    comptime for i in range(N):
        var d = sbb(a[i], b[i], br)
        r[i] = d[0]
        br = d[1]
    var mask = UInt64(0) - br
    var c: UInt64 = 0
    comptime for i in range(N):
        var s = adc(r[i], md.m[i] & mask, c)
        r[i] = s[0]
        c = s[1]
    return r^


@always_inline
def _row[N: Int](mut t: Array[UInt64, N + 2], a: Fe[N], bi: UInt64, md: Modulus[N]):
    var c: UInt64 = 0
    comptime if N <= 32:
        comptime for j in range(N):
            var uv = mac(t[j], a[j], bi, c)
            t[j] = uv[0]
            c = uv[1]
    else:
        for j in range(N):
            var uv = mac(t[j], a[j], bi, c)
            t[j] = uv[0]
            c = uv[1]
    var top = adc(t[N], c, 0)
    t[N] = top[0]
    t[N + 1] = top[1]
    var mq = t[0] * md.m0inv
    var uv = mac(t[0], mq, md.m[0], 0)
    c = uv[1]
    comptime if N <= 32:
        comptime for j in range(1, N):
            uv = mac(t[j], mq, md.m[j], c)
            t[j - 1] = uv[0]
            c = uv[1]
    else:
        for j in range(1, N):
            uv = mac(t[j], mq, md.m[j], c)
            t[j - 1] = uv[0]
            c = uv[1]
    var hi = adc(t[N], c, 0)
    t[N - 1] = hi[0]
    t[N] = t[N + 1] + hi[1]
    t[N + 1] = 0


def mont_mul[N: Int](a: Fe[N], b: Fe[N], md: Modulus[N]) -> Fe[N]:
    """a*b/R mod m (CIOS)."""
    var t = Array[UInt64, N + 2](fill=0)
    comptime if N <= 32:
        comptime for i in range(N):
            _row(t, a, b[i], md)
    else:
        for i in range(N):
            _row(t, a, b[i], md)
    var r = Fe[N](fill=0)
    for i in range(N):
        r[i] = t[i]
    return reduce_once(r, t[N], md)


def to_mont[N: Int](a: Fe[N], md: Modulus[N]) -> Fe[N]:
    return mont_mul(a, md.r2, md)


def from_mont[N: Int](a: Fe[N], md: Modulus[N]) -> Fe[N]:
    return mont_mul(a, small[N](1), md)


def mont_one[N: Int](md: Modulus[N]) -> Fe[N]:
    return to_mont(small[N](1), md)


def pow_ct[N: Int, E: Int](a: Fe[N], e: Fe[E], md: Modulus[N]) -> Fe[N]:
    """a^e in the Montgomery domain: fixed 4-bit windows over all 64E bits, table read by full scan."""
    var tab = Array[UInt64, 16 * N](fill=0)
    var one = mont_one(md)
    var cur = one.copy()
    for k in range(16):
        comptime for i in range(N):
            tab[k * N + i] = cur[i]
        cur = mont_mul(cur, a, md)
    var r = one^
    for w in range(16 * E - 1, -1, -1):
        for _ in range(4):
            r = mont_mul(r, r, md)
        var nib = (e[w >> 4] >> UInt64(4 * (w & 15))) & 15
        var sel = Fe[N](fill=0)
        for k in range(16):
            var mask = eq_mask(k, Int(nib))
            comptime for i in range(N):
                sel[i] |= tab[k * N + i] & mask
        r = mont_mul(r, sel, md)
    return r^


def mont_inv[N: Int](a: Fe[N], md: Modulus[N]) -> Fe[N]:
    """a^-1 for prime m via a^(m-2) (0 maps to 0); the exponent is public."""
    var e = md.m.copy()
    e[0] -= 2
    return pow_ct(a, e, md)
