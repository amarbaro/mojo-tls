# RSA: PKCS#1 v1.5 and PSS verify (RFC 8017), PSS sign with CRT, exponent blinding and a fault check.
# Moduli of exactly 2048, 3072 or 4096 bits. PSS salt length = hash length (RFC 8446 section 4.2.3).
from .bn import *
from .random import random_bytes
from .sha2 import sha2


def _strip(b: Span[UInt8, _]) -> List[UInt8]:
    var i = 0
    while i < len(b) - 1 and b[i] == 0:
        i += 1
    return List[UInt8](b[i:])


def _digest_info(alg: Int) -> List[UInt8]:
    var t: List[UInt8] = [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
    if alg == 384:
        t = [0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
    elif alg == 512:
        t = [0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
    return t^


def _pkcs1_em(alg: Int, hash: Span[UInt8, _], k: Int) -> List[UInt8]:
    """EMSA-PKCS1-v1_5: 00 01 FF..FF 00 DigestInfo hash, k bytes."""
    var t = _digest_info(alg)
    t.extend(hash)
    var em = List[UInt8](length=k, fill=0xFF)
    em[0] = 0
    em[1] = 1
    em[k - len(t) - 1] = 0
    for i in range(len(t)):
        em[k - len(t) + i] = t[i]
    return em^


def _mgf1(alg: Int, seed: Span[UInt8, _], n: Int) -> List[UInt8]:
    var out = List[UInt8]()
    var ctr = 0
    while len(out) < n:
        var m = List[UInt8](seed)
        for sh in range(3, -1, -1):
            m.append(UInt8((ctr >> (8 * sh)) & 0xFF))
        out.extend(Span(sha2(alg, m)))
        ctr += 1
    out.shrink(n)
    return out^


def _pub_op[N: Int](n: Span[UInt8, _], e: UInt64, s: Span[UInt8, _]) -> List[UInt8]:
    """s^e mod n as 8N bytes (RSAVP1); empty when s >= n. Variable time: only public data."""
    var md = Modulus[N](from_be[N](n))
    var sv = from_be[N](s)
    if lt(sv, md.m) == 0:
        return List[UInt8]()
    var sm = to_mont(sv, md)
    var r = sm.copy()
    var tb = 63
    while (e >> UInt64(tb)) & 1 == 0:
        tb -= 1
    for i in range(tb - 1, -1, -1):
        r = mont_mul(r, r, md)
        if (e >> UInt64(i)) & 1 == 1:
            r = mont_mul(r, sm, md)
    return to_be(from_mont(r, md))


def _pub(n: Span[UInt8, _], e: UInt64, s: Span[UInt8, _]) -> List[UInt8]:
    if len(s) != len(n):
        return List[UInt8]()
    if len(n) == 256:
        return _pub_op[32](n, e, s)
    if len(n) == 384:
        return _pub_op[48](n, e, s)
    return _pub_op[64](n, e, s)


def _check_pub(n: Span[UInt8, _], e: Span[UInt8, _]) raises -> UInt64:
    if (len(n) != 256 and len(n) != 384 and len(n) != 512) or n[0] < 0x80 or n[len(n) - 1] & 1 == 0:
        raise Error("tls: unsupported rsa modulus")
    var ev: UInt64 = 0
    if len(e) > 4:
        raise Error("tls: rsa exponent too large")
    for i in range(len(e)):
        ev = (ev << 8) | UInt64(e[i])
    if ev < 3 or ev & 1 == 0:
        raise Error("tls: bad rsa exponent")
    return ev


struct RsaPublic(Copyable, Movable):
    var n: List[UInt8]
    var e: UInt64

    def __init__(out self, n: Span[UInt8, _], e: Span[UInt8, _]) raises:
        self.n = _strip(n)
        self.e = _check_pub(self.n, _strip(e))

    def verify_pkcs1(self, hash_alg: Int, hash: Span[UInt8, _], sig: Span[UInt8, _]) -> Bool:
        var em = _pub(self.n, self.e, sig)
        var k = len(self.n)
        if len(em) != k or len(hash) != hash_alg // 8:
            return False
        var want = _pkcs1_em(hash_alg, hash, k)  # compared in full, never parsed
        var diff: UInt8 = 0
        for i in range(k):
            diff |= want[i] ^ em[i]
        return diff == 0

    def verify_pss(self, hash_alg: Int, hash: Span[UInt8, _], sig: Span[UInt8, _], salt_len: Int = -1) -> Bool:
        """salt_len -1 means the hash length (TLS 1.3); certificates name theirs (RFC 4055, default 20)."""
        var em = _pub(self.n, self.e, sig)
        var k = len(self.n)
        var hl = hash_alg // 8
        var sl = hl if salt_len < 0 else salt_len
        if len(em) != k or len(hash) != hl or em[k - 1] != 0xBC or em[0] & 0x80 != 0 or k < hl + sl + 2:
            return False
        var dl = k - hl - 1
        var h = List[UInt8](Span(em)[dl : dl + hl])
        var mask = _mgf1(hash_alg, h, dl)
        var db = List[UInt8](length=dl, fill=0)
        for i in range(dl):
            db[i] = em[i] ^ mask[i]
        db[0] &= 0x7F
        var sep = dl - sl - 1  # zeros, then 0x01, then the salt
        for i in range(sep):
            if db[i] != 0:
                return False
        if db[sep] != 1:
            return False
        var m2 = List[UInt8](length=8, fill=0)
        m2.extend(hash)
        m2.extend(Span(db)[sep + 1 :])
        var h2 = sha2(hash_alg, m2)
        return h2 == h


def _half_mod[H: Int](c: Fe[2 * H], md: Modulus[H]) -> Fe[H]:
    """c mod m for a 2H-limb c and an m with its top bit set."""
    var lo = Fe[H](fill=0)
    var hi = Fe[H](fill=0)
    for i in range(H):
        lo[i] = c[i]
        hi[i] = c[H + i]
    return add(mont_mul(hi, md.r2, md), reduce_once(lo, 0, md), md)  # hi*R + lo


def _blind_exp[H: Int](d: Fe[H], p: Fe[H], r: UInt64) -> Fe[H + 1]:
    """d + r*(p-1): same power for any base coprime to p, but a different bit pattern on every call."""
    var e = Fe[H + 1](fill=0)
    var pm1 = p.copy()
    pm1[0] -= 1
    var c: UInt64 = 0
    var c2: UInt64 = 0
    for i in range(H):
        var t = mac(0, pm1[i], r, c)
        c = t[1]
        var s = adc(t[0], d[i], c2)
        e[i] = s[0]
        c2 = s[1]
    e[H] = c + c2
    return e^


def _crt_half[H: Int](c: Fe[2 * H], d: Fe[H], md: Modulus[H]) raises -> Fe[H]:
    var r = from_be[1](random_bytes(8))[0]
    var m = pow_ct(to_mont(_half_mod[H](c, md), md), _blind_exp(d, md.m, r), md)
    return from_mont(m, md)


def _sign_crt[H: Int](
    n: Span[UInt8, _], e: UInt64, p: Span[UInt8, _], q: Span[UInt8, _], dp: Span[UInt8, _], dq: Span[UInt8, _],
    qinv: Span[UInt8, _], em: Span[UInt8, _],
) raises -> List[UInt8]:
    var mp = Modulus[H](from_be[H](p))
    var mq = Modulus[H](from_be[H](q))
    var c = from_be[2 * H](em)
    var sp = _crt_half[H](c, from_be[H](dp), mp)
    var sq = _crt_half[H](c, from_be[H](dq), mq)
    var diff = sub(sp, reduce_once(sq, 0, mp), mp)
    var hh = mont_mul(to_mont(from_be[H](qinv), mp), diff, mp)  # qinv*(sp - sq) mod p
    var s = Fe[2 * H](fill=0)  # sq + hh*q
    var qv = from_be[H](q)
    for i in range(H):
        var carry: UInt64 = 0
        for j in range(H):
            var t = mac(s[i + j], hh[i], qv[j], carry)
            s[i + j] = t[0]
            carry = t[1]
        s[i + H] = carry
    var carry: UInt64 = 0
    for i in range(2 * H):
        var t = adc(s[i], sq[i] if i < H else 0, carry)
        s[i] = t[0]
        carry = t[1]
    var out = to_be(s)
    if _pub_op[2 * H](n, e, out) != List[UInt8](em):  # a faulty CRT half would leak p or q
        raise Error("tls: rsa signing fault")
    return out^


struct RsaPrivate(Copyable, Movable):
    var pk: RsaPublic
    var p: List[UInt8]
    var q: List[UInt8]
    var dp: List[UInt8]
    var dq: List[UInt8]
    var qinv: List[UInt8]

    def __init__(
        out self, n: Span[UInt8, _], e: Span[UInt8, _], p: Span[UInt8, _], q: Span[UInt8, _], dp: Span[UInt8, _],
        dq: Span[UInt8, _], qinv: Span[UInt8, _],
    ) raises:
        self.pk = RsaPublic(n, e)
        self.p = _strip(p)
        self.q = _strip(q)
        self.dp = _strip(dp)
        self.dq = _strip(dq)
        self.qinv = _strip(qinv)
        var h = len(self.pk.n) // 2
        if len(self.p) != h or len(self.q) != h or self.p[0] < 0x80 or self.q[0] < 0x80 or len(self.dp) > h or len(self.dq) > h or len(self.qinv) > h:
            raise Error("tls: bad rsa private key")

    def public(self) -> RsaPublic:
        return self.pk.copy()

    def sign_pss(self, hash_alg: Int, hash: Span[UInt8, _]) raises -> List[UInt8]:
        var k = len(self.pk.n)
        var hl = hash_alg // 8
        if len(hash) != hl:
            raise Error("tls: bad hash length")
        var salt = random_bytes(hl)
        var m2 = List[UInt8](length=8, fill=0)
        m2.extend(hash)
        m2.extend(Span(salt))
        var h = sha2(hash_alg, m2)
        var dl = k - hl - 1
        var db = List[UInt8](length=dl, fill=0)
        db[dl - hl - 1] = 1
        for i in range(hl):
            db[dl - hl + i] = salt[i]
        var mask = _mgf1(hash_alg, h, dl)
        var em = List[UInt8](capacity=k)
        for i in range(dl):
            em.append(db[i] ^ mask[i])
        em[0] &= 0x7F
        em.extend(Span(h))
        em.append(0xBC)
        return self._sign(em)

    def sign_pkcs1(self, hash_alg: Int, hash: Span[UInt8, _]) raises -> List[UInt8]:
        """RSASSA-PKCS1-v1_5, for TLS 1.2 peers that do not offer PSS (deterministic)."""
        if len(hash) != hash_alg // 8:
            raise Error("tls: bad hash length")
        return self._sign(_pkcs1_em(hash_alg, hash, len(self.pk.n)))

    def _sign(self, em: Span[UInt8, _]) raises -> List[UInt8]:
        var k = len(self.pk.n)
        if k == 256:
            return _sign_crt[16](self.pk.n, self.pk.e, self.p, self.q, self.dp, self.dq, self.qinv, em)
        if k == 384:
            return _sign_crt[24](self.pk.n, self.pk.e, self.p, self.q, self.dp, self.dq, self.qinv, em)
        return _sign_crt[32](self.pk.n, self.pk.e, self.p, self.q, self.dp, self.dq, self.qinv, em)

    def zeroize(mut self):
        for i in range(len(self.p)):
            self.p[i] = 0
        for i in range(len(self.q)):
            self.q[i] = 0
        for i in range(len(self.dp)):
            self.dp[i] = 0
        for i in range(len(self.dq)):
            self.dq[i] = 0
        for i in range(len(self.qinv)):
            self.qinv[i] = 0


def _d_ok[N: Int](n: Span[UInt8, _], e: UInt64, d: Span[UInt8, _]) -> Bool:
    var md = Modulus[N](from_be[N](n))
    var m = Fe[N](fill=0)
    m[0] = 2
    var s = from_mont(pow_ct(to_mont(m, md), from_be[N](d), md), md)
    return _pub_op[N](n, e, to_be(s)) == to_be(m)


def rsa_d_ok(n: Span[UInt8, _], e: Span[UInt8, _], d: Span[UInt8, _]) raises -> Bool:
    """(2^d)^e == 2 mod n: the private exponent d belongs to (n, e). Constant time in d."""
    var nn = _strip(n)
    var ee = _check_pub(nn, _strip(e))
    var dd = _strip(d)
    if len(dd) > len(nn):
        return False
    var k = len(nn)
    if k == 256:
        return _d_ok[32](nn, ee, dd)
    if k == 384:
        return _d_ok[48](nn, ee, dd)
    if k == 512:
        return _d_ok[64](nn, ee, dd)
    return False
