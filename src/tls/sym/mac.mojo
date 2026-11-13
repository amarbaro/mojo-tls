"""HMAC (RFC 2104), HKDF (RFC 5869), HKDF-Expand-Label (RFC 8446 7.1) and the TLS 1.2 PRF (RFC 5246 5)."""
from tls.sym.sha2 import Hash


def wipe(mut b: List[UInt8]):
    for i in range(len(b)):
        b[i] = 0


def hmac[H: Hash](key: Span[UInt8, ImmutAnyOrigin], data: Span[UInt8, ImmutAnyOrigin]) -> List[UInt8]:
    var k = List[UInt8](length=H.BLOCK, fill=0)
    if len(key) > H.BLOCK:
        var kh = H()
        kh.update(key)
        var d = kh.digest()
        for i in range(len(d)):
            k[i] = d[i]
        wipe(d)
    else:
        for i in range(len(key)):
            k[i] = key[i]
    for i in range(H.BLOCK):
        k[i] ^= 0x36
    var inner = H()
    inner.update(k)
    inner.update(data)
    var d = inner.digest()
    for i in range(H.BLOCK):
        k[i] ^= 0x36 ^ 0x5C
    var outer = H()
    outer.update(k)
    outer.update(d)
    wipe(k)
    return outer.digest()


def hkdf_extract[H: Hash](salt: Span[UInt8, ImmutAnyOrigin], ikm: Span[UInt8, ImmutAnyOrigin]) -> List[UInt8]:
    """An empty salt is HashLen zero bytes: HMAC zero-pads its key, so the same call covers both."""
    return hmac[H](salt, ikm)


def hkdf_expand[H: Hash](prk: Span[UInt8, ImmutAnyOrigin], info: Span[UInt8, ImmutAnyOrigin], n: Int) raises -> List[UInt8]:
    if n < 0 or n > 255 * H.OUT:
        raise Error("tls: hkdf output too long")
    var out = List[UInt8](capacity=n + H.OUT)
    var t = List[UInt8]()
    var i = 1
    while len(out) < n:
        var m = t.copy()
        m.extend(info)
        m.append(UInt8(i))
        t = hmac[H](prk, m)
        out.extend(Span(t))
        i += 1
    out.shrink(n)
    return out^


def hkdf_expand_label[H: Hash](
    secret: Span[UInt8, ImmutAnyOrigin], label: StringSlice[_], context: Span[UInt8, ImmutAnyOrigin], n: Int
) raises -> List[UInt8]:
    if label.byte_length() > 249 or len(context) > 255 or n > 0xFFFF:
        raise Error("tls: hkdf label too long")
    var info: List[UInt8] = [UInt8(n >> 8), UInt8(n & 0xFF), UInt8(6 + label.byte_length())]
    info.extend("tls13 ".as_bytes())
    info.extend(label.as_bytes())
    info.append(UInt8(len(context)))
    info.extend(context)
    return hkdf_expand[H](secret, info, n)


def prf12[H: Hash](secret: Span[UInt8, ImmutAnyOrigin], label: StringSlice[_], seed: Span[UInt8, ImmutAnyOrigin], n: Int) -> List[UInt8]:
    """P_hash(secret, label | seed): A(i) = HMAC(secret, A(i-1)), output HMAC(secret, A(i) | label | seed)."""
    var ls = List[UInt8](label.as_bytes())
    ls.extend(seed)
    var a = hmac[H](secret, ls)
    var out = List[UInt8](capacity=n + H.OUT)
    while len(out) < n:
        var m = a.copy()
        m.extend(Span(ls))
        out.extend(hmac[H](secret, m))
        var nx = hmac[H](secret, a)
        a = nx^
    out.shrink(n)
    return out^
