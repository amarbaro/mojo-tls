# PEM (RFC 7468) over bytes: no String is ever built from file or key bytes except the printable-ASCII label.
# Base64 decode has no branch or table index on the character value (range masks), so it is safe for key text;
# the only data-dependent branches are on whitespace and '=', which are public layout.
from tls.x509.der import Bytes, view


@fieldwise_init
struct PemBlock(Copyable, Movable):
    var label: String
    var der: List[UInt8]


def _find(h: Bytes, needle: StringLiteral, start: Int) -> Int:
    var nb = needle.as_bytes()
    var n = len(nb)
    var i = start
    while i + n <= len(h):
        var ok = True
        for j in range(n):
            if h[i + j] != nb[j]:
                ok = False
                break
        if ok:
            return i
        i += 1
    return -1


def _in(c: Int, lo: Int, hi: Int) -> Int:
    """All-ones when lo <= c <= hi, else 0, without branching."""
    return ~(((c - lo) | (hi - c)) >> 63)


def b64_decode(s: Span[UInt8, _]) raises -> List[UInt8]:
    """Standard base64 with optional whitespace and '=' padding. Errors never name the offending byte."""
    var out = List[UInt8](capacity=len(s) * 3 // 4 + 3)
    var bad = 0
    var acc = 0
    var cnt = 0  # data characters seen
    var pad = 0
    for i in range(len(s)):
        var c = Int(s[i])
        if c == 32 or c == 10 or c == 13 or c == 9:
            continue
        if c == 61:
            pad += 1
            continue
        var up = _in(c, 65, 90)
        var lo = _in(c, 97, 122)
        var dg = _in(c, 48, 57)
        var pl = _in(c, 43, 43)
        var sl = _in(c, 47, 47)
        bad |= (~(up | lo | dg | pl | sl)) & 1
        bad |= 1 if pad > 0 else 0
        acc = (acc << 6) | ((up & (c - 65)) | (lo & (c - 71)) | (dg & (c + 4)) | (pl & 62) | (sl & 63))
        cnt += 1
        if cnt % 4 == 0:
            out.append(UInt8((acc >> 16) & 255))
            out.append(UInt8((acc >> 8) & 255))
            out.append(UInt8(acc & 255))
            acc = 0
    var r = cnt % 4
    if r == 2:
        out.append(UInt8((acc >> 4) & 255))
    elif r == 3:
        out.append(UInt8((acc >> 10) & 255))
        out.append(UInt8((acc >> 2) & 255))
    bad |= 1 if (r == 1 or pad != (4 - r) % 4) else 0
    if bad != 0:
        for i in range(len(out)):
            out[i] = 0
        raise Error("tls: pem: bad base64")
    return out^


def pem_spans(text: Bytes) -> List[Tuple[Bytes, Bytes]]:
    """(label, body) views of every well-formed BEGIN/END block, in file order."""
    var res = List[Tuple[Bytes, Bytes]]()
    var pos = 0
    while True:
        var b = _find(text, "-----BEGIN ", pos)
        if b < 0:
            break
        var ls = b + 11
        var le = _find(text, "-----", ls)
        pos = ls
        if le < 0:
            break
        var label = text[ls:le]
        var okl = le - ls <= 64
        for i in range(len(label)):
            if label[i] < 32 or label[i] > 126:
                okl = False
        if not okl:
            continue
        var bs = le + 5
        var e = _find(text, "-----END ", bs)
        if e < 0:
            break
        var te = e + 9 + len(label)
        pos = e + 9
        var tail = text[e + 9 : te]
        var okt = te + 5 <= len(text) and len(tail) == len(label)
        if okt:
            for i in range(len(label)):
                if tail[i] != label[i]:
                    okt = False
        if okt:
            for i in range(5):
                if text[te + i] != 45:
                    okt = False
        if okt:
            res.append((label, text[bs:e]))
            pos = te + 5
    return res^


def pem_blocks(text: Bytes) raises -> List[PemBlock]:
    """Decode every PEM block. Raises on the first bad base64 body."""
    var res = List[PemBlock]()
    for ref sp in pem_spans(text):
        var lb = sp[0]
        res.append(PemBlock(String(unsafe_from_utf8=lb), b64_decode(sp[1])))
    return res^
