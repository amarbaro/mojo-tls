# Strict DER reader (X.690): views into the input, no copies. Every read is bounds-checked and raises
# "tls: der: ..." on malformed input: indefinite or non-minimal lengths, non-minimal INTEGER/OID,
# BOOLEAN other than 00/FF, bad BIT STRING, bad times, high tag numbers.

comptime Bytes = Span[UInt8, ImmUntrackedOrigin]


def view(s: Span[UInt8, _]) -> Bytes:
    """Untracked view: the owner must stay alive past the last use of the view (keep a later `_ = len(owner)`).
    For comparisons pass the owner itself (`same(a, b)`), which borrows it for the call."""
    return rebind[Bytes](s)


def copy_of(b: Bytes) -> List[UInt8]:
    var o = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        o.append(b[i])
    return o^


def same(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _hv(c: UInt8) -> Int:
    return Int(c) - 48 if c < 58 else Int(c) - 87


def hex_is(a: Span[UInt8, _], h: StringLiteral) -> Bool:
    """True when `a` equals the bytes spelled by lowercase hex string `h` (OID contents, DigestInfo prefixes)."""
    var hb = h.as_bytes()
    if len(hb) != 2 * len(a):
        return False
    for i in range(len(a)):
        if Int(a[i]) != _hv(hb[2 * i]) * 16 + _hv(hb[2 * i + 1]):
            return False
    return True


def be_int(b: Bytes) raises -> Int:
    if len(b) > 7:
        raise Error("tls: der: integer too large")
    var v = 0
    for i in range(len(b)):
        v = (v << 8) | Int(b[i])
    return v


def _days(y: Int, m: Int, d: Int) -> Int:
    """Days since 1970-01-01 (proleptic Gregorian, Hinnant's algorithm)."""
    var yy = y - 1 if m <= 2 else y
    var era = yy // 400
    var yoe = yy - era * 400
    var mp = (m + 9) % 12
    var doy = (153 * mp + 2) // 5 + d - 1
    var doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def parse_time(tag: Int, c: Bytes) raises -> Int:
    """UTCTime (0x17, YYMMDDHHMMSSZ, pivot 50) or GeneralizedTime (0x18, YYYYMMDDHHMMSSZ) to epoch seconds."""
    var n = 13 if tag == 0x17 else 15
    if (tag != 0x17 and tag != 0x18) or len(c) != n or c[n - 1] != 90:
        raise Error("tls: der: bad time")
    var v = List[Int]()
    for i in range(n - 1):
        if c[i] < 48 or c[i] > 57:
            raise Error("tls: der: bad time")
        v.append(Int(c[i]) - 48)
    var k = 0
    var y = 0
    if tag == 0x17:
        y = v[0] * 10 + v[1]
        y += 1900 if y >= 50 else 2000
        k = 2
    else:
        y = v[0] * 1000 + v[1] * 100 + v[2] * 10 + v[3]
        k = 4
    var mo = v[k] * 10 + v[k + 1]
    var d = v[k + 2] * 10 + v[k + 3]
    var hh = v[k + 4] * 10 + v[k + 5]
    var mi = v[k + 6] * 10 + v[k + 7]
    var ss = v[k + 8] * 10 + v[k + 9]
    var leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    var dim = 31
    if mo == 4 or mo == 6 or mo == 9 or mo == 11:
        dim = 30
    elif mo == 2:
        dim = 29 if leap else 28
    if mo < 1 or mo > 12 or d < 1 or d > dim or hh > 23 or mi > 59 or ss > 59:
        raise Error("tls: der: bad time")
    return _days(y, mo, d) * 86400 + hh * 3600 + mi * 60 + ss


struct Der(Copyable, Movable):
    var b: Bytes
    var p: Int
    var full: Bytes  # whole TLV of the last element read (the TBS bytes, raw names)
    var tag: Int  # tag of the last element read
    var unused: Int  # unused bits of the last BIT STRING read

    def __init__(out self, b: Bytes):
        self.b = b
        self.p = 0
        self.full = b
        self.tag = 0
        self.unused = 0

    def done(self) -> Bool:
        return self.p >= len(self.b)

    def peek(self) -> Int:
        return Int(self.b[self.p]) if self.p < len(self.b) else -1

    def next(mut self, want: Int = -1) raises -> Bytes:
        """Read one TLV, return its contents. `want` >= 0 requires that tag."""
        var n = len(self.b)
        if self.p + 2 > n:
            raise Error("tls: der: truncated")
        var t = Int(self.b[self.p])
        if (t & 0x1F) == 0x1F:
            raise Error("tls: der: high tag number")
        if want >= 0 and t != want:
            raise Error("tls: der: unexpected tag")
        var q = self.p + 1
        var l = Int(self.b[q])
        q += 1
        if l >= 0x80:
            var k = l - 0x80
            if k == 0 or k > 4 or q + k > n:
                raise Error("tls: der: bad length")
            if self.b[q] == 0:
                raise Error("tls: der: non-minimal length")
            l = 0
            for i in range(k):
                l = (l << 8) | Int(self.b[q + i])
            if l < 0x80:
                raise Error("tls: der: non-minimal length")
            q += k
        if l > n - q:
            raise Error("tls: der: truncated")
        self.tag = t
        self.full = self.b[self.p : q + l]
        self.p = q + l
        return self.b[q : q + l]

    def sub(mut self, want: Int) raises -> Der:
        return Der(self.next(want))

    def wrap(mut self, want: Int) raises -> Der:
        """[want] EXPLICIT wrapper around exactly one SEQUENCE: returns that SEQUENCE's contents."""
        var w = Der(self.next(want))
        var s = w.seq()
        w.end()
        return s^

    def wint(mut self, want: Int) raises -> Int:
        """[want] EXPLICIT wrapper around one small INTEGER."""
        var w = Der(self.next(want))
        var v = w.small_int()
        w.end()
        return v

    def seq(mut self) raises -> Der:
        return Der(self.next(0x30))

    def end(self) raises:
        if self.p != len(self.b):
            raise Error("tls: der: trailing data")

    def int_raw(mut self) raises -> Bytes:
        """INTEGER contents, minimal two's complement, sign not checked."""
        var c = self.next(0x02)
        if len(c) == 0:
            raise Error("tls: der: empty integer")
        if len(c) > 1 and ((c[0] == 0 and c[1] < 0x80) or (c[0] == 0xFF and c[1] >= 0x80)):
            raise Error("tls: der: non-minimal integer")
        return c

    def int_bytes(mut self) raises -> Bytes:
        """Positive INTEGER as big-endian magnitude without the sign byte."""
        var c = self.int_raw()
        if c[0] >= 0x80:
            raise Error("tls: der: negative integer")
        return c[1:] if c[0] == 0 and len(c) > 1 else c

    def small_int(mut self) raises -> Int:
        return be_int(self.int_bytes())

    def oid(mut self) raises -> Bytes:
        var c = self.next(0x06)
        if len(c) == 0 or c[len(c) - 1] >= 0x80:
            raise Error("tls: der: bad oid")
        for i in range(len(c)):
            if c[i] == 0x80 and (i == 0 or c[i - 1] < 0x80):
                raise Error("tls: der: non-minimal oid")
        return c

    def bits(mut self) raises -> Bytes:
        """BIT STRING contents after the unused-bits octet; `unused` holds that octet."""
        var c = self.next(0x03)
        if len(c) == 0 or c[0] > 7 or (len(c) == 1 and c[0] != 0):
            raise Error("tls: der: bad bit string")
        self.unused = Int(c[0])
        return c[1:]

    def octets(mut self) raises -> Bytes:
        return self.next(0x04)

    def boolean(mut self) raises -> Bool:
        var c = self.next(0x01)
        if len(c) != 1 or (c[0] != 0 and c[0] != 0xFF):
            raise Error("tls: der: bad boolean")
        return c[0] == 0xFF

    def null(mut self) raises:
        if len(self.next(0x05)) != 0:
            raise Error("tls: der: bad null")

    def time(mut self) raises -> Int:
        if self.peek() != 0x17 and self.peek() != 0x18:
            raise Error("tls: der: bad time")
        var c = self.next()
        return parse_time(self.tag, c)
