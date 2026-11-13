# mojo-tls lane 4: byte helpers, alert names and a bounds-checked reader.
# Errors are Error("tls: <alert_name>: <what>"); the state machines map the name to the alert they send.


def bad(name: String, what: String) -> Error:
    return Error("tls: " + name + ": " + what)


def _alerts() -> List[Tuple[Int, String]]:
    return [
        (0, "close_notify"), (10, "unexpected_message"), (20, "bad_record_mac"), (22, "record_overflow"),
        (40, "handshake_failure"), (42, "bad_certificate"), (43, "unsupported_certificate"),
        (44, "certificate_revoked"), (45, "certificate_expired"), (46, "certificate_unknown"),
        (47, "illegal_parameter"), (48, "unknown_ca"), (50, "decode_error"), (51, "decrypt_error"),
        (70, "protocol_version"), (71, "insufficient_security"), (80, "internal_error"),
        (86, "inappropriate_fallback"), (90, "user_canceled"), (109, "missing_extension"),
        (110, "unsupported_extension"), (112, "unrecognized_name"), (116, "certificate_required"),
        (120, "no_application_protocol"),
    ]


def alert_name(code: Int) -> String:
    for t in _alerts():
        if t[0] == code:
            return t[1]
    return "alert_" + String(code)


def alert_of(msg: String) -> Int:
    """Alert code for an error message built by bad(); internal_error for anything else."""
    if not msg.startswith("tls: "):
        return 80
    var parts = msg.split(": ")
    if len(parts) < 2:
        return 80
    for t in _alerts():
        if t[1] == String(parts[1]):
            return t[0]
    return 80


def put8(mut o: List[UInt8], v: Int):
    o.append(UInt8(v & 0xFF))


def put16(mut o: List[UInt8], v: Int):
    o.append(UInt8((v >> 8) & 0xFF))
    o.append(UInt8(v & 0xFF))


def put24(mut o: List[UInt8], v: Int):
    o.append(UInt8((v >> 16) & 0xFF))
    o.append(UInt8((v >> 8) & 0xFF))
    o.append(UInt8(v & 0xFF))


def put32(mut o: List[UInt8], v: Int):
    put16(o, v >> 16)
    put16(o, v & 0xFFFF)


def putb(mut o: List[UInt8], b: List[UInt8]):
    o.extend(Span(b))


def vec8(b: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8](capacity=len(b) + 1)
    put8(o, len(b))
    putb(o, b)
    return o^


def vec16(b: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8](capacity=len(b) + 2)
    put16(o, len(b))
    putb(o, b)
    return o^


def vec24(b: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8](capacity=len(b) + 3)
    put24(o, len(b))
    putb(o, b)
    return o^


def is_ip(host: String) -> Bool:
    """An IPv4 or IPv6 literal: RFC 6066 3 forbids it in server_name."""
    var dots = True
    for c in host.as_bytes():
        if c == 58:
            return True
        dots = dots and (c == 46 or (c >= 48 and c <= 57))
    return dots and host.byte_length() > 0


def bytes_of(s: String) -> List[UInt8]:
    var o = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        o.append(b)
    return o^


def str_of(b: List[UInt8]) -> String:
    var s = String()
    for c in b:
        s += chr(Int(c))
    return s^


def ct_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    """Equality that takes the same time for any content of equal length."""
    if len(a) != len(b):
        return False
    var acc: UInt8 = 0
    for i in range(len(a)):
        acc |= a[i] ^ b[i]
    return acc == 0


def wipe(mut b: List[UInt8]):
    for i in range(len(b)):
        b[i] = 0


struct Rd(Copyable, Movable):
    """Reader over a private copy of the bytes; every read checks the remaining length first."""

    var b: List[UInt8]
    var p: Int

    def __init__(out self, var b: List[UInt8]):
        self.b = b^
        self.p = 0

    def left(self) -> Int:
        return len(self.b) - self.p

    def _at(self, i: Int) -> Int:
        """Byte i, or 0 past the end: a missed need() check then shows as wrong data, never as an out-of-bounds trap."""
        return Int(self.b[i]) if i < len(self.b) else 0

    def need(self, n: Int) raises:
        if n < 0 or n > len(self.b) - self.p:
            raise bad("decode_error", "message too short")

    def u8(mut self) raises -> Int:
        self.need(1)
        self.p += 1
        return self._at(self.p - 1)

    def u16(mut self) raises -> Int:
        self.need(2)
        self.p += 2
        return (self._at(self.p - 2) << 8) | self._at(self.p - 1)

    def u24(mut self) raises -> Int:
        self.need(3)
        self.p += 3
        return (self._at(self.p - 3) << 16) | (self._at(self.p - 2) << 8) | self._at(self.p - 1)

    def u32(mut self) raises -> Int:
        var hi = self.u16()
        return (hi << 16) | self.u16()

    def take(mut self, n: Int) raises -> List[UInt8]:
        self.need(n)
        var o = List[UInt8](capacity=n)
        for i in range(n):
            o.append(UInt8(self._at(self.p + i)))
        self.p += n
        return o^

    def rest(self) -> List[UInt8]:
        """The unread bytes (a copy; does not advance, use on a reader that is dropped after)."""
        var o = List[UInt8](capacity=self.left())
        for i in range(self.p, len(self.b)):
            o.append(self.b[i])
        return o^

    def sub8(mut self) raises -> Rd:
        return Rd(self.take(self.u8()))

    def sub16(mut self) raises -> Rd:
        return Rd(self.take(self.u16()))

    def sub24(mut self) raises -> Rd:
        return Rd(self.take(self.u24()))

    def done(self) raises:
        if self.left() != 0:
            raise bad("decode_error", "trailing bytes")
