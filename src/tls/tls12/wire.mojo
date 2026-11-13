"""TLS wire helpers: a bounds-checked reader and big-endian writers. Every peer length is checked
before use; a short read raises Error("tls: short read") and never indexes out of range."""


struct Rd(Copyable, Movable):
    var d: List[UInt8]
    var p: Int

    def __init__(out self, var d: List[UInt8]):
        self.d = d^
        self.p = 0

    def left(self) -> Int:
        return len(self.d) - self.p

    def u8(mut self) raises -> Int:
        if self.p >= len(self.d):
            raise Error("tls: short read")
        self.p += 1
        return Int(self.d[self.p - 1])

    def u16(mut self) raises -> Int:
        return (self.u8() << 8) | self.u8()

    def u24(mut self) raises -> Int:
        return (self.u16() << 8) | self.u8()

    def take(mut self, n: Int) raises -> List[UInt8]:
        if n < 0 or n > self.left():
            raise Error("tls: short read")
        self.p += n
        return List[UInt8](self.d[self.p - n : self.p])

    def sub(mut self, n: Int) raises -> Rd:
        """A reader over the next n bytes (a length-prefixed vector)."""
        return Rd(self.take(n))

    def vec8(mut self) raises -> Rd:
        return self.sub(self.u8())

    def vec16(mut self) raises -> Rd:
        return self.sub(self.u16())

    def vec24(mut self) raises -> Rd:
        return self.sub(self.u24())


def bl(*v: Int) -> List[UInt8]:
    var o = List[UInt8]()
    for x in v:
        o.append(UInt8(x))
    return o^


def cat(*parts: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8]()
    for p in parts:
        o.extend(p.copy())
    return o^


def p16(mut o: List[UInt8], v: Int):
    o.append(UInt8((v >> 8) & 255))
    o.append(UInt8(v & 255))


def p24(mut o: List[UInt8], v: Int):
    o.append(UInt8((v >> 16) & 255))
    p16(o, v)


def put(mut o: List[UInt8], b: List[UInt8]):
    o.extend(b.copy())


def bytes_of(s: String) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def str_of(b: List[UInt8]) -> String:
    """Bytes as a String, one code point per byte (Latin-1, like tls13.wire): the peer's bytes are never UTF-8 we checked."""
    var s = String()
    for c in b:
        s += chr(Int(c))
    return s^


def is_ip(host: String) -> Bool:
    """An IPv4 or IPv6 literal: RFC 6066 3 forbids it in server_name."""
    var dots = True
    for c in host.as_bytes():
        if c == 58:
            return True
        dots = dots and (c == 46 or (c >= 48 and c <= 57))
    return dots and host.byte_length() > 0


def pre8(b: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8]()
    o.append(UInt8(len(b)))
    put(o, b)
    return o^


def pre16(b: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8]()
    p16(o, len(b))
    put(o, b)
    return o^


def ct_eq(a: List[UInt8], b: List[UInt8]) -> Bool:
    """Equal contents, OR-accumulated (the length is public)."""
    if len(a) != len(b):
        return False
    var acc = UInt8(0)
    for i in range(len(a)):
        acc |= a[i] ^ b[i]
    return acc == 0


def wipe(mut b: List[UInt8]):
    for i in range(len(b)):
        b[i] = 0
