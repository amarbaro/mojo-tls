"""TLS 1.2 handshake message codecs (RFC 5246 7.4, 7627, 8422, 5746). Parsers are strict and bounds checked:
trailing bytes, duplicate extensions and bad lengths raise. Unknown suites, groups, extensions and GREASE
values are skipped, never an error. Builders return whole handshake messages (type, u24 length, body)."""
from .wire import Rd, bl, p16, p24, put, pre8, pre16, bytes_of, str_of, is_ip

comptime CCS = 20
comptime ALERT = 21
comptime HAND = 22
comptime APP = 23
comptime H_CH = 1
comptime H_SH = 2
comptime H_CERT = 11
comptime H_SKE = 12
comptime H_CREQ = 13
comptime H_SHD = 14
comptime H_CV = 15
comptime H_CKE = 16
comptime H_FIN = 20
comptime A_CLOSE = 0
comptime A_UNEXPECTED = 10
comptime A_BAD_MAC = 20
comptime A_OVERFLOW = 22
comptime A_HANDSHAKE = 40
comptime A_BAD_CERT = 42
comptime A_ILLEGAL = 47
comptime A_DECODE = 50
comptime A_DECRYPT = 51
comptime A_VERSION = 70
comptime A_INTERNAL = 80
comptime A_NO_ALPN = 120
comptime MAX_MSG = 65536  # one handshake message
comptime MAX_HS = 262144  # all handshake bytes of one connection
comptime G_X25519 = 0x001D
comptime G_P256 = 0x0017
comptime G_P384 = 0x0018
# our TLS 1.2 suites, server preference order; AEAD 0 = AES-128-GCM, 1 = AES-256-GCM, 2 = ChaCha20-Poly1305


def suites() -> List[Int]:
    return [0xC02B, 0xCCA9, 0xC02C, 0xC02F, 0xCCA8, 0xC030]


def suite_known(s: Int) -> Bool:
    return s == 0xC02B or s == 0xC02C or s == 0xC02F or s == 0xC030 or s == 0xCCA8 or s == 0xCCA9


def suite_aead(s: Int) -> Int:
    return 2 if s >= 0xCCA8 else (1 if s == 0xC02C or s == 0xC030 else 0)


def suite_sha384(s: Int) -> Bool:
    return s == 0xC02C or s == 0xC030


def suite_ecdsa(s: Int) -> Bool:
    return s == 0xC02B or s == 0xC02C or s == 0xCCA9


def hs(typ: Int, body: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8]()
    o.append(UInt8(typ))
    p24(o, len(body))
    put(o, body)
    return o^


def _ext(mut o: List[UInt8], typ: Int, body: List[UInt8]):
    p16(o, typ)
    put(o, pre16(body))


def _list16(vals: List[Int]) -> List[UInt8]:
    var o = List[UInt8]()
    for v in vals:
        p16(o, v)
    return pre16(o)


struct ClientHello(Movable):
    var legacy: Int
    var random: List[UInt8]
    var sid: List[UInt8]
    var suites: List[Int]
    var sni: String
    var alpn: List[String]
    var groups: List[Int]
    var sigalgs: List[Int]
    var versions: List[Int]  # supported_versions, empty when absent
    var ems: Bool
    var ri: Bool  # renegotiation_info extension or SCSV seen
    var ri_bad: Bool  # renegotiation_info with a non-empty value on an initial handshake
    var points: Bool  # ec_point_formats offered (uncompressed is mandatory when present)

    def __init__(out self):
        self.legacy = 0
        self.random = List[UInt8]()
        self.sid = List[UInt8]()
        self.suites = List[Int]()
        self.sni = String()
        self.alpn = List[String]()
        self.groups = List[Int]()
        self.sigalgs = List[Int]()
        self.versions = List[Int]()
        self.ems = False
        self.ri = False
        self.ri_bad = False
        self.points = False

    def offers13(self) -> Bool:
        return 0x0304 in self.versions

    def offers12(self) -> Bool:
        """TLS 1.2 is acceptable: listed in supported_versions, or legacy_version says 1.2+ with no such list."""
        return (0x0303 in self.versions) if len(self.versions) > 0 else self.legacy >= 0x0303


def _hostname(b: List[UInt8]) raises -> String:
    if len(b) == 0 or len(b) > 255:
        raise Error("tls: bad server_name")
    var o = List[UInt8]()
    for c in b:
        var x = Int(c)
        if x >= 65 and x <= 90:
            x += 32
        if not ((x >= 97 and x <= 122) or (x >= 48 and x <= 57) or x == 45 or x == 46 or x == 42 or x == 95):
            raise Error("tls: bad server_name")
        o.append(UInt8(x))
    return str_of(o)


def parse_client_hello(body: List[UInt8]) raises -> ClientHello:
    var r = Rd(body.copy())
    var ch = ClientHello()
    ch.legacy = r.u16()
    ch.random = r.take(32)
    ch.sid = r.vec8().d.copy()
    if len(ch.sid) > 32:
        raise Error("tls: session id too long")
    var cs = r.vec16()
    if cs.left() < 2 or cs.left() % 2 != 0:
        raise Error("tls: bad cipher suites")
    while cs.left() > 0:
        var s = cs.u16()
        ch.suites.append(s)
        if s == 0x00FF:
            ch.ri = True
    var zero = False
    var comp = r.vec8()
    while comp.left() > 0:
        var x = comp.u8()
        zero = zero or x == 0
    if not zero:
        raise Error("tls: no null compression")
    if r.left() == 0:
        return ch^
    var ex = r.vec16()
    if r.left() != 0:
        raise Error("tls: trailing bytes after extensions")
    var seen = List[Int]()
    while ex.left() > 0:
        var typ = ex.u16()
        var d = ex.vec16()
        if typ in seen:
            raise Error("tls: duplicate extension")
        seen.append(typ)
        if typ == 0x0000:
            var l = d.vec16()
            while l.left() > 0:
                var nt = l.u8()
                var nm = l.vec16().d.copy()
                if nt == 0 and ch.sni.byte_length() == 0:
                    ch.sni = _hostname(nm)
        elif typ == 0x000A:
            var l = d.vec16()
            while l.left() > 0:
                ch.groups.append(l.u16())
        elif typ == 0x000B:
            var l = d.vec8()
            var unc = False
            while l.left() > 0:
                var x = l.u8()
                unc = unc or x == 0
            if not unc:
                raise Error("tls: uncompressed point format missing")
            ch.points = True
        elif typ == 0x000D:
            var l = d.vec16()
            while l.left() > 0:
                ch.sigalgs.append(l.u16())
        elif typ == 0x0010:
            var l = d.vec16()
            while l.left() > 0:
                ch.alpn.append(str_of(l.vec8().d))
        elif typ == 0x0017:
            ch.ems = True
        elif typ == 0xFF01:
            ch.ri = True
            ch.ri_bad = d.vec8().left() != 0
        elif typ == 0x002B:
            var l = d.vec8()
            while l.left() > 0:
                ch.versions.append(l.u16())
        else:
            d.p = len(d.d)  # unknown or GREASE: skipped
        if d.left() != 0:
            raise Error("tls: trailing bytes in extension")
    return ch^


def choose_suite(ch: ClientHello, ecdsa_ok: Bool, rsa_ok: Bool) -> Int:
    """0 when nothing matches. Server order, except that a client listing ChaCha20 first (no AES hardware) is obeyed."""
    var order = suites()
    if len(ch.suites) > 0 and suite_known(ch.suites[0]) and suite_aead(ch.suites[0]) == 2:
        order = ch.suites.copy()
    for s in order:
        if suite_known(s) and s in ch.suites and ((ecdsa_ok and suite_ecdsa(s)) or (rsa_ok and not suite_ecdsa(s))):
            return s
    return 0


def choose_group(ch: ClientHello) -> Int:
    for g in ch.groups:
        if g == G_X25519 or g == G_P256 or g == G_P384:
            return g
    return 0


def sentinel(random: List[UInt8]) -> Bool:
    """RFC 8446 4.1.3 downgrade marker (TLS 1.2 = 01) in the last 8 bytes of a ServerHello random."""
    var m = bytes_of("DOWNGRD")
    m.append(1)
    for i in range(8):
        if random[24 + i] != m[i]:
            return False
    return True


def build_server_hello(random: List[UInt8], suite: Int, ems: Bool, ri: Bool, points: Bool, alpn: String, sni_ack: Bool) -> List[UInt8]:
    var b = List[UInt8]()
    p16(b, 0x0303)
    put(b, random)
    b.append(0)  # empty session id: no resumption
    p16(b, suite)
    b.append(0)
    var e = List[UInt8]()
    if sni_ack:
        _ext(e, 0x0000, List[UInt8]())
    if ri:
        _ext(e, 0xFF01, pre8(List[UInt8]()))
    if ems:
        _ext(e, 0x0017, List[UInt8]())
    if points:
        _ext(e, 0x000B, pre8(bl(0)))
    if alpn.byte_length() > 0:
        _ext(e, 0x0010, pre16(pre8(bytes_of(alpn))))
    put(b, pre16(e))
    return hs(H_SH, b)


def build_certificate(chain: List[List[UInt8]]) -> List[UInt8]:
    var c = List[UInt8]()
    for cert in chain:
        p24(c, len(cert))
        put(c, cert)
    var b = List[UInt8]()
    p24(b, len(c))
    put(b, c)
    return hs(H_CERT, b)


def ske_params(group: Int, pub: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8]()
    o.append(3)  # named_curve
    p16(o, group)
    put(o, pre8(pub))
    return o^


def build_ske(params: List[UInt8], scheme: Int, sig: List[UInt8]) -> List[UInt8]:
    var b = params.copy()
    p16(b, scheme)
    put(b, pre16(sig))
    return hs(H_SKE, b)


def parse_cke(body: List[UInt8]) raises -> List[UInt8]:
    var r = Rd(body.copy())
    var pub = r.vec8().d.copy()
    if r.left() != 0 or len(pub) == 0:
        raise Error("tls: bad client key exchange")
    return pub^


def build_creq(schemes: List[Int]) -> List[UInt8]:
    """CertificateRequest (RFC 5246 7.4.4): rsa_sign and ecdsa_sign, our signature schemes, no CA list."""
    var b = List[UInt8]()
    put(b, pre8([UInt8(1), 64]))
    put(b, pre16(_list16(schemes)))
    p16(b, 0)
    return hs(H_CREQ, b)


def parse_creq(body: List[UInt8]) raises -> List[Int]:
    """The signature schemes of a CertificateRequest."""
    var r = Rd(body.copy())
    _ = r.vec8()
    var l = r.vec16()
    _ = r.vec16()
    if r.left() != 0 or l.left() == 0 or l.left() % 2 != 0:
        raise Error("tls: bad certificate request")
    var o = List[Int]()
    while l.left() > 0:
        o.append(l.u16())
    return o^


def build_cv(scheme: Int, sig: List[UInt8]) -> List[UInt8]:
    var b = List[UInt8]()
    p16(b, scheme)
    put(b, pre16(sig))
    return hs(H_CV, b)


def parse_cv(body: List[UInt8]) raises -> Tuple[Int, List[UInt8]]:
    var r = Rd(body.copy())
    var s = r.u16()
    var sig = r.vec16().d.copy()
    if r.left() != 0 or len(sig) == 0:
        raise Error("tls: bad certificate verify")
    return (s, sig^)


# ---- client side ----


def build_client_hello(random: List[UInt8], host: String, alpn: List[String], offer13: Bool, offered: List[Int]) -> List[UInt8]:
    var b = List[UInt8]()
    p16(b, 0x0303)
    put(b, random)
    b.append(0)
    var cs = List[UInt8]()
    for s in offered:
        p16(cs, s)
    put(b, pre16(cs))
    b.append(1)
    b.append(0)
    var e = List[UInt8]()
    if host.byte_length() > 0 and not is_ip(host):
        _ext(e, 0x0000, pre16(bl(0) + pre16(bytes_of(host))))
    _ext(e, 0xFF01, pre8(List[UInt8]()))
    _ext(e, 0x0017, List[UInt8]())
    _ext(e, 0x000A, _list16([G_X25519, G_P256, G_P384]))
    _ext(e, 0x000B, pre8(bl(0)))
    _ext(e, 0x000D, _list16([0x0403, 0x0503, 0x0804, 0x0805, 0x0401, 0x0501]))
    if len(alpn) > 0:
        var a = List[UInt8]()
        for n in alpn:
            put(a, pre8(bytes_of(n)))
        _ext(e, 0x0010, pre16(a))
    if offer13:
        _ext(e, 0x002B, pre8(bl(3, 4, 3, 3)))
    put(b, pre16(e))
    return hs(H_CH, b)


struct ServerHello(Movable):
    var random: List[UInt8]
    var suite: Int
    var ems: Bool
    var ri: Bool
    var ri_bad: Bool
    var alpn: String

    def __init__(out self):
        self.random = List[UInt8]()
        self.suite = 0
        self.ems = False
        self.ri = False
        self.ri_bad = False
        self.alpn = String()


def parse_server_hello(body: List[UInt8]) raises -> ServerHello:
    var r = Rd(body.copy())
    var sh = ServerHello()
    if r.u16() != 0x0303:
        raise Error("tls: server did not select TLS 1.2")
    sh.random = r.take(32)
    _ = r.vec8()
    sh.suite = r.u16()
    if r.u8() != 0:
        raise Error("tls: compression selected")
    if r.left() == 0:
        return sh^
    var ex = r.vec16()
    if r.left() != 0:
        raise Error("tls: trailing bytes after extensions")
    var seen = List[Int]()
    while ex.left() > 0:
        var typ = ex.u16()
        var d = ex.vec16()
        if typ in seen:
            raise Error("tls: duplicate extension")
        seen.append(typ)
        if typ == 0x0017:
            sh.ems = True
        elif typ == 0xFF01:
            sh.ri = True
            sh.ri_bad = d.vec8().left() != 0
        elif typ == 0x0010:
            var l = d.vec16()
            sh.alpn = str_of(l.vec8().d)
            if l.left() != 0:
                raise Error("tls: server chose several protocols")
        elif typ == 0x0000 or typ == 0x000B:
            d.p = len(d.d)  # allowed, content not needed
        else:
            raise Error("tls: unsolicited extension")
        if d.left() != 0:
            raise Error("tls: trailing bytes in extension")
    return sh^


def parse_certificate(body: List[UInt8]) raises -> List[List[UInt8]]:
    var r = Rd(body.copy())
    var l = r.vec24()
    if r.left() != 0:
        raise Error("tls: trailing bytes after certificates")
    var chain = List[List[UInt8]]()
    while l.left() > 0:
        var c = l.vec24().d.copy()
        if len(c) == 0 or len(chain) >= 10:
            raise Error("tls: bad certificate list")
        chain.append(c^)
    if len(chain) == 0:
        raise Error("tls: empty certificate list")
    return chain^


struct Ske(Movable):
    var group: Int
    var pub: List[UInt8]
    var scheme: Int
    var sig: List[UInt8]
    var params: List[UInt8]

    def __init__(out self):
        self.group = 0
        self.pub = List[UInt8]()
        self.scheme = 0
        self.sig = List[UInt8]()
        self.params = List[UInt8]()


def parse_ske(body: List[UInt8]) raises -> Ske:
    var r = Rd(body.copy())
    var s = Ske()
    if r.u8() != 3:
        raise Error("tls: not a named curve")
    s.group = r.u16()
    s.pub = r.vec8().d.copy()
    s.params = List[UInt8](body[0 : r.p])
    s.scheme = r.u16()
    s.sig = r.vec16().d.copy()
    if r.left() != 0 or len(s.pub) == 0 or len(s.sig) == 0:
        raise Error("tls: bad server key exchange")
    return s^
