# mojo-tls lane 4: handshake message codecs (RFC 8446 4). A message is a List[UInt8] with its 4-byte header.
# Parsing keeps extensions as an ordered (type, body) list, so a parsed hello re-encodes byte for byte.
from tls.tls13.wire import Rd, bad, put8, put16, put24, put32, putb, vec8, vec16, vec24, bytes_of, str_of

comptime H_CH = 1
comptime H_SH = 2
comptime H_NST = 4
comptime H_EE = 8
comptime H_CERT = 11
comptime H_CR = 13
comptime H_CV = 15
comptime H_FIN = 20
comptime H_KU = 24
comptime H_MSGHASH = 254

comptime X_SNI = 0
comptime X_GROUPS = 10
comptime X_SIGALGS = 13
comptime X_ALPN = 16
comptime X_PADDING = 21
comptime X_PSK = 41
comptime X_EARLY = 42
comptime X_VERSIONS = 43
comptime X_COOKIE = 44
comptime X_PSK_MODES = 45
comptime X_KEYSHARE = 51
comptime X_RSL = 28

comptime G_X25519 = 0x001D
comptime G_P256 = 0x0017
comptime G_P384 = 0x0018
comptime G_X448 = 0x001E
comptime MAX_CHAIN = 10


def hrr_random() -> List[UInt8]:
    """SHA-256("HelloRetryRequest"), RFC 8446 4.1.3."""
    var o: List[UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ]
    return o^


def hs_msg(t: Int, body: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8](capacity=4 + len(body))
    put8(o, t)
    put24(o, len(body))
    putb(o, body)
    return o^


def hs_body(msg: List[UInt8], t: Int) raises -> Rd:
    """Check the header of a message of type t and return a reader over its body."""
    if len(msg) < 4 or Int(msg[0]) != t:
        raise bad("unexpected_message", "wrong handshake message type")
    var r = Rd(msg.copy())
    r.p = 1
    var n = r.u24()
    if n != len(msg) - 4:
        raise bad("decode_error", "handshake length field")
    return r^


struct Ext(Copyable, Movable):
    var t: Int
    var d: List[UInt8]

    def __init__(out self, t: Int, var d: List[UInt8]):
        self.t = t
        self.d = d^


def enc_exts(exts: List[Ext]) raises -> List[UInt8]:
    var body = List[UInt8]()
    for e in exts:
        put16(body, e.t)
        putb(body, vec16(e.d))
    if len(body) > 0xFFFF:
        raise bad("internal_error", "extensions too long")
    return vec16(body)


def parse_exts(mut r: Rd) raises -> List[Ext]:
    """Extensions block (u16 length first); a repeated type is illegal_parameter."""
    var b = r.sub16()
    var out = List[Ext]()
    while b.left() > 0:
        var t = b.u16()
        for e in out:
            if e.t == t:
                raise bad("illegal_parameter", "duplicate extension " + String(t))
        out.append(Ext(t, b.sub16().rest()))
    return out^


def find(exts: List[Ext], t: Int) -> Int:
    for i in range(len(exts)):
        if exts[i].t == t:
            return i
    return -1


struct Hello(Copyable, Movable):
    """ClientHello (server False) or ServerHello/HelloRetryRequest (server True)."""

    var server: Bool
    var ver: Int
    var random: List[UInt8]
    var sid: List[UInt8]
    var suites: List[Int]  # a ServerHello has exactly one
    var comp: List[UInt8]
    var exts: List[Ext]

    def __init__(out self, server: Bool, random: List[UInt8], sid: List[UInt8], suites: List[Int], var exts: List[Ext]):
        self.server = server
        self.ver = 0x0303
        self.random = random.copy()
        self.sid = sid.copy()
        self.suites = suites.copy()
        self.comp = [UInt8(0)]
        self.exts = exts^

    def is_hrr(self) -> Bool:
        return self.server and len(self.random) == 32 and self.random == hrr_random()

    def encode(self) raises -> List[UInt8]:
        var b = List[UInt8]()
        put16(b, self.ver)
        putb(b, self.random)
        putb(b, vec8(self.sid))
        if self.server:
            put16(b, self.suites[0])
            put8(b, 0)
        else:
            var s = List[UInt8]()
            for c in self.suites:
                put16(s, c)
            putb(b, vec16(s))
            putb(b, vec8(self.comp))
        putb(b, enc_exts(self.exts))
        return hs_msg(H_SH if self.server else H_CH, b)


def parse_hello(msg: List[UInt8], server: Bool) raises -> Hello:
    var r = hs_body(msg, H_SH if server else H_CH)
    var ver = r.u16()
    var random = r.take(32)
    var sid = r.sub8().rest()
    if len(sid) > 32:
        raise bad("illegal_parameter", "session id longer than 32")
    var suites = List[Int]()
    var comp = List[UInt8]()
    if server:
        suites.append(r.u16())
        comp.append(UInt8(r.u8()))
        if comp[0] != 0:
            raise bad("illegal_parameter", "compression method")
    else:
        var s = r.sub16()
        if s.left() < 2 or s.left() % 2 != 0:
            raise bad("decode_error", "cipher suite list")
        while s.left() > 0:
            suites.append(s.u16())
        comp = r.sub8().rest()
        if len(comp) == 0:
            raise bad("decode_error", "compression methods")
    var exts = parse_exts(r)
    r.done()
    var h = Hello(server, random, sid, suites, exts^)
    h.ver = ver
    h.comp = comp^
    return h^


def x_sni(host: String) -> Ext:
    var e = List[UInt8]()
    put8(e, 0)
    putb(e, vec16(bytes_of(host)))
    return Ext(X_SNI, vec16(e))


def x_u16s(t: Int, vals: List[Int]) -> Ext:
    var e = List[UInt8]()
    for v in vals:
        put16(e, v)
    return Ext(t, vec16(e))


def x_versions_client(vals: List[Int]) -> Ext:
    var e = List[UInt8]()
    for v in vals:
        put16(e, v)
    return Ext(X_VERSIONS, vec8(e))


def x_versions_server(v: Int) -> Ext:
    var e = List[UInt8]()
    put16(e, v)
    return Ext(X_VERSIONS, e^)


def x_keyshares(shares: List[Tuple[Int, List[UInt8]]]) -> Ext:
    var e = List[UInt8]()
    for s in shares:
        put16(e, s[0])
        putb(e, vec16(s[1]))
    return Ext(X_KEYSHARE, vec16(e))


def x_keyshare_server(group: Int, data: List[UInt8]) -> Ext:
    var e = List[UInt8]()
    put16(e, group)
    putb(e, vec16(data))
    return Ext(X_KEYSHARE, e^)


def x_keyshare_hrr(group: Int) -> Ext:
    var e = List[UInt8]()
    put16(e, group)
    return Ext(X_KEYSHARE, e^)


def x_alpn(protos: List[String]) -> Ext:
    var e = List[UInt8]()
    for p in protos:
        putb(e, vec8(bytes_of(p)))
    return Ext(X_ALPN, vec16(e))


def x_cookie(c: List[UInt8]) -> Ext:
    return Ext(X_COOKIE, vec16(c))


def x_rsl(v: Int) -> Ext:
    var e = List[UInt8]()
    put16(e, v)
    return Ext(X_RSL, e^)


def x_psk_modes() -> Ext:
    return Ext(X_PSK_MODES, [UInt8(1), UInt8(1)])


def x_psk_client(identity: List[UInt8], age: Int, binder_len: Int) -> Ext:
    """pre_shared_key of a ClientHello with one identity; the binder is zeros until the caller fills in the last bytes."""
    var ids = List[UInt8]()
    putb(ids, vec16(identity))
    put32(ids, age)
    var e = vec16(ids)
    putb(e, vec16(vec8(List[UInt8](length=binder_len, fill=0))))
    return Ext(X_PSK, e^)


def x_psk_server(selected: Int) -> Ext:
    var e = List[UInt8]()
    put16(e, selected)
    return Ext(X_PSK, e^)


def p_psk_modes(d: List[UInt8]) raises -> List[Int]:
    var r = Rd(d.copy())
    var l = r.sub8()
    r.done()
    var o = List[Int]()
    while l.left() > 0:
        o.append(l.u8())
    return o^


def p_psk_client(d: List[UInt8]) raises -> Tuple[List[Tuple[List[UInt8], Int]], List[List[UInt8]], Int]:
    """Client pre_shared_key: (identities with obfuscated age, binders, byte length of the binders vector with its u16 length)."""
    var r = Rd(d.copy())
    var ids = r.sub16()
    var bs = r.sub16()
    r.done()
    if ids.left() < 7 or bs.left() < 33:
        raise bad("decode_error", "pre_shared_key lists too short")
    var bl = bs.left() + 2
    var idl = List[Tuple[List[UInt8], Int]]()
    while ids.left() > 0:
        var id = ids.sub16().rest()
        if len(id) == 0:
            raise bad("decode_error", "empty PSK identity")
        idl.append((id^, ids.u32()))
    var bl2 = List[List[UInt8]]()
    while bs.left() > 0:
        var b = bs.sub8().rest()
        if len(b) < 32:
            raise bad("decode_error", "PSK binder shorter than 32")
        bl2.append(b^)
    return (idl^, bl2^, bl)


def p_sni(d: List[UInt8]) raises -> String:
    """First host_name of a server_name extension; empty when the list has none."""
    var r = Rd(d.copy())
    var l = r.sub16()
    r.done()
    while l.left() > 0:
        var t = l.u8()
        var name = l.sub16().rest()
        if t == 0:
            if len(name) == 0:
                raise bad("illegal_parameter", "empty host name")
            for i in range(len(name)):  # host names compare case-insensitively (RFC 6066 3): keep them lower case, like tls12
                if name[i] >= 65 and name[i] <= 90:
                    name[i] += 32
            return str_of(name)
    return String()


def p_u16s(d: List[UInt8]) raises -> List[Int]:
    var r = Rd(d.copy())
    var l = r.sub16()
    r.done()
    if l.left() % 2 != 0 or l.left() == 0:  # RFC 8446 4.2.3, 4.2.7: both vectors are <2..2^16-1>, an empty one is malformed
        raise bad("decode_error", "odd or empty u16 list")
    var o = List[Int]()
    while l.left() > 0:
        o.append(l.u16())
    return o^


def p_versions_client(d: List[UInt8]) raises -> List[Int]:
    var r = Rd(d.copy())
    var l = r.sub8()
    r.done()
    if l.left() < 2 or l.left() % 2 != 0:
        raise bad("decode_error", "supported_versions list")
    var o = List[Int]()
    while l.left() > 0:
        o.append(l.u16())
    return o^


def p_version_server(d: List[UInt8]) raises -> Int:
    var r = Rd(d.copy())
    var v = r.u16()
    r.done()
    return v


def p_keyshares(d: List[UInt8]) raises -> List[Tuple[Int, List[UInt8]]]:
    """Client key_share entries, each key exchange kept whole (an ML-KEM share is 1216 bytes and is skipped later)."""
    var r = Rd(d.copy())
    var l = r.sub16()
    r.done()
    var o = List[Tuple[Int, List[UInt8]]]()
    while l.left() > 0:
        var g = l.u16()
        for s in o:
            if s[0] == g:
                raise bad("illegal_parameter", "duplicate key share group")
        o.append((g, l.sub16().rest()))
    return o^


def p_keyshare_server(d: List[UInt8]) raises -> Tuple[Int, List[UInt8]]:
    var r = Rd(d.copy())
    var g = r.u16()
    var k = r.sub16().rest()
    r.done()
    return (g, k^)


def p_alpn(d: List[UInt8]) raises -> List[String]:
    var r = Rd(d.copy())
    var l = r.sub16()
    r.done()
    var o = List[String]()
    while l.left() > 0:
        var p = l.sub8().rest()
        if len(p) == 0:
            raise bad("illegal_parameter", "empty ALPN name")
        o.append(str_of(p))
    if len(o) == 0:
        raise bad("decode_error", "empty ALPN list")
    return o^


def p_cookie(d: List[UInt8]) raises -> List[UInt8]:
    var r = Rd(d.copy())
    var c = r.sub16().rest()
    r.done()
    if len(c) == 0:
        raise bad("decode_error", "empty cookie")
    return c^


def p_rsl(d: List[UInt8]) raises -> Int:
    var r = Rd(d.copy())
    var v = r.u16()
    r.done()
    if v < 64:
        raise bad("illegal_parameter", "record_size_limit below 64")
    return v


def enc_ee(exts: List[Ext]) raises -> List[UInt8]:
    return hs_msg(H_EE, enc_exts(exts))


def parse_ee(msg: List[UInt8]) raises -> List[Ext]:
    var r = hs_body(msg, H_EE)
    var e = parse_exts(r)
    r.done()
    return e^


def enc_cert(ctx: List[UInt8], chain: List[List[UInt8]]) raises -> List[UInt8]:
    var l = List[UInt8]()
    for c in chain:
        putb(l, vec24(c))
        put16(l, 0)  # no per-certificate extensions
    var b = vec8(ctx)
    putb(b, vec24(l))
    return hs_msg(H_CERT, b)


def parse_cert(msg: List[UInt8]) raises -> Tuple[List[UInt8], List[List[UInt8]]]:
    """(request context, DER chain); at most MAX_CHAIN entries, each non-empty."""
    var r = hs_body(msg, H_CERT)
    var ctx = r.sub8().rest()
    var l = r.sub24()
    r.done()
    var chain = List[List[UInt8]]()
    while l.left() > 0:
        if len(chain) == MAX_CHAIN:
            raise bad("illegal_parameter", "certificate chain longer than 10")
        var c = l.sub24().rest()
        if len(c) == 0:
            raise bad("decode_error", "empty certificate")
        chain.append(c^)
        _ = parse_exts(l)
    return (ctx^, chain^)


def enc_cv(scheme: Int, sig: List[UInt8]) -> List[UInt8]:
    var b = List[UInt8]()
    put16(b, scheme)
    putb(b, vec16(sig))
    return hs_msg(H_CV, b)


def parse_cv(msg: List[UInt8]) raises -> Tuple[Int, List[UInt8]]:
    var r = hs_body(msg, H_CV)
    var s = r.u16()
    var sig = r.sub16().rest()
    r.done()
    return (s, sig^)


def enc_fin(vd: List[UInt8]) -> List[UInt8]:
    return hs_msg(H_FIN, vd)


def parse_fin(msg: List[UInt8], h: Int) raises -> List[UInt8]:
    var r = hs_body(msg, H_FIN)
    if r.left() != h:
        raise bad("decode_error", "Finished length")
    return r.rest()


struct Ticket(Copyable, Movable):
    var lifetime: Int
    var age_add: Int
    var nonce: List[UInt8]
    var ticket: List[UInt8]
    var exts: List[Ext]

    def __init__(out self, lifetime: Int, age_add: Int, nonce: List[UInt8], ticket: List[UInt8], var exts: List[Ext]):
        self.lifetime = lifetime
        self.age_add = age_add
        self.nonce = nonce.copy()
        self.ticket = ticket.copy()
        self.exts = exts^

    def encode(self) raises -> List[UInt8]:
        var b = List[UInt8]()
        put32(b, self.lifetime)
        put32(b, self.age_add)
        putb(b, vec8(self.nonce))
        putb(b, vec16(self.ticket))
        putb(b, enc_exts(self.exts))
        return hs_msg(H_NST, b)


def parse_nst(msg: List[UInt8]) raises -> Ticket:
    var r = hs_body(msg, H_NST)
    var life = r.u32()
    var add = r.u32()
    var nonce = r.sub8().rest()
    var t = r.sub16().rest()
    if len(t) == 0:
        raise bad("decode_error", "empty ticket")
    var e = parse_exts(r)
    r.done()
    if life > 604800:
        raise bad("illegal_parameter", "ticket lifetime over 7 days")
    return Ticket(life, add, nonce, t, e^)


def enc_ku(request: Bool) -> List[UInt8]:
    return hs_msg(H_KU, [UInt8(1 if request else 0)])


def enc_cr(ctx: List[UInt8], exts: List[Ext]) raises -> List[UInt8]:
    var b = vec8(ctx)
    putb(b, enc_exts(exts))
    return hs_msg(H_CR, b)


def parse_cr(msg: List[UInt8]) raises -> Tuple[List[UInt8], List[Ext]]:
    """CertificateRequest: (context, extensions); signature_algorithms is required."""
    var r = hs_body(msg, H_CR)
    var ctx = r.sub8().rest()
    var e = parse_exts(r)
    r.done()
    if find(e, X_SIGALGS) < 0:
        raise bad("missing_extension", "CertificateRequest without signature_algorithms")
    return (ctx^, e^)
