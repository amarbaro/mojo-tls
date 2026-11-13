"""Shared test helpers: a three-certificate TlsConfig over the fake crypto, an in-memory pump between a Client12
and a Server12, hand-built records and ClientHellos, and PASS/FAIL accounting."""
from std.memory import ArcPointer
from fake_crypto import FakeCrypto
from tls.net.config import TlsConfig, CertEntry
from tls.tls12.client import Client12
from tls.tls12.crypto import K_P256, K_P384, K_RSA
from tls.tls12.msg import hs, H_CH, suites
from tls.tls12.server import Server12
from tls.tls12.wire import bl, bytes_of, p16, put, pre8, pre16

comptime Cl = Client12[FakeCrypto]
comptime Sv = Server12[FakeCrypto]


def cert_of(key: String) -> List[List[UInt8]]:
    var l = List[List[UInt8]]()
    l.append(bytes_of("cert:" + key))
    return l^


def make_cfg(tls13: Bool = True) -> ArcPointer[TlsConfig]:
    var c = TlsConfig()
    c.tls13 = tls13
    c.certs.append(CertEntry(["localhost"], cert_of("key-p256"), bytes_of("key-p256"), K_P256))
    c.certs.append(CertEntry(["*.example.org"], cert_of("key-p384"), bytes_of("key-p384"), K_P384))
    c.certs.append(CertEntry(["rsa.test"], cert_of("key-rsa"), bytes_of("key-rsa"), K_RSA))
    c.alpn = ["http/1.1"]
    return ArcPointer(c^)


def pump(mut c: Cl, mut s: Sv) raises:
    """Move bytes both ways until both sides are quiet. Raises what feed() raises."""
    for _ in range(50):
        var a = c.cn.take_output()
        var b = s.cn.take_output()
        if len(a) == 0 and len(b) == 0:
            return
        if len(a) > 0:
            s.feed(a)
        if len(b) > 0:
            c.feed(b)


def pump_bytes(mut c: Cl, mut s: Sv) raises:
    """Same, one byte per feed(): every parser must cope with any fragmentation."""
    for _ in range(200):
        var a = c.cn.take_output()
        var b = s.cn.take_output()
        if len(a) == 0 and len(b) == 0:
            return
        for i in range(len(a)):
            s.feed(Span(a)[i : i + 1])
        for i in range(len(b)):
            c.feed(Span(b)[i : i + 1])


def rec(typ: Int, body: List[UInt8]) -> List[UInt8]:
    var o = bl(typ, 3, 3)
    put(o, pre16(body))
    return o^


def started(host: String, alpn: List[String], offer13: Bool = False, offered: List[Int] = suites()) raises -> Cl:
    var c = Cl(host, alpn, offer13, offered)
    c.start()
    return c^


def mk_ch(
    legacy: Int = 0x0303,
    ems: Bool = True,
    ri: Int = 0,  # -1 absent, 0 empty value, 1 non-empty value
    versions: List[Int] = [],
    cs: List[Int] = [0xC02B, 0xC02F],
    groups: List[Int] = [0x001D, 0x0017],
    sigalgs: List[Int] = [0x0403, 0x0804],
    sni: String = "localhost",
    alpn: List[String] = [],
    extra: List[UInt8] = [],
    trailing: Int = 0,
) -> List[UInt8]:
    """A ClientHello handshake message; every field a test wants to break is a parameter."""
    var b = List[UInt8]()
    p16(b, legacy)
    put(b, List[UInt8](length=32, fill=9))
    b.append(0)
    var c = List[UInt8]()
    for s in cs:
        p16(c, s)
    put(b, pre16(c))
    put(b, bl(1, 0))
    var e = List[UInt8]()
    if sni.byte_length() > 0:
        p16(e, 0)
        put(e, pre16(pre16(bl(0) + pre16(bytes_of(sni)))))
    if ems:
        p16(e, 0x17)
        p16(e, 0)
    if ri >= 0:
        p16(e, 0xFF01)
        put(e, pre16(pre8(bl(1, 2) if ri == 1 else List[UInt8]())))
    if len(groups) > 0:
        var g = List[UInt8]()
        for x in groups:
            p16(g, x)
        p16(e, 0x0A)
        put(e, pre16(pre16(g)))
    if len(sigalgs) > 0:
        var g = List[UInt8]()
        for x in sigalgs:
            p16(g, x)
        p16(e, 0x0D)
        put(e, pre16(pre16(g)))
    if len(versions) > 0:
        var g = List[UInt8]()
        for x in versions:
            p16(g, x)
        p16(e, 0x2B)
        put(e, pre16(pre8(g)))
    if len(alpn) > 0:
        var g = List[UInt8]()
        for x in alpn:
            put(g, pre8(bytes_of(x)))
        p16(e, 0x10)
        put(e, pre16(pre16(g)))
    put(e, extra)
    put(b, pre16(e))
    for _ in range(trailing):
        b.append(0xAA)
    return hs(H_CH, b)


struct T:
    var ok: Int
    var bad: Int

    def __init__(out self):
        self.ok = 0
        self.bad = 0

    def check(mut self, name: String, cond: Bool, why: String = ""):
        if cond:
            self.ok += 1
            print("PASS", name)
        else:
            self.bad += 1
            print("FAIL", name + ":", why)

    def done(self) raises:
        print("RESULT ok=" + String(self.ok), "bad=" + String(self.bad))
        if self.bad > 0:
            raise Error("FAIL: " + String(self.bad) + " checks")
