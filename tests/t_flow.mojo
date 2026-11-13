"""Protocol logic over the fake crypto: handshakes for every suite and certificate kind, fragmentation, record
integrity, SNI/ALPN, downgrade sentinel, and every way a hostile peer can break the state machines."""
from std.memory import ArcPointer
from tutil import *
from tls.net.config import TlsConfig
from tls.net.server import TlsServer
from tls.tls12.msg import *
from fake_crypto import mix
from tls.tls12.wire import bl, bytes_of, str_of, cat, put
from tls.tls12.conn import Conn, EV_NONE


def rd(path: String) raises -> List[UInt8]:
    with open(path, "r") as f:
        return f.read_bytes()


def cauth12(mut t: T, name: String, key_of: String, roots_of: String, want_alert: Int, label: String) raises:
    """TLS 1.2 client certificate: `name` (empty: none) signed with the key of `key_of`, a server that trusts `roots_of`;
    want_alert -9 = the handshake completes and the server saw the certificate."""
    var dir = String(".work/gate/certs/")
    var cfg = make_cfg()
    cfg[].require_client_cert = True
    cfg[].client_roots.append(rd(dir + roots_of + ".der"))
    var c = started("localhost", ["http/1.1"], False, [0xC02B])
    if name.byte_length() > 0:
        var chain = List[List[UInt8]]()
        chain.append(rd(dir + name + ".crt.der"))
        c.set_client_cert(chain, rd(dir + (key_of if key_of.byte_length() > 0 else name) + ".key.der"))
    var s = Sv(cfg)
    var why = String()
    try:
        pump(c, s)
    except e:
        why = String(e)
    if want_alert == -9:
        t.check(label, c.cn.established and s.cn.established and name.byte_length() > 0 and s.client_cert == rd(dir + name + ".crt.der"), "established " + String(s.cn.established) + " " + why)
    else:
        t.check(label, not s.cn.established and s.cn.alert == want_alert, "alert " + String(s.cn.alert) + " (" + why + "), want " + String(want_alert))


def srv_alert(cfg: ArcPointer[TlsConfig], data: List[UInt8], mut why: String) -> Int:
    """Feed data to a fresh server: the alert it queued, or -9 when it accepted the bytes."""
    var s = Sv(cfg)
    try:
        s.feed(data)
    except e:
        why = String(e)
        return s.cn.alert
    return -9


def expect(mut t: T, name: String, cfg: ArcPointer[TlsConfig], data: List[UInt8], want: Int):
    var why = String()
    var got = srv_alert(cfg, data, why)
    t.check(name, got == want, "alert " + String(got) + " (" + why + "), want " + String(want))


def roundtrip(mut t: T, name: String, host: String, offered: List[Int], want_suite: Int) raises:
    var cfg = make_cfg()
    var c = started(host, ["http/1.1"], False, offered)
    var s = Sv(cfg)
    pump(c, s)
    var ok = c.cn.established and s.cn.established and c.cn.suite == want_suite and s.cn.suite == want_suite
    var big = List[UInt8]()
    for i in range(40000):
        big.append(UInt8(i * 7 & 255))
    c.cn.write_app(big)
    s.cn.write_app(bytes_of("pong"))
    pump(c, s)
    ok = ok and s.cn.take_app() == big and str_of(c.cn.take_app()) == "pong"
    t.check(name, ok, "suite " + String(c.cn.suite) + " established " + String(c.cn.established))


def main() raises:
    var t = T()
    var cfg = make_cfg()

    # every suite end to end: ECDSA suites on the P-256 cert, RSA suites on the RSA cert
    for s in suites():
        roundtrip(t, "suite " + hex(s), "rsa.test" if not suite_ecdsa(s) else "localhost", [s], s)
    roundtrip(t, "client lists ChaCha first: obeyed", "rsa.test", [0xCCA8, 0xC02F], 0xCCA8)
    roundtrip(t, "client lists GCM first: server order", "rsa.test", [0xC02F, 0xCCA8], 0xC02F)

    # record layer bytes, derived from the RFCs here and compared with what the engine put on the wire:
    # GCM (RFC 5246 6.2.3.3, 5288): nonce = salt(4) + explicit(8) with explicit = seq, sent in the record
    # ChaCha20 (RFC 7905): nonce = iv(12) xor (0^4 + seq), no explicit part. AAD = seq(8) type version length.
    for sx in [0xC02B, 0xCCA8]:
        var cw = started("rsa.test" if sx == 0xCCA8 else "localhost", [], False, [sx])
        var sw = Sv(cfg)
        pump(cw, sw)
        var seq = Int(cw.cn.wr.seq)
        var sq = List[UInt8]()
        for i in range(8):
            sq.append(UInt8((seq >> (56 - 8 * i)) & 255))
        var iv = cw.cn.wr.iv.copy()
        var nonce = List[UInt8]()
        if sx == 0xCCA8:
            for i in range(12):
                nonce.append(iv[i] if i < 4 else iv[i] ^ sq[i - 4])
        else:
            nonce = cat(iv, sq)
        var pt = bytes_of("abc")
        var aad = cat(sq, bl(23, 3, 3, 0, 3))
        var ks = mix(cat(cw.cn.wr.key, nonce), 3)
        var ct = List[UInt8]()
        for i in range(3):
            ct.append(pt[i] ^ ks[i])
        var tag = mix(cat(cw.cn.wr.key, nonce, aad, ct), 16)
        var body = cat(sq, ct, tag) if sx == 0xC02B else cat(ct, tag)
        cw.cn.write_app(pt)
        t.check("record bytes " + hex(sx) + ": nonce, AAD, explicit part", cw.cn.take_output() == cat(bl(23, 3, 3, 0, len(body)), body) and seq == 1, "seq " + String(seq))

    # fragmentation: one byte per feed
    var c = started("localhost", ["http/1.1"])
    var s = Sv(cfg)
    pump_bytes(c, s)
    t.check("byte-at-a-time handshake", c.cn.established and s.cn.established)

    # record integrity: tamper, replay, reorder
    c.cn.write_app(bytes_of("one"))
    var r1 = c.cn.take_output()
    c.cn.write_app(bytes_of("two"))
    var r2 = c.cn.take_output()
    var bad = r1.copy()
    bad[len(bad) - 1] ^= 1
    var s2 = Sv(cfg)
    var c2 = started("localhost", ["http/1.1"])
    pump(c2, s2)
    c2.cn.write_app(bytes_of("one"))
    var q1 = c2.cn.take_output()
    q1[len(q1) - 1] ^= 1
    try:
        s2.feed(q1)
        t.check("tampered record rejected", False, "accepted")
    except:
        t.check("tampered record rejected", s2.cn.alert == A_BAD_MAC and s2.cn.dead)
        var out = s2.cn.take_output()
        t.check("fatal alert queued", len(out) > 0 and out[0] == 21)
    s.feed(r1)
    t.check("record 1 accepted", str_of(s.cn.take_app()) == "one")
    try:
        s.feed(r1)
        t.check("replayed record rejected", False, "accepted")
    except:
        t.check("replayed record rejected", s.cn.alert == A_BAD_MAC)
    var s3 = Sv(cfg)
    var c3 = started("localhost", ["http/1.1"])
    pump(c3, s3)
    c3.cn.write_app(bytes_of("one"))
    var p1 = c3.cn.take_output()
    c3.cn.write_app(bytes_of("two"))
    var p2 = c3.cn.take_output()
    try:
        s3.feed(p2)
        t.check("reordered record rejected", False, "accepted")
    except:
        t.check("reordered record rejected", s3.cn.alert == A_BAD_MAC)
    var why0 = String()
    t.check("incomplete record header is just waited for", True if srv_alert(cfg, bl(1), why0) == -9 else False)
    try:
        s3.feed(p1)
        t.check("dead connection refuses input", False)
    except:
        t.check("dead connection refuses input", True)

    # SNI selection
    t.check("sni exact", cfg[].order("localhost")[0] == 0)
    t.check("sni wildcard", cfg[].order("x.example.org")[0] == 1)
    t.check("sni wildcard is one label", cfg[].order("a.b.example.org")[0] == 0 and cfg[].order("example.org")[0] == 0)
    t.check("sni unknown: default first, all offered", cfg[].order("nope.test") == [0, 1, 2])
    var cw = started("x.example.org", ["http/1.1"])
    var sw = Sv(cfg)
    pump(cw, sw)
    t.check("wildcard cert served", cw.cn.established and cw.chain[0] == bytes_of("cert:key-p384"))
    var cu = started("UPPER.Example.ORG", [])
    var su = Sv(cfg)
    pump(cu, su)
    t.check("sni is case-insensitive", su.sni == "upper.example.org" and cu.chain[0] == bytes_of("cert:key-p384"))
    var cn_ = started("", [])
    var sn = Sv(cfg)
    pump(cn_, sn)
    t.check("no SNI: default cert", cn_.cn.established and cn_.chain[0] == bytes_of("cert:key-p256"))

    # ALPN
    var ca = started("localhost", ["h2", "http/1.1"])
    var sa = Sv(cfg)
    pump(ca, sa)
    t.check("alpn picked", ca.negotiated == "http/1.1" and sa.alpn == "http/1.1")
    var cfg0 = make_cfg()
    cfg0[].alpn = List[String]()  # no ALPN configured: a client that offers it still gets a handshake, no protocol selected
    var c0 = started("localhost", ["h2", "http/1.1"])
    var s0 = Sv(cfg0)
    var ok0 = False
    try:
        pump(c0, s0)
        ok0 = c0.cn.established and s0.cn.established and c0.negotiated == "" and s0.alpn == ""
    except:
        pass
    t.check("server without ALPN ignores the extension", ok0)
    var cb = started("localhost", ["spdy/3"])
    var sb = Sv(cfg)
    try:
        pump(cb, sb)
        t.check("alpn no overlap refused", False)
    except:
        t.check("alpn no overlap refused", sb.cn.alert == A_NO_ALPN)

    # downgrade sentinel (RFC 8446 4.1.3)
    var cs = started("localhost", [], True)
    var ss = Sv(cfg)
    ss.feed(cs.cn.take_output())
    var fl = ss.cn.take_output()
    var tail = List[UInt8](Span(fl)[11 + 24 : 11 + 32])
    var want = bytes_of("DOWNGRD")
    want.append(1)
    t.check("server writes the sentinel to a 1.3 client", tail == want)
    try:
        cs.feed(fl)
        t.check("1.3-capable client rejects the sentinel", False)
    except:
        t.check("1.3-capable client rejects the sentinel", cs.cn.alert == A_ILLEGAL)
    var cp = started("localhost", [], False)
    var sp = Sv(cfg)
    sp.feed(cp.cn.take_output())
    var fl2 = sp.cn.take_output()
    t.check("sentinel for a client whose supported_versions was stripped (audit #1)", List[UInt8](Span(fl2)[35:43]) == want)
    var c12 = started("localhost", [], True)  # a server with no TLS 1.3 engine (cfg.tls13 False) must not claim a downgrade
    var s12 = Sv(make_cfg(False))
    s12.feed(c12.cn.take_output())
    t.check("no sentinel from a TLS 1.2-only server", List[UInt8](Span(s12.cn.take_output())[35:43]) != want)

    # sequence numbers never wrap (RFC 5246 6.1; a wrap reuses the AEAD nonce): the last usable number is 2^64-2 (audit #2)
    for sx in [0xC02B, 0xCCA8]:
        var cq = started("rsa.test" if sx == 0xCCA8 else "localhost", [], False, [sx])
        var sq_ = Sv(cfg)
        pump(cq, sq_)
        cq.cn.wr.seq = UInt64.MAX - 1
        cq.cn.write_app(bytes_of("last"))
        t.check("write seq: 2^64-2 still seals " + hex(sx), cq.cn.wr.seq == UInt64.MAX and len(cq.cn.take_output()) > 0)
        var wrapped = False
        try:
            cq.cn.write_app(bytes_of("wrap"))
        except:
            wrapped = cq.cn.alert == A_INTERNAL
        t.check("write seq: refuses to wrap " + hex(sx), wrapped and cq.cn.wr.seq == UInt64.MAX and len(cq.cn.take_output()) == 0)
        var cr = started("rsa.test" if sx == 0xCCA8 else "localhost", [], False, [sx])
        var sr_ = Sv(cfg)
        pump(cr, sr_)
        cr.cn.write_app(bytes_of("data"))
        sr_.cn.rd.seq = UInt64.MAX
        var rwrapped = False
        try:
            sr_.feed(cr.cn.take_output())
        except:
            rwrapped = sr_.cn.alert == A_INTERNAL
        t.check("read seq: refuses to wrap " + hex(sx), rwrapped and sr_.cn.rd.seq == UInt64.MAX)

    # input buffer stays bounded when every read ends inside a record (audit #3): 16-byte handshake records, one byte first, then 32 bytes at a time: every read ends one byte into a record
    var gc = Conn[FakeCrypto](False)
    var stream = List[UInt8]()
    for _ in range(9000):
        stream.extend(bl(22, 3, 3, 0, 11, 1, 0, 0, 7, 0, 1, 2, 3, 4, 5, 6))
    var peak = 0
    var at = 0
    var step = 1
    while at < len(stream):
        gc.feed(Span(stream)[at : min(at + step, len(stream))])
        at += step
        step = 32
        while gc.poll() != EV_NONE:
            pass
        peak = max(peak, len(gc.inb))
    t.check("input buffer bounded under misaligned reads", peak < 70000, "peak " + String(peak) + " bytes for " + String(len(stream)) + " fed")

    # a server without certificates is a configuration error at start, not an index panic on the first connection (audit #7)
    var refused_empty = False
    try:
        var nocert = TlsServer[FakeCrypto](TlsConfig(), 0)
        _ = nocert.port()
    except e:
        refused_empty = "no certificate" in String(e)
    t.check("TlsServer refuses an empty certificate list at construction", refused_empty)

    # ClientHello errors: the alert is the contract
    expect(t, "good hello accepted", cfg, rec(22, mk_ch()), -9)
    expect(t, "GREASE everywhere accepted", cfg, rec(22, mk_ch(cs=[0x0A0A, 0xC02B], groups=[0x2A2A, 0x001D], sigalgs=[0x0A0A, 0x0403], versions=[0x3A3A, 0x0304, 0x0303], extra=bl(0x1A, 0x1A, 0, 1, 0))), -9)
    expect(t, "TLS 1.1 legacy_version", cfg, rec(22, mk_ch(legacy=0x0302)), A_VERSION)
    expect(t, "supported_versions without 1.2", cfg, rec(22, mk_ch(versions=[0x0304])), A_VERSION)
    expect(t, "no extended master secret", cfg, rec(22, mk_ch(ems=False)), A_HANDSHAKE)
    expect(t, "renegotiation_info not empty", cfg, rec(22, mk_ch(ri=1)), A_HANDSHAKE)
    expect(t, "no common group", cfg, rec(22, mk_ch(groups=[0x0A0A])), A_HANDSHAKE)
    expect(t, "no signature algorithms we can use", cfg, rec(22, mk_ch(sigalgs=[0x0201])), A_HANDSHAKE)
    expect(t, "only TLS 1.3 suites", cfg, rec(22, mk_ch(cs=[0x1301, 0x1302])), A_HANDSHAKE)
    expect(t, "only CBC and RSA key exchange", cfg, rec(22, mk_ch(cs=[0x002F, 0xC013, 0x009C])), A_HANDSHAKE)
    expect(t, "duplicate extension", cfg, rec(22, mk_ch(extra=bl(0, 0x17, 0, 0))), A_DECODE)
    expect(t, "trailing bytes in hello", cfg, rec(22, mk_ch(trailing=3)), A_DECODE)
    expect(t, "bad host name", cfg, rec(22, mk_ch(sni="a b")), A_DECODE)
    expect(t, "truncated hello body", cfg, rec(22, hs(H_CH, List[UInt8](Span(mk_ch())[4:34]))), A_DECODE)
    expect(t, "hello message split over records is waited for", cfg, rec(22, List[UInt8](Span(mk_ch())[0:30])), -9)

    # state machine order
    expect(t, "CCS before anything", cfg, rec(20, bl(1)), A_UNEXPECTED)
    expect(t, "application data before the handshake", cfg, rec(23, bl(1, 2, 3)), A_UNEXPECTED)
    expect(t, "Finished first", cfg, rec(22, hs(H_FIN, List[UInt8](length=12, fill=0))), A_UNEXPECTED)
    expect(t, "ClientKeyExchange first", cfg, rec(22, hs(H_CKE, bl(1, 5))), A_UNEXPECTED)
    expect(t, "empty handshake record", cfg, rec(22, List[UInt8]()), A_UNEXPECTED)
    expect(t, "record type 99", cfg, bl(99, 3, 3, 0, 1, 0), A_UNEXPECTED)
    expect(t, "record version 2.x", cfg, bl(22, 2, 0, 0, 1, 0), A_VERSION)
    expect(t, "record over 2^14 in the clear", cfg, bl(22, 3, 3, 0x40, 0x01), A_OVERFLOW)
    expect(t, "handshake message over 64 KiB", cfg, rec(22, bl(1, 0x01, 0x11, 0x70, 0, 0)), A_ILLEGAL)
    expect(t, "alert from peer: no alert back", cfg, rec(21, bl(2, 40)), -1)
    expect(t, "bad alert length", cfg, rec(21, bl(2)), A_DECODE)
    var dup = cat(rec(22, mk_ch()), rec(22, mk_ch()))
    expect(t, "second ClientHello", cfg, dup, A_UNEXPECTED)
    var half = rec(22, List[UInt8](Span(mk_ch())[0:50]))
    expect(t, "CCS inside a handshake message", cfg, cat(half, rec(20, bl(1))), A_UNEXPECTED)
    expect(t, "bad CCS body", cfg, cat(rec(22, mk_ch()), rec(20, bl(2))), A_DECODE)

    # a wrong Finished, each way (the forged record is sealed with the right keys: only verify_data is wrong)
    var cf1 = started("localhost", [])
    var sf1 = Sv(cfg)
    sf1.feed(cf1.cn.take_output())
    cf1.feed(sf1.cn.take_output())
    var o1 = cf1.cn.take_output()
    var keep = 0
    for _ in range(2):  # CKE record, CCS record
        keep += 5 + (Int(o1[keep + 3]) << 8 | Int(o1[keep + 4]))
    cf1.cn.wr.seq = 0
    cf1.cn.write_rec(HAND, hs(H_FIN, List[UInt8](length=12, fill=0)))
    var forged = cat(List[UInt8](Span(o1)[0:keep]), cf1.cn.take_output())
    try:
        sf1.feed(forged)
        t.check("server rejects a wrong client Finished", False)
    except:
        t.check("server rejects a wrong client Finished", sf1.cn.alert == A_DECRYPT and not sf1.cn.established)
    var cf2 = started("localhost", [])
    var sf2 = Sv(cfg)
    sf2.feed(cf2.cn.take_output())
    cf2.feed(sf2.cn.take_output())
    sf2.feed(cf2.cn.take_output())
    var o2 = sf2.cn.take_output()
    var ccs_len = 5 + (Int(o2[3]) << 8 | Int(o2[4]))
    sf2.cn.wr.seq = 0
    sf2.cn.write_rec(HAND, hs(H_FIN, List[UInt8](length=12, fill=1)))
    var forged2 = cat(List[UInt8](Span(o2)[0:ccs_len]), sf2.cn.take_output())
    try:
        cf2.feed(forged2)
        t.check("client rejects a wrong server Finished", False)
    except:
        t.check("client rejects a wrong server Finished", cf2.cn.alert == A_DECRYPT and not cf2.cn.established)

    # after the handshake: renegotiation is refused, close_notify answered
    var cr = started("localhost", [])
    var sr = Sv(cfg)
    pump(cr, sr)
    cr.cn.send_hs(mk_ch())
    try:
        sr.feed(cr.cn.take_output())
        t.check("renegotiation refused", False)
    except:
        t.check("renegotiation refused", sr.cn.alert == A_UNEXPECTED)
    var cc = started("localhost", [])
    var sc = Sv(cfg)
    pump(cc, sc)
    cc.cn.close()
    pump(cc, sc)
    t.check("close_notify both ways", sc.cn.peer_closed and sc.cn.sent_close and cc.cn.peer_closed and not sc.cn.dead)

    # client side: a hostile server
    var ch = started("localhost", ["http/1.1"], False, [0xC02B])
    var out = ch.cn.take_output()
    var sv = Sv(cfg)
    sv.feed(out)
    var flight = sv.cn.take_output()
    var tampered = flight.copy()
    tampered[len(tampered) - 5] ^= 1  # last signature byte of the ServerKeyExchange
    try:
        ch.feed(tampered)
        t.check("bad ServerKeyExchange signature", False)
    except:
        t.check("bad ServerKeyExchange signature", ch.cn.alert == A_BAD_CERT)
    var c4 = started("localhost", [], False, [0xC02B])
    _ = c4.cn.take_output()
    var rnd = List[UInt8](length=32, fill=1)
    try:
        c4.feed(rec(22, build_server_hello(rnd, 0xC02F, True, True, False, "", False)))
        t.check("suite we did not offer", False)
    except:
        t.check("suite we did not offer", c4.cn.alert == A_ILLEGAL)
    var c5 = started("localhost", [], False, [0xC02B])
    _ = c5.cn.take_output()
    try:
        c5.feed(rec(22, build_server_hello(rnd, 0xC02B, False, True, False, "", False)))
        t.check("server without extended master secret", False)
    except:
        t.check("server without extended master secret", c5.cn.alert == A_HANDSHAKE)
    var c6 = started("localhost", [], False, [0xC02B])
    _ = c6.cn.take_output()
    try:
        c6.feed(rec(22, hs(H_CREQ, bl(0, 0, 0))))
        t.check("CertificateRequest before ServerHello", False)
    except:
        t.check("CertificateRequest before ServerHello", c6.cn.alert == A_UNEXPECTED)
    var c7 = started("localhost", [], False, [0xC02B])
    _ = c7.cn.take_output()
    try:
        c7.feed(rec(22, build_server_hello(rnd, 0xC02B, True, True, False, "h2", False)))
        t.check("ALPN we did not offer", False)
    except:
        t.check("ALPN we did not offer", c7.cn.alert == A_ILLEGAL)

    # fuzz: mutated first flights never crash or hang; they are accepted or refused with an error
    var seed = UInt64(88172645463325252)
    var fuzz_ok = 0
    var hello = rec(22, mk_ch(alpn=["http/1.1"], versions=[0x0304, 0x0303]))
    for it in range(3000):
        var m = hello.copy() if it % 2 == 0 else flight.copy()
        for _ in range(1 + it % 4):
            seed ^= seed << 13
            seed ^= seed >> 7
            seed ^= seed << 17
            var i = Int(seed % UInt64(len(m)))
            m[i] = UInt8((seed >> 20) & 255) if it % 3 != 0 else m[i] ^ UInt8(1 << Int((seed >> 8) % 8))
        if it % 5 == 0:
            m = List[UInt8](Span(m)[0 : Int((seed >> 9) % UInt64(len(m)))])
        if it % 2 == 0:
            _ = srv_alert(cfg, m, why0)
        else:
            var cf = started("localhost", ["http/1.1"], False, [0xC02B])
            try:
                cf.feed(m)
            except:
                pass
        fuzz_ok += 1
    cauth12(t, "cli-p256", "", "ca", -9, "TLS 1.2 client certificate P-256: accepted, the server saw it")
    cauth12(t, "cli-rsa", "", "ca", -9, "TLS 1.2 client certificate RSA: accepted")
    cauth12(t, "", "", "ca", 40, "TLS 1.2 no client certificate: handshake_failure")
    cauth12(t, "cli-evil", "", "ca", 42, "TLS 1.2 certificate of another CA: bad_certificate")
    cauth12(t, "cli-serverauth", "", "ca", 42, "TLS 1.2 serverAuth-only certificate: bad_certificate")
    cauth12(t, "cli-p256", "cli-evil", "ca", 51, "TLS 1.2 signature of another key: decrypt_error")
    cauth12(t, "cli-p256", "cli-rsa", "ca", 47, "TLS 1.2 RSA signature for a P-256 certificate: illegal_parameter")
    t.check("fuzz: 3000 mutated flights, no crash", fuzz_ok == 3000)
    t.done()
