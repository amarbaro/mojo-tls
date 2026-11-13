# Gate: handshake codecs. Every message of RFC 8448 sections 3 and 5 parses and re-encodes byte for byte; field values
# are checked; malformed input (every truncation, flipped bytes, bad lengths, duplicates, caps) raises and never crashes.
from tls.tls13.messages import *
from tls.tls13.wire import Rd, alert_of
from tls.tls13.ticket import TicketState, seal_ticket, open_ticket
from chk import Vec, T, hexd


def code(msg: List[UInt8], what: Int) -> Int:
    """Alert code a parser raises for msg, 0 when it parses (what: 1 CH, 2 SH, 3 EE, 4 Cert, 5 CV, 6 Fin32, 7 NST, 8 CR)."""
    try:
        if what == 1:
            _ = parse_hello(msg, False)
        elif what == 2:
            _ = parse_hello(msg, True)
        elif what == 3:
            _ = parse_ee(msg)
        elif what == 4:
            _ = parse_cert(msg)
        elif what == 5:
            _ = parse_cv(msg)
        elif what == 6:
            _ = parse_fin(msg, 32)
        elif what == 7:
            _ = parse_nst(msg)
        else:
            _ = parse_cr(msg)
    except e:
        return alert_of(String(e))
    return 0


def reenc(mut t: T, v: Vec, sec: Int, step: String, field: String, nth: Int, what: Int, name: String) raises:
    var m = v.get(sec, step, field, nth)
    var again = List[UInt8]()
    if what == 1:
        again = parse_hello(m, False).encode()
    elif what == 2:
        again = parse_hello(m, True).encode()
    elif what == 3:
        again = enc_ee(parse_ee(m))
    elif what == 4:
        var c = parse_cert(m)
        again = enc_cert(c[0], c[1])
    elif what == 5:
        var c = parse_cv(m)
        again = enc_cv(c[0], c[1])
    elif what == 6:
        again = hs_msg(H_FIN, parse_fin(m, 32))
    else:
        again = parse_nst(m).encode()
    t.eq("s" + String(sec) + " " + name + " re-encodes byte for byte (" + String(len(m)) + " bytes)", again, m)
    # every truncation and a one-byte extension is rejected; flipped bytes never crash
    var bad_cuts = 0
    for n in range(len(m)):
        if code(List[UInt8](Span(m)[0:n]), what) != 0:
            bad_cuts += 1
    t.ok(name + ": all " + String(len(m)) + " truncations raise", bad_cuts == len(m))
    var longer = m.copy()
    longer.append(0)
    t.ok(name + ": trailing byte raises", code(longer, what) != 0)
    var seed: UInt64 = 0x243f6a8885a308d3
    var survived = 0
    for _ in range(200):
        var f = m.copy()
        seed = seed * 6364136223846793005 + 1442695040888963407
        f[Int((seed >> 33) % UInt64(len(f)))] ^= UInt8(1 << Int((seed >> 20) % 8))
        if code(f, what) == 0:
            survived += 1
    t.ok(name + ": 200 flipped-bit variants parse or raise without a crash (" + String(survived) + " still parse)", True)


def fields(mut t: T, v: Vec) raises:
    var ch = parse_hello(v.get(3, "construct a ClientHello", "ClientHello"), False)
    t.ok("s3 CH: random, no session id, 3 suites, 1 compression", len(ch.random) == 32 and len(ch.sid) == 0 and ch.suites == [0x1301, 0x1303, 0x1302] and len(ch.comp) == 1)
    t.ok("s3 CH: sni 'server'", p_sni(ch.exts[find(ch.exts, X_SNI)].d) == "server")
    t.ok("s3 CH: supported_versions {1.3}", p_versions_client(ch.exts[find(ch.exts, X_VERSIONS)].d) == [0x0304])
    t.ok("s3 CH: 5 +3 groups listed, x25519 first", p_u16s(ch.exts[find(ch.exts, X_GROUPS)].d)[0] == G_X25519 and len(p_u16s(ch.exts[find(ch.exts, X_GROUPS)].d)) == 9)
    t.ok("s3 CH: 15 signature algorithms", len(p_u16s(ch.exts[find(ch.exts, X_SIGALGS)].d)) == 15)
    var ks = p_keyshares(ch.exts[find(ch.exts, X_KEYSHARE)].d)
    t.ok("s3 CH: one x25519 share equal to the client public key", len(ks) == 1 and ks[0][0] == G_X25519)
    t.eq("s3 CH: share bytes", ks[0][1], v.get(3, "{client}  create an ephemeral x25519", "public key"))
    t.ok("s3 CH: record_size_limit 16385", p_rsl(ch.exts[find(ch.exts, X_RSL)].d) == 16385)
    var sh = parse_hello(v.get(3, "construct a ServerHello", "ServerHello"), True)
    t.ok("s3 SH: suite 0x1301, not an HRR", sh.suites == [0x1301] and not sh.is_hrr())
    var sk = p_keyshare_server(sh.exts[find(sh.exts, X_KEYSHARE)].d)
    t.eq("s3 SH: key share is the server public key", sk[1], v.get(3, "{server}  create an ephemeral x25519", "public key"))
    t.ok("s3 SH: supported_versions 0x0304", p_version_server(sh.exts[find(sh.exts, X_VERSIONS)].d) == 0x0304)
    var ee = parse_ee(v.get(3, "construct an EncryptedExtensions", "EncryptedExtensions"))
    t.ok("s3 EE: groups, record_size_limit, empty server_name", len(ee) == 3 and ee[0].t == X_GROUPS and ee[1].t == X_RSL and ee[2].t == X_SNI and len(ee[2].d) == 0)
    var cert = parse_cert(v.get(3, "construct a Certificate", "Certificate"))
    t.ok("s3 Certificate: empty context, one 432-byte certificate", len(cert[0]) == 0 and len(cert[1]) == 1 and len(cert[1][0]) == 432)
    var cv = parse_cv(v.get(3, "construct a CertificateVerify", "CertificateVerify"))
    t.ok("s3 CertificateVerify: rsa_pss_rsae_sha256, 128-byte signature", cv[0] == 0x0804 and len(cv[1]) == 128)
    var nst = parse_nst(v.get(3, "NewSessionTicket", "NewSessionTicket"))
    t.ok("s3 NewSessionTicket: lifetime 30 s, 2-byte nonce, 178-byte ticket", nst.lifetime == 30 and len(nst.nonce) == 2 and len(nst.ticket) == 178)
    # section 5: HRR
    var hrr = parse_hello(v.get(5, "construct a ServerHello", "ServerHello", 0), True)
    t.ok("s5 HRR: random is SHA-256('HelloRetryRequest')", hrr.is_hrr())
    t.ok("s5 HRR: selects secp256r1 and carries a 114-byte cookie", hrr.exts[find(hrr.exts, X_KEYSHARE)].d == [UInt8(0), UInt8(0x17)] and len(p_cookie(hrr.exts[find(hrr.exts, X_COOKIE)].d)) == 114)
    var ch2 = parse_hello(v.get(5, "construct a ClientHello", "ClientHello", 1), False)
    t.ok("s5 CH2: P-256 share (65 bytes), cookie echoed, padding extension last", p_keyshares(ch2.exts[find(ch2.exts, X_KEYSHARE)].d)[0][0] == G_P256 and ch2.exts[len(ch2.exts) - 1].t == X_PADDING and find(ch2.exts, X_COOKIE) >= 0)


def malformed(mut t: T, v: Vec) raises:
    var chm = v.get(3, "construct a ClientHello", "ClientHello")
    var ch = parse_hello(chm, False)
    var dup = ch.copy()
    dup.exts.append(Ext(X_SNI, dup.exts[0].d.copy()))
    t.ok("duplicate extension gives illegal_parameter", code(dup.encode(), 1) == 47)
    var long_sid = ch.copy()
    long_sid.sid = List[UInt8](length=33, fill=1)
    t.ok("33-byte session id gives illegal_parameter", code(long_sid.encode(), 1) == 47)
    var odd = ch.copy()
    odd.suites = [0x1301]
    var ob = odd.encode()
    t.ok("a single cipher suite is accepted", code(ob, 1) == 0)
    var nocomp = ch.copy()
    nocomp.comp = List[UInt8]()
    t.ok("empty compression list gives decode_error", code(nocomp.encode(), 1) == 50)
    var wrongtype = chm.copy()
    wrongtype[0] = 2
    t.ok("wrong message type gives unexpected_message", code(wrongtype, 1) == 10)
    var lenbad = chm.copy()
    lenbad[3] ^= 1
    t.ok("wrong length field gives decode_error", code(lenbad, 1) == 50)
    var chain = List[List[UInt8]]()
    for _ in range(11):
        chain.append(List[UInt8](length=4, fill=9))
    t.ok("11 certificates give illegal_parameter", code(enc_cert(List[UInt8](), chain), 4) == 47)
    chain.clear()
    chain.append(List[UInt8]())
    t.ok("empty certificate entry gives decode_error", code(enc_cert(List[UInt8](), chain), 4) == 50)
    chain.clear()
    for _ in range(10):
        chain.append(List[UInt8](length=4, fill=9))
    t.ok("10 certificates are accepted", code(enc_cert(List[UInt8](), chain), 4) == 0)
    t.ok("Finished of 31 bytes gives decode_error", code(hs_msg(H_FIN, List[UInt8](length=31, fill=1)), 6) == 50)
    t.ok("Finished of 32 bytes is accepted", code(hs_msg(H_FIN, List[UInt8](length=32, fill=1)), 6) == 0)
    var nst = Ticket(604801, 1, List[UInt8](), List[UInt8](length=4, fill=1), List[Ext]())
    t.ok("ticket lifetime above 7 days gives illegal_parameter", code(nst.encode(), 7) == 47)
    var nst0 = Ticket(10, 1, List[UInt8](), List[UInt8](), List[Ext]())
    t.ok("empty ticket gives decode_error", code(nst0.encode(), 7) == 50)
    var rsl = False
    try:
        _ = p_rsl(x_rsl(63).d)
    except e:
        rsl = True
    t.ok("record_size_limit 63 is rejected", rsl)
    var e1 = List[Ext]()
    e1.append(x_u16s(X_GROUPS, [1, 2]))
    t.ok("CertificateRequest without signature_algorithms gives missing_extension", code(hs_msg(H_CR, enc_cr_body(e1)), 8) == 109)


def enc_cr_body(exts: List[Ext]) raises -> List[UInt8]:
    var b: List[UInt8] = [UInt8(0)]
    b.extend(Span(enc_exts(exts)))
    return b^


def roundtrip(mut t: T) raises:
    """Random hellos built from the typed extension builders parse back to the same fields."""
    var seed: UInt64 = 0x13198a2e03707344
    var ok = 0
    for _ in range(300):
        var exts = List[Ext]()
        seed = seed * 6364136223846793005 + 1442695040888963407
        var host = String("h") + String(Int((seed >> 40) % 100000)) + ".example"
        exts.append(x_sni(host))
        var groups = List[Int]()
        for i in range(Int((seed >> 20) % 5) + 1):
            groups.append(0x17 + i)
        exts.append(x_u16s(X_GROUPS, groups))
        exts.append(x_alpn([String("http/1.1"), String("h2")]))
        var share = List[UInt8](length=Int((seed >> 8) % 300), fill=UInt8(seed & 0xFF))
        exts.append(x_keyshares([(G_X25519, share.copy())]))
        var h = Hello(False, List[UInt8](length=32, fill=UInt8(seed & 0xFF)), List[UInt8](length=Int(seed % 33), fill=3), [0x1301, 0x1302], exts^)
        var p = parse_hello(h.encode(), False)
        if (
            p_sni(p.exts[0].d) == host
            and p_u16s(p.exts[1].d) == groups
            and p_alpn(p.exts[2].d) == [String("http/1.1"), String("h2")]
            and p_keyshares(p.exts[3].d)[0][1] == share
            and p.suites == [0x1301, 0x1302]
            and len(p.sid) == Int(seed % 33)
        ):
            ok += 1
    t.ok("300 random hellos round-trip through the typed builders and parsers (" + String(ok) + "/300)", ok == 300)


def reader_bounds(mut t: T) raises:
    """Every read of one byte more than is left must raise: the exact boundary, for each reader method."""
    var raised = 0
    var b: List[UInt8] = [1, 2, 3]
    for k in range(5):
        var r = Rd(b.copy())
        try:
            _ = r.take(3)
            if k == 0:
                _ = r.u8()
            elif k == 1:
                _ = r.u16()
            elif k == 2:
                _ = r.u24()
            elif k == 3:
                _ = r.take(1)
            else:
                _ = r.u32()
        except:
            raised += 1
    t.ok("Rd: a read one byte past the end raises (u8, u16, u24, take, u32)", raised == 5)
    var r2 = Rd(b.copy())
    var short = False
    try:
        _ = r2.take(4)
    except:
        short = True
    var r3 = Rd(b.copy())
    var exact = len(r3.take(3)) == 3 and r3.left() == 0
    t.ok("Rd: take(left + 1) raises and take(left) works", short and exact)
    var empty = False
    try:
        _ = p_u16s([0, 0])  # an extension body holding an empty list: signature_algorithms and supported_groups need >= 1 entry
    except e:
        empty = alert_of(String(e)) == 50
    var one = len(p_u16s([0, 2, 4, 3])) == 1
    t.ok("an empty u16 list is a decode_error, a one-entry list parses", empty and one)


def psk_and_ticket(mut t: T) raises:
    """pre_shared_key and tickets: a round trip, every truncation and every flipped bit of a ticket raises, nothing crashes."""
    var ext = x_psk_client([UInt8(1), 2, 3, 4, 5, 6, 7, 8], 0xDEADBEEF, 32)
    var p = p_psk_client(ext.d)
    t.ok("pre_shared_key: one identity, age, one 32-byte binder, binders vector 35 bytes", len(p[0]) == 1 and p[0][0][1] == 0xDEADBEEF and len(p[0][0][0]) == 8 and len(p[1]) == 1 and len(p[1][0]) == 32 and p[2] == 35)
    var cuts = 0
    for n in range(len(ext.d)):
        try:
            _ = p_psk_client(List[UInt8](Span(ext.d)[0:n]))
        except:
            cuts += 1
        var f = ext.d.copy()
        f[n] ^= 0xFF
        try:
            _ = p_psk_client(f)
        except:
            pass  # a flipped value byte may still parse: it must only never crash
    t.ok("pre_shared_key: all " + String(len(ext.d)) + " truncations raise", cuts == len(ext.d))
    var key = List[UInt8](length=32, fill=9)
    var st = TicketState(1000, 86400, 77, 0x1301, List[UInt8](length=32, fill=5), "h2", "example.com")
    var blob = seal_ticket(key, st)
    var got = open_ticket([key.copy()], blob)
    t.ok("ticket: seals and opens with every field intact", got.issued == 1000 and got.lifetime == 86400 and got.age_add == 77 and got.suite == 0x1301 and got.psk == st.psk and got.alpn == "h2" and got.sni == "example.com")
    var bad_cuts = 0
    for n in range(len(blob)):
        try:
            _ = open_ticket([key.copy()], List[UInt8](Span(blob)[0:n]))
        except:
            bad_cuts += 1
    t.ok("ticket: all " + String(len(blob)) + " truncations raise", bad_cuts == len(blob))
    var bad_bits = 0
    for n in range(len(blob)):
        for bit in range(8):
            var f = blob.copy()
            f[n] ^= UInt8(1 << bit)
            try:
                _ = open_ticket([key.copy()], f)
            except:
                bad_bits += 1
    t.ok("ticket: every one of " + String(8 * len(blob)) + " flipped bits raises (key name or AEAD tag)", bad_bits == 8 * len(blob))
    var raised = False
    try:
        _ = open_ticket([List[UInt8](length=32, fill=1)], blob)
    except:
        raised = True
    t.ok("ticket: another key does not open it", raised)


def main() raises:
    var t = T("codec")
    psk_and_ticket(t)
    reader_bounds(t)
    var v = Vec()
    reenc(t, v, 3, "construct a ClientHello", "ClientHello", 0, 1, "ClientHello")
    reenc(t, v, 3, "construct a ServerHello", "ServerHello", 0, 2, "ServerHello")
    reenc(t, v, 3, "construct an EncryptedExtensions", "EncryptedExtensions", 0, 3, "EncryptedExtensions")
    reenc(t, v, 3, "construct a Certificate", "Certificate", 0, 4, "Certificate")
    reenc(t, v, 3, "construct a CertificateVerify", "CertificateVerify", 0, 5, "CertificateVerify")
    reenc(t, v, 3, "{server}  construct a Finished", "Finished", 0, 6, "server Finished")
    reenc(t, v, 3, "NewSessionTicket", "NewSessionTicket", 0, 7, "NewSessionTicket")
    reenc(t, v, 5, "construct a ClientHello", "ClientHello", 0, 1, "ClientHello 1 (HRR trace)")
    reenc(t, v, 5, "construct a ServerHello", "ServerHello", 0, 2, "HelloRetryRequest")
    reenc(t, v, 5, "construct a ClientHello", "ClientHello", 1, 1, "ClientHello 2 (cookie, padding)")
    reenc(t, v, 5, "construct a ServerHello", "ServerHello", 1, 2, "ServerHello (P-256)")
    fields(t, v)
    malformed(t, v)
    roundtrip(t)
    t.done()
