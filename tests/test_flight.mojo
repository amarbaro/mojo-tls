# Gate: client and server state machines reproduce RFC 8448 byte for byte. Section 3 (1-RTT, x25519, AES-128-GCM),
# section 5 (HelloRetryRequest to secp256r1, cookie, padding) and section 7 (compatibility mode: session id, CCS). Each side is run against the other side's recorded
# bytes: the output must equal the trace. CertificateVerify content is printed for the openssl oracle (tests/gate_tls13.sh).
from tls.tls13.client import Client13
from tls.tls13.conn import *
from tls.tls13.keysched import hash_of
from tls.tls13.messages import *
from tls.tls13.record import Cipher, seal_all, HS, ALERT
from tls.tls13.server import Server13, ServerConfig
from chk import Vec, T, hexs
from rec import RecSigner, RecVerifier


def cat(a: List[UInt8], b: List[UInt8]) -> List[UInt8]:
    var o = a.copy()
    o.extend(Span(b))
    return o^


def zeros32() -> List[UInt8]:
    return List[UInt8](length=32, fill=0)


struct Trace(Movable):
    """The parts of one RFC 8448 handshake, section 3 (plain) or 5 (HRR)."""

    var sec: Int
    var ch_rec: List[UInt8]  # first ClientHello record
    var ch2_rec: List[UInt8]  # second ClientHello record (HRR only)
    var hrr_rec: List[UInt8]
    var sh_rec: List[UInt8]
    var flight_rec: List[UInt8]
    var cfin_rec: List[UInt8]
    var scc: List[UInt8]  # server ChangeCipherSpec record (compatibility mode, section 7)
    var ccc: List[UInt8]  # client ChangeCipherSpec record
    var ch: Hello
    var sh: Hello
    var content: List[UInt8]  # what the server signs
    var chain: List[List[UInt8]]
    var sig: List[UInt8]
    var scheme: Int
    var ee: List[Ext]
    var cx_priv: List[UInt8]
    var cp_priv: List[UInt8]
    var sx_priv: List[UInt8]
    var sp_priv: List[UInt8]
    var cookie: List[UInt8]

    def __init__(out self, v: Vec, sec: Int) raises:
        self.sec = sec
        var hrr = sec == 5
        var cr = "{client}  send handshake record"
        var sr = "{server}  send handshake record"
        self.ch_rec = v.get(sec, cr, "complete record", 0)
        self.ch2_rec = v.get(sec, cr, "complete record", 1) if hrr else List[UInt8]()
        self.cfin_rec = v.get(sec, cr, "complete record", 2 if hrr else 1)
        self.hrr_rec = v.get(sec, sr, "complete record", 0) if hrr else List[UInt8]()
        self.sh_rec = v.get(sec, sr, "complete record", 1 if hrr else 0)
        self.flight_rec = v.get(sec, sr, "complete record", 2 if hrr else 1)
        var ch1 = v.get(sec, "construct a ClientHello", "ClientHello", 0)
        var ch2 = v.get(sec, "construct a ClientHello", "ClientHello", 1) if hrr else List[UInt8]()
        self.scc = v.get(sec, "{server}  send change_cipher_spec", "complete record") if sec == 7 else List[UInt8]()
        self.ccc = v.get(sec, "{client}  send change_cipher_spec", "complete record") if sec == 7 else List[UInt8]()
        self.ch = parse_hello(ch1, False)
        var shm = v.get(sec, "construct a ServerHello", "ServerHello", 1 if hrr else 0)
        self.sh = parse_hello(shm, True)
        var eem = v.get(sec, "construct an EncryptedExtensions", "EncryptedExtensions")
        var certm = v.get(sec, "construct a Certificate", "Certificate")
        self.ee = parse_ee(eem)
        var c = parse_cert(certm)
        self.chain = c[1].copy()
        var cv = parse_cv(v.get(sec, "construct a CertificateVerify", "CertificateVerify"))
        self.scheme = cv[0]
        self.sig = cv[1].copy()
        var tr = List[UInt8]()
        if hrr:
            tr = hs_msg(H_MSGHASH, hash_of(32, ch1))
            tr = cat(tr, v.get(sec, "construct a ServerHello", "ServerHello", 0))
            tr = cat(tr, ch2)
        else:
            tr = ch1.copy()
        tr = cat(cat(cat(cat(tr, shm), eem), certm), List[UInt8]())
        self.content = List[UInt8](length=64, fill=0x20)  # RFC 8446 4.4.3, written out here, not taken from src
        for b in "TLS 1.3, server CertificateVerify".as_bytes():
            self.content.append(b)
        self.content.append(0)
        self.content.extend(Span(hash_of(32, tr)))
        self.cx_priv = v.get(sec, "{client}  create an ephemeral x25519", "private key")
        self.sx_priv = v.get(sec, "{server}  create an ephemeral x25519", "private key") if not hrr else zeros32()
        self.cp_priv = v.get(sec, "{client}  create an ephemeral P-256", "private key") if hrr else zeros32()
        self.sp_priv = v.get(sec, "{server}  create an ephemeral P-256", "private key") if hrr else zeros32()
        self.cookie = List[UInt8]()
        if hrr:
            var hh = parse_hello(v.get(sec, "construct a ServerHello", "ServerHello", 0), True)
            self.cookie = p_cookie(hh.exts[find(hh.exts, X_COOKIE)].d)


def server_side(mut t: T, v: Vec, tr: Trace) raises:
    var tag = "s" + String(tr.sec) + " server: "
    var cfg = ServerConfig(tr.sh.random, tr.sx_priv, tr.sp_priv)
    cfg.ee_exts = tr.ee.copy()
    cfg.cookie = tr.cookie.copy()
    if tr.sec == 5:
        cfg.groups = [G_P256]  # this server wants P-256 only, so the x25519 ClientHello gets an HRR
    var srv = Server13[RecSigner](cfg^, RecSigner(tr.chain, tr.sig, tr.scheme, tr.content))
    var out = srv.feed(Span(tr.ch_rec))
    if tr.sec == 5:
        t.eq(tag + "HelloRetryRequest record", out.send, tr.hrr_rec)
        out = srv.feed(Span(tr.ch2_rec))
    t.ok(tag + "no error (" + out.error + ")", out.error == "")
    t.eq(tag + "ServerHello" + (" + CCS" if tr.sec == 7 else "") + " + encrypted flight records", out.send, cat(cat(tr.sh_rec, tr.scc), tr.flight_rec))
    var fin = srv.feed(Span(cat(tr.ccc, tr.cfin_rec)))
    t.ok(tag + "client Finished verifies, handshake done", fin.has(EV_DONE) and fin.error == "")
    t.ok(tag + "state is open, group and SNI recorded", srv.c.state == S_OPEN and srv.group == (G_P256 if tr.sec == 5 else G_X25519) and srv.sni == "server")
    if tr.sec == 3:
        # the rest of the section 3 trace: server app data is record seq 1 in the RFC (it sent a ticket first)
        srv.c.tx.seq = 1
        t.eq(tag + "application_data record", srv.write(v.get(3, "{server}  send application_data", "payload")), v.get(3, "{server}  send application_data", "complete record"))
        var app = srv.feed(Span(v.get(3, "{client}  send application_data", "complete record")))
        t.eq(tag + "client application data decrypts", app.data, v.get(3, "{client}  send application_data", "payload"))
        var cl = srv.feed(Span(v.get(3, "{client}  send alert", "complete record")))
        t.ok(tag + "client close_notify seen", cl.has(EV_CLOSE))
        t.eq(tag + "close_notify answered (record seq 2)", cl.send, v.get(3, "{server}  send alert", "complete record"))
        print("CVCONTENT " + hexs(tr.content))


def client_side(mut t: T, v: Vec, tr: Trace) raises:
    var tag = "s" + String(tr.sec) + " client: "
    var cli = Client13[RecVerifier](tr.ch, "server", tr.cx_priv, tr.cp_priv, RecVerifier(tr.chain, tr.sig, tr.scheme, tr.content, "server"))
    t.eq(tag + "ClientHello record", cli.start(), tr.ch_rec)
    var out = Out()
    if tr.sec == 5:
        out = cli.feed(Span(tr.hrr_rec))
        t.eq(tag + "second ClientHello record (P-256 share, cookie, padding to 512)", out.send, tr.ch2_rec)
    out = cli.feed(Span(cat(cat(tr.sh_rec, tr.scc), tr.flight_rec)))
    t.ok(tag + "no error (" + out.error + ")", out.error == "")
    t.ok(tag + "handshake done, certificate verified once", out.has(EV_DONE) and cli.v.calls == 1)
    t.eq(tag + "client" + (" CCS +" if tr.sec == 7 else "") + " Finished record", out.send, cat(tr.ccc, tr.cfin_rec))
    if tr.sec == 3:
        t.eq(tag + "application_data record (seq 0)", cli.write(v.get(3, "{client}  send application_data", "payload")), v.get(3, "{client}  send application_data", "complete record"))
        var nst = cli.feed(Span(v.get(3, "{server}  send handshake record", "complete record", 2)))
        t.ok(tag + "NewSessionTicket stored", nst.has(EV_TICKET) and len(cli.c.tickets) == 1 and cli.c.tickets[0].lifetime == 30)
        var app = cli.feed(Span(v.get(3, "{server}  send application_data", "complete record")))
        t.eq(tag + "server application data decrypts", app.data, v.get(3, "{server}  send application_data", "payload"))
        var cl = cli.feed(Span(v.get(3, "{server}  send alert", "complete record")))
        t.ok(tag + "server close_notify seen", cl.has(EV_CLOSE))
        t.eq(tag + "close_notify answered (record seq 1)", cl.send, v.get(3, "{client}  send alert", "complete record"))


def hs_cipher(v: Vec, what: String) raises -> Cipher:
    var c = Cipher()
    c.set(0x1301, v.get(3, what, "key expanded"), v.get(3, what, "iv expanded"))
    return c^


def alert_of_record(rec: List[UInt8], mut c: Cipher) raises -> Tuple[Int, Int]:
    var r = c.open(rec)
    return (Int(r[1][0]) if r[0] == 21 and len(r[1]) == 2 else -1, Int(r[1][1]) if len(r[1]) == 2 else -1)


def negatives(mut t: T, v: Vec) raises:
    """A Finished that does not verify ends the handshake with decrypt_error (alert 51), on both sides."""
    var tr = Trace(v, 3)
    var fin = v.get(3, "{client}  construct a Finished", "Finished")
    fin[len(fin) - 1] ^= 1
    var cfg = ServerConfig(tr.sh.random, tr.sx_priv, tr.sp_priv)
    cfg.ee_exts = tr.ee.copy()
    var srv = Server13[RecSigner](cfg^, RecSigner(tr.chain, tr.sig, tr.scheme, tr.content))
    _ = srv.feed(Span(tr.ch_rec))
    var chs = hs_cipher(v, "derive read traffic keys for handshake")
    var bad = List[UInt8]()
    seal_all(chs, HS, fin, bad)
    var out = srv.feed(Span(bad))
    t.ok("server: client Finished with one bit flipped gives decrypt_error", out.has(EV_ERROR) and out.error.startswith("tls: decrypt_error") and srv.c.state == S_FAILED)
    var sap = Cipher()
    sap.set(0x1301, v.get(3, "derive write traffic keys for application", "key expanded", 0), v.get(3, "derive write traffic keys for application", "iv expanded", 0))
    var a = alert_of_record(out.send, sap)
    t.ok("server: a fatal decrypt_error alert (2, 51) went out under the application key", a[0] == 2 and a[1] == 51)
    t.ok("server: after the failure further input is ignored", len(srv.feed(Span(bad)).send) == 0)
    var cli = Client13[RecVerifier](tr.ch, "server", tr.cx_priv, tr.cp_priv, RecVerifier(tr.chain, tr.sig, tr.scheme, tr.content, "server"))
    _ = cli.start()
    var sfin = v.get(3, "{server}  construct a Finished", "Finished")
    sfin[len(sfin) - 1] ^= 1
    var flight = v.get(3, "construct an EncryptedExtensions", "EncryptedExtensions")
    flight.extend(Span(v.get(3, "construct a Certificate", "Certificate")))
    flight.extend(Span(v.get(3, "construct a CertificateVerify", "CertificateVerify")))
    flight.extend(Span(sfin))
    var shs = hs_cipher(v, "derive write traffic keys for handshake")
    var recs = tr.sh_rec.copy()
    seal_all(shs, HS, flight, recs)
    var cout = cli.feed(Span(recs))
    t.ok("client: server Finished with one bit flipped gives decrypt_error", cout.has(EV_ERROR) and cout.error.startswith("tls: decrypt_error") and not cout.has(EV_DONE))
    var cc = hs_cipher(v, "derive read traffic keys for handshake")
    var b = alert_of_record(cout.send, cc)
    t.ok("client: a fatal decrypt_error alert (2, 51) went out under the client handshake key", b[0] == 2 and b[1] == 51)


def main() raises:
    var t = T("flight")
    var v = Vec()
    for sec in [3, 5, 7]:
        var tr = Trace(v, sec)
        server_side(t, v, tr)
        client_side(t, v, tr)
    negatives(t, v)
    t.done()
