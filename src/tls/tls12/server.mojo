"""Server12: the TLS 1.2 server state machine, sans-IO. feed() takes bytes from the peer; the caller then sends
cn.take_output() and reads cn.take_app(). A failed feed() has already queued the fatal alert: flush and close.
Flow: ClientHello -> ServerHello, Certificate, ServerKeyExchange, ServerHelloDone -> ClientKeyExchange, CCS,
Finished -> CCS, Finished. ECDHE with AES-GCM or ChaCha20 only; extended master secret required; no resumption,
no renegotiation, no client certificates."""
from std.memory import ArcPointer
from tls.net.config import TlsConfig
from .conn import Conn, EV_NONE, EV_HS, EV_CCS, EV_APP, EV_CLOSE
from .crypto import Crypto12, K_RSA, K_P384
from .msg import *
from .wire import bytes_of, cat, put, ct_eq, wipe, bl
from tls.tls13.clientauth import verify_client
from tls.tls13.ticket import unix_now
from tls.tls13.wire import alert_of


struct Server12[C: Crypto12](Movable):
    var cn: Conn[Self.C]
    var cfg: ArcPointer[TlsConfig]
    var st: Int  # 0 ClientHello, 1 ClientKeyExchange, 2 CCS, 3 Finished, 4 done, 5 client Certificate, 6 CertificateVerify
    var cchain: List[List[UInt8]]
    var client_cert: List[UInt8]  # DER of the authenticated client certificate, empty if none
    var group: Int
    var eph: List[UInt8]
    var sni: String
    var alpn: String

    def __init__(out self, cfg: ArcPointer[TlsConfig]):
        self.cn = Conn[Self.C](True)
        self.cfg = cfg
        self.st = 0
        self.cchain = List[List[UInt8]]()
        self.client_cert = List[UInt8]()
        self.group = 0
        self.eph = List[UInt8]()
        self.sni = String()
        self.alpn = String()

    def feed(mut self, data: Span[UInt8, _]) raises:
        if self.cn.dead:
            raise Error("tls: connection is closed")
        self.cn.feed(data)
        try:
            self._step()
        except e:
            self.cn.die()
            wipe(self.eph)
            raise e^

    def _step(mut self) raises:
        while True:
            var ev = self.cn.poll()
            if ev == EV_NONE:
                return
            if ev == EV_CLOSE:
                self.cn.close()
                return
            if ev == EV_APP:
                continue
            if ev == EV_CCS:
                if self.st != 2:
                    raise self.cn.fatal(A_UNEXPECTED, "unexpected change_cipher_spec")
                self.cn.enable(True)
                self.st = 3
                continue
            var t = self.cn.ev_type
            if self.st == 0 and t == H_CH:
                self._client_hello()
            elif self.st == 5 and t == H_CERT:
                self._client_cert()
            elif self.st == 6 and t == H_CV:
                self._client_cv()
            elif self.st == 1 and t == H_CKE:
                self._client_key_exchange()
            elif self.st == 3 and t == H_FIN:
                self._finished()
            else:
                raise self.cn.fatal(A_UNEXPECTED, "unexpected handshake message")

    def _client_hello(mut self) raises:
        var ch = parse_client_hello(self.cn.ev_body)
        if not ch.offers12():
            raise self.cn.fatal(A_VERSION, "client does not offer TLS 1.2")
        if ch.ri_bad:
            raise self.cn.fatal(A_HANDSHAKE, "renegotiation_info on an initial handshake")
        if not ch.ems:
            raise self.cn.fatal(A_HANDSHAKE, "extended master secret required")
        self.group = choose_group(ch)
        if self.group == 0:
            raise self.cn.fatal(A_HANDSHAKE, "no common group")
        var pick = -1
        var scheme = 0
        for i in self.cfg[].order(ch.sni):
            ref e = self.cfg[].certs[i]
            var s: Int
            if e.kind == K_RSA:
                s = 0x0804 if 0x0804 in ch.sigalgs else (0x0401 if 0x0401 in ch.sigalgs else 0)
            else:
                s = (0x0503 if e.kind == K_P384 else 0x0403)
                s = s if s in ch.sigalgs else 0
            if s != 0:
                self.cn.suite = choose_suite(ch, e.kind != K_RSA, e.kind == K_RSA)
                if self.cn.suite != 0:
                    pick = i
                    scheme = s
                    break
        if pick < 0:
            raise self.cn.fatal(A_HANDSHAKE, "no common cipher suite, signature scheme and certificate")
        self.sni = ch.sni.copy()
        if len(ch.alpn) > 0 and len(self.cfg[].alpn) > 0:  # RFC 7301: a server with no ALPN protocols ignores the extension
            for a in self.cfg[].alpn:
                if a in ch.alpn:
                    self.alpn = a.copy()
                    break
            if self.alpn.byte_length() == 0:
                raise self.cn.fatal(A_NO_ALPN, "no common ALPN protocol")
        self.cn.cr = ch.random.copy()
        self.cn.sr = self.cn.c.random(32)
        if self.cfg[].tls13:  # RFC 8446 4.1.3: a server with a TLS 1.3 engine that answers with 1.2 sets the sentinel whatever the hello offered (an on-path peer can strip supported_versions); a 1.2-only server must stay silent or Firefox and Chrome abort
            var m = bytes_of("DOWNGRD")
            m.append(1)
            for i in range(8):
                self.cn.sr[24 + i] = m[i]
        ref e = self.cfg[].certs[pick]
        var kp = self.cn.c.keygen(self.group)
        self.eph = kp[0].copy()
        var params = ske_params(self.group, kp[1])
        var signed = cat(self.cn.cr, self.cn.sr, params)
        var sig = self.cn.c.sign(e.kind, e.key, scheme, signed)
        var flight = build_server_hello(self.cn.sr, self.cn.suite, True, True, ch.points, self.alpn, ch.sni.byte_length() > 0 and e.matches(ch.sni))
        put(flight, build_certificate(e.chain))
        put(flight, build_ske(params, scheme, sig))
        var auth = self.cfg[].require_client_cert
        if auth:
            put(flight, build_creq([0x0403, 0x0503, 0x0804, 0x0805, 0x0401, 0x0501]))
        put(flight, hs(H_SHD, List[UInt8]()))
        put(self.cn.tx, flight)
        self.cn.write_rec(HAND, flight)
        self.st = 5 if auth else 1

    def _client_cert(mut self) raises:
        if len(self.cn.ev_body) == 3 and self.cn.ev_body[0] == 0 and self.cn.ev_body[1] == 0 and self.cn.ev_body[2] == 0:
            raise self.cn.fatal(A_HANDSHAKE, "the client sent no certificate")  # RFC 5246 7.4.6: an empty Certificate answers a request
        self.cchain = parse_certificate(self.cn.ev_body)
        self.st = 1

    def _client_cv(mut self) raises:
        var cv = parse_cv(self.cn.ev_body)
        var cut = len(self.cn.tx) - 4 - len(self.cn.ev_body)  # the signature covers every message before this one
        try:
            if cv[0] not in [0x0403, 0x0503, 0x0804, 0x0805, 0x0401, 0x0501]:
                raise Error("tls: illegal_parameter: client CertificateVerify scheme")
            verify_client(self.cchain, self.cfg[].client_roots, unix_now(), cv[0], List[UInt8](Span(self.cn.tx)[:cut]), cv[1])
        except e:
            raise self.cn.fatal(alert_of(String(e)), String(e))
        self.client_cert = self.cchain[0].copy()
        self.st = 2

    def _client_key_exchange(mut self) raises:
        var pub = parse_cke(self.cn.ev_body)
        var shared: List[UInt8]
        try:
            shared = self.cn.c.ecdh(self.group, self.eph, pub)
        except:
            raise self.cn.fatal(A_ILLEGAL, "invalid key share")
        wipe(self.eph)
        self.cn.derive(shared^)
        self.st = 6 if self.cfg[].require_client_cert else 2

    def _finished(mut self) raises:
        var body = self.cn.ev_body.copy()
        if not ct_eq(body, self.cn.finished("client finished")):
            raise self.cn.fatal(A_DECRYPT, "bad Finished")
        put(self.cn.tx, hs(H_FIN, body))
        self.cn.write_rec(CCS, bl(1))
        self.cn.enable(False)
        self.cn.send_hs(hs(H_FIN, self.cn.finished("server finished")))
        wipe(self.cn.keys)
        wipe(self.cn.master)
        self.cn.established = True
        self.st = 4
