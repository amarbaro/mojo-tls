"""Client12: the TLS 1.2 client state machine, sans-IO (same shape as Server12). start() queues the ClientHello:
send cn.take_output() first. The server certificate chain and the ServerKeyExchange signature are checked through
Crypto12.verify (chain validation is lane 3). Extended master secret and renegotiation_info are required of the
server; client certificates are not supported (a CertificateRequest is a fatal error)."""
from .conn import Conn, EV_NONE, EV_HS, EV_CCS, EV_APP, EV_CLOSE
from .crypto import Crypto12
from .msg import *
from .wire import cat, put, ct_eq, wipe, bl, pre8
from tls.tls13.clientauth import key_schemes, sign_with_key


struct Client12[C: Crypto12](Movable):
    var cn: Conn[Self.C]
    var host: String
    var alpn: List[String]
    var offer13: Bool
    var st: Int  # 0 ServerHello, 1 Certificate, 2 ServerKeyExchange, 3 ServerHelloDone, 4 CCS, 5 Finished, 6 done
    var chain: List[List[UInt8]]
    var ske: Ske
    var negotiated: String  # the ALPN protocol the server chose
    var offered: List[Int]
    var cert_chain: List[List[UInt8]]  # client certificate for a CertificateRequest (set_client_cert), DER leaf first
    var cert_key: List[UInt8]
    var cr_schemes: List[Int]  # schemes of the CertificateRequest, empty = none asked
    var got_cr: Bool

    def __init__(out self, host: String, alpn: List[String], offer13: Bool = False, offered: List[Int] = suites()):
        self.cn = Conn[Self.C](False)
        self.host = host
        self.alpn = alpn.copy()
        self.offer13 = offer13
        self.st = 0
        self.chain = List[List[UInt8]]()
        self.ske = Ske()
        self.negotiated = String()
        self.cert_chain = List[List[UInt8]]()
        self.cert_key = List[UInt8]()
        self.cr_schemes = List[Int]()
        self.got_cr = False
        self.offered = offered.copy()

    def start(mut self) raises:
        """Queue the ClientHello; call once, then send cn.take_output()."""
        self.cn.cr = self.cn.c.random(32)
        self.cn.send_hs(build_client_hello(self.cn.cr, self.host, self.alpn, self.offer13, self.offered))

    def feed(mut self, data: Span[UInt8, _]) raises:
        if self.cn.dead:
            raise Error("tls: connection is closed")
        self.cn.feed(data)
        try:
            self._step()
        except e:
            self.cn.die()
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
                if self.st != 4:
                    raise self.cn.fatal(A_UNEXPECTED, "unexpected change_cipher_spec")
                self.cn.enable(True)
                self.st = 5
                continue
            var t = self.cn.ev_type
            if self.st == 0 and t == H_SH:
                self._server_hello()
            elif self.st == 1 and t == H_CERT:
                self.chain = parse_certificate(self.cn.ev_body)
                self.st = 2
            elif self.st == 2 and t == H_SKE:
                self._server_key_exchange()
            elif self.st == 3 and t == H_CREQ and not self.got_cr:
                self.cr_schemes = parse_creq(self.cn.ev_body)
                self.got_cr = True
            elif self.st == 3 and t == H_SHD:
                if len(self.cn.ev_body) != 0:
                    raise self.cn.fatal(A_DECODE, "bad ServerHelloDone")
                self._key_exchange()
            elif self.st == 5 and t == H_FIN:
                if not ct_eq(self.cn.ev_body, self.cn.finished("server finished")):
                    raise self.cn.fatal(A_DECRYPT, "bad Finished")
                wipe(self.cn.keys)
                wipe(self.cn.master)
                self.cn.established = True
                self.st = 6
            else:
                raise self.cn.fatal(A_UNEXPECTED, "unexpected handshake message")

    def _server_hello(mut self) raises:
        var sh = parse_server_hello(self.cn.ev_body)
        if sh.suite not in self.offered:
            raise self.cn.fatal(A_ILLEGAL, "server chose a suite we did not offer")
        if not sh.ems or not sh.ri or sh.ri_bad:
            raise self.cn.fatal(A_HANDSHAKE, "server lacks extended master secret or secure renegotiation")
        if self.offer13 and sentinel(sh.random):
            raise self.cn.fatal(A_ILLEGAL, "TLS 1.3 downgrade detected")
        if sh.alpn.byte_length() > 0 and sh.alpn not in self.alpn:
            raise self.cn.fatal(A_ILLEGAL, "server chose an ALPN protocol we did not offer")
        self.negotiated = sh.alpn.copy()
        self.cn.suite = sh.suite
        self.cn.sr = sh.random.copy()
        self.st = 1

    def _server_key_exchange(mut self) raises:
        self.ske = parse_ske(self.cn.ev_body)
        var g = self.ske.group
        var sch = self.ske.scheme
        var ecdsa = sch == 0x0403 or sch == 0x0503
        if not (g == G_X25519 or g == G_P256 or g == G_P384) or ecdsa != suite_ecdsa(self.cn.suite):
            raise self.cn.fatal(A_ILLEGAL, "group or signature scheme does not fit the suite")
        if not (ecdsa or sch == 0x0804 or sch == 0x0805 or sch == 0x0401 or sch == 0x0501):
            raise self.cn.fatal(A_ILLEGAL, "signature scheme not offered")
        try:
            self.cn.c.verify(self.chain, self.host, sch, cat(self.cn.cr, self.cn.sr, self.ske.params), self.ske.sig)
        except e:
            raise self.cn.fatal(A_BAD_CERT, String("server certificate or signature rejected: ", e))
        self.st = 3

    def set_client_cert(mut self, chain: List[List[UInt8]], key_der: List[UInt8]):
        """Present `chain` (signed with `key_der`) when the server sends a CertificateRequest; otherwise an empty Certificate."""
        self.cert_chain = chain.copy()
        self.cert_key = key_der.copy()

    def _key_exchange(mut self) raises:
        var kp = self.cn.c.keygen(self.ske.group)
        var shared: List[UInt8]
        try:
            shared = self.cn.c.ecdh(self.ske.group, kp[0], self.ske.pub)
        except:
            raise self.cn.fatal(A_ILLEGAL, "invalid server key share")
        wipe(kp[0])
        var scheme = 0
        if self.got_cr:
            if len(self.cert_chain) > 0:
                for s in key_schemes(self.cert_key):
                    if scheme == 0 and s in self.cr_schemes:
                        scheme = s
            self.cn.send_hs(build_certificate(self.cert_chain.copy() if scheme != 0 else List[List[UInt8]]()))
        self.cn.send_hs(hs(H_CKE, pre8(kp[1])))
        self.cn.derive(shared^)
        if scheme != 0:  # RFC 5246 7.4.8: the signature covers the handshake messages up to and including the ClientKeyExchange
            self.cn.send_hs(build_cv(scheme, sign_with_key(self.cert_key, scheme, self.cn.tx.copy())))
        self.cn.write_rec(CCS, bl(1))
        self.cn.enable(False)
        self.cn.send_hs(hs(H_FIN, self.cn.finished("client finished")))
        self.st = 4
