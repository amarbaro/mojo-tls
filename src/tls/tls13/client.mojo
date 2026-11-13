# mojo-tls lane 4: TLS 1.3 client state machine, sans-IO (RFC 8446 4, 4.1.4 HelloRetryRequest, 4.6 post-handshake).
# Client13(hello, host, x25519_private, p256_private, verifier): start() returns the ClientHello record, feed(bytes)
# returns an Out. Randomness is given by the caller (the hello holds the random, the private keys are arguments).
from tls.asym import x25519, x25519_base, x448, x448_base, P256Key, p384_public, p384_ecdh, random_bytes
from tls.tls13.conn import *
from tls.tls13.keysched import hash_of, finished_mac, cv_content
from tls.tls13.messages import *
from tls.tls13.keysched import KeySchedule, suite_hash_len
from tls.tls13.record import seal_all, HS, MAX_PLAIN
from tls.tls13.clientauth import key_schemes, sign_with_key
from tls.tls13.ticket import Session, resumption_psk, binder_of, truncated_hash
from tls.tls13.verify import Verifier
from tls.tls13.wire import Rd, bad, ct_equal, wipe, str_of, is_ip


def kex_public(group: Int, xp: List[UInt8], pp: List[UInt8], qp: List[UInt8], yp: List[UInt8]) raises -> List[UInt8]:
    """Public share of our private key for `group`: xp x25519, pp P-256, qp P-384, yp x448."""
    if group == G_X25519:
        return x25519_base(xp)
    if group == G_P256:
        return P256Key(pp).public_bytes()
    if group == G_P384:
        return p384_public(qp)
    if group == G_X448:
        return x448_base(yp)
    raise bad("internal_error", "key exchange group")


def kex_shared(
    group: Int, xp: List[UInt8], pp: List[UInt8], qp: List[UInt8], yp: List[UInt8], peer: List[UInt8]
) raises -> List[UInt8]:
    """The (EC)DHE secret; a malformed or low-order peer share is illegal_parameter."""
    try:
        if group == G_X25519:
            return x25519(xp, peer)
        if group == G_P256:
            return P256Key(pp).ecdh(peer)
        if group == G_P384:
            return p384_ecdh(qp, peer)
        if group == G_X448:
            return x448(yp, peer)
    except e:
        raise bad("illegal_parameter", "invalid key share")
    raise bad("illegal_parameter", "unsupported key share group")


def pad_hello(mut h: Hello) raises:
    """RFC 7685 padding: a ClientHello of 256..511 bytes is padded to 512 (avoids a known middlebox bug)."""
    var i = find(h.exts, X_PADDING)
    if i >= 0:
        _ = h.exts.pop(i)
    var n = len(h.encode())
    if n >= 256 and n <= 507:
        var at = find(h.exts, X_PSK)  # pre_shared_key stays the last extension
        h.exts.insert(at if at >= 0 else len(h.exts), Ext(X_PADDING, List[UInt8](length=512 - n - 4, fill=0)))


def default_hello(
    host: String, random: List[UInt8], sid: List[UInt8], x_pub: List[UInt8], alpn: List[String]
) raises -> Hello:
    """ClientHello offering TLS 1.3 only, x25519 share, secp256r1, secp384r1 and x448 on request (HRR), the three TLS 1.3 suites."""
    var e = List[Ext]()
    if host.byte_length() > 0 and not is_ip(host):
        e.append(x_sni(host))
    e.append(x_versions_client([0x0304]))
    e.append(x_u16s(X_GROUPS, [G_X25519, G_P256, G_P384, G_X448]))
    e.append(x_u16s(X_SIGALGS, [0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501]))
    e.append(x_keyshares([(G_X25519, x_pub.copy())]))
    if len(alpn) > 0:
        e.append(x_alpn(alpn))
    var h = Hello(False, random, sid, [0x1301, 0x1303, 0x1302], e^)
    pad_hello(h)
    return h^


def bind_hello(mut ch: Hello, transcript: List[UInt8], psk: List[UInt8]) raises:
    """Fill in the PSK binder of `ch` over the transcript so far (RFC 8446 4.2.11.2)."""
    var i = find(ch.exts, X_PSK)
    if i < 0:
        return
    var h = len(psk)
    var b = binder_of(h, psk, truncated_hash(h, transcript, ch.encode(), 3 + h))
    var d = len(ch.exts[i].d)
    for j in range(h):
        ch.exts[i].d[d - h + j] = b[j]


def shared_groups(h: Hello) raises -> List[Int]:
    var o = List[Int]()
    for s in p_keyshares(h.exts[find(h.exts, X_KEYSHARE)].d):
        o.append(s[0])
    return o^


struct Client13[V: Verifier](Movable):
    var c: Conn
    var v: Self.V
    var host: String
    var ch: Hello
    var x_priv: List[UInt8]
    var p_priv: List[UInt8]
    var q_priv: List[UInt8]  # P-384 and x448 keys, used only after a HelloRetryRequest
    var y_priv: List[UInt8]
    var hrr_done: Bool
    var hrr_suite: Int
    var th_cert: List[UInt8]
    var chain: List[List[UInt8]]
    var cr_ctx: List[UInt8]
    var got_cr: Bool
    var cert_chain: List[List[UInt8]]  # client certificate to present when asked (set_client_cert), DER leaf first
    var cert_key: List[UInt8]  # its PKCS#8 / SEC1 private key
    var cr_schemes: List[Int]  # signature schemes the server's CertificateRequest accepts
    var force_scheme: Int  # test hook: sign the CertificateVerify with this scheme even when the server did not list it
    var alpn: String  # protocol the server selected, empty if none
    var group: Int  # group of the key exchange that was used
    var sess: Session  # ticket offered by offer(), valid while resumed is set or an offer is outstanding
    var offered: Bool
    var resumed: Bool  # the server accepted the PSK: no certificate flight

    def __init__(
        out self, ch: Hello, host: String, x_priv: List[UInt8], p_priv: List[UInt8], var v: Self.V
    ) raises:
        if find(ch.exts, X_KEYSHARE) < 0 or find(ch.exts, X_GROUPS) < 0 or find(ch.exts, X_SIGALGS) < 0:
            raise bad("internal_error", "ClientHello needs key_share, supported_groups, signature_algorithms")
        self.c = Conn(True)
        self.v = v^
        self.host = host
        self.ch = ch.copy()
        self.x_priv = x_priv.copy()
        self.p_priv = p_priv.copy()
        self.q_priv = random_bytes(48)
        self.y_priv = random_bytes(56)
        self.hrr_done = False
        self.hrr_suite = 0
        self.th_cert = List[UInt8]()
        self.chain = List[List[UInt8]]()
        self.cr_ctx = List[UInt8]()
        self.got_cr = False
        self.cert_chain = List[List[UInt8]]()
        self.cert_key = List[UInt8]()
        self.cr_schemes = List[Int]()
        self.force_scheme = 0
        self.alpn = String()
        self.group = 0
        self.sess = Session(0, List[UInt8](), List[UInt8](), 0, 0, 0)
        self.offered = False
        self.resumed = False

    def offer(mut self, s: Session, now_ms: Int) raises:
        """Offer `s` (from session()) in the ClientHello, before start(): psk_dhe_ke with one identity (RFC 8446 4.2.11)."""
        if s.suite not in self.ch.suites:
            raise bad("internal_error", "session suite is not offered in the ClientHello")
        self.sess = s.copy()
        self.offered = True
        var age = (now_ms - s.at_ms + s.age_add) & 0xFFFFFFFF
        var i = find(self.ch.exts, X_PSK)
        if i >= 0:
            _ = self.ch.exts.pop(i)
        if find(self.ch.exts, X_PSK_MODES) < 0:
            self.ch.exts.append(x_psk_modes())
        self.ch.exts.append(x_psk_client(s.ticket, age, len(s.psk)))
        pad_hello(self.ch)

    def set_client_cert(mut self, chain: List[List[UInt8]], key_der: List[UInt8]):
        """Present `chain` (signed with `key_der`) when the server sends a CertificateRequest; before that or without a
        matching signature scheme the answer is an empty Certificate."""
        self.cert_chain = chain.copy()
        self.cert_key = key_der.copy()

    def session(self, i: Int, now_ms: Int) raises -> Session:
        """The i-th NewSessionTicket this connection received, as a Session; `now_ms` stamps its arrival."""
        var t = self.c.tickets[i].copy()
        return Session(self.c.suite, resumption_psk(self.c.h, self.c.res_master, t.nonce), t.ticket, t.age_add, t.lifetime, now_ms)

    def start(mut self) raises -> List[UInt8]:
        """The first flight: the ClientHello record."""
        bind_hello(self.ch, self.c.transcript, self.sess.psk)
        var m = self.ch.encode()
        self.c.add(m)
        var o = List[UInt8]()
        self.c.tx.pver = 0x0301
        seal_all(self.c.tx, HS, m, o)
        self.c.tx.pver = 0x0303
        self.c.state = S_WAIT_SH
        return o^

    def feed(mut self, data: Span[UInt8, _]) -> Out:
        var out = Out()
        if self.c.state == 0 or self.c.state >= S_CLOSED:
            return out^
        try:
            self.c.rd.push(data)
            var m = List[UInt8]()
            while self.c.state < S_CLOSED and self.c.step(out):
                while self.c.state < S_CLOSED and self.c.take_msg(m):
                    self.on_msg(out, m)
        except e:
            self.c.fail(e, out)
        return out^

    def write(mut self, data: List[UInt8]) raises -> List[UInt8]:
        return self.c.send_app(data)

    def close(mut self) -> List[UInt8]:
        return self.c.close()

    def key_update(mut self) raises -> List[UInt8]:
        var o = List[UInt8]()
        self.c.key_update(True, o)
        return o^

    def on_msg(mut self, mut out: Out, m: List[UInt8]) raises:
        var s = self.c.state
        if s == S_OPEN:
            self.c.post(out, m)
        elif s == S_WAIT_SH:
            self.on_sh(out, m)
        elif s == S_WAIT_EE:
            self.on_ee(m)
        elif s == S_WAIT_CERT and Int(m[0]) == H_CR:
            var cr = parse_cr(m)
            self.cr_ctx = cr[0].copy()
            self.cr_schemes = p_u16s(cr[1][find(cr[1], X_SIGALGS)].d)
            self.got_cr = True
            self.c.add(m)
            self.c.state = S_WAIT_CERT2
        elif s == S_WAIT_CERT or s == S_WAIT_CERT2:
            self.on_cert(m)
        elif s == S_WAIT_CV:
            self.on_cv(m)
        else:
            self.on_fin(out, m)

    def on_sh(mut self, mut out: Out, m: List[UInt8]) raises:
        var sh = parse_hello(m, True)
        var suite = sh.suites[0]
        if sh.ver != 0x0303 or sh.sid != self.ch.sid or suite not in self.ch.suites:
            raise bad("illegal_parameter", "ServerHello does not match our ClientHello")
        var vi = find(sh.exts, X_VERSIONS)
        if vi < 0:
            raise bad("protocol_version", "server did not select TLS 1.3")
        if p_version_server(sh.exts[vi].d) != 0x0304:
            raise bad("illegal_parameter", "selected version")
        for e in sh.exts:
            if e.t != X_KEYSHARE and e.t != X_VERSIONS and not (e.t == X_PSK and self.offered and not sh.is_hrr()) and not (sh.is_hrr() and e.t == X_COOKIE):
                raise bad("illegal_parameter" if find(self.ch.exts, e.t) >= 0 else "unsupported_extension", "extension " + String(e.t) + " in ServerHello")  # RFC 8446 4.2: offered but not defined here / never offered
        if self.hrr_done and suite != self.hrr_suite:
            raise bad("illegal_parameter", "cipher suite changed after HelloRetryRequest")
        self.c.set_suite(suite)
        if sh.is_hrr():
            self.on_hrr(out, sh, m)
            return
        var ki = find(sh.exts, X_KEYSHARE)
        if ki < 0:
            raise bad("missing_extension", "ServerHello without key_share")
        var pi = find(sh.exts, X_PSK)
        if pi >= 0:
            var pr = Rd(sh.exts[pi].d.copy())
            if pr.u16() != 0 or pr.left() != 0:
                raise bad("illegal_parameter", "selected PSK identity")
            if suite_hash_len(suite) != len(self.sess.psk):
                raise bad("illegal_parameter", "PSK hash does not match the cipher suite")
            self.resumed = True
            self.c.ks = KeySchedule(self.c.h, self.sess.psk)
        var share = p_keyshare_server(sh.exts[ki].d)
        if share[0] not in shared_groups(self.ch):
            raise bad("illegal_parameter", "server chose a group we sent no share for")
        self.group = share[0]
        var dhe = kex_shared(share[0], self.x_priv, self.p_priv, self.q_priv, self.y_priv, share[1])
        self.c.add(m)
        self.c.at_boundary()
        var th = self.c.th()
        self.c.ks.to_handshake(dhe)
        self.c.chs = self.c.ks.derive("c hs traffic", th)
        self.c.shs = self.c.ks.derive("s hs traffic", th)
        self.c.install_hs()
        self.c.state = S_WAIT_EE

    def on_hrr(mut self, mut out: Out, sh: Hello, m: List[UInt8]) raises:
        if self.hrr_done:
            raise bad("unexpected_message", "second HelloRetryRequest")
        var ch2 = self.ch.copy()
        var ei = find(ch2.exts, X_EARLY)
        if ei >= 0:
            _ = ch2.exts.pop(ei)  # RFC 8446 4.1.2: the second ClientHello drops early_data
        var changed = False
        var ki = find(sh.exts, X_KEYSHARE)
        if ki >= 0:
            var r = Rd(sh.exts[ki].d.copy())
            var g = r.u16()
            r.done()
            if g not in p_u16s(self.ch.exts[find(self.ch.exts, X_GROUPS)].d) or g in shared_groups(self.ch):
                raise bad("illegal_parameter", "HelloRetryRequest group")
            ch2.exts[find(ch2.exts, X_KEYSHARE)] = x_keyshares([(g, kex_public(g, self.x_priv, self.p_priv, self.q_priv, self.y_priv))])
            changed = True
        var ci = find(sh.exts, X_COOKIE)
        if ci >= 0:
            _ = p_cookie(sh.exts[ci].d)
            var at = find(ch2.exts, X_PSK_MODES)
            ch2.exts.insert(at if at >= 0 else len(ch2.exts), Ext(X_COOKIE, sh.exts[ci].d.copy()))
            changed = True
        if not changed:
            raise bad("illegal_parameter", "HelloRetryRequest asks for no change")
        pad_hello(ch2)
        self.c.transcript = hs_msg(H_MSGHASH, hash_of(self.c.h, self.c.transcript))
        self.c.add(m)
        bind_hello(ch2, self.c.transcript, self.sess.psk)
        var m2 = ch2.encode()
        self.c.add(m2)
        if len(ch2.sid) > 0:
            self.c.send_ccs(out.send)
        seal_all(self.c.tx, HS, m2, out.send)
        self.ch = ch2^
        self.hrr_done = True
        self.hrr_suite = sh.suites[0]

    def on_ee(mut self, m: List[UInt8]) raises:
        for e in parse_ee(m):
            if find(self.ch.exts, e.t) < 0:
                raise bad("unsupported_extension", "EncryptedExtensions carries an extension we did not offer")
            if e.t != X_SNI and e.t != X_GROUPS and e.t != X_ALPN and e.t != X_EARLY and e.t != X_RSL:  # RFC 8446 4.2: not defined for this message
                raise bad("illegal_parameter", "extension " + String(e.t) + " in EncryptedExtensions")
            if e.t == X_ALPN:
                var p = p_alpn(e.d)
                if len(p) != 1 or p[0] not in p_alpn(self.ch.exts[find(self.ch.exts, X_ALPN)].d):
                    raise bad("illegal_parameter", "ALPN selection")
                self.alpn = p[0]
            elif e.t == X_RSL:
                self.c.tx.limit = min(MAX_PLAIN, p_rsl(e.d) - 1)
        self.c.add(m)
        self.c.state = S_WAIT_FIN if self.resumed else S_WAIT_CERT

    def on_cert(mut self, m: List[UInt8]) raises:
        var c = parse_cert(m)
        if len(c[0]) != 0 or len(c[1]) == 0:
            raise bad("illegal_parameter" if len(c[1]) > 0 else "decode_error", "server Certificate")
        self.chain = c[1].copy()
        self.c.add(m)
        self.th_cert = self.c.th()
        self.c.state = S_WAIT_CV

    def on_cv(mut self, m: List[UInt8]) raises:
        var cv = parse_cv(m)
        var offered = p_u16s(self.ch.exts[find(self.ch.exts, X_SIGALGS)].d)
        if cv[0] not in offered or cv[0] == 0x0401 or cv[0] == 0x0501 or cv[0] == 0x0601 or cv[0] == 0x0201:
            raise bad("illegal_parameter", "CertificateVerify scheme")  # rsa_pkcs1 is not allowed here (4.2.3)
        self.v.verify(self.chain, cv[0], cv_content(False, self.th_cert), cv[1], self.host)
        self.c.add(m)
        self.c.state = S_WAIT_FIN

    def on_fin(mut self, mut out: Out, m: List[UInt8]) raises:
        var h = self.c.h
        if not ct_equal(parse_fin(m, h), finished_mac(h, self.c.shs, self.c.th())):
            raise bad("decrypt_error", "server Finished does not verify")
        self.c.add(m)
        self.c.at_boundary()
        var th_sf = self.c.th()
        self.c.ks.to_master()
        var cap = self.c.ks.derive("c ap traffic", th_sf)
        var sap = self.c.ks.derive("s ap traffic", th_sf)
        self.c.exp_master = self.c.ks.derive("exp master", th_sf)
        var flight = List[UInt8]()
        if self.got_cr:  # our certificate if a scheme of its key is accepted, else an empty Certificate
            var scheme = 0
            if len(self.cert_chain) > 0:
                for s in key_schemes(self.cert_key):
                    if scheme == 0 and s in self.cr_schemes:
                        scheme = s
            if self.force_scheme != 0 and len(self.cert_chain) > 0:
                scheme = self.force_scheme
            var cm = enc_cert(self.cr_ctx, self.cert_chain.copy() if scheme != 0 else List[List[UInt8]]())
            self.c.add(cm)
            flight.extend(Span(cm))
            if scheme != 0:
                var cvm = enc_cv(scheme, sign_with_key(self.cert_key, scheme, cv_content(True, self.c.th())))
                self.c.add(cvm)
                flight.extend(Span(cvm))
        var fin = enc_fin(finished_mac(h, self.c.chs, self.c.th()))
        self.c.add(fin)
        flight.extend(Span(fin))
        if len(self.ch.sid) > 0:
            self.c.send_ccs(out.send)
        seal_all(self.c.tx, HS, flight, out.send)
        self.c.res_master = self.c.ks.derive("res master", self.c.th())
        self.c.install_tx(cap)
        self.c.install_rx(sap)
        wipe(self.c.chs)
        wipe(self.c.shs)
        self.c.state = S_OPEN
        out.events.append(EV_DONE)
