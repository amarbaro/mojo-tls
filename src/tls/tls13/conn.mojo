# mojo-tls lane 4: the part of a TLS 1.3 connection that client and server share: record in/out, handshake
# reassembly, transcript, alerts, KeyUpdate, application data, key limit. Sans-IO: bytes in, an Out of bytes/events out.
from tls.sym.aead import dup
from tls.tls13.record import Cipher, RecordReader, seal_all, CCS, ALERT, HS, APP, MAX_PLAIN
from tls.tls13.keysched import KeySchedule, traffic_key, traffic_iv, next_secret, hash_of, suite_hash_len, suite_key_len
from tls.tls13.messages import Ticket, enc_ku, hs_body, parse_nst, H_KU, H_NST
from tls.tls13.wire import bad, alert_of, alert_name, wipe, putb

comptime EV_DONE = 1  # handshake complete, application data may flow
comptime EV_CLOSE = 2  # peer sent close_notify
comptime EV_KEYUPDATE = 3  # peer updated its sending key
comptime EV_TICKET = 4  # client stored a NewSessionTicket
comptime EV_ERROR = 5  # fatal error, see Out.error; the alert is already in Out.send

comptime S_WAIT_SH = 1
comptime S_WAIT_EE = 2
comptime S_WAIT_CERT = 3  # Certificate or CertificateRequest
comptime S_WAIT_CERT2 = 4  # Certificate after CertificateRequest
comptime S_WAIT_CV = 5
comptime S_WAIT_FIN = 6
comptime S_WAIT_CH = 10
comptime S_WAIT_CH2 = 11
comptime S_OPEN = 20
comptime S_CLOSED = 21
comptime S_FAILED = 22

comptime MAX_HS = 65536  # one handshake message
comptime MAX_TICKETS = 8


struct Out(Movable):
    var send: List[UInt8]  # bytes for the peer
    var data: List[UInt8]  # decrypted application data
    var events: List[Int]
    var error: String

    def __init__(out self):
        self.send = List[UInt8]()
        self.data = List[UInt8]()
        self.events = List[Int]()
        self.error = String()

    def has(self, ev: Int) -> Bool:
        for e in self.events:
            if e == ev:
                return True
        return False


struct Conn(Movable):
    var client: Bool
    var state: Int
    var rd: RecordReader
    var rx: Cipher
    var tx: Cipher
    var hs: List[UInt8]  # received handshake bytes not yet a whole message
    var transcript: List[UInt8]
    var suite: Int
    var h: Int
    var ks: KeySchedule
    var rx_secret: List[UInt8]
    var tx_secret: List[UInt8]
    var chs: List[UInt8]  # handshake traffic secrets, kept until the Finished messages are done
    var shs: List[UInt8]
    var res_master: List[UInt8]
    var exp_master: List[UInt8]
    var tickets: List[Ticket]
    var ccs_in: Int
    var ccs_out: Bool
    var wclosed: Bool
    var rx_limit: Int  # largest content a record may carry, from our record_size_limit
    var key_limit: UInt64  # records per sending key before we send KeyUpdate
    var skip: Int  # bytes of undecryptable early data we may still skip (RFC 8446 4.2.10, 0-RTT refused)

    def __init__(out self, client: Bool):
        self.client = client
        self.state = 0
        self.rd = RecordReader()
        self.rx = Cipher()
        self.tx = Cipher()
        self.hs = List[UInt8]()
        self.transcript = List[UInt8]()
        self.suite = 0
        self.h = 32
        self.ks = KeySchedule(32)
        self.rx_secret = List[UInt8]()
        self.tx_secret = List[UInt8]()
        self.chs = List[UInt8]()
        self.shs = List[UInt8]()
        self.res_master = List[UInt8]()
        self.exp_master = List[UInt8]()
        self.tickets = List[Ticket]()
        self.ccs_in = 0
        self.ccs_out = False
        self.wclosed = False
        self.rx_limit = MAX_PLAIN
        self.key_limit = UInt64(1) << 24  # RFC 8446 5.5: AES-GCM allows 2^24.5 records
        self.skip = 0

    def set_suite(mut self, suite: Int) raises:
        _ = suite_key_len(suite)
        self.suite = suite
        self.h = suite_hash_len(suite)
        self.ks = KeySchedule(self.h)

    def add(mut self, msg: List[UInt8]):
        self.transcript.extend(Span(msg))

    def th(self) -> List[UInt8]:
        return hash_of(self.h, self.transcript)

    def install_tx(mut self, secret: List[UInt8]) raises:
        self.tx_secret = secret.copy()
        self.tx.set(self.suite, traffic_key(self.h, secret, suite_key_len(self.suite)), traffic_iv(self.h, secret))

    def install_rx(mut self, secret: List[UInt8]) raises:
        self.rx_secret = secret.copy()
        self.rx.set(self.suite, traffic_key(self.h, secret, suite_key_len(self.suite)), traffic_iv(self.h, secret))

    def install_hs(mut self) raises:
        """Handshake traffic keys: client sends under chs and reads shs, the server the reverse."""
        var a = self.chs.copy()
        var b = self.shs.copy()
        if self.client:
            self.install_rx(b)
            self.install_tx(a)
        else:
            self.install_tx(b)
            self.install_rx(a)

    def send_ccs(mut self, mut o: List[UInt8]):
        """Middlebox-compatibility ChangeCipherSpec (RFC 8446 D.4), at most once."""
        if not self.ccs_out:
            self.ccs_out = True
            var ccs: List[UInt8] = [20, 3, 3, 0, 1, 1]
            o.extend(Span(ccs))

    def send_alert(mut self, level: Int, desc: Int, mut o: List[UInt8]) raises:
        var a = List[UInt8](capacity=2)
        a.append(UInt8(level))
        a.append(UInt8(desc))
        seal_all(self.tx, ALERT, a, o)

    def step(mut self, mut out: Out) raises -> Bool:
        """Process one record. False when the input holds no whole record."""
        var rec = List[UInt8]()
        if not self.rd.next(rec):
            return False
        var typ = Int(rec[0])
        if typ == CCS:
            if self.state == S_OPEN or len(rec) != 6 or rec[5] != 1 or self.ccs_in >= 2 or len(self.transcript) == 0:
                raise bad("unexpected_message", "change_cipher_spec")
            self.ccs_in += 1
            return True
        var body = List[UInt8]()
        if self.rx.on:
            if typ != APP:
                raise bad("unexpected_message", "unprotected record after the keys were installed")
            var r: Tuple[Int, List[UInt8]]
            try:
                r = self.rx.open(rec)
            except e:
                var used = max(1, len(rec) - 5)  # an empty record spends one byte: the budget must run out
                if self.state != S_WAIT_FIN or self.skip < used:
                    raise e
                self.skip -= used  # early data we refused: it was sealed under a key we never had
                return True
            self.skip = 0  # a record that opens ends the early data
            typ = r[0]
            body = r[1].copy()
            if len(body) > self.rx_limit:
                raise bad("record_overflow", "record longer than our record_size_limit")
        else:
            if typ == APP:
                var used = max(1, len(rec) - 5)
                if self.skip < used:
                    raise bad("unexpected_message", "unprotected application data")
                self.skip -= used  # early data sent before a HelloRetryRequest
                return True
            if len(rec) - 5 > MAX_PLAIN:
                raise bad("record_overflow", "record longer than 2^14")
            body = dup(Span(rec)[5:])
        if typ == ALERT:
            if len(self.hs) > 0:
                raise bad("unexpected_message", "alert inside a handshake message")
            if len(body) != 2:
                raise bad("decode_error", "alert length")
            if body[1] == 0:
                out.events.append(EV_CLOSE)
                if not self.wclosed:
                    self.wclosed = True
                    self.send_alert(1, 0, out.send)
                self.state = S_CLOSED
                self.wipe()
            elif body[1] != 90:  # user_canceled is ignored; every other alert is fatal in TLS 1.3
                raise bad("peer_alert", alert_name(Int(body[1])))
        elif typ == HS:
            if len(body) == 0:
                raise bad("unexpected_message", "empty handshake record")
            self.hs.extend(Span(body))
        elif typ == APP:
            if self.state != S_OPEN or len(self.hs) > 0:
                raise bad("unexpected_message", "application data in the handshake")
            out.data.extend(Span(body))
        else:
            raise bad("unexpected_message", "record type " + String(typ))
        return True

    def take_msg(mut self, mut m: List[UInt8]) raises -> Bool:
        """Move the next whole handshake message (header included) from the reassembly buffer into m."""
        if len(self.hs) < 4:
            return False
        var n = (Int(self.hs[1]) << 16) | (Int(self.hs[2]) << 8) | Int(self.hs[3])
        if n > MAX_HS:
            raise bad("decode_error", "handshake message longer than 64 KiB")
        if len(self.hs) < 4 + n:
            return False
        m = List[UInt8](Span(self.hs)[0 : 4 + n])
        self.hs = List[UInt8](Span(self.hs)[4 + n :])
        return True

    def at_boundary(self) raises:
        """Keys change only between records: nothing may follow the message that changes them."""
        if len(self.hs) != 0:
            raise bad("unexpected_message", "handshake data after a key change")

    def post(mut self, mut out: Out, m: List[UInt8]) raises:
        """A handshake message after the handshake: KeyUpdate, or NewSessionTicket on a client."""
        var t = Int(m[0])
        if t == H_KU:
            var r = hs_body(m, H_KU)
            var req = r.u8()
            r.done()
            if req > 1:
                raise bad("illegal_parameter", "KeyUpdate request value")
            self.at_boundary()
            self.install_rx(next_secret(self.h, self.rx_secret))
            out.events.append(EV_KEYUPDATE)
            if req == 1:
                self.key_update(False, out.send)
        elif t == H_NST and self.client:
            var tk = parse_nst(m)
            if len(self.tickets) < MAX_TICKETS:
                self.tickets.append(tk^)
                out.events.append(EV_TICKET)
        else:
            raise bad("unexpected_message", "handshake message " + String(t) + " after the handshake")

    def key_update(mut self, request: Bool, mut o: List[UInt8]) raises:
        """Send KeyUpdate under the old key, then switch the sending key (RFC 8446 4.6.3)."""
        seal_all(self.tx, HS, enc_ku(request), o)
        self.install_tx(next_secret(self.h, self.tx_secret))

    def send_app(mut self, data: List[UInt8]) raises -> List[UInt8]:
        var o = List[UInt8](capacity=len(data) + 64 + (len(data) // self.tx.limit + 1) * 22)  # every record adds a header, a type byte and a tag
        if self.state != S_OPEN or self.wclosed:
            raise bad("internal_error", "connection not open for writing")
        var i = 0
        while i < len(data):
            if self.tx.seq >= self.key_limit:
                self.key_update(True, o)
            var n = min(len(data) - i, self.tx.limit)
            self.tx.seal(APP, data, i, n, o)
            i += n
        return o^

    def close(mut self) -> List[UInt8]:
        """close_notify; nothing more is sent after it."""
        var o = List[UInt8]()
        if not self.wclosed and self.state != S_FAILED:
            self.wclosed = True
            try:
                self.send_alert(1, 0, o)
            except:
                pass
        return o^

    def fail(mut self, e: Error, mut out: Out):
        """Fatal error: send the alert the message names (unless the peer sent it), wipe keys, stop."""
        var msg = String(e)
        if self.state != S_FAILED:
            if not msg.startswith("tls: peer_alert"):
                try:
                    self.send_alert(2, alert_of(msg), out.send)
                except:
                    pass
            self.state = S_FAILED
            out.error = msg^
            out.events.append(EV_ERROR)
            self.wipe()

    def wipe(mut self):
        self.rx.wipe()
        self.tx.wipe()
        wipe(self.rx_secret)
        wipe(self.tx_secret)
        wipe(self.chs)
        wipe(self.shs)
        wipe(self.res_master)
        wipe(self.exp_master)
        wipe(self.ks.secret)
