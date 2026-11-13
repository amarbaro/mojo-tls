"""The part of a TLS 1.2 connection both roles share, sans-IO: record layer (RFC 5246 6, AEAD suites only, GCM
and RFC 7905 ChaCha20), handshake reassembly with size caps, transcript, key schedule (extended master secret,
RFC 7627: the only mode we speak), alerts. Bytes in with feed(), bytes out with take_output()."""
from tls.sym.aead import dup
from .crypto import Crypto12
from .msg import *
from .wire import Rd, bl, cat, p16, put, wipe, bytes_of

comptime EV_NONE = 0
comptime EV_HS = 1  # a handshake message is in ev_type / ev_body / ev_raw
comptime EV_CCS = 2
comptime EV_APP = 3  # decrypted data was appended to app
comptime EV_CLOSE = 4  # the peer sent close_notify
comptime MAX_REC = 16384


struct Cipher(Movable):
    var on: Bool
    var aead: Int
    var key: List[UInt8]
    var iv: List[UInt8]  # 4 bytes (GCM) or 12 bytes (ChaCha)
    var seq: UInt64
    var nonce: List[UInt8]  # scratch, no per-record allocation
    var aad: List[UInt8]

    def __init__(out self):
        self.on = False
        self.aead = 0
        self.key = List[UInt8]()
        self.iv = List[UInt8]()
        self.seq = 0
        self.nonce = List[UInt8](length=12, fill=0)
        self.aad = List[UInt8](length=13, fill=0)

    def start(mut self, aead: Int, var key: List[UInt8], var iv: List[UInt8]):
        self.on = True
        self.aead = aead
        self.key = key^
        self.iv = iv^
        self.seq = 0

    def prep(mut self, typ: Int, plen: Int):
        """AAD for the next record, and for ChaCha its nonce (iv xor seq); GCM fills the explicit part itself."""
        for i in range(8):
            var b = UInt8((self.seq >> UInt64(56 - 8 * i)) & 255)
            self.aad[i] = b
            if self.aead == 2:
                self.nonce[4 + i] = self.iv[4 + i] ^ b
        for i in range(4):
            self.nonce[i] = self.iv[i]
        self.aad[8] = UInt8(typ)
        self.aad[9] = 3
        self.aad[10] = 3
        self.aad[11] = UInt8(plen >> 8)
        self.aad[12] = UInt8(plen & 255)

    def wipe(mut self):
        wipe(self.key)
        wipe(self.iv)
        self.on = False


struct Conn[C: Crypto12](Movable):
    var c: Self.C
    var server: Bool
    var inb: List[UInt8]
    var inp: Int
    var out: List[UInt8]
    var rd: Cipher
    var wr: Cipher
    var hsbuf: List[UInt8]
    var hsp: Int
    var hs_total: Int
    var app: List[UInt8]
    var tx: List[UInt8]  # transcript: every handshake message in wire order
    var ev_type: Int
    var ev_body: List[UInt8]
    var alert: Int  # alert to send if the current error is fatal (default decode_error), -1 = the peer sent it
    var established: Bool
    var dead: Bool
    var peer_closed: Bool
    var sent_close: Bool
    var suite: Int
    var cr: List[UInt8]
    var sr: List[UInt8]
    var master: List[UInt8]
    var keys: List[UInt8]  # pending key block: client key, server key, client iv, server iv

    def __init__(out self, server: Bool):
        self.c = Self.C()
        self.server = server
        self.inb = List[UInt8]()
        self.inp = 0
        self.out = List[UInt8]()
        self.rd = Cipher()
        self.wr = Cipher()
        self.hsbuf = List[UInt8]()
        self.hsp = 0
        self.hs_total = 0
        self.app = List[UInt8]()
        self.tx = List[UInt8]()
        self.ev_type = 0
        self.ev_body = List[UInt8]()
        self.alert = A_DECODE
        self.established = False
        self.dead = False
        self.peer_closed = False
        self.sent_close = False
        self.suite = 0
        self.cr = List[UInt8]()
        self.sr = List[UInt8]()
        self.master = List[UInt8]()
        self.keys = List[UInt8]()

    def fatal(mut self, code: Int, what: String) -> Error:
        self.alert = code
        return Error("tls: ", what)

    # ---- output ----

    def write_rec(mut self, typ: Int, data: List[UInt8]) raises:
        var off = 0
        while True:
            if self.wr.on and self.wr.seq == UInt64.MAX:  # RFC 5246 6.1: a wrap would reuse the AEAD nonce
                raise self.fatal(A_INTERNAL, "write sequence number exhausted")
            var n = min(MAX_REC, len(data) - off)
            var h = len(self.out)
            self.out.append(UInt8(typ))
            self.out.append(3)
            self.out.append(3)
            self.out.append(0)
            self.out.append(0)
            if self.wr.on:
                self.wr.prep(typ, n)
                if self.wr.aead < 2:
                    for i in range(8):
                        self.out.append(self.wr.aad[i])
                        self.wr.nonce[4 + i] = self.wr.aad[i]
            var s = len(self.out)
            self.out.extend(Span(data)[off : off + n])
            if self.wr.on:
                self.c.seal(self.wr.aead, self.wr.key, self.wr.nonce, self.wr.aad, self.out, s)
                self.wr.seq += 1
            var tot = len(self.out) - h - 5
            self.out[h + 3] = UInt8(tot >> 8)
            self.out[h + 4] = UInt8(tot & 255)
            off += n
            if off >= len(data):
                break

    def send_hs(mut self, msg: List[UInt8]) raises:
        put(self.tx, msg)
        self.write_rec(HAND, msg)

    def send_alert(mut self, level: Int, desc: Int):
        try:
            self.write_rec(ALERT, bl(level, desc))
        except:
            pass

    def close(mut self):
        """Send close_notify once; the connection stays readable until the peer's side ends."""
        if not self.sent_close and not self.dead:
            self.sent_close = True
            self.send_alert(1, A_CLOSE)

    def die(mut self):
        """Fatal error: queue the alert (unless the peer sent it), wipe every secret."""
        if not self.dead:
            if self.alert >= 0:
                self.send_alert(2, self.alert)
            self.dead = True
            self.wr.wipe()
            self.rd.wipe()
            wipe(self.master)
            wipe(self.keys)

    def take_output(mut self) -> List[UInt8]:
        var o = self.out^
        self.out = List[UInt8]()
        return o^

    def take_app(mut self) -> List[UInt8]:
        var o = self.app^
        self.app = List[UInt8]()
        return o^

    def write_app(mut self, data: List[UInt8]) raises:
        if not self.established or self.sent_close or self.dead:
            raise Error("tls: connection not writable")
        if len(data) > 0:
            self.write_rec(APP, data)

    # ---- input ----

    def feed(mut self, data: Span[UInt8, _]):
        if self.inp == len(self.inb):
            self.inb.clear()
            self.inp = 0
        elif self.inp > 65536:  # a read that ends inside a record never empties the buffer: drop the consumed prefix
            var rest = dup(Span(self.inb)[self.inp :])
            self.inb = rest^
            self.inp = 0
        self.inb.extend(data)

    def _hs_next(mut self) raises -> Bool:
        var n = len(self.hsbuf) - self.hsp
        if n < 4:
            return False
        var t = Int(self.hsbuf[self.hsp])
        var l = (Int(self.hsbuf[self.hsp + 1]) << 16) | (Int(self.hsbuf[self.hsp + 2]) << 8) | Int(self.hsbuf[self.hsp + 3])
        if l > MAX_MSG:
            raise self.fatal(A_ILLEGAL, "handshake message too large")
        if n < 4 + l:
            return False
        self.ev_type = t
        self.ev_body = List[UInt8](self.hsbuf[self.hsp + 4 : self.hsp + 4 + l])
        if t != H_FIN:  # a Finished joins the transcript after it is verified
            self.tx.extend(Span(self.hsbuf)[self.hsp : self.hsp + 4 + l])
        self.hsp += 4 + l
        if self.hsp == len(self.hsbuf):
            self.hsbuf.clear()
            self.hsp = 0
        return True

    def poll(mut self) raises -> Int:
        while True:
            if self._hs_next():
                return EV_HS
            var avail = len(self.inb) - self.inp
            if avail < 5:
                return EV_NONE
            var typ = Int(self.inb[self.inp])
            var n = (Int(self.inb[self.inp + 3]) << 8) | Int(self.inb[self.inp + 4])
            if typ < CCS or typ > APP:
                raise self.fatal(A_UNEXPECTED, "bad record type")
            if self.inb[self.inp + 1] != 3:
                raise self.fatal(A_VERSION, "bad record version")
            if n > MAX_REC + (2048 if self.rd.on else 0):
                raise self.fatal(A_OVERFLOW, "record too large")
            if avail < 5 + n:
                return EV_NONE
            var s = self.inp + 5
            var e = s + n
            if self.rd.on:
                if self.rd.seq == UInt64.MAX:
                    raise self.fatal(A_INTERNAL, "read sequence number exhausted")
                var ex = 8 if self.rd.aead < 2 else 0
                if n < ex + 16:
                    raise self.fatal(A_BAD_MAC, "record too short")
                self.rd.prep(typ, n - ex - 16)
                if ex == 8:
                    for i in range(8):
                        self.rd.nonce[4 + i] = self.inb[s + i]
                try:
                    self.c.open(self.rd.aead, self.rd.key, self.rd.nonce, self.rd.aad, self.inb, s + ex, e)
                except:
                    raise self.fatal(A_BAD_MAC, "bad record mac")
                self.rd.seq += 1
                s += ex
                e -= 16
            self.inp += 5 + n
            var plen = e - s
            if plen > MAX_REC:
                raise self.fatal(A_OVERFLOW, "record too large")
            if typ == APP:
                if not self.established:
                    raise self.fatal(A_UNEXPECTED, "application data before the handshake ended")
                self.app.extend(Span(self.inb)[s:e])
                return EV_APP
            if plen == 0:
                raise self.fatal(A_UNEXPECTED, "empty handshake, alert or CCS record")
            if typ == HAND:
                self.hs_total += plen
                if self.hs_total > MAX_HS and not self.established:
                    raise self.fatal(A_ILLEGAL, "handshake too large")
                self.hsbuf.extend(Span(self.inb)[s:e])
            elif typ == CCS:
                if plen != 1 or self.inb[s] != 1:
                    raise self.fatal(A_DECODE, "bad change_cipher_spec")
                if self.hsp != len(self.hsbuf):
                    raise self.fatal(A_UNEXPECTED, "change_cipher_spec inside a handshake message")
                return EV_CCS
            else:
                if plen != 2:
                    raise self.fatal(A_DECODE, "bad alert")
                var lvl = Int(self.inb[s])
                var desc = Int(self.inb[s + 1])
                if desc == A_CLOSE:
                    self.peer_closed = True
                    return EV_CLOSE
                if lvl == 2 or (desc != 100 and desc != 90 and desc != 112):  # warnings we ignore: no_renegotiation, user_canceled, unrecognized_name (RFC 6066: servers send it and go on)
                    self.alert = -1
                    raise Error("tls: alert from peer: ", desc)

    # ---- keys ----

    def derive(mut self, var pms: List[UInt8]):
        """Extended master secret (the session hash covers everything up to and including the key exchange)."""
        var sha = suite_sha384(self.suite)
        self.master = self.c.prf(sha, pms, "extended master secret", self.c.hash(sha, self.tx), 48)
        wipe(pms)
        var kl = 16 if suite_aead(self.suite) == 0 else 32
        var il = 12 if suite_aead(self.suite) == 2 else 4
        self.keys = self.c.prf(sha, self.master, "key expansion", cat(self.sr, self.cr), 2 * kl + 2 * il)

    def enable(mut self, rx: Bool):
        """Switch one direction to the derived keys (call when CCS is received / sent)."""
        var a = suite_aead(self.suite)
        var kl = 16 if a == 0 else 32
        var il = 12 if a == 2 else 4
        var theirs = rx == self.server  # server reads with the client's keys, client reads with the server's
        var k = 0 if theirs else kl
        var v = 2 * kl + (0 if theirs else il)
        var key = List[UInt8](Span(self.keys)[k : k + kl])
        var iv = List[UInt8](Span(self.keys)[v : v + il])
        if rx:
            self.rd.start(a, key^, iv^)
        else:
            self.wr.start(a, key^, iv^)

    def finished(self, label: String) -> List[UInt8]:
        var sha = suite_sha384(self.suite)
        return self.c.prf(sha, self.master, label, self.c.hash(sha, self.tx), 12)
