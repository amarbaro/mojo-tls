# mojo-tls lane 4: TLS 1.3 record layer (RFC 8446 5). One Cipher per direction; AEAD is done in place in the
# output buffer on send; a received record is decrypted into one new buffer, the inner type and padding are stripped.
from std.ffi import external_call
from tls.sym import AesGcm, ChaCha20Poly1305
from tls.sym.aead import dup
from tls.tls13.keysched import CHACHA20_POLY1305_SHA256, suite_key_len
from tls.tls13.wire import bad

comptime CCS = 20
comptime ALERT = 21
comptime HS = 22
comptime APP = 23
comptime MAX_PLAIN = 16384
comptime MAX_CIPHER = 16384 + 256


def _cp(dst: Int, src: Int, n: Int):
    if n > 0:
        _ = external_call["memcpy", Int](dst, src, n)


struct Cipher(Movable):
    """One direction. Unprotected until set(); seq restarts at 0 on every set() (new traffic key)."""

    var on: Bool
    var suite: Int
    var key: List[UInt8]
    var iv: List[UInt8]
    var nonce: List[UInt8]
    var seq: UInt64
    var gcm: List[AesGcm]
    var cc: List[ChaCha20Poly1305]
    var limit: Int  # most content bytes in one record (record_size_limit of the peer)
    var pver: Int  # legacy_record_version written on unprotected records

    def __init__(out self):
        self.on = False
        self.suite = 0
        self.key = List[UInt8]()
        self.iv = List[UInt8]()
        self.nonce = List[UInt8](length=12, fill=0)
        self.seq = 0
        self.gcm = List[AesGcm]()
        self.cc = List[ChaCha20Poly1305]()
        self.limit = MAX_PLAIN
        self.pver = 0x0303

    def set(mut self, suite: Int, key: List[UInt8], iv: List[UInt8]) raises:
        if len(key) != suite_key_len(suite) or len(iv) != 12:
            raise bad("internal_error", "bad traffic key size")
        self.suite = suite
        self.key = key.copy()
        self.iv = iv.copy()
        self.seq = 0
        self.on = True
        self._drop()
        if suite == CHACHA20_POLY1305_SHA256:
            self.cc.append(ChaCha20Poly1305(key))
        else:
            self.gcm.append(AesGcm(key))

    def _drop(mut self):
        for ref g in self.gcm:
            g.wipe()
        for ref c in self.cc:
            c.wipe()
        self.gcm.clear()
        self.cc.clear()

    def wipe(mut self):
        for i in range(len(self.key)):
            self.key[i] = 0
        for i in range(len(self.iv)):
            self.iv[i] = 0
        self._drop()
        self.on = False

    def _nonce(mut self):
        """RFC 8446 5.3: the 64-bit sequence number, left-padded to 12 bytes, XOR iv."""
        for i in range(12):
            self.nonce[i] = self.iv[i]
        for i in range(8):
            self.nonce[4 + i] ^= UInt8((self.seq >> UInt64(56 - 8 * i)) & 0xFF)

    def seal(mut self, ctype: Int, data: List[UInt8], start: Int, n: Int, mut out: List[UInt8], pad: Int = 0) raises:
        """Append one record holding data[start:start+n] (n <= limit) to out."""
        if n < 0 or start < 0 or start + n > len(data) or n > self.limit or pad < 0:
            raise bad("internal_error", "record size")
        var base = len(out)
        if not self.on:
            out.resize(base + 5 + n, 0)
            out[base] = UInt8(ctype)
            out[base + 1] = UInt8(self.pver >> 8)
            out[base + 2] = UInt8(self.pver & 0xFF)
            out[base + 3] = UInt8(n >> 8)
            out[base + 4] = UInt8(n & 0xFF)
            _cp(Int(out.unsafe_ptr()) + base + 5, Int(data.unsafe_ptr()) + start, n)
            return
        var inner = n + 1 + pad
        if self.seq == UInt64.MAX or inner + 16 > MAX_CIPHER:
            raise bad("internal_error", "sequence number or padding exhausted")
        var hdr: List[UInt8] = [UInt8(APP), 3, 3, UInt8((inner + 16) >> 8), UInt8((inner + 16) & 0xFF)]
        var body = List[UInt8](unsafe_uninit_length=inner)  # no memset of the whole record: only the tail is written
        _cp(Int(body.unsafe_ptr()), Int(data.unsafe_ptr()) + start, n)
        body[n] = UInt8(ctype)
        for i in range(n + 1, inner):
            body[i] = 0  # padding
        self._nonce()
        if self.suite == CHACHA20_POLY1305_SHA256:
            self.cc[0].seal(self.nonce, hdr, body)
        else:
            self.gcm[0].seal(self.nonce, hdr, body)
        out.extend(Span(hdr))
        out.extend(Span(body))
        self.seq += 1

    def open(mut self, rec: List[UInt8]) raises -> Tuple[Int, List[UInt8]]:
        """Decrypt a protected record (header included): (inner content type, content). Raises bad_record_mac."""
        var n = len(rec) - 5 - 16
        if n + 16 > MAX_CIPHER:
            raise bad("record_overflow", "protected record longer than 2^14+256")
        if n < 1:
            raise bad("bad_record_mac", "protected record shorter than the tag")
        if self.seq == UInt64.MAX:
            raise bad("internal_error", "sequence number exhausted")
        var pt = dup(Span(rec)[5:])
        var hdr = dup(Span(rec)[:5])
        self._nonce()
        try:
            if self.suite == CHACHA20_POLY1305_SHA256:
                self.cc[0].open(self.nonce, hdr, pt)
            else:
                self.gcm[0].open(self.nonce, hdr, pt)
        except:
            raise bad("bad_record_mac", "authentication failed")
        self.seq += 1
        var i = n - 1
        while i >= 0 and pt[i] == 0:  # RFC 8446 5.4: the type is the last non-zero byte
            i -= 1
        if i < 0:
            raise bad("unexpected_message", "inner plaintext has no content type")
        var ct = Int(pt[i])
        pt.resize(i, 0)
        return (ct, pt^)


def seal_all(mut c: Cipher, ctype: Int, data: List[UInt8], mut out: List[UInt8]) raises:
    """Split data over records of at most c.limit content bytes."""
    var i = 0
    while i < len(data):
        var n = min(len(data) - i, c.limit)
        c.seal(ctype, data, i, n, out)
        i += n


struct RecordReader(Movable):
    """Turns a byte stream into whole records; a bad header is rejected before its body is buffered."""

    var buf: List[UInt8]
    var pos: Int

    def __init__(out self):
        self.buf = List[UInt8]()
        self.pos = 0

    def push(mut self, data: Span[UInt8, _]):
        self.buf.extend(data)

    def next(mut self, mut rec: List[UInt8]) raises -> Bool:
        """Move the next whole record (header included) into rec. False when more bytes are needed."""
        if len(self.buf) - self.pos < 5:
            return False
        var t = Int(self.buf[self.pos])
        if t < CCS or t > APP:
            raise bad("unexpected_message", "unknown record type")
        if self.buf[self.pos + 1] != 3:
            raise bad("protocol_version", "record version")
        var n = (Int(self.buf[self.pos + 3]) << 8) | Int(self.buf[self.pos + 4])
        if n > MAX_CIPHER:
            raise bad("record_overflow", "record longer than 2^14+256")
        if len(self.buf) - self.pos < 5 + n:
            return False
        rec = List[UInt8](length=5 + n, fill=0)
        _cp(Int(rec.unsafe_ptr()), Int(self.buf.unsafe_ptr()) + self.pos, 5 + n)
        self.pos += 5 + n
        if self.pos == len(self.buf):
            self.buf.clear()
            self.pos = 0
        elif self.pos > 65536:
            # The Span borrows the old buffer until the copy exists. A pointer laundered through Int() did not:
            # Mojo freed the old buffer before the memcpy read it (use-after-free, docs/heap-grow.md).
            self.buf = dup(Span(self.buf)[self.pos:])
            self.pos = 0
        return True
