# mojo-tls wave 3: TLS 1.3 session tickets and PSK binders (RFC 8446 4.6.1, 4.2.11).
# A ticket is a stateless AEAD blob: key_name(16) | nonce(12) | ChaCha20-Poly1305(state) | tag(16), AAD = key_name.
# key_name = first 16 bytes of SHA-256("mojo-tls ticket" | key), so the server finds the right key after a rotation.
from std.ffi import external_call
from tls.asym import random_bytes
from tls.sym import ChaCha20Poly1305, sha256
from tls.tls13.keysched import KeySchedule, finished_mac, expand_label, hash_of
from tls.tls13.wire import Rd, bad, put8, put16, put32, putb, vec8, wipe, bytes_of, str_of


def unix_now() -> Int:
    return Int(external_call["time", Int64](Int64(0)))


struct TicketState(Copyable, Movable):
    """What the server needs back from a ticket: the PSK and the facts a resumption must match."""

    var issued: Int  # unix seconds
    var lifetime: Int  # seconds
    var age_add: Int
    var suite: Int
    var psk: List[UInt8]
    var alpn: String
    var sni: String

    def __init__(
        out self, issued: Int, lifetime: Int, age_add: Int, suite: Int, psk: List[UInt8], alpn: String, sni: String
    ):
        self.issued = issued
        self.lifetime = lifetime
        self.age_add = age_add
        self.suite = suite
        self.psk = psk.copy()
        self.alpn = alpn
        self.sni = sni


struct Session(Copyable, Movable):
    """What a client keeps from a NewSessionTicket to resume with it."""

    var suite: Int
    var psk: List[UInt8]
    var ticket: List[UInt8]
    var age_add: Int
    var lifetime: Int
    var at_ms: Int  # when the ticket arrived, caller's clock in milliseconds

    def __init__(
        out self, suite: Int, psk: List[UInt8], ticket: List[UInt8], age_add: Int, lifetime: Int, at_ms: Int
    ):
        self.suite = suite
        self.psk = psk.copy()
        self.ticket = ticket.copy()
        self.age_add = age_add
        self.lifetime = lifetime
        self.at_ms = at_ms


def key_name(key: List[UInt8]) -> List[UInt8]:
    var m = bytes_of("mojo-tls ticket")
    m.extend(Span(key))
    return List[UInt8](Span(sha256(m))[:16])


def seal_ticket(key: List[UInt8], st: TicketState) raises -> List[UInt8]:
    var pt = List[UInt8]()
    put8(pt, 1)
    put32(pt, st.issued >> 32)
    put32(pt, st.issued & 0xFFFFFFFF)
    put32(pt, st.lifetime)
    put32(pt, st.age_add)
    put16(pt, st.suite)
    putb(pt, vec8(st.psk))
    putb(pt, vec8(bytes_of(st.alpn)))
    putb(pt, vec8(bytes_of(st.sni)))
    var name = key_name(key)
    var nonce = random_bytes(12)
    ChaCha20Poly1305(key).seal(nonce, name, pt)
    var out = name.copy()
    out.extend(Span(nonce))
    out.extend(Span(pt))
    return out^


def open_ticket(keys: List[List[UInt8]], blob: List[UInt8]) raises -> TicketState:
    """The state inside `blob`; raises when no configured key opens it or the plaintext is malformed (the caller then
    does a full handshake: a ticket is never trusted without its AEAD tag)."""
    if len(blob) < 16 + 12 + 16 + 1:
        raise bad("decode_error", "ticket too short")
    var name = List[UInt8](Span(blob)[:16])
    for key in keys:
        if key_name(key) == name:
            var pt = List[UInt8](Span(blob)[28:])
            var nonce = List[UInt8](Span(blob)[16:28])
            ChaCha20Poly1305(key).open(nonce, name, pt)
            var r = Rd(pt^)
            if r.u8() != 1:
                raise bad("decode_error", "ticket version")
            var issued = (r.u32() << 32) | r.u32()
            var lifetime = r.u32()
            var age_add = r.u32()
            var suite = r.u16()
            var psk = r.sub8().rest()
            var alpn = str_of(r.sub8().rest())
            var sni = str_of(r.sub8().rest())
            r.done()
            return TicketState(issued, lifetime, age_add, suite, psk, alpn, sni)
    raise bad("decrypt_error", "no ticket key matches")


def resumption_psk(h: Int, res_master: List[UInt8], nonce: List[UInt8]) raises -> List[UInt8]:
    return expand_label(h, res_master, "resumption", nonce, h)


def binder_of(h: Int, psk: List[UInt8], truncated_hash: List[UInt8]) raises -> List[UInt8]:
    """RFC 8446 4.2.11.2: HMAC(finished_key(binder_key), Transcript-Hash(truncated ClientHello)), binder_key from "res binder"."""
    var bk = KeySchedule(h, psk).derive("res binder", hash_of(h, List[UInt8]()))
    var mac = finished_mac(h, bk, truncated_hash)
    wipe(bk)
    return mac^


def truncated_hash(h: Int, transcript: List[UInt8], ch_msg: List[UInt8], binders_len: Int) -> List[UInt8]:
    """Hash of the transcript so far plus the ClientHello without its binders vector (the last `binders_len` bytes)."""
    var t = transcript.copy()
    t.extend(Span(ch_msg)[: len(ch_msg) - binders_len])
    return hash_of(h, t)
