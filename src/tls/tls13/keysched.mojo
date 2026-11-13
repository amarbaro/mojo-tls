# mojo-tls lane 4: TLS 1.3 key schedule (RFC 8446 7.1-7.3). h = hash length: 32 (SHA-256) or 48 (SHA-384).
from tls.sym import Sha256, Sha384, sha256, sha384, hmac, hkdf_extract, hkdf_expand_label
from tls.tls13.wire import bad, putb

comptime AES128_GCM_SHA256 = 0x1301
comptime AES256_GCM_SHA384 = 0x1302
comptime CHACHA20_POLY1305_SHA256 = 0x1303


def suite_key_len(suite: Int) raises -> Int:
    if suite == AES128_GCM_SHA256:
        return 16
    if suite == AES256_GCM_SHA384 or suite == CHACHA20_POLY1305_SHA256:
        return 32
    raise bad("handshake_failure", "unsupported cipher suite")


def suite_hash_len(suite: Int) -> Int:
    return 48 if suite == AES256_GCM_SHA384 else 32


def hash_of(h: Int, d: List[UInt8]) -> List[UInt8]:
    return sha384(d) if h == 48 else sha256(d)


def hmac_of(h: Int, key: List[UInt8], d: List[UInt8]) -> List[UInt8]:
    return hmac[Sha384](key, d) if h == 48 else hmac[Sha256](key, d)


def extract(h: Int, salt: List[UInt8], ikm: List[UInt8]) -> List[UInt8]:
    return hkdf_extract[Sha384](salt, ikm) if h == 48 else hkdf_extract[Sha256](salt, ikm)


def expand_label(h: Int, secret: List[UInt8], label: String, ctx: List[UInt8], n: Int) raises -> List[UInt8]:
    if h == 48:
        return hkdf_expand_label[Sha384](secret, label, ctx, n)
    return hkdf_expand_label[Sha256](secret, label, ctx, n)


def traffic_key(h: Int, secret: List[UInt8], klen: Int) raises -> List[UInt8]:
    return expand_label(h, secret, "key", List[UInt8](), klen)


def traffic_iv(h: Int, secret: List[UInt8]) raises -> List[UInt8]:
    return expand_label(h, secret, "iv", List[UInt8](), 12)


def next_secret(h: Int, secret: List[UInt8]) raises -> List[UInt8]:
    """KeyUpdate: application_traffic_secret_N+1 (RFC 8446 7.2)."""
    return expand_label(h, secret, "traffic upd", List[UInt8](), h)


def finished_mac(h: Int, base: List[UInt8], transcript_hash: List[UInt8]) raises -> List[UInt8]:
    """verify_data = HMAC(finished_key, Transcript-Hash(...)) (RFC 8446 4.4.4)."""
    return hmac_of(h, expand_label(h, base, "finished", List[UInt8](), h), transcript_hash)


def cv_content(client: Bool, transcript_hash: List[UInt8]) -> List[UInt8]:
    """The bytes a CertificateVerify signs (RFC 8446 4.4.3)."""
    var o = List[UInt8](capacity=130 + len(transcript_hash))
    for _ in range(64):
        o.append(0x20)
    var ctx = "TLS 1.3, client CertificateVerify" if client else "TLS 1.3, server CertificateVerify"
    for b in ctx.as_bytes():
        o.append(b)
    o.append(0)
    putb(o, transcript_hash)
    return o^


struct KeySchedule(Copyable, Movable):
    """Early -> handshake -> master secret chain; secret holds the current stage."""

    var h: Int
    var secret: List[UInt8]

    def __init__(out self, h: Int, psk: List[UInt8] = List[UInt8]()):
        self.h = h
        var zeros = List[UInt8](length=h, fill=0)
        self.secret = extract(h, zeros, psk if len(psk) > 0 else zeros)

    def _derived(self) raises -> List[UInt8]:
        return expand_label(self.h, self.secret, "derived", hash_of(self.h, List[UInt8]()), self.h)

    def to_handshake(mut self, dhe: List[UInt8]) raises:
        self.secret = extract(self.h, self._derived(), dhe)

    def to_master(mut self) raises:
        self.secret = extract(self.h, self._derived(), List[UInt8](length=self.h, fill=0))

    def derive(self, label: String, transcript_hash: List[UInt8]) raises -> List[UInt8]:
        """Derive-Secret(current stage, label, Transcript-Hash)."""
        return expand_label(self.h, self.secret, label, transcript_hash, self.h)
