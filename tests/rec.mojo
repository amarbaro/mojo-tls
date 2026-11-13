# Test doubles for the Signer and Verifier seams. RecSigner answers with a recorded signature and refuses any other
# signed content; RecVerifier accepts only the recorded chain, scheme, content and signature.
from tls.tls13.verify import Signer, Verifier


struct RecSigner(Signer):
    var ch: List[List[UInt8]]
    var sig: List[UInt8]
    var scheme: Int
    var content: List[UInt8]  # the CertificateVerify content the server must ask us to sign; empty = any

    def __init__(out self, chain: List[List[UInt8]], sig: List[UInt8], scheme: Int, content: List[UInt8]):
        self.ch = chain.copy()
        self.sig = sig.copy()
        self.scheme = scheme
        self.content = content.copy()

    def schemes(self) -> List[Int]:
        return [self.scheme]

    def chain(self) -> List[List[UInt8]]:
        return self.ch.copy()

    def sign(self, scheme: Int, content: List[UInt8]) raises -> List[UInt8]:
        if scheme != self.scheme or (len(self.content) > 0 and content != self.content):
            raise Error("tls: internal_error: RecSigner asked to sign unexpected content")
        return self.sig.copy()


struct RecVerifier(Verifier):
    var ch: List[List[UInt8]]
    var sig: List[UInt8]
    var scheme: Int
    var content: List[UInt8]
    var host: String
    var calls: Int

    def __init__(out self, chain: List[List[UInt8]], sig: List[UInt8], scheme: Int, content: List[UInt8], host: String):
        self.ch = chain.copy()
        self.sig = sig.copy()
        self.scheme = scheme
        self.content = content.copy()
        self.host = host
        self.calls = 0

    def verify(
        mut self, chain: List[List[UInt8]], scheme: Int, signed: List[UInt8], sig: List[UInt8], host: String
    ) raises:
        self.calls += 1
        if chain != self.ch or scheme != self.scheme or sig != self.sig or host != self.host:
            raise Error("tls: bad_certificate: RecVerifier mismatch")
        if len(self.content) > 0 and signed != self.content:
            raise Error("tls: decrypt_error: RecVerifier content mismatch")


struct Refuse(Verifier):
    """A verifier that rejects every chain (bad_certificate)."""

    def __init__(out self):
        pass

    def verify(
        mut self, chain: List[List[UInt8]], scheme: Int, signed: List[UInt8], sig: List[UInt8], host: String
    ) raises:
        raise Error("tls: bad_certificate: refused")
