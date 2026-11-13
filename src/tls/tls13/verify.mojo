# mojo-tls lane 4: the two seams to the other lanes. Lane 2-3 implement them (certificate chain + signature
# check, private key signing); lane 4 only passes the exact bytes: the DER chain, the signature scheme, the
# CertificateVerify content and the signature.


trait Verifier(Movable, Deinitable):
    def verify(
        mut self, chain: List[List[UInt8]], scheme: Int, signed: List[UInt8], sig: List[UInt8], host: String
    ) raises:
        """Raise Error("tls: bad_certificate: ...") unless chain validates for host and sig is chain[0]'s signature over signed."""
        ...


trait Signer(Movable, Deinitable):
    def schemes(self) -> List[Int]:
        """Signature schemes this key can sign with, in preference order (e.g. 0x0403, 0x0804)."""
        ...

    def chain(self) -> List[List[UInt8]]:
        """DER certificate chain, leaf first."""
        ...

    def sign(self, scheme: Int, content: List[UInt8]) raises -> List[UInt8]:
        ...


struct NoVerify(Verifier):
    """Accepts any chain and signature. For loopback tests only: it makes the handshake unauthenticated."""

    def __init__(out self):
        pass

    def verify(
        mut self, chain: List[List[UInt8]], scheme: Int, signed: List[UInt8], sig: List[UInt8], host: String
    ) raises:
        pass
