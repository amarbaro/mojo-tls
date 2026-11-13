"""The crypto surface lane 5 needs, as one trait. Wave 2 implements it from lanes 1-3 (names in docs/api.md);
the tests use a deterministic fake so the whole protocol logic is exercised without real crypto.
Lists are plain byte lists; seal/open work in place on a region of one buffer, so the record layer does not
allocate per record. aead: 0 AES-128-GCM, 1 AES-256-GCM, 2 ChaCha20-Poly1305. kind: K_* of a certificate key."""

comptime K_P256 = 1
comptime K_P384 = 2
comptime K_RSA = 3


trait Crypto12(Defaultable, Movable, Deinitable):
    def random(self, n: Int) raises -> List[UInt8]:
        ...

    def hash(self, sha384: Bool, data: List[UInt8]) -> List[UInt8]:
        ...

    def prf(self, sha384: Bool, secret: List[UInt8], label: String, seed: List[UInt8], n: Int) -> List[UInt8]:
        """RFC 5246 5 P_hash, the label is prepended to the seed."""
        ...

    def keygen(self, group: Int) raises -> Tuple[List[UInt8], List[UInt8]]:
        """(secret, public point in the TLS encoding: 32 bytes for x25519, uncompressed 0x04||X||Y otherwise)."""
        ...

    def ecdh(self, group: Int, secret: List[UInt8], peer: List[UInt8]) raises -> List[UInt8]:
        """Shared x coordinate; raises on an invalid or low-order peer point."""
        ...

    def sign(self, kind: Int, key_der: List[UInt8], scheme: Int, msg: List[UInt8]) raises -> List[UInt8]:
        """Signature over msg (the scheme hashes it) with a PKCS#8 / SEC1 private key."""
        ...

    def verify(self, chain: List[List[UInt8]], host: String, scheme: Int, msg: List[UInt8], sig: List[UInt8]) raises:
        """Client side: validate the chain for host (lane 3), then the ServerKeyExchange signature with the leaf key."""
        ...

    def seal(self, aead: Int, key: List[UInt8], nonce: List[UInt8], aad: List[UInt8], mut buf: List[UInt8], start: Int) raises:
        """Encrypt buf[start:] in place and append the 16-byte tag."""
        ...

    def open(self, aead: Int, key: List[UInt8], nonce: List[UInt8], aad: List[UInt8], mut buf: List[UInt8], start: Int, end: Int) raises:
        """buf[start:end] is ciphertext||tag. Verify the tag first; on success buf[start:end-16] holds the plaintext,
        on failure raise and leave the bytes unchanged."""
        ...
