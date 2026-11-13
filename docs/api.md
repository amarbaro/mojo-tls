# API

The public surface of `tls`, by layer. Import from the submodule shown.

All bytes are `List[UInt8]` in, `Span[UInt8, _]` for read-only views. Errors raise `Error("tls: <what>")`.

## `tls.sym`
- `sha256(data) -> List[UInt8]`, `sha384(data)`, `sha512(data)`; streaming `Sha256`, `Sha384` with `update(data)`, `digest()`
- `hmac[H](key, data) -> List[UInt8]` (H = sha256 | sha384)
- `hkdf_extract[H](salt, ikm)`, `hkdf_expand[H](prk, info, n)`, `hkdf_expand_label[H](secret, label, context, n)` (RFC 8446 7.1)
- `prf12[H](secret, label, seed, n)` (RFC 5246 5)
- `Aead` trait-like structs `AesGcm(key)`, `ChaCha20Poly1305(key)`: `seal(nonce, aad, mut plaintext) -> tag appended in place`, `open(nonce, aad, mut ciphertext_with_tag) raises` (in place, constant-time tag compare)

## `tls.asym`
- `x25519(scalar32, point32) -> List[UInt8]`, `x25519_base(scalar32)`
- `P256Key`: `generate()` (from a CSPRNG), `public_bytes()` (uncompressed), `ecdh(peer_uncompressed) -> shared32`, `sign_sha256(msg_hash32) -> DER signature`
- `p256_verify(pub, hash, der_sig) -> Bool`, `p384_verify(...)`, `p384_sign(d48, hash48) -> der` (RFC 6979 with HMAC-SHA-384)
- `RsaPublic`: `verify_pkcs1(hash_alg, hash, sig)`, `verify_pss(hash_alg, hash, sig)`; `RsaPrivate`: `sign_pss(hash_alg, hash) -> sig` (CRT + blinding)
- `random_bytes(n)` from `getrandom(2)`

## `tls.x509`
- `der` reader: `Der(bytes)` with `seq()`, `int_bytes()`, `oid()`, `bits()`, `octets()`, `time()`, `tag()`
- `pem_blocks(text) -> List[(label, der)]`
- `Certificate.parse(der)`: subject/issuer raw names, SAN dns/ip, not_before/after, public key (kind + bytes), basic_constraints, key_usage, eku, tbs bytes, signature alg + value
- `verify_chain(chain: List[Certificate], host, now, roots) raises` and `load_system_roots()`
- `load_private_key(pem) -> PrivateKey` (P-256 or RSA)

## `tls.tls13`
- `Record` reader/writer over a byte stream with an optional AEAD per direction
- message codecs: ClientHello, ServerHello (+ HRR), EncryptedExtensions, Certificate, CertificateVerify, Finished, NewSessionTicket, KeyUpdate, Alert
- `KeySchedule[H]`: early, handshake, application secrets, traffic keys/ivs, finished keys, transcript hash
- `Client13`, `Server13` state machines: `feed(bytes) -> output bytes + events` (sans-IO, no sockets)

## `tls.tls12` and `tls.net`
- `Client12`, `Server12` sans-IO like lane 4
- `TlsConfig` (certs per SNI name, ALPN list, versions), `TlsServer` on mojo-aio (nonblocking, per-connection buffers, timeouts), `TlsStream` read/write for blocking clients
