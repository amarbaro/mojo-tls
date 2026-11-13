# Design

mojo-tls is five layers, each in its own directory under `src/tls/`, each with its own gate. Nothing above `tls.net` touches a socket.

```
tls.net      TlsServer (mojo-aio), TlsStream, TlsConfig      sockets, SNI certificate table, timeouts
tls.tls13    Client13, Server13   tls.tls12  Client12, Server12      sans-IO engines: bytes in, bytes + events out
tls.x509     DER, PEM, Certificate, chain, system roots, PSL      parse and validate
tls.asym     x25519 x448 P-256 P-384 RSA ECDSA random             public key
tls.sym      SHA-2 HMAC HKDF AES-GCM ChaCha20-Poly1305            symmetric
```

## Choices

- **Sans-IO engines.** An engine owns the state machine and the record layer and nothing else; the caller moves bytes. The same
  code runs under mojo-aio, a blocking socket, or a test that wires a client to a server in memory (3052 handshakes per second).
- **Crypto behind traits.** `Verifier` and `Signer` (TLS 1.3) and `Crypto12` (TLS 1.2) are the only seams to the primitives, so tests run the
  full state machines over fixed fake crypto and the product runs `RealCrypto`.
- **Policy over compatibility.** TLS 1.2 is offered only in its safe form (see README, "What it is not").
- **Every length is checked before use.** A short read raises; handshake messages are capped at 64 KiB, records at 2^14 + 256.
- **Bytes, not objects.** Records are sealed in place in the output buffer; a received record is decrypted into one new buffer.

## Per-layer notes

| Layer | Current truth |
|---|---|
| sym | [sym.md](sym.md) |
| asym | [asym.md](asym.md) |
| x509 | [x509.md](x509.md) |
| TLS 1.3 | [tls13.md](tls13.md) |
| TLS 1.2 and net | [tls12.md](tls12.md) |

Public function signatures: [api.md](api.md).
