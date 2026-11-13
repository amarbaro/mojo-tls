---
name: mojo-tls
description: "TLS 1.3 and 1.2 client and server for Mojo, pure Mojo with X.509, no OpenSSL: HTTPS servers and clients, sans-IO engines, certificate validation. Use when Mojo code must speak TLS or validate a certificate chain."
metadata:
  short-description: "TLS 1.3/1.2 client and server for Mojo, pure Mojo, with X.509; sans-IO engines and an aio server"
---

# mojo-tls

TLS 1.3 and 1.2, client and server, with X.509 validation, written in Mojo 1.2: no OpenSSL, no C library. Tested against openssl,
tlsfuzzer, testssl, Firefox, Chromium and Vivaldi. 0.1.1, internally audited, not independently audited.

## When to use

A Mojo program must serve HTTPS, connect to a TLS server and check its certificate, or parse and validate X.509 chains.
Not for DTLS, QUIC, OCSP, revocation, TLS 1.2 CBC or RSA key exchange, 0-RTT (all refused or absent by policy).

## Install

`pixi add mojo-tls` (channels in the README), or from a clone: `scripts/deps.sh`, then `mojo run -I src -I .work/deps/mojo-aio/src app.mojo`.

## The calls (full programs: `examples/server.mojo`, `examples/client.mojo`)

```mojo
# server: one port serves TLS 1.3 and 1.2
from tls.net.config import TlsConfig, CertEntry
from tls.net.server import TlsServer, TlsHandler, ConnInfo
from tls.tls12.realcrypto import RealCrypto
var cfg = TlsConfig()
cfg.alpn.append("http/1.1")
cfg.certs.append(CertEntry([String("localhost")], chain, key_der, kind))  # chain: List[List[UInt8]] DER, leaf first
var srv = TlsServer[RealCrypto](cfg^, port, "127.0.0.1", True)
srv.run(handler)                                   # handler: struct implementing TlsHandler.handle(fd, info, data, mut reply) -> Bool

# client engine (sans-IO): you move the bytes
from tls.tls13.client import Client13, default_hello
var cli = Client13[Check](hello, host, secret, random32, Check())   # Check: struct implementing Verifier (see client.mojo)
send(cli.start())                                  # ClientHello
var o = cli.feed(Span(received))                   # o.send: bytes to write; o.data: plaintext; o.events: EV_DONE, EV_CLOSE, ...
send(cli.write(request_bytes))                     # after EV_DONE
send(cli.close())                                  # close_notify
```

Other pieces: `tls.net.stream.tls_connect` (blocking client), `Server13`/`Client12`/`Server12` (same shape), `tls.x509.cert.Certificate.parse`,
`tls.x509.chain` (`verify_chain`, `load_system_roots`), `tls.asym` (x25519, P256Key, p384, RSA), `tls.sym` (sha256, hmac, hkdf, AesGcm, ChaCha20Poly1305).

## Gotchas

- The engines are sans-IO: always write `o.send` of every `feed`, even when it holds an error; check `o.error` after each call.
- Write application data only after `EV_DONE`.
- The caller supplies randomness (`random_bytes` from `tls.asym`); a repeated random or key share breaks the handshake's guarantees.
- `Verifier` decides trust: the `Check` in `examples/client.mojo` validates the chain against the system roots (or `TLS_ROOTS`) and the host name. `NoVerify` is for tests only.
- A TLS 1.2 peer without `extended_master_secret`, CBC suites and RSA key exchange are refused with a fatal alert, by policy.
- Errors raise `Error("tls: ...")`; catch them for untrusted peers.

## Gate

`scripts/ci.sh` must end `PASS 6/6 gates` (needs `uv`, `openssl`, network for the Wycheproof and x509-limbo data).
`scripts/example.sh` for the examples alone. `tests/matrix.sh` is the lab matrix (browsers, tlsfuzzer, testssl): 176 PASS, 11 SKIP by policy, 0 FAIL.
