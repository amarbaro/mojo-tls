# TLS 1.2 and the network layer (lane 5)

Current truth for `src/tls/tls12/` and `src/tls/net/`. Gate: `tests/check.sh` (add `mutants` to prove the tests can fail).

## What exists

| File | Role |
|---|---|
| `tls12/wire.mojo` | `Rd` bounds-checked reader (a short read raises, never indexes out of range), big-endian writers, `ct_eq`, `wipe` |
| `tls12/msg.mojo` | codecs: ClientHello parse (SNI, ALPN, groups, sigalgs, supported_versions, EMS, renegotiation_info, GREASE skipped), ServerHello build and parse, Certificate, ServerKeyExchange, ClientKeyExchange, suite table, suite/group choice, downgrade sentinel |
| `tls12/conn.mojo` | `Conn[C]`: record layer (GCM and ChaCha20 per RFC 5288/7905), handshake reassembly (64 KiB message cap, 256 KiB handshake cap, record cap 2^14 + 2048), transcript, extended-master-secret key schedule, alerts, `close_notify` |
| `tls12/server.mojo` | `Server12[C]` sans-IO state machine |
| `tls12/client.mojo` | `Client12[C]` sans-IO state machine |
| `tls12/crypto.mojo` | `Crypto12` trait: the only crypto surface lane 5 touches |
| `net/config.mojo` | `TlsConfig`, `CertEntry`: certificates by SNI (exact, `*.x`, default), ALPN, timeouts, limits |
| `net/server.mojo` | `TlsServer[C]` on `mojo-aio`: TLS 1.3 (`Server13`) and 1.2 (`Server12`) on one port, chosen from the first record; `TlsHandler.handle(fd, info: ConnInfo, data, reply)` gets version, SNI, ALPN; after our last record it half-closes and drains (1 s idle, 32 MiB cap) so the peer gets the alert, not a reset |
| `net/stream.mojo` | `TlsStream[C]` blocking client, `tls_connect`, `tcp_connect` |

Policy (refused with a fatal alert, tested): TLS below 1.2, CBC and RSA key exchange, a client without extended master
secret, non-empty `renegotiation_info`, renegotiation after the handshake, no common group/suite/sigalg, ALPN with no
overlap. Supported: ECDHE (x25519, secp256r1, secp384r1) with ECDSA or RSA certificates, AES-128/256-GCM and
ChaCha20-Poly1305 suites (0xC02B, 0xCCA9, 0xC02C, 0xC02F, 0xCCA8, 0xC030). A client that lists ChaCha20 first is obeyed
(no AES hardware), otherwise server order. When the client offered TLS 1.3 the ServerHello random carries the
`DOWNGRD\x01` sentinel (RFC 8446 4.1.3); `Client12(offer13=True)` rejects it.

Matrix findings (2026-11-12, fixed): the DOWNGRD sentinel is written only when `TlsConfig.tls13` says a TLS 1.3 engine sits behind
the config (a 1.2-only server must stay silent or Firefox/Chrome abort with alert 47); a server with no ALPN configured ignores a
client's ALPN offer (RFC 7301); the client ignores a warning `unrecognized_name`; both clients leave an IP literal out of server_name.
`tests/matrix.sh` runs every cell (openssl both ways, tlsfuzzer, testssl, Firefox, Chromium, Vivaldi) against `tests/matrix/msrv.mojo`.

## Using it

Sans-IO: `Server12[C](cfg).feed(bytes)`, then send `cn.take_output()` and read `cn.take_app()`; `cn.write_app(data)`,
`cn.close()`. A failed `feed` has queued the fatal alert in the output: flush it, then close. `Client12.start()` queues the
ClientHello. `TlsServer[C](cfg, port, host).step(handler)` is one loop pass; `run(handler)` loops. `TlsStream` is
`tls_connect[C](host, port, alpn, addr)` then `read(dst)`, `write(data)`, `close()`.

## Crypto12 and the lanes (wave 2 writes `RealCrypto(Crypto12)`, about 60 lines)

| Method | Lane function (docs/api.md) |
|---|---|
| `random` | `random_bytes` (lane 2) |
| `hash(sha384, data)` | `sha256` / `sha384` (lane 1) |
| `prf(sha384, secret, label, seed, n)` | `prf12[H]` (lane 1); label is prepended to the seed |
| `keygen(group)`, `ecdh(group, sec, peer)` | `x25519_base` + `x25519`; `P256Key.generate/public_bytes/ecdh`; `p384_public` + `p384_ecdh` (secp384r1, wave 3) |
| `sign(kind, key_der, scheme, msg)` | `P256Key.sign_sha256` (0x0403), `p384_sign` over SHA-384 (0x0503), `RsaPrivate.sign_pss` and PKCS#1 v1.5 for 0x0401; the DER key is parsed per call by `load_private_key_der` |
| `verify(chain, host, scheme, msg, sig)` | `verify_chain` (lane 3) then `p256_verify` / `p384_verify` / `RsaPublic.verify_pss/pkcs1` with the leaf key; an ECDSA scheme (0x0403 or 0x0503) is checked against the leaf's key type, not a curve (TLS 1.2 binds none) |
| `seal`, `open` | `AesGcm(key)`, `ChaCha20Poly1305(key)` in place on `buf[start:]`; the 8-byte GCM explicit nonce and the tag layout are already handled by `Conn` |

Needs beyond api.md: P-384 sign and ECDH (a P-384 certificate or group needs them; a P-256-only server does not), RSA
PKCS#1 v1.5 sign (0x0401 fallback), a `PrivateKey` that can be built once per certificate. All present since v0.1.1.

## Tests

`tests/t_flow.mojo` (protocol logic over `tests/fake_crypto.mojo`, which is deterministic and insecure), `t_hello.mojo`
(six real ClientHellos in `tests/vectors/`, captured by `tests/vectors/capture.sh`), `net.sh` (TlsServer and TlsStream over
loopback sockets), `interop/hello_probe.sh` (real OpenSSL against our ServerHello), `interop/run.sh` (the full matrix,
`peers` mode self-tests the harness against `openssl s_server`; `ours` mode waits for `TLS_SERVER_BIN` / `TLS_CLIENT_BIN`),
`bench_engine.mojo` (framing cost without crypto).

## Real peers today (temporary crypto)

`tests/real/` puts lane 4's `_tmp_crypto` (Mosaad-M-tls port, MIT) behind `Crypto12` as `RealCrypto` (ECDSA P-256 only,
no chain validation on the client). `tests/real/build.sh` builds `real_server` / `real_client`; `tests/check.sh` runs
`tests/interop/run.sh ours` with them: openssl s_client, curl, Python ssl and headless Vivaldi (Chrome 156, TLS 1.2 only,
AES_128_GCM) against our server, our client against `openssl s_server`, three AEAD suites each, negatives. It needs
lane 4's tree (`LANE4=`), so it prints SKIP when that is gone. Speed with that crypto: `openssl s_time -new` against
one `real_server` thread: about 940 full handshakes/s (the engines cost about 10 us of that, see bench_engine).

## Wave 2 checklist (printed as SKIP today, never PASS)

1. `RealCrypto` over lanes 1-3 replaces `tests/real/` (delete it); add P-384 and RSA certificate cells
   (`TLS_KINDS="p256 p384 rsa"`), the PEM/PKCS#8 loader from lane 3 in the server binary, chain validation in the client.
2. An `examples/` https server on mojo-bento (the plan row) and a Firefox headless cell (`firefox` is installed).
3. Bulk throughput through the engine with a real AEAD (only handshakes were timed with real crypto).
4. `testssl.sh` is not installed: the "only the listed suites" scan is UNVERIFIED.
5. 10k handshakes/s on 8 cores: multi-threaded accept (one listener shared by one Loop per thread) and faster crypto;
   today 940/s per thread.
6. Secret zeroing is a plain store loop; check the generated code keeps it.
