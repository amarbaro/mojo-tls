# TLS 1.3 (lane 4): `src/tls/tls13/`

Sans-IO TLS 1.3 client and server: bytes in, bytes and events out, no sockets. 1500 lines of code by `mokei`
(`src/tls/tls13/*.mojo` without `_tmp_crypto/`). Gate: `tests/gate_tls13.sh [--mutants]`.

## Files

| File | What |
|---|---|
| `wire.mojo` | `bad(alert_name, what)` errors, alert names and codes, `put*`, `Rd` bounds-checked reader, `ct_equal`, `wipe` |
| `keysched.mojo` | `KeySchedule(h)` early/handshake/master, `expand_label`, traffic key/iv, `finished_mac`, `cv_content`, `next_secret` (KeyUpdate), suite table |
| `record.mojo` | `Cipher` (one direction: nonce, in-place AEAD seal into the output buffer, open, padding strip, limits), `RecordReader`, `seal_all` |
| `messages.mojo` | `Hello` (ClientHello, ServerHello, HRR), `Ext` list, typed extension builders and parsers, EE, Certificate, CertificateVerify, Finished, `Ticket`, KeyUpdate, CertificateRequest |
| `conn.mojo` | `Conn`: shared by both roles. Handshake reassembly, transcript, alerts, KeyUpdate, key limit, wipe. `Out` result struct |
| `client.mojo` | `Client13[V: Verifier]`, `default_hello`, `kex_public`, `kex_shared`, `pad_hello` |
| `server.mojo` | `Server13[S: Signer]`, `ServerConfig` |
| `verify.mojo` | traits `Verifier` and `Signer` (the seams to lanes 2 and 3), `NoVerify` (tests only) |
| `_tmp_crypto/` | TEMPORARY port from Mosaad-M-tls (MIT, notice in `LICENSE-Mosaad-M-tls`). Wave 2 replaces it |

## Use

```mojo
# client: the caller supplies randomness (hello random, session id, x25519 and P-256 private keys)
var h = default_hello(host, random32, session_id32, x25519_public_key(xpriv), [String("http/1.1")])
var c = Client13[MyVerifier](h, host, xpriv, ppriv, MyVerifier(...))
send(c.start())                       # ClientHello record
var o = c.feed(Span(bytes_from_peer)) # o.send -> peer, o.data = application data, o.events, o.error
if o.has(EV_DONE): send(c.write(request))
# server
var cfg = ServerConfig(server_random32, xpriv, ppriv)   # cfg.suites, groups, alpn, cookie, rsl, ee_exts
var s = Server13[MySigner](cfg^, MySigner(...))
var o = s.feed(Span(bytes_from_peer))   # s.sni, s.alpn, s.group, s.c.suite after the handshake
```

Events: `EV_DONE`, `EV_CLOSE` (peer close_notify, ours is queued in `o.send`), `EV_KEYUPDATE`, `EV_TICKET`, `EV_ERROR`.
A fatal error never raises: `o.error` names it (`tls: <alert>: <what>`), the alert is already in `o.send`, keys are
zeroed, later input is ignored. A peer's fatal alert gives `tls: peer_alert: <name>` and no alert goes back.
`c.write(data)`, `c.key_update()`, `c.close()` return bytes to send. `c.c.key_limit` (default 2^24 records) triggers an
automatic KeyUpdate in `write`.

## Behaviour that is fixed (checked by a gate)

- Records: header checked before the body is buffered (type, 0x03xx, length <= 2^14+256), unprotected record after the
  keys are installed is `unexpected_message` (except the compatibility CCS), inner type = last non-zero byte, send limit
  from the peer's `record_size_limit`, receive limit from ours, sequence number never wraps.
- Handshake: messages reassembled across records (cap 64 KiB), key changes only at record boundaries, strict order,
  duplicate extension is `illegal_parameter`, certificate chain cap 10, Finished compared in constant time,
  CertificateVerify content built here, `rsa_pkcs1` refused for CertificateVerify.
- HelloRetryRequest both ways: `message_hash` transcript, share replaced in place, cookie, ClientHello padding to 512,
  server checks that ClientHello 2 equals ClientHello 1 except share, cookie, padding.
- Compatibility mode: session id echo, one CCS each way, CCS after the handshake is rejected.
- KeyUpdate: answered under the old key, `update_requested` answered once, KeyUpdate not alone in its record rejected.
- Session tickets: client keeps at most 8, no resumption yet. The server sends none.

## Seams to the other lanes

`Verifier.verify(chain, scheme, signed, sig, host)` raises `tls: bad_certificate: ...`. Lane 3 chain validation plus lane 2
signature check implement it. `Signer.schemes() / chain() / sign(scheme, content)` is lane 2 signing (ECDSA P-256,
RSA-PSS) plus lane 3 key loading. Replacing `_tmp_crypto`: the call sites are `keysched.mojo` (hash, hmac, hkdf),
`record.mojo` (`GcmKey.seal_into/open_into`, `chacha20_poly1305_seal_into/open_into`: 2 call sites each) and
`client.mojo` (`x25519_public_key`, `x25519_shared`, `p256_public_key`, `p256_ecdh`).

## Interface changes against `docs/api.md`

- `KeySchedule[H]` is `KeySchedule(h: Int)` with the hash length (32 or 48) at run time; the transcript is kept as bytes
  in `Conn` and hashed on demand (one code path for SHA-256 and SHA-384).
- Errors are `Error("tls: <alert_name>: <what>")` (a superset of `tls: <what>`); `wire.alert_of` maps them to codes.
- `Client13` and `Server13` are generic over `Verifier` / `Signer` (new traits in `verify.mojo`); randomness and ephemeral
  private keys are constructor inputs, so the machines are deterministic and testable.
- `Record` is `Cipher` + `RecordReader`; the AEAD is pointer based and in place (`seal_into`), not `seal(nonce, aad, mut pt)`.
- `feed` returns `Out` (send, data, events, error) instead of a tuple.

## Session tickets and resumption (wave 3a)

`tls13/ticket.mojo`. The server keeps no state: a ticket is `key_name(16) | nonce(12) | ChaCha20-Poly1305(state) | tag(16)`
with `state` = issue time, lifetime, age_add, suite, resumption PSK, ALPN, SNI (AAD = key_name). `ServerConfig.ticket_keys`
(32 bytes each; the first seals, all open, so a rotation is "prepend a key"), `ticket_lifetime` (86400 s), `now` (unix
seconds, 0 = read the clock). `TlsConfig.ticket_keys` feeds it; `TlsServer` makes one key at start when the list is empty.
One NewSessionTicket follows the client Finished, also after a resumption. Only `psk_dhe_ke` (a key share is always used).

Server, `pick_psk`: a ticket is used only if it opens, its suite, ALPN and SNI equal this handshake's, it is not expired
or from the future, and the client's obfuscated age agrees (age at most the lifetime); anything else is a full handshake
and never an error. A ticket that opens but whose binder (4.2.11.2, constant time) is wrong aborts with `decrypt_error`
(the RFC says abort; an earlier plan said fall back). `pre_shared_key` must be the last extension, `psk_key_exchange_modes`
must be present. A resumption sends no Certificate and no CertificateVerify.

0-RTT is refused: `early_data` is ignored, and the records the client sealed under early keys are skipped (up to 64 KiB,
`Conn.skip`) until a record opens; `early_data` in the second ClientHello is `illegal_parameter`.

Client: `c.session(i, now_ms)` turns the i-th received ticket into a `Session`; `c.offer(session, now_ms)` before `start()`
adds psk_key_exchange_modes and `pre_shared_key` (binder filled in `start()` and again after a HelloRetryRequest).
`c.resumed` tells whether the server accepted it.

## Client certificates (wave 3b)

Server: `ServerConfig.require_client_cert` + `client_roots` (DER trust anchors; `TlsConfig` has the same two fields and passes them
to both engines). TLS 1.3: a CertificateRequest (empty context, schemes ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
rsa_pss_rsae_sha256/384) follows EncryptedExtensions; the client Certificate must be non-empty (`certificate_required` 116
otherwise), its chain valid for clientAuth against `client_roots` (`bad_certificate`), the CertificateVerify scheme one we asked
for and the signature valid over the transcript with the client context string (`decrypt_error`; `illegal_parameter` when the
scheme does not fit the key); the client Finished then covers the whole transcript. `Server13.client_cert` / `Server12.client_cert`
hold the DER of the authenticated certificate. With client authentication on there are no tickets and no resumption (a ticket
would carry no identity). The check is `tls13/clientauth.mojo` `verify_client`; it is also what Server12 calls.
TLS 1.2: CertificateRequest (rsa_sign, ecdsa_sign, schemes above plus rsa_pkcs1_sha256/384) after the ServerKeyExchange; an empty
Certificate is `handshake_failure`, a bad chain `bad_certificate`, a bad CertificateVerify (signature over the messages up to the
ClientKeyExchange) `decrypt_error`.
Client: `Client13.set_client_cert(chain, key_der)` / `Client12.set_client_cert(...)`: when the server asks and a scheme of the key is
in its list the certificate and a CertificateVerify are sent, else an empty Certificate (what a client without certificate does).
Not done: optional client authentication (ask, accept an empty answer), certificate_authorities filtering, post-handshake auth.

## Open items

tlsfuzzer is not installed here (not run). 0-RTT, optional client authentication, post-handshake authentication, ML-KEM hybrid share (an incoming 1216-byte share is skipped), a
TLS 1.2 fallback decision (lane 5: a ServerHello without `supported_versions` gives `protocol_version`).
Speed is in `tests/bench_tls13.mojo`; the ported ChaCha20 (2.2 GB/s against openssl 4.8) and x25519 (163 us against 33 us)
are lane 1-2 work.
