# mojo-tls

<!-- badges -->
[![ci](https://github.com/amarbaro/mojo-tls/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/amarbaro/mojo-tls/actions/workflows/ci.yml) [![latest release](https://img.shields.io/github/v/release/amarbaro/mojo-tls)](https://github.com/amarbaro/mojo-tls/releases/latest) [![license](https://img.shields.io/github/license/amarbaro/mojo-tls)](https://github.com/amarbaro/mojo-tls/blob/main/LICENSE) [![checks](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/amarbaro/mojo-tls/badges/checks.json)](https://github.com/amarbaro/mojo-tls/actions/workflows/ci.yml)
<!-- /badges -->

<!-- install -->
Install: `pixi workspace channel add https://conda.modular.com/max https://prefix.dev/amarbaro/amarbaro`, then `pixi add mojo-tls` (import `tls`). From source: `git clone https://github.com/amarbaro/mojo-tls`, `mojo-tls/scripts/deps.sh` (fetches the one dependency, [mojo-aio](https://github.com/amarbaro/mojo-aio)), then `mojo run -I mojo-tls/src -I mojo-tls/.work/deps/mojo-aio/src app.mojo`.
Toolchain: Mojo 1.2 stable.
<!-- /install -->

TLS 1.3 and TLS 1.2, client and server, with X.509 certificate validation, in pure Mojo: no OpenSSL, no C library, no
foreign calls except a few libc functions (`memcpy`, `getrandom`, `explicit_bzero`, `time`, and the socket calls in `tls.net`). 16.7k lines of Mojo under `src/tls/`. It speaks to openssl,
Firefox, Chromium and Vivaldi in both directions (see Checks).

**Status: 0.1.1, internally audited (14 findings, see the [release note](docs/releases/v0.1.1.md)), not independently audited.** Read [Security](#security) before you put it on the open internet.

## What you get

| | |
|---|---|
| Protocols | TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246 with extended master secret, RFC 7627), client and server |
| TLS 1.3 suites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` |
| TLS 1.2 suites | ECDHE with ECDSA or RSA certificates: `ECDHE-{ECDSA,RSA}-AES128-GCM-SHA256`, `-AES256-GCM-SHA384`, `-CHACHA20-POLY1305` |
| Key exchange | x25519, secp256r1 (P-256), secp384r1 (P-384), x448 (TLS 1.3) |
| Certificates | ECDSA P-256 / P-384, RSA 2048+ (PKCS#1 v1.5 and PSS); chain building to the system roots or a PEM file, name and IP matching, Public Suffix List, name constraints |
| TLS 1.3 features | session resumption (`psk_dhe_ke`, one ticket per connection), client certificates, HelloRetryRequest, KeyUpdate, ALPN, SNI, `record_size_limit` |
| Server | `TlsServer` on [mojo-aio](https://github.com/amarbaro/mojo-aio): TLS 1.3 and 1.2 on one port, certificates by SNI (exact, `*.x`, default), `require_client_cert` |
| Engines | `Client13`, `Server13`, `Client12`, `Server12` are sans-IO: bytes in, bytes and events out. Bring your own socket |

## What it is not

Refused by policy, with a fatal alert, tested. These are the 11 SKIP cells of the matrix: tlsfuzzer's TLS 1.2 scripts
and testssl's TLS 1.2 probes start from handshakes our server refuses.

- TLS 1.1 and below, SSL.
- TLS 1.2 CBC suites and RSA key exchange (no forward secrecy).
- A TLS 1.2 client that does not send `extended_master_secret`; non-empty `renegotiation_info`; renegotiation.
- 0-RTT early data (ignored and skipped, never decrypted).
- Not implemented: DTLS, QUIC, OCSP stapling, certificate revocation, FFDHE groups, compression, post-quantum groups.

## Quickstart

A server (`examples/server.mojo`), TLS 1.3 and 1.2 on one port:

```mojo
"""HTTPS server: TLS 1.3 and 1.2 on one port. usage: server CERT.pem KEY.pem [PORT]  (PORT 0 = any free port)
CERT.pem holds the certificate chain, leaf first; KEY.pem a PKCS#8 or SEC1 key (P-256) or an RSA key (2048+)."""
from std.sys import argv
from tls.net.config import TlsConfig, CertEntry
from tls.net.server import TlsServer, TlsHandler, ConnInfo
from tls.tls12.realcrypto import RealCrypto
from tls.tls12.crypto import K_P256, K_RSA
from tls.x509.cert import KEY_P256
from tls.x509.der import view
from tls.x509.key import load_private_key_der
from tls.x509.pem import pem_blocks


struct Hello(TlsHandler):
    """Answers every request with one small page, then closes the connection."""

    def __init__(out self):
        pass

    def handle(mut self, fd: Int, info: ConnInfo, data: List[UInt8], mut reply: List[UInt8]) raises -> Bool:
        var body = String("hello from mojo-tls over TLS 1.") + ("3" if info.ver == 13 else "2") + "\n"
        var head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: " + String(body.byte_length()) + "\r\n\r\n"
        reply.extend(Span((head + body).as_bytes()))
        return True  # close after the reply


def read_pem(path: String, label_has: String) raises -> List[List[UInt8]]:
    """The DER bodies of every PEM block in the file whose label contains label_has."""
    var raw: List[UInt8]
    with open(path, "r") as f:
        raw = f.read_bytes()
    var out = List[List[UInt8]]()
    for b in pem_blocks(view(raw)):
        if label_has in b.label:
            out.append(b.der.copy())
    _ = len(raw)
    return out^


def main() raises:
    var a = argv()
    if len(a) < 3:
        raise Error("usage: server CERT.pem KEY.pem [PORT]")
    var chain = read_pem(String(a[1]), "CERTIFICATE")
    var keys = read_pem(String(a[2]), "PRIVATE KEY")
    if len(chain) == 0 or len(keys) != 1:
        raise Error("need a certificate chain and exactly one private key")
    var kind = K_P256 if load_private_key_der(keys[0]).kind == KEY_P256 else K_RSA
    var cfg = TlsConfig()
    cfg.alpn.append("http/1.1")
    cfg.certs.append(CertEntry([String("localhost")], chain^, keys[0].copy(), kind))  # the first entry is the default
    var srv = TlsServer[RealCrypto](cfg^, Int(String(a[3])) if len(a) > 3 else 0, "127.0.0.1", True)
    print("LISTENING", srv.port(), flush=True)
    var h = Hello()
    srv.run(h)
```

A TLS 1.3 client (`examples/client.mojo`); the engine is sans-IO, here the sockets come from mojo-aio:

```mojo
"""HTTPS client over TLS 1.3. usage: client HOST ADDR PORT
HOST is the name the certificate must match, ADDR the IPv4 address to connect to. The server certificate is checked
against the system roots, or against the PEM file named by TLS_ROOTS (a private CA)."""
from std.sys import argv
import aio
from tls.asym import x25519_base, random_bytes
from tls.net.stream import tcp_connect
from tls.tls12.realcrypto import RealCrypto
from tls.tls13.client import Client13, default_hello
from tls.tls13.conn import EV_CLOSE, EV_DONE
from tls.tls13.verify import Verifier


struct Check(Verifier):
    """Chain and signature checks of the shipped crypto: chain to the roots, host name, CertificateVerify."""

    def __init__(out self):
        pass

    def verify(mut self, chain: List[List[UInt8]], scheme: Int, signed: List[UInt8], sig: List[UInt8], host: String) raises:
        RealCrypto().verify(chain, host, scheme, signed, sig)


def send(fd: Int32, data: List[UInt8]) raises:
    var done = 0
    while done < len(data):
        var n = aio.write(fd, Span(data)[done:])
        if n <= 0:
            raise Error("write failed")
        done += n


def main() raises:
    var a = argv()
    if len(a) < 4:
        raise Error("usage: client HOST ADDR PORT")
    var host = String(a[1])
    var fd = tcp_connect(String(a[2]), Int(String(a[3])))
    var secret = random_bytes(32)
    var hello = default_hello(host, random_bytes(32), random_bytes(32), x25519_base(secret), ["http/1.1"])
    var cli = Client13[Check](hello, host, secret, random_bytes(32), Check())
    send(fd, cli.start())
    var buf = List[UInt8](length=16384, fill=0)
    var reply = List[UInt8]()
    var asked = False
    while True:
        var n = aio.read(fd, buf)
        if n <= 0:
            break
        var o = cli.feed(Span(buf)[0:n])
        send(fd, o.send)
        if o.error.byte_length() > 0:
            raise Error(o.error)
        if o.has(EV_DONE) and not asked:  # handshake finished: the application data keys are installed
            asked = True
            var req = String("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
            send(fd, cli.write(List[UInt8](req.as_bytes())))
        reply.extend(Span(o.data))
        if o.has(EV_CLOSE):
            break
    if not asked:
        raise Error("connection closed during the handshake")
    print(String(unsafe_from_utf8=Span(reply)), end="")
    print("-- TLS 1.3, ALPN", cli.alpn)
    send(fd, cli.close())
    aio.close(fd)
```

`scripts/example.sh` builds both, serves a throwaway CA's certificate, fetches a page with the example client over TLS 1.3 and
with `openssl s_client -tls1_2` over TLS 1.2, and checks that a wrong host name is refused.

## Checks

Receipts are in `docs/perf.md` and the gate output; every number below is a count from a gate that exits non-zero on any miss.

| Gate | What |
|---|---|
| `tests/matrix.sh` | 187 cells: **176 PASS, 11 SKIP, 0 FAIL**. Our server and client against openssl (both ways, both versions), tlsfuzzer (26 scripts pass), testssl, Firefox, Chromium and Vivaldi (16 cells each) |
| `tests/gate_asym.sh` | Wycheproof: x448 510/510, ecdh secp384r1 790/790, x25519 518/518, ecdh P-256 355/355, plus ECDSA and RSA vectors; `tests/ct.mojo` constant-time checks |
| `tests/gate_x509.sh` | x509-limbo 9748 cases, 9730 agree (10 invalid chains accepted and 8 valid rejected, each pinned with a reason in `tests/limbo_known.txt`); 118 of 118 system roots parse |
| `tests/gate_tls13.sh` | handshake, record, key schedule, client auth and resumption tests (conn 206 checks, client auth 29), openssl interop, 43 planted bugs (mutants) all caught |
| `tests/sym_gate.sh` | SHA-2, HMAC, HKDF, AES-GCM, ChaCha20-Poly1305 against Wycheproof, RFC and oracle vectors |
| `tests/check.sh` | TLS 1.2 and server tests, `t_flow` policy checks (78) |
| `scripts/ci.sh` | what CI runs: all of the above except the lab matrix and the mutant sweeps |

The matrix needs browsers, tlsfuzzer, testssl and the `tests/matrix/` fixtures; it is a lab run, not a CI job.

## Performance

One core pinned (`taskset -c 5`), Ryzen 7 7800X3D, Mojo 1.2.0 (`tests/bench*.mojo`; method, profiling pass and sources of each number in [docs/perf.md](docs/perf.md)):

| Operation | Result |
|---|---|
| x25519 scalar mult | 61 us |
| P-256 ECDSA sign / verify, ECDH | 147 / 186 / 130 us |
| P-384 verify | 532 us |
| AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 record seal (16 KiB) | 5.1 / 4.4 / 1.6 GB/s |
| The same, record open | 5.4 / 4.7 / 1.7 GB/s |
| In-memory TLS 1.3 handshakes, both sides (x25519, fixed signature) | 3055 per second |

## Security

- Timing: `tests/ct.mojo` is a dudect-style test (fixed against random secret, Welch t-test, a |t| above 4.5 fails) on the x25519, x448 and
  P-256 scalar multiplications, ECDSA P-256 signing and RSA-PSS (CRT) signing; it runs inside `tests/gate_asym.sh`. AEAD tag and Finished
  comparisons use a constant-time compare, and traffic keys are wiped when a connection closes. This is a test, not a proof, and no
  independent audit has been done.
- Every parser is bounds-checked (a short read raises, never indexes out of range) and fuzzed (`tests/fuzz.mojo`, tlsfuzzer).
- Report a vulnerability privately through GitHub: **Security** tab, **Report a vulnerability**. Please do not open a public issue for one.
  See [SECURITY.md](SECURITY.md).

## More

API: [docs/api.md](docs/api.md). Design: [docs/design.md](docs/design.md). Numbers: [docs/perf.md](docs/perf.md). Shipped agent
skill: [skills/mojo-tls/SKILL.md](skills/mojo-tls/SKILL.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. Third-party code and test data are credited in [NOTICE](NOTICE).
