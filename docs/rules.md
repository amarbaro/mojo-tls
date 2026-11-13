# Rules (what broke -> the rule)

- A byte loop `List[UInt8](Span(x))` was 26.5% of all cycles in the record bench and nobody saw it until corewait ran -> before every publish run the profiling pass (memory-optimization, corewait, heaptide, wavewait), measure each change against the previous binary alternating on one pinned core, medians, peak RSS, and keep the table in docs/perf.md; copy bytes with one `memcpy` from a Span.
- `x = f(Span(x))` with x a List returned a wrong value (TLS PRF A(2) came out as A(1)) -> never assign a call result over the list its Span borrows from: compute into a temp (`var nx = f(a); a = nx^`).
- SHA-512/384 padding left the 0x80 byte inside the 16-byte length field when the message length was 112..119 mod 128 -> clear the whole block before writing the length, then test every length 0..139 against an oracle.
- A mutant regex containing `|` split on the mutant file's `|` separator and ran as a different mutant -> the separator is `@`; write a literal `|` as `[|]`.
- OpenSSL's `enc -chacha20` carries a counter wrap into the nonce word, RFC 8439 leaves it undefined -> keep oracle messages below 2^32 blocks.
- `Span[UInt8, _]` parameters infer a mutable origin from a `List` argument and reject the same list twice -> declare read-only inputs as `Span[UInt8, ImmutAnyOrigin]`.
- A generic over a trait whose methods hold a value needs `Deinitable` on the trait, not `Movable`.

# Rules learned (what broke -> the rule)

Lane 4 (TLS 1.3), 2026-11-12. Other lanes append their own lines; concatenate on merge.

- A sed rewrite of `crypto.` in the ported Mosaad files also renamed the `llvm.aarch64.crypto.aese` intrinsics -> rewrite
  only the leading `from`/`import` lines (`tools/port_tmp_crypto.sh`), then diff the result against the source.
- A test whose expected value is computed by the code under test (CertificateVerify content) let a mutant of that code
  survive -> write the expected bytes out by hand in the test and add an independent oracle (openssl verifies the RFC 8448
  signature over our content).
- A mutant of the Finished check survived because every test fed valid input -> each verification gets a test that feeds
  the same message with one bit flipped and checks the alert on the wire.
- A plaintext record arriving after the traffic keys were installed went to the AEAD (wrong alert) -> check the outer type
  before decrypting; found by the loopback gate, not by the RFC traces.
- The interop client closed stdin right after its request, so close_notify overtook the echo; RFC 8446 6.1 makes the
  receiver close at once and drop pending writes -> harnesses wait for the reply before closing.
- A generic struct parameter needs `trait X(Movable, Deinitable)` on this Mojo, otherwise "field has non-'Deinitable' type".
- Parallel lanes load the box (load average 50+): numbers are best of N rounds, never a single run.


## Lane 5 (TLS 1.2, net, interop harness)

- `zero = zero or r.u8() == 0` in a `while r.left() > 0` scan never read again once `zero` was true: endless loop on a
  ClientHello. Read into a variable first, then combine. Found by the mutation fuzz, not by review.
- `openssl s_client -no_extended_master_secret` does not exist (it is `-no_ems`): the client printed usage, the "server
  refuses it" check passed for the wrong reason. A negative probe must prove the client really connected and the
  handshake then failed (`refused()` in tests/interop/run.sh).
- A harness is tested against a known good peer before it judges ours: `run.sh peers` found three probe bugs (s_client
  quit on stdin EOF before the reply, curl exits non-zero under `pipefail` after a close without close_notify, a CA SPKI
  pin never matches an unchained leaf in Chromium).
- `vivaldi --headless=new --dump-dom` never exits here: drive it over CDP (tests/interop/browser_probe.py).
- A test must make the condition happen. The first slow-reader test (2 MiB) left the "EPOLLOUT never armed" mutant alive
  because loopback buffers swallowed it; 4 MiB to a 4 KiB receive buffer makes partial writes real.
- An alert code of 0 must not mean "default decode_error" (0 is close_notify): the default is `A_DECODE`, `-1` means
  "the peer sent the alert, send none back".
- Mojo 1.2: `raise` after assigning a field of a field in a raising `__init__` fails to compile ("destroyed out of the
  middle"): do the raising work in `start()`. `ref p = self.tab[fd]` is invalidated by any `mut self` call: index again.
  `List + List` needs implicit copies: use `cat(...)`. `Int(String, base=16)` does not exist: decode nibbles.

Lane x509 wave 2 (2026-11-12).

- A build that failed left the old binary in place and the next run reported old results -> every build script deletes the binary first and fails when it is missing (`tests/lim.sh`).
- `cmd1; commit` committed after a failed gate stage -> commit only after the check in the same `&&` chain, read the PASS lines first.
- A limbo case can contradict another (`conflicts_with`, and unmarked pairs such as the CN cases) -> an invalid chain accepted is never pinned except the one policy class the orchestrator named; the valid twin is pinned with the reason.
- A mutant survived because a second rule rejected the same fixture first (ca_check_removed, wildcard_tld, leaf_ca_ok) -> a fixture must violate exactly one rule; a survivor is a test gap or an equivalent mutant (delete the code), never ignored.
- A fixture leaf signed by the wrong root made a cap test pass for the wrong reason -> check each negative case by flipping the one thing it tests (the mutant of the cap).
- `view(read_file(p))` freed the bytes while the view was alive (22 roots "dropped") -> bind the buffer to a variable that outlives the view.
- Real roots break pedantic rules (serial 0 in GoDaddy and Hellenic, no SKI in TWCA Global Root CA) -> audit the system bundle (`gate_x509.sh roots`) before turning a profile rule on for anchors.
## Lane matrix (wave 2)

- Two lane 1 mutants (gcm-noncelen, aes-keylen) were "killed" by SIGILL from a bounds trap, not by a check -> a mutant runner
  counts only a checked error (exit 1, a printed FAIL or a raised Error) as a kill; exit >= 124 (signal, timeout) is a survivor; code clamps its loops so a missed policy check cannot read out of bounds.
- Duplicate lines in tests/mutants_sym.txt ran the same mutant twice in one directory and garbled the log -> mutant names are unique.
- `playwright install chromium` deleted the older chromium, headless-shell and ffmpeg builds from the shared `~/.cache/ms-playwright`
  (it prunes builds "unused" by its own version) -> never run `playwright install` against the shared cache; set
  `PLAYWRIGHT_BROWSERS_PATH=<repo>/.work/...` first, or reuse an installed build read-only.
- `tests/matrix/msrv.mojo` killed every connection after 20 s (alarm); tlsfuzzer test-tls13-finished 'pad_right 16777183' sends a 16 MiB Finished
  in about 20 s and expects the decode_error we had already sent, then a close: the reset hit it mid-send and the cell failed, but only when the
  script's random sample of 40 cases happened to pick it -> a harness timeout must exceed the slowest peer (now 330 s), and every tlsfuzzer cell
  runs all cases (`-n 0`), never the default random sample of 40.
- Chromium matrix cells failed with net::ERR_NETWORK_CHANGED when other sessions' docker containers added veth interfaces mid-run (2026-11-12, 2 of 162 cells; rerun of ^chromium/ 16/16 twice) -> a browser cell that fails with ERR_NETWORK_CHANGED is retried once before it counts as FAIL; report the retry.
- New first-record parsing in TlsServer sliced first[9:need] for a record shorter than 9 bytes: one tiny record from any client crashed the server, found only by the matrix (2026-11-12) -> new parser code on a network path gets a short-input regression client (tests/net.sh 'tiny') before the matrix.
- TlsServer closed the socket with the peer's input unread after a fatal alert: the kernel reset the connection and tlsfuzzer lost our decode_error (2026-11-12) -> after our last record the server half-closes and drains (idle limit per read, byte cap), never a bare close.

## Wave 3 (3c groups)

- `ServerConfig.__init__` does not raise, `random_bytes` does -> a field that needs fresh randomness stays empty in the
  constructor and `Server13` fills it where it already raises (no signature change for the callers in `src/tls/net`).
- The Wycheproof x448 "invalid" cases (57-byte public key) failed because the harness only accepted a raise for
  "acceptable" results -> a raise is the right answer for every `invalid` case; the harness says so.
- `tests/gate_tls13.sh` is mode 644: a chain that runs it directly dies with rc 126 and looks like a gate failure -> start gates with `bash tests/<gate>.sh`.
- A tlsfuzzer echo script (`test-tls13-lengths`) hung against the HTTP-only matrix server and looked like a ticket bug -> `msrv` echoes a stream that does not start with "GET"; read what a script needs from its server before reading a timeout as ours.
- A probe run alone skips the script's "sanity" probe -> check a failing probe by running it with `sanity`, or the whole script.
- `pkill -f <pattern>` inside the same bash command kills its own wrapper shell -> keep the PID from `$!` or `ps | awk` and `kill` it.
- The plan said a forged binder falls back to a full handshake; RFC 8446 4.2.11 says abort -> the RFC wins where the plan only paraphrases it: unknown, expired or mismatched tickets fall back, a bad binder on a ticket that opens is `decrypt_error`.
- `test-tls13-lengths` is 16384 probes (about 280 s in one process, the cell budget) -> four cells of 4096 named probes, so every case still runs.
- tlsfuzzer `check sigalgs in cert request` answers a CertificateRequest with an empty Certificate and expects the handshake to go on; a server that requires the certificate fails it by design -> expected-fail with that reason, optional client authentication is not implemented.
- A client-auth server may not resume or issue tickets: a ticket carries no client identity, so a resumed session would skip the authentication -> `pick_psk` ignores PSKs and `send_ticket` is off while `require_client_cert` is set.
- The TLS 1.2 CertificateVerify signs the messages BEFORE it, but the transcript buffer already holds the received CertificateVerify -> cut `4 + len(body)` bytes off the end before verifying.
- tlsfuzzer scripts name their expectations about the server (client-auth, sigalgs offered via `-s`, tickets via `-t`): read the script's option list before judging a probe, and pass what our server really does.
- The matrix echo hook kept state per fd and a reused fd inherited it, so "GET /" was echoed and a probe failed one run in four -> never key per-connection state on an fd without clearing it when the connection ends; decide per chunk.
- `tests/mutants_x509.txt` is applied with perl: a `(` in a pattern is a group, write `\(`; gate_tls13.sh and check.sh use sed with paths under `src/` (`tls/tls13/...`): a mutant that names a missing file prints "FAIL mutant: ..." with no reason line.
- Two gate chains started at once share `.work/mut` and corrupt each other's logs -> one chain at a time, check `ps` before launching.
- A pointer laundered through Int() does not keep its List alive: Mojo drops a List at its last use and the free was ordered before the memcpy (RecordReader UAF, 2026-11-12) -> memcpy only from a Span, or use the owner again after the call; rr_grow runs under heaptide in gate_tls13.

## Audit fix lane (v0.1.1, 2026-11-12)

- 5 of 14 audit findings were wrong or half right (#6 a borrowed argument is kept alive by the caller, #8 a branch the parser makes unreachable, #10 RFC 8446 5.4 mandates `unexpected_message`, #11 RFC 5280 4.2.1.10 allows a leading period only in URI constraints and x509-limbo pins the refusal, #12 the unoffered-extension alert was already right) -> every finding is reproduced on the tree and checked against the RFC text before a fix; a behaviour an independent suite pins (limbo, RFC MUST) is never "fixed" because a report says so.
- The first growth test (16-byte records, 17-byte reads) passed on the unfixed tree: the two sizes realign every 272 bytes and the buffer empties -> a regression test runs against the unfixed tree first, and a read pattern must never land on a record boundary (one byte first, then 32 per read).
- `real_server` hardcoded `K_P256` and check.sh ran `TLS_KINDS=p256`, so no P-384 or RSA key ever reached the real engine in the gate; the audit's P-384 finding hid there -> harness constants follow the input (the kind comes from the key), and the gate runs every kind it claims.
- A P-384 certificate failed on the client for a second reason after the sign path worked: TLS 1.2 binds no curve to the signature scheme, and `openssl s_server` signs a P-384 certificate with 0x0403 -> verify by key type, not by the scheme's curve name; found only by the interop cell against `s_server`.
- Widening what the key loader accepts flipped a pinned refusal (`ec384_refused` in tests/data/key_cases.txt) that only gate_x509 caught -> before widening an accepted set, grep the manifests and mutants for the refusal it pins, and change both in one commit.
- `ct` (dudect, one pinned core) failed `p256 scalar mult` five times in a row on a busy box, and the unmodified v0.1.0 binary also failed it once; the scalar-mult code was untouched -> before blaming a change, alternate the old and new binaries on the same core (reverse the order too: the last one of a round fails more), then rerun the gate alone.
