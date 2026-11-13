# Lane 1: symmetric crypto (`src/tls/sym/`)

Status: gate passes (`tests/sym_gate.sh`, 53 mutants killed). Import everything with `from tls.sym import ...`.

| File | Lines | Content |
|---|---|---|
| `sha2.mojo` | 158 | `Sha2[dt, ol]` generic body: `Sha256`, `Sha384`, `Sha512` (streaming `update`/`digest`), `sha256()` etc., trait `Hash` |
| `mac.mojo` | 85 | `hmac[H]`, `hkdf_extract[H]`, `hkdf_expand[H]`, `hkdf_expand_label[H]`, `prf12[H]`, `wipe` |
| `aes.mojo` | 107 | `Aes(key)`: key schedule, `encrypt_block`, `encrypt8`; AES-NI path or constant-time software path |
| `gcm.mojo` | 194 | `AesGcm(key)`: GHASH on PCLMUL (or ctmul64), CTR fused with GHASH on seal |
| `chacha.mojo` | 239 | `chacha20_xor`, `Poly1305` (radix 2^44), `poly1305_mac`, `ChaCha20Poly1305(key)` |
| `__init__.mojo` | 7 | re-exports the API |
| `aead.mojo` | 16 | trait `Aead`: `seal(nonce, aad, mut buf)` appends the tag; `open(nonce, aad, mut buf) raises` verifies then decrypts in place, drops the tag; `wipe()` |

## Behaviour that callers rely on

- `open` checks the tag over the ciphertext in constant time before it decrypts; on a bad tag it raises
  `tls: bad record mac` and the buffer is byte-for-byte unchanged. No unauthenticated plaintext is ever produced.
- Nonce must be 12 bytes, tag is 16 bytes, AES keys 16 or 32 bytes, ChaCha20 key 32 bytes; anything else raises.
- Per-nonce size limits are enforced (GCM (2^32-2)*16 bytes, ChaCha20-Poly1305 (2^32-1)*64 bytes). The caller
  owns the record sequence number and the 2^24.5-records-per-key rekey (RFC 8446 5.5).
- `hkdf_expand` raises above 255*HashLen. `hkdf_expand_label` raises for a label over 249 bytes, a context over 255, n over 65535.
- Pass the hash to every PRF call site (`prf12[Sha384]` for `*_SHA384` suites): the reference repo had a bug where the master secret used SHA-256 there.

## Hardware and software paths

- AES-NI + PCLMUL are used when the compile target has the `aes` and `pclmul` features (x86 native builds).
  `-D TLS_SOFT_AES=true` forces the software path; other targets (aarch64 included) take it automatically.
- Software AES: SubBytes is the GF(2^8) inverse (x^254) plus the affine map, as mask arithmetic on the 16 state
  bytes at once. No table, no secret-indexed load, no secret branch. The key schedule uses the same S-box.
- Software GHASH: BearSSL's ctmul64 (integer multiplies with spaced digits). It relies on the 64-bit integer
  multiply being constant time, true on x86-64 and current aarch64 cores, not guaranteed everywhere.
- Secrets in temporaries (HMAC pad block, AES round keys via `AesGcm.wipe`) are zeroed on a best-effort basis;
  Mojo gives no guarantee that a dead store survives optimisation. Keystream scratch is not wiped.

## Gate

`tests/sym_gate.sh` builds `tests/sym_check.mojo` twice (hardware, `-D TLS_SOFT_AES=true`), runs every vector line,
then applies each mutant of `tests/mutants_sym.txt` (sed on a copy of `src/`, optional build flags) and requires the
runner to fail. Vector lines: `tests/vec/` (committed: Wycheproof hmac/hkdf/aes_gcm/chacha20_poly1305 for the
96-bit-nonce, 128-bit-tag, AES-128/256 groups, FIPS 197, RFC 8448 label, RFC 8439 Poly1305) and `.work/vec/random-*.txt`
(seeded, made by `tools/gen_vec.py random .work/vec` with openssl and python `cryptography` as oracles).
`tools/fetch_wycheproof.sh` refreshes the Wycheproof JSON; `tools/gen_vec.py wycheproof tests/vec` converts it.
Out of lane scope and not counted: Wycheproof AES-192, non-96-bit nonces, truncated tags.
`tests/bench_sym.mojo` prints throughput (build it, run `bench_sym 300`).

## Numbers (7800X3D, loaded machine, best of batches, 16 KiB)

| | ours | `openssl speed` |
|---|---|---|
| AES-128-GCM seal | 6.4-6.6 GB/s | 15.0 GB/s |
| AES-256-GCM seal | 5.7 GB/s | 11.8 GB/s |
| ChaCha20-Poly1305 seal | 1.77 GB/s | 4.2 GB/s |
| ChaCha20 xor alone | 4.78 GB/s | |
| Poly1305 alone | 2.96 GB/s | |
| SHA-256 | 0.51 GB/s (no SHA-NI) | 2.46 GB/s (SHA-NI) |
| SHA-512 | 0.78 GB/s | 1.07 GB/s |
| AES-128-GCM software path | 0.022 GB/s | |
