# Lane 2: asymmetric crypto (`src/tls/asym/`), current truth

Pure Mojo, no C library. One constant-time Montgomery field (`bn.mojo`, generic in limb count N, carries through
UInt128) serves X25519 (N=4, p = 2^255-19), P-256 (N=4), P-384 (N=6) and RSA (N=16..64). Montgomery constants
(m0inv, R^2) are computed at construction, never hard-coded.

| File | What |
|---|---|
| `bn.mojo` | limb ops, `Modulus[N]`, CIOS `mont_mul` (unrolled up to 32 limbs), `pow_ct` (fixed 4-bit windows, table read by full scan), `eq_mask` |
| `x25519.mojo` | RFC 7748 ladder, generic over the field size (`ladder[N]`); raises on an all-zero result (RFC 8446 7.4.2) |
| `x448.mojo` | X448 (RFC 7748): the same ladder over 2^448 - 2^224 - 1, a24 = 39081, 56-byte inputs |
| `ec.mojo` | P-256/P-384: complete a=-3 formulas (Renes-Costello-Batina), windowed constant-time scalar mult, ECDH with full peer validation, ECDSA sign (RFC 6979, HMAC of the curve hash: SHA-256 for P-256, SHA-384 for `p384_sign`; no low-s) and verify (strict DER), `P256Key`, `p384_public(d)` / `p384_ecdh(d, peer)` for ephemeral secp384r1 keys |
| `rsa.mojo` | `RsaPublic.verify_pkcs1/verify_pss` (full EM re-encode compare, PSS salt = hash length), `RsaPrivate.sign_pss/sign_pkcs1` (CRT, exponent blinding, post-sign fault check) |
| `random.mojo` | `random_bytes(n)` through `getrandom(2)`, short read or error raises, no fallback |
| `sha2.mojo` | interim SHA-256/384/512 + HMAC (RFC 6979 and MGF1 need them). Lane 1 owns these: at integration replace the file by imports from `tls.sym` |

## Interface as built (differences from `docs/api.md` in bold)

- `x25519(scalar32, point32) raises -> List[UInt8]`, `x25519_base(scalar32) raises`. **Both raise `tls: low-order point` when the result is all zero.** `x448(scalar56, point56)`, `x448_base(scalar56)` likewise.
- `P256Key(d32) raises` (**new**: load a stored key), `P256Key.generate() raises`, `public_bytes()`, `ecdh(peer) raises -> shared32`, `sign_sha256(hash32) raises -> DER`, **`zeroize()`**.
- `p256_verify(pub65, hash, der) -> Bool`, `p384_verify(pub97, hash, der) -> Bool`: **never raise**; malformed input is `False`. A hash longer than the curve size is truncated to its leftmost bytes (FIPS 186-5).
- `RsaPublic(n_be, e_be) raises` (**moduli of exactly 2048, 3072 or 4096 bits, e odd in [3, 2^32)**), `verify_pkcs1(hash_alg, hash, sig) -> Bool`, `verify_pss(hash_alg, hash, sig) -> Bool`. **`hash_alg` is the Int 256, 384 or 512.**
- `RsaPrivate(n, e, p, q, dp, dq, qinv) raises` (**CRT parts, big-endian bytes; lane 3's PKCS#1/PKCS#8 loader fills it**), `sign_pss(hash_alg, hash) raises`, **`sign_pkcs1(hash_alg, hash) raises`** (TLS 1.2 peers without PSS), `public()`, `zeroize()`.
- `random_bytes(n) raises`.

## Security notes

- Secret-dependent paths use masks only: `cswap`, `select`, `eq_mask` (arithmetic, so no compiler turns it into a branch), fixed loop counts. `tests/ct.mojo` is the dudect-style check.
- RSA blinding is exponent blinding: d_p + r(p-1), d_q + s(q-1) with fresh 64-bit r, s per signature, plus fixed-window constant-time exponentiation. There is no message blinding (that needs a modular inverse of the blinding factor, which costs a second half-size exponentiation per prime).
- Every signature is verified with the public key before it is returned (Boneh-DeMillo-Lipton).
- Mojo gives no stack zeroization: `zeroize()` clears the stored key bytes, copies on the stack (limb arrays) die with the frame without being wiped.
- ECDSA sign does not normalise to low-s (matches the RFC 6979 vectors); both verify.

## Gate

`tests/gate_asym.sh` (needs `.work/wycheproof`, a shallow clone of C2SP/wycheproof, and openssl): Wycheproof via `tools/wyc2cases.py` + `tests/vectors.mojo`, RFC KATs `tests/kat.mojo`, parser fuzz `tests/fuzz.mojo`, openssl cross-checks `tests/oracle.sh` (`tests/tool.mojo` is the CLI under test), timing `tests/ct.mojo`, mutants `tests/mutants_asym.sh` (`tests/mutants_asym.txt`). Speed: `tests/bench.mojo`.

## Speed (best of 8 runs of `tools/bench-min.sh` on a loaded 7800X3D, microseconds; openssl 3.6 `speed`, one thread, same box)

| Operation | here | openssl | ratio |
|---|---|---|---|
| X25519 scalar mult | 65 | 22 | 2.9x |
| P-256 ECDH | 126 | 33 | 3.9x |
| P-256 ECDSA sign / verify | 143 / 177 | 14 / 43 | 10x / 4.2x |
| P-384 ECDSA verify | 527 | 383 | 1.4x |
| RSA-2048 PSS sign (CRT) / verify | 766 / 36 | 192 / 12.5 | 4.0x / 2.9x |
| RSA-4096 PSS sign / verify | 5565 / 200 | 1155 / 45 | 4.8x / 4.4x |

Open: a fixed-base comb table for P-256 (sign and ephemeral key generation) needs a table owned by a long-lived context.
