# Performance

Machine: Ryzen 7 7800X3D, one core pinned (`taskset -c 5`), Mojo 1.2.0 (2016d0cd), tree at commit a2452e2. Binaries are built by
`mojo build -I src -I tests -I <mojo-aio>/src tests/bench*.mojo`. Each number is a best-of or median printed by the bench itself.

| Operation | Result | Source |
|---|---|---|
| x25519 scalar mult | 60.6 us | `tests/bench.mojo` |
| P-256 ECDSA sign / verify / ECDH | 147.0 / 185.9 / 129.9 us | `tests/bench.mojo` |
| P-384 verify (full path) | 531.9 us | `tests/bench.mojo` |
| AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 seal, 16 KiB | 6.64 / 5.67 / 1.77 GB/s | `tests/bench_sym.mojo` (primitive alone) |
| chacha20 xor / poly1305 / sha256 / sha512, 16 KiB | 4.86 / 2.94 / 0.51 / 0.75 GB/s | `tests/bench_sym.mojo` |
| TLS 1.3 record seal, 16 KiB, suites 0x1301 / 0x1302 / 0x1303 | 5058 / 4464 / 1614 MB/s | `tests/bench_tls13.mojo` |
| TLS 1.3 record open, same suites | 5390 / 4723 / 1671 MB/s | `tests/bench_tls13.mojo` |
| In-memory TLS 1.3 handshakes, client + server, same suites | 3056 / 2890 / 3106 per second | `tests/bench_tls13.mojo` |

The handshake bench uses a fixed-signature signer, so the ECDSA or RSA cost (above) is not in it. Peak RSS of `bench_tls13`: 11.7 MB.
Not measured: a network benchmark, RSA signing or verification speed, TLS 1.2 throughput.

## Profiling pass v0.1.0

Method: every change measured against the previous binary (`before-bench_tls13`, built from c2216c7 plus the bench fix), alternating, pinned to core 5,
5 rounds, medians, peak RSS from `/usr/bin/time -f %M`. Receipts: `.work/prof/` (binaries, run logs, corewait and heaptide recordings).

### Hot paths and what changed (memory-optimization)

Hot paths named: record seal and open (AES-GCM and ChaCha20-Poly1305), the handshake (x25519, P-256, P-384, signature verify, x509 chain parse), record framing.

| Hot path | Before | After | Change |
|---|---|---|---|
| record open, 0x1301 AES-128-GCM | 2280 MB/s | 5390 MB/s | `dup()`: one memcpy instead of a `List(Span)` byte loop (it was 26.5% of all cycles) |
| record open, 0x1302 AES-256-GCM | 2149 MB/s | 4723 MB/s | same |
| record open, 0x1303 ChaCha20-Poly1305 | 1188 MB/s | 1671 MB/s | same |
| record seal, 0x1301 / 0x1302 / 0x1303 | 4935 / 4390 / 1613 MB/s | 5058 / 4464 / 1614 MB/s | body built with `unsafe_uninit_length`, only the padding tail zeroed (+2.5% / +1.7% / 0.1%) |
| handshakes per second, 3 suites | 3058 / 2899 / 3106 | 3056 / 2890 / 3106 | unchanged (within noise): handshake cost is x25519 and hashing, not copies |
| x25519 per second | 16527 | 16537 | unchanged |
| peak RSS, bench_tls13 | 11720 KB | 11668 KB | unchanged |
| `send_app` output buffer | `len + 64`: reallocated and copied the whole buffer at record 64 | capacity counts the per-record header, type byte and tag (22 B) | one realloc and one whole-buffer copy less per large write (not timed separately) |

Constant-time code was not touched: the copies are in the record layer and the TLS 1.2 AEAD wrapper, not in a primitive. `tests/ct.mojo` and the
timing gate run inside `tests/gate_asym.sh`; the full gates and matrix (176 PASS, 11 SKIP, 0 FAIL) passed on the committed fix (1b016b2).

Attempts reverted: none. Not done, on purpose: the per-record allocations (seal: header + body; open: copy, header copy, record; 5 to 16 KiB each) are small against the
3 us of AEAD work per record and were not profiled further. SHA-256 at 0.51 GB/s is software-only (no SHA-NI path) and is the next target for the handshake.

### corewait (CPU stall profile, `tests/bench_tls13.mojo 3000 100`)

| | Before | After |
|---|---|---|
| cycles | 5.84 G | 4.31 G (-26%) |
| instructions | 19.0 G | 10.8 G (-43%) |
| wall time | 1.17 s | 0.86 s |
| IPC | 3.25 | 2.50 |
| package energy | 52.0 J | 30.7 J |
| top function | `List.__init__` byte copy 26.5% of cycles (a `cmp rcx, rdx` loop, 19.3% on one instruction) | gone |

The IPC fell because the removed loop was the cheapest, highest-IPC code in the run. What is left (after): `Poly1305.blocks` 30.6% (a dependent `mulx` chain,
cause `busy`/`dep`: arithmetic-bound, no cheap fix), `chacha20_xor` 19.5%, `Cipher.seal` 15.0%, `mont_mul` 8.9% (x25519 and P-256), `Cipher.open` 8.6%, `_ghash` 6.9%.
No row is stalled on memory (`mem` column 0): the record paths are compute-bound.

### heaptide (heap profile of one handshake plus 1 MiB each way, client and server in one process; `tests/heap_xfer.mojo`)

| | 1 handshake | 21 handshakes |
|---|---|---|
| leaks (direct / indirect) | 0 / 0 | 0 / 0 |
| live at exit | 85,446 B | 85,446 B (flat: no growth) |
| peak live | 1.47 MB runtime allocation + the 1 MiB application buffers (send buffer 1,050,070 B, reader buffer 1,049,984 B) | same |
| allocation sites per record (HOTSPOTS) | at least 4: seal body, seal header, open copy, record copy; 64 records per MiB each | 1344 per site over 21 handshakes (21 x 64) |

heaptide needed no change to measure mojo-tls. One thing it taught: it found a real use-after-free that every native gate had passed
(`docs/rules.md`, the `Int()`-laundered pointer rule; fixed in 1b016b2, repro `tests/rr_grow.mojo`, now run natively and under heaptide by `tests/gate_tls13.sh`).
Mojo's allocator is `TCMallocGlobals::tc_new` (the `KGEN_CompilerRT_AlignedAlloc` call is a jump to it). Natively it mmaps a 1 GiB region at start and a gdb `catch syscall munmap` saw no unmap of a record buffer on `free`; under heaptide the same calls reach glibc, where a freed 256 KiB block is unmapped at once. Allocation counts and live bytes seen by heaptide are the program's
own; peak RSS and mapping behaviour are glibc's, not the native run's.

### wavewait

wavewait: N/A, no GPU kernels. mojo-tls is CPU-only; no GPU path was added.
