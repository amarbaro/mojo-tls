# Use-after-free in RecordReader.next (found 2026-11-12, fixed in 1b016b2)

**Library bug**, in `src/tls/tls13/record.mojo` (the compaction in `RecordReader.next`), present since the record layer was written.
heaptide found it without being at fault: under its preload a 256 KiB+ block is a glibc mmap chunk that `free` unmaps at once, while natively
Mojo's allocator (`TCMallocGlobals::tc_new`) keeps the freed block readable, so every native gate passed by luck. See docs/perf.md.

## Mechanism (the code before the fix)
```
elif self.pos > 65536:                                    # compaction, after 4 records of 16406 bytes: pos = 65624
    var rest = List[UInt8](length=len(self.buf) - self.pos, fill=0)
    _cp(Int(rest.unsafe_ptr()), Int(self.buf.unsafe_ptr()) + self.pos, len(rest))   # reads the OLD buffer
    self.buf = rest^                                      # drops the OLD buffer
```
The old buffer's address goes through `Int(...)`, so the compiler sees no dependency between the memcpy and the
drop of the old `self.buf`. In the built code the drop is scheduled **before** the memcpy:
`Conn::step` +0x1379: `_unchecked_grow` (rest) -> `KGEN_CompilerRT_AlignedFree(old buf)` -> `memcpy(rest, old+pos, n)`
(objdump of the heap_xfer binary; `tests/rr_grow` shows the same order).
Under glibc with the block mmapped, the memcpy source page is already unmapped: SIGSEGV. If the freed block is
reused instead (the earlier "bad_record_mac on the last record" run, before the send_app capacity change), the copy
reads foreign bytes: bad_record_mac. Natively the block is still intact, so every gate passes: **latent UAF in
production builds too**; the bytes are right only by luck.

## Evidence
- gdb, heap_xfer 1 262144 under heaptide: SIGSEGV in `memcpy` (dst 0x7ffdb41b6010 = rest, src 0x7ffdb41f7068, n 196872 =
  262496 - 65624). `catch syscall munmap` with `rdi == 0x7ffdb41e7000, rsi == 0x41000`: hit from `free` called in
  `Conn::step` 0x16 bytes before the faulting memcpy; src = old buf (0x7ffdb41e7010) + pos 65624. `info proc mappings`: gap there.
- Native, same binary, MALLOC_PERTURB_=165 under gdb: the FREE breakpoint fires before the MEMCPY breakpoint, same order.
- Sizes under heaptide: 64 KiB passes (pos never > 65536); 256 KiB, 512 KiB, 768 KiB, 1 MiB all SIGSEGV.
- The fix: `self.buf = dup(Span(self.buf)[self.pos:])`: the Span borrows the old buffer until the new list exists. `tests/rr_grow.mojo` then passes, and `heap_xfer` with 1 MiB passes under heaptide.

## Minimal repro
`tests/rr_grow.mojo`: RecordReader only, 16 records pushed at once, bytes checked.
```
.venv/bin/mojo build -I src tests/rr_grow.mojo -o .work/hx/rr
.work/hx/rr                                                                 # PASS, also before the fix (latent)
heaptide run --out .work/hx/ht-rr -- .work/hx/rr                            # before 1b016b2: Segmentation fault, after: PASS
```
The input list is built with exact capacity on purpose: a big `List` grown by doubling frees mapped blocks, which
raises glibc's mmap threshold and hides the bug. Full-stack repro: `tests/heap_xfer.mojo` (`heap_xfer 1 262144`).
Native-only detection does not exist yet (valgrind dies with SIGILL on Mojo's AVX-512); heaptide is the detector.

## Rule

A pointer laundered through `Int()` does not keep its `List` alive: Mojo drops a `List` at its last use and the free can be ordered before the memcpy. Copy only from a
`Span` or pointer whose owner is used again after the call (same class fixed in `realcrypto.mojo` open). `tests/rr_grow.mojo` runs natively and under `heaptide run` in `tests/gate_tls13.sh`.
