# Regression/repro for the RecordReader compaction path (pos > 65536): 16 records of 16406 bytes pushed in one call, read
# back one by one, every byte checked. Run it natively AND under `heaptide run -- rr_grow` (real glibc free: munmap).
# Exits non-zero on a wrong byte; under the buggy compaction the process dies with SIGSEGV instead.
from tls.tls13.record import RecordReader


def main() raises:
    var rr = RecordReader()
    var all = List[UInt8](capacity=16 * 16406)  # exact: no big realloc+free before the reader runs (a free of a mapped block raises glibc's mmap threshold and hides the bug)
    for r in range(16):
        all.append(23)
        all.append(3)
        all.append(3)
        all.append(UInt8(16401 >> 8))
        all.append(UInt8(16401 & 0xFF))
        for _ in range(16401):
            all.append(UInt8(r + 1))
    rr.push(Span(all))
    var rec = List[UInt8]()
    for r in range(16):
        if not rr.next(rec):
            raise Error("FAIL record " + String(r) + ": reader wants more bytes")
        if len(rec) != 16406:
            raise Error("FAIL record " + String(r) + ": length " + String(len(rec)))
        for i in range(5, len(rec)):
            if rec[i] != UInt8(r + 1):
                raise Error("FAIL record " + String(r) + ": byte " + String(i) + " is " + String(Int(rec[i])))
    print("PASS rr_grow")
