"""Throughput of the lane 1 AEADs: 16 KiB records sealed in place, one resident process. Run: bench_sym [MS per row]."""
from std.sys import argv
from std.time import perf_counter_ns
from tls.sym import *


def rate[A: Aead](name: String, a: A, ms: Int) raises:
    var nonce = List[UInt8](length=12, fill=7)
    var aad = List[UInt8](length=13, fill=1)
    var buf = List[UInt8](length=16384, fill=3)
    a.seal(nonce, aad, buf)
    buf.shrink(16384)
    var best = Int.MAX
    var t_end = perf_counter_ns() + ms * 1_000_000
    while perf_counter_ns() < t_end:
        var t0 = perf_counter_ns()
        for _ in range(50):
            a.seal(nonce, aad, buf)
            buf.shrink(16384)
        best = min(best, Int(perf_counter_ns() - t0))
    print(name, "16 KiB seal:", Float64(50 * 16384) / Float64(best), "GB/s (best of batches of 50)")


def main() raises:
    var ms = Int(argv()[1]) if len(argv()) > 1 else 300
    rate("aes-128-gcm", AesGcm(List[UInt8](length=16, fill=9)), ms)
    rate("aes-256-gcm", AesGcm(List[UInt8](length=32, fill=9)), ms)
    rate("chacha20-poly1305", ChaCha20Poly1305(List[UInt8](length=32, fill=9)), ms)
    var buf = List[UInt8](length=16384, fill=3)
    var k = SIMD[DType.uint32, 8](7)
    var best = Int.MAX
    var t_end = perf_counter_ns() + ms * 1_000_000
    while perf_counter_ns() < t_end:
        var t0 = perf_counter_ns()
        for _ in range(50):
            chacha20_xor(k, SIMD[DType.uint32, 4](1), 1, buf.unsafe_ptr(), 16384)
        best = min(best, Int(perf_counter_ns() - t0))
    print("chacha20 xor 16 KiB:", Float64(50 * 16384) / Float64(best), "GB/s")
    best = Int.MAX
    t_end = perf_counter_ns() + ms * 1_000_000
    var tg = SIMD[DType.uint32, 4](0)
    while perf_counter_ns() < t_end:
        var t0 = perf_counter_ns()
        for _ in range(50):
            tg ^= poly1305_mac(List[UInt8](length=32, fill=5), buf)
        best = min(best, Int(perf_counter_ns() - t0))
    print("poly1305 16 KiB:", Float64(50 * 16384) / Float64(best), "GB/s", tg[0] & 0)
    best = Int.MAX
    t_end = perf_counter_ns() + ms * 1_000_000
    var d = List[UInt8]()
    while perf_counter_ns() < t_end:
        var t0 = perf_counter_ns()
        for _ in range(50):
            d = sha256(buf)
        best = min(best, Int(perf_counter_ns() - t0))
    print("sha256 16 KiB:", Float64(50 * 16384) / Float64(best), "GB/s", d[0] & 0)
    best = Int.MAX
    t_end = perf_counter_ns() + ms * 1_000_000
    while perf_counter_ns() < t_end:
        var t0 = perf_counter_ns()
        for _ in range(50):
            d = sha512(buf)
        best = min(best, Int(perf_counter_ns() - t0))
    print("sha512 16 KiB:", Float64(50 * 16384) / Float64(best), "GB/s", d[0] & 0)
