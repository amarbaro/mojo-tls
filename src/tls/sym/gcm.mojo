"""AES-GCM (NIST SP 800-38D): 96-bit nonce, 128-bit tag, in place.

GHASH works on byte-bit-reversed blocks, which turns GCM's reflected bit order into an ordinary carry-less
polynomial product reduced by x^128 + x^7 + x^2 + x + 1 (x^128 = 0x87). Eight blocks are multiplied by
H^8..H^1 and reduced once. The carry-less multiply is PCLMULQDQ, or a constant-time integer-multiply
version (BearSSL's ctmul64) when the hardware path is off. open() verifies the tag over the ciphertext
before it decrypts, so no unauthenticated plaintext is ever produced.

The field layout (bit-reversed bytes, deferred Karatsuba over 8 blocks, 0x87 reduction) follows crypto/aes_hw.mojo of
Mosaad-M-tls (MIT, Copyright (c) 2026 mmosaad); the code here is rewritten.
"""
from std.bit import byte_swap
from std.memory import bitcast
from std.sys.intrinsics import llvm_intrinsic
from tls.sym.aes import Aes, V16, U64x2, HW
from tls.sym.aead import Aead


@always_inline
def _rev64(x: UInt64) -> UInt64:
    return llvm_intrinsic["llvm.bitreverse.i64", UInt64, has_side_effect=False](x)


def _bmul(x: UInt64, y: UInt64) -> UInt64:
    """x*y with the carries of 4-bit-spaced digits discarded: low 64 bits of the carry-less product."""
    comptime M = 0x1111111111111111
    var x0 = x & M
    var x1 = x & (M << 1)
    var x2 = x & (M << 2)
    var x3 = x & (M << 3)
    var y0 = y & M
    var y1 = y & (M << 1)
    var y2 = y & (M << 2)
    var y3 = y & (M << 3)
    var z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
    var z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
    var z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
    var z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
    return (z0 & M) | (z1 & (M << 1)) | (z2 & (M << 2)) | (z3 & (M << 3))


@always_inline
def _clmul(a: UInt64, b: UInt64) -> U64x2:
    """64 x 64 -> 128-bit carry-less product as (low, high) words."""
    comptime if HW:
        return llvm_intrinsic["llvm.x86.pclmulqdq", U64x2, has_side_effect=False](U64x2(a, 0), U64x2(b, 0), Int8(0))
    else:
        return U64x2(_bmul(a, b), _rev64(_bmul(_rev64(a), _rev64(b))) >> 1)


@always_inline
def _field(b: V16) -> U64x2:
    return bitcast[DType.uint64, 2](llvm_intrinsic["llvm.bitreverse.v16i8", V16, has_side_effect=False](b))


@always_inline
def _unfield(x: U64x2) -> V16:
    return llvm_intrinsic["llvm.bitreverse.v16i8", V16, has_side_effect=False](bitcast[DType.uint8, 16](x))


@always_inline
def _acc(mut lo: U64x2, mut hi: U64x2, mut mid: U64x2, x: U64x2, h: U64x2):
    """Add the unreduced product x*h to the accumulators (Karatsuba: mid collects (x0^x1)*(h0^h1))."""
    lo ^= _clmul(x[0], h[0])
    hi ^= _clmul(x[1], h[1])
    mid ^= _clmul(x[0] ^ x[1], h[0] ^ h[1])


@always_inline
def _reduce(lo: U64x2, hi: U64x2, mid: U64x2) -> U64x2:
    var mm = mid ^ lo ^ hi  # the true middle term
    var m = U64x2(lo[1] ^ mm[0], hi[0] ^ mm[1]) ^ _clmul(hi[1], 0x87)  # words 1,2 plus w3 * x^192
    var b = _clmul(m[1], 0x87)  # w2 * x^128
    return U64x2(lo[0] ^ b[0], m[0] ^ b[1])


struct AesGcm(Aead, Copyable, Movable):
    var aes: Aes
    var hp: Array[U64x2, 8]  # hp[i] = H^(i+1)

    def __init__(out self, key: Span[UInt8, _]) raises:
        self.aes = Aes(key)
        self.hp = Array[U64x2, 8](fill=U64x2(0))
        var h = _field(self.aes.encrypt_block(V16(0)))
        self.hp[0] = h
        for i in range(1, 8):
            self.hp[i] = self._mul(self.hp[i - 1], h)

    @always_inline
    def _mul(self, x: U64x2, h: U64x2) -> U64x2:
        var lo = U64x2(0)
        var hi = U64x2(0)
        var mid = U64x2(0)
        _acc(lo, hi, mid, x, h)
        return _reduce(lo, hi, mid)

    def _ghash(self, mut y: U64x2, p: Pointer[UInt8, _], n: Int):
        """Absorb n bytes at p; the last block is zero padded."""
        var off = 0
        while off + 128 <= n:
            var lo = U64x2(0)
            var hi = U64x2(0)
            var mid = U64x2(0)
            comptime for i in range(8):
                var x = _field(p.unsafe_offset(off + 16 * i).unsafe_load[width=16]())
                comptime if i == 0:
                    x ^= y
                _acc(lo, hi, mid, x, self.hp[7 - i])
            y = _reduce(lo, hi, mid)
            off += 128
        while off < n:
            var last = V16(0)
            for i in range(min(16, n - off)):
                last[i] = p[unsafe_offset=off + i]
            y = self._mul(y ^ _field(last), self.hp[0])
            off += 16

    def _ctr[o: MutOrigin, enc: Bool](self, j0: V16, p: Pointer[UInt8, o], n: Int, mut y: U64x2):
        """XOR the keystream for counters 2, 3, ... (J0 is counter 1) into n bytes at p. When encrypting, the
        ciphertext is absorbed into y in the same pass, so AES and carry-less multiplies overlap."""
        var w = bitcast[DType.uint32, 4](j0)
        var ctr = UInt32(2)
        var off = 0
        var ks = Array[V16, 8](fill=V16(0))
        while off + 128 <= n:
            comptime for i in range(8):
                w[3] = byte_swap(ctr + UInt32(i))
                ks[i] = bitcast[DType.uint8, 16](w)
            self.aes.encrypt8(ks)
            var lo = U64x2(0)
            var hi = U64x2(0)
            var mid = U64x2(0)
            comptime for i in range(8):
                var q = p.unsafe_offset(off + 16 * i)
                var c = q.unsafe_load[width=16]() ^ ks[i]
                q.unsafe_store(0, c)
                comptime if enc:
                    var x = _field(c)
                    comptime if i == 0:
                        x ^= y
                    _acc(lo, hi, mid, x, self.hp[7 - i])
            comptime if enc:
                y = _reduce(lo, hi, mid)
            ctr += 8
            off += 128
        var done = off
        while off < n:
            w[3] = byte_swap(ctr)
            ctr += 1
            var k = self.aes.encrypt_block(bitcast[DType.uint8, 16](w))
            for i in range(min(16, n - off)):
                p[unsafe_offset=off + i] ^= k[i]
            off += 16
        comptime if enc:
            self._ghash(y, p.unsafe_offset(done), n - done)

    def _finish(self, j0: V16, y: U64x2, alen: Int, n: Int) -> V16:
        """Absorb the length block and mask with E(J0)."""
        var l = _field(bitcast[DType.uint8, 16](U64x2(byte_swap(UInt64(alen) * 8), byte_swap(UInt64(n) * 8))))
        return _unfield(self._mul(y ^ l, self.hp[0])) ^ self.aes.encrypt_block(j0)

    def _j0(self, nonce: Span[UInt8, _], n: Int) raises -> V16:
        if len(nonce) != 12 or n < 0 or n > 68719476704:  # 12-byte nonce; plaintext at most (2^32 - 2) blocks
            raise Error("tls: gcm bad nonce or length")
        var j0 = V16(0)
        for i in range(min(12, len(nonce))):  # clamped: a missed length check cannot read out of bounds
            j0[i] = nonce[i]
        j0[15] = 1
        return j0

    def seal(self, nonce: Span[UInt8, ImmutAnyOrigin], aad: Span[UInt8, ImmutAnyOrigin], mut buf: List[UInt8]) raises:
        var n = len(buf)
        var j0 = self._j0(nonce, n)
        var p = buf.unsafe_ptr()
        var y = U64x2(0)
        self._ghash(y, aad.unsafe_ptr(), len(aad))
        self._ctr[enc=True](j0, p, n, y)
        var t = self._finish(j0, y, len(aad), n)
        for i in range(16):
            buf.append(t[i])

    def open(self, nonce: Span[UInt8, ImmutAnyOrigin], aad: Span[UInt8, ImmutAnyOrigin], mut buf: List[UInt8]) raises:
        var n = len(buf) - 16
        var j0 = self._j0(nonce, n)
        var p = buf.unsafe_ptr()
        var y = U64x2(0)
        self._ghash(y, aad.unsafe_ptr(), len(aad))
        self._ghash(y, p, n)
        var given = p.unsafe_offset(n).unsafe_load[width=16]()
        if (self._finish(j0, y, len(aad), n) ^ given).reduce_or() != 0:
            raise Error("tls: bad record mac")
        self._ctr[enc=False](j0, p, n, y)
        buf.shrink(n)

    def wipe(mut self):
        self.aes.wipe()
        self.hp = Array[U64x2, 8](fill=U64x2(0))
