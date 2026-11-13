"""ChaCha20 (RFC 8439 2.4), Poly1305 (2.5) and their AEAD (2.8), in place.

ChaCha20 keeps each state word as a SIMD vector whose lane j belongs to block j, so the rounds are the scalar
code on vectors (add, xor, rotate: constant time, no intrinsics). Poly1305 is radix 2^26 on 64-bit products
with a mask-selected final reduction. open() verifies the tag over the ciphertext before it decrypts.
"""
from std.bit import rotate_bits_left
from std.math import iota
from std.memory import bitcast
from tls.sym.aead import Aead

comptime U32 = DType.uint32
comptime U128 = Scalar[DType.uint128]


@always_inline
def _qr[W: Int, a: Int, b: Int, c: Int, d: Int](mut x: Array[SIMD[U32, W], 16]):
    x[a] += x[b]
    x[d] = rotate_bits_left[16](x[d] ^ x[a])
    x[c] += x[d]
    x[b] = rotate_bits_left[12](x[b] ^ x[c])
    x[a] += x[b]
    x[d] = rotate_bits_left[8](x[d] ^ x[a])
    x[c] += x[d]
    x[b] = rotate_bits_left[7](x[b] ^ x[c])


def _keystream[W: Int, o: MutOrigin](k: SIMD[U32, 8], n: SIMD[U32, 4], ctr: UInt32, ks: Pointer[UInt32, o]):
    """Blocks ctr .. ctr+W-1 into ks, block j at ks[16j .. 16j+16]."""
    comptime V = SIMD[U32, W]
    var x = Array[V, 16](fill=V(0))
    x[0] = V(0x61707865)
    x[1] = V(0x3320646E)
    x[2] = V(0x79622D32)
    x[3] = V(0x6B206574)
    comptime for i in range(8):
        x[4 + i] = V(k[i])
    x[12] = V(ctr) + iota[U32, W]()
    x[13] = V(n[0])
    x[14] = V(n[1])
    x[15] = V(n[2])
    var init = x.copy()
    for _ in range(10):
        _qr[W, 0, 4, 8, 12](x)
        _qr[W, 1, 5, 9, 13](x)
        _qr[W, 2, 6, 10, 14](x)
        _qr[W, 3, 7, 11, 15](x)
        _qr[W, 0, 5, 10, 15](x)
        _qr[W, 1, 6, 11, 12](x)
        _qr[W, 2, 7, 8, 13](x)
        _qr[W, 3, 4, 9, 14](x)
    comptime for i in range(16):
        ks.unsafe_offset(i).unsafe_strided_store[width=W](x[i] + init[i], 16)


def chacha20_xor[o: MutOrigin](key: SIMD[U32, 8], nonce: SIMD[U32, 4], ctr: UInt32, p: Pointer[UInt8, o], n: Int):
    """XOR n bytes at p with the keystream starting at block ctr (nonce lane 3 unused). Counter wraps mod 2^32."""
    var ks = Array[UInt32, 256](fill=0)
    var off = 0
    var c = ctr
    while off + 1024 <= n:
        _keystream[16](key, nonce, c, ks.unsafe_ptr())
        for j in range(0, 1024, 64):
            var q = p.unsafe_offset(off + j)
            q.unsafe_store(0, q.unsafe_load[width=64]() ^ ks.unsafe_ptr().unsafe_bitcast[UInt8]().unsafe_offset(j).unsafe_load[width=64]())
        off += 1024
        c += 16
    while off < n:
        _keystream[4](key, nonce, c, ks.unsafe_ptr())
        var kb = ks.unsafe_ptr().unsafe_bitcast[UInt8]()
        for j in range(min(256, n - off)):
            p[unsafe_offset=off + j] ^= kb[unsafe_offset=j]
        off += 256
        c += 4


def _words[n: Int](s: Span[UInt8, _]) -> SIMD[U32, n]:
    var w = SIMD[U32, n](0)
    for i in range(min(len(s) // 4, n)):
        w[i] = UInt32(s[4 * i]) | (UInt32(s[4 * i + 1]) << 8) | (UInt32(s[4 * i + 2]) << 16) | (UInt32(s[4 * i + 3]) << 24)
    return w


struct Poly1305:
    """Radix 2^44 (three limbs) with 128-bit products."""
    var h: Array[UInt64, 3]
    var r: Array[UInt64, 3]
    var pad: SIMD[DType.uint64, 2]

    def __init__(out self, t: SIMD[U32, 8]):
        var k = bitcast[DType.uint64, 4](t)
        self.pad = SIMD[DType.uint64, 2](k[2], k[3])
        self.h = Array[UInt64, 3](fill=0)
        self.r = Array[UInt64, 3](fill=0)
        self.r[0] = k[0] & 0xFFC0FFFFFFF
        self.r[1] = ((k[0] >> 44) | (k[1] << 20)) & 0xFFFFFC0FFFF
        self.r[2] = (k[1] >> 24) & 0x00FFFFFFC0F

    def blocks(mut self, p: Pointer[UInt8, _], n: Int, hibit: UInt64):
        """Absorb n bytes (a multiple of 16); hibit is 1 << 40 for a full block, 0 for the 0x01-terminated tail."""
        comptime M44 = 0xFFFFFFFFFFF
        var r0 = self.r[0]
        var r1 = self.r[1]
        var r2 = self.r[2]
        var s1 = r1 * 20
        var s2 = r2 * 20
        var h0 = self.h[0]
        var h1 = self.h[1]
        var h2 = self.h[2]
        for off in range(0, n, 16):
            var m = p.unsafe_offset(off).unsafe_bitcast[UInt64]()
            var t0 = m.unsafe_load[width=1, alignment=1]()
            var t1 = m.unsafe_offset(1).unsafe_load[width=1, alignment=1]()
            h0 += t0 & M44
            h1 += ((t0 >> 44) | (t1 << 20)) & M44
            h2 += ((t1 >> 24) & 0x3FFFFFFFFFF) | hibit
            var d0 = U128(h0) * U128(r0) + U128(h1) * U128(s2) + U128(h2) * U128(s1)
            var d1 = U128(h0) * U128(r1) + U128(h1) * U128(r0) + U128(h2) * U128(s2)
            var d2 = U128(h0) * U128(r2) + U128(h1) * U128(r1) + U128(h2) * U128(r0)
            d1 += d0 >> 44
            d2 += d1 >> 44
            h0 = UInt64(d0) & M44
            h1 = UInt64(d1) & M44
            var c = UInt64(d2 >> 42)
            h2 = UInt64(d2) & 0x3FFFFFFFFFF
            h0 += c * 5
            h1 += h0 >> 44
            h0 &= M44
        self.h[0] = h0
        self.h[1] = h1
        self.h[2] = h2

    def padded(mut self, p: Pointer[UInt8, _], n: Int):
        """AEAD segment: the data, zero padded to a multiple of 16, every block a full block."""
        self.blocks(p, n - n % 16, 1 << 40)
        if n % 16 != 0:
            var t = Array[UInt8, 16](fill=0)
            for i in range(n % 16):
                t[i] = p[unsafe_offset=n - n % 16 + i]
            self.blocks(t.unsafe_ptr(), 16, 1 << 40)
            _ = t[0]  # keep the block alive until blocks() has read it

    def tag(self) -> SIMD[U32, 4]:
        """Fully carry, subtract p when h >= p (mask select, no branch), add the pad mod 2^128."""
        comptime M44 = 0xFFFFFFFFFFF
        comptime M42 = 0x3FFFFFFFFFF
        var h0 = self.h[0]
        var h1 = self.h[1]
        var h2 = self.h[2]
        for _ in range(2):
            h1 += h0 >> 44
            h0 &= M44
            h2 += h1 >> 44
            h1 &= M44
            h0 += (h2 >> 42) * 5
            h2 &= M42
        h1 += h0 >> 44
        h0 &= M44
        var g0 = h0 + 5
        var g1 = h1 + (g0 >> 44)
        g0 &= M44
        var g2 = h2 + (g1 >> 44) - (1 << 42)
        g1 &= M44
        var keep = (g2 >> 63) - 1  # all ones when h >= p (g2 did not underflow)
        h0 = (h0 & ~keep) | (g0 & keep)
        h1 = (h1 & ~keep) | (g1 & keep)
        h2 = (h2 & ~keep) | (g2 & keep)
        var t0 = self.pad[0]
        var t1 = self.pad[1]
        h0 += t0 & M44
        h1 += (((t0 >> 44) | (t1 << 20)) & M44) + (h0 >> 44)
        h0 &= M44
        h2 += ((t1 >> 24) & M42) + (h1 >> 44)
        h1 &= M44
        return bitcast[U32, 4](SIMD[DType.uint64, 2](h0 | (h1 << 44), (h1 >> 20) | (h2 << 24)))


def poly1305_mac(key: Span[UInt8, _], msg: Span[UInt8, _]) -> SIMD[U32, 4]:
    """The plain RFC 8439 MAC: a short last block is terminated by a 0x01 byte instead of zero padded."""
    var st = Poly1305(_words[8](key))
    var n = len(msg)
    var p = msg.unsafe_ptr()
    st.blocks(p, n - n % 16, 1 << 40)
    if n % 16 != 0:
        var t = Array[UInt8, 16](fill=0)
        for i in range(n % 16):
            t[i] = p[unsafe_offset=n - n % 16 + i]
        t[n % 16] = 1
        st.blocks(t.unsafe_ptr(), 16, 0)
        _ = t[0]
    return st.tag()


struct ChaCha20Poly1305(Aead, Copyable, Movable):
    var key: SIMD[U32, 8]

    def __init__(out self, key: Span[UInt8, _]) raises:
        if len(key) != 32:
            raise Error("tls: chacha20 key must be 32 bytes")
        self.key = _words[8](key)

    def wipe(mut self):
        self.key = SIMD[U32, 8](0)

    def _tag(self, nonce: SIMD[U32, 4], aad: Span[UInt8, _], ct: Pointer[UInt8, _], n: Int) -> SIMD[U32, 4]:
        var ks = Array[UInt32, 16](fill=0)
        _keystream[1](self.key, nonce, 0, ks.unsafe_ptr())  # block 0: its first 32 bytes are the one-time Poly1305 key
        var st = Poly1305(ks.unsafe_ptr().unsafe_load[width=8]())
        st.padded(aad.unsafe_ptr(), len(aad))
        st.padded(ct, n)
        var lens = Array[UInt64, 2](fill=UInt64(len(aad)))
        lens[1] = UInt64(n)
        st.blocks(lens.unsafe_ptr().unsafe_bitcast[UInt8](), 16, 1 << 40)
        _ = lens[0]
        return st.tag()

    def _nonce(self, nonce: Span[UInt8, _], n: Int) raises -> SIMD[U32, 4]:
        if len(nonce) != 12 or n < 0 or n > 274877906880:  # 12-byte nonce; plaintext at most 2^32 - 1 blocks
            raise Error("tls: chacha20-poly1305 bad nonce or length")
        return _words[4](nonce)

    def seal(self, nonce: Span[UInt8, ImmutAnyOrigin], aad: Span[UInt8, ImmutAnyOrigin], mut buf: List[UInt8]) raises:
        var n = len(buf)
        var nw = self._nonce(nonce, n)
        var p = buf.unsafe_ptr()
        chacha20_xor(self.key, nw, 1, p, n)
        var t = self._tag(nw, aad, p, n)
        for i in range(16):
            buf.append(UInt8((t[i // 4] >> UInt32(8 * (i % 4))) & 0xFF))

    def open(self, nonce: Span[UInt8, ImmutAnyOrigin], aad: Span[UInt8, ImmutAnyOrigin], mut buf: List[UInt8]) raises:
        var n = len(buf) - 16
        var nw = self._nonce(nonce, n)
        var p = buf.unsafe_ptr()
        var given = _words[4](Span(buf)[n:])
        if (self._tag(nw, aad, p, n) ^ given).reduce_or() != 0:
            raise Error("tls: bad record mac")
        chacha20_xor(self.key, nw, 1, p, n)
        buf.shrink(n)
