"""AES-128/256 encryption (FIPS 197), no table lookups.

Hardware path: AES-NI (aesenc/aesenclast) on x86 with the aes and pclmul features. Software path (any other
target, or -D TLS_SOFT_AES=true): SubBytes is the GF(2^8) inverse x^254 plus the affine map, computed with
mask arithmetic on all 16 state bytes at once, so no secret ever indexes memory or steers a branch.
Key schedule uses the same S-box, so it is constant time on both paths.
"""
from std.sys import get_defined_bool
from std.sys.info import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic
from std.bit import rotate_bits_left
from std.memory import bitcast

comptime V16 = SIMD[DType.uint8, 16]
comptime U64x2 = SIMD[DType.uint64, 2]
comptime HW = (not get_defined_bool["TLS_SOFT_AES", False]()) and CompilationTarget.is_x86() and CompilationTarget._has_feature["aes"]() and CompilationTarget._has_feature["pclmul"]()


@always_inline
def _xt(a: V16) -> V16:
    return (a << 1) ^ ((a >> 7) * 0x1B)


@always_inline
def _mul(a: V16, b: V16) -> V16:
    var r = V16(0)
    var x = a
    var y = b
    comptime for _ in range(8):
        r ^= x & ((y & 1) * 255)
        x = _xt(x)
        y >>= 1
    return r


def _sbox(x: V16) -> V16:
    var x3 = _mul(_mul(x, x), x)
    var x7 = _mul(_mul(x3, x3), x)
    var x15 = _mul(_mul(x7, x7), x)
    var x31 = _mul(_mul(x15, x15), x)
    var x63 = _mul(_mul(x31, x31), x)
    var x127 = _mul(_mul(x63, x63), x)
    var b = _mul(x127, x127)  # x^254 = x^-1 (0 for 0)
    return b ^ rotate_bits_left[1](b) ^ rotate_bits_left[2](b) ^ rotate_bits_left[3](b) ^ rotate_bits_left[4](b) ^ 0x63


@always_inline
def _round[last: Bool](s: V16, k: V16) -> V16:
    """One AES round as aesenc/aesenclast define it: ShiftRows, SubBytes, MixColumns (not in the last), xor key."""
    comptime if HW:
        comptime if last:
            return bitcast[DType.uint8, 16](llvm_intrinsic["llvm.x86.aesni.aesenclast", U64x2, has_side_effect=False](bitcast[DType.uint64, 2](s), bitcast[DType.uint64, 2](k)))
        return bitcast[DType.uint8, 16](llvm_intrinsic["llvm.x86.aesni.aesenc", U64x2, has_side_effect=False](bitcast[DType.uint64, 2](s), bitcast[DType.uint64, 2](k)))
    else:
        var v = _sbox(s.shuffle[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]())
        comptime if not last:
            var r1 = v.shuffle[1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12]()
            v = _xt(v ^ r1) ^ r1 ^ v.shuffle[2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]() ^ v.shuffle[3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]()
        return v ^ k


struct Aes(Copyable, Movable):
    var rk: Array[V16, 15]
    var nr: Int

    def __init__(out self, key: Span[UInt8, _]) raises:
        if len(key) != 16 and len(key) != 32:
            raise Error("tls: aes key must be 16 or 32 bytes")
        var nk = max(1, min(len(key) // 16, 2))  # round keys in the key itself; clamped so a missed policy check cannot read out of bounds
        self.nr = 6 + 4 * nk
        self.rk = Array[V16, 15](fill=V16(0))
        for i in range(nk):
            for j in range(min(16, len(key) - 16 * i)):
                self.rk[i][j] = key[16 * i + j]
        var rcon: UInt8 = 1
        for i in range(nk, self.nr + 1):
            var a = self.rk[i - nk]
            var b = self.rk[i - 1]
            var t: V16
            if nk == 1 or i % 2 == 0:  # RotWord + Rcon (256-bit keys: only on even steps)
                t = _sbox(b.shuffle[13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12]())
                t ^= V16(rcon, 0, 0, 0, rcon, 0, 0, 0, rcon, 0, 0, 0, rcon, 0, 0, 0)
                rcon = _xt(V16(rcon))[0]
            else:
                t = _sbox(b.shuffle[12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15]())
            self.rk[i] = a ^ a.shift_right[4]() ^ a.shift_right[8]() ^ a.shift_right[12]() ^ t

    @always_inline
    def encrypt_block(self, block: V16) -> V16:
        var s = block ^ self.rk[0]
        for r in range(1, self.nr):
            s = _round[False](s, self.rk[r])
        return _round[True](s, self.rk[self.nr])

    @always_inline
    def encrypt8(self, mut b: Array[V16, 8]):
        """Eight blocks, round-outer so the AES units pipeline across them."""
        comptime for i in range(8):
            b[i] ^= self.rk[0]
        for r in range(1, self.nr):
            comptime for i in range(8):
                b[i] = _round[False](b[i], self.rk[r])
        comptime for i in range(8):
            b[i] = _round[True](b[i], self.rk[self.nr])

    def wipe(mut self):
        self.rk = Array[V16, 15](fill=V16(0))
