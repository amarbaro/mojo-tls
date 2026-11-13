# X448 (RFC 7748 section 5): the ladder of x25519.mojo over GF(2^448 - 2^224 - 1), a24 = 39081.
from .bn import *
from .x25519 import ladder


def _field() -> Modulus[7]:
    var m = Fe[7](fill=0xFFFFFFFFFFFFFFFF)
    m[3] = 0xFFFFFFFEFFFFFFFF
    return Modulus[7](m)


def x448(scalar: Span[UInt8, _], point: Span[UInt8, _]) raises -> List[UInt8]:
    """Scalar mult of the u-coordinate `point` (56 bytes LE). Raises on an all-zero result (low-order input)."""
    if len(scalar) != 56 or len(point) != 56:
        raise Error("tls: x448 needs 56-byte inputs")
    var k = List[UInt8](scalar)
    k[0] &= 252
    k[55] |= 128
    return ladder(k^, 448, point, _field(), 39081)


def x448_base(scalar: Span[UInt8, _]) raises -> List[UInt8]:
    var five = List[UInt8](length=56, fill=0)
    five[0] = 5
    return x448(scalar, five)
