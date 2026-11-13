# SHA-2 and HMAC by bit size (256/384/512) over lane 1, for RFC 6979 nonces and PSS MGF1.
from tls.sym import Sha256, Sha384, Sha512, sha256, sha384, sha512
from tls.sym import hmac as _hmac


def sha2(alg: Int, data: Span[UInt8, _]) -> List[UInt8]:
    return sha256(data) if alg == 256 else (sha384(data) if alg == 384 else sha512(data))


def hmac(alg: Int, key: Span[UInt8, _], data: Span[UInt8, _]) -> List[UInt8]:
    var k = List[UInt8](key)
    var d = List[UInt8](data)
    if alg == 256:
        return _hmac[Sha256](k, d)
    return _hmac[Sha384](k, d) if alg == 384 else _hmac[Sha512](k, d)
