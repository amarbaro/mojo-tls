# CLI over tls.asym for the openssl cross-checks in tests/oracle.sh. Hex in, hex out; verify prints 1 or 0.
#   x25519 <scalar> <u> | x25519-base <scalar> | p256-pub <d> | p256-ecdh <d> <pub> | p256-sign <d> <hash>
#   p256-verify <pub> <hash> <sig> | p384-verify <pub> <hash> <sig> | p384-sign <d> <hash>
#   rsa-sign-pss <alg> <hash> <n> <e> <p> <q> <dp> <dq> <qinv> | rsa-verify-pss <alg> <hash> <n> <e> <sig>
#   rsa-sign-pkcs1 <same args as rsa-sign-pss> | rsa-verify-pkcs1 <alg> <hash> <n> <e> <sig> | rand <n>
from std.sys import argv
from tls.asym import *
from tls.asym.ec import unhex


def hexs(b: Span[UInt8, _]) -> String:
    var s = String()
    comptime d = "0123456789abcdef"
    for x in b:
        s += String(d[byte=Int(x >> 4)]) + String(d[byte=Int(x & 15)])
    return s^


def main() raises:
    var a = List[String]()
    for x in argv():
        a.append(String(x))
    var c = a[1]
    if c == "x25519":
        print(hexs(x25519(unhex(a[2]), unhex(a[3]))))
    elif c == "x25519-base":
        print(hexs(x25519_base(unhex(a[2]))))
    elif c == "p256-pub":
        print(hexs(P256Key(unhex(a[2])).public_bytes()))
    elif c == "p256-ecdh":
        print(hexs(P256Key(unhex(a[2])).ecdh(unhex(a[3]))))
    elif c == "p256-sign":
        print(hexs(P256Key(unhex(a[2])).sign_sha256(unhex(a[3]))))
    elif c == "p256-verify":
        print(1 if p256_verify(unhex(a[2]), unhex(a[3]), unhex(a[4])) else 0)
    elif c == "p384-sign":
        print(hexs(p384_sign(unhex(a[2]), unhex(a[3]))))
    elif c == "p384-verify":
        print(1 if p384_verify(unhex(a[2]), unhex(a[3]), unhex(a[4])) else 0)
    elif c == "rsa-sign-pss":
        var k = RsaPrivate(unhex(a[4]), unhex(a[5]), unhex(a[6]), unhex(a[7]), unhex(a[8]), unhex(a[9]), unhex(a[10]))
        print(hexs(k.sign_pss(Int(a[2]), unhex(a[3]))))
    elif c == "rsa-sign-pkcs1":
        var k = RsaPrivate(unhex(a[4]), unhex(a[5]), unhex(a[6]), unhex(a[7]), unhex(a[8]), unhex(a[9]), unhex(a[10]))
        print(hexs(k.sign_pkcs1(Int(a[2]), unhex(a[3]))))
    elif c == "rsa-verify-pss":
        print(1 if RsaPublic(unhex(a[4]), unhex(a[5])).verify_pss(Int(a[2]), unhex(a[3]), unhex(a[6])) else 0)
    elif c == "rsa-verify-pkcs1":
        print(1 if RsaPublic(unhex(a[4]), unhex(a[5])).verify_pkcs1(Int(a[2]), unhex(a[3]), unhex(a[6])) else 0)
    elif c == "rand":
        print(hexs(random_bytes(Int(a[2]))))
    else:
        raise Error("tool: unknown command " + c)
