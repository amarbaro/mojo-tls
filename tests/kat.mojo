# Known-answer and property checks for tls.asym that need no external file: RFC 7748, RFC 6979 A.2.5, round trips,
# exponent blinding, random_bytes. Prints PASS <name> / FAIL <name>: <why>; exits non-zero on any failure.
from tls.asym import *
from tls.asym.ec import unhex, from_be, p384_public, p384_ecdh
from tls.asym.bn import Fe, Modulus, to_mont, from_mont, pow_ct, small
from tls.asym.rsa import _blind_exp
from tls.asym.sha2 import sha2

comptime HEX = "0123456789abcdef"


def hexs(b: Span[UInt8, _]) -> String:
    var s = String()
    for x in b:
        s += String(HEX[byte=Int(x >> 4)]) + String(HEX[byte=Int(x & 15)])
    return s^


def check(name: String, ok: Bool, mut bad: Int):
    if ok:
        print("PASS " + name)
    else:
        print("FAIL " + name + ": mismatch")
        bad += 1


def main() raises:
    var bad = 0
    # RFC 7748 section 5.2 and 6.1
    check("x25519 rfc7748 5.2 #1", hexs(x25519(unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))) == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", bad)
    check("x25519 rfc7748 5.2 #2", hexs(x25519(unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"), unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))) == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", bad)
    var a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    var b = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    var apub = x25519_base(a)
    var bpub = x25519_base(b)
    check("x25519 rfc7748 6.1 pubs", hexs(apub) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" and hexs(bpub) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bad)
    check("x25519 rfc7748 6.1 shared", hexs(x25519(a, bpub)) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" and hexs(x25519(b, apub)) == hexs(x25519(a, bpub)), bad)
    var k = unhex("0900000000000000000000000000000000000000000000000000000000000000")
    var u = k.copy()
    for _ in range(1000):
        var nk = x25519(k, u)
        u = k^
        k = nk^
    check("x25519 rfc7748 5.2 1000 iterations", hexs(k) == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", bad)
    var low = List[UInt8](length=32, fill=0)
    var raised = False
    try:
        _ = x25519(a, low)
    except:
        raised = True
    check("x25519 rejects the all-zero point", raised, bad)

    # RFC 7748 section 5.2 and 6.2 (x448)
    check("x448 rfc7748 5.2 #1", hexs(x448(unhex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"), unhex("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"))) == "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f", bad)
    check("x448 rfc7748 5.2 #2", hexs(x448(unhex("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"), unhex("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"))) == "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d", bad)
    var xa = unhex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
    var xb = unhex("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
    var xapub = x448_base(xa)
    var xbpub = x448_base(xb)
    check("x448 rfc7748 6.2 pubs", hexs(xapub) == "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0" and hexs(xbpub) == "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609", bad)
    check("x448 rfc7748 6.2 shared", hexs(x448(xa, xbpub)) == "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d" and hexs(x448(xb, xapub)) == hexs(x448(xa, xbpub)), bad)
    var k4 = List[UInt8](length=56, fill=0)
    k4[0] = 5
    var u4 = k4.copy()
    for _ in range(1000):
        var nk4 = x448(k4, u4)
        u4 = k4^
        k4 = nk4^
    check("x448 rfc7748 5.2 1000 iterations", hexs(k4) == "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38", bad)
    raised = False
    try:
        _ = x448(xa, List[UInt8](length=56, fill=0))
    except:
        raised = True
    check("x448 rejects the all-zero point", raised, bad)

    # RFC 5903 section 8.2 (ECP-384)
    var ia = unhex("099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194")
    var ib = unhex("41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC")
    var ga = p384_public(ia)
    var gb = p384_public(ib)
    check("p384 pubs rfc5903 8.2", hexs(ga) == "04667842d7d180ac2cde6f74f37551f55755c7645c20ef73e31634fe72b4c55ee6de3ac808acb4bdb4c88732aee95f41aa9482ed1fc0eeb9cafc4984625ccfc23f65032149e0e144ada024181535a0f38eeb9fcff3c2c947dae69b4c634573a81c" and hexs(gb) == "04e558dbef53eecde3d3fccfc1aea08a89a987475d12fd950d83cfa41732bc509d0d1ac43a0336def96fda41d0774a3571dcfbec7aacf3196472169e838430367f66eebe3c6e70c416dd5f0c68759dd1fff83fa40142209dff5eaad96db9e6386c", bad)
    raised = False
    try:
        _ = p384_public(List[UInt8](length=48, fill=0))
    except:
        raised = True
    check("p384 refuses a zero private scalar", raised, bad)
    check("p384 ecdh rfc5903 8.2", hexs(p384_ecdh(ia, gb)) == "11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4d603135569b9e9d09cf5d4a270f59746" and hexs(p384_ecdh(ib, ga)) == hexs(p384_ecdh(ia, gb)), bad)

    # RFC 6979 A.2.5 (P-256, SHA-256): the DER of the RFC's (r, s)
    var key = P256Key(unhex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"))
    check("p256 pub rfc6979 A.2.5", hexs(key.public_bytes()) == "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", bad)
    var sig = key.sign_sha256(sha2(256, "sample".as_bytes()))
    check("ecdsa p256 rfc6979 A.2.5 sample", hexs(sig) == "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8", bad)
    sig = key.sign_sha256(sha2(256, "test".as_bytes()))
    check("ecdsa p256 rfc6979 A.2.5 test", hexs(sig) == "3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d3836702" + "20019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083", bad)

    # round trips with fresh keys; a flipped hash bit or signature bit must fail
    var rt = True
    for i in range(10):
        var k1 = P256Key.generate()
        var k2 = P256Key.generate()
        var h = sha2(256, random_bytes(40))
        var s = k1.sign_sha256(h)
        rt = rt and p256_verify(k1.public_bytes(), h, s) and not p256_verify(k2.public_bytes(), h, s)
        rt = rt and hexs(k1.ecdh(k2.public_bytes())) == hexs(k2.ecdh(k1.public_bytes()))
        var h2 = h.copy()
        h2[i] ^= 1
        var s2 = s.copy()
        s2[len(s2) - 1 - i] ^= 1
        rt = rt and not p256_verify(k1.public_bytes(), h2, s) and not p256_verify(k1.public_bytes(), h, s2)
        rt = rt and hexs(k1.sign_sha256(h)) == hexs(s)  # deterministic
    check("p256 round trips, tamper, ecdh symmetry, determinism", rt, bad)

    # exponent blinding: same power, different exponent; modulus 2^255 - 19 stands in for a prime p
    var pm = Fe[4](fill=0xFFFFFFFFFFFFFFFF)
    pm[0] = 0xFFFFFFFFFFFFFFED
    pm[3] = 0x7FFFFFFFFFFFFFFF
    var md = Modulus[4](pm)
    var d = from_be[4](random_bytes(32))
    var base = to_mont(from_be[4](random_bytes(31)), md)
    var eb = _blind_exp[4](d, pm, 0x123456789ABCDEF)
    var plain = Fe[5](fill=0)
    for i in range(4):
        plain[i] = d[i]
    check("rsa exponent blinding changes the exponent, keeps the power", eb != plain and pow_ct(base, eb, md) == pow_ct(base, d, md), bad)

    # random_bytes: 1 MiB, chi-square over byte values (255 dof: mean 255, sd 22.6) and two reads differ
    var r1 = random_bytes(1 << 20)
    var cnt = List[Int](length=256, fill=0)
    for x in r1:
        cnt[Int(x)] += 1
    var chi = 0.0
    for c in cnt:
        var dlt = Float64(c) - 4096.0
        chi += dlt * dlt / 4096.0
    check("random_bytes 1 MiB chi-square in [150, 400] (got " + String(Int(chi)) + ")", len(r1) == (1 << 20) and chi > 150 and chi < 400 and hexs(random_bytes(32)) != hexs(random_bytes(32)), bad)
    if bad > 0:
        raise Error("kat: failures")
