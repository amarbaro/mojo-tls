"""Lane 1 gate runner: sym_check VECFILE... checks every line of every vector file, prints PASS/FAIL per kind.
An unknown kind is a failure (a skipped vector is not a pass). See tools/gen_vec.py for the line format."""
from std.collections import Dict
from std.sys import argv, exit
from tls.sym import *
from tls.sym.aes import V16
from tls.sym.chacha import _words


def unhex(s: StringSlice) raises -> List[UInt8]:
    var out = List[UInt8]()
    if s == "-":
        return out^
    var b = s.as_bytes()
    for i in range(0, len(b), 2):
        var v = 0
        for j in range(2):
            var c = Int(b[i + j])
            v = v * 16 + (c - 48 if c < 58 else c - 87)
        out.append(UInt8(v))
    return out^


def hash_of(alg: StringSlice, m: Span[UInt8, ImmutAnyOrigin]) raises -> List[UInt8]:
    if alg == "256":
        return sha256(m)
    elif alg == "384":
        return sha384(m)
    elif alg == "512":
        return sha512(m)
    raise Error("alg " + String(alg))


def mac_of(alg: StringSlice, k: Span[UInt8, ImmutAnyOrigin], m: Span[UInt8, ImmutAnyOrigin]) raises -> List[UInt8]:
    if alg == "256":
        return hmac[Sha256](k, m)
    elif alg == "384":
        return hmac[Sha384](k, m)
    return hmac[Sha512](k, m)


def same(a: List[UInt8], b: List[UInt8]) -> Bool:
    return len(a) == len(b) and Span(a) == Span(b)


def rejects[A: Aead](a: A, iv: List[UInt8], aad: List[UInt8], var bad: List[UInt8]) -> Bool:
    """Open must raise and leave the buffer as it was."""
    var snap = bad.copy()
    try:
        a.open(iv, aad, bad)
        return False
    except:
        return same(bad, snap)


def aead_case[A: Aead](a: A, iv: List[UInt8], aad: List[UInt8], msg: List[UInt8], ct: List[UInt8], tag: List[UInt8], valid: Bool) raises -> Bool:
    var wire = ct.copy()
    wire.extend(Span(tag))
    if not valid:
        return rejects(a, iv, aad, wire^)
    var buf = msg.copy()
    a.seal(iv, aad, buf)
    if not same(buf, wire):
        return False
    a.open(iv, aad, buf)
    if not same(buf, msg):
        return False
    for i in range(len(wire) - 16 if len(msg) > 64 else 0, len(wire)):  # every tag byte (and ct for short rows)
        var bad = wire.copy()
        bad[i] ^= 1
        if not rejects(a, iv, aad, bad^):
            return False
    if len(aad) > 0:
        var bad_aad = aad.copy()
        bad_aad[len(aad) - 1] ^= 0x80
        if not rejects(a, iv, bad_aad, wire.copy()):
            return False
    var bad_iv = iv.copy()
    bad_iv[0] ^= 1
    return rejects(a, bad_iv, aad, wire.copy())


def bad_args[A: Aead](a: A) -> Bool:
    """Short buffers and wrong nonce lengths must raise, never crash."""
    var aad = List[UInt8](length=3, fill=1)
    for n in range(16):
        if not rejects(a, List[UInt8](length=12, fill=0), aad, List[UInt8](length=n, fill=5)):
            return False
    for n in [0, 11, 13, 16]:
        var buf = List[UInt8](length=20, fill=5)
        try:
            a.seal(List[UInt8](length=n, fill=0), aad, buf)
            return False
        except:
            if len(buf) != 20:
                return False
    return True


def check(f: List[String]) raises -> Bool:
    var kind = f[0]
    var alg = f[1] if len(f) > 1 else String("")
    if kind == "hash":
        return same(hash_of(alg, unhex(f[2])), unhex(f[3]))
    elif kind == "hmac":
        var got = mac_of(alg, unhex(f[2]), unhex(f[3]))
        var want = unhex(f[4])
        var eq = len(want) <= len(got) and Span(got)[: len(want)] == Span(want)
        return eq == (f[5] == "valid")
    elif kind == "hkdf":
        var ikm = unhex(f[2])
        var salt = unhex(f[3])
        var info = unhex(f[4])
        var n = Int(f[5])
        var ok = f[7] == "valid"
        try:
            var prk = hkdf_extract[Sha256](salt, ikm) if alg == "256" else hkdf_extract[Sha384](salt, ikm)
            var okm = hkdf_expand[Sha256](prk, info, n) if alg == "256" else hkdf_expand[Sha384](prk, info, n)
            return ok and same(okm, unhex(f[6]))
        except:
            return not ok
    elif kind == "hkdfl":
        var sec = unhex(f[2])
        var lab = String(unsafe_from_utf8=unhex(f[3]))
        var ctx = unhex(f[4])
        var o = hkdf_expand_label[Sha256](sec, lab, ctx, Int(f[5])) if alg == "256" else hkdf_expand_label[Sha384](sec, lab, ctx, Int(f[5]))
        return same(o, unhex(f[6]))
    elif kind == "prf":
        var sec = unhex(f[2])
        var lab = String(unsafe_from_utf8=unhex(f[3]))
        var seed = unhex(f[4])
        var o = prf12[Sha256](sec, lab, seed, Int(f[5])) if alg == "256" else prf12[Sha384](sec, lab, seed, Int(f[5]))
        return same(o, unhex(f[6]))
    elif kind == "aead":
        var iv = unhex(f[3])
        var args = (unhex(f[4]), unhex(f[5]), unhex(f[6]), unhex(f[7]), f[8] == "valid")
        if alg == "gcm":
            return aead_case(AesGcm(unhex(f[2])), iv, args[0], args[1], args[2], args[3], args[4])
        if alg == "chacha":
            return aead_case(ChaCha20Poly1305(unhex(f[2])), iv, args[0], args[1], args[2], args[3], args[4])
        raise Error("unknown aead " + alg)
    elif kind == "chacha":
        var buf = unhex(f[4])
        chacha20_xor(_words[8](unhex(f[1])), _words[4](unhex(f[2])), UInt32(Int(f[3])), buf.unsafe_ptr(), len(buf))
        return same(buf, unhex(f[5]))
    elif kind == "poly":
        var t = poly1305_mac(unhex(f[1]), unhex(f[2]))
        var want = unhex(f[3])
        for i in range(16):
            if UInt8((t[i // 4] >> UInt32(8 * (i % 4))) & 0xFF) != want[i]:
                return False
        return True
    elif kind == "badargs":
        var ok = True
        for n in [0, 15, 17, 24, 31, 33]:  # key sizes outside the lane: AES-192 included
            try:
                _ = AesGcm(List[UInt8](length=n, fill=1))
                ok = False
            except:
                pass
        try:
            _ = ChaCha20Poly1305(List[UInt8](length=31, fill=1))
            ok = False
        except:
            pass
        return ok and bad_args(AesGcm(List[UInt8](length=16, fill=1))) and bad_args(ChaCha20Poly1305(List[UInt8](length=32, fill=1)))
    elif kind == "aesblk":
        var b = unhex(f[2])
        var v = V16(0)
        for i in range(16):
            v[i] = b[i]
        var o = Aes(unhex(f[1])).encrypt_block(v)
        var w = unhex(f[3])
        for i in range(16):
            if o[i] != w[i]:
                return False
        return True
    raise Error("unknown kind " + kind)


def main() raises:
    var passed = Dict[String, Int]()
    var failed = Dict[String, Int]()
    var first = Dict[String, String]()
    for a in range(1, len(argv())):
        var path = String(argv()[a])
        var lines = open(path, "r").read().split("\n")
        for ln in range(len(lines)):
            if lines[ln].byte_length() == 0:
                continue
            var f = List[String]()
            for p in lines[ln].split(" "):
                f.append(String(p))
            var ok = False
            var err = String()
            try:
                ok = check(f)
            except e:
                err = String(e)
            var k = f[0]
            if ok:
                passed[k] = passed.get(k, 0) + 1
            else:
                failed[k] = failed.get(k, 0) + 1
                if k not in first:
                    first[k] = path + ":" + String(ln + 1)
                if failed[k] <= 4:
                    print("  fail", path + ":" + String(ln + 1), "alg", f[1], "len", lines[ln].byte_length(), err)
    var bad = 0
    for e in passed.items():
        var nf = failed.get(e.key, 0)
        if nf == 0:
            print("PASS", e.key, e.value)
    for e in failed.items():
        bad += e.value
        print("FAIL", e.key, ":", e.value, "failed, first at", first[e.key])
    if bad > 0:
        exit(1)
