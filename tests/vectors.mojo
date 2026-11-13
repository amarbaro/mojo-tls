# Runs a flat case file made by tools/wyc2cases.py (Wycheproof) against tls.asym. usage: vectors <cases.txt> [kind ...]
# Prints "PASS <kind> n/n" or "FAIL <kind> tc<id>: <reason>" per failed case; exits non-zero on any failure.
from std.sys import argv
from tls.asym import *
from tls.asym.ec import unhex, ecdh, p256, p384, valid_pub, from_be


def strip0(b: List[UInt8]) -> List[UInt8]:
    var i = 0
    while i < len(b) - 1 and b[i] == 0:
        i += 1
    return List[UInt8](Span(b)[i:])


def hexs(b: Span[UInt8, _]) -> String:
    var s = String()
    comptime d = "0123456789abcdef"
    for x in b:
        s += String(d[byte=Int(x >> 4)]) + String(d[byte=Int(x & 15)])
    return s^


def run_case(kind: String, f: List[String]) -> String:
    """Returns "" when the case passes, else the reason. f = result, then the hex fields."""
    var res = f[0]
    var ok = False
    var raised = False
    if kind == "x25519" or kind == "x448":
        var got = List[UInt8]()
        try:
            got = x25519(unhex(f[1]), unhex(f[2])) if kind == "x25519" else x448(unhex(f[1]), unhex(f[2]))
        except:
            raised = True
        # a raise is the TLS-level answer for a low-order input (all-zero secret); only "acceptable" may do that
        ok = (not raised and hexs(got) == f[3]) or (raised and res == "invalid") or (raised and res != "valid" and f[3] == "00" * (32 if kind == "x25519" else 56))
    elif kind == "ecdh" or kind == "ecdh384":
        var got = List[UInt8]()
        try:
            got = ecdh(from_be[4](unhex(f[1])), unhex(f[2]), p256()) if kind == "ecdh" else ecdh(from_be[6](unhex(f[1])), unhex(f[2]), p384())
        except:
            raised = True
        ok = (res == "invalid" and raised) or (res != "invalid" and not raised and hexs(got) == f[3]) or (res == "acceptable" and raised)
    elif kind == "ecdsa":
        var pub = unhex(f[2])
        var good = p256_verify(pub, unhex(f[3]), unhex(f[4])) if f[1] == "256" else p384_verify(pub, unhex(f[3]), unhex(f[4]))
        ok = good if res == "valid" else (res == "acceptable" or not good)
    elif kind == "rsa_pkcs1" or kind == "rsa_pss":
        var good: Bool
        try:
            var pk = RsaPublic(strip0(unhex(f[2])), strip0(unhex(f[3])))
            if kind == "rsa_pkcs1":
                good = pk.verify_pkcs1(Int(f[1]), unhex(f[4]), unhex(f[5]))
            else:
                good = pk.verify_pss(Int(f[1]), unhex(f[4]), unhex(f[5]))
        except:
            good = False
        ok = good if res == "valid" else (res == "acceptable" or not good)
    return "" if ok else "result " + res + ", got " + ("raise" if raised else "other")


def main() raises:
    var args = argv()
    var want = List[String]()
    for i in range(2, len(args)):
        want.append(String(args[i]))
    var kinds = List[String]()
    var total = List[Int]()
    var bad = List[Int]()
    for line in open(String(args[1]), "r").read().split("\n"):
        if line.byte_length() == 0:
            continue
        var f = List[String]()
        for p in line.split("|"):
            f.append(String(p))
        var kind = f[0]
        if len(want) > 0 and kind not in want:
            continue
        var ki = -1
        for j in range(len(kinds)):
            if kinds[j] == kind:
                ki = j
        if ki < 0:
            kinds.append(kind)
            total.append(0)
            bad.append(0)
            ki = len(kinds) - 1
        total[ki] += 1
        var why = run_case(kind, List[String](f[2:]))
        if why.byte_length() > 0:
            bad[ki] += 1
            print("FAIL " + kind + " tc" + f[1] + ": " + why)
    var failed = False
    for j in range(len(kinds)):
        if bad[j] == 0:
            print("PASS " + kinds[j] + " " + String(total[j]) + "/" + String(total[j]))
        else:
            failed = True
            print("FAIL " + kinds[j] + " " + String(total[j] - bad[j]) + "/" + String(total[j]))
    if failed:
        raise Error("vectors: failures")
