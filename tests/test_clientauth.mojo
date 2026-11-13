# Gate: client certificate verification (tls13/clientauth.mojo + the clientAuth purpose of x509/chain.mojo) with real certificates
# from tests/matrix/gen_certs.sh (default dir .work/gate/certs, DER copies): sign with the key, verify with the chain.
from std.sys import argv
from tls.tls13.clientauth import verify_client, sign_with_key, key_schemes
from tls.tls13.ticket import unix_now
from chk import T


def rd(path: String) raises -> List[UInt8]:
    with open(path, "r") as f:
        return f.read_bytes()


def one(b: List[UInt8]) -> List[List[UInt8]]:
    var o = List[List[UInt8]]()
    o.append(b.copy())
    return o^


def why(chain: List[List[UInt8]], roots: List[List[UInt8]], now: Int, scheme: Int, signed: List[UInt8], sig: List[UInt8]) -> String:
    """"" when the client is accepted, else the alert name the refusal carries."""
    try:
        verify_client(chain, roots, now, scheme, signed, sig)
    except e:
        var parts = String(e).split(": ")
        return String(parts[1]) if len(parts) > 1 else String(e)
    return String()


def main() raises:
    var dir = String(".work/gate/certs")
    var a = argv()
    if len(a) > 1:
        dir = String(a[1])
    var t = T("clientauth")
    var ca = one(rd(dir + "/ca.der"))
    var now = unix_now()
    var msg = List[UInt8](String("the transcript the client signs").as_bytes())
    for name in ["cli-p256", "cli-rsa"]:
        var chain = one(rd(dir + "/" + name + ".crt.der"))
        var key = rd(dir + "/" + name + ".key.der")
        for s in key_schemes(key):
            var tag = name + " scheme " + String(s) + ": "
            var sig = sign_with_key(key, s, msg)
            t.ok(tag + "a valid client is accepted", why(chain, ca, now, s, msg, sig) == "")
            var flipped = sig.copy()
            flipped[len(flipped) - 1] ^= 1
            t.ok(tag + "a flipped signature is decrypt_error", why(chain, ca, now, s, msg, flipped) == "decrypt_error")
            var other = msg.copy()
            other[0] ^= 1
            t.ok(tag + "another transcript is decrypt_error", why(chain, ca, now, s, other, sig) == "decrypt_error")
            t.ok(tag + "an untrusted CA is bad_certificate", why(chain, one(rd(dir + "/evil-ca.der")), now, s, msg, sig) == "bad_certificate")
            t.ok(tag + "no roots is bad_certificate", why(chain, List[List[UInt8]](), now, s, msg, sig) == "bad_certificate")
            t.ok(tag + "an expired certificate is bad_certificate", why(chain, ca, now + 40 * 86400, s, msg, sig) == "bad_certificate")
            t.ok(tag + "a not yet valid certificate is bad_certificate", why(chain, ca, now - 86400 * 365, s, msg, sig) == "bad_certificate")
            t.ok(tag + "an empty chain is bad_certificate", why(List[List[UInt8]](), ca, now, s, msg, sig) == "bad_certificate")
        var wrong = 0x0804 if name == "cli-p256" else 0x0403
        t.ok(name + ": a scheme the key cannot use is illegal_parameter", why(chain, ca, now, wrong, msg, List[UInt8](length=64, fill=1)) == "illegal_parameter")
    var sa = one(rd(dir + "/cli-serverauth.crt.der"))
    var sk = rd(dir + "/cli-serverauth.key.der")
    t.ok("a serverAuth-only certificate is bad_certificate", why(sa, ca, now, 0x0403, msg, sign_with_key(sk, 0x0403, msg)) == "bad_certificate")
    var evil = one(rd(dir + "/cli-evil.crt.der"))
    var ek = rd(dir + "/cli-evil.key.der")
    t.ok("a certificate of another CA is bad_certificate", why(evil, ca, now, 0x0403, msg, sign_with_key(ek, 0x0403, msg)) == "bad_certificate")
    t.ok("the same certificate under its own CA is accepted", why(evil, one(rd(dir + "/evil-ca.der")), now, 0x0403, msg, sign_with_key(ek, 0x0403, msg)) == "")
    t.done()
