# Lane 3 gate binary. One resident process, modes picked by argv[1]: unit | bundle | fuzz | chain | keys | bench.
# Driven by tests/gate_x509.sh, which builds fixtures and oracles with openssl. Prints PASS/FAIL lines, exits 1 on any FAIL.
from std.sys import argv, exit
from std.time import perf_counter_ns
from tls.x509.der import Der, Bytes, view, copy_of, parse_time, same
from tls.x509.pem import b64_decode, pem_blocks, pem_spans
from tls.x509.cert import Certificate, KEY_RSA, KEY_P256, KEY_P384
from tls.x509.key import load_private_key, PrivateKey, _parse, wipe
from tls.sym import sha256, sha384
from tls.asym import P256Key, RsaPrivate, p384_sign
from tls.x509.chain import anchor_rules, verify_chain, load_roots_pem, load_system_roots, host_matches, parse_ip

comptime HEX = "0123456789abcdef"


def hexs(b: Bytes) -> String:
    var s = String()
    var h = HEX.as_bytes()
    for i in range(len(b)):
        s += chr(Int(h[Int(b[i]) >> 4]))
        s += chr(Int(h[Int(b[i]) & 15]))
    return s^


def unhex(s: String) -> List[UInt8]:
    var o = List[UInt8]()
    var b = s.as_bytes()
    var i = 0
    while i + 1 < len(b):
        o.append(UInt8((Int(b[i]) - (48 if b[i] < 58 else 87)) * 16 + Int(b[i + 1]) - (48 if b[i + 1] < 58 else 87)))
        i += 2
    return o^


def read_file(path: String) raises -> List[UInt8]:
    with open(path, "r") as f:
        return f.read_bytes()


struct Tally(Movable):
    var fails: Int
    var passes: Int

    def __init__(out self):
        self.fails = 0
        self.passes = 0

    def check(mut self, name: String, ok: Bool, why: String = ""):
        if ok:
            self.passes += 1
        else:
            self.fails += 1
            print("FAIL", name + ":", why)


# ---------------------------------------------------------------- unit
def tlv(tag: Int, body: List[UInt8]) -> List[UInt8]:
    var o = List[UInt8]()
    o.append(UInt8(tag))
    if len(body) < 128:
        o.append(UInt8(len(body)))
    elif len(body) < 256:
        o.append(0x81)
        o.append(UInt8(len(body)))
    else:
        o.append(0x82)
        o.append(UInt8(len(body) >> 8))
        o.append(UInt8(len(body) & 255))
    o.extend(body.copy())
    return o^


def cat(a: List[UInt8], b: List[UInt8]) -> List[UInt8]:
    var o = a.copy()
    o.extend(b.copy())
    return o^


def mini_cert(exts: List[List[UInt8]]) -> List[UInt8]:
    """Hand-built v3 certificate (EC P-256 key of zeros, empty names) with the given Extension TLVs."""
    var alg = tlv(0x30, unhex("06082a8648ce3d040302"))
    var tm = unhex("170d3330313233313030303030305a")
    var pt = List[UInt8]()
    pt.append(0)
    pt.append(4)
    for _ in range(64):
        pt.append(7)
    var spki = tlv(0x30, cat(tlv(0x30, unhex("06072a8648ce3d020106082a8648ce3d030107")), tlv(0x03, pt)))
    var body = tlv(0xA0, unhex("020102"))
    body = cat(body, unhex("020101"))
    body = cat(body, alg)
    body = cat(body, tlv(0x30, List[UInt8]()))
    body = cat(body, tlv(0x30, cat(unhex("170d3230303130313030303030305a"), unhex("170d3330313233313030303030305a"))))
    body = cat(body, tlv(0x30, List[UInt8]()))
    body = cat(body, spki)
    var xs = List[UInt8]()
    for ref e in exts:
        xs = cat(xs, e)
    body = cat(body, tlv(0xA3, tlv(0x30, xs)))
    var sig = List[UInt8]()
    sig.append(0)
    sig.append(1)
    return tlv(0x30, cat(cat(tlv(0x30, body), alg), tlv(0x03, sig)))


def ext(oid: String, crit: Bool, val: String) -> List[UInt8]:
    var b = unhex("06" + "03" + oid)
    if crit:
        b = cat(b, unhex("0101ff"))
    return tlv(0x30, cat(b, tlv(0x04, unhex(val))))


def parses(exts: List[List[UInt8]]) -> Bool:
    try:
        _ = Certificate.parse(mini_cert(exts))
        return True
    except:
        return False


def x509_unit(mut t: Tally):
    var none = List[List[UInt8]]()
    t.check("mini cert parses", parses(none), "rejected")
    var bc = ext("551d13", True, "3003010" + "1ff")
    var one = List[List[UInt8]]()
    one.append(bc.copy())
    t.check("one basicConstraints", parses(one), "rejected")
    var two = one.copy()
    two.append(bc.copy())
    t.check("duplicate extension", not parses(two), "accepted")
    var kind = List[List[UInt8]]()
    kind.append(ext("551d13", False, "3000"))
    kind.append(ext("551d0f", False, "03020080"))
    t.check("two different extensions", parses(kind), "rejected")
    var bad_eku = List[List[UInt8]]()
    bad_eku.append(ext("551d25", False, "3000"))
    t.check("empty eku", not parses(bad_eku), "accepted")
    var bad_ip = List[List[UInt8]]()
    bad_ip.append(ext("551d11", False, "3005870301020" + "3"))
    t.check("san ip of 3 bytes", not parses(bad_ip), "accepted")
    var bc_trail = List[List[UInt8]]()
    bc_trail.append(ext("551d13", False, "30050101ff0500"))
    t.check("junk inside basicConstraints", not parses(bc_trail), "accepted")
    try:
        var c = Certificate.parse(mini_cert(one))
        t.check("bc fields", c.has_bc and c.is_ca and c.path_len == -1, "wrong")
        t.check("validity", c.not_before == 1577836800 and c.not_after == 1924905600, String(c.not_before))
        var c2 = Certificate.parse(mini_cert(kind))
        t.check("key usage bit order", c2.has_ku and c2.ku == 1, String(c2.ku))
    except e:
        t.check("mini cert fields", False, String(e))


def _raises_der(hx: String, which: Int) -> Bool:
    """True when reading `hx` with reader `which` raises."""
    var l = unhex(hx)
    var d = Der(view(l))
    var bad = False
    try:
        if which == 0:
            _ = d.next()
            d.end()
        elif which == 1:
            _ = d.int_bytes()
        elif which == 2:
            _ = d.boolean()
        elif which == 3:
            _ = d.oid()
        elif which == 4:
            _ = d.bits()
        elif which == 5:
            _ = d.time()
        elif which == 6:
            _ = d.int_raw()
    except:
        bad = True
    _ = l[0]
    return bad


def _time(tag: Int, s: String) raises -> Int:
    var t = s
    var r = parse_time(tag, view(t.as_bytes()))
    _ = t.byte_length()
    return r


def _b64(s: String) raises -> String:
    var t = s
    var d = b64_decode(view(t.as_bytes()))
    var r = hexs(view(d))
    _ = len(d)
    _ = t.byte_length()
    return r


def _b64_bad(s: String) -> Bool:
    var t = s
    var bad = False
    try:
        _ = b64_decode(view(t.as_bytes()))
    except e:
        bad = True
        if "!" in String(e) or "9" in String(e):
            bad = False  # error text must not echo input bytes
    _ = t.byte_length()
    return bad


def unit(mut t: Tally) raises:
    # host_matches alone (the leaf rules already refuse these SANs): *.com is not a wildcard, a partial label is not either
    var wild = load_certs("ec_wild.pem", "tests/data/")[0].copy()
    t.check("host_matches *.com refused", not host_matches(wild, view("foo.com".as_bytes())), "matched")
    t.check("host_matches *.wild.example.com", host_matches(wild, view("x.wild.example.com".as_bytes())), "no match")
    # DER strictness: each malformed encoding must be rejected
    t.check("der non-minimal length 81 05", _raises_der("308105020100" + "0000", 0), "accepted")
    t.check("der long length 82 0001", _raises_der("30820001ff", 0), "accepted")
    t.check("der indefinite length", _raises_der("30800000", 0), "accepted")
    t.check("der truncated", _raises_der("300502", 0), "accepted")
    t.check("der length past end", _raises_der("3005020100", 0), "accepted")
    t.check("der high tag number", _raises_der("1f0100", 0), "accepted")
    t.check("der trailing data", _raises_der("020100ff", 0), "accepted")
    t.check("der int 0001", _raises_der("02020001", 1), "accepted")
    t.check("der int ff80", _raises_der("0202ff80", 6), "accepted")
    t.check("der int negative", _raises_der("020180", 1), "accepted")
    t.check("der int empty", _raises_der("0200", 1), "accepted")
    t.check("der bool 01", _raises_der("010101", 2), "accepted")
    t.check("der bool length 2", _raises_der("01020000", 2), "accepted")
    t.check("der oid 8001", _raises_der("06028001", 3), "accepted")
    t.check("der oid unterminated", _raises_der("060181", 3), "accepted")
    t.check("der oid empty", _raises_der("0600", 3), "accepted")
    t.check("der bits unused 8", _raises_der("03020800", 4), "accepted")
    t.check("der bits empty", _raises_der("0300", 4), "accepted")
    t.check("der bits unused without data", _raises_der("030105", 4), "accepted")
    t.check("der time month 13", _raises_der("170d3231333332303030303030" + "5a", 5), "accepted")
    t.check("der good bool ff", not _raises_der("0101ff", 2), "rejected")
    t.check("der good int 0080", not _raises_der("02020080", 1), "rejected")
    t.check("der good oid", not _raises_der("06032a0304", 3), "rejected")
    # times (RFC 5280 4.1.2.5): pivot at 50, leap days, strict digits
    t.check("time 2049-12-31", _time(0x17, "491231235959Z") == 2524607999, "pivot 49")
    t.check("time 1950-01-01", _time(0x17, "500101000000Z") == -631152000, "pivot 50")
    t.check("time gen 2050", _time(0x18, "20500101000000Z") == 2524608000, "generalized")
    t.check("time leap 2024-02-29", _time(0x17, "240229000000Z") == 1709164800, "leap")
    var bads = List[String]()
    bads.append("250230000000Z")  # 30 Feb
    bads.append("230229000000Z")  # 29 Feb in a common year
    bads.append("251301000000Z")
    bads.append("250101240000Z")
    bads.append("250101006000Z")
    bads.append("25010100000Z")  # short
    bads.append("2501010000000Z")  # long
    bads.append("250101000000+")  # no Z
    bads.append("25010a000000Z")
    for i in range(len(bads)):
        var bad = False
        try:
            _ = _time(0x17, bads[i])
        except:
            bad = True
        t.check("time reject " + bads[i], bad, "accepted")
    # base64 (RFC 4648 section 10) and error hygiene
    t.check("b64 empty", _b64("") == "", "")
    t.check("b64 f", _b64("Zg==") == "66", "")
    t.check("b64 fo", _b64("Zm8=") == "666f", "")
    t.check("b64 foo", _b64("Zm9v") == "666f6f", "")
    t.check("b64 foob", _b64("Zm9vYg==") == "666f6f62", "")
    t.check("b64 fooba", _b64("Zm9vYmE=") == "666f6f6261", "")
    t.check("b64 foobar ws", _b64("Zm9v\r\nYmFy\n") == "666f6f626172", "")
    t.check("b64 all chars", _b64("+/+/") == "fbffbf", "")
    t.check("b64 bad pad 1", _b64_bad("Zg="), "accepted")
    t.check("b64 bad pad 3", _b64_bad("Zg==="), "accepted")
    t.check("b64 bad len", _b64_bad("Z"), "accepted")
    t.check("b64 bad char", _b64_bad("Zm9!"), "accepted")
    t.check("b64 data after pad", _b64_bad("Zg==Zg=="), "accepted")
    t.check("b64 char below +", _b64_bad("Zm9*"), "accepted")
    t.check("b64 char above z", _b64_bad("Zm9{"), "accepted")
    t.check("b64 char colon", _b64_bad("Zm9:"), "accepted")
    # PEM
    var pem = String(
        "junk\n-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"
        "-----BEGIN A-----\nYmFy\n-----END B-----\n"
        "-----BEGIN PRIVATE KEY-----\nZg==\n-----END PRIVATE KEY-----\n"
    )
    var bl = pem_blocks(view(pem.as_bytes()))
    t.check("pem blocks", len(bl) == 2, "got " + String(len(bl)))
    t.check("pem label 0", bl[0].label == "CERTIFICATE" and hexs(view(bl[0].der)) == "666f6f", bl[0].label)
    t.check("pem label 1", bl[1].label == "PRIVATE KEY" and hexs(view(bl[1].der)) == "66", bl[1].label + " " + hexs(view(bl[1].der)))
    _ = pem.byte_length()
    x509_unit(t)
    # a certificate with trailing garbage must not parse
    var pf = read_file("tests/data/ec_root.pem")
    var cb = pem_blocks(view(pf))
    var good = cb[0].der.copy()
    var ext = good.copy()
    ext.append(0)
    var bad = False
    try:
        _ = Certificate.parse(ext^)
    except:
        bad = True
    t.check("cert trailing byte", bad, "accepted")
    var ok = True
    var why = String()
    try:
        _ = Certificate.parse(good^)
    except e:
        ok = False
        why = String(e)
    t.check("cert parses", ok, why)
    _ = pf[0]


# ---------------------------------------------------------------- bundle
def bundle(path: String, mut t: Tally) raises:
    """Print one line per cert: not_before not_after serial_hex key_hex (key_hex '-' for kinds we do not read)."""
    var raw = read_file(path)
    var spans = pem_spans(view(raw))
    var n = 0
    for ref sp in spans:
        var c = Certificate.parse(b64_decode(sp[1]))
        var kh = hexs(view(c.key_a)) if len(c.key_a) > 0 else String("-")
        var sr = c.serial()
        if len(sr) > 1 and sr[0] == 0 and sr[1] >= 0x80:
            sr = sr[1:]
        print(c.not_before, c.not_after, hexs(sr), kh)
        n += 1
    _ = raw[0]
    t.check("bundle parsed", n > 0, "no certs")


# ---------------------------------------------------------------- fuzz
struct Rng(Movable):
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed

    def next(mut self) -> Int:
        self.s ^= self.s << 13
        self.s ^= self.s >> 7
        self.s ^= self.s << 17
        return Int(self.s >> 1)


def mutate(src: List[UInt8], mut r: Rng) -> List[UInt8]:
    var o = src.copy()
    var k = r.next() % 4
    for _ in range(1 + r.next() % 3):
        var i = r.next() % len(o)
        if k == 0:
            o[i] = UInt8(r.next() & 255)
        elif k == 1:
            o[i] = o[i] ^ UInt8(1 << (r.next() % 8))
        elif k == 2 and len(o) > 8:
            o.resize(i + 1, 0)
        else:
            o[i] = UInt8(0xFF if r.next() % 2 == 0 else 0)
    return o^


def fuzz(path: String, rounds: Int, mut t: Tally) raises:
    var raw = read_file(path)
    var seeds = List[List[UInt8]]()
    for ref sp in pem_spans(view(raw)):
        seeds.append(b64_decode(sp[1]))
    var r = Rng(0x9E3779B97F4A7C15)
    var parsed = 0
    var rejected = 0
    for i in range(len(seeds)):
        for _ in range(rounds):
            var m = mutate(seeds[i], r)
            try:
                var c = Certificate.parse(m^)
                parsed += 1
                _ = c.subject()
            except:
                rejected += 1
    # random garbage and truncations of every prefix of one cert
    for i in range(1, len(seeds[0])):
        var pre = List[UInt8](capacity=i)
        for j in range(i):
            pre.append(seeds[0][j])
        try:
            _ = Certificate.parse(pre^)
            t.check("prefix parses", False, "prefix of length " + String(i) + " parsed")
        except:
            pass
    for _ in range(2000):
        var g = List[UInt8]()
        for _ in range(r.next() % 200):
            g.append(UInt8(r.next() & 255))
        try:
            _ = Certificate.parse(g^)
        except:
            pass
    print("fuzz: mutants", len(seeds) * rounds, "parsed", parsed, "rejected", rejected)
    t.check("fuzz survived", True)
    _ = raw[0]


# ---------------------------------------------------------------- chain
def load_certs(files: String, dir: String) raises -> List[Certificate]:
    var out = List[Certificate]()
    if files == "@system":
        return load_system_roots()
    for f in files.split(","):
        var raw = read_file(dir + String(f))
        for ref sp in pem_spans(view(raw)):
            out.append(Certificate.parse(b64_decode(sp[1])))
        _ = len(raw)
    return out^


def chain_mode(manifest: String, mut t: Tally) raises:
    """Lines: name expect now host roots chain. Verdict must equal `expect` (ok | fail)."""
    var text = String(unsafe_from_utf8=read_file(manifest))
    var n = 0
    var t0 = perf_counter_ns()
    for line in text.split("\n"):
        var f = line.split(" ")
        if len(f) < 6:
            continue
        var name = String(f[0])
        var host = String(f[3])
        if host == "-":
            host = String()
        var verdict = String("ok")
        var why = String()
        try:  # a certificate the parser refuses (resource caps) is a rejected chain
            var certs = load_certs(String(f[5]), "tests/data/")
            var roots = load_certs(String(f[4]), "tests/data/")
            verify_chain(certs, host, Int(atol(String(f[2]))), roots)
        except e:
            verdict = "fail"
            why = String(e)
        t.check(name, verdict == String(f[1]), "expected " + String(f[1]) + ", got " + verdict + " (" + why + ")")
        n += 1
    print("chain: ", n, "cases in", (perf_counter_ns() - t0) // 1000000, "ms")


# ---------------------------------------------------------------- keys
def write_file(path: String, b: List[UInt8]) raises:
    with open(path, "w") as f:
        f.write_bytes(b)


def der_int(b: List[UInt8]) -> List[UInt8]:
    var i = 0
    while i < len(b) - 1 and b[i] == 0:
        i += 1
    var o = List[UInt8]()
    if b[i] >= 0x80:
        o.append(0)
    for j in range(i, len(b)):
        o.append(b[j])
    return tlv(0x02, o)


def sign_with(k: PrivateKey, name: String, dir: String) raises:
    """Sign a fixed message the way a TLS server would (ECDSA-SHA256, ECDSA P-384 with SHA-384, or RSA PKCS#1 v1.5 SHA-256); openssl verifies the file."""
    var msg = String("mojo-tls lane 3 private key test")
    write_file(dir + "/msg.txt", List[UInt8](msg.as_bytes()))
    var h = sha256(List[UInt8](msg.as_bytes()))
    if k.kind == KEY_P256:
        write_file(dir + "/sig_" + name + ".der", P256Key(k.d).sign_sha256(h))
    elif k.kind == KEY_P384:
        write_file(dir + "/sig_" + name + ".der", p384_sign(k.d, sha384(List[UInt8](msg.as_bytes()))))
    else:
        var r = RsaPrivate(k.pub, k.e, k.p, k.q, k.dp, k.dq, k.qinv)
        write_file(dir + "/sig_" + name + ".bin", r.sign_pkcs1(256, h))


def drop_and_peek(path: String) raises -> Int:
    """Load an RSA key, return the address of its private exponent, let the key die."""
    var raw = read_file(path)
    var addr = 0
    var k = load_private_key(raw)
    addr = Int(k.d.unsafe_ptr())
    _ = len(raw)
    return addr


def zero_after_free(mut t: Tally) raises:
    """Freed key memory (bytes 32..239 of d, between the allocator's free-list link) is zero; a control list is not."""
    var addr = drop_and_peek("tests/data/key_rsa_pkcs8.pem")
    var p = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=addr)
    var nz = 0
    for i in range(32, 240):
        if p[unsafe_offset=i] != 0:
            nz += 1
    var c = List[UInt8](length=256, fill=0xAB)
    var ca = Int(c.unsafe_ptr())
    c = List[UInt8]()
    var cp = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=ca)
    var cnz = 0
    for i in range(32, 240):
        if cp[unsafe_offset=i] != 0:
            cnz += 1
    if cnz == 0:
        print("note keys: control buffer was recycled, zero-after-free check skipped")
        return
    t.check("key memory zero after drop", nz == 0, String(nz) + " of 208 bytes nonzero")


def flips(pem_path: String, fmt: Int, name: String, mut t: Tally) raises:
    """Every single-byte corruption of a key encoding must be refused (all fields are cross-checked)."""
    var raw = read_file(pem_path)
    var bl = pem_blocks(view(raw))
    var der = bl[0].der.copy()
    var accepted = 0
    for i in range(len(der)):
        var m = der.copy()
        m[i] = m[i] ^ 0x5A
        try:
            _ = _parse(fmt, view(m))
            accepted += 1
        except:
            pass
        _ = len(m)
    t.check(name + " flips", accepted == 0, String(accepted) + " of " + String(len(der)) + " corruptions accepted")
    print("keys:", name, len(der), "single-byte corruptions, all refused" if accepted == 0 else "SOME ACCEPTED")
    _ = len(raw)


def ec_scalars(mut t: Tally) raises:
    """SEC1 keys without public half: only scalars in [1, n-1] are keys."""
    var n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    var cases = List[Tuple[String, Bool]]()
    cases.append(("0000000000000000000000000000000000000000000000000000000000000000", False))
    cases.append((n, False))
    cases.append(("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552", False))
    cases.append(("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", False))
    cases.append(("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", True))
    cases.append(("0000000000000000000000000000000000000000000000000000000000000001", True))
    for ref c in cases:
        var der = tlv(0x30, cat(unhex("020101"), tlv(0x04, unhex(c[0]))))
        var ok = True
        try:
            _ = _parse(1, view(der))
        except:
            ok = False
        t.check("ec scalar " + String(c[0].as_bytes()[0]) + String(c[0].as_bytes()[63]), ok == c[1], "accepted" if ok else "refused")
        _ = len(der)


def keys_mode(manifest: String, outdir: String, mut t: Tally) raises:
    var text = String(unsafe_from_utf8=read_file(manifest))
    for line in text.split("\n"):
        var f = line.split(" ")
        if len(f) < 4:
            continue
        var name = String(f[0])
        var raw = read_file("tests/data/" + String(f[2]))
        var t0 = perf_counter_ns()
        try:
            var k = load_private_key(raw)
            var us = (perf_counter_ns() - t0) // 1000
            t.check(name, String(f[1]) == "ok", "loaded but expected a refusal")
            print("key", name, "kind", k.kind, "pub", hexs(view(k.pub)), "load_us", us)
            sign_with(k, name, outdir)
            for cn in ["cert_key_ec.pem", "cert_key_rsa.pem"]:
                var cf = read_file("tests/data/" + cn)
                var cb = pem_blocks(view(cf))
                var c = Certificate.parse(cb[0].der.copy())
                t.check(name + " vs " + cn, k.matches(c) == (String(f[3]) == cn), "match verdict wrong")
                _ = len(cf)
        except e:
            t.check(name, String(f[1]) == "fail", "refused: " + String(e))
            print("key", name, "refused:", String(e))
            t.check(name + " message", String(e).startswith("tls: key: "), String(e))
            if "_refused" in name:
                var m = String(e)
                t.check(name + " says unsupported", "unsupported" in m and ("encrypted" in m) == ("encrypted" in name), m)
        _ = len(raw)
    ec_scalars(t)
    flips("tests/data/key_rsa_pkcs1.pem", 2, "rsa_pkcs1", t)
    flips("tests/data/key_ec_sec1.pem", 1, "ec_sec1", t)
    flips("tests/data/key_ec_pkcs8.pem", 8, "ec_pkcs8", t)
    zero_after_free(t)


def fuzz_chain(leaf: String, inter: String, root: String, host: String, rounds: Int, mut t: Tally) raises:
    """Mutated leaf or intermediate DER must never verify (every byte is covered by a signature or a length) nor crash."""
    var base = load_certs(leaf + "," + inter, "tests/data/")
    var roots = load_certs(root, "tests/data/")
    var now = base[0].not_before + 86400
    var r = Rng(0xD1B54A32D192ED03)
    var accepted = 0
    var parsed = 0
    for i in range(rounds):
        var which = i % 2
        var m = mutate(base[which].raw, r)
        if same(m, base[which].raw):
            continue  # the mutation wrote the byte it already had
        try:
            var c = Certificate.parse(m^)
            parsed += 1
            var chain = List[Certificate]()
            if which == 0:
                chain.append(c^)
                chain.append(base[1].copy())
            else:
                chain.append(base[0].copy())
                chain.append(c^)
            verify_chain(chain, host, now, roots)
            accepted += 1
        except:
            pass
    print("fuzz chain:", leaf, rounds, "mutants,", parsed, "parsed,", accepted, "accepted")
    t.check("fuzz chain " + leaf + " never accepted", accepted == 0, String(accepted) + " mutants verified")


def sort(mut l: List[Int]):
    for i in range(1, len(l)):
        var j = i
        while j > 0 and l[j - 1] > l[j]:
            var x = l[j]
            l[j] = l[j - 1]
            l[j - 1] = x
            j -= 1


def bench(mut t: Tally) raises:
    """Resident-process timings (microseconds per operation, median of 5 batches)."""
    var raw = read_file("/etc/ssl/certs/ca-certificates.crt")
    var ders = List[List[UInt8]]()
    for ref sp in pem_spans(view(raw)):
        ders.append(b64_decode(sp[1]))
    var lap = List[Int]()
    for _ in range(5):
        var t0 = perf_counter_ns()
        for _ in range(20):
            for ref d in ders:
                _ = Certificate.parse(d.copy())
        lap.append(Int((perf_counter_ns() - t0) // (20 * len(ders))))
    sort(lap)
    print("bench parse_cert_ns", lap[2], "(", len(ders), "system roots, copy of the DER included )")
    var roots = load_system_roots()
    var specs = List[String]()
    specs.append("ec_leaf.pem,ec_inter.pem|ec_root.pem|a.example.com|ec_chain_p256")
    specs.append("rsa_leaf.pem,rsa_inter.pem|rsa_root.pem|rsa.example.com|rsa2048_chain")
    specs.append("rsa_leaf_pss32.pem,rsa_inter.pem|rsa_root.pem|pss32.example.com|rsa_pss_leaf_on_rsa_chain")
    specs.append("ec384_leaf.pem,ec384_inter.pem|ec384_root.pem|p384.example.com|ec_chain_p384")
    for ref sp in specs:
        var f = sp.split("|")
        var chain = load_certs(String(f[0]), "tests/data/")
        var rt = load_certs(String(f[1]), "tests/data/")
        var now = chain[0].not_before + 86400
        var laps = List[Int]()
        for _ in range(5):
            var t0 = perf_counter_ns()
            for _ in range(20):
                verify_chain(chain, String(f[2]), now, rt)
            laps.append(Int((perf_counter_ns() - t0) // 20000))
        sort(laps)
        print("bench verify_chain_us", laps[2], String(f[3]), "(2 signatures)")
    var real = load_certs("live_github.com.pem", "tests/data/")
    var tl = List[Int]()
    for _ in range(5):
        var t0 = perf_counter_ns()
        for _ in range(20):
            verify_chain(real, "github.com", 1794455136, roots)
        tl.append(Int((perf_counter_ns() - t0) // 20000))
    sort(tl)
    print("bench verify_chain_us", tl[2], "live github.com against", len(roots), "system roots")
    for nm in ["key_ec_pkcs8.pem", "key_rsa_pkcs8.pem", "key_rsa3072_pkcs8.pem"]:
        var kr = read_file("tests/data/" + nm)
        var kl = List[Int]()
        for _ in range(5):
            var t0 = perf_counter_ns()
            for _ in range(5):
                _ = load_private_key(kr)
            kl.append(Int((perf_counter_ns() - t0) // 5000))
        sort(kl)
        print("bench load_private_key_us", kl[2], nm)
        _ = len(kr)
    _ = len(raw)
    t.check("bench ran", True)


def dec(s: String) raises -> Certificate:
    return Certificate.parse(b64_decode(s.as_bytes()))


def limbo_mode(path: String, mut t: Tally) raises:
    """Informational x509-limbo run (see tools/limbo_convert.py): prints `DIFF id expected got why` per disagreement."""
    var text = String(unsafe_from_utf8=read_file(path))
    var agree = 0
    var diff = 0
    var ok_rejected = 0
    var fail_accepted = 0
    for line in text.split("\n"):
        var f = line.split(" ")
        if len(f) < 6:
            continue
        var roots = List[Certificate]()
        for c in String(f[4]).split(","):
            try:
                roots.append(dec(String(c)))
            except:
                pass
        var chain = List[Certificate]()
        var parts = String(f[5]).split(",")
        var verdict = String("fail")
        var why = String("peer certificate did not parse")
        var peer = True
        try:
            chain.append(dec(String(parts[0])))
        except:
            peer = False
        for i in range(1, len(parts)):
            try:
                chain.append(dec(String(parts[i])))
            except:
                pass
        var host = String(f[3])
        if host == "-":
            host = String()
        if peer:
            try:
                verify_chain(chain, host, Int(atol(String(f[2]))), roots)
                verdict = "ok"
                why = String()
            except e:
                why = String(e)
        if verdict == String(f[1]):
            agree += 1
        else:
            diff += 1
            if String(f[1]) == "ok":
                ok_rejected += 1
            else:
                fail_accepted += 1
            print("DIFF", String(f[0]), "expected", String(f[1]), "got", verdict, "(" + why + ")")
    print("limbo:", agree + diff, "cases,", agree, "agree,", ok_rejected, "valid chains rejected,", fail_accepted, "invalid chains accepted")
    t.check("limbo ran", True)


def roots_mode(path: String, mut t: Tally) raises:
    """Every certificate of the bundle must pass the trust-anchor profile; prints the ones that do not."""
    var dropped = 0
    var raw = read_file(path)
    var roots = load_roots_pem(view(raw), dropped)
    var bad = 0
    for ref r in roots:
        try:
            anchor_rules(r, 0)
        except e:
            bad += 1
            var cn = String()
            var sj = r.subject()
            for i in range(len(sj)):
                if sj[i] >= 32 and sj[i] < 127:
                    cn += chr(Int(sj[i]))
            print("ROOT", String(e), "|", cn)
    print("roots:", len(roots), "parsed,", dropped, "dropped,", bad, "fail the anchor profile")
    t.check("roots audited", dropped == 0)
    _ = len(raw)


def main() raises:
    var a = argv()
    var mode = String(a[1])
    var t = Tally()
    if mode == "unit":
        unit(t)
    elif mode == "fuzzchain":
        fuzz_chain("ec_leaf.pem", "ec_inter.pem", "ec_root.pem", "a.example.com", Int(atol(String(a[2]))), t)
        fuzz_chain("rsa_leaf.pem", "rsa_inter.pem", "rsa_root.pem", "rsa.example.com", Int(atol(String(a[2]))), t)
    elif mode == "limbo":
        limbo_mode(String(a[2]), t)
    elif mode == "roots":
        roots_mode(String(a[2]), t)
    elif mode == "bench":
        bench(t)
    elif mode == "bundle":
        bundle(String(a[2]), t)
    elif mode == "fuzz":
        fuzz(String(a[2]), Int(atol(String(a[3]))), t)
    elif mode == "keys":
        keys_mode(String(a[2]), String(a[3]), t)
    elif mode == "chain":
        chain_mode(String(a[2]), t)
    else:
        print("FAIL mode: unknown mode", mode)
        exit(2)
    if mode != "bundle":
        print("PASS" if t.fails == 0 else "FAIL", mode, ":", t.passes, "checks passed,", t.fails, "failed")
    if t.fails > 0:
        exit(1)
