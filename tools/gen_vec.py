#!/usr/bin/env python3
"""Vector generator for the sym gate (an oracle, not a twin of the Mojo code).

  gen_vec.py wycheproof OUTDIR  Wycheproof JSON (.work/wyche, see fetch_wycheproof.sh) -> OUTDIR/wyche-{mac,aead}.txt
  gen_vec.py random OUTDIR      seeded random cases; openssl (dgst, mac, kdf, enc) and python `cryptography` answer

Line format: `kind field...`, fields hex, `-` = empty, `valid`/`invalid` last where it applies.
  hash H msg digest | hmac H key msg tag valid | hkdf H ikm salt info size okm valid
  hkdfl H secret label ctx n okm | prf H secret label seed n out
  aesblk key pt ct | aead A key iv aad msg ct tag valid | chacha key nonce ctr pt ct | poly key msg tag
"""
import json, os, random, subprocess, sys, tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

H = lambda b: b.hex() if b else "-"
SIZE = {"256": 32, "384": 48, "512": 64}


def wycheproof(src, out):
    mac, aead = [], []
    for alg in SIZE:
        d = json.load(open(f"{src}/hmac_sha{alg}_test.json"))
        for g in d["testGroups"]:
            for t in g["tests"]:
                mac.append(f"hmac {alg} {H(bytes.fromhex(t['key']))} {H(bytes.fromhex(t['msg']))} {H(bytes.fromhex(t['tag']))} {t['result']}")
    for alg in ("256", "384"):
        d = json.load(open(f"{src}/hkdf_sha{alg}_test.json"))
        for g in d["testGroups"]:
            for t in g["tests"]:
                f = lambda k: H(bytes.fromhex(t[k]))
                mac.append(f"hkdf {alg} {f('ikm')} {f('salt')} {f('info')} {t['size']} {f('okm')} {t['result']}")
    for name, tag in (("aes_gcm", "gcm"), ("chacha20_poly1305", "chacha")):
        d = json.load(open(f"{src}/{name}_test.json"))
        for g in d["testGroups"]:
            if g["ivSize"] != 96 or g["tagSize"] != 128 or g["keySize"] not in (128, 256):
                continue  # out of lane scope: 96-bit nonce, 128-bit tag, AES-128/256 only
            for t in g["tests"]:
                f = lambda k: H(bytes.fromhex(t[k]))
                res = "valid" if t["result"] in ("valid", "acceptable") else "invalid"
                aead.append(f"aead {tag} {f('key')} {f('iv')} {f('aad')} {f('msg')} {f('ct')} {f('tag')} {res}")
    os.makedirs(out, exist_ok=True)
    open(f"{out}/wyche-mac.txt", "w").write("\n".join(mac) + "\n")
    open(f"{out}/wyche-aead.txt", "w").write("\n".join(aead) + "\n")
    print(f"wycheproof: {len(mac)} mac/kdf rows, {len(aead)} aead rows")


def ossl(*args, inp=None):
    return subprocess.run(["openssl", *args], input=inp, capture_output=True, check=True).stdout


def digest(alg, msg):
    return ossl("dgst", f"-sha{alg}", "-binary", inp=msg)


def hmac_ossl(alg, key, msg):
    return ossl("dgst", f"-sha{alg}", "-binary", "-mac", "HMAC", "-macopt", f"hexkey:{key.hex()}", inp=msg)


def rnd_len(r, big=False):
    c = r.random()
    if c < 0.5: return r.randint(0, 80)
    if c < 0.8: return r.randint(0, 300)
    return r.randint(1000, 20000) if big else r.randint(0, 600)


def random_cases(out, seed=20261112):
    r = random.Random(seed)
    B = lambda n: r.randbytes(n)
    rows = {"mac": [], "aes": [], "chacha": []}
    for alg in SIZE:
        for n in list(range(0, 140)) + [r.randint(140, 5000) for _ in range(20)] + [1000000]:
            m = B(n)
            rows["mac"].append(f"hash {alg} {H(m)} {H(digest(alg, m))}")
        for _ in range(60):
            k, m = B(r.choice([1, 16, 32, 63, 64, 65, 127, 128, 129, 200])), B(rnd_len(r))
            rows["mac"].append(f"hmac {alg} {H(k)} {H(m)} {H(hmac_ossl(alg, k, m))} valid")
    for alg in ("256", "384"):
        for _ in range(40):
            sec, lab, seed_ = B(r.randint(1, 48)), r.choice([b"master secret", b"key expansion", b"client finished", b"extended master secret"]), B(r.randint(0, 100))
            n = r.choice([12, 16, 32, 48, 72, 104, 128, 200])
            o = ossl("kdf", "-binary", "-keylen", str(n), "-kdfopt", f"digest:SHA{alg}", "-kdfopt", f"hexsecret:{sec.hex()}", "-kdfopt", f"hexseed:{(lab + seed_).hex()}", "TLS1-PRF")
            rows["mac"].append(f"prf {alg} {H(sec)} {H(lab)} {H(seed_)} {n} {H(o)}")
        for _ in range(40):
            ikm, salt, info = B(r.randint(1, 64)), B(r.choice([0, 0, 13, 32, 64])), B(r.choice([0, 7, 50]))
            n = r.choice([1, 16, 32, 42, 48, 49, 100, 255 * SIZE[alg]])
            o = ossl("kdf", "-binary", "-keylen", str(n), "-kdfopt", f"digest:SHA{alg}", "-kdfopt", f"hexkey:{ikm.hex()}", "-kdfopt", f"hexsalt:{salt.hex()}", "-kdfopt", f"hexinfo:{info.hex()}", "HKDF")
            rows["mac"].append(f"hkdf {alg} {H(ikm)} {H(salt)} {H(info)} {n} {H(o)} valid")
    # HKDF-Expand-Label (RFC 8446 7.1) by the definition, with python's hmac as the oracle
    import hmac as pyhmac, hashlib
    for alg in ("256", "384"):
        for _ in range(40):
            sec, lab, ctx, n = B(SIZE[alg]), r.choice([b"key", b"iv", b"finished", b"derived", b"c hs traffic", b"traffic upd"]), B(r.choice([0, 32, 48])), r.choice([12, 16, 32, 48])
            info = n.to_bytes(2, "big") + bytes([6 + len(lab)]) + b"tls13 " + lab + bytes([len(ctx)]) + ctx
            t, o, i = b"", b"", 1
            while len(o) < n:
                t = pyhmac.new(sec, t + info + bytes([i]), getattr(hashlib, f"sha{alg}")).digest(); o += t; i += 1
            rows["mac"].append(f"hkdfl {alg} {H(sec)} {H(lab)} {H(ctx)} {n} {H(o[:n])}")
    for kl in (16, 32):
        for _ in range(60):
            k, p = B(kl), B(16)
            o = ossl("enc", f"-aes-{kl * 8}-ecb", "-K", k.hex(), "-nopad", inp=p)
            rows["aes"].append(f"aesblk {H(k)} {H(p)} {H(o)}")
        for _ in range(250):
            k, iv, a, m = B(kl), B(12), B(rnd_len(r)), B(rnd_len(r, True))
            ctt = AESGCM(k).encrypt(iv, m, a or None)
            rows["aes"].append(f"aead gcm {H(k)} {H(iv)} {H(a)} {H(m)} {H(ctt[:-16])} {H(ctt[-16:])} valid")
    for _ in range(300):
        k, iv, a, m = B(32), B(12), B(rnd_len(r)), B(rnd_len(r, True))
        ctt = ChaCha20Poly1305(k).encrypt(iv, m, a or None)
        rows["chacha"].append(f"aead chacha {H(k)} {H(iv)} {H(a)} {H(m)} {H(ctt[:-16])} {H(ctt[-16:])} valid")
    for _ in range(100):
        k, nonce, ctr = B(32), B(12), r.choice([0, 1, 7, 0xFFFFFFF0, r.getrandbits(32)])
        m = B(r.randint(0, 1024) if ctr > 0xFFFF0000 else rnd_len(r, True))  # openssl carries a counter wrap into the nonce word, RFC 8439 does not say: stay below 2^32 blocks
        o = ossl("enc", "-chacha20", "-K", k.hex(), "-iv", (ctr.to_bytes(4, "little") + nonce).hex(), inp=m)
        rows["chacha"].append(f"chacha {H(k)} {H(nonce)} {ctr} {H(m)} {H(o)}")
    for _ in range(300):
        k, m = B(32), B(rnd_len(r))
        o = ossl("mac", "-macopt", f"hexkey:{k.hex()}", "-binary", "POLY1305", inp=m)
        rows["chacha"].append(f"poly {H(k)} {H(m)} {H(o)}")
    # Poly1305 edge cases: h close to 2^130 - 5, so the final conditional subtraction runs (RFC 8439 A.3 style)
    ff = b"\xff" * 16
    for rr in (1, 2, 5, 0xFC):
        for ss in (bytes(16), ff):
            for m in (ff, ff * 2, ff * 3, b"\xfd" + ff[1:], b"\x02" + bytes(15), ff + b"\xf0" + ff[1:] + b"\x11" + bytes(15),
                      ff + b"\xfb" + b"\xfe" * 15 + b"\x01" * 16, bytes([0xfb]) + b"\xfe" * 15, ff[:15], ff[:1]):
                k = bytes([rr]) + bytes(15) + ss
                o = ossl("mac", "-macopt", f"hexkey:{(k + bytes(32))[:32].hex()}", "-binary", "POLY1305", inp=m)
                rows["chacha"].append(f"poly {H((k + bytes(32))[:32])} {H(m)} {H(o)}")
    os.makedirs(out, exist_ok=True)
    for k, v in rows.items():
        open(f"{out}/random-{k}.txt", "w").write("\n".join(v) + "\n")
    print({k: len(v) for k, v in rows.items()})


if __name__ == "__main__":
    {"wycheproof": lambda: wycheproof(".work/wyche", sys.argv[2]), "random": lambda: random_cases(sys.argv[2])}[sys.argv[1]]()
