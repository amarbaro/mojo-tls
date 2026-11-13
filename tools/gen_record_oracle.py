#!/usr/bin/env python3
"""Record-layer oracle vectors from python `cryptography` (AES-GCM, ChaCha20-Poly1305), written to
tests/vectors/record_oracle.txt. Test data only; the gate that reads it is Mojo.
usage: python3 -I tools/gen_record_oracle.py > tests/vectors/record_oracle.txt
line: suite seq ctype pad key iv payload record   (hex, payload may be '-')"""
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

r = random.Random(8448)
sizes = [0, 1, 2, 15, 16, 17, 63, 64, 65, 255, 256, 1000, 4096, 16383, 16384]
for suite, klen in ((0x1301, 16), (0x1302, 32), (0x1303, 32)):
    for i, n in enumerate(sizes):
        key, iv = r.randbytes(klen), r.randbytes(12)
        seq = r.choice([0, 1, 2, 255, 256, 2**32 - 1, 2**32, 2**63, 2**64 - 2])
        ctype = r.choice([21, 22, 23])
        pad = r.choice([0, 0, 1, 7, 100])
        payload = r.randbytes(n)
        inner = payload + bytes([ctype]) + bytes(pad)
        hdr = bytes([23, 3, 3]) + (len(inner) + 16).to_bytes(2, "big")
        nonce = (int.from_bytes(iv, "big") ^ seq).to_bytes(12, "big")
        aead = ChaCha20Poly1305(key) if suite == 0x1303 else AESGCM(key)
        rec = hdr + aead.encrypt(nonce, inner, hdr)
        print(suite, seq, ctype, pad, key.hex(), iv.hex(), payload.hex() or "-", rec.hex())
