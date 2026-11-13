#!/usr/bin/env python3
"""Extract the hex fields of RFC 8448 into tests/vectors/rfc8448.txt (test data only; the gates are Mojo).
usage: python3 -I tools/rfc8448_extract.py rfc8448.txt > tests/vectors/rfc8448.txt
line: <section> | <step title> | <field label> | <hex>"""
import re, sys

lines = open(sys.argv[1]).read().split("\n")
out, sec, step, i = [], 0, "", 0
field = re.compile(r"^      ([A-Za-z][^:(]*?)(?: \((\d+) octets?\))?:\s*(.*)$")
while i < len(lines):
    l = lines[i]
    m = re.match(r"^(\d+)\.  ", l)
    if m:
        sec = int(m.group(1))
    if re.match(r"^   \{(client|server)\}", l):
        step = l.strip().rstrip(":")
    f = field.match(l)
    if f and 3 <= sec <= 7:
        hexs = f.group(3)
        i += 1
        while i < len(lines):
            if re.match(r"^         [0-9a-f ]+$", lines[i]):
                hexs += " " + lines[i].strip()
            elif not (re.match(r"^\s*$", lines[i]) or lines[i].startswith(("Thomson", "RFC 8448", "\f"))):
                break
            i += 1
        h = hexs.replace(" ", "")
        if h and re.fullmatch(r"[0-9a-f]+", h):
            out.append(f"{sec} | {step} | {f.group(1).strip()} | {h}")
        continue
    i += 1
print("\n".join(out))
