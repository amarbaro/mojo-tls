#!/usr/bin/env python3
"""Oracle helper: print "n e p q dp dq qinv" (hex, one line) of an RSA private key PEM, read through `openssl rsa -text`."""
import re, subprocess, sys

txt = subprocess.run(["openssl", "rsa", "-in", sys.argv[1], "-noout", "-text"], capture_output=True, text=True, check=True).stdout
parts = {}
cur = None
for line in txt.splitlines():
    m = re.match(r"^(modulus|privateExponent|prime1|prime2|exponent1|exponent2|coefficient):\s*$", line)
    if m:
        cur = m.group(1)
        parts[cur] = ""
    elif line.startswith("publicExponent:"):
        parts["e"] = "%x" % int(line.split()[1])
        cur = None
    elif cur and line.startswith(" "):
        parts[cur] += line.strip().replace(":", "")
    else:
        cur = None
e = parts["e"] if len(parts["e"]) % 2 == 0 else "0" + parts["e"]
print(parts["modulus"], e, parts["prime1"], parts["prime2"], parts["exponent1"], parts["exponent2"], parts["coefficient"])
