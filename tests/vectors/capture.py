"""capture.py PORT OUT.hex: accept one TCP connection, store the first TLS record (a ClientHello) as hex, close.
Oracle for tests/vectors/*.hex: real client hellos from openssl, curl, python ssl and Vivaldi (Chromium)."""
import socket, struct, sys

port, out = int(sys.argv[1]), sys.argv[2]
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port)); ls.listen(1); ls.settimeout(30)
c, _ = ls.accept(); c.settimeout(10)
b = b""
while len(b) < 5 or len(b) < 5 + struct.unpack(">H", b[3:5])[0]:
    d = c.recv(65536)
    if not d: break
    b += d
open(out, "w").write(b[: 5 + struct.unpack(">H", b[3:5])[0]].hex() + "\n")
c.close()
