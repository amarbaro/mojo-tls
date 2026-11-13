"""browser_probe.py URL LEAF_SPKI_B64 MARKER: load URL in headless Vivaldi over CDP (stdlib only, no Playwright).
Exit 0 and print "<tls protocol> <cipher> <marker>" when the page text contains MARKER; exit 1 otherwise.
Chromium is limited to TLS 1.2 (--ssl-version-max=tls1.2) and trusts the server's leaf cert by SPKI pin only (the chain is not sent, so a CA pin cannot match).
`vivaldi --dump-dom` never exits on this machine, hence CDP."""
import base64, json, os, signal, socket, struct, subprocess, sys, tempfile, time, urllib.request

url, spki, marker = sys.argv[1:4]
prof = tempfile.mkdtemp(prefix="vprof-", dir=os.environ.get("PROBE_TMP"))
port = socket.socket(); port.bind(("127.0.0.1", 0)); dbg = port.getsockname()[1]; port.close()
proc = subprocess.Popen(
    ["vivaldi", "--headless=new", "--disable-vivaldi", "--disable-gpu", "--no-sandbox", f"--user-data-dir={prof}",
     f"--remote-debugging-port={dbg}", "--ssl-version-max=tls1.2", f"--ignore-certificate-errors-spki-list={spki}", "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def http(path, method="GET"):
    return json.load(urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{dbg}{path}", method=method), timeout=5))


class WS:
    def __init__(self, ws_url):
        host, path = ws_url[5:].split("/", 1)
        self.s = socket.create_connection((host.split(":")[0], int(host.split(":")[1])), 5)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(f"GET /{path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.s.recv(1)
        assert b" 101 " in buf.split(b"\r\n")[0]

    def send(self, obj):
        d = json.dumps(obj).encode(); m = os.urandom(4)
        n = len(d)
        hdr = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", n))
        self.s.sendall(hdr + m + bytes(b ^ m[i % 4] for i, b in enumerate(d)))

    def _n(self, n):
        b = b""
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c: raise EOFError
            b += c
        return b

    def recv(self):
        data = b""
        while True:
            b0, b1 = self._n(2); n = b1 & 0x7F
            if n == 126: n = struct.unpack(">H", self._n(2))[0]
            elif n == 127: n = struct.unpack(">Q", self._n(8))[0]
            data += self._n(n)
            if b0 & 0x80: return json.loads(data)


def run():
    for _ in range(100):
        try: http("/json/version"); break
        except Exception: time.sleep(0.2)
    tab = [t for t in http("/json") if t["type"] == "page"][0]
    ws = WS(tab["webSocketDebuggerUrl"]); seq = [0]; sec = {}
    def call(method, **params):
        seq[0] += 1; ws.send({"id": seq[0], "method": method, "params": params}); return seq[0]
    call("Network.enable"); call("Page.enable"); call("Page.navigate", url=url)
    deadline = time.time() + 30; ask = None; text = ""
    while time.time() < deadline:
        ws.s.settimeout(max(0.5, deadline - time.time()))
        try: m = ws.recv()
        except Exception: break
        if m.get("method") == "Network.responseReceived" and m["params"]["response"].get("securityDetails"):
            sec = m["params"]["response"]["securityDetails"]
        if m.get("method") == "Page.loadEventFired" or m.get("method") == "Page.frameStoppedLoading":
            ask = call("Runtime.evaluate", expression="document.body ? document.body.innerText : ''")
        if ask and m.get("id") == ask:
            text = m["result"]["result"].get("value", ""); break
    if marker in text and sec:
        print(sec.get("protocol"), sec.get("cipher"), marker); return 0
    print(f"marker missing; text={text[:80]!r} sec={sec}"); return 1


try: rc = run()
except Exception as e: print("probe error:", repr(e)); rc = 1
finally:
    os.killpg(proc.pid, signal.SIGKILL); proc.wait()
    subprocess.run(["rm", "-rf", prof])
sys.exit(rc)
