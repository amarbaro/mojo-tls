"""vivaldi_probe.py URL CDP_PORT USER_DATA_DIR: load URL in headless Vivaldi over CDP (stdlib only: Playwright's connect hangs on Vivaldi,
and `vivaldi --dump-dom` never exits here). The test CA is trusted through the NSS db under HOME (set by matrix.sh), never by a
flag. Prints one JSON line {protocol, cipher, version, text} or {error}; exit 1 on error. CDP framing after tests/interop/browser_probe.py."""
import base64, json, os, signal, socket, struct, subprocess, sys, time, urllib.request

url, dbg, prof = sys.argv[1], int(sys.argv[2]), sys.argv[3]
proc = subprocess.Popen(
    ["/usr/bin/vivaldi-stable", "--headless=new", "--disable-vivaldi", "--disable-gpu", "--no-sandbox", f"--user-data-dir={prof}",
     f"--remote-debugging-port={dbg}", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def http(path):
    return json.load(urllib.request.urlopen(f"http://127.0.0.1:{dbg}{path}", timeout=5))


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
    ver = {}
    for _ in range(100):
        try: ver = http("/json/version"); break
        except Exception: time.sleep(0.2)
    tab = [t for t in http("/json") if t["type"] == "page"][0]
    ws = WS(tab["webSocketDebuggerUrl"]); seq = [0]; sec = {}; err = ""
    def call(method, **params):
        seq[0] += 1; ws.send({"id": seq[0], "method": method, "params": params}); return seq[0]
    call("Network.enable"); call("Page.enable"); call("Page.navigate", url=url)
    deadline = time.time() + 40; ask = None; text = None
    while time.time() < deadline:
        ws.s.settimeout(max(0.5, deadline - time.time()))
        try: m = ws.recv()
        except Exception: break
        if m.get("method") == "Network.responseReceived" and m["params"]["response"].get("securityDetails"):
            sec = m["params"]["response"]["securityDetails"]
        if m.get("method") == "Network.loadingFailed": err = m["params"].get("errorText", "load failed")
        if m.get("method") in ("Page.loadEventFired", "Page.frameStoppedLoading") and not ask:
            ask = call("Runtime.evaluate", expression="document.body ? document.body.innerText : ''")
        if ask and m.get("id") == ask:
            text = m["result"]["result"].get("value", ""); break
    if text is None or not sec:
        return {"error": f"no page: {err or 'timeout'} text={text!r}"}
    return {"protocol": sec.get("protocol"), "cipher": sec.get("cipher"), "version": ver.get("Browser", ""), "text": text}


rc = 0
try:
    r = run(); print(json.dumps(r)); rc = 1 if "error" in r else 0
except Exception as e:
    print(json.dumps({"error": repr(e)[:300]})); rc = 1
finally:
    os.killpg(proc.pid, signal.SIGKILL); proc.wait()
sys.exit(rc)
