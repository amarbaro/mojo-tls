#!/usr/bin/env python3
"""Interop gate for lane 4: our sans-IO Server13/Client13 against real TLS stacks, joined by a byte relay.
Our side is a Mojo binary speaking over stdin/stdout (tests/interop_server.mojo, tests/interop_client.mojo); this script
relays those pipes to a TCP socket, so openssl s_client / s_server, curl and python ssl talk to our code unmodified.
Python and openssl are oracles here; nothing of ours is in Python.
usage: python3 -I tests/interop.py <server_bin> <client_bin>  (run from the repo root; prints PASS/FAIL lines)"""
import datetime, os, socket, ssl, subprocess, sys, threading, time

SRV, CLI = sys.argv[1], sys.argv[2]
D = ".work/interop"
os.makedirs(D, exist_ok=True)
PEM, DER, KEYPEM, KEYHEX = f"{D}/cert.pem", f"{D}/cert.der", f"{D}/key.pem", f"{D}/key.hex"
fails = 0


def make_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    open(PEM, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(DER, "wb").write(cert.public_bytes(serialization.Encoding.DER))
    open(KEYPEM, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(KEYHEX, "w").write(format(key.private_numbers().private_value, "064x"))


def check(name, ok, why=""):
    global fails
    print(("PASS interop: " if ok else "FAIL interop: ") + name + ("" if ok else f": {why}"), flush=True)
    fails += 0 if ok else 1


def relay(conn, proc):
    """socket <-> process stdin/stdout until either side closes."""
    def up():
        try:
            while True:
                b = conn.recv(65536)
                if not b:
                    break
                proc.stdin.write(b)
                proc.stdin.flush()
        except OSError:
            pass
        try:
            proc.stdin.close()
        except OSError:
            pass

    def down():
        try:
            while True:
                b = os.read(proc.stdout.fileno(), 65536)
                if not b:
                    break
                conn.sendall(b)
        except OSError:
            pass
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    ts = [threading.Thread(target=up, daemon=True), threading.Thread(target=down, daemon=True)]
    for t in ts:
        t.start()
    return ts


def listener():
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    ls.settimeout(20)
    return ls, ls.getsockname()[1]


def our_server(suite_hex, mode):
    ls, port = listener()

    def accept_and_serve():
        conn, _ = ls.accept()
        m = subprocess.Popen([SRV, DER, KEYHEX, suite_hex, mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ts = relay(conn, m)
        try:
            m.wait(timeout=20)
        except subprocess.TimeoutExpired:
            m.kill()
        for t in ts:
            t.join(2)
        res["mojo_err"] = m.stderr.read().decode()
        conn.close()

    res = {}
    th = threading.Thread(target=accept_and_serve, daemon=True)
    th.start()
    return port, th, res


def server_case(name, suite_hex, ossl_suite, groups, mode, want_group):
    port, th, res = our_server(suite_hex, mode)
    c = subprocess.Popen(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-ciphersuites", ossl_suite, "-groups", groups,
         "-servername", "localhost", "-CAfile", PEM, "-verify_return_error", "-verify_hostname", "localhost",
         "-alpn", "http/1.1", "-brief"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.0)  # let the handshake finish, then talk, then close: close_notify must not overtake the data
    try:
        c.stdin.write(b"hello\n")
        c.stdin.flush()
        time.sleep(0.7)
        c.stdin.close()
    except OSError:  # s_client already gave up (for example it rejected our certificate)
        pass
    c.stdout_data, c.stderr_data = c.stdout.read(), c.stderr.read()
    try:
        c.wait(timeout=20)
    except subprocess.TimeoutExpired:
        c.kill()
    th.join(25)
    err = c.stderr_data.decode()
    mo = res.get("mojo_err", "")
    ok = (c.returncode == 0 and "TLSv1.3" in err and ossl_suite in err and "Verification: OK" in err
          and b"echo: hello" in c.stdout_data and "alpn=http/1.1" in mo and "sni=localhost" in mo
          and f"group={want_group}" in mo and "close_notify received" in mo)
    check(f"our server <- openssl s_client: {name}", ok, f"rc={c.returncode} err={err[-300:]!r} out={c.stdout_data[-80:]!r} mojo={mo[-200:]!r}")


def curl_case():
    port, th, res = our_server("any", "plain")
    c = subprocess.run(["curl", "-sS", "--tlsv1.3", "--cacert", PEM, "--resolve", f"localhost:{port}:127.0.0.1", "-v",
                        f"https://localhost:{port}/", "-m", "20"], capture_output=True, timeout=30)
    th.join(25)
    out = c.stdout.decode(errors="replace")
    check("our server <- curl (TLS 1.3, certificate verified)", c.returncode == 0 and "echo: GET /" in out and "SSL connection using TLSv1.3" in c.stderr.decode(),
          f"rc={c.returncode} out={out[-200:]!r} err={c.stderr.decode()[-200:]!r}")


def pyssl_case():
    port, th, res = our_server("any", "hrr")
    ctx = ssl.create_default_context(cafile=PEM)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ecdh_curve("prime256v1")
    ctx.set_alpn_protocols(["http/1.1"])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=20) as s:
            with ctx.wrap_socket(s, server_hostname="localhost") as t:
                t.sendall(b"ping")
                got = t.recv(100)
                ver, cipher = t.version(), t.cipher()[0]
        th.join(25)
        check("our server <- python ssl (TLS 1.3, P-256)", got == b"echo: ping" and ver == "TLSv1.3" and "group=23" in res.get("mojo_err", ""), f"{got!r} {ver} {cipher} {res}")
    except Exception as e:
        check("our server <- python ssl (TLS 1.3, P-256)", False, repr(e))


def client_case(name, suite_hex, ossl_suite, groups, want_group):
    ls, port = listener()
    ls.close()
    ss = subprocess.Popen(["openssl", "s_server", "-accept", str(port), "-cert", PEM, "-key", KEYPEM, "-tls1_3", "-ciphersuites", ossl_suite,
                           "-groups", groups, "-www", "-alpn", "http/1.1"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(100):
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=5)
            break
        except OSError:
            time.sleep(0.1)
    m = subprocess.Popen([CLI, DER, suite_hex, "localhost"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ts = relay(conn, m)
    try:
        m.wait(timeout=20)
    except subprocess.TimeoutExpired:
        m.kill()
    for t in ts:
        t.join(2)
    ss.terminate()
    try:
        so, se = ss.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        ss.kill()
        so, se = ss.communicate()
    mo = m.stderr.read().decode()
    ok = (f"suite={int(suite_hex, 16)}" in mo and f"group={want_group}" in mo and "alpn=http/1.1" in mo
          and "HTTP/1.0 200 ok" in mo and f"Cipher is {ossl_suite}" in mo and "TLSv1.3" in mo)
    check(f"our client -> openssl s_server: {name}", ok, f"mojo={mo[-400:]!r} server={(so+se)[-200:]!r}")
    conn.close()


make_cert()
S128, S256, SCHA = ("1301", "TLS_AES_128_GCM_SHA256"), ("1302", "TLS_AES_256_GCM_SHA384"), ("1303", "TLS_CHACHA20_POLY1305_SHA256")
for s in (S128, S256, SCHA):
    server_case(f"{s[1]}, x25519", s[0], s[1], "X25519", "plain", 29)
    client_case(f"{s[1]}, x25519", s[0], s[1], "X25519", 29)
server_case("TLS_AES_128_GCM_SHA256, secp256r1 share", "1301", S128[1], "P-256", "plain", 23)
server_case("TLS_AES_128_GCM_SHA256, HelloRetryRequest x25519 -> secp256r1", "1301", S128[1], "X25519:P-256", "hrr", 23)
server_case("TLS_CHACHA20_POLY1305_SHA256, HelloRetryRequest", "1303", SCHA[1], "X25519:P-256", "hrr", 23)
client_case("TLS_AES_128_GCM_SHA256, HelloRetryRequest x25519 -> secp256r1", "1301", S128[1], "P-256", 23)
client_case("TLS_AES_256_GCM_SHA384, HelloRetryRequest", "1302", S256[1], "P-256", 23)
curl_case()
pyssl_case()
sys.exit(1 if fails else 0)
