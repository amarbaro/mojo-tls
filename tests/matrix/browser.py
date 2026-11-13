"""browser.py URL: load URL in headless Chromium (the Playwright build). The test CA is trusted only through a throwaway NSS db
under HOME (set by matrix.sh). Prints one JSON line {protocol, cipher, version, text} or {error}; exit 1 on error.
Never --ignore-certificate-errors: a CA that is not trusted must fail the load. Vivaldi has vivaldi_probe.py."""
import json, sys
from playwright.sync_api import sync_playwright

try:
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, args=["--no-first-run", "--disable-gpu"])
        resp = b.new_context().new_page().goto(sys.argv[1], timeout=25000)
        sd = resp.security_details() or {}
        page = resp.frame.page
        out = {"protocol": sd.get("protocol"), "cipher": sd.get("cipher"), "version": b.version, "text": page.inner_text("body")}
        b.close()
    print(json.dumps(out))
except Exception as e:  # noqa: BLE001
    print(json.dumps({"error": str(e).splitlines()[0][:300]}))
    sys.exit(1)
