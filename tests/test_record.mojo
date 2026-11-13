# Gate: record layer. RFC 8448 section 3 records byte for byte (AES-128-GCM), python-cryptography oracle vectors
# for all three suites (padding, sequence numbers up to 2^64-2, sizes 0..2^14), tamper/limit/fuzz negatives.
from tls.tls13.record import Cipher, RecordReader, seal_all, HS, ALERT, APP
from tls.tls13.wire import alert_of
from chk import Vec, T, hexd, u64


def rfc(mut t: T, v: Vec) raises:
    var sec = 3
    var skey = v.get(sec, "derive write traffic keys for handshake", "key expanded")
    var siv = v.get(sec, "derive write traffic keys for handshake", "iv expanded")
    var rec = v.get(sec, "{server}  send handshake record", "complete record", 1)
    var payload = v.get(sec, "{server}  send handshake record", "payload", 1)
    var c = Cipher()
    c.set(0x1301, skey, siv)
    var got = c.open(rec)
    t.ok("server handshake record opens as type 22", got[0] == 22)
    t.eq("server handshake record payload (657 bytes)", got[1], payload)
    var s = Cipher()
    s.set(0x1301, skey, siv)
    var out = List[UInt8]()
    seal_all(s, HS, payload, out)
    t.eq("server handshake record re-sealed byte for byte (679 bytes)", out, rec)
    var cf = Cipher()
    cf.set(0x1301, v.get(sec, "derive read traffic keys for handshake", "key expanded"), v.get(sec, "derive read traffic keys for handshake", "iv expanded"))
    var o2 = List[UInt8]()
    seal_all(cf, HS, v.get(sec, "{client}  send handshake record", "payload", 1), o2)
    t.eq("client Finished record (58 bytes)", o2, v.get(sec, "{client}  send handshake record", "complete record", 1))
    # server: NST (seq 0), app data (seq 1), alert (seq 2); client: app data (seq 0), alert (seq 1)
    var sap = Cipher()
    sap.set(0x1301, v.get(sec, "derive write traffic keys for application", "key expanded", 0), v.get(sec, "derive write traffic keys for application", "iv expanded", 0))
    var cap = Cipher()
    cap.set(0x1301, v.get(sec, "{client}  derive write traffic keys for application", "key expanded"), v.get(sec, "{client}  derive write traffic keys for application", "iv expanded"))
    var a = List[UInt8]()
    seal_all(sap, HS, v.get(sec, "NewSessionTicket", "NewSessionTicket"), a)
    t.eq("NewSessionTicket record (227 bytes, seq 0)", a, v.get(sec, "{server}  send handshake record", "complete record", 2))
    var b = List[UInt8]()
    seal_all(sap, APP, v.get(sec, "{server}  send application_data", "payload"), b)
    t.eq("server application_data record (72 bytes, seq 1)", b, v.get(sec, "{server}  send application_data", "complete record"))
    var d = List[UInt8]()
    seal_all(sap, ALERT, v.get(sec, "{server}  send alert", "payload"), d)
    t.eq("server close_notify record (24 bytes, seq 2)", d, v.get(sec, "{server}  send alert", "complete record"))
    var e = List[UInt8]()
    seal_all(cap, APP, v.get(sec, "{client}  send application_data", "payload"), e)
    t.eq("client application_data record (72 bytes, seq 0)", e, v.get(sec, "{client}  send application_data", "complete record"))
    var f = List[UInt8]()
    seal_all(cap, ALERT, v.get(sec, "{client}  send alert", "payload"), f)
    t.eq("client close_notify record (24 bytes, seq 1)", f, v.get(sec, "{client}  send alert", "complete record"))


def oracle(mut t: T) raises:
    var txt: String
    with open("tests/vectors/record_oracle.txt", "r") as fh:
        txt = fh.read()
    var n = 0
    var good = 0
    for l in txt.split("\n"):
        var p = l.split(" ")
        if len(p) != 8:
            continue
        n += 1
        var suite = Int(String(p[0]))
        var payload = hexd(String(p[6])) if String(p[6]) != "-" else List[UInt8]()
        var rec = hexd(String(p[7]))
        var c = Cipher()
        c.set(suite, hexd(String(p[4])), hexd(String(p[5])))
        c.seq = u64(String(p[1]))
        var out = List[UInt8]()
        c.seal(Int(String(p[2])), payload, 0, len(payload), out, Int(String(p[3])))
        var same = len(out) == len(rec)
        if same:
            for i in range(len(rec)):
                if out[i] != rec[i]:
                    same = False
                    break
        var d = Cipher()
        d.set(suite, hexd(String(p[4])), hexd(String(p[5])))
        d.seq = u64(String(p[1]))
        var r = d.open(rec)
        var back = r[0] == Int(String(p[2])) and len(r[1]) == len(payload)
        if back:
            for i in range(len(payload)):
                if r[1][i] != payload[i]:
                    back = False
                    break
        if same and back:
            good += 1
        else:
            print("  oracle case " + String(n) + " suite " + String(suite) + " len " + String(len(payload)) + " same=" + String(same) + " back=" + String(back))
    t.ok("oracle vectors seal and open (" + String(good) + "/" + String(n) + ", 3 suites)", n == 45 and good == n)


def flip(rec: List[UInt8], i: Int) -> List[UInt8]:
    var o = rec.copy()
    o[i] ^= 0x01
    return o^


def negatives(mut t: T, v: Vec) raises:
    var skey = v.get(3, "derive write traffic keys for handshake", "key expanded")
    var siv = v.get(3, "derive write traffic keys for handshake", "iv expanded")
    var rec = v.get(3, "{server}  send handshake record", "complete record", 1)
    var caught = 0
    var tries = 0
    for i in range(0, len(rec), 7):
        tries += 1
        var c = Cipher()
        c.set(0x1301, skey, siv)
        try:
            _ = c.open(flip(rec, i))
        except e:
            caught += 1
    t.ok("every 7th byte flipped in a record is rejected (" + String(caught) + "/" + String(tries) + ")", caught == tries)
    var c2 = Cipher()
    c2.set(0x1301, skey, siv)
    var wrong_seq = False
    try:
        c2.seq = 1
        _ = c2.open(rec)
    except e:
        wrong_seq = alert_of(String(e)) == 20
    t.ok("wrong sequence number gives bad_record_mac", wrong_seq)
    var z = Cipher()
    z.set(0x1301, skey, siv)
    var zr = Cipher()
    zr.set(0x1301, skey, siv)
    var out = List[UInt8]()
    zr.seal(0, List[UInt8](), 0, 0, out)  # content type 0 and no payload: inner plaintext is all zero
    var code = 0
    try:
        _ = z.open(out)
    except e:
        code = alert_of(String(e))
    t.ok("all-zero inner plaintext gives unexpected_message", code == 10)
    var s = Cipher()
    s.set(0x1301, skey, siv)
    s.limit = 100
    var data = List[UInt8](length=250, fill=7)
    var o = List[UInt8]()
    seal_all(s, APP, data, o)
    t.ok("send limit 100 splits 250 bytes into records of 100, 100 and 50 bytes", len(o) == 122 + 122 + 72)
    var pc = Cipher()
    pc.set(0x1301, skey, siv)
    var po = List[UInt8]()
    pc.seal(HS, data, 0, 10, po, 300)
    var po2 = Cipher()
    po2.set(0x1301, skey, siv)
    var pr = po2.open(po)
    t.ok("300 bytes of padding stripped, content kept", pr[0] == HS and len(pr[1]) == 10)
    var big = Cipher()
    big.set(0x1301, skey, siv)
    var over = False
    try:
        var huge = List[UInt8](length=16385, fill=1)
        var ob = List[UInt8]()
        big.seal(APP, huge, 0, 16385, ob)
    except e:
        over = True
    t.ok("sealing more than 2^14 bytes in one record is refused", over)
    var rr = RecordReader()
    var hdr = List[UInt8]()
    hdr.append(23)
    hdr.append(3)
    hdr.append(3)
    hdr.append(0x41)
    hdr.append(0x01)  # length 16641 = 2^14 + 257
    rr.push(Span(hdr))
    var tmp = List[UInt8]()
    var ov = 0
    try:
        _ = rr.next(tmp)
    except e:
        ov = alert_of(String(e))
    t.ok("header longer than 2^14+256 gives record_overflow before the body arrives", ov == 22)
    var rr2 = RecordReader()
    var got = 0
    var whole = True
    for i in range(len(rec)):
        var one = List[UInt8]()
        one.append(rec[i])
        rr2.push(Span(one))
        var r2 = List[UInt8]()
        if rr2.next(r2):
            got += 1
            whole = whole and i == len(rec) - 1 and len(r2) == len(rec)
    t.ok("byte-wise fed record comes out once, whole, at the last byte", got == 1 and whole)
    var seed: UInt64 = 0x9e3779b97f4a7c15
    var raised = 0
    for _ in range(300):
        var m = 22 + Int((seed >> 33) % 80)
        var junk = List[UInt8](length=m, fill=0)
        for i in range(m):
            seed = seed * 6364136223846793005 + 1442695040888963407
            junk[i] = UInt8((seed >> 56) & 0xFF)
        var fc = Cipher()
        fc.set(0x1303, List[UInt8](length=32, fill=1), siv)
        try:
            _ = fc.open(junk)
        except e:
            raised += 1
    t.ok("300 random records are all rejected without a crash", raised == 300)


def main() raises:
    var t = T("record")
    var v = Vec()
    rfc(t, v)
    oracle(t)
    negatives(t, v)
    t.done()
