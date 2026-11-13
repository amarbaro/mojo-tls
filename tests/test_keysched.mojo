# Gate: key schedule against RFC 8448 sections 3 (x25519, AES-128-GCM) and 5 (HRR trace), SHA-256 chain.
# SHA-384 and KeyUpdate are printed here and compared with `openssl kdf` by tests/gate_tls13.sh.
from tls.tls13.keysched import KeySchedule, traffic_key, traffic_iv, finished_mac, next_secret, expand_label
from chk import Vec, T, hexs


def chain(mut t: T, v: Vec, sec: Int) raises:
    var tag = "RFC8448 s" + String(sec) + " "
    var ks = KeySchedule(32)
    t.eq(tag + "early secret", ks.secret, v.get(sec, "extract secret \"early\"", "secret"))
    var derived = expand_label(32, ks.secret, "derived", v.get(sec, "derive secret for handshake", "hash"), 32)
    t.eq(tag + "derived(early)", derived, v.get(sec, "derive secret for handshake", "expanded"))
    ks.to_handshake(v.get(sec, "extract secret \"handshake\"", "IKM"))
    t.eq(tag + "handshake secret", ks.secret, v.get(sec, "extract secret \"handshake\"", "secret"))
    var chs = ks.derive("c hs traffic", v.get(sec, "\"tls13 c hs traffic\"", "hash"))
    var shs = ks.derive("s hs traffic", v.get(sec, "\"tls13 s hs traffic\"", "hash"))
    t.eq(tag + "c hs traffic", chs, v.get(sec, "\"tls13 c hs traffic\"", "expanded"))
    t.eq(tag + "s hs traffic", shs, v.get(sec, "\"tls13 s hs traffic\"", "expanded"))
    t.eq(tag + "server hs key", traffic_key(32, shs, 16), v.get(sec, "derive write traffic keys for handshake", "key expanded"))
    t.eq(tag + "server hs iv", traffic_iv(32, shs), v.get(sec, "derive write traffic keys for handshake", "iv expanded"))
    ks.to_master()
    t.eq(tag + "master secret", ks.secret, v.get(sec, "extract secret \"master\"", "secret"))
    var cap = ks.derive("c ap traffic", v.get(sec, "\"tls13 c ap traffic\"", "hash"))
    var sap = ks.derive("s ap traffic", v.get(sec, "\"tls13 s ap traffic\"", "hash"))
    t.eq(tag + "c ap traffic", cap, v.get(sec, "\"tls13 c ap traffic\"", "expanded"))
    t.eq(tag + "s ap traffic", sap, v.get(sec, "\"tls13 s ap traffic\"", "expanded"))
    t.eq(tag + "exp master", ks.derive("exp master", v.get(sec, "\"tls13 exp master\"", "hash")), v.get(sec, "\"tls13 exp master\"", "expanded"))
    t.eq(tag + "server ap key", traffic_key(32, sap, 16), v.get(sec, "derive write traffic keys for application", "key expanded", 0))
    t.eq(tag + "server ap iv", traffic_iv(32, sap), v.get(sec, "derive write traffic keys for application", "iv expanded", 0))
    t.eq(tag + "client ap key", traffic_key(32, cap, 16), v.get(sec, "{client}  derive write traffic keys for application", "key expanded"))
    t.eq(tag + "client hs key", traffic_key(32, chs, 16), v.get(sec, "derive read traffic keys for handshake", "key expanded"))
    t.eq(tag + "client hs iv", traffic_iv(32, chs), v.get(sec, "derive read traffic keys for handshake", "iv expanded"))
    t.eq(tag + "res master", ks.derive("res master", v.get(sec, "\"tls13 res master\"", "hash")), v.get(sec, "\"tls13 res master\"", "expanded"))


def main() raises:
    var t = T("keysched")
    var v = Vec()
    chain(t, v, 3)
    chain(t, v, 5)
    # Finished (RFC 8448 3): finished key from the server hs traffic secret, verify_data over the transcript hash.
    var sec = 3
    var shs = v.get(sec, "\"tls13 s hs traffic\"", "expanded")
    var fkey = v.get(sec, "{server}  calculate finished", "expanded")
    t.eq("RFC8448 s3 finished_key", expand_label(32, shs, "finished", List[UInt8](), 32), fkey)
    # SHA-384 chain and KeyUpdate, for the openssl oracle in tests/gate_tls13.sh
    var ks = KeySchedule(48)
    ks.to_handshake(List[UInt8](length=48, fill=0x11))
    print("SHA384-HS " + hexs(ks.secret))
    var th = List[UInt8](length=48, fill=0x5a)
    print("SHA384-CHS " + hexs(ks.derive("c hs traffic", th)))
    print("SHA384-KEY " + hexs(traffic_key(48, ks.secret, 32)))
    print("SHA384-UPD " + hexs(next_secret(48, ks.secret)))
    print("SHA256-UPD " + hexs(next_secret(32, shs)))
    t.done()
