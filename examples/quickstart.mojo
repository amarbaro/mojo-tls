from tls.sym import sha256


def main() raises:
    var msg = String("abc")
    var d = sha256(msg.as_bytes())
    var hex = String()
    for b in d:
        hex += hex_byte(b)
    print("sha256(abc) =", hex)
    if hex != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
        raise Error("FAIL quickstart: sha256 mismatch")


def hex_byte(b: UInt8) -> String:
    comptime digits = "0123456789abcdef"
    return String(digits[byte=Int(b >> 4)]) + String(digits[byte=Int(b & 15)])
