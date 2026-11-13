# Test helpers for lane 4: RFC 8448 vector lookup, hex, and a PASS/FAIL counter.
# Run from the repo root (vectors are read from tests/vectors/rfc8448.txt).


def hexd(s: String) -> List[UInt8]:
    var o = List[UInt8]()
    var hi = -1
    for c in s.as_bytes():
        var v = -1
        if c >= 48 and c <= 57:
            v = Int(c) - 48
        elif c >= 97 and c <= 102:
            v = Int(c) - 87
        elif c >= 65 and c <= 70:
            v = Int(c) - 55
        if v < 0:
            continue
        if hi < 0:
            hi = v
        else:
            o.append(UInt8(hi * 16 + v))
            hi = -1
    return o^


def hexs(b: List[UInt8]) -> String:
    var s = String()
    var d = "0123456789abcdef"
    for x in b:
        s += String(d[byte=Int(x) >> 4]) + String(d[byte=Int(x) & 15])
    return s^


def u64(s: String) -> UInt64:
    var v: UInt64 = 0
    for c in s.as_bytes():
        v = v * 10 + UInt64(Int(c) - 48)
    return v


struct Vec(Movable):
    var rows: List[String]

    def __init__(out self) raises:
        var txt: String
        with open("tests/vectors/rfc8448.txt", "r") as f:
            txt = f.read()
        self.rows = List[String]()
        for l in txt.split("\n"):
            if l.byte_length() > 0:
                self.rows.append(String(l))

    def get(self, sec: Int, step: String, field: String, nth: Int = 0) raises -> List[UInt8]:
        """nth row of section sec whose step contains `step` and whose field label equals `field`."""
        var seen = 0
        for r in self.rows:
            var p = r.split(" | ")
            if len(p) != 4 or Int(String(p[0])) != sec:
                continue
            if String(p[1]).find(step) >= 0 and String(p[2]) == field:
                if seen == nth:
                    return hexd(String(p[3]))
                seen += 1
        raise Error("vector not found: " + String(sec) + " " + step + " / " + field + " #" + String(nth))


struct T(Movable):
    var name: String
    var fails: Int
    var n: Int

    def __init__(out self, name: String):
        self.name = name
        self.fails = 0
        self.n = 0

    def ok(mut self, what: String, cond: Bool):
        self.n += 1
        if cond:
            print("PASS " + self.name + ": " + what)
        else:
            self.fails += 1
            print("FAIL " + self.name + ": " + what)

    def eq(mut self, what: String, a: List[UInt8], b: List[UInt8]):
        var same = len(a) == len(b)
        if same:
            for i in range(len(a)):
                if a[i] != b[i]:
                    same = False
                    break
        if not same:
            print("  got  " + hexs(a))
            print("  want " + hexs(b))
        self.ok(what, same)

    def done(self) raises:
        print(self.name + ": " + String(self.n - self.fails) + "/" + String(self.n) + " checks passed")
        if self.fails > 0:
            raise Error("FAIL " + self.name + ": " + String(self.fails) + " checks failed")
