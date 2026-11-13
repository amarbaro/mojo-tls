# OS CSPRNG through getrandom(2); never falls back to a weaker source, a short read raises.
from std.ffi import external_call


def random_bytes(n: Int) raises -> List[UInt8]:
    var out = List[UInt8](length=n, fill=0)
    var got = 0
    while got < n:
        var want = min(n - got, 256)
        var r = external_call["getrandom", Int](Int(out.unsafe_ptr()) + got, want, 0)
        if r <= 0:
            raise Error("tls: getrandom failed")
        got += r
    return out^
