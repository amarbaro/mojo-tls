"""The AEAD shape the record layers use: in place, 12-byte nonce, 16-byte tag."""
from std.ffi import external_call


def dup(s: Span[UInt8, _]) -> List[UInt8]:
    """A copy of s by one memcpy: List(span) copies byte by byte (26% of the cycles of the record open bench)."""
    var o = List[UInt8](length=len(s), fill=0)
    if len(s) > 0:
        _ = external_call["memcpy", Int](Int(o.unsafe_ptr()), Int(s.unsafe_ptr()), len(s))
    return o^


trait Aead:
    def seal(self, nonce: Span[UInt8, ImmutAnyOrigin], aad: Span[UInt8, ImmutAnyOrigin], mut buf: List[UInt8]) raises:
        """Encrypt buf in place and append the 16-byte tag."""
        ...

    def open(self, nonce: Span[UInt8, ImmutAnyOrigin], aad: Span[UInt8, ImmutAnyOrigin], mut buf: List[UInt8]) raises:
        """Check the tag (constant time) before touching the data, then decrypt in place and drop the tag.
        On a bad tag raise and leave buf unchanged."""
        ...

    def wipe(mut self):
        """Zero the key material (best effort)."""
        ...
