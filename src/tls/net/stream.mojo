"""TlsStream: a blocking TLS 1.2 client connection over a TCP socket (Client12 does the protocol). Names resolve
only as IPv4 literals or "localhost" (no resolver in pure Mojo yet); `host` is what the certificate must match."""
import aio
from std.ffi import external_call
from tls.tls12.client import Client12
from tls.tls12.crypto import Crypto12


def tcp_connect(addr: String, port: Int, rcvbuf: Int = 0) raises -> Int32:
    """A blocking, connected IPv4 TCP socket (TCP_NODELAY); rcvbuf > 0 sets a small SO_RCVBUF first (slow-reader tests)."""
    var fd = external_call["socket", Int32](Int32(2), Int32(1 | 0o2000000), Int32(0))
    if fd < 0:
        raise Error("tls: socket failed")
    if rcvbuf > 0:
        var rb = Int32(rcvbuf)
        _ = external_call["setsockopt", Int32](fd, Int32(1), Int32(8), Pointer(to=rb), Int32(4))
    var sa = SIMD[DType.uint32, 4](UInt32(2) | (UInt32(port & 0xFF) << 24) | (UInt32(port >> 8) << 16), aio._ipv4(addr), 0, 0)
    if external_call["connect", Int32](fd, Pointer(to=sa), Int32(16)) != 0:
        aio.close(fd)
        raise Error("tls: connect to ", addr, ":", port, " failed")
    var one = Int32(1)
    _ = external_call["setsockopt", Int32](fd, Int32(6), Int32(1), Pointer(to=one), Int32(4))
    return fd


struct TlsStream[C: Crypto12](Movable):
    var fd: Int32
    var eng: Client12[Self.C]
    var buf: List[UInt8]
    var rx: List[UInt8]  # decrypted bytes not yet returned by read()

    def __init__(out self, fd: Int32, var eng: Client12[Self.C]):
        self.fd = fd
        self.eng = eng^
        self.buf = List[UInt8](length=32768, fill=0)
        self.rx = List[UInt8]()

    def __deinit__(deinit self):
        if self.fd >= 0:
            aio.close(self.fd)

    def _flush(mut self) raises:
        var o = self.eng.cn.take_output()
        var sent = 0
        while sent < len(o):
            var n = aio.write(self.fd, Span(o)[sent:])
            if n < 0:
                raise Error("tls: write failed")
            sent += n

    def _pull(mut self) raises -> Int:
        """Read once from the socket and feed the engine; 0 at end of stream."""
        var n = aio.read(self.fd, self.buf)
        if n <= 0:
            return 0
        try:
            self.eng.feed(Span(self.buf)[0:n])
        except e:
            try:
                self._flush()  # the fatal alert
            except:
                pass
            raise e^
        self._flush()
        return n

    def handshake(mut self) raises:
        self.eng.start()
        self._flush()
        while not self.eng.cn.established:
            if self._pull() == 0:
                raise Error("tls: connection closed during the handshake")

    def read(mut self, mut dst: List[UInt8]) raises -> Int:
        """Append decrypted bytes to dst and return how many; 0 once the peer closed (close_notify or EOF)."""
        while True:
            var app = self.eng.cn.take_app()
            if len(app) > 0:
                var n = len(app)
                dst.extend(app^)
                return n
            if self.eng.cn.peer_closed or self._pull() == 0:
                return 0

    def write(mut self, data: List[UInt8]) raises:
        self.eng.cn.write_app(data)
        self._flush()

    def close(mut self):
        self.eng.cn.close()
        try:
            self._flush()
        except:
            pass
        self.eng.cn.alert = -1
        self.eng.cn.die()
        if self.fd >= 0:
            aio.close(self.fd)
            self.fd = -1


def tls_connect[C: Crypto12](host: String, port: Int, alpn: List[String] = [], addr: String = "", rcvbuf: Int = 0) raises -> TlsStream[C]:
    """Connect to addr (default: host) and finish the handshake."""
    var s = TlsStream[C](tcp_connect(addr if addr.byte_length() > 0 else host, port, rcvbuf), Client12[C](host, alpn))
    s.handshake()
    return s^
