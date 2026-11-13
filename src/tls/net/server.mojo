"""TlsServer: a nonblocking TLS 1.3 + 1.2 server on mojo-aio (one epoll Loop, one thread; run one per core with
SO_REUSEPORT-style separate ports or a front balancer). Per connection: the first record (the ClientHello) picks the
engine, Server13 when the client offers TLS 1.3 and cfg.tls13 is on, else Server12; then an output queue with
partial-write handling (EPOLLOUT armed only while bytes are queued), read pause when the peer does not drain
(cfg.max_out), a handshake deadline and an idle deadline from one timer chain. Plaintext goes to a TlsHandler."""
import aio
from std.ffi import external_call
from std.memory import ArcPointer
from std.time import perf_counter_ns
from tls.tls12.crypto import Crypto12, K_P256, K_P384
from tls.tls12.msg import parse_client_hello
from tls.tls12.server import Server12
from tls.tls13.conn import EV_CLOSE, EV_DONE, EV_ERROR
from tls.tls13.server import Server13, ServerConfig
from tls.tls13.verify import Signer
from .config import TlsConfig

comptime _RD = aio.IN | aio.RDHUP
comptime _DRAIN_MS = 1000  # after our last byte (alert or close_notify): half-close, read and drop the peer's rest; 1 s idle
comptime _DRAIN_MAX = 32 << 20  # bytes discarded before we stop waiting (a peer mid-way through a 16 MiB message still gets our alert)
comptime _FIRST_MAX = 16384 + 256  # the first record is one ClientHello: never buffer more before an engine is chosen


struct CSign[C: Crypto12](Signer):
    """TLS 1.3 CertificateVerify signer over a Crypto12 backend and one CertEntry."""

    var kind: Int
    var key: List[UInt8]
    var certs: List[List[UInt8]]

    def __init__(out self, kind: Int, key: List[UInt8], var certs: List[List[UInt8]]):
        self.kind = kind
        self.key = key.copy()
        self.certs = certs^

    def schemes(self) -> List[Int]:
        if self.kind == K_P256:
            return [0x0403]
        if self.kind == K_P384:
            return [0x0503]
        return [0x0804]

    def chain(self) -> List[List[UInt8]]:
        return self.certs.copy()

    def sign(self, scheme: Int, content: List[UInt8]) raises -> List[UInt8]:
        return Self.C().sign(self.kind, self.key, scheme, content)


@fieldwise_init
struct ConnInfo(Copyable, Movable):
    """What the handshake settled for one connection."""

    var ver: Int  # 12 or 13
    var sni: String  # server_name the client sent, empty if none
    var alpn: String  # protocol selected, empty if none


trait TlsHandler(Movable, Deinitable):
    def handle(mut self, fd: Int, info: ConnInfo, data: List[UInt8], mut reply: List[UInt8]) raises -> Bool:
        """Decrypted bytes arrived on connection fd. Append the answer to reply; return True to close after it is sent."""
        ...


struct Peer[C: Crypto12](Movable):
    var eng: Server12[Self.C]
    var e13: List[Server13[CSign[Self.C]]]  # holds one engine once the ClientHello chose TLS 1.3
    var ver: Int  # 0 until the first record is complete, then 12 or 13
    var first: List[UInt8]  # bytes of the first record while ver == 0
    var est13: Bool
    var live: Bool
    var gen: Int
    var out: List[UInt8]
    var outp: Int
    var born: Int  # ns
    var last: Int  # ns, last traffic
    var closing: Bool  # close once the queue is drained
    var armed: Bool  # EPOLLOUT is set
    var paused: Bool  # reading stopped: the peer is not draining our output
    var draining: Bool  # our side is shut (SHUT_WR); discarding input until EOF so the peer gets our last record, not a reset
    var drained: Int  # bytes discarded while draining

    def __init__(out self, cfg: ArcPointer[TlsConfig]):
        self.eng = Server12[Self.C](cfg)
        self.e13 = List[Server13[CSign[Self.C]]]()
        self.ver = 0
        self.first = List[UInt8]()
        self.est13 = False
        self.live = False
        self.gen = 0
        self.out = List[UInt8]()
        self.outp = 0
        self.born = 0
        self.last = 0
        self.closing = False
        self.armed = False
        self.paused = False
        self.draining = False
        self.drained = 0

    def established(self) -> Bool:
        return self.est13 if self.ver == 13 else self.eng.cn.established


struct TlsServer[C: Crypto12](Movable):
    var cfg: ArcPointer[TlsConfig]
    var loop: aio.Loop
    var lfd: Int32
    var tab: List[Peer[Self.C]]  # indexed by fd
    var rbuf: List[UInt8]
    var gen: Int
    var live: Int
    var handshakes: Int  # completed
    var failed: Int  # closed by an error or alert before the handshake ended
    var timeouts: Int
    var closed: Int  # connections finished, for any reason
    var stopped: Bool

    def __init__(out self, var cfg: TlsConfig, port: Int = 0, host: String = "127.0.0.1", tls13: Bool = True) raises:
        if len(cfg.certs) == 0:
            raise Error("tls: TlsConfig has no certificate (add a CertEntry before starting the server)")  # else the first ClientHello indexes certs[order(sni)[0]] out of range
        if tls13 and len(cfg.ticket_keys) == 0:
            cfg.ticket_keys = [Self.C().random(32)]  # one key per server start: tickets survive connections, not restarts
        cfg.tls13 = tls13  # also tells Server12 to send the DOWNGRD sentinel to a 1.3-capable client (RFC 8446 4.1.3)
        self.cfg = ArcPointer(cfg^)
        self.loop = aio.Loop(1024)
        self.lfd = aio.tcp_listen(port, host)
        self.tab = List[Peer[Self.C]]()
        self.rbuf = List[UInt8](length=32768, fill=0)
        self.gen = 0
        self.live = 0
        self.handshakes = 0
        self.failed = 0
        self.timeouts = 0
        self.closed = 0
        self.stopped = False
        self.loop.add(self.lfd, aio.IN, UInt64(self.lfd))

    def port(self) raises -> Int:
        return aio.local_port(self.lfd)

    def _ms_left(self, p: Peer[Self.C], now: Int) -> Int:
        if p.draining:
            return (p.last + _DRAIN_MS * 1_000_000 - now + 999_999) // 1_000_000
        var est = p.established()
        var limit = (self.cfg[].idle_ms if est else self.cfg[].handshake_ms) * 1_000_000
        return ((p.born if not est else p.last) + limit - now + 999_999) // 1_000_000

    def _drop(mut self, fd: Int):
        ref p = self.tab[fd]
        if not p.live:
            return
        if not p.established():
            self.failed += 1
        p.eng.cn.alert = -1  # no alert, just wipe the secrets
        p.eng.cn.die()
        p.e13.clear()
        try:
            self.loop.remove(Int32(fd))
        except:
            pass
        aio.close(Int32(fd))
        p.live = False
        p.out = List[UInt8]()
        p.outp = 0
        self.live -= 1
        self.closed += 1

    def _flush(mut self, fd: Int) raises:
        ref p = self.tab[fd]
        if p.ver == 12:
            var o = p.eng.cn.take_output()
            if len(o) > 0:
                p.out.extend(o^)
        while p.outp < len(p.out):
            var n = aio.write(Int32(fd), Span(p.out)[p.outp :])
            if n == -2:
                self._drop(fd)
                return
            if n == -1:
                break
            p.outp += n
        var queued = len(p.out) - p.outp
        if queued == 0:
            p.out.clear()
            p.outp = 0
            if p.closing:
                # Closing with the peer's input unread makes the kernel send a reset, and the peer can lose the alert or
                # close_notify we just wrote. Half-close and drain instead; _read drops the connection at EOF, the timer after _DRAIN_MS.
                p.closing = False
                p.draining = True
                p.last = Int(perf_counter_ns())
                _ = external_call["shutdown", Int32](Int32(fd), Int32(1))  # SHUT_WR
                self.loop.after(_DRAIN_MS, UInt64(fd) | (UInt64(p.gen) << 32))
        var want_out = queued > 0
        var pause = queued > self.cfg[].max_out
        if want_out != p.armed or pause != p.paused:
            p.armed = want_out
            p.paused = pause
            var ev = (aio.OUT if want_out else UInt32(0)) | (0 if pause else _RD)
            self.loop.modify(Int32(fd), ev, UInt64(fd) | (UInt64(p.gen) << 32))

    def _read[H: TlsHandler](mut self, fd: Int, mut h: H) raises:
        for _ in range(8):
            ref p = self.tab[fd]
            var n = aio.read(Int32(fd), self.rbuf)
            if n == -1:
                return
            if n <= 0:
                self._drop(fd)  # EOF or error
                return
            if p.draining:
                p.drained += n  # the peer's rest after our last record: dropped unread, each read extends the 1 s idle limit
                p.last = Int(perf_counter_ns())
                if p.drained > _DRAIN_MAX:
                    self._drop(fd)
                    return
                continue
            p.last = Int(perf_counter_ns())
            var data = List[UInt8](Span(self.rbuf)[0:n])
            if p.ver == 0:
                p.first.extend(Span(data))
                var need = 5 + (Int(p.first[3]) << 8 | Int(p.first[4])) if len(p.first) >= 5 else 5
                # Not a handshake record (type 22, version 3.x, at most one record): Server12 answers with its own alert at once.
                var bad = len(p.first) >= 5 and (p.first[0] != 22 or p.first[1] != 3 or need > _FIRST_MAX)
                if not bad and len(p.first) < need:
                    continue
                var tls13 = False
                var sni = String()
                if self.cfg[].tls13 and not bad:
                    tls13 = True  # a hello the 1.2 parser cannot read goes to Server13: its own alert answers
                    try:
                        if need < 9:
                            raise Error("record too short for a ClientHello")  # Server13 answers it with its own alert
                        var ch = parse_client_hello(List[UInt8](Span(p.first)[9:need]))
                        sni = ch.sni.copy()
                        tls13 = ch.offers13() or not self.cfg[].tls12
                    except:
                        pass
                if tls13:
                    ref e = self.cfg[].certs[self.cfg[].order(sni)[0]]
                    var rng = Self.C()
                    var sc = ServerConfig(rng.random(32), rng.random(32), rng.random(32))
                    sc.alpn = self.cfg[].alpn.copy()
                    sc.ticket_keys = self.cfg[].ticket_keys.copy()
                    sc.client_roots = self.cfg[].client_roots.copy()
                    sc.require_client_cert = self.cfg[].require_client_cert
                    p.e13.append(Server13[CSign[Self.C]](sc^, CSign[Self.C](e.kind, e.key, e.chain.copy())))
                    p.ver = 13
                else:
                    p.ver = 12
                data = p.first.copy()
                p.first.clear()
            if p.ver == 13:
                var o = p.e13[0].feed(Span(data))
                p.out.extend(Span(o.send))
                if o.has(EV_ERROR) or o.error.byte_length() > 0:
                    p.closing = True  # the alert is in o.send; never feed the engine again (a second alert breaks peers)
                    self._flush(fd)
                    return
                if o.has(EV_DONE):
                    p.est13 = True
                    self.handshakes += 1
                if len(o.data) > 0:
                    var reply = List[UInt8]()
                    try:  # a handler or a write on a connection the peer just closed must end that connection, never the server
                        var stop = h.handle(fd, ConnInfo(13, p.e13[0].sni, p.e13[0].alpn), o.data, reply)
                        if len(reply) > 0 and not o.has(EV_CLOSE):
                            p.out.extend(Span(p.e13[0].write(reply)))
                        if stop:
                            p.out.extend(Span(p.e13[0].close()))
                            p.closing = True
                    except:
                        p.closing = True
                if o.has(EV_CLOSE) and not p.closing:
                    p.out.extend(Span(p.e13[0].close()))
                    p.closing = True
                self._flush(fd)
                if not self.tab[fd].live or self.tab[fd].paused:
                    return
                continue
            var was = p.eng.cn.established
            try:
                p.eng.feed(Span(data))
            except:
                p.closing = True  # the engine queued the alert
                self._flush(fd)
                return
            if p.eng.cn.established and not was:
                self.handshakes += 1
            var app = p.eng.cn.take_app()
            if len(app) > 0:
                var reply = List[UInt8]()
                var stop = h.handle(fd, ConnInfo(12, p.eng.sni, p.eng.alpn), app, reply)
                if len(reply) > 0:
                    p.eng.cn.write_app(reply)
                if stop:
                    p.eng.cn.close()
                    p.closing = True
            if p.eng.cn.peer_closed:
                p.closing = True
            self._flush(fd)
            if not self.tab[fd].live or self.tab[fd].paused:
                return

    def step[H: TlsHandler](mut self, mut h: H, timeout_ms: Int = 1000) raises:
        """One pass of the event loop: accept, read, write, expire."""
        var evs = List[aio.Event]()
        _ = self.loop.wait(evs, timeout_ms)
        for ev in evs:
            var fd = Int(ev.token & 0xFFFFFFFF)
            if ev.events & aio.TIMER != 0:
                if fd < len(self.tab) and self.tab[fd].live and self.tab[fd].gen == Int(ev.token >> 32):
                    var left = self._ms_left(self.tab[fd], Int(perf_counter_ns()))
                    if left <= 0:
                        if not self.tab[fd].draining:
                            self.timeouts += 1
                        self._drop(fd)
                    else:
                        self.loop.after(left, ev.token)
            elif Int32(fd) == self.lfd:
                self._accept()
            elif fd < len(self.tab) and self.tab[fd].live and self.tab[fd].gen == Int(ev.token >> 32):
                if ev.events & aio.OUT != 0:
                    self._flush(fd)
                if self.tab[fd].live and ev.events & (_RD | aio.ERR | aio.HUP) != 0 and not self.tab[fd].paused:
                    self._read(fd, h)

    def _accept(mut self) raises:
        while True:
            var c = aio.accept(self.lfd)
            if c < 0:
                return
            if self.live >= self.cfg[].max_conns:
                aio.close(c)
                continue
            while len(self.tab) <= Int(c):
                self.tab.append(Peer[Self.C](self.cfg))
            self.gen += 1
            ref p = self.tab[Int(c)]
            p.eng = Server12[Self.C](self.cfg)
            p.e13.clear()
            p.ver = 0
            p.first = List[UInt8]()
            p.est13 = False
            p.live = True
            p.gen = self.gen
            p.out = List[UInt8]()
            p.outp = 0
            p.closing = False
            p.armed = False
            p.paused = False
            p.draining = False
            p.drained = 0
            p.born = Int(perf_counter_ns())
            p.last = p.born
            self.live += 1
            var tok = UInt64(c) | (UInt64(self.gen) << 32)
            self.loop.add(c, _RD, tok)
            self.loop.after(self.cfg[].handshake_ms, tok)

    def run[H: TlsHandler](mut self, mut h: H) raises:
        while not self.stopped:
            self.step(h)

    def close(mut self):
        for fd in range(len(self.tab)):
            if self.tab[fd].live:
                self._drop(fd)
        aio.close(self.lfd)
