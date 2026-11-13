"""TlsConfig: the certificates a server offers (picked by SNI), ALPN protocols, timeouts and size limits."""


struct CertEntry(Copyable, Movable):
    var names: List[String]  # lower case; "*.example.com" matches one extra label
    var chain: List[List[UInt8]]  # DER certificates, leaf first
    var key: List[UInt8]  # DER private key (PKCS#8 or SEC1)
    var kind: Int  # K_P256, K_P384 or K_RSA from tls.tls12.crypto

    def __init__(out self, var names: List[String], var chain: List[List[UInt8]], var key: List[UInt8], kind: Int):
        self.names = names^
        self.chain = chain^
        self.key = key^
        self.kind = kind

    def matches(self, host: String) -> Bool:
        for n in self.names:
            if n == host:
                return True
            if n.startswith("*."):
                var dot = host.find(".")
                if dot > 0 and String(host[byte = dot :]) == String(n[byte = 1 :]):
                    return True
        return False


struct TlsConfig(Movable):
    var certs: List[CertEntry]  # the first entry is the default
    var alpn: List[String]  # server preference order; empty = no ALPN
    var handshake_ms: Int  # a connection that has not finished its handshake by then is closed
    var idle_ms: Int  # an established connection with no traffic for this long is closed
    var max_conns: Int
    var max_out: Int  # queued output bytes per connection before reading pauses
    var tls12: Bool  # False: TLS 1.3 only, a client that does not offer 1.3 gets Server13's protocol_version alert
    var client_roots: List[List[UInt8]]  # DER trust anchors for client certificates
    var require_client_cert: Bool  # ask every client for a certificate that chains to client_roots (clientAuth); no tickets then
    var ticket_keys: List[List[UInt8]]  # TLS 1.3 session ticket keys (32 bytes, first seals); empty = TlsServer makes one at start
    var tls13: Bool  # a TLS 1.3 engine sits behind this config: a TLS 1.2 answer to a 1.3 client carries the DOWNGRD sentinel (RFC 8446 4.1.3)

    def __init__(out self):
        self.certs = List[CertEntry]()
        self.alpn = List[String]()
        self.handshake_ms = 10000
        self.idle_ms = 60000
        self.max_conns = 65536
        self.max_out = 1 << 20
        self.tls12 = True
        self.client_roots = List[List[UInt8]]()
        self.require_client_cert = False
        self.ticket_keys = List[List[UInt8]]()
        self.tls13 = False

    def order(self, sni: String) -> List[Int]:
        """Entries to try, SNI matches first, then the rest in configuration order (default first)."""
        var o = List[Int]()
        for i in range(len(self.certs)):
            if self.certs[i].matches(sni):
                o.append(i)
        for i in range(len(self.certs)):
            if i not in o:
                o.append(i)
        return o^
