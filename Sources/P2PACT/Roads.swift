import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Roads carry packets (spec §3). A road encrypts nothing and trusts nothing; it may lose,
// duplicate and reorder packets. send never blocks for long: it queues or drops.

/// Road carries packets.
public protocol Road: AnyObject {
    var name: String { get }
    func send(_ addr: String, _ pkt: Bytes) -> Bool
}

/// Endpoint is where to send on a road: a UDP or TCP address, or a relay channel.
public struct Endpoint {
    public let road: Road
    public let addr: String
    public init(road: Road, addr: String) { self.road = road; self.addr = addr }
    public var key: String { road.name + "|" + addr }
}

/// Receiver is called from the road's own threads; the node re-posts to its queue.
typealias Receiver = (Bytes, Endpoint) -> Void

/// RoadStats counts payload bytes and packets.
public struct RoadStats {
    public let sentBytes: Int64
    public let sentPackets: Int64
    public let recvBytes: Int64
    public let recvPackets: Int64
}

// MARK: small helpers

final class AtomicFlag {
    private let l = NSLock()
    private var v = false
    var value: Bool { l.lock(); defer { l.unlock() }; return v }
    /// setIfUnset sets the flag; true — this call did it.
    @discardableResult func setIfUnset() -> Bool {
        l.lock(); defer { l.unlock() }
        if v { return false }
        v = true
        return true
    }
    func set(_ x: Bool) { l.lock(); v = x; l.unlock() }
}

final class Counters {
    private let l = NSLock()
    private var sb: Int64 = 0, sp: Int64 = 0, rb: Int64 = 0, rp: Int64 = 0
    func sent(_ n: Int) { l.lock(); sb += Int64(n); sp += 1; l.unlock() }
    func received(_ n: Int) { l.lock(); rb += Int64(n); rp += 1; l.unlock() }
    func snapshot() -> RoadStats { l.lock(); defer { l.unlock() }; return RoadStats(sentBytes: sb, sentPackets: sp, recvBytes: rb, recvPackets: rp) }
}

/// FrameQueue is a bounded blocking queue of byte strings.
final class FrameQueue {
    private let c = NSCondition()
    private var items = [Bytes]()
    private var head = 0
    private let limit: Int
    init(limit: Int) { self.limit = limit }

    var count: Int { c.lock(); defer { c.unlock() }; return items.count - head }

    func offer(_ b: Bytes) -> Bool {
        c.lock(); defer { c.unlock() }
        if items.count - head >= limit { return false }
        items.append(b)
        c.signal()
        return true
    }

    /// poll waits up to timeout seconds for an item; nil — none (or cancel() turned true after a nudge).
    func poll(timeout: TimeInterval, cancel: () -> Bool) -> Bytes? {
        let deadline = Date().addingTimeInterval(timeout)
        c.lock(); defer { c.unlock() }
        while items.count - head == 0 {
            if cancel() { return nil }
            if !c.wait(until: deadline) { return nil }
        }
        return takeLocked()
    }

    /// drain takes everything queued now.
    func drain() -> [Bytes] {
        c.lock(); defer { c.unlock() }
        var out = [Bytes]()
        while items.count - head > 0 { out.append(takeLocked()) }
        return out
    }

    private func takeLocked() -> Bytes {
        let b = items[head]
        head += 1
        if head > 64 && head * 2 > items.count { items.removeFirst(head); head = 0 }
        if items.count == head { items.removeAll(keepingCapacity: true); head = 0 }
        return b
    }

    func clear() { c.lock(); items.removeAll(); head = 0; c.unlock() }

    /// nudge wakes waiters so they re-check their cancel condition.
    func nudge() { c.lock(); c.broadcast(); c.unlock() }
}

func spawn(_ name: String, _ body: @escaping () -> Void) {
    let t = Thread(block: body)
    t.name = name
    t.stackSize = 512 << 10
    t.start()
}

// MARK: addresses

/// hostPort splits "host:port" and "[v6]:port".
func hostPort(_ addr: String) -> (String, Int)? {
    guard let i = addr.lastIndex(of: ":"), i != addr.startIndex else { return nil }
    guard let port = Int(addr[addr.index(after: i)...]) else { return nil }
    var host = String(addr[..<i])
    if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    return (host, port)
}

/// bindParts reads a bind string: "host:port", ":port" or "port".
func bindParts(_ bind: String) -> (String, Int) {
    if let hp = hostPort(bind) { return hp }
    var s = Substring(bind)
    if s.hasPrefix(":") { s = s.dropFirst() }
    return ("", Int(s) ?? 0)
}

func joinHostPort(_ host: String, _ port: Int) -> String {
    host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
}

struct SockAddr {
    var storage: sockaddr_storage
    var len: socklen_t
    var family: Int32 { Int32(storage.ss_family) }

    func with<R>(_ body: (UnsafePointer<sockaddr>, socklen_t) -> R) -> R {
        var s = storage
        return withUnsafePointer(to: &s) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, len) }
        }
    }

    var text: String {
        var host = [CChar](repeating: 0, count: 256)
        var serv = [CChar](repeating: 0, count: 32)
        let r = with { sa, l in getnameinfo(sa, l, &host, 256, &serv, 32, NI_NUMERICHOST | NI_NUMERICSERV) }
        if r != 0 { return "" }
        var h = String(cString: host)
        if let pct = h.firstIndex(of: "%") { h = String(h[..<pct]) }
        if h.lowercased().hasPrefix("::ffff:"), h.contains(".") { h = String(h.dropFirst(7)) } // IPv4 on a dual-stack socket
        return joinHostPort(h, Int(String(cString: serv)) ?? 0)
    }
}

/// listenAddrs are the addresses to try for a listen address: "" (all) — IPv6 any, which takes IPv4 too (dual stack,
/// as Go's ":port"), then IPv4 any for a host without IPv6.
func listenAddrs(host: String, port: Int, type: Int32) -> [SockAddr] {
    if host.isEmpty {
        return resolve(host: "", port: port, family: AF_INET6, type: type, passive: true)
            + resolve(host: "", port: port, family: AF_INET, type: type, passive: true)
    }
    return resolve(host: host, port: port, family: AF_UNSPEC, type: type, passive: true)
}

/// openListenSocket opens and binds a socket on the first address that works; v6 sockets accept IPv4 as well.
func bindFirst(_ addrs: [SockAddr], _ type: Int32, prepare: (Int32) -> Void) -> (Int32, SockAddr)? {
    for sa in addrs {
        let s = openSocket(sa.family, type)
        if s < 0 { continue }
        if sa.family == AF_INET6 { setIntOpt(s, Int32(IPPROTO_IPV6), IPV6_V6ONLY, 0) }
        prepare(s)
        if sa.with({ sysBind(s, $0, $1) }) == 0 { return (s, sa) }
        Darwin_close(s)
    }
    return nil
}

/// v4Mapped turns an IPv4 address into the IPv6 form a dual-stack socket sends to.
func v4Mapped(_ a: SockAddr) -> SockAddr {
    if a.family != AF_INET { return a }
    var ss = a.storage
    var out = sockaddr_in6()
    withUnsafePointer(to: &ss) { p in
        p.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { v4 in
            out.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            out.sin6_family = sa_family_t(AF_INET6)
            out.sin6_port = v4.pointee.sin_port
            withUnsafeMutableBytes(of: &out.sin6_addr) { b in
                for i in 10..<12 { b[i] = 0xff }
                withUnsafeBytes(of: v4.pointee.sin_addr) { for i in 0..<4 { b[12 + i] = $0[i] } }
            }
        }
    }
    var st = sockaddr_storage()
    memcpy(&st, &out, MemoryLayout<sockaddr_in6>.size)
    return SockAddr(storage: st, len: socklen_t(MemoryLayout<sockaddr_in6>.size))
}

func sockAddr(fromStorage ss: sockaddr_storage, len: socklen_t) -> SockAddr { SockAddr(storage: ss, len: len) }

/// resolve turns host and port into socket addresses (host "" — the wildcard address).
func resolve(host: String, port: Int, family: Int32, type: Int32, passive: Bool = false) -> [SockAddr] {
    var hints = addrinfo()
    hints.ai_family = family
    hints.ai_socktype = type
    hints.ai_flags = (passive ? AI_PASSIVE : 0) | AI_NUMERICSERV
    var res: UnsafeMutablePointer<addrinfo>?
    let rc: Int32 = host.isEmpty
        ? getaddrinfo(nil, String(port), &hints, &res)
        : getaddrinfo(host, String(port), &hints, &res)
    if rc != 0 || res == nil { return [] }
    defer { freeaddrinfo(res) }
    var out = [SockAddr]()
    var p = res
    while let ai = p {
        if let sa = ai.pointee.ai_addr {
            var ss = sockaddr_storage()
            memcpy(&ss, sa, Int(min(Int(ai.pointee.ai_addrlen), MemoryLayout<sockaddr_storage>.size)))
            out.append(SockAddr(storage: ss, len: ai.pointee.ai_addrlen))
        }
        p = ai.pointee.ai_next
    }
    return out
}

func localName(_ fd: Int32) -> SockAddr? {
    var ss = sockaddr_storage()
    var l = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let r = withUnsafeMutablePointer(to: &ss) { p in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &l) }
    }
    return r == 0 ? SockAddr(storage: ss, len: l) : nil
}

func setIntOpt(_ fd: Int32, _ level: Int32, _ name: Int32, _ v: Int32) {
    var x = v
    _ = setsockopt(fd, level, name, &x, socklen_t(MemoryLayout<Int32>.size))
}

func noSigpipe(_ fd: Int32) {
    #if canImport(Darwin)
    setIntOpt(fd, SOL_SOCKET, SO_NOSIGPIPE, 1)
    #endif
}

func openSocket(_ family: Int32, _ type: Int32) -> Int32 {
    let fd = socket(family, type, 0)
    if fd >= 0 { noSigpipe(fd) }
    return fd
}

/// localAddrs lists our addresses for hints: the listen address, or every IPv4 network address when listening on all.
func localAddrs(host: String, port: Int) -> [String] {
    if !(host.isEmpty || host == "0.0.0.0" || host == "::") { return [joinHostPort(host, port)] }
    var out = [String]()
    var ifs: UnsafeMutablePointer<ifaddrs>?
    if getifaddrs(&ifs) != 0 { return out }
    defer { freeifaddrs(ifs) }
    var p = ifs
    while let i = p {
        defer { p = i.pointee.ifa_next }
        let flags = Int32(i.pointee.ifa_flags)
        guard flags & IFF_UP != 0, let sa = i.pointee.ifa_addr, Int32(sa.pointee.sa_family) == AF_INET else { continue }
        let v4 = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
        if v4 >> 24 == 127 || v4 >> 16 == 0xA9FE { continue }
        out.append(joinHostPort("\(v4 >> 24).\((v4 >> 16) & 255).\((v4 >> 8) & 255).\(v4 & 255)", port))
    }
    return out
}

/// connectTimeout makes a TCP connection with a deadline; -1 — it failed.
func tcpConnect(_ host: String, _ port: Int, timeout: Int32) -> Int32 {
    for sa in resolve(host: host, port: port, family: AF_UNSPEC, type: SOCK_STREAM) {
        let fd = openSocket(sa.family, SOCK_STREAM)
        if fd < 0 { continue }
        let fl = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, fl | O_NONBLOCK)
        var rc = sa.with { connect(fd, $0, $1) }
        if rc != 0 && errno == EINPROGRESS {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let n = poll(&pfd, 1, timeout)
            if n > 0 {
                var err: Int32 = 0
                var l = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l)
                rc = err == 0 ? 0 : -1
            }
        }
        if rc == 0 {
            _ = fcntl(fd, F_SETFL, fl)
            return fd
        }
        close(fd)
    }
    return -1
}

/// waitReadable polls fd for input for up to ms milliseconds.
func waitReadable(_ fd: Int32, _ ms: Int32) -> Bool {
    var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
    let n = poll(&pfd, 1, ms)
    return n > 0
}

// MARK: UDP

/// UdpRoad is the main road: one packet is one datagram (spec §3).
public final class UdpRoad: Road {
    public let name = "udp"
    private let recv: Receiver
    private var fd: Int32
    private let family: Int32
    private let lock = NSLock()
    private var addrs = [String: SockAddr]()
    private let closedFlag = AtomicFlag()
    private let exited = DispatchSemaphore(value: 0)
    private let counters = Counters()
    private let bound: SockAddr

    /// drop is for tests: it says a packet is lost, both ways.
    public var drop: (() -> Bool)?

    init(bind: String, recv: @escaping Receiver) throws {
        self.recv = recv
        let (host, port) = bindParts(bind)
        let cands = listenAddrs(host: host, port: port, type: SOCK_DGRAM)
        if cands.isEmpty { throw P2pactIOError("cannot resolve \(bind)") }
        // a burst of retransmissions must not overflow the receive queue
        guard let (s, sa) = bindFirst(cands, SOCK_DGRAM, prepare: { s in
            setIntOpt(s, SOL_SOCKET, SO_RCVBUF, 1 << 20)
            setIntOpt(s, SOL_SOCKET, SO_SNDBUF, 1 << 20)
        }) else {
            throw P2pactIOError("cannot bind \(bind): \(String(cString: strerror(errno)))")
        }
        fd = s
        family = sa.family
        bound = localName(s) ?? sa
        spawn("p2pact-udp") { [self] in run() }
    }

    public var localAddr: String { bound.text }

    func localAddrs() -> [String] {
        guard let (h, p) = hostPort(bound.text) else { return [] }
        return P2PACT.localAddrs(host: h, port: p)
    }

    public func stats() -> RoadStats { counters.snapshot() }

    public func send(_ addr: String, _ pkt: Bytes) -> Bool {
        counters.sent(pkt.count)
        if drop?() == true { return true }
        if closedFlag.value { return false }
        lock.lock()
        var to = addrs[addr]
        lock.unlock()
        if to == nil {
            guard let (h, p) = hostPort(addr), let r = resolve(host: h, port: p, family: family == AF_INET6 ? AF_UNSPEC : family, type: SOCK_DGRAM).first else { return false }
            let a = family == AF_INET6 ? v4Mapped(r) : r // a dual-stack socket sends IPv4 as mapped
            lock.lock(); addrs[addr] = a; lock.unlock()
            to = a
        }
        let r = pkt.withUnsafeBytes { b in
            to!.with { sa, l in sendto(fd, b.baseAddress, pkt.count, 0, sa, l) }
        }
        return r >= 0
    }

    private func run() {
        defer { exited.signal() }
        var buf = Bytes(repeating: 0, count: 2048)
        while !closedFlag.value {
            if !waitReadable(fd, 200) { continue }
            var ss = sockaddr_storage()
            var l = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = buf.withUnsafeMutableBytes { b in
                withUnsafeMutablePointer(to: &ss) { p in
                    p.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, b.baseAddress, b.count, 0, $0, &l) }
                }
            }
            if n < 0 { if closedFlag.value { break }; continue }
            counters.received(n)
            if drop?() == true { continue }
            let from = SockAddr(storage: ss, len: l).text
            recv(Bytes(buf[0..<n]), Endpoint(road: self, addr: from))
        }
        Darwin_close(fd)
    }

    public func close() {
        if !closedFlag.setIfUnset() { return }
        _ = exited.wait(timeout: .now() + 2)
    }
}

#if canImport(Darwin)
private func Darwin_bind(_ fd: Int32, _ sa: UnsafePointer<sockaddr>, _ l: socklen_t) -> Int32 { Darwin.bind(fd, sa, l) }
#else
private func Darwin_bind(_ fd: Int32, _ sa: UnsafePointer<sockaddr>, _ l: socklen_t) -> Int32 { Glibc.bind(fd, sa, l) }
#endif
func sysBind(_ fd: Int32, _ sa: UnsafePointer<sockaddr>, _ l: socklen_t) -> Int32 { Darwin_bind(fd, sa, l) }

// MARK: stream roads

/// Link is one connection of a stream road: a socket with buffered reads.
final class Link {
    private let fd: Int32
    private let lock = NSLock()
    private var closedFlag = false
    private var rbuf = Bytes(repeating: 0, count: 64 << 10)
    private var rpos = 0, rlen = 0

    init(fd: Int32) { self.fd = fd }

    /// readExact reads exactly n bytes; nil — the connection ended, failed or timed out.
    func readExact(_ n: Int) -> Bytes? {
        var out = Bytes()
        out.reserveCapacity(n)
        while out.count < n {
            if rpos == rlen {
                var r: Int
                repeat {
                    r = rbuf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
                } while r < 0 && errno == EINTR
                if r <= 0 { return nil }
                rpos = 0; rlen = r
            }
            let k = min(n - out.count, rlen - rpos)
            out.append(contentsOf: rbuf[rpos..<rpos + k])
            rpos += k
        }
        return out
    }

    func write(_ b: Bytes) -> Bool {
        var off = 0
        while off < b.count {
            #if canImport(Darwin)
            let flags: Int32 = 0
            #else
            let flags = Int32(MSG_NOSIGNAL)
            #endif
            let r = b.withUnsafeBytes { send(fd, $0.baseAddress! + off, b.count - off, flags) }
            if r < 0 && errno == EINTR { continue }
            if r <= 0 { return false }
            off += r
        }
        return true
    }

    func close() {
        lock.lock()
        if closedFlag { lock.unlock(); return }
        closedFlag = true
        lock.unlock()
        shutdown(fd, SHUT_RDWR)
        Darwin_close(fd)
    }
}

private func Darwin_close(_ fd: Int32) {
    #if canImport(Darwin)
    _ = Darwin.close(fd)
    #else
    _ = Glibc.close(fd)
    #endif
}

/// StreamRoad carries packets over connections that keep order, each framed as a 2-byte length and
/// the packet (spec §3): TCP (the fallback road where UDP is blocked) and the local socket. Connections
/// are made on demand and reused both ways; sessions do not depend on them.
public class StreamRoad: Road {
    public let name: String
    private let recv: Receiver
    private let lock = NSLock()
    private var conns = [String: Conn]() // by remote address as we know it
    let closed = AtomicFlag()
    private var pausedValue = false
    private let counters = Counters()

    fileprivate final class Conn {
        let addr: String
        let out = FrameQueue(limit: 1024)
        private let road: StreamRoad
        private let l = NSLock()
        private var link: Link?
        let stopped = AtomicFlag()

        init(_ road: StreamRoad, _ addr: String) { self.road = road; self.addr = addr }

        func stop() {
            if !stopped.setIfUnset() { return }
            l.lock(); let lk = link; l.unlock()
            lk?.close()
            out.nudge()
            road.remove(addr, self)
        }

        /// serve runs one connection: a writer thread and this reader.
        func serve(_ lk: Link) {
            l.lock(); link = lk; l.unlock()
            if stopped.value { lk.close(); return }
            spawn("p2pact-\(road.name)-w") { [self] in
                while !stopped.value {
                    guard let f = out.poll(timeout: 30, cancel: { self.stopped.value }) else { continue }
                    var all = f
                    for g in out.drain() { all.append(contentsOf: g) }
                    if !lk.write(all) { break }
                }
                stop()
            }
            let ep = Endpoint(road: road, addr: addr)
            while !stopped.value {
                guard let h = lk.readExact(2) else { break }
                let n = Int(h[0]) << 8 | Int(h[1])
                if n > MAX_PACKET + 64 { break }
                guard let pkt = lk.readExact(n) else { break }
                road.counters.received(2 + n)
                road.recv(pkt, ep)
            }
            stop()
        }
    }

    init(name: String, recv: @escaping Receiver) {
        self.name = name
        self.recv = recv
    }

    /// connect dials addr: nil — it did not answer. It runs on a thread of its own.
    func connect(_ addr: String) -> Link? { nil }

    fileprivate func remove(_ addr: String, _ c: Conn) {
        lock.lock()
        if conns[addr] === c { conns[addr] = nil }
        lock.unlock()
    }

    /// accepted serves a connection a listener took in; addr names it for answers.
    func accepted(addr: String, link: Link) {
        let c = Conn(self, addr)
        lock.lock()
        let old = conns.updateValue(c, forKey: addr)
        lock.unlock()
        old?.stop()
        spawn("p2pact-\(name)-r") { c.serve(link) }
    }

    public func stats() -> RoadStats { counters.snapshot() }

    /// paused: no connections (the node pauses); the listener stays and refuses them.
    public var paused: Bool {
        lock.lock(); defer { lock.unlock() }
        return pausedValue
    }

    /// send queues a packet to addr, dialing in the background if there is no connection.
    public func send(_ addr: String, _ pkt: Bytes) -> Bool {
        if pkt.count > MAX_PACKET + 64 || closed.value || paused { return false }
        lock.lock()
        var c = conns[addr]
        var fresh = false
        if c == nil || c!.stopped.value {
            c = Conn(self, addr)
            conns[addr] = c
            fresh = true
        }
        lock.unlock()
        let conn = c!
        if fresh { dial(conn) }
        var frame = Bytes()
        frame.reserveCapacity(2 + pkt.count)
        frame.append(UInt8(pkt.count >> 8 & 0xff))
        frame.append(UInt8(pkt.count & 0xff))
        frame.append(contentsOf: pkt)
        if !conn.out.offer(frame) { return false } // the queue is full
        counters.sent(frame.count)
        return true
    }

    private func dial(_ c: Conn) {
        spawn("p2pact-\(name)-dial") { [self] in
            if let l = connect(c.addr) { c.serve(l) } else { c.stop() }
        }
    }

    /// pause closes every connection and refuses new ones (true), or takes them again.
    public func pause(_ on: Bool) {
        lock.lock()
        pausedValue = on
        let all = Array(conns.values)
        lock.unlock()
        if on { for c in all { c.stop() } }
    }

    /// connections counts open connections (tests).
    public var connections: Int {
        lock.lock(); defer { lock.unlock() }
        return conns.count
    }

    public func close() {
        closed.set(true)
        lock.lock(); let all = Array(conns.values); lock.unlock()
        for c in all { c.stop() }
    }
}

/// Listener is an accept loop over a listening socket, polled so that close can stop it.
final class Listener {
    let fd: Int32
    private let stop = AtomicFlag()
    private let exited = DispatchSemaphore(value: 0)

    init(fd: Int32, name: String, onAccept: @escaping (Int32) -> Void) {
        self.fd = fd
        spawn(name) { [self] in
            while !stop.value {
                if !waitReadable(fd, 200) { continue }
                let c = accept(fd, nil, nil)
                if c < 0 { continue }
                noSigpipe(c)
                onAccept(c)
            }
            Darwin_close(fd)
            exited.signal()
        }
    }

    func close() {
        if stop.setIfUnset() { _ = exited.wait(timeout: .now() + 2) }
    }
}

/// TcpRoad is the fallback road where UDP is blocked (spec §3): a 2-byte length, then the
/// packet. Connections are made on demand and reused both ways; sessions do not depend on them.
public final class TcpRoad: StreamRoad {
    private var listener: Listener?
    private var bound: SockAddr?

    /// bind "" — dial only.
    init(bind: String, recv: @escaping Receiver) throws {
        super.init(name: "tcp", recv: recv)
        if bind.isEmpty { return }
        let (host, port) = bindParts(bind)
        let cands = listenAddrs(host: host, port: port, type: SOCK_STREAM)
        if cands.isEmpty { throw P2pactIOError("cannot resolve \(bind)") }
        guard let (s, sa) = bindFirst(cands, SOCK_STREAM, prepare: { setIntOpt($0, SOL_SOCKET, SO_REUSEADDR, 1) }) else {
            throw P2pactIOError("cannot listen on \(bind): \(String(cString: strerror(errno)))")
        }
        if listen(s, 128) != 0 {
            let e = errno
            Darwin_close(s)
            throw P2pactIOError("cannot listen on \(bind): \(String(cString: strerror(e)))")
        }
        bound = localName(s) ?? sa
        listener = Listener(fd: s, name: "p2pact-tcp-accept") { [unowned self] c in
            if self.paused { Darwin_close(c); return }
            var ss = sockaddr_storage()
            var l = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let r = withUnsafeMutablePointer(to: &ss) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(c, $0, &l) }
            }
            let peer = r == 0 ? SockAddr(storage: ss, len: l).text : "tcp-\(c)"
            self.accepted(addr: peer, link: self.link(c))
        }
    }

    private func link(_ fd: Int32) -> Link {
        setIntOpt(fd, Int32(IPPROTO_TCP), TCP_NODELAY, 1)
        var tv = timeval(tv_sec: 180, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        return Link(fd: fd)
    }

    override func connect(_ addr: String) -> Link? {
        guard let (h, p) = hostPort(addr) else { return nil }
        let fd = tcpConnect(h, p, timeout: 10_000)
        return fd < 0 ? nil : link(fd)
    }

    /// localAddr is the listen address ("" — dial only).
    public var localAddr: String { bound?.text ?? "" }

    func localAddrs() -> [String] {
        guard let b = bound, let (h, p) = hostPort(b.text) else { return [] }
        return P2PACT.localAddrs(host: h, port: p)
    }

    public override func close() {
        closed.set(true)
        listener?.close()
        super.close()
    }
}
