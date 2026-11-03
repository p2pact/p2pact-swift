import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// The local socket road (spec §3): programs on the same computer (a plugin, a CLI, an MCP server)
// talk to the node with the same packets over a stream socket, framed as on TCP. The node
// listens; a program dials. Only the device's own OS user may open the socket (mode 0600);
// trust still comes from pairing.

private func unixAddr(_ path: String) -> SockAddr? {
    var sun = sockaddr_un()
    sun.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(path.utf8)
    let cap = MemoryLayout.size(ofValue: sun.sun_path)
    if bytes.isEmpty || bytes.count >= cap { return nil }
    withUnsafeMutableBytes(of: &sun.sun_path) { p in
        for (i, b) in bytes.enumerated() { p[i] = b }
        p[bytes.count] = 0
    }
    var ss = sockaddr_storage()
    memcpy(&ss, &sun, MemoryLayout<sockaddr_un>.size)
    return SockAddr(storage: ss, len: socklen_t(MemoryLayout<sockaddr_un>.size))
}

private func unixConnect(_ path: String) -> Int32 {
    guard let sa = unixAddr(path) else { return -1 }
    let fd = openSocket(AF_UNIX, SOCK_STREAM)
    if fd < 0 { return -1 }
    if sa.with({ connect(fd, $0, $1) }) != 0 {
        _ = Darwin_closeFd(fd)
        return -1
    }
    return fd
}

private func Darwin_closeFd(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
    return Darwin.close(fd)
    #else
    return Glibc.close(fd)
    #endif
}

/// LocalRoad is the local socket road: a stream road over a Unix domain socket.
final class LocalRoad: StreamRoad {
    private var listener: Listener?
    private let path: String?
    private let seqLock = NSLock()
    private var seq = 0

    private init(recv: @escaping Receiver, listenPath: String?) throws {
        path = listenPath
        super.init(name: "local", recv: recv)
        guard let p = listenPath else { return }
        guard let sa = unixAddr(p) else { throw P2pactIOError("bad socket path \(p)") }
        let s = openSocket(AF_UNIX, SOCK_STREAM)
        if s < 0 { throw P2pactIOError("cannot open a socket") }
        if sa.with({ sysBind(s, $0, $1) }) != 0 || chmod(p, 0o600) != 0 || sysListen(s, 64) != 0 {
            let e = errno
            _ = Darwin_closeFd(s)
            unlink(p)
            throw P2pactIOError("cannot listen on \(p): \(String(cString: strerror(e)))")
        }
        listener = Listener(fd: s, name: "p2pact-local-accept") { [unowned self] c in
            if self.paused { _ = Darwin_closeFd(c); return }
            // peers of a unix socket have no address: number them
            self.seqLock.lock(); self.seq += 1; let n = self.seq; self.seqLock.unlock()
            self.accepted(addr: "local-\(n)", link: Link(fd: c))
        }
    }

    override func connect(_ addr: String) -> Link? {
        let fd = unixConnect(addr)
        return fd < 0 ? nil : Link(fd: fd)
    }

    override func close() {
        closed.set(true)
        listener?.close()
        if let p = path { unlink(p) }
        super.close()
    }

    /// listen opens the socket at path (mode 0600). An old socket file nobody listens on is replaced.
    static func listen(_ path: String, _ recv: @escaping Receiver) throws -> LocalRoad {
        if path.isEmpty { throw P2pactIOError("no socket path") }
        var st = stat()
        if lstat(path, &st) == 0 {
            if st.st_mode & S_IFMT != S_IFSOCK { throw P2pactIOError("\(path) is not a socket") }
            let probe = unixConnect(path)
            if probe >= 0 {
                _ = Darwin_closeFd(probe)
                throw P2pactIOError("\(path) is in use")
            }
            unlink(path)
        }
        return try LocalRoad(recv: recv, listenPath: path)
    }

    /// dialer makes a road that dials only: the node does not listen.
    static func dialer(_ recv: @escaping Receiver) -> LocalRoad {
        try! LocalRoad(recv: recv, listenPath: nil)
    }
}

private func sysListen(_ fd: Int32, _ n: Int32) -> Int32 {
    #if canImport(Darwin)
    return Darwin.listen(fd, n)
    #else
    return Glibc.listen(fd, n)
    #endif
}
