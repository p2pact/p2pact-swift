// Interop peer for p2pact-tests: a P2PACT node driven by JSON lines on stdin, answering on stdout.
// Every implementation ships one, so any two can be tested against each other. The commands are those
// of p2pact-go/cmd/p2pact-interop (see p2pact-kotlin's Interop.kt for the list).
// Usage: p2pact-interop [data dir] [name]

import Darwin
import Foundation
import P2PACT

setvbuf(stdout, nil, _IOLBF, 0)

let args = CommandLine.arguments
let dir = args.count > 1 ? args[1] : NSTemporaryDirectory() + "p2pact-interop-\(UUID().uuidString)"
let node: Node
do {
    node = try Node(dir: dir, name: args.count > 2 ? args[2] : "swift")
} catch {
    FileHandle.standardError.write(Data("cannot start: \(error)\n".utf8))
    exit(1)
}

// 64.1 echoes; 64.2 echoes too but answers later: once a 64.1 call has run after it
let heldLock = NSLock()
var held: [Future<[Cbor.Value]>] = []
node.handle(64, 1) { _, args in
    guard let b = args.first?.asBytes ?? (args.isEmpty || args[0].isNull ? [] : nil) else { throw P2pactError(Errors.badArgs, "no data") }
    heldLock.lock()
    let hs = held
    held = []
    heldLock.unlock()
    for f in hs { f.complete([]) }
    return .values([.bytes(b)])
}
node.handle(64, 2) { _, args in
    guard let b = args.first?.asBytes else { throw P2pactError(Errors.badArgs, "no data") }
    let f = Future<[Cbor.Value]>()
    let out = Future<[Cbor.Value]>()
    heldLock.lock()
    held.append(f)
    heldLock.unlock()
    f.whenComplete { r in
        switch r {
        case .success: out.complete([.bytes(b)])
        case .failure(let e): out.fail(e)
        }
    }
    DispatchQueue.global().asyncAfter(deadline: .now() + 30) { f.fail(P2pactError(Errors.failed, "no call came behind")) }
    return .later(out)
}

var ownTools: [String: Int] = [:]
let eventsLock = NSLock()
var events: [[String: Any]] = []
node.onEvent = { peer, tool, ev, args in
    let d = args.first?.asBytes.map { b64s($0) } ?? ""
    let item: [String: Any] = ["peer": peer, "tool": node.peerToolName(peer, tool) ?? "", "event": ev, "data": d]
    eventsLock.lock(); events.append(item); eventsLock.unlock()
}
node.start()

func b64s(_ b: [UInt8]) -> String { Data(b).base64EncodedString() }
func unb(_ s: String?) -> [UInt8] { Data(base64Encoded: s ?? "").map { [UInt8]($0) } ?? [] }

func say(_ v: [String: Any]) {
    let d = try! JSONSerialization.data(withJSONObject: v, options: [])
    FileHandle.standardOutput.write(d + Data("\n".utf8))
}

func grantsIn(_ v: Any?) -> [Grant] {
    ((v as? [Any]) ?? []).compactMap { e in
        guard let l = e as? [Any], l.count >= 2, let t = l[0] as? String, let n = (l[1] as? NSNumber)?.intValue else { return nil }
        return Grant(t, n)
    }
}

func grantsOut(_ g: [Grant]?) -> [Any] { (g ?? []).map { [$0.tool, $0.level] as [Any] } }

struct DriverError: Error { let msg: String; let code: Int? }

/// A Bluetooth LE link stood in for by a TCP connection: send writes at most the MTU at a time, at the link's rate.
final class PipeLink: AppRoad {
    let fd: Int32
    let rate: Int
    private var free: Int64 = 0
    init(fd: Int32, rate: Int) { self.fd = fd; self.rate = rate }

    func send(_ b: [UInt8]) throws {
        if rate > 0 {
            let now = Int64(DispatchTime.now().uptimeNanoseconds)
            if free < now - 10_000_000 { free = now } // idle: the link starts now
            free += Int64(b.count) * 1_000_000_000 / Int64(rate)
            let wait = free - Int64(DispatchTime.now().uptimeNanoseconds)
            if wait > 2_000_000 { usleep(UInt32(wait / 1000)) }
        }
        var at = 0
        while at < b.count {
            let n = b[at...].withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            if n <= 0 { throw P2pactError(Errors.failed, "link write failed") }
            at += n
        }
    }
}

func splitHostPort(_ s: String) -> (String, UInt16) {
    let i = s.lastIndex(of: ":")!
    return (String(s[s.startIndex..<i]), UInt16(s[s.index(after: i)...])!)
}

func sockaddr4(_ host: String, _ port: UInt16) -> sockaddr_in {
    var a = sockaddr_in()
    a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    a.sin_family = sa_family_t(AF_INET)
    a.sin_port = port.bigEndian
    inet_pton(AF_INET, host == "localhost" ? "127.0.0.1" : host, &a.sin_addr)
    return a
}

func linkRoad(fd: Int32, peer: String?, cfg: AppRoadConfig) throws {
    var one: Int32 = 1
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    let road: AttachedRoad
    do { road = try node.attachRoad(peer: peer, road: PipeLink(fd: fd, rate: cfg.rate), config: cfg) } catch {
        close(fd)
        throw error
    }
    let t = Thread {
        var buf = [UInt8](repeating: 0, count: cfg.mtu)
        while true {
            let n = buf.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if n <= 0 { break }
            road.receive(Array(buf[0..<n]))
        }
        road.detach()
        close(fd)
    }
    t.start()
}

func callResult(_ f: Future<[Cbor.Value]>) throws -> [UInt8] {
    let res = try f.get()
    guard let b = res.first?.asBytes else { throw DriverError(msg: "invalid result", code: nil) }
    return b
}

func handle(_ req: [String: Any]) throws {
    func str(_ k: String) -> String { req[k] as? String ?? "" }
    func num(_ k: String) -> Int { (req[k] as? NSNumber)?.intValue ?? 0 }
    switch req["cmd"] as? String ?? "" {
    case "listen":
        if let u = req["udp"] as? String, !u.isEmpty { try node.listenUdp(u) }
        if let t = req["tcp"] as? String { try node.listenTcp(t) }
        if let r = req["relay"] as? String { node.setRelay(RelayHint(addr: r, fp: req["fp"] as? String ?? "")) }
        say(["addr": node.id.addr, "udp": node.udpAddr, "tcp": node.tcpAddr])
    case "relay":
        node.setRelay(RelayHint(addr: str("addr"), fp: str("fp")))
        node.setRelayWS((req["ws"] as? [Any])?.compactMap { $0 as? String } ?? [])
        say(["ok": true])
    case "advertise": // {"hints":{"udp":[…],"tcp":[…]}} instead of our own addresses; no hints — our own again
        if let h = req["hints"] as? [String: Any] {
            func list(_ k: String) -> [String] { (h[k] as? [Any])?.compactMap { $0 as? String } ?? [] }
            node.setAdvertise(Hints(udp: list("udp"), tcp: list("tcp")))
        } else {
            node.setAdvertise(nil)
        }
        say(["ok": true])
    case "paths":
        say(["paths": node.paths(str("peer"))])
    case "invite":
        say(["invite": node.invite(ttlMs: 600_000).string])
    case "join":
        let wants: [Grant]? = req["wants"] != nil ? grantsIn(req["wants"]) : nil
        let p = try node.join(try Invite.parse(str("invite")), timeoutMs: 15_000, wants: wants)
        say(["peer": p.addr])
    case "known":
        say(["known": node.peer(str("peer")) != nil])
    case "call":
        let stream = Int64(num("stream"))
        let b = try callResult(node.callOn(str("peer"), stream: stream, 64, 1, [.bytes(unb(req["data"] as? String))], timeoutMs: 60_000))
        say(["data": b64s(b)])
    case "later":
        let stream = Int64(num("stream"))
        let peer = str("peer")
        let first = node.callOn(peer, stream: stream, 64, 2, [.bytes(unb(req["data"] as? String))], timeoutMs: 20_000)
        usleep(100_000) // the held call goes first
        do { _ = try node.callOn(peer, stream: stream, 64, 1, [.bytes(Array("behind".utf8))], timeoutMs: 10_000).get() } catch {
            throw DriverError(msg: "the call behind the held one: \(error)", code: nil)
        }
        say(["data": b64s(try callResult(first))])
    case "dict":
        try node.addDict(unb(req["raw"] as? String))
        say(["ok": true])
    case "dict-state":
        let st = node.dictState(str("peer"))
        say(["own": st.own.map { b64s($0) } as Any? ?? NSNull(), "using": st.using.map { b64s($0) } as Any? ?? NSNull(), "training": st.training])
    case "road":
        let cfg = AppRoadConfig(name: "ble", stream: true, mtu: num("mtu"), rate: num("rate"))
        if let listen = req["listen"] as? String {
            let (host, port) = splitHostPort(listen)
            let ls = socket(AF_INET, SOCK_STREAM, 0)
            var one: Int32 = 1
            setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
            var a = sockaddr4(host, port)
            let rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(ls, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            if rc != 0 || Darwin.listen(ls, 1) != 0 { throw DriverError(msg: "cannot listen on \(listen)", code: nil) }
            var bound = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(ls, $0, &len) } }
            Thread {
                let c = accept(ls, nil, nil)
                close(ls)
                if c >= 0 { try? linkRoad(fd: c, peer: nil, cfg: cfg) }
            }.start()
            say(["road": "\(host):\(UInt16(bigEndian: bound.sin_port))"])
        } else {
            let (host, port) = splitHostPort(str("dial"))
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            var a = sockaddr4(host, port)
            let rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            if rc != 0 { throw DriverError(msg: "cannot dial \(str("dial"))", code: nil) }
            try linkRoad(fd: fd, peer: req["peer"] as? String, cfg: cfg)
            say(["ok": true])
        }
    case "kind":
        node.kind = num("kind")
        say(["ok": true])
    case "peer-info":
        let peer = str("peer")
        let number: Any = (req["tool"] as? String).flatMap { node.toolNumber(peer, $0) } as Any? ?? NSNull()
        say(["kind": node.peer(peer)?.kind ?? 0, "tools": node.peerTools(peer), "number": number])
    case "tool":
        let name = str("name")
        let n = try node.registerTool(name, 1)
        ownTools[name] = n
        let echo: Handler = { _, args in .values([args.at(0)]) }
        try node.handleTool(name, 1, echo)
        try node.handleTool(name, 2, echo)
        try node.handleTool(name, 3) { _, _ in .values([.bytes(Array(name.utf8))]) }
        node.markRead(n, 1, 3)
        say(["number": n])
    case "call-tool":
        let stream = Int64(num("stream"))
        let f = node.callToolOn(str("peer"), stream: stream, str("name"), num("method"), [.bytes(unb(req["data"] as? String))], timeoutMs: 60_000)
        do {
            say(["data": b64s(try callResult(f))])
        } catch {
            if let pe = error as? P2pactError { say(["error": pe.text, "code": pe.code]) } else { say(["error": "\(error)"]) }
        }
    case "grant":
        try node.grant(str("peer"), str("tool"), num("level"))
        say(["ok": true])
    case "set-grants":
        try node.setGrants(str("peer"), grantsIn(req["grants"]))
        say(["ok": true])
    case "grants":
        let peer = str("peer")
        say(["allowed": grantsOut(node.grants(peer)), "granted": grantsOut(node.grantedBy(peer))])
    case "emit":
        guard let n = ownTools[str("name")] else { throw DriverError(msg: "no such tool", code: nil) }
        try node.event(str("peer"), n, num("event"), [.bytes(unb(req["data"] as? String))])
        say(["ok": true])
    case "events":
        eventsLock.lock()
        let e = events
        eventsLock.unlock()
        say(["events": e])
    case "on-wants":
        let cap = num("level")
        node.onWants = { _, wants in wants.map { Grant($0.tool, min($0.level, cap)) } }
        say(["ok": true])
    case "local":
        if let l = req["listen"] as? String { try node.listenLocal(l) } else { try node.useLocal(str("use")) }
        say(["ok": true])
    case "plugin-env":
        let env = try node.pluginEnv(ttlMs: 600_000, grants: grantsIn(req["grants"]))
        var m: [String: String] = [:]
        for kv in env {
            let i = kv.firstIndex(of: "=")!
            m[String(kv[kv.startIndex..<i])] = String(kv[kv.index(after: i)...])
        }
        say(["socket": m[ENV_SOCKET] ?? "", "invite": m[ENV_INVITE] ?? ""])
    case "proxy":
        let name = str("name")
        let plugin = str("plugin")
        try node.handleToolAll(name) { _, level, method, args in
            if method == 2 && level < LEVEL_WRITE { throw P2pactError(Errors.forbidden, "forbidden") }
            return .values(try node.callToolOn(plugin, name, method, args, timeoutMs: 20_000).get())
        }
        say(["ok": true])
    // via a third device (spec §3)
    case "hide": // announce no addresses from now on: known devices reach us over roads they have, or through a forwarder
        node.setAdvertise(Hints())
        say(["ok": true])
    case "forward":
        try node.allowForward(str("a"), str("b"), req["on"] as? Bool ?? false)
        say(["ok": true])
    case "paths":
        say(["paths": node.paths(str("peer"))])
    case "forward-stats":
        let st = node.forwardStats()
        say(["forwarded": st.forwarded, "dropped": st.dropped])
    case "close":
        node.close()
        exit(0)
    default:
        say(["error": "unknown command \(str("cmd"))"])
    }
}

while let line = readLine() {
    if line.trimmingCharacters(in: .whitespaces).isEmpty { continue }
    guard let req = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any] else {
        say(["error": "bad json"])
        continue
    }
    do {
        try handle(req)
    } catch let e as DriverError {
        say(["error": e.msg])
    } catch let e as P2pactError {
        say(["error": e.text])
    } catch {
        say(["error": "\(error)"])
    }
}
node.close()
exit(0)
