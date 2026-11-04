import XCTest
@testable import P2PACT

final class Inbox {
    private let c = NSCondition()
    private var items = [(Bytes, Endpoint)]()
    func put(_ b: Bytes, _ e: Endpoint) { c.lock(); items.append((b, e)); c.broadcast(); c.unlock() }
    func take(timeout: TimeInterval = 5) -> (Bytes, Endpoint)? {
        let d = Date().addingTimeInterval(timeout)
        c.lock(); defer { c.unlock() }
        while items.isEmpty { if !c.wait(until: d) { return nil } }
        return items.removeFirst()
    }
}

final class RoadsTests: XCTestCase {
    func testHostPort() {
        XCTAssertEqual(hostPort("1.2.3.4:80")?.0, "1.2.3.4")
        XCTAssertEqual(hostPort("[::1]:81")?.0, "::1")
        XCTAssertEqual(hostPort("[::1]:81")?.1, 81)
        XCTAssertNil(hostPort("nope"))
    }

    func testUdpLoopbackEcho() throws {
        let ia = Inbox(), ib = Inbox()
        let a = try UdpRoad(bind: "127.0.0.1:0") { ia.put($0, $1) }
        let b = try UdpRoad(bind: "127.0.0.1:0") { ib.put($0, $1) }
        defer { a.close(); b.close() }
        XCTAssertTrue(a.localAddr.hasPrefix("127.0.0.1:"))
        XCTAssertFalse(a.localAddr.hasSuffix(":0"))
        XCTAssertTrue(a.send(b.localAddr, [1, 2, 3]))
        let (pkt, ep) = try XCTUnwrap(ib.take())
        XCTAssertEqual(pkt, [1, 2, 3])
        XCTAssertEqual(ep.addr, a.localAddr)
        XCTAssertEqual(ep.key, "udp|" + a.localAddr)
        XCTAssertTrue(b.send(ep.addr, [9, 8]))
        XCTAssertEqual(ia.take()?.0, [9, 8])
        XCTAssertEqual(a.localAddrs(), [a.localAddr])
        let all = try UdpRoad(bind: ":0") { _, _ in }
        defer { all.close() }
        XCTAssertTrue(all.localAddr.hasPrefix("[::]:") || all.localAddr.hasPrefix("0.0.0.0:")) // dual stack, IPv4 only without IPv6
        let v6 = try UdpRoad(bind: "[::1]:0") { _, _ in }
        defer { v6.close() }
        XCTAssertTrue(v6.localAddr.hasPrefix("[::1]:"))
        XCTAssertTrue(a.send("localhost:\(hostPort(b.localAddr)!.1)", [7]))
        XCTAssertEqual(ib.take()?.0, [7])
    }

    func testTcpTwoNodes() throws {
        let ia = Inbox(), ib = Inbox()
        let a = try TcpRoad(bind: "127.0.0.1:0") { ia.put($0, $1) }
        let b = try TcpRoad(bind: "") { ib.put($0, $1) }
        defer { a.close(); b.close() }
        XCTAssertEqual(b.localAddr, "")
        XCTAssertTrue(b.send(a.localAddr, [1, 2, 3]))
        let (pkt, ep) = try XCTUnwrap(ia.take())
        XCTAssertEqual(pkt, [1, 2, 3])
        // answer over the same connection
        XCTAssertTrue(a.send(ep.addr, [4, 5]))
        XCTAssertEqual(ib.take()?.0, [4, 5])
        for i in 0..<50 { XCTAssertTrue(b.send(a.localAddr, [UInt8(i)])) }
        for i in 0..<50 { XCTAssertEqual(ia.take()?.0, [UInt8(i)]) }
        XCTAssertEqual(b.connections, 1)
        XCTAssertFalse(b.send(a.localAddr, Bytes(repeating: 0, count: MAX_PACKET + 65)))
        b.pause(true)
        XCTAssertFalse(b.send(a.localAddr, [1]))
        XCTAssertEqual(b.connections, 0)
        b.pause(false)
        XCTAssertTrue(b.send(a.localAddr, [6]))
        XCTAssertEqual(ia.take()?.0, [6])
        // dialing nothing fails quietly
        XCTAssertTrue(b.send("127.0.0.1:1", [1]))
        Thread.sleep(forTimeInterval: 0.5)
    }

    func testLocalRoad() throws {
        let dir = NSTemporaryDirectory() + "p2pact-" + UUID().uuidString.prefix(6)
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/n.sock"
        let is_ = Inbox(), ic = Inbox()
        let server = try LocalRoad.listen(path) { is_.put($0, $1) }
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertThrowsError(try LocalRoad.listen(path) { _, _ in })
        let client = LocalRoad.dialer { ic.put($0, $1) }
        XCTAssertEqual(client.name, "local")
        XCTAssertTrue(client.send(path, [1, 2]))
        let (pkt, ep) = try XCTUnwrap(is_.take())
        XCTAssertEqual(pkt, [1, 2])
        XCTAssertTrue(server.send(ep.addr, [3]))
        XCTAssertEqual(ic.take()?.0, [3])
        client.close(); server.close()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        // a stale socket file is replaced
        let s1 = try LocalRoad.listen(path) { _, _ in }
        s1.close()
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var sun = sockaddr_un(); sun.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &sun.sun_path) { p in for (i, b) in path.utf8.enumerated() { p[i] = b } }
        _ = withUnsafePointer(to: &sun) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        Darwin.close(fd)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        let s2 = try LocalRoad.listen(path) { _, _ in }
        s2.close()
    }

    func testAttachedStream() {
        let got = Inbox()
        let sent = Inbox()
        final class App: AppRoad {
            let box: Inbox
            init(_ b: Inbox) { box = b }
            func send(_ b: Bytes) throws { box.put(b, Endpoint(road: Dummy.shared, addr: "")) }
        }
        let road = AttachedRoad(app: App(sent), config: AppRoadConfig(name: "ble", stream: true, mtu: 20), peer: nil,
                                deliver: { got.put($0, $1) }, onDetach: { _ in })
        XCTAssertEqual(road.name, "app:ble")
        XCTAssertEqual(road.rate, Double(DEFAULT_APP_RATE))
        // out: 50-byte packet -> 52-byte frame in pieces of <= 20
        XCTAssertTrue(road.send("", Bytes(repeating: 7, count: 50)))
        var total = Bytes()
        while total.count < 52, let (p, _) = sent.take(timeout: 2) { XCTAssertLessThanOrEqual(p.count, 20); total += p }
        XCTAssertEqual(total.count, 52)
        XCTAssertEqual(total[0], 0); XCTAssertEqual(total[1], 50)
        // in: the same stream, plus another frame, in 20-byte pieces
        let stream = total + [0, 3, 1, 2, 3]
        var at = 0
        while at < stream.count { road.receive(Bytes(stream[at..<min(at + 20, stream.count)])); at += 20 }
        XCTAssertEqual(got.take()?.0, Bytes(repeating: 7, count: 50))
        XCTAssertEqual(got.take()?.0, [1, 2, 3])
        // damaged length: dropped, then it recovers on fresh framing
        road.receive([0xff, 0xff, 1, 2, 3])
        XCTAssertNil(got.take(timeout: 0.2))
        road.receive([0, 1, 9])
        XCTAssertEqual(got.take()?.0, [9])
        road.detach()
        XCTAssertTrue(road.isDetached)
        XCTAssertFalse(road.send("", [1]))
    }

    func testAttachedDatagram() {
        let got = Inbox()
        let road = AttachedRoad(app: Null(), config: AppRoadConfig(stream: false, mtu: MAX_ROAD_PACKET, rate: 1000), peer: "p",
                                deliver: { got.put($0, $1) }, onDetach: { _ in })
        XCTAssertEqual(road.rate, 1000)
        road.receive([1, 2])
        XCTAssertEqual(got.take()?.0, [1, 2])
        road.detach()
    }
}

final class Dummy: Road {
    static let shared = Dummy()
    let name = "dummy"
    func send(_ addr: String, _ pkt: Bytes) -> Bool { true }
}
final class Null: AppRoad { func send(_ b: Bytes) throws {} }

final class RelayLiveTests: XCTestCase {
    func testRelayPinned() throws {
        guard let fp = ProcessInfo.processInfo.environment["RELAY_FP"] else { throw XCTSkip("no relay") }
        let ia = Inbox(), ib = Inbox()
        let hint = RelayHint(addr: "127.0.0.1:18443", fp: fp)
        let a = RelayRoad(hint: hint) { ia.put($0, $1) }
        let b = RelayRoad(hint: hint) { ib.put($0, $1) }
        defer { a.close(); b.close() }
        let ch = String(repeating: "ab", count: 16)
        a.join(ch, "a"); b.join(ch, "b")
        XCTAssertEqual(a.open, 1)
        Thread.sleep(forTimeInterval: 1)
        XCTAssertTrue(a.send(ch, [1, 2, 3]))
        XCTAssertEqual(ib.take()?.0, [1, 2, 3])
        XCTAssertTrue(b.send(ch, [4]))
        XCTAssertEqual(ia.take()?.0, [4])
        let bad = RelayRoad(hint: RelayHint(addr: "127.0.0.1:18443", fp: String(repeating: "0", count: 64))) { _, _ in XCTFail() }
        bad.join(ch, "a")
        Thread.sleep(forTimeInterval: 1.5)
        bad.close()
        a.leave(ch)
        XCTAssertEqual(a.open, 0)
    }
}
