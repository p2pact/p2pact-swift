import XCTest
import Foundation
@testable import P2PACT

/// A relay's UDP side: it records the observe requests and answers them with the address it is told to.
final class FakeObserver {
    let road: UdpRoad
    private let l = NSLock()
    private var reqs = [(nonce: Bytes, from: String, size: Int)]()
    /// answer: the address to report ("ip:port", IPv4); nil — silent
    var answer: String?
    var answerNonceXor: UInt8 = 0

    init() throws {
        var me: FakeObserver?
        road = try UdpRoad(bind: "127.0.0.1:0") { p, e in me?.got(p, e) }
        me = self
    }

    private func got(_ p: Bytes, _ e: Endpoint) {
        guard p.first == UInt8(P_OBSERVE), p.count >= 17 else { return }
        let nonce = Bytes(p[1..<17])
        l.lock(); reqs.append((nonce, e.addr, p.count)); let a = answer; let x = answerNonceXor; l.unlock()
        if let a = a { _ = road.send(e.addr, FakeObserver.reply(nonce.map { $0 ^ x }, a)) }
    }

    static func reply(_ nonce: Bytes, _ addr: String) -> Bytes {
        let (h, p) = hostPort(addr)!
        let ip = h.split(separator: ".").map { UInt8($0)! }
        return [UInt8(P_OBSERVE)] + nonce + Bytes(repeating: 0, count: 10) + [0xff, 0xff] + ip + [UInt8(p >> 8), UInt8(p & 255)]
    }

    var requests: [(nonce: Bytes, from: String, size: Int)] { l.lock(); defer { l.unlock() }; return reqs }
    var hint: RelayHint { RelayHint(addr: road.localAddr, fp: "") }
    func close() { road.close() }
}

final class NatPunchTests: XCTestCase {
    private func node(_ name: String) throws -> Node {
        let n = try Node(dir: tempDir(), name: name)
        try n.listenUdp("127.0.0.1:0")
        n.start()
        return n
    }

    func testObserveCodec() {
        let nonce = Bytes((0..<16).map { UInt8($0 + 1) })
        let req = encodeObserve(nonce: nonce)
        XCTAssertEqual(req.count, 36)
        XCTAssertEqual(req[0], 8)
        XCTAssertEqual(Bytes(req[1..<17]), nonce)
        XCTAssertTrue(req[17...].allSatisfy { $0 == 0 })

        let rep = FakeObserver.reply(nonce, "203.0.113.7:40000")
        XCTAssertEqual(rep.count, 35)
        let d = decodeObserve(rep)
        XCTAssertEqual(d?.nonce, nonce)
        XCTAssertEqual(d?.addr, "203.0.113.7:40000")

        // IPv6, not mapped
        var v6 = [UInt8(8)] + nonce + [0x20, 0x01, 0x0d, 0xb8] + Bytes(repeating: 0, count: 11) + [1] + [0x1f, 0x90]
        XCTAssertEqual(decodeObserve(v6)?.addr, "[2001:db8::1]:8080")
        // malformed: size, type, zero port, unspecified address
        XCTAssertNil(decodeObserve(Bytes(rep.dropLast())))
        XCTAssertNil(decodeObserve(rep + [0]))
        var bad = rep; bad[0] = 6
        XCTAssertNil(decodeObserve(bad))
        bad = rep; bad[33] = 0; bad[34] = 0
        XCTAssertNil(decodeObserve(bad))
        v6.replaceSubrange(17..<33, with: Bytes(repeating: 0, count: 16))
        XCTAssertNil(decodeObserve(v6))
    }

    func testObserveRequestAndHints() throws {
        let saved = observeEvery
        observeEvery = 200 * MS
        defer { observeEvery = saved }
        let relay = try FakeObserver()
        defer { relay.close() }
        relay.answer = "203.0.113.7:40000"
        let a = try node("A")
        defer { a.close() }
        a.setRelay(relay.hint)
        eventually("observed") { a.reflexiveForTest() == "203.0.113.7:40000" }
        // the request came from the node's own UDP socket, 36 bytes
        let first = try XCTUnwrap(relay.requests.first)
        XCTAssertEqual(first.size, 36)
        XCTAssertEqual(first.from, a.udpAddr)
        // the reflexive address joins the local ones
        var udp = a.hintsForTest().udp
        XCTAssertTrue(udp.contains("203.0.113.7:40000"))
        XCTAssertTrue(udp.contains(a.udpAddr), "local addresses stay")
        // it changes: the old one is replaced
        relay.answer = "203.0.113.8:41000"
        eventually("changed") { a.reflexiveForTest() == "203.0.113.8:41000" }
        udp = a.hintsForTest().udp
        XCTAssertTrue(udp.contains("203.0.113.8:41000"))
        XCTAssertFalse(udp.contains("203.0.113.7:40000"))
        XCTAssertTrue(udp.contains(a.udpAddr))
        // repeated: asked again every observeEvery
        eventually("again") { relay.requests.count >= 3 }
        // without a relay the hints are what they were
        let b = try node("B")
        defer { b.close() }
        XCTAssertEqual(b.hintsForTest().udp, [b.udpAddr])
    }

    func testObserveReplyChecks() throws {
        let relay = try FakeObserver() // never answers on its own
        let rogue = Inbox()
        let other = try UdpRoad(bind: "127.0.0.1:0") { rogue.put($0, $1) }
        defer { relay.close(); other.close() }
        let a = try node("A")
        defer { a.close() }
        a.setRelay(relay.hint)
        eventually("request") { !relay.requests.isEmpty }
        let nonce = relay.requests[0].nonce
        let rep = FakeObserver.reply(nonce, "203.0.113.9:50000")
        // right nonce, but not from the relay's address
        _ = other.send(a.udpAddr, rep)
        // from the relay, wrong nonce
        _ = relay.road.send(a.udpAddr, FakeObserver.reply(nonce.map { $0 ^ 1 }, "203.0.113.9:50000"))
        // from the relay, wrong size
        _ = relay.road.send(a.udpAddr, Bytes(rep.dropLast()))
        Thread.sleep(forTimeInterval: 0.5)
        XCTAssertNil(a.reflexiveForTest())
        // the real one
        _ = relay.road.send(a.udpAddr, rep)
        eventually("accepted") { a.reflexiveForTest() == "203.0.113.9:50000" }
        // a nonce answers once
        _ = relay.road.send(a.udpAddr, FakeObserver.reply(nonce, "203.0.113.10:50001"))
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertEqual(a.reflexiveForTest(), "203.0.113.9:50000")
    }

    func testPausedNoObserve() throws {
        let saved = observeEvery
        observeEvery = 200 * MS
        defer { observeEvery = saved }
        let relay = try FakeObserver()
        defer { relay.close() }
        let a = try node("A")
        defer { a.close() }
        a.setPaused(true)
        a.setRelay(relay.hint)
        Thread.sleep(forTimeInterval: 1.5) // maintain runs, nothing goes
        XCTAssertEqual(relay.requests.count, 0)
        a.setPaused(false)
        eventually("observe on resume") { !relay.requests.isEmpty }
    }

    // MARK: bursts

    private func pairNodes() throws -> (Node, Node, String, String) {
        let a = try node("A"), b = try node("B")
        _ = try b.join(a.invite(ttlMs: 60_000))
        let aAddr = a.id.addr, bAddr = b.id.addr
        eventually("paired") { a.peer(bAddr) != nil && b.peer(aAddr) != nil }
        return (a, b, aAddr, bAddr)
    }

    func testBurstTriggersAndKeepalives() throws {
        let saved = observeEvery
        observeEvery = 200 * MS
        defer { observeEvery = saved }
        let (a, b, _, bAddr) = try pairNodes()
        defer { a.close(); b.close() }
        let relay = try FakeObserver()
        defer { relay.close() }
        a.setRelay(relay.hint)
        relay.answer = "203.0.113.1:1000"
        eventually("observed") { a.reflexiveForTest() != nil }
        // (a) the session is on a live direct road (loopback UDP): no burst
        XCTAssertFalse(a.burstActiveForTest(bAddr))

        // (a) not on a direct road, reflexive changes: burst
        a.leaveDirectForTest(bAddr)
        relay.answer = "203.0.113.2:2000"
        eventually("changed") { a.reflexiveForTest() == "203.0.113.2:2000" }
        // the other one's hints have our new address (the hello)
        XCTAssertTrue(a.burstActiveForTest(bAddr))
        a.burstClearForTest(bAddr)

        // (b) hello with changed UDP hints, session not direct: burst, and keepalives reach those addresses
        let got = Inbox()
        let target = try UdpRoad(bind: "127.0.0.1:0") { got.put($0, $1) }
        defer { target.close() }
        b.setPaused(true) // silent, so that nothing arrives from it and the burst runs its time
        Thread.sleep(forTimeInterval: 0.3)
        a.leaveDirectForTest(bAddr)
        a.helloHintsForTest(bAddr, Hints(udp: [target.localAddr]))
        XCTAssertTrue(a.burstActiveForTest(bAddr))
        var n = 0
        while let (p, _) = got.take(timeout: 1.0) {
            XCTAssertEqual(Int(p[0]), P_DATA)
            n += 1
            if n > 40 { break }
        }
        XCTAssertGreaterThanOrEqual(n, 8, "every 200 ms for 3 s")
        XCTAssertLessThanOrEqual(n, 20)
        XCTAssertFalse(a.burstActiveForTest(bAddr), "ends after 3 s")

        // (b) the same hints again: nothing changed, no burst
        a.leaveDirectForTest(bAddr)
        a.helloHintsForTest(bAddr, Hints(udp: [target.localAddr]))
        XCTAssertFalse(a.burstActiveForTest(bAddr))
    }

    func testBurstOnRelaySession() throws {
        let (a, b, _, bAddr) = try pairNodes()
        defer { a.close(); b.close() }
        // (c) a session established over a relay or an application road: burst
        a.sessionUpForTest(bAddr, Endpoint(road: Dummy.shared, addr: "x"))
        XCTAssertTrue(a.burstActiveForTest(bAddr))
        a.burstClearForTest(bAddr)
        // over UDP: none
        a.sessionUpForTest(bAddr, Endpoint(road: Dummy.shared, addr: "x").udpLike(a))
        XCTAssertFalse(a.burstActiveForTest(bAddr))
    }

    func testNoBurstWhilePaused() throws {
        let (a, b, _, bAddr) = try pairNodes()
        defer { a.close(); b.close() }
        a.leaveDirectForTest(bAddr)
        a.setPaused(true)
        a.sessionUpForTest(bAddr, Endpoint(road: Dummy.shared, addr: "x"))
        XCTAssertFalse(a.burstActiveForTest(bAddr))
        a.setPaused(false)
        a.sessionUpForTest(bAddr, Endpoint(road: Dummy.shared, addr: "x"))
        XCTAssertTrue(a.burstActiveForTest(bAddr))
        a.setPaused(true)
        XCTAssertFalse(a.burstActiveForTest(bAddr), "pause ends the burst")
    }
}

private extension Endpoint {
    /// an endpoint on a road that ranks as UDP (for the burst trigger test)
    func udpLike(_ n: Node) -> Endpoint { Endpoint(road: UdpNamed.shared, addr: "y") }
}

private final class UdpNamed: Road {
    static let shared = UdpNamed()
    let name = "udp"
    func send(_ addr: String, _ pkt: Bytes) -> Bool { true }
}
