import XCTest
import Foundation
@testable import P2PACT

/// Via a third device (spec §3): A and B reach each other only through X.
final class ForwardTests: XCTestCase {
    private var nodes: [Node] = []

    override func tearDown() {
        for n in nodes { n.close() }
        nodes = []
        super.tearDown()
    }

    private func node(_ name: String, udp: Bool = true, dir: String = tempDir(), start: Bool = true) throws -> Node {
        let n = try Node(dir: dir, name: name)
        n.noLearning = true
        if udp { try n.listenUdp("127.0.0.1:0") }
        n.handle(64, 1) { _, args in .values([args.at(0)]) }
        if start { n.start() }
        nodes.append(n)
        return n
    }

    /// pair: joiner joins owner's invite, so it knows where owner is.
    private func pair(_ owner: Node, _ joiner: Node) throws {
        _ = try joiner.join(owner.invite(ttlMs: 60_000))
        eventually("\(owner.name) knows \(joiner.name)") { owner.peer(joiner.id.addr) != nil }
    }

    private func friends(_ p: Node, _ q: Node) throws {
        try p.befriend(Peer(addr: q.id.addr, key: q.id.key.publicKey, name: q.name, pairSecret: [], hints: Hints()))
        try q.befriend(Peer(addr: p.id.addr, key: p.id.key.publicKey, name: p.name, pairSecret: [], hints: Hints()))
    }

    private func echo(_ from: Node, _ to: Node, _ msg: Bytes, timeout: Int64 = 10_000, file: StaticString = #filePath, line: UInt = #line) {
        do {
            let res = try from.call(to.id.addr, 64, 1, [.bytes(msg)], timeoutMs: timeout).get()
            XCTAssertEqual(res.at(0).asBytes, msg, "\(from.name) → \(to.name): wrong echo", file: file, line: line)
        } catch {
            XCTFail("\(from.name) → \(to.name): \(error)", file: file, line: line)
        }
    }

    private func unreachable(_ from: Node, _ to: Node, file: StaticString = #filePath, line: UInt = #line) {
        if (try? from.call(to.id.addr, 64, 1, [.bytes(Bytes("hi".utf8))], timeoutMs: 2000).get()) != nil {
            XCTFail("\(from.name) reached \(to.name)", file: file, line: line)
        }
    }

    /// three: A and B trust each other but cannot reach each other — they know no address of the other and announce
    /// none — while both are paired with X over UDP.
    private func three(xDir: String = tempDir()) throws -> (Node, Node, Node) {
        let a = try node("A"), x = try node("X", dir: xDir), b = try node("B")
        a.setAdvertise(Hints())
        b.setAdvertise(Hints())
        try pair(x, a)
        try pair(x, b)
        try friends(a, b)
        return (a, x, b)
    }

    /// Tap records what X forwards.
    private final class Tap {
        private let lock = NSLock()
        private var pkts: [Bytes] = []
        init(_ x: Node) { x.setForwardTap { [weak self] _, _, pkt in self?.add(pkt) } }
        private func add(_ p: Bytes) { lock.lock(); pkts.append(p); lock.unlock() }
        var count: Int { lock.lock(); defer { lock.unlock() }; return pkts.count }
        func contains(_ b: Bytes) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return pkts.contains { p in p.count >= b.count && (0...(p.count - b.count)).contains { i in Bytes(p[i..<i + b.count]) == b } }
        }
    }

    /// forge sends X an event 0.7 for B by hand.
    private func forge(_ a: Node, _ x: Node, _ b: Node) throws {
        try a.event(x.id.addr, 0, EV_FORWARD, [.bytes(addrBytes(b.id.addr)!), .bytes([UInt8(P_INIT)] + randomBytes(200))])
    }

    // A and B, which cannot reach each other, set up a session through X and talk both ways — calls, events, a long
    // message; X carries only ciphertext.
    func testForwardViaThirdDevice() throws {
        let xDir = tempDir()
        let (a, x, b) = try three(xDir: xDir)
        let tap = Tap(x)
        try x.allowForward(a.id.addr, b.id.addr, true)
        XCTAssertEqual(x.forwards(a.id.addr), [b.id.addr])
        eventually("A hears X forwards to B") { a.forwarders(b.id.addr) == [x.id.addr] }

        let marker = Bytes("plaintext-marker-that-X-must-never-see".utf8)
        let msg = Bytes(repeating: UInt8(ascii: "."), count: 100) + marker
        echo(a, b, msg)
        echo(b, a, msg)
        XCTAssertEqual(a.paths(b.id.addr), ["via:" + x.id.addr])
        XCTAssertEqual(b.paths(a.id.addr), ["via:" + x.id.addr])

        let long = randomBytes(40 << 10)
        echo(a, b, long, timeout: 20_000)
        echo(b, a, long, timeout: 20_000)

        let lock = NSLock()
        var seen = Set<String>()
        for n in [a, b] {
            n.onEvent = { _, _, _, args in
                lock.lock(); seen.insert(args.at(0).asString ?? ""); lock.unlock()
            }
        }
        try a.event(b.id.addr, 64, 3, [.text("to B")])
        try b.event(a.id.addr, 64, 3, [.text("to A")])
        eventually("events both ways", timeout: 5) { lock.lock(); defer { lock.unlock() }; return seen == ["to A", "to B"] }

        XCTAssertGreaterThan(tap.count, 0, "X forwarded nothing")
        XCTAssertFalse(tap.contains(marker), "X saw the plaintext")
        XCTAssertGreaterThan(x.forwardStats().forwarded, 0, "no forwarded packets counted")
        x.trust.flush()
        XCTAssertEqual(Trust(dir: xDir).get(a.id.addr)?.forward, [b.id.addr], "the consent is kept with the trusted list")
    }

    // X forwards nothing for a pair it was not opted in for, nor to a device it does not trust, and stops when it
    // forgets one of the two.
    func testForwardRefused() throws {
        let (a, x, b) = try three()
        let tap = Tap(x)

        // not opted in: no road via X, and a forged 0.7 is dropped
        unreachable(a, b)
        try forge(a, x, b)
        eventually("X drops the forged packet") { x.forwardStats().dropped > 0 }
        XCTAssertEqual(tap.count, 0, "X forwarded without consent")

        // only between devices X trusts, never to itself
        let stranger = try node("S", udp: false)
        XCTAssertThrowsError(try x.allowForward(a.id.addr, stranger.id.addr, true), "X agreed to forward to a device it does not trust")
        XCTAssertThrowsError(try x.allowForward(a.id.addr, x.id.addr, true), "X agreed to forward to itself")

        // opted in, then X forgets B: A learns it, and X forwards nothing more
        try x.allowForward(a.id.addr, b.id.addr, true)
        echo(a, b, Bytes("through X".utf8))
        x.forget(b.id.addr)
        eventually("A hears X no longer forwards to B") { a.forwarders(b.id.addr).isEmpty }
        let before = tap.count
        let dropped = x.forwardStats().dropped
        try forge(a, x, b)
        eventually("X drops a packet for a device it forgot") { x.forwardStats().dropped > dropped }
        XCTAssertEqual(tap.count, before, "X forwarded to a device it forgot")
    }

    // Withdrawing the consent stops forwarding and tells both devices.
    func testForwardWithdrawn() throws {
        let (a, x, b) = try three()
        try x.allowForward(a.id.addr, b.id.addr, true)
        echo(a, b, Bytes("through X".utf8))
        try x.allowForward(b.id.addr, a.id.addr, false)
        eventually("both hear X no longer forwards") { a.forwarders(b.id.addr).isEmpty && b.forwarders(a.id.addr).isEmpty }
        let dropped = x.forwardStats().dropped
        try forge(a, x, b)
        eventually("X drops the packet") { x.forwardStats().dropped > dropped }
    }

    // The rate limit: a direction may send a burst, then only its rate; what is over the rate waits, up to a burst, and
    // goes as the bucket refills; past that it is dropped.
    func testForwardBucket() throws {
        let a = try node("A", udp: false, start: false), b = try node("B", udp: false, start: false)
        let n = try node("X", udp: false, start: false)
        try n.befriend(Peer(addr: a.id.addr, key: a.id.key.publicKey, name: "A", pairSecret: [], hints: Hints()))
        try n.befriend(Peer(addr: b.id.addr, key: b.id.key.publicKey, name: "B", pairSecret: [], hints: Hints()))
        n.forwardRate = 1000
        let now = Clock.nanos()
        var offered = 0
        while n.fwdOfferForTest("a>b", b.id.addr, 1000, now) { offered += 1 }
        let burst = Int64(FORWARD_BURST / 1000)
        XCTAssertEqual(n.forwardStats().forwarded, burst)
        XCTAssertEqual(Int64(offered), 2 * burst)
        n.fwdReleaseForTest(now + 400 * MS) // 536 left + 400: not enough
        XCTAssertEqual(n.forwardStats().forwarded, burst, "more than the rate")
        n.fwdReleaseForTest(now + 2100 * MS)
        XCTAssertEqual(n.forwardStats().forwarded, burst + 2, "the rate refills")
        XCTAssertTrue(n.fwdOfferForTest("b>a", a.id.addr, 1000, now), "the other direction has its own bucket")
        XCTAssertEqual(n.forwardStats().forwarded, burst + 3)
    }

    func testAddrBytes() throws {
        let n = try node("A", udp: false, start: false)
        let b = try XCTUnwrap(addrBytes(n.id.addr))
        XCTAssertEqual(b.count, 16)
        XCTAssertEqual(addrText(b), n.id.addr)
        XCTAssertNil(addrBytes("nonsense"))
        XCTAssertNil(addrBytes(String(repeating: "1", count: 26)))
        XCTAssertEqual(forwardStream(Bytes(repeating: 0, count: 16)), 1)
        XCTAssertEqual(forwardStream(Bytes(repeating: 0xff, count: 16)), -1) // the high bit: a uvarint of 10 bytes on the wire
    }

    // One hop only: X reaches B only through Y, so it does not forward A's packets to B (no chains).
    func testForwardOneHop() throws {
        let a = try node("A"), x = try node("X"), y = try node("Y"), b = try node("B")
        a.setAdvertise(Hints())
        b.setAdvertise(Hints())
        try pair(y, x)
        try pair(y, b)
        try pair(x, a)
        x.setAdvertise(Hints()) // Y and A know where X is; B never learns it
        try friends(x, b)
        try friends(a, b)
        try y.allowForward(x.id.addr, b.id.addr, true)
        echo(x, b, Bytes("X to B through Y".utf8))
        try x.allowForward(a.id.addr, b.id.addr, true)
        eventually("A hears X forwards to B") { a.forwarders(b.id.addr).count == 1 }
        unreachable(a, b)
        let st = x.forwardStats()
        XCTAssertEqual(st.forwarded, 0, "X forwarded over a road via Y")
        XCTAssertGreaterThan(st.dropped, 0)
    }

    // A road via a third device gives way to a direct one as soon as it answers (spec §7).
    func testForwardGivesWayToDirect() throws {
        let old = probeEvery
        probeEvery = 300 * MS
        defer { probeEvery = old }
        let (a, x, b) = try three()
        try x.allowForward(a.id.addr, b.id.addr, true)
        echo(a, b, Bytes("through X".utf8))
        a.setAdvertise(nil) // A announces its UDP address again: B probes it
        eventually("the session moves to UDP", timeout: 20) {
            echo(b, a, Bytes("ping".utf8), timeout: 5000)
            return b.paths(a.id.addr).contains("udp")
        }
        let fw = x.forwardStats().forwarded
        for _ in 0..<20 { echo(a, b, Bytes("direct".utf8), timeout: 5000) }
        let carried = x.forwardStats().forwarded - fw
        XCTAssertLessThanOrEqual(carried, 4, "X still carried \(carried) packets after UDP came up")
    }
}
