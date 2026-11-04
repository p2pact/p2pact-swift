import XCTest
@testable import P2PACT

/// The NAT prime (spec §7): one byte to port 3478 of a public host before a datagram to it, after primeIdle without one.
final class PrimeTests: XCTestCase {
    func testPublicAddresses() throws {
        let cases: [(String, Bool)] = [
            ("178.88.48.86", true), ("161.35.71.42", true), ("::ffff:8.8.8.8", true),
            ("10.1.2.3", false), ("192.168.31.178", false), ("172.16.0.1", false), ("100.94.117.6", false),
            ("127.0.0.1", false), ("169.254.1.1", false), ("2001:db8::1", false), ("0.0.0.0", false), ("240.0.0.1", false)
        ]
        for (ip, isPublic) in cases {
            let a = try XCTUnwrap(resolve(host: ip, port: 1, family: AF_UNSPEC, type: SOCK_DGRAM).first, ip)
            XCTAssertEqual(ipv4(a).map(natPublic) ?? false, isPublic, ip)
        }
        let v4 = try XCTUnwrap(resolve(host: "8.8.8.8", port: 1, family: AF_INET, type: SOCK_DGRAM).first)
        XCTAssertEqual(withPort(v4, 3478).text, "8.8.8.8:3478")
        XCTAssertEqual(withPort(v4Mapped(v4), 3478).text, "8.8.8.8:3478")
    }

    func testPrimesFirstAndAfterIdle() throws {
        let primes = Inbox(), peerIn = Inbox()
        let stun = try UdpRoad(bind: "127.0.0.1:0") { primes.put($0, $1) }
        let peer = try UdpRoad(bind: "127.0.0.1:0") { peerIn.put($0, $1) }
        let saved = (primeIdle, primeGap, primePort, primeHost)
        primeIdle = 600 * MS
        primeGap = 150 * MS
        primePort = hostPort(stun.localAddr)!.1
        primeHost = { _ in true }
        let u = try UdpRoad(bind: "127.0.0.1:0") { _, _ in }
        defer {
            u.close(); stun.close(); peer.close()
            (primeIdle, primeGap, primePort, primeHost) = saved
        }
        let gapMs = Double(primeGap / MS)
        func count() -> Int {
            var n = 0
            while let (b, from) = primes.take(timeout: 0.05) {
                XCTAssertEqual(b, [0])
                XCTAssertEqual(from.addr, u.localAddr)
                n += 1
            }
            return n
        }
        // got: what the peer received, each with how many ms after start it came
        func got(_ want: Int, _ start: Date) -> [String: Double] {
            var out = [String: Double]()
            while out.count < want, let (b, _) = peerIn.take(timeout: 1) {
                out[String(decoding: b, as: UTF8.self)] = Date().timeIntervalSince(start) * 1000
            }
            XCTAssertEqual(out.count, want)
            return out
        }

        var start = Date()
        XCTAssertTrue(u.send(peer.localAddr, Array("first".utf8)))
        XCTAssertTrue(u.send(peer.localAddr, Array("second".utf8)))
        XCTAssertEqual(count(), 1, "first datagrams")
        for (m, at) in got(2, start) { XCTAssertGreaterThanOrEqual(at, gapMs - 10, m) }

        start = Date()
        _ = u.send(peer.localAddr, Array("third".utf8))
        XCTAssertLessThan(got(1, start)["third"] ?? 1e9, gapMs - 10, "a datagram after the gap waited")
        XCTAssertEqual(count(), 0, "a datagram right after")

        Thread.sleep(forTimeInterval: 0.65)
        _ = u.send(peer.localAddr, Array("after idle".utf8))
        _ = got(1, Date())
        XCTAssertEqual(count(), 1, "after primeIdle")

        primeHost = { _ in false }
        Thread.sleep(forTimeInterval: 0.65)
        start = Date()
        _ = u.send(peer.localAddr, Array("private".utf8))
        XCTAssertLessThan(got(1, start)["private"] ?? 1e9, gapMs - 10, "a datagram to a private address waited")
        XCTAssertEqual(count(), 0, "a private address")
    }
}
