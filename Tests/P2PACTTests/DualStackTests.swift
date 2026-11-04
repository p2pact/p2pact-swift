import XCTest
import Foundation
@testable import P2PACT

final class DualStackTests: XCTestCase {
    /// Go's ":0" listens on IPv4 and IPv6 at once; so do we: one UDP road takes datagrams from both and answers each
    /// on the address it wrote from (an IPv4 sender shows as plain IPv4, not as a mapped IPv6 one).
    func testUdpDualStack() throws {
        let inbox = Inbox()
        let server = try UdpRoad(bind: ":0") { inbox.put($0, $1) }
        defer { server.close() }
        guard let (_, port) = hostPort(server.localAddr) else { return XCTFail(server.localAddr) }

        let back4 = Inbox()
        let v4 = try UdpRoad(bind: "127.0.0.1:0") { back4.put($0, $1) }
        defer { v4.close() }
        XCTAssertTrue(v4.send("127.0.0.1:\(port)", [4]))
        let (got4, from4) = try XCTUnwrap(inbox.take())
        XCTAssertEqual(got4, [4])
        XCTAssertTrue(from4.addr.hasPrefix("127.0.0.1:"), from4.addr)
        XCTAssertTrue(server.send(from4.addr, [40]))
        XCTAssertEqual(back4.take()?.0, [40])

        let back6 = Inbox()
        guard let v6 = try? UdpRoad(bind: "[::1]:0", recv: { back6.put($0, $1) }) else { throw XCTSkip("no IPv6 loopback") }
        defer { v6.close() }
        XCTAssertTrue(v6.send("[::1]:\(port)", [6]))
        let (got6, from6) = try XCTUnwrap(inbox.take())
        XCTAssertEqual(got6, [6])
        XCTAssertTrue(from6.addr.hasPrefix("[::1]:"), from6.addr)
        XCTAssertTrue(server.send(from6.addr, [60]))
        XCTAssertEqual(back6.take()?.0, [60])
    }

    func testTcpDualStack() throws {
        let inbox = Inbox()
        let server = try TcpRoad(bind: ":0") { inbox.put($0, $1) }
        defer { server.close() }
        guard let (_, port) = hostPort(server.localAddr) else { return XCTFail(server.localAddr) }
        let c4 = try TcpRoad(bind: "") { _, _ in }
        defer { c4.close() }
        XCTAssertTrue(c4.send("127.0.0.1:\(port)", [4]))
        XCTAssertEqual(inbox.take()?.0, [4])
        let c6 = try TcpRoad(bind: "") { _, _ in }
        defer { c6.close() }
        XCTAssertTrue(c6.send("[::1]:\(port)", [6]))
        XCTAssertEqual(inbox.take()?.0, [6])
    }
}
