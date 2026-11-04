import XCTest
import Foundation
@testable import P2PACT

/// A p2pact-go relay (cmd/p2pact-relay) as a child process. Needs P2PACT_RELAY=/abs/path/to/the/built/relay;
/// without it the tests skip (build it: `go build -o /tmp/p2pact-relay ./cmd/p2pact-relay` in p2pact-go).
final class RelayProc {
    let port: Int
    let dir: String
    private var proc: Process?
    private(set) var fp = ""

    init(port: Int = 0, dir: String? = nil) throws {
        guard let bin = ProcessInfo.processInfo.environment["P2PACT_RELAY"], !bin.isEmpty else { throw XCTSkip("P2PACT_RELAY is not set") }
        self.dir = dir ?? NSTemporaryDirectory() + "p2pact-relay-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: self.dir, withIntermediateDirectories: true)
        self.port = port == 0 ? RelayProc.freePort() : port
        bin_ = bin
        try start()
    }
    private var bin_ = ""

    func start() throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin_)
        p.arguments = ["-addr", "127.0.0.1:\(port)", "-data", dir]
        let err = Pipe()
        p.standardError = err
        p.standardOutput = FileHandle.nullDevice
        try p.run()
        proc = p
        // "... relay started addr=127.0.0.1:N fingerprint=<hex>"
        var seen = ""
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            let d = err.fileHandleForReading.availableData
            if d.isEmpty { break }
            seen += String(decoding: d, as: UTF8.self)
            if let r = seen.range(of: "fingerprint=") {
                fp = String(seen[r.upperBound...].prefix(64))
                return
            }
        }
        throw NSError(domain: "relay", code: 1, userInfo: [NSLocalizedDescriptionKey: "the relay did not start: \(seen)"])
    }

    func stop() { proc?.terminate(); proc?.waitUntilExit(); proc = nil }
    deinit { stop() }
    var hint: RelayHint { RelayHint(addr: "127.0.0.1:\(port)", fp: fp) }

    static func freePort() -> Int {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(s) }
        var a = sockaddr_in()
        a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        a.sin_family = sa_family_t(AF_INET)
        a.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var l = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &l) } }
        return Int(UInt16(bigEndian: a.sin_port))
    }
}

func waitFor(_ what: String, timeout: TimeInterval = 15, file: StaticString = #filePath, line: UInt = #line, _ f: () -> Bool) {
    let end = Date().addingTimeInterval(timeout)
    while !f() {
        if Date() > end { return XCTFail("timeout: \(what)", file: file, line: line) }
        Thread.sleep(forTimeInterval: 0.05)
    }
}

final class RelayTests: XCTestCase {
    let ch = String(repeating: "cd", count: 16)

    /// two roads on one channel; packets go both ways
    func pair(_ r: RelayProc, keepalive: TimeInterval = 25) -> (RelayRoad, Inbox, RelayRoad, Inbox) {
        let ia = Inbox(), ib = Inbox()
        let a = RelayRoad(hint: r.hint, keepalive: keepalive) { ia.put($0, $1) }
        let b = RelayRoad(hint: r.hint, keepalive: keepalive) { ib.put($0, $1) }
        a.join(ch, "a"); b.join(ch, "b")
        return (a, ia, b, ib)
    }

    func testPinnedBothWays() throws {
        let r = try RelayProc()
        let (a, ia, b, ib) = pair(r)
        defer { a.close(); b.close() }
        waitFor("both connected") { a.sessions >= 1 && b.sessions >= 1 }
        XCTAssertTrue(a.send(ch, [1, 2, 3]))
        XCTAssertEqual(ib.take()?.0, [1, 2, 3])
        XCTAssertTrue(b.send(ch, [9]))
        XCTAssertEqual(ia.take()?.0, [9])
        // a wrong fingerprint never connects
        let bad = RelayRoad(hint: RelayHint(addr: r.hint.addr, fp: String(repeating: "0", count: 64))) { _, _ in XCTFail("delivered") }
        bad.join(ch, "a")
        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertEqual(bad.sessions, 0)
        bad.close()
    }

    /// An idle connection says "p" every keepalive and the relay answers "P"; the default is 25 s.
    func testKeepalive() throws {
        let r = try RelayProc()
        let (a, _, b, ib) = pair(r, keepalive: 0.3)
        defer { a.close(); b.close() }
        waitFor("pongs") { a.pongs >= 4 && b.pongs >= 4 }
        XCTAssertEqual(a.sessions, 1) // kept, not reconnected
        XCTAssertTrue(a.send(ch, [7]))
        XCTAssertEqual(ib.take()?.0, [7])
        let d = RelayRoad(hint: r.hint) { _, _ in }
        XCTAssertEqual(d.keepaliveSeconds, 25)
    }

    /// The relay goes away and comes back (same address and certificate): both sides reconnect by themselves.
    func testReconnectAfterRelayDrop() throws {
        let r = try RelayProc()
        let (a, ia, b, ib) = pair(r)
        defer { a.close(); b.close() }
        waitFor("connected") { a.sessions >= 1 && b.sessions >= 1 }
        XCTAssertTrue(a.send(ch, [1]))
        XCTAssertEqual(ib.take()?.0, [1])
        r.stop()
        Thread.sleep(forTimeInterval: 1)
        try r.start()
        XCTAssertEqual(r.hint.fp, a.hint.fp) // the same certificate
        waitFor("reconnected") { a.sessions >= 2 && b.sessions >= 2 }
        XCTAssertTrue(b.send(ch, [2]))
        XCTAssertEqual(ia.take()?.0, [2])
        XCTAssertTrue(a.send(ch, [3]))
        XCTAssertEqual(ib.take()?.0, [3])
    }

    /// No fingerprint: the certificate is judged by the system's trust store (the path for a relay with a real
    /// certificate). The test relay is self-signed, so the system refuses it and nothing connects; the
    /// pinned path is the one that accepts it.
    func testSystemTrustRefusesSelfSigned() throws {
        let r = try RelayProc()
        let road = RelayRoad(hint: RelayHint(addr: r.hint.addr, fp: "")) { _, _ in XCTFail("delivered") }
        defer { road.close() }
        road.join(ch, "a")
        Thread.sleep(forTimeInterval: 2)
        XCTAssertEqual(road.sessions, 0)
    }
}
