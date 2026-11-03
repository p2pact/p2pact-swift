import XCTest
import Foundation
@testable import P2PACT

func tempDir() -> String {
    let d = NSTemporaryDirectory() + "p2pact-test-" + UUID().uuidString
    try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
    return d
}

func eventually(_ what: String, timeout: TimeInterval = 10, _ f: () -> Bool, file: StaticString = #filePath, line: UInt = #line) {
    let end = Date().addingTimeInterval(timeout)
    while Date() < end {
        if f() { return }
        Thread.sleep(forTimeInterval: 0.02)
    }
    XCTFail("timed out: \(what)", file: file, line: line)
}

final class WantsTests: XCTestCase {
    private func node(_ dir: String, _ name: String, kind: Int = Kind.unknown) throws -> Node {
        let n = try Node(dir: dir, name: name)
        n.kind = kind
        try n.listenUdp("127.0.0.1:0")
        n.start()
        return n
    }

    // A newcomer that asked, and was not yet answered, may use nothing: until the first 0.6 the
    // device grants it an empty list, kept over a restart; one that did not ask has everything.
    func testNothingUntilTold() throws {
        let a = try node(tempDir(), "Mac", kind: Kind.computer)
        let dirB = tempDir()
        let b = try node(dirB, "App", kind: Kind.client)
        let c = try node(tempDir(), "Phone")
        defer { a.close(); b.close(); c.close() }
        let release = DispatchSemaphore(value: 0)
        a.onWants = { _, _ in
            release.wait()
            return [Grant("com.acme.x", LEVEL_READ)]
        }
        _ = try b.join(a.invite(ttlMs: 60_000), wants: [Grant("com.acme.x", LEVEL_WRITE)])
        let aAddr = a.id.addr
        XCTAssertEqual(b.grantedBy(aAddr), [], "before the first 0.6")
        b.trust.flush()
        XCTAssertEqual(Trust(dir: dirB).get(aAddr)?.granted, [], "kept over a restart")
        release.signal()
        eventually("told") { b.grantedBy(aAddr) == [Grant("com.acme.x", LEVEL_READ)] }

        // no wants: everything until told
        a.onWants = nil
        _ = try c.join(a.invite(ttlMs: 60_000))
        XCTAssertEqual(c.grantedBy(aAddr), defaultGrants())
        XCTAssertNil(c.peer(aAddr)?.granted)
    }

    // A newcomer that asked for everything and got it still hears 0.6: it cannot tell "everything"
    // from "not yet answered" otherwise.
    func testEverythingIsTold() throws {
        let a = try node(tempDir(), "Mac", kind: Kind.computer)
        let b = try node(tempDir(), "App", kind: Kind.client)
        defer { a.close(); b.close() }
        let told = DispatchSemaphore(value: 0)
        b.onGranted = { _, _ in told.signal() }
        _ = try b.join(a.invite(ttlMs: 60_000), wants: [Grant(ALL_TOOLS, LEVEL_WRITE)])
        XCTAssertEqual(told.wait(timeout: .now() + 10), .success, "0.6 did not come")
        XCTAssertEqual(b.grantedBy(a.id.addr), defaultGrants())
        XCTAssertEqual(b.peer(a.id.addr)?.granted, [Grant(ALL_TOOLS, LEVEL_WRITE)])
    }

    // afterEvents completes behind the events already queued on a stream.
    func testAfterEvents() throws {
        let a = try node(tempDir(), "Mac")
        let b = try node(tempDir(), "App")
        defer { a.close(); b.close() }
        let got = NSLock()
        var seen: [Int] = []
        b.onEvent = { _, _, ev, _ in
            Thread.sleep(forTimeInterval: 0.05)
            got.lock(); seen.append(ev); got.unlock()
        }
        let peer = try b.join(a.invite(ttlMs: 60_000))
        _ = peer
        eventually("session") { !a.paths(b.id.addr).isEmpty }
        try a.registerTool("com.acme.t")
        for i in 1...3 { try a.eventOn(b.id.addr, stream: 7, 64, i) }
        try b.afterEvents(a.id.addr, stream: 7).get(timeout: 10)
        // events sent before arrive before what afterEvents waited for, once they have arrived
        eventually("events") { got.lock(); defer { got.unlock() }; return seen.count == 3 }
        try b.afterEvents(a.id.addr, stream: 7).get(timeout: 10)
        got.lock(); XCTAssertEqual(seen, [1, 2, 3]); got.unlock()
    }
}
