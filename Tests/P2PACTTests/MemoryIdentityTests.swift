import XCTest
import Foundation
@testable import P2PACT

/// Keys held in memory (Identity.generate, Node(identity:)) and devices on this computer known without pairing
/// (trustLocal, localOnly): a window tells its key to its own computer over stdin and talks over the local socket.
final class MemoryIdentityTests: XCTestCase {
    private var nodes: [Node] = []

    override func tearDown() {
        for n in nodes { n.close() }
        nodes = []
        super.tearDown()
    }

    func testGenerateWritesNothing() throws {
        let dir = tempDir()
        let id = Identity.generate()
        XCTAssertEqual(id.key.publicKey.count, 32)
        XCTAssertEqual(id.sign.publicKey.count, 32)
        XCTAssertEqual(id.addr, Crypto.address(id.key.publicKey))
        XCTAssertNotEqual(Identity.generate().addr, id.addr)
        let n = try Node(dir: dir, name: "window", identity: id)
        nodes.append(n)
        XCTAssertEqual(n.id.addr, id.addr)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir + "/net-key.json"))
    }

    func testTrustLocalKeepsLocalOnly() throws {
        let dir = tempDir()
        let n = try Node(dir: dir, name: "window", identity: Identity.generate())
        let other = Identity.generate()
        XCTAssertThrowsError(try n.trustLocal(Peer(addr: other.addr, key: Identity.generate().key.publicKey, name: "x", pairSecret: [], hints: Hints())))
        try n.trustLocal(Peer(addr: other.addr, key: other.key.publicKey, name: "engine", pairSecret: [], hints: Hints(udp: ["1.2.3.4:5"]),
                              signKey: other.sign.publicKey, kind: Kind.computer, local: true))
        let p = try XCTUnwrap(n.peer(other.addr))
        XCTAssertTrue(p.local)
        XCTAssertTrue(p.localOnly)
        XCTAssertTrue(p.hints.udp.isEmpty)
        n.close()
        // the mark survives the file, in p2pact-go's format
        waitFor("net-peers.json") {
            (FileManager.default.contents(atPath: dir + "/net-peers.json")).map { String(decoding: $0, as: UTF8.self).contains("\"local_only\" : true") } ?? false
        }
        let again = try Node(dir: dir, name: "window", identity: Identity.generate())
        nodes.append(again)
        XCTAssertEqual(again.peer(other.addr)?.localOnly, true)
    }

    /// A window with keys in memory reaches its computer over the local socket; the computer knows it only by key.
    func testMemoryKeyOverLocalSocket() throws {
        let sock = "/tmp/p2pact-mem-\(UUID().uuidString.prefix(8)).sock"
        defer { unlink(sock) }
        let engine = try Node(dir: tempDir(), name: "engine")
        engine.kind = Kind.computer
        engine.handle(64, 1) { _, _ in .values([.text("pong")]) }
        try engine.listenLocal(sock)
        engine.start()
        nodes.append(engine)

        let win = Identity.generate()
        let window = try Node(dir: tempDir(), name: "window", identity: win)
        window.kind = Kind.client
        try window.trustLocal(Peer(addr: engine.id.addr, key: engine.id.key.publicKey, name: "engine", pairSecret: [], hints: Hints(),
                                   signKey: engine.id.sign.publicKey, kind: Kind.computer, local: true))
        try window.useLocal(sock)
        window.start()
        nodes.append(window)

        // a stranger is met with silence
        XCTAssertThrowsError(try window.call(engine.id.addr, 64, 1, [], timeoutMs: 700).get())
        try engine.trustLocal(Peer(addr: win.addr, key: win.key.publicKey, name: "window", pairSecret: [], hints: Hints(),
                                   signKey: win.sign.publicKey, kind: Kind.client))
        var got: String?
        waitFor("call over the local socket") {
            got = try? window.call(engine.id.addr, 64, 1, [], timeoutMs: 1000).get().at(0).asString
            return got != nil
        }
        XCTAssertEqual(got, "pong")
        XCTAssertEqual(engine.paths(win.addr).count, 1)
    }
}
