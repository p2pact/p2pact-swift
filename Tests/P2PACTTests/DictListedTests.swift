import XCTest
import Foundation
@testable import P2PACT

final class DictListedTests: XCTestCase {
    private func node(_ name: String) throws -> Node {
        let n = try Node(dir: tempDir(), name: name)
        try n.listenUdp("127.0.0.1:0")
        n.noLearning = true
        n.start()
        return n
    }

    private func dictBytes(_ seed: Int) throws -> Bytes {
        let samples: [Bytes] = (0..<400).map { i in
            Bytes("{\"seq\":\(i + seed * 1000),\"user\":\"u\(i % 13)\",\"body\":\"hello, this is chat message number \(i * 31 % 17) about topic \(i % 7) in room \(seed)\",\"ts\":\(1_700_000_000 + i)}".utf8)
        }
        return try train(samples, [], 4 << 10)
    }

    private let text = (0..<8).map { "step \($0): the agent finished the task and pushed a commit; the tests pass and the build is green; do the messages go through the server or not?" }.joined(separator: " ")

    // The sender lists more dictionaries than the receiver keeps of one kind (a common one the receiver lacks plus
    // four of its own for the receiver: all five are the pair's on the receiver). The receiver must keep what the
    // sender lists instead of evicting one for another and fetching it back forever, and messages compressed
    // meanwhile must all run.
    func testListedDictsKept() throws {
        let a = try node("Engine"), b = try node("CLI")
        defer { a.close(); b.close() }
        let lock = NSLock()
        var asked = 0
        a.handle(0, 5) { peer, args in
            lock.lock(); asked += 1; lock.unlock()
            return .values(try a.dictHandlerForTest(peer, args))
        }
        var got = 0
        b.onEvent = { _, _, _, _ in lock.lock(); got += 1; lock.unlock() }
        _ = try b.join(a.invite(ttlMs: 60_000))
        eventually("a knows b") { a.peer(b.id.addr) != nil }
        // the built-in common dictionary is on both sides; a common one b lacks plus four of a's own for b
        // are five pair's dictionaries on b
        try a.addDict(dictBytes(0))
        for seed in 1...DICT_KEEP { a.addDictForTest(try Dict(dictBytes(seed), peer: b.id.addr, own: true)) }
        for i in 0..<20 { try a.event(b.id.addr, 9, 1, [.text("\(i) \(text)")]) }
        Thread.sleep(forTimeInterval: 2)
        lock.lock(); let n = asked; lock.unlock()
        XCTAssertLessThanOrEqual(n, 2 * (DICT_KEEP + 1), "b asked for dictionaries \(n) times: it evicts what a still lists")
        XCTAssertEqual(b.heldForTest(a.id.addr), 0, "messages still held")
        XCTAssertEqual(b.dictIdsForTest(a.id.addr).filter { !$0.isEmpty }.count, DICT_KEEP + 2) // the common one and the five
        eventually("got all 20 messages") { lock.lock(); defer { lock.unlock() }; return got >= 20 }
    }

    // A message waits for a dictionary the sender cannot give: it is not dropped silently at the first failed
    // fetch, but held, asked for again and dropped after holdDrop with onHeld.
    func testHeldDictUnreachable() throws {
        let oldAsk = holdAsk, oldDrop = holdDrop
        holdAsk = 200 * MS
        holdDrop = 1500 * MS
        defer { holdAsk = oldAsk; holdDrop = oldDrop }
        let a = try node("Phone"), b = try node("Mac")
        defer { a.close(); b.close() }
        _ = try b.join(a.invite(ttlMs: 60_000))
        eventually("a knows b") { a.peer(b.id.addr) != nil }
        let raw = try dictBytes(0)
        try a.addDict(raw)
        try b.addDict(raw)
        // a compresses with the dictionary itself (not just the common one) and b with it for a: the lists are settled
        let rid = dictId(raw)
        eventually("a sees b's list") { a.dictState(b.id.addr).using == rid }
        eventually("b sees a's list") { b.dictState(a.id.addr).using == rid }
        let lock = NSLock()
        var asked = 0
        a.handle(0, 5) { _, _ in
            lock.lock(); asked += 1; lock.unlock()
            throw P2pactError(Errors.notFound, "no such dictionary")
        }
        let held = DispatchSemaphore(value: 0)
        var heldN = 0
        let start = Date()
        b.onHeld = { _, k in heldN = k; held.signal() }
        b.loseDictsForTest() // b lost the dictionary and a does not know
        try a.event(b.id.addr, 9, 1, [.text(text)])
        XCTAssertEqual(held.wait(timeout: .now() + 10), .success, "the held message was dropped silently or never")
        XCTAssertGreaterThanOrEqual(heldN, 1)
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), 0.2)
        lock.lock(); let n = asked; lock.unlock()
        XCTAssertGreaterThanOrEqual(n, 2, "asked for the dictionary \(n) times: not asked again before dropping")
    }
}
