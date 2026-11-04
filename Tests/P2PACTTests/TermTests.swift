import XCTest
import Foundation
@testable import P2PACT

/// Tool 5 p2pact.term and former names (core spec §8, §8.1), as in p2pact-go.
final class TermTests: XCTestCase {
    private var nodes: [Node] = []
    private let former = "com.example.term"

    override func tearDown() {
        for n in nodes { n.close() }
        nodes = []
        super.tearDown()
    }

    private func node(_ name: String) throws -> Node {
        let n = try Node(dir: tempDir(), name: name)
        n.noLearning = true
        try n.listenUdp("127.0.0.1:0")
        n.start()
        nodes.append(n)
        return n
    }

    private func pair(_ owner: Node, _ joiner: Node) throws {
        _ = try joiner.join(owner.invite(ttlMs: 60_000))
        eventually("\(owner.name) knows \(joiner.name)") { owner.peer(joiner.id.addr) != nil }
    }

    /// A handler answering its name; method 1 is read, the others need write.
    private func served(_ who: String) -> ToolHandler {
        { _, level, method, _ in
            if method != 1 && level < LEVEL_WRITE { throw P2pactError(Errors.forbidden, "read only") }
            return .values([.text(who)])
        }
    }

    private func call(_ from: Node, _ to: String, _ name: String, _ method: Int) -> Result<String, Error> {
        Result { try from.callToolOn(to, name, method, [], timeoutMs: 5000).get().at(0).asString ?? "" }
    }

    private func code(_ r: Result<String, Error>) -> Int? {
        if case .failure(let e) = r { return (e as? P2pactError)?.code }
        return nil
    }

    func testFixedTable() throws {
        XCTAssertEqual(fixedTool("p2pact.term"), 5)
        XCTAssertNil(fixedTool(former))
        let a = try node("Mac")
        XCTAssertThrowsError(try a.registerTool("p2pact.term", 1), "a name of the spec is not a named tool")
    }

    // A tool of the spec served by the application: one handler under number 5, announced in {tool: version};
    // the node checks read, the handler the rest.
    func testFixedToolServedByApp() throws {
        let a = try node("Mac"), b = try node("Phone")
        try pair(a, b)
        let addr = a.id.addr, me = b.id.addr
        try a.handleToolAll("p2pact.term", served("term"))
        eventually("term in the hello") { b.peerHasTool(addr, "p2pact.term") }
        XCTAssertEqual(b.peerTools(addr), [], "a tool of the spec is not in the named map")
        let r = b.resolveTool(addr, "p2pact.term")
        XCTAssertEqual(r?.number, 5)
        XCTAssertEqual(r?.called, "p2pact.term")
        XCTAssertEqual(try call(b, addr, "p2pact.term", 1).get(), "term")

        try a.setGrants(me, [Grant("p2pact.term", LEVEL_READ)])
        XCTAssertEqual(try call(b, addr, "p2pact.term", 1).get(), "term", "read")
        XCTAssertEqual(code(call(b, addr, "p2pact.term", 2)), Errors.forbidden, "write at read")
        try a.setGrants(me, [Grant("p2pact.chat", LEVEL_WRITE)])
        XCTAssertEqual(code(call(b, addr, "p2pact.term", 1)), Errors.forbidden, "no grant on term")
    }

    // Grants on either name count for both, the highest wins, for calls and for events; each name answers
    // under its own number.
    func testAliasRights() throws {
        let a = try node("Mac"), b = try node("Phone")
        XCTAssertThrowsError(try a.aliasTool(former, former))
        XCTAssertThrowsError(try a.aliasTool("p2pact.chat", "p2pact.term"), "a name of the spec taken as an alias")
        try a.aliasTool(former, "p2pact.term")
        try a.handleToolAll("p2pact.term", served("p2pact.term"))
        try a.handleToolAll(former, served(former))
        let events = EventLog()
        b.onEvent = { _, tool, _, _ in events.add(tool) }
        try pair(a, b)
        let addr = a.id.addr, me = b.id.addr
        eventually("both names") { b.peerHasTool(addr, "p2pact.term") && b.peerHasTool(addr, former) }
        let alias = try XCTUnwrap(b.toolNumber(addr, former))
        XCTAssertGreaterThanOrEqual(alias, FIRST_NAMED_TOOL)

        let cases: [([Grant], Int)] = [
            ([Grant(former, LEVEL_WRITE)], LEVEL_WRITE),
            ([Grant("p2pact.term", LEVEL_WRITE)], LEVEL_WRITE),
            ([Grant("p2pact.term", LEVEL_READ), Grant(former, LEVEL_WRITE)], LEVEL_WRITE),
            ([Grant(former, LEVEL_READ)], LEVEL_READ),
            ([Grant("p2pact.chat", LEVEL_WRITE)], 0)
        ]
        for (grants, level) in cases {
            try a.setGrants(me, grants)
            for name in ["p2pact.term", former] {
                XCTAssertEqual(a.level(me, name), level, "\(grants) on \(name)")
                let rd = call(b, addr, name, 1), wr = call(b, addr, name, 2)
                XCTAssertEqual((try? rd.get()) == name, level >= LEVEL_READ, "\(grants) read on \(name)")
                XCTAssertEqual((try? wr.get()) == name, level >= LEVEL_WRITE, "\(grants) write on \(name)")
            }
            // read does not give write
            if level == LEVEL_READ { XCTAssertEqual(code(call(b, addr, "p2pact.term", 2)), Errors.forbidden) }
            // events of either number reach a device with read on either name
            events.clear()
            try a.event(me, 5, 3)
            try a.event(me, alias, 3)
            if level >= LEVEL_READ {
                eventually("both events under \(grants)") { events.all == [5, alias] }
            } else {
                Thread.sleep(forTimeInterval: 0.4)
                XCTAssertEqual(events.all, [], "events without read: \(grants)")
            }
        }
        XCTAssertEqual(b.peerToolName(addr, 5), "p2pact.term", "events under 5 are p2pact.term")
    }

    // A device that knows the terminal only by its former name and one that serves p2pact.term talk both
    // ways: a new caller reaches the old device by the alias, an old caller reaches the new device by the
    // former name, a new one goes to 5.
    func testAliasOldAndNewDevices() throws {
        let old = try node("Old"), nw = try node("New"), phone = try node("Phone")
        try old.handleToolAll(former, served("old")) // before p2pact.term
        try nw.aliasTool(former, "p2pact.term")
        try nw.handleToolAll("p2pact.term", served("new:5"))
        try nw.handleToolAll(former, served("new:alias"))
        try phone.aliasTool(former, "p2pact.term") // a new caller
        try pair(nw, old)
        try pair(phone, old)
        try pair(phone, nw)
        let oldAddr = old.id.addr, nwAddr = nw.id.addr
        eventually("hellos") {
            phone.peerHasTool(oldAddr, former) && phone.peerHasTool(nwAddr, "p2pact.term")
                && old.peerHasTool(nwAddr, former) && nw.peerHasTool(oldAddr, former)
        }
        XCTAssertFalse(phone.peerHasTool(oldAddr, "p2pact.term"), "the old device announced 5")
        let toOld = try XCTUnwrap(phone.resolveTool(oldAddr, "p2pact.term"))
        XCTAssertGreaterThanOrEqual(toOld.number, FIRST_NAMED_TOOL)
        XCTAssertEqual(toOld.called, former)
        XCTAssertEqual(phone.resolveTool(nwAddr, "p2pact.term")?.number, 5)
        XCTAssertEqual(phone.resolveTool(nwAddr, former)?.called, former, "asked by the alias itself")
        XCTAssertNil(phone.resolveTool(oldAddr, "com.example.none"))

        try nw.setGrants(oldAddr, [Grant("p2pact.term", LEVEL_WRITE)]) // an old caller, granted the new name
        XCTAssertEqual(try call(phone, oldAddr, "p2pact.term", 1).get(), "old")
        XCTAssertEqual(try call(phone, nwAddr, "p2pact.term", 1).get(), "new:5")
        XCTAssertEqual(try call(nw, oldAddr, "p2pact.term", 1).get(), "old")
        XCTAssertEqual(try call(old, nwAddr, former, 1).get(), "new:alias")
        XCTAssertEqual(code(call(old, phone.id.addr, "com.example.none", 1)), Errors.noMethod)
    }
}

private final class EventLog {
    private let lock = NSLock()
    private var list: [Int] = []
    func add(_ t: Int) { lock.lock(); list.append(t); lock.unlock() }
    func clear() { lock.lock(); list = []; lock.unlock() }
    var all: [Int] { lock.lock(); defer { lock.unlock() }; return list }
}
