import XCTest
import Foundation
@testable import P2PACTClient
@preconcurrency import P2PACT

private let ID = "0b7c2e64-1d2a-4f5e-9a10-6c3b8d7e9f01"

final class FleetClientTests: ClientTestCase {
    func testReadMethods() async throws {
        let fleet = try await connect().fleet
        let hello = try await fleet.hello()
        XCTAssertEqual(hello.protocolVersion, "0.2")
        XCTAssertEqual(hello.node.name, "MacBook Pro")
        XCTAssertEqual(hello.node.os, "darwin")
        XCTAssertEqual(hello.node.agents.first?.id, "claude")
        XCTAssertEqual(hello.node.status.long("working"), 1)
        let node = try await fleet.node()
        XCTAssertEqual(node.name, "MacBook Pro")

        let list = try await fleet.sessions()
        XCTAssertEqual(list.count, 1)
        let s = try XCTUnwrap(list.first)
        XCTAssertEqual(s.id, ID)
        XCTAssertEqual(s.agent, "claude")
        XCTAssertEqual(s.dir, "/Users/me/app")
        XCTAssertEqual(s.phase, "working")
        XCTAssertEqual(s.title, "Починить вход")
        XCTAssertEqual(s.updated, "2026-10-27T10:00:00Z")
        XCTAssertEqual(s.raw.obj("status")?.obj("owner")?.str("node"), "3f2a9c01d4e5b6a7")
        let one = try await fleet.session(ID)
        XCTAssertEqual(one.id, ID)
        assertSent(2, "session/get", "p2pact.fleet", "session-get.request")

        let m = try await fleet.messages(ID, after: 2)
        assertSent(2, "session/messages", "p2pact.fleet", "session-messages.request")
        XCTAssertEqual(m.last, 3)
        XCTAssertTrue(m.older)
        XCTAssertEqual(m.messages.first?.text, "Готово")
        XCTAssertEqual(m.messages.first?.role, "assistant")
    }

    func testWatchDeliversEventsInOrder() async throws {
        let fleet = try await connect().fleet
        let events = fleet.events.queue()
        let watch = try await fleet.watch(partial: false)
        assertSent(2, "fleet/watch", "p2pact.fleet", "watch.request")
        XCTAssertEqual(watch.sessions.first?.id, ID)

        for n in ["notify-session-changed", "notify-session-messages", "notify-notify"] {
            engine.notify(2, Fixtures.read("p2pact.fleet", n))
        }
        guard case .sessionsChanged(let changed) = try await nextOrFail(events) else { return XCTFail("changed") }
        XCTAssertEqual(changed.first?.phase, "working")
        guard case .sessionMessages(let id, let msgs) = try await nextOrFail(events) else { return XCTFail("messages") }
        XCTAssertEqual(id, ID)
        XCTAssertEqual(msgs.first?.seq, 4)
        XCTAssertEqual(msgs.first?.text, "Продолжай")
        guard case .notify(let text) = try await nextOrFail(events) else { return XCTFail("notify") }
        XCTAssertEqual(text, "Агент ждёт ответа")

        engine.notify(2, ["jsonrpc": "2.0", "method": "session/resync", "params": ["id": .string(ID)]])
        guard case .resync(let rid) = try await nextOrFail(events) else { return XCTFail("resync") }
        XCTAssertEqual(rid, ID)
        engine.notify(2, ["jsonrpc": "2.0", "method": "something/new", "params": ["k": 1]])
        guard case .other(let method, _) = try await nextOrFail(events) else { return XCTFail("other") }
        XCTAssertEqual(method, "something/new")

        await watch.stop()
        assertSent(2, "fleet/unwatch", "p2pact.fleet", "unwatch.request")
    }

    func testWriteMethods() async throws {
        let fleet = try await connect().fleet
        let s = try await fleet.create(SessionSpec(agent: "claude", dir: "/Users/me/app", perms: "ask"), text: "Почини вход")
        assertSent(2, "session/create", "p2pact.fleet", "session-create.request")
        XCTAssertEqual(s.phase, "starting")

        try await fleet.send(ID, text: "Продолжай")
        assertSent(2, "session/send", "p2pact.fleet", "session-send.request")

        let e = await thrown { try await fleet.send("нет", text: "?") }
        let rpc = try XCTUnwrap(e as? RpcError)
        XCTAssertTrue(rpc.isNoSuchResource)
        XCTAssertEqual(rpc.code, -32004)

        let settings = try await fleet.setSettings(["sleep_after": 15])
        XCTAssertEqual(settings, ["sleep_after": 15])
        assertSent(2, "settings/set", "p2pact.fleet", "settings-set.request")

        try await fleet.answer(ID, waitId: "w1", answers: ["Q": "A"])
        XCTAssertEqual(engine.seen.last { $0.method == "session/answer" }?.params, ["id": .string(ID), "waitId": "w1", "answers": ["Q": "A"]])
        try await fleet.interrupt(ID)
        let closed = try await fleet.close(ID)
        XCTAssertNil(closed.warning)
        try await fleet.setKeep(ID, on: true)
        XCTAssertEqual(engine.seen.last { $0.method == "session/setKeep" }?.params, ["id": .string(ID), "on": true])
    }

    func testReadOnlyFleet() async throws {
        let computer = try await connect(decide: { _ in [Grant(Tools.fleet, LEVEL_READ)] })
        let fleet = computer.fleet
        let list = try await fleet.sessions()
        XCTAssertEqual(list.count, 1)
        let writes: [() async throws -> Void] = [
            { try await fleet.send(ID, text: "x") },
            { _ = try await fleet.create(SessionSpec(agent: "claude")) },
            { try await fleet.interrupt(ID) }
        ]
        for write in writes {
            let e = await thrown(write)
            XCTAssertEqual((e as? P2pactCallError)?.isForbidden, true, "\(String(describing: e))")
        }
        // no grant on the chat at all: even reading is refused
        let c = await thrown { try await computer.chat.listSessions() }
        XCTAssertEqual((c as? P2pactCallError)?.isForbidden, true, "\(String(describing: c))")
    }
}

final class PluginsClientTests: ClientTestCase {
    private let wants = defaultWants + [Grant("com.example.hello", LEVEL_WRITE)]

    func testListLogGrants() async throws {
        let plugins = try await connect(wants: wants).plugins
        let list = try await plugins.list()
        let p = try XCTUnwrap(list.first)
        XCTAssertEqual(list.count, 1)
        XCTAssertEqual(p.name, "com.example.hello")
        XCTAssertEqual(p.status, .running)
        XCTAssertTrue(p.enabled)
        XCTAssertEqual(p.pid, 4242)
        XCTAssertEqual(p.announced, ["com.example.hello"])
        XCTAssertEqual(p.needs, ["p2pact.chat:read"])

        let log = try await plugins.log("com.example.hello", lines: 2)
        XCTAssertEqual(log, "started\nready\n")
        assertSent(4, "plugins/log", "p2pact.plugins", "plugins.log.request")

        let g = try await plugins.grants("com.example.hello")
        XCTAssertEqual(g.grants, [Grant("p2pact.chat", LEVEL_READ)]) // the engine sends the level as a string
        XCTAssertEqual(g.read, ["com.example.hello": [2]])

        // plugins are asked for with read only: writing needs the person to widen it
        let e = await thrown { try await plugins.enable("com.example.hello") }
        XCTAssertEqual((e as? P2pactCallError)?.isForbidden, true, "\(String(describing: e))")
    }

    func testLevelAcceptsStringAndInteger() {
        XCTAssertEqual(levelOf("read"), LEVEL_READ)
        XCTAssertEqual(levelOf("write"), LEVEL_WRITE)
        XCTAssertEqual(levelOf(1), LEVEL_READ)
        XCTAssertEqual(levelOf(.int(2)), LEVEL_WRITE)
        XCTAssertNil(levelOf("nope"))
    }

    func testUnknownPluginLog() async throws {
        let plugins = try await connect(wants: wants).plugins
        let e = await thrown { try await plugins.log("com.example.nope") }
        XCTAssertEqual((e as? RpcError)?.code, -32004)
    }

    func testWatchDeliversChanged() async throws {
        let plugins = try await connect(wants: wants).plugins
        let events = plugins.events.queue()
        let watch = try await plugins.watch()
        assertSent(4, "plugins/watch", "p2pact.plugins", "plugins.watch.request")
        XCTAssertEqual(watch.plugins.first?.name, "com.example.hello")

        engine.notify(4, Fixtures.read("p2pact.plugins", "plugins.changed.notification"))
        guard case .changed(let c, let removed) = try await nextOrFail(events) else { return XCTFail("changed") }
        XCTAssertEqual(c.name, "com.example.hello")
        XCTAssertEqual(c.status, .running)
        XCTAssertFalse(removed)

        engine.notify(4, Fixtures.read("p2pact.plugins", "plugins.changed.removed.notification"))
        guard case .changed(let r, let gone) = try await nextOrFail(events) else { return XCTFail("removed") }
        XCTAssertEqual(r.status, .stopped)
        XCTAssertTrue(gone)

        await watch.stop()
        assertSent(4, "plugins/unwatch", "p2pact.plugins", "plugins.unwatch.request")
    }

    func testEnableDisableWithWrite() async throws {
        let computer = try await connect(wants: wants.filter { $0.tool != Tools.plugins } + [Grant(Tools.plugins, LEVEL_WRITE)])
        try await computer.plugins.enable("com.example.hello")
        assertSent(4, "plugins/enable", "p2pact.plugins", "plugins.enable.request")
        try await computer.plugins.disable("com.example.hello")
        assertSent(4, "plugins/disable", "p2pact.plugins", "plugins.disable.request")
    }

    func testCallsPluginToolByName() async throws {
        let computer = try await connect(wants: wants)
        let n = try XCTUnwrap(computer.toolNumber("com.example.hello"))
        XCTAssertGreaterThanOrEqual(n, 64) // the computer's own number
        let r = try await computer.plugins.callTool("com.example.hello", method: 1, args: ["world"])
        XCTAssertEqual(r, ["hello world"])

        // a tool the computer does not announce
        let e = await thrown { try await computer.plugins.callTool("com.example.nothing", method: 1) }
        XCTAssertEqual(e as? P2pactCallError, .noMethod("the computer has no tool com.example.nothing"))
    }

    func testToolGrantIsNeeded() async throws {
        let computer = try await connect() // no grant on the hosted tool
        let e = await thrown { try await computer.callTool("com.example.hello", method: 1, args: ["x"]) }
        XCTAssertEqual((e as? P2pactCallError)?.isForbidden, true, "\(String(describing: e))")
    }
}

/// The client over a node the application runs itself: it owns the pairing and the callbacks, the SDK serves the chat.
final class WrappedNodeTests: XCTestCase {
    func testChatOverTheApplicationsNode() async throws {
        let dir = NSTemporaryDirectory() + "p2pact-wrapped-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let engine = try FakeEngine(dir: dir + "/engine")
        defer { engine.close() }
        let node = try Node(dir: dir + "/app", name: "Phone app")
        defer { node.close() }
        try node.listenUdp("127.0.0.1:0")
        let client = P2pactClient(node: node)
        // the application's own callbacks, passing on to the SDK
        let hellos = Queue<String>()
        node.onHello = { addr in client.hello(addr); hellos.put(addr) }
        node.onEvent = { addr, tool, ev, args in client.event(addr, tool, ev, args) }
        node.start()

        let peer = try await node.joinAsync(Invite.parse(engine.invite()), timeoutMs: 15_000).value()
        let hello = await hellos.next()
        XCTAssertEqual(hello, peer.addr)
        let computer = try XCTUnwrap(client.computer(id: peer.addr))
        XCTAssertEqual(computer.state, .online)

        let list = try await computer.chat.listSessions()
        XCTAssertEqual(list.sessions.first?.id, "s1")
        // a request on a stream of the application's choice (0: the computer's own)
        _ = try await computer.chat.request("session/list", params: ["sessionId": "s1"], stream: 0)
        XCTAssertEqual(engine.seen.map { $0.method }, ["initialize", "session/list", "session/list"])

        // closing the client leaves the application's node alone
        client.close()
        XCTAssertFalse(node.paths(peer.addr).isEmpty)
    }

    func testJSONRoundTrip() throws {
        let v = try JSONValue.parse(#"{"a":[1,2.5,"x",null,true],"b":{"c":"d"}}"#)
        XCTAssertEqual(v.obj("b")?.str("c"), "d")
        let back = try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(v))
        XCTAssertEqual(back, v)
        // whole doubles go on the wire as integers; byte strings come back as base64 text
        XCTAssertEqual(cborFromJSON(.double(3)), .int(3))
        XCTAssertEqual(jsonFromCbor(.bytes([1, 2, 3])), "AQID")
        XCTAssertEqual(jsonFromCbor(cborFromJSON(v)), v)
    }
}
