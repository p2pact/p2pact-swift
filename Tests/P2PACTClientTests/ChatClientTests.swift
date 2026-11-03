import XCTest
import Foundation
@testable import P2PACTClient
@preconcurrency import P2PACT

final class ChatClientTests: ClientTestCase {
    func testPairingGrantsAndState() async throws {
        let computer = try await connect()
        XCTAssertEqual(client.computers().map { $0.id }, [computer.id])
        XCTAssertEqual(computer.name, "MacBook Pro")
        XCTAssertEqual(computer.state, .online)
        XCTAssertEqual(computer.grants, defaultWants)
        XCTAssertEqual(computer.level(Tools.chat), LEVEL_WRITE)
        XCTAssertEqual(computer.level(Tools.plugins), LEVEL_READ)
        XCTAssertFalse(computer.canWrite(Tools.plugins))
        // the engine knows us as a client
        XCTAssertEqual(engine.node.peer(try engine.clientAddr())?.kind, Kind.client)
    }

    // A joiner that paired with wants has no grants until the first 0.6.
    func testNothingUntilTheFirstGrantsEvent() async throws {
        engine = try FakeEngine(dir: tmp())
        let release = DispatchSemaphore(value: 0)
        engine.node.onWants = { _, _ in release.wait(); return [Grant(Tools.chat, LEVEL_READ)] }
        client = try P2pactClient(dir: tmp(), name: "Test app", config: ClientConfig(udp: "127.0.0.1:0", tcp: nil))
        let events = client.computerEvents.queue()
        let computer = try await client.pair(engine.invite(), wants: defaultWants)
        XCTAssertEqual(computer.grants, [])
        XCTAssertEqual(computer.level(Tools.chat), 0)
        release.signal()
        while true {
            let e = try await nextOrFail(events, "grants")
            if case .grantsChanged(_, let g) = e, !g.isEmpty { XCTAssertEqual(g, [Grant(Tools.chat, LEVEL_READ)]); break }
        }
        XCTAssertEqual(computer.level(Tools.chat), LEVEL_READ)
    }

    func testInitializeAndList() async throws {
        let chat = try await connect().chat
        let info = try await chat.initialize()
        assertSent(1, "initialize", "p2pact.chat", "initialize.request")
        XCTAssertEqual(info.agents.map { $0.id }, ["claude"])
        XCTAssertEqual(info.agents[0].name, "Claude Code")
        XCTAssertTrue(info.loadSession)
        XCTAssertTrue(info.extensions)
        XCTAssertEqual(info.agentTitle, "MacBook Pro")

        let list = try await chat.listSessions()
        assertSent(1, "session/list", "p2pact.chat", "session.list.request")
        let s = try XCTUnwrap(list.sessions.first)
        XCTAssertEqual(list.sessions.count, 1)
        XCTAssertEqual(s.id, "s1")
        XCTAssertEqual(s.cwd, "/w/proj")
        XCTAssertEqual(s.agent, "claude")
        XCTAssertEqual(s.state, .working)
        XCTAssertEqual(s.updatedAt, "2026-11-03T10:00:00Z")
        XCTAssertNil(list.nextCursor)
        // the raw JSON stays reachable
        XCTAssertEqual(s.raw.str("sessionId"), "s1")
        XCTAssertEqual(chat.sessions, [s])
    }

    func testCallsInitializeFirstByThemselves() async throws {
        let chat = try await connect().chat
        _ = try await chat.listAllSessions()
        XCTAssertEqual(engine.seen.map { $0.method }, ["initialize", "session/list"])
    }

    func testNewPromptCancel() async throws {
        let chat = try await connect().chat
        let created = try await chat.newSession(cwd: "/w/app", agent: "codex", model: "gpt-5", text: "собери проект", perms: "ask", mid: "n1")
        XCTAssertEqual(created.sessionId, "nomad-1")
        assertSent(1, "session/new", "p2pact.chat", "session.new.request")

        let result = try await chat.prompt("s1", text: "запусти тесты", mid: "m1")
        XCTAssertEqual(result.stopReason, "end_turn")
        XCTAssertFalse(result.duplicate)
        assertSent(1, "session/prompt", "p2pact.chat", "session.prompt.request")

        try chat.cancel("s1")
        let n = try await nextOrFail(engine.fromClient, "cancel")
        XCTAssertEqual(n.str("method"), "session/cancel")
        XCTAssertEqual(n.obj("params")?.str("sessionId"), "s1")
    }

    func testLoadGivesTheWholeHistory() async throws {
        let chat = try await connect().chat
        let live = chat.updates.queue()
        let loaded = try await chat.loadSession("s1", cwd: "/w/proj")
        assertSent(1, "session/load", "p2pact.chat", "session.load.request")
        XCTAssertTrue(loaded.older)
        // all three replayed messages are in the result, in order, though the answer may come first
        let u = loaded.updates
        XCTAssertEqual(u.count, 3)
        guard u.count == 3 else { return }
        guard case .userMessage = u[0].kind else { return XCTFail("\(u[0].kind)") }
        XCTAssertEqual(u[0].text, "привет")
        XCTAssertEqual(u[0].seq, 1)
        guard case .agentMessage = u[1].kind else { return XCTFail("\(u[1].kind)") }
        XCTAssertEqual(u[1].text, "Привет! Чем помочь?")
        XCTAssertEqual(u[1].seq, 2)
        XCTAssertEqual(u[1].time, "2026-11-03T10:00:01Z")
        guard case .toolCall(let call) = u[2].kind else { return XCTFail("\(u[2].kind)") }
        XCTAssertEqual(call.toolCallId, "m3")
        XCTAssertEqual(call.title, "Bash: go test")
        XCTAssertEqual(call.kind, "execute")
        XCTAssertEqual(call.status, "completed")
        // and they went to the listeners too
        for _ in 0..<3 { _ = try await nextOrFail(live, "update") }
    }

    func testLiveUpdatesAndChanges() async throws {
        let chat = try await connect().chat
        let updates = chat.updates.queue()
        let changes = chat.sessionChanges.queue()
        engine.notifyChat(Fixtures.read("p2pact.chat", "session.update.agent_message.notification"))
        engine.notifyChat(Fixtures.read("p2pact.chat", "_p2pact.session_changed.notification"))
        let u = try await nextOrFail(updates)
        XCTAssertEqual(u.sessionId, "s1")
        guard case .agentMessage = u.kind else { return XCTFail("\(u.kind)") }
        XCTAssertEqual(u.text, "Привет! Чем помочь?")
        let s = try await nextOrFail(changes)
        XCTAssertEqual(s.id, "s1")
        XCTAssertEqual(s.state, .idle)
        XCTAssertEqual(s.agent, "claude")
        XCTAssertEqual(s.title, "proj")
        XCTAssertEqual(chat.sessions.map { $0.id }, ["s1"])
        // closing removes it from the known chats
        engine.notifyChat(["jsonrpc": "2.0", "method": "_p2pact/session_changed",
                           "params": ["sessionId": "s1", "_meta": ["p2pact": ["state": "closed"]]]])
        let closed = try await nextOrFail(changes)
        XCTAssertEqual(closed.state, .closed)
        XCTAssertTrue(chat.sessions.isEmpty)
    }

    func testEventsAsAsyncStream() async throws {
        let chat = try await connect().chat
        let stream = chat.updates.stream()
        engine.notifyChat(Fixtures.read("p2pact.chat", "session.update.agent_message.notification"))
        var it = stream.makeAsyncIterator()
        let u = await it.next()
        XCTAssertEqual(u?.text, "Привет! Чем помочь?")
    }

    func testUnknownUpdatesAreKeptRaw() async throws {
        let chat = try await connect().chat
        let updates = chat.updates.queue()
        engine.notifyChat(["jsonrpc": "2.0", "method": "session/update", "params": [
            "sessionId": "s1", "update": ["sessionUpdate": "brand_new", "x": 1, "extra": ["y"]]]])
        let u = try await nextOrFail(updates)
        XCTAssertEqual(u.kind, .other("brand_new"))
        XCTAssertEqual(u.raw.long("x"), 1)
    }

    func testPermissionRequestAnswered() async throws {
        let computer = try await connect()
        let seen = Queue<PermissionRequest>()
        computer.chat.permissionHandler = { r in seen.put(r); return r.allow() }
        let res = try await engine.ask(1, Fixtures.read("p2pact.chat", "session.request_permission.request"), sessionId: "s1")
        XCTAssertEqual(res, Fixtures.read("p2pact.chat", "session.request_permission.response"))
        let r = try await nextOrFail(seen)
        XCTAssertEqual(r.toolCall.title, "Bash: rm -rf build")
        XCTAssertEqual(r.options.map { $0.optionId }, ["allow", "always", "deny"])
        XCTAssertEqual(r.deny(), .selected(optionId: "deny"))
    }

    func testQuestionAnswered() async throws {
        let computer = try await connect()
        let asked = Queue<QuestionRequest>()
        computer.chat.questionHandler = { q in
            asked.put(q)
            return ["База?": "SQLite", "Что проверить?": QuestionRequest.join(["Тесты"])]
        }
        let res = try await engine.ask(1, Fixtures.read("p2pact.chat", "_p2pact.question.request"), sessionId: "s1")
        XCTAssertEqual(res, Fixtures.read("p2pact.chat", "_p2pact.question.response"))
        let q = try await nextOrFail(asked)
        XCTAssertEqual(q.questions.count, 2)
        XCTAssertEqual(q.questions[0].header, "База")
        XCTAssertEqual(q.questions[0].options.map { $0.label }, ["Postgres", "SQLite"])
        XCTAssertEqual(q.questions[0].options[0].description, "основная")
        XCTAssertTrue(q.questions[1].multi)
    }

    func testRequestAnsweredElsewhere() async throws {
        let computer = try await connect()
        let shown = Queue<PermissionRequest>()
        // the person never decides here
        computer.chat.permissionHandler = { r in
            shown.put(r)
            try await Task.sleep(nanoseconds: 60 * 1_000_000_000)
            return r.allow()
        }
        let answered = computer.chat.requestAnswered.queue()
        async let res = engine.ask(1, Fixtures.read("p2pact.chat", "session.request_permission.request"), sessionId: "s1")
        let r = try await nextOrFail(shown)
        engine.notifyChat(Fixtures.read("p2pact.chat", "_p2pact.request_answered.notification"))
        let a = try await nextOrFail(answered)
        XCTAssertEqual(a.toolCallId, "w1")
        await r.answered.wait()
        XCTAssertTrue(r.answered.isFired)
        // the call does not hang: the computer got an error answer
        let reply = try await res
        XCTAssertNotNil(reply.obj("error"))
    }

    func testWithoutHandlerTheComputerHearsNoSuchMethod() async throws {
        _ = try await connect()
        let res = try await engine.ask(1, Fixtures.read("p2pact.chat", "session.request_permission.request"), sessionId: "s1")
        XCTAssertEqual(res.obj("error")?.long("code"), -32601)
        let fs = try await engine.ask(1, ["jsonrpc": "2.0", "method": "fs/read_text_file", "params": ["sessionId": "s1"]], sessionId: "s1")
        XCTAssertEqual(fs.obj("error")?.long("code"), -32601)
    }

    func testExtensions() async throws {
        let chat = try await connect().chat
        try await chat.close("s1")
        assertSent(1, "_p2pact/close", "p2pact.chat", "_p2pact.close.request")
        try await chat.restart("s1")
        try await chat.hide("s1", on: true)
        XCTAssertEqual(engine.seen.last { $0.method == "_p2pact/hide" }?.params, ["sessionId": "s1", "on": true])

        let page = try await chat.older("s1", before: 3)
        assertSent(1, "_p2pact/older", "p2pact.chat", "_p2pact.older.request")
        let m = try XCTUnwrap(page.messages.first)
        XCTAssertEqual(page.messages.count, 1)
        XCTAssertEqual(m.seq, 1)
        XCTAssertEqual(m.role, "user")
        XCTAssertEqual(m.text, "привет")
        XCTAssertFalse(page.more)

        let diff = try await chat.diff("s1")
        assertSent(1, "_p2pact/diff", "p2pact.chat", "_p2pact.diff.request")
        XCTAssertEqual(diff.files.first?.path, "a.go")
        XCTAssertEqual(diff.files.first?.added, 3)
        XCTAssertEqual(diff.patch, "diff --git a/a.go b/a.go\n")
        XCTAssertFalse(diff.truncated)

        let image = try await chat.image("s1", path: "/w/proj/shot.png")
        assertSent(1, "_p2pact/image", "p2pact.chat", "_p2pact.image.request")
        XCTAssertEqual(image.error, "not_found")
        XCTAssertNil(image.data)
    }

    func testLateReports() async throws {
        let chat = try await connect().chat
        let reports = chat.reports.queue()
        engine.notifyChat(Fixtures.read("p2pact.chat", "_p2pact.report.notification"))
        let r = try await nextOrFail(reports)
        XCTAssertEqual(r.str("cmd"), "diff_more")
    }

    // Read-only: reading works, writing is the P2PACT error 4, not a JSON-RPC error.
    func testReadOnlyGrantRefusesWrites() async throws {
        let computer = try await connect(decide: { _ in [Grant(Tools.chat, LEVEL_READ), Grant(Tools.fleet, LEVEL_READ)] })
        XCTAssertEqual(computer.level(Tools.chat), LEVEL_READ)
        XCTAssertFalse(computer.canWrite(Tools.chat))
        let chat = computer.chat
        let list = try await chat.listSessions()
        XCTAssertEqual(list.sessions.count, 1)
        _ = try await chat.loadSession("s1", cwd: "/w/proj")
        let writes: [() async throws -> Any] = [
            { try await chat.newSession(cwd: "/w/app") },
            { try await chat.prompt("s1", text: "x") },
            { try await chat.close("s1") }
        ]
        for write in writes {
            let e = await thrown(write)
            XCTAssertEqual(e as? P2pactCallError, .forbidden("forbidden"), "\(String(describing: e))")
            XCTAssertEqual((e as? P2pactCallError)?.code, 4)
        }
        // the refused calls did not reach the tool's handler as writes
        XCTAssertTrue(engine.seen.allSatisfy { !($0.method == "session/prompt" && $0.level >= LEVEL_WRITE) })
    }

    func testErrorCodesAreTyped() {
        let want: [Int: P2pactCallError] = [1: .noMethod("x"), 2: .badArgs("x"), 3: .notFound("x"), 4: .forbidden("x"), 5: .failed("x"), 6: .notDelivered("x")]
        for (code, e) in want {
            XCTAssertEqual(typed(P2pactError(code, "x")) as? P2pactCallError, e)
            XCTAssertEqual(e.code, code)
        }
        XCTAssertEqual((typed(P2pactError(99, "?")) as? P2pactCallError)?.code, 99)
    }

    func testJsonRpcErrorsAreRpcErrors() async throws {
        let chat = try await connect().chat
        engine.override("1:session/list") { _ in ["jsonrpc": "2.0", "error": ["code": -32601, "message": "nope", "data": "d"]] }
        let e = await thrown { try await chat.listSessions() }
        let rpc = try XCTUnwrap(e as? RpcError)
        XCTAssertTrue(rpc.isMethodNotFound)
        XCTAssertEqual(rpc.message, "nope")
        XCTAssertEqual(rpc.data, "d")
    }

    func testStreamOfMatchesTheSpec() {
        XCTAssertEqual(streamOf(nil), 0)
        XCTAssertEqual(streamOf(""), 0)
        XCTAssertNotEqual(streamOf("s1"), streamOf("s2"))
        XCTAssertEqual(streamOf("s1"), streamOf("s1"))
    }
}
