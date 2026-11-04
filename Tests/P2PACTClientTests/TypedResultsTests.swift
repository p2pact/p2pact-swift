import XCTest
import Foundation
@testable import P2PACTClient
@preconcurrency import P2PACT

/// The typed results of `_p2pact/*` against the engine's fixtures, in both forms: the fixture as it is (result
/// version 2) and with the typed fields stripped, only `lines` (an engine older than that).
final class TypedResultsTests: ClientTestCase {
    private let dir = "p2pact.chat"

    private func chat(legacy: Bool) async throws -> ChatClient {
        let computer = try await connect()
        engine.legacy = legacy
        return computer.chat
    }

    private func forBoth(_ body: (ChatClient, Bool) async throws -> Void) async throws {
        for legacy in [false, true] {
            let c = try await chat(legacy: legacy)
            try await body(c, legacy)
            client.close(); engine.close()
        }
    }

    func testInitializeAsksForResultVersion2() async throws {
        let computer = try await connect()
        let info = try await computer.chat.initialize()
        assertSent(1, "initialize", dir, "initialize.request")
        XCTAssertEqual(info.resultVersion, 2)
    }

    func testOlder() async throws {
        try await forBoth { chat, legacy in
            let page = try await chat.older("s1", before: 3)
            self.assertSent(1, "_p2pact/older", self.dir, "_p2pact.older.request")
            XCTAssertEqual(page.messages.map { $0.text }, ["привет"], "legacy=\(legacy)")
            XCTAssertEqual(page.messages.first?.time, "2026-11-03T10:00:00Z")
            XCTAssertFalse(page.more)
            XCTAssertEqual(page.run, "r1")
        }
    }

    func testCommands() async throws {
        try await forBoth { chat, legacy in
            let cmds = try await chat.commands("s1")
            self.assertSent(1, "_p2pact/commands", self.dir, "_p2pact.commands.request")
            XCTAssertEqual(cmds.count, 1, "legacy=\(legacy)")
            XCTAssertEqual(cmds.first?.name, "review")
            XCTAssertEqual(cmds.first?.desc, "Review the changes")
            XCTAssertEqual(cmds.first?.hint, "<pr>")
            XCTAssertEqual(cmds.first?.args, [CommandArg(value: "main", desc: "base branch")])
        }
    }

    func testFiles() async throws {
        try await forBoth { chat, legacy in
            let f = try await chat.files("s1", query: "fac")
            self.assertSent(1, "_p2pact/files", self.dir, "_p2pact.files.request")
            XCTAssertEqual(f.files, ["agent/pkg/acpchat/facade.go"], "legacy=\(legacy)")
            XCTAssertEqual(f.query, "fac")
        }
    }

    func testHistory() async throws {
        try await forBoth { chat, legacy in
            let h = try await chat.history(query: "", offset: 0)
            self.assertSent(1, "_p2pact/history", self.dir, "_p2pact.history.request")
            XCTAssertEqual(h.items.count, 1, "legacy=\(legacy)")
            XCTAssertEqual(h.items.first?.id, "h1")
            XCTAssertEqual(h.items.first?.agent, "claude")
            XCTAssertEqual(h.items.first?.dir, "/w/proj")
            XCTAssertEqual(h.items.first?.title, "Fix the build")
            XCTAssertEqual(h.items.first?.updated, 1793700000000)
            XCTAssertEqual(h.items.first?.count, 12)
            XCTAssertEqual(h.from, 0)
            XCTAssertEqual(h.total, 2)
            XCTAssertFalse(h.partial)
            XCTAssertEqual(h.cursor, legacy ? nil : 1)
        }
    }

    func testHistoryOpenAndActions() async throws {
        try await forBoth { chat, legacy in
            let o = try await chat.historyOpen("h1")
            self.assertSent(1, "_p2pact/history_open", self.dir, "_p2pact.history_open.request")
            XCTAssertTrue(o.ok, "legacy=\(legacy)")
            XCTAssertNil(o.error)
            let c = try await chat.close("s1")
            self.assertSent(1, "_p2pact/close", self.dir, "_p2pact.close.request")
            XCTAssertTrue(c.ok)
            let r = try await chat.restart("s1")
            self.assertSent(1, "_p2pact/restart", self.dir, "_p2pact.restart.request")
            XCTAssertTrue(r.ok)
            let h = try await chat.hide("s1", on: true)
            self.assertSent(1, "_p2pact/hide", self.dir, "_p2pact.hide.request")
            XCTAssertTrue(h.ok)
        }
    }

    func testActionFailure() async throws {
        let chat = try await connect().chat
        engine.override("1:_p2pact/close") { _ in ["jsonrpc": "2.0", "result": ["ok": false, "error": "no such chat", "lines": []]] }
        let r = try await chat.close("zzz")
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.error, "no such chat")
        // an older engine tells a refusal with the line `alert`
        engine.override("1:_p2pact/close") { _ in ["jsonrpc": "2.0", "result": ["lines": [["cmd": "alert", "text": "no such chat"]]]] }
        let old = try await chat.close("zzz")
        XCTAssertFalse(old.ok)
        XCTAssertEqual(old.error, "no such chat")
    }

    func testProjects() async throws {
        try await forBoth { chat, legacy in
            let p = try await chat.projects(cwd: "/w/proj")
            self.assertSent(1, "_p2pact/projects", self.dir, "_p2pact.projects.request")
            XCTAssertEqual(p.dirs, ["/w/proj"], "legacy=\(legacy)")
            XCTAssertEqual(p.projectDirs, ["proj": ["/w/proj", "/w/proj-api"]])
            XCTAssertEqual(p.dirRepos, ["/w/proj": "git@example.com:team/proj.git"])
        }
    }

    func testAgents() async throws {
        try await forBoth { chat, legacy in
            let a = try await chat.agents()
            self.assertSent(1, "_p2pact/agents", self.dir, "_p2pact.agents.request")
            XCTAssertEqual(a.agents.count, 1, "legacy=\(legacy)")
            let x = try XCTUnwrap(a.agents.first)
            XCTAssertEqual(x.id, "claude")
            XCTAssertEqual(x.name, "Claude Code")
            XCTAssertEqual(x.type, "claude")
            XCTAssertTrue(x.enabled)
            XCTAssertEqual(x.models, ["opus", "sonnet"])
            XCTAssertEqual(x.defaultModel, "sonnet")
            XCTAssertEqual(a.presets.map { $0.id }, ["p1"])
            XCTAssertEqual(a.presets.first?.name, "Claude Sonnet")
        }
    }

    func testImageAndDiff() async throws {
        try await forBoth { chat, legacy in
            let bad = try await chat.image("s1", path: "/w/proj/shot.png")
            self.assertSent(1, "_p2pact/image", self.dir, "_p2pact.image.request")
            XCTAssertEqual(bad.error, "not_found", "legacy=\(legacy)")
            XCTAssertEqual(bad.path, "/w/proj/shot.png")
            XCTAssertNil(bad.data)

            // the fixture with the bytes
            self.engine.override("1:_p2pact/image") { _ in Fixtures.read(self.dir, "_p2pact.image.data.response") }
            if legacy { self.engine.override("1:_p2pact/image") { _ in FakeEngine.stripTyped("_p2pact/image", Fixtures.read(self.dir, "_p2pact.image.data.response")) } }
            let ok = try await chat.image("s1", path: "/w/proj/ok.png")
            XCTAssertNil(ok.error)
            XCTAssertEqual(ok.path, "/w/proj/ok.png")
            XCTAssertEqual(ok.data?.hasPrefix("iVBOR"), true)
            XCTAssertEqual(ok.mime, legacy ? nil : "image/png")

            let d = try await chat.diff("s1")
            self.assertSent(1, "_p2pact/diff", self.dir, "_p2pact.diff.request")
            XCTAssertEqual(d.files, [DiffFile(path: "a.go", added: 3, removed: 1, status: "M")])
            XCTAssertEqual(d.patch, "diff --git a/a.go b/a.go\n")
            XCTAssertFalse(d.truncated)
            XCTAssertNil(d.error)
        }
    }

    func testDiffError() async throws {
        let chat = try await connect().chat
        engine.override("1:_p2pact/diff") { _ in ["jsonrpc": "2.0", "result": ["error": "not_git", "lines": [["cmd": "diff", "error": "not_git"]]]] }
        let d = try await chat.diff("s1")
        XCTAssertEqual(d.error, "not_git")
        XCTAssertTrue(d.files.isEmpty)
    }
}
