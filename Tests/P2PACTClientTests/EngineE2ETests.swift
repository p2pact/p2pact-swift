import XCTest
import Foundation
@testable import P2PACTClient
@preconcurrency import P2PACT

/// The client SDK against the real Nomad Code engine (Go, `agent/cmd/nomadcode`, TestAppE2E): the
/// engine runs as a `go test` process on 127.0.0.1 with a random port, nothing of the user's engine
/// is touched. Only with `P2PACT_ENGINE_E2E=<path to nomad-code/agent>` (Go is needed).
final class EngineE2ETests: XCTestCase {
    private final class Engine {
        let dir: String
        let log: String
        let proc = Process()

        init(agent: String, decide: String) throws {
            dir = NSTemporaryDirectory() + "app-e2e-" + UUID().uuidString
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            log = dir + "/engine.log"
            FileManager.default.createFile(atPath: log, contents: nil)
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            proc.arguments = ["go", "test", "-count=1", "-v", "-run", "^TestAppE2E$", "./cmd/nomadcode"]
            proc.currentDirectoryURL = URL(fileURLWithPath: agent)
            var env = ProcessInfo.processInfo.environment
            env["NOMAD_APP_E2E"] = dir
            env["NOMAD_APP_E2E_DECIDE"] = decide
            proc.environment = env
            let h = FileHandle(forWritingAtPath: log)
            proc.standardOutput = h
            proc.standardError = h
            try proc.run()
        }

        var tail: String { String(((try? String(contentsOfFile: log, encoding: .utf8)) ?? "").suffix(3000)) }

        func waitFile(_ name: String, timeout: TimeInterval = 120) async throws -> String {
            let end = Date().addingTimeInterval(timeout)
            while Date() < end {
                if let s = try? String(contentsOfFile: dir + "/" + name, encoding: .utf8), !s.isEmpty { return s }
                try await Task.sleep(nanoseconds: 50_000_000)
            }
            XCTFail("no file \(name) from the engine: \(tail)")
            throw CancellationError()
        }

        func finish() async throws {
            try "ok".write(toFile: dir + "/done", atomically: true, encoding: .utf8)
            let end = Date().addingTimeInterval(60)
            while proc.isRunning && Date() < end { try await Task.sleep(nanoseconds: 100_000_000) }
            XCTAssertFalse(proc.isRunning, "the engine did not finish: \(tail)")
            XCTAssertEqual(proc.terminationStatus, 0, tail)
        }

        func close() {
            if proc.isRunning { proc.terminate() }
            try? FileManager.default.removeItem(atPath: dir)
        }
    }

    private func agentPath() throws -> String {
        guard let p = ProcessInfo.processInfo.environment["P2PACT_ENGINE_E2E"], !p.isEmpty else {
            throw XCTSkip("P2PACT_ENGINE_E2E is not set")
        }
        return p
    }

    private let wants = [Grant(Tools.chat, LEVEL_WRITE), Grant(Tools.fleet, LEVEL_READ)]

    private func app() throws -> (P2pactClient, String) {
        let dir = NSTemporaryDirectory() + "app-e2e-client-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return (try P2pactClient(dir: dir, name: "E2E app", config: ClientConfig(udp: "127.0.0.1:0", tcp: nil)), dir)
    }

    private func waitLevel(_ computer: Computer, _ tool: String, _ level: Int) async {
        let end = Date().addingTimeInterval(20)
        while computer.level(tool) != level && Date() < end { try? await Task.sleep(nanoseconds: 50_000_000) }
    }

    func testAppAgainstEngine() async throws {
        let engine = try Engine(agent: try agentPath(), decide: "yes")
        let (client, dir) = try app()
        defer { client.close(); engine.close(); try? FileManager.default.removeItem(atPath: dir) }

        let computer = try await client.pair(try await engine.waitFile("invite"), wants: wants, timeout: 60)
        try await computer.whenOnline()
        let decision = try await engine.waitFile("decision")
        XCTAssertEqual(decision, "approved")
        // what the person decided arrives as the first 0.6
        await waitLevel(computer, Tools.chat, LEVEL_WRITE)
        XCTAssertEqual(computer.level(Tools.chat), LEVEL_WRITE)
        XCTAssertEqual(computer.level(Tools.fleet), LEVEL_READ)

        let chat = computer.chat
        let info = try await chat.initialize()
        XCTAssertTrue(info.loadSession)
        let list = try await chat.listSessions()
        XCTAssertEqual(list.sessions.map { $0.id }, ["s1"])

        // history
        let loaded = try await chat.loadSession("s1")
        let texts = loaded.updates.compactMap { u -> String? in
            switch u.kind {
            case .userMessage: return "u:" + u.text
            case .agentMessage: return "a:" + u.text
            default: return nil
            }
        }
        XCTAssertTrue(texts.contains("u:привет") && texts.contains("a:Готово"), "\(texts)")

        // fleet: read
        let fleet = computer.fleet
        let sessions = try await fleet.sessions()
        XCTAssertEqual(sessions.map { $0.id }, ["s1"])
        let events = fleet.events.queue()
        _ = try await fleet.watch()

        // the permission handler answers the engine's question
        let asked = Queue<PermissionRequest>()
        chat.permissionHandler = { r in asked.put(r); return r.allow() }

        // the prompt answers the Stop hook
        _ = try await engine.waitFile("ready")
        async let prompt = chat.prompt("s1", text: "из приложения")
        let stop = try await engine.waitFile("stop")
        XCTAssertTrue(stop.contains("из приложения"), stop)
        let request = try await nextOrFail(asked, "permission request")
        XCTAssertEqual(request.sessionId, "s1")
        let perm = try await engine.waitFile("perm")
        XCTAssertTrue(perm.contains("\"behavior\":\"allow\""), perm)
        // the turn ends once the permission is answered and the agent is idle again
        let result = try await prompt
        XCTAssertEqual(result.stopReason, "end_turn")

        // the fleet watch event about the finished turn
        var seen = false
        let end = Date().addingTimeInterval(20)
        while !seen && Date() < end {
            guard let e = await events.next(timeout: 0.5) else { continue }
            if case .sessionMessages(let id, let msgs) = e, id == "s1", msgs.contains(where: { $0.text == "Сделано" }) { seen = true }
        }
        XCTAssertTrue(seen, "no fleet event with the agent's reply")

        // fleet is read-only for us
        let e = await thrown { try await fleet.send("s1", text: "нельзя") }
        XCTAssertEqual((e as? P2pactCallError)?.isForbidden, true, "session/send must be forbidden: \(String(describing: e))")
        try await engine.finish()
    }

    func testReadOnlyDecisionForbidsPrompt() async throws {
        let engine = try Engine(agent: try agentPath(), decide: "read")
        let (client, dir) = try app()
        defer { client.close(); engine.close(); try? FileManager.default.removeItem(atPath: dir) }

        let computer = try await client.pair(try await engine.waitFile("invite"), wants: wants, timeout: 60)
        try await computer.whenOnline()
        let decision = try await engine.waitFile("decision")
        XCTAssertEqual(decision, "read")
        await waitLevel(computer, Tools.chat, LEVEL_READ)
        XCTAssertEqual(computer.level(Tools.chat), LEVEL_READ)
        let list = try await computer.chat.listSessions()
        XCTAssertEqual(list.sessions.map { $0.id }, ["s1"])
        let e = await thrown { try await computer.chat.prompt("s1", text: "нельзя") }
        XCTAssertEqual((e as? P2pactCallError)?.isForbidden, true, "prompt must be forbidden: \(String(describing: e))")
        try await engine.finish()
    }

    private func nextOrFail<T>(_ q: Queue<T>, _ what: String) async throws -> T {
        guard let v = await q.next(timeout: 20) else {
            XCTFail("no \(what) within 20 s")
            throw CancellationError()
        }
        return v
    }
}
