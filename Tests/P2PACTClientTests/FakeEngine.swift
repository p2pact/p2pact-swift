import XCTest
import Foundation
@testable import P2PACTClient
@preconcurrency import P2PACT

/// The engine's reference messages (contract/tools of the engine repository, copied to the test resources).
enum Fixtures {
    static func url(_ dir: String, _ name: String) -> URL? {
        Bundle.module.url(forResource: "tools", withExtension: nil)?.appendingPathComponent("\(dir)/\(name).json")
    }

    static func exists(_ dir: String, _ name: String) -> Bool {
        url(dir, name).map { FileManager.default.fileExists(atPath: $0.path) } ?? false
    }

    static func read(_ dir: String, _ name: String) -> JSONValue {
        let text = try! String(contentsOf: url(dir, name)!, encoding: .utf8)
        return try! JSONValue.parse(text)
    }

    /// The `params` of a request fixture ({} when it has none).
    static func params(_ dir: String, _ name: String) -> JSONValue { read(dir, name).obj("params") ?? .object([:]) }
}

struct Seen {
    let tool: Int
    let method: String
    let params: JSONValue
    let level: Int
}

/// A queue a test waits on: events arrive from the library's threads, the test takes them in order.
final class Queue<T> {
    private let cond = NSCondition()
    private var items: [T] = []

    func put(_ v: T) { cond.lock(); items.append(v); cond.broadcast(); cond.unlock() }

    func next(timeout: TimeInterval = 10) async -> T? {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if let v = take() { return v }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        return nil
    }

    private func take() -> T? {
        cond.lock()
        defer { cond.unlock() }
        return items.isEmpty ? nil : items.removeFirst()
    }

    var isEmpty: Bool { cond.lock(); defer { cond.unlock() }; return items.isEmpty }
}

extension Events {
    func queue() -> Queue<T> {
        let q = Queue<T>()
        subscribe { q.put($0) }
        return q
    }
}

/// FakeEngine is a computer built from the library alone: it serves tools 1, 2 and 4 and a hosted
/// tool, and answers with the messages of the contract fixtures. What a client sent is in `seen`.
final class FakeEngine {
    let node: Node
    private let lock = NSLock()
    private var _seen: [Seen] = []
    private var _overrides: [String: (JSONValue) -> JSONValue] = [:]
    private var _decide: ([Grant]) -> [Grant] = { $0 }

    /// Notifications the client sent (`session/cancel`…), as JSON-RPC messages.
    let fromClient = Queue<JSONValue>()
    let watchers = Queue<Bool>()
    /// The address of the paired client.
    private let pairedF = Future<String>()

    static let chatReads: Set<String> = ["initialize", "session/list", "session/load", "_p2pact/older", "_p2pact/commands", "_p2pact/files",
                                         "_p2pact/history", "_p2pact/projects", "_p2pact/agents", "_p2pact/image", "_p2pact/diff"]
    static let fleetReads: Set<String> = ["fleet/hello", "node/get", "session/list", "session/get", "session/messages", "fleet/watch", "fleet/unwatch"]
    static let pluginsReads: Set<String> = ["plugins/list", "plugins/log", "plugins/grants", "plugins/watch", "plugins/unwatch"]

    var seen: [Seen] { lock.locked { _seen } }

    /// What the person grants a newcomer that asked for wants; by default what it asked.
    var decide: ([Grant]) -> [Grant] {
        get { lock.locked { _decide } }
        set { lock.locked { _decide = newValue } }
    }

    /// Answers for a method ("1:session/list"), in place of the fixture's.
    func override(_ key: String, _ f: @escaping (JSONValue) -> JSONValue) { lock.locked { _overrides[key] = f } }

    init(dir: String) throws {
        node = try Node(dir: dir, name: "MacBook Pro")
        node.kind = Kind.computer
        try node.listenUdp("127.0.0.1:0")
        node.onWants = { [unowned self] _, wants in self.decide(wants) }
        node.onPaired = { [unowned self] p in self.pairedF.complete(p.addr) }
        node.onEvent = { [unowned self] _, tool, ev, args in
            if tool == 1 && ev == 1, let a = args.first { self.fromClient.put(jsonFromCbor(a)) }
        }
        node.handleLevel(1, 1) { [unowned self] _, level, args in try self.rpc(1, level, args, Self.chatReads) }
        node.handleLevel(2, 1) { [unowned self] _, level, args in try self.rpc(2, level, args, Self.fleetReads) }
        node.handleLevel(4, 1) { [unowned self] _, level, args in try self.rpc(4, level, args, Self.pluginsReads) }
        try node.handleTool("com.example.hello", 1) { _, args in
            .values([.text("hello " + (args.first?.asString ?? ""))])
        }
        node.start()
    }

    func invite() -> String { node.invite(ttlMs: 60_000).string }

    func clientAddr() throws -> String { try pairedF.get(timeout: 10) }

    private func rpc(_ tool: Int, _ level: Int, _ args: [Cbor.Value], _ reads: Set<String>) throws -> Reply {
        guard let first = args.first, let method = jsonFromCbor(first).str("method") else { throw P2pactError(Errors.badArgs, "no method") }
        let params = jsonFromCbor(first).obj("params") ?? .object([:])
        lock.locked { _seen.append(Seen(tool: tool, method: method, params: params, level: level)) }
        // one P2PACT method carries all of the tool: the level is checked on the JSON-RPC method (chat spec §6)
        if !reads.contains(method) && level < LEVEL_WRITE { throw P2pactError(Errors.forbidden, "forbidden") }
        let over = lock.locked { _overrides["\(tool):\(method)"] }
        let resp: JSONValue
        if let o = over { resp = o(params) } else {
            switch tool {
            case 1: resp = chat(method, params)
            case 2: resp = fleet(method, params)
            default: resp = plugins(method, params)
            }
        }
        return .values([cborFromJSON(tool == 1 && legacy ? Self.stripTyped(method, resp) : resp)])
    }

    /// An engine older than result version 2: the `_p2pact/*` results hold only `lines`.
    var legacy: Bool {
        get { lock.locked { _legacy } }
        set { lock.locked { _legacy = newValue } }
    }
    private var _legacy = false

    static func stripTyped(_ method: String, _ resp: JSONValue) -> JSONValue {
        guard method.hasPrefix("_p2pact/"), let result = resp.obj("result"), let lines = result["lines"] else { return resp }
        return ["jsonrpc": "2.0", "result": ["lines": lines]]
    }

    private func chat(_ method: String, _ params: JSONValue) -> JSONValue {
        let stem = method.replacingOccurrences(of: "/", with: ".")
        if method == "session/load" {
            for n in ["session.update.user_message", "session.update.agent_message", "session.update.tool_call"] {
                notifyChat(Fixtures.read("p2pact.chat", "\(n).notification"))
            }
            return ["jsonrpc": "2.0", "result": ["_meta": ["p2pact": ["older": true]]]]
        }
        if Fixtures.exists("p2pact.chat", "\(stem).response") { return Fixtures.read("p2pact.chat", "\(stem).response") }
        return ["jsonrpc": "2.0", "result": [:]]
    }

    private func fleet(_ method: String, _ params: JSONValue) -> JSONValue {
        let stem: String?
        switch method {
        case "fleet/hello": stem = "hello"
        case "session/list": stem = "session-list"
        case "session/get": stem = "session-get"
        case "session/messages": stem = "session-messages"
        case "fleet/watch": watchers.put(params.bool("partial") ?? false); stem = "watch"
        case "fleet/unwatch": stem = "unwatch"
        case "session/create": stem = "session-create"
        case "session/send": stem = params.str("id") == "нет" ? "session-send-unknown" : "session-send"
        case "settings/set": stem = "settings-set"
        default: stem = nil
        }
        if method == "node/get" {
            return ["jsonrpc": "2.0", "result": Fixtures.read("p2pact.fleet", "hello.response").obj("result")!.obj("node")!]
        }
        if let s = stem { return Fixtures.read("p2pact.fleet", "\(s).response") }
        return ["jsonrpc": "2.0", "result": ["ok": true]]
    }

    private func plugins(_ method: String, _ params: JSONValue) -> JSONValue {
        let stem = method.replacingOccurrences(of: "/", with: ".")
        if method == "plugins/log" && params.str("name") == "com.example.nope" { return Fixtures.read("p2pact.plugins", "plugins.log.unknown.response") }
        if Fixtures.exists("p2pact.plugins", "\(stem).response") { return Fixtures.read("p2pact.plugins", "\(stem).response") }
        return ["jsonrpc": "2.0", "error": ["code": -32601, "message": .string("no method \(method)")]]
    }

    // --- to the client ---

    /// notify sends a JSON-RPC notification as the tool's event, on the stream of its session or id.
    func notify(_ tool: Int, _ msg: JSONValue) {
        let p = msg.obj("params") ?? .object([:])
        let stream = streamOf(p.str("sessionId") ?? p.str("id"))
        try! node.eventOn(try! clientAddr(), stream: stream, tool, 1, [cborFromJSON(msg)])
    }

    func notifyChat(_ msg: JSONValue) { notify(1, msg) }

    /// ask makes a request of the client, as the agent device does (permissions, questions).
    func ask(_ tool: Int, _ msg: JSONValue, sessionId: String) async throws -> JSONValue {
        let r = try await node.callOn(try clientAddr(), stream: streamOf(sessionId), tool, 1, [cborFromJSON(msg)], timeoutMs: 10_000).value()
        return jsonFromCbor(r[0])
    }

    func close() { node.close() }
}

/// A client app paired with a FakeEngine in this process. Waits are on events, not on time.
class ClientTestCase: XCTestCase {
    var engine: FakeEngine!
    var client: P2pactClient!
    private var dirs: [String] = []

    override func tearDown() {
        client?.close()
        engine?.close()
        for d in dirs { try? FileManager.default.removeItem(atPath: d) }
        super.tearDown()
    }

    func tmp() -> String {
        let d = NSTemporaryDirectory() + "p2pact-client-test-" + UUID().uuidString
        try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true)
        dirs.append(d)
        return d
    }

    /// Starts the engine and the client; pairs with wants and waits until the computer's hello and its grants (0.6) came.
    func connect(wants: [Grant] = defaultWants, decide: (([Grant]) -> [Grant])? = nil) async throws -> Computer {
        engine = try FakeEngine(dir: tmp())
        if let d = decide { engine.decide = d }
        client = try P2pactClient(dir: tmp(), name: "Test app", config: ClientConfig(udp: "127.0.0.1:0", tcp: nil))
        let events = client.computerEvents.queue()
        let computer = try await client.pair(engine.invite(), wants: wants)
        try await computer.whenOnline()
        // the given or narrowed grants (event 0.6) come right after pairing, even when they are everything
        // (the engine first tells "nothing yet" while it decides, then the decision)
        let expected = engine.decide(wants)
        while !expected.allSatisfy({ computer.level($0.tool) == $0.level }) {
            guard await events.next() != nil else { XCTFail("event 0.6 with the decision did not come"); break }
        }
        return computer
    }

    /// What the client sent for method equals the fixture's params.
    func assertSent(_ tool: Int, _ method: String, _ dir: String, _ fixture: String, file: StaticString = #filePath, line: UInt = #line) {
        guard let s = engine.seen.last(where: { $0.tool == tool && $0.method == method }) else {
            return XCTFail("\(method) was not called", file: file, line: line)
        }
        XCTAssertEqual(s.params, Fixtures.params(dir, fixture), method, file: file, line: line)
    }

    func nextOrFail<T>(_ q: Queue<T>, _ what: String = "event", file: StaticString = #filePath, line: UInt = #line) async throws -> T {
        guard let v = await q.next() else {
            XCTFail("no \(what) within 10 s", file: file, line: line)
            throw CancellationError()
        }
        return v
    }

    func waitUntil(_ what: String, timeout: TimeInterval = 10, file: StaticString = #filePath, line: UInt = #line, _ f: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if f() { return }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out: \(what)", file: file, line: line)
    }
}

/// Runs an async call that must throw; gives the error.
func thrown<T>(_ f: () async throws -> T) async -> Error? {
    do { _ = try await f(); return nil } catch { return error }
}
