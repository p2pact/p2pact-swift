import Foundation
@preconcurrency import P2PACT

/// ChatClient is tool 1 `p2pact.chat` of one computer: ACP over P2PACT with the `_p2pact/<name>`
/// extensions (chat spec). Methods that read need level 1 on the tool, the others level 2; a method
/// the grants refuse throws `P2pactCallError.forbidden`.
///
/// `initialize` goes first by itself (and again after the computer's hello comes anew). All calls
/// about one session ride the session's own stream, as the spec says.
public final class ChatClient {
    private let computer: Computer
    private var node: Node { computer.owner.node }

    /// Live messages of chats (and the history while a session is loaded).
    public let updates = Events<ChatUpdate>()
    /// A chat appeared, changed state or title, or closed (`_p2pact/session_changed`).
    public let sessionChanges = Events<ChatSession>()
    /// Another client answered a request: stop showing it.
    public let requestAnswered = Events<RequestAnswered>()
    /// Late lines of extension commands (`_p2pact/report`): JSON objects with `cmd`.
    public let reports = Events<JSONValue>()

    private let lock = NSLock()
    private var _permissionHandler: PermissionHandler?
    private var _questionHandler: QuestionHandler?
    private var known: [String: ChatSession] = [:]
    private var collectors: [(id: String, box: Collector)] = []
    private var pending: [String: Signal] = [:]
    private var initialized: Future<InitializeResult>?

    private final class Collector {
        let lock = NSLock()
        var items: [ChatUpdate] = []
        func add(_ u: ChatUpdate) { lock.locked { items.append(u) } }
        var all: [ChatUpdate] { lock.lock(); defer { lock.unlock() }; return items }
    }

    init(computer: Computer) { self.computer = computer }

    /// Answers `session/request_permission`; without one the computer gets "no such method" and asks elsewhere.
    public var permissionHandler: PermissionHandler? {
        get { lock.lock(); defer { lock.unlock() }; return _permissionHandler }
        set { lock.locked { _permissionHandler = newValue } }
    }

    /// Answers `_p2pact/question`.
    public var questionHandler: QuestionHandler? {
        get { lock.lock(); defer { lock.unlock() }; return _questionHandler }
        set { lock.locked { _questionHandler = newValue } }
    }

    /// The chats seen so far (from lists and changes), without the closed.
    public var sessions: [ChatSession] {
        lock.lock(); defer { lock.unlock() }
        return known.values.sorted { $0.id < $1.id }
    }

    /// What `initialize` said, once it has.
    public var info: InitializeResult? {
        let f = lock.locked { initialized }
        guard let f = f, f.isDone else { return nil }
        return try? f.get(timeout: 0.001)
    }

    // --- connection ---

    /// initialize says hello to the computer's chat: capabilities, the agents it offers. It also asks
    /// for the extension notifications (`_meta.p2pact.ext: 1`). The other calls do it for you.
    @discardableResult
    public func initialize() async throws -> InitializeResult {
        let params: JSONValue = [
            "protocolVersion": 1,
            "clientCapabilities": [:],
            "_meta": ["p2pact": ["ext": 1, "v": 2]]
        ]
        let f = Future<InitializeResult>()
        lock.locked { initialized = f }
        f.whenComplete { [weak self] r in
            if case .failure = r, let self = self {
                self.lock.lock()
                if self.initialized === f { self.initialized = nil }
                self.lock.unlock()
            }
        }
        let c = computer
        Task {
            do { f.complete(InitializeResult(try await c.rpc(Tools.chatNumber, "initialize", params))) } catch { f.fail(error) }
        }
        return try await f.value()
    }

    func reconnected() {
        lock.locked { initialized = nil }
    }

    private func ensureInitialized() async throws {
        let f = lock.locked { initialized }
        if let f = f { _ = try await f.value() } else { try await initialize() }
    }

    private func call(_ method: String, _ params: JSONValue?, stream: Int64 = 0, timeoutMs: Int64? = nil) async throws -> JSONValue {
        try await ensureInitialized()
        return try await computer.rpc(Tools.chatNumber, method, params, stream: stream, timeoutMs: timeoutMs)
    }

    /// call, then wait for the events queued on the stream before the result (a result may come ahead of them).
    private func settledCall(_ method: String, _ params: JSONValue?, stream: Int64) async throws -> JSONValue {
        let r = try await call(method, params, stream: stream)
        try await node.afterEvents(computer.id, stream: stream).value()
        return r
    }

    // --- chats ---

    /// listSessions is `session/list`: one page.
    public func listSessions(cwd: String? = nil, cursor: String? = nil) async throws -> SessionList {
        var p: [String: JSONValue] = [:]
        if let c = cwd { p["cwd"] = .string(c) }
        if let c = cursor { p["cursor"] = .string(c) }
        let r = try await call("session/list", .object(p))
        let list = r.objs("sessions").map(ChatSession.init)
        for s in list { remember(s) }
        return SessionList(sessions: list, nextCursor: r.str("nextCursor"), raw: r)
    }

    /// listAllSessions follows the cursor to the end.
    public func listAllSessions(cwd: String? = nil) async throws -> [ChatSession] {
        var all: [ChatSession] = []
        var cursor: String?
        while true {
            let page = try await listSessions(cwd: cwd, cursor: cursor)
            all += page.sessions
            guard let next = page.nextCursor, !next.isEmpty, !page.sessions.isEmpty else { return all }
            cursor = next
        }
    }

    /// newSession is `session/new`. `agent` is one of `InitializeResult.agents` (default: the first),
    /// `model` one of the agent's models, `text` the first task (sent at once), `perms` "skip" or "ask".
    /// `mid` makes a repeat after a restart harmless.
    public func newSession(cwd: String, agent: String? = nil, model: String? = nil, text: String? = nil, perms: String? = nil, mid: String = ChatClient.newMid()) async throws -> NewSession {
        var meta: [String: JSONValue] = [:]
        if let a = agent { meta["agent"] = .string(a) }
        meta["mid"] = .string(mid)
        if let m = model { meta["model"] = .string(m) }
        if let t = text { meta["text"] = .string(t) }
        if let p = perms { meta["perms"] = .string(p) }
        let params: JSONValue = ["cwd": .string(cwd), "mcpServers": [], "_meta": ["p2pact": .object(meta)]]
        let r = try await call("session/new", params)
        guard let id = r.str("sessionId") else { throw P2pactCallError.failed("no sessionId in the answer") }
        return NewSession(sessionId: id, raw: r)
    }

    /// loadSession is `session/load`: the chat's history comes as updates (also to `updates`) and is
    /// in the result when it returns. A long chat comes as its tail: `LoadedSession.older`; `older`
    /// fetches the earlier part.
    public func loadSession(_ sessionId: String, cwd: String = "") async throws -> LoadedSession {
        let stream = streamOf(sessionId)
        let box = Collector()
        lock.locked { collectors.append((sessionId, box)) }
        defer {
            lock.locked { if let i = collectors.firstIndex(where: { $0.box === box }) { collectors.remove(at: i) } }
        }
        let params: JSONValue = ["sessionId": .string(sessionId), "cwd": .string(cwd), "mcpServers": []]
        // the result may come ahead of the last updates queued before it: wait for them
        let r = try await settledCall("session/load", params, stream: stream)
        return LoadedSession(sessionId: sessionId, updates: box.all, older: r.p2pactMeta.bool("older") ?? false, raw: r)
    }

    /// prompt is `session/prompt`: it returns when the agent's turn ends (minutes, no timeout); the
    /// reply comes as `updates` meanwhile. `mid` is kept for repeats: send the same one if you do not
    /// know whether the first went.
    public func prompt(_ sessionId: String, text: String, mid: String = ChatClient.newMid()) async throws -> PromptResult {
        try await prompt(sessionId, blocks: [ContentBlock.text(text)], mid: mid)
    }

    public func prompt(_ sessionId: String, blocks: [JSONValue], mid: String = ChatClient.newMid()) async throws -> PromptResult {
        let params: JSONValue = ["sessionId": .string(sessionId), "prompt": .array(blocks), "_meta": ["p2pact": ["mid": .string(mid)]]]
        let r = try await call("session/prompt", params, stream: streamOf(sessionId), timeoutMs: 0)
        return PromptResult(stopReason: r.str("stopReason"), duplicate: r.bool("duplicate") ?? false, raw: r)
    }

    /// cancel is the notification `session/cancel`: the agent stops the turn.
    public func cancel(_ sessionId: String) throws {
        try computer.notify(Tools.chatNumber, "session/cancel", ["sessionId": .string(sessionId)], stream: streamOf(sessionId))
    }

    @discardableResult
    public func setMode(_ sessionId: String, modeId: String) async throws -> JSONValue {
        try await call("session/set_mode", ["sessionId": .string(sessionId), "modeId": .string(modeId)], stream: streamOf(sessionId))
    }

    @discardableResult
    public func setModel(_ sessionId: String, modelId: String) async throws -> JSONValue {
        try await call("session/set_model", ["sessionId": .string(sessionId), "modelId": .string(modelId)], stream: streamOf(sessionId))
    }

    /// request is any ACP or extension method that has no typed call: the `result` object. It rides the
    /// stream of the params' `sessionId`, or `stream` when given (0: the computer's own stream). Like
    /// `loadSession`, it returns after the events the computer sent before the result have been handled.
    public func request(_ method: String, params: JSONValue, stream: Int64? = nil) async throws -> JSONValue {
        try await settledCall(method, params, stream: stream ?? streamOf(params.str("sessionId")))
    }

    // --- extensions (chat spec §10) ---

    /// command calls `_p2pact/<name>` and gives its lines (§9.3): JSON objects with `cmd`. Lines that
    /// come later arrive in `reports`. A failure the person should see is the line `{"cmd":"alert"}`.
    public func command(_ name: String, params: JSONValue = [:]) async throws -> [JSONValue] {
        try await settledCall("_p2pact/\(name)", params, stream: streamOf(params.str("sessionId"))).objs("lines")
    }

    /// The whole `result` of `_p2pact/<name>`, and where its content is: the result itself when it has one of the
    /// typed `keys` (an engine of result version 2), else the line `cmd == name` of `lines` (an older engine; the
    /// line may also be missing: then `{}`). Content that an older engine sends late (`commands`, `agents`,
    /// `history`) is not in the result there: it comes in `reports`, and the typed result is empty (not waited for).
    private func extCall(_ name: String, _ params: JSONValue, keys: [String]) async throws -> (src: JSONValue, lines: [JSONValue]) {
        let r = try await settledCall("_p2pact/\(name)", params, stream: streamOf(params.str("sessionId")))
        let lines = r.objs("lines")
        if keys.contains(where: { r[$0] != nil }) { return (r, lines) }
        return (lines.first { $0.str("cmd") == name } ?? .object([:]), lines)
    }

    private func action(_ name: String, _ params: JSONValue) async throws -> ActionResult {
        let r = try await settledCall("_p2pact/\(name)", params, stream: streamOf(params.str("sessionId")))
        let lines = r.objs("lines")
        if let ok = r.bool("ok") { return ActionResult(ok: ok, error: r.str("error"), lines: lines, raw: r) }
        // an older engine: no `ok`; a refusal is the line `alert`
        let alert = lines.first { $0.str("cmd") == "alert" }
        return ActionResult(ok: alert == nil, error: alert?.str("text") ?? alert?.str("error"), lines: lines, raw: r)
    }

    /// close closes the chat: it leaves the list.
    @discardableResult
    public func close(_ sessionId: String) async throws -> ActionResult { try await action("close", ["sessionId": .string(sessionId)]) }

    /// restart starts the agent of a chat again.
    @discardableResult
    public func restart(_ sessionId: String) async throws -> ActionResult { try await action("restart", ["sessionId": .string(sessionId)]) }

    /// hide hides a chat from the list (on) or shows it again.
    @discardableResult
    public func hide(_ sessionId: String, on: Bool = true) async throws -> ActionResult {
        try await action("hide", ["sessionId": .string(sessionId), "on": .bool(on)])
    }

    /// historyOpen is `_p2pact/history_open`: opens a past conversation (an item of `history`) as a chat.
    @discardableResult
    public func historyOpen(_ id: String) async throws -> ActionResult { try await action("history_open", ["sessionId": .string(id)]) }

    /// older is `_p2pact/older`: the page of messages just before `before` (the `seq` of the oldest you have).
    public func older(_ sessionId: String, before: Int64) async throws -> OlderPage {
        let (l, _) = try await extCall("older", ["sessionId": .string(sessionId), "before": .int(before)], keys: ["messages"])
        let msgs = l.objs("messages").map { m in
            ChatMessage(seq: m.long("seq") ?? 0, role: m.str("role") ?? "", text: m.str("text") ?? "", time: m.str("time"),
                        images: m["images"]?.arrayValue?.compactMap { $0.stringValue } ?? [], raw: m)
        }
        return OlderPage(sessionId: sessionId, messages: msgs, more: l.bool("more") ?? false, run: l.str("run"), raw: l)
    }

    /// diff is `_p2pact/diff`: the changes in the chat's folder (git).
    public func diff(_ sessionId: String) async throws -> DiffResult {
        let (l, _) = try await extCall("diff", ["sessionId": .string(sessionId)], keys: ["files", "patch", "error"])
        let files = l.objs("files").map { DiffFile(path: $0.str("path") ?? "", added: $0.int("added") ?? 0, removed: $0.int("removed") ?? 0, status: $0.str("status")) }
        return DiffResult(files: files, patch: l.str("patch") ?? "", truncated: l.bool("truncated") ?? false, error: l.str("error"), raw: l)
    }

    /// image is `_p2pact/image`: the bytes (base64) of an image a message points to.
    public func image(_ sessionId: String, path: String) async throws -> ImageResult {
        let (l, _) = try await extCall("image", ["sessionId": .string(sessionId), "path": .string(path)], keys: ["path", "data", "error"])
        return ImageResult(path: l.str("path"), mime: l.str("mime"), data: l.str("data"), error: l.str("error"), raw: l)
    }

    /// commands is `_p2pact/commands`: the slash commands of a chat.
    public func commands(_ sessionId: String) async throws -> [ChatCommand] {
        let (l, _) = try await extCall("commands", ["sessionId": .string(sessionId)], keys: ["commands"])
        let list = l["commands"] != nil ? l.objs("commands") : l.objs("list")
        return list.map { c in
            ChatCommand(name: c.str("name") ?? "", desc: c.str("desc"), hint: c.str("hint"),
                        args: c.objs("args").map { CommandArg(value: $0.str("value") ?? "", desc: $0.str("desc")) }, raw: c)
        }
    }

    /// files is `_p2pact/files`: paths in the chat's folder that match `query`.
    public func files(_ sessionId: String, query: String) async throws -> FilesResult {
        let (l, _) = try await extCall("files", ["sessionId": .string(sessionId), "query": .string(query)], keys: ["files"])
        let list = l["files"] != nil ? l.strings("files") : l.strings("list")
        return FilesResult(files: list, query: l.str("query") ?? query, raw: l)
    }

    /// history is `_p2pact/history`: past conversations of the computer's agents, a page from `offset`.
    /// Continue from `cursor` while it is there.
    public func history(query: String = "", offset: Int = 0) async throws -> HistoryPage {
        let (l, _) = try await extCall("history", ["query": .string(query), "offset": .int(Int64(offset))], keys: ["items"])
        let list = l["items"] != nil ? l.objs("items") : l.objs("list")
        let items = list.map { h in
            HistoryItem(id: h.str("id") ?? "", agent: h.str("agent"), dir: h.str("dir"), title: h.str("title"),
                        updated: h.long("updated"), count: h.int("count"), raw: h)
        }
        return HistoryPage(items: items, query: l.str("query") ?? query, from: l.int("from") ?? offset, total: l.int("total") ?? items.count,
                           cursor: l.int("cursor"), partial: l.bool("partial") ?? false, raw: l)
    }

    /// projects is `_p2pact/projects`: the folders the computer works in (for `cwd`, the ones of that project).
    public func projects(cwd: String? = nil) async throws -> ProjectsResult {
        var p: [String: JSONValue] = [:]
        if let c = cwd { p["cwd"] = .string(c) }
        let (l, _) = try await extCall("projects", .object(p), keys: ["dirs", "project_dirs", "dir_repos"])
        var pd: [String: [String]] = [:]
        for (k, v) in l["project_dirs"]?.objectValue ?? [:] { pd[k] = v.arrayValue?.compactMap { $0.stringValue } ?? [] }
        var dr: [String: String] = [:]
        for (k, v) in l["dir_repos"]?.objectValue ?? [:] { if let s = v.stringValue { dr[k] = s } }
        return ProjectsResult(dirs: l.strings("dirs"), projectDirs: pd, dirRepos: dr, raw: l)
    }

    /// agents is `_p2pact/agents`: the agents the computer can start and the presets.
    public func agents() async throws -> AgentsResult {
        let r = try await settledCall("_p2pact/agents", [:], stream: 0)
        var agents = r.objs("agents")
        var presets = r.objs("presets")
        if r["agents"] == nil && r["presets"] == nil { // an older engine: two lines with `list`
            let lines = r.objs("lines")
            agents = lines.first { $0.str("cmd") == "agents" }?.objs("list") ?? []
            presets = lines.first { $0.str("cmd") == "presets" }?.objs("list") ?? []
        }
        return AgentsResult(
            agents: agents.map { a in
                ChatAgent(id: a.str("id") ?? "", name: a.str("name") ?? a.str("id") ?? "", type: a.str("type"), enabled: a.bool("enabled") ?? true,
                          models: a.strings("models"), defaultModel: a.str("default"), raw: a)
            },
            presets: presets.map { AgentPreset(id: $0.str("id") ?? "", name: $0.str("name") ?? "", raw: $0) },
            raw: r)
    }

    // --- from the computer ---

    private func remember(_ s: ChatSession) {
        if s.id.isEmpty { return }
        lock.lock()
        if s.state == .closed { known.removeValue(forKey: s.id) } else { known[s.id] = s }
        lock.unlock()
    }

    /// A `notify` event (`session/update`, `_p2pact/…`).
    func notified(_ args: [Cbor.Value]) {
        guard let first = args.first else { return }
        let msg = jsonFromCbor(first)
        let params = msg.obj("params") ?? .object([:])
        switch msg.str("method") {
        case "session/update":
            guard let sid = params.str("sessionId"), let up = params.obj("update") else { return }
            let u = ChatUpdate(sessionId: sid, update: up)
            let cs = lock.locked { collectors.filter { $0.id == sid } }
            for c in cs { c.box.add(u) }
            updates.emit(u)
        case "_p2pact/session_changed":
            let s = ChatSession(params)
            remember(s)
            sessionChanges.emit(s)
        case "_p2pact/request_answered":
            guard let sid = params.str("sessionId"), let tc = params.str("toolCallId") else { return }
            let sig = lock.locked { pending.removeValue(forKey: "\(sid)/\(tc)") }
            sig?.fire()
            requestAnswered.emit(RequestAnswered(sessionId: sid, toolCallId: tc))
        case "_p2pact/report", "_nomad/report": // _nomad/…: an engine older than the ext flag
            if let line = params.obj("line") { reports.emit(line) }
        default: break
        }
    }

    /// A request of the computer (`1.1 rpc`): the answer as a JSON-RPC message.
    func incoming(_ args: [Cbor.Value]) -> Reply {
        guard let first = args.first, jsonFromCbor(first).objectValue != nil else { return .values(error(RpcError.invalidParams, "bad request")) }
        let req = jsonFromCbor(first)
        let params = req.obj("params") ?? .object([:])
        switch req.str("method") {
        case "session/request_permission":
            guard let h = permissionHandler else { return .values(error(RpcError.methodNotFound, "method not found")) }
            let sid = params.str("sessionId") ?? ""
            let call = ToolCallInfo(params.obj("toolCall") ?? .object([:]))
            let answered = Signal()
            let key = "\(sid)/\(call.toolCallId)"
            lock.locked { pending[key] = answered }
            let options = params.objs("options").map {
                PermissionOption(optionId: $0.str("optionId") ?? "", name: $0.str("name") ?? "", kind: $0.str("kind"), description: $0.p2pactMeta.str("description"), raw: $0)
            }
            let request = PermissionRequest(sessionId: sid, toolCall: call, options: options, raw: params, answered: answered)
            return ask(answered, key) {
                let o = try await h(request)
                switch o {
                case .selected(let id): return ["outcome": ["outcome": "selected", "optionId": .string(id)]]
                case .cancelled: return ["outcome": ["outcome": "cancelled"]]
                }
            }
        case "_p2pact/question", "_nomad/question": // _nomad/…: an engine older than the ext flag
            guard let h = questionHandler else { return .values(error(RpcError.methodNotFound, "method not found")) }
            let sid = params.str("sessionId") ?? ""
            let tc = params.str("toolCallId") ?? ""
            let answered = Signal()
            let key = "\(sid)/\(tc)"
            lock.locked { pending[key] = answered }
            let questions = params.objs("questions").map { q in
                Question(question: q.str("question") ?? "", header: q.str("header"), multi: q.bool("multi") ?? false,
                         options: q.objs("options").map { QuestionOption(label: $0.str("label") ?? "", description: $0.str("description")) })
            }
            let request = QuestionRequest(sessionId: sid, toolCallId: tc, questions: questions, raw: params, answered: answered)
            return ask(answered, key) {
                let a = try await h(request)
                return ["answers": .object(a.mapValues { .string($0) })]
            }
        default:
            // fs and terminal methods: the agent device does not use our files (chat spec §7)
            return .values(error(RpcError.methodNotFound, "method not found"))
        }
    }

    /// ask runs the application's handler; the request ends when it answers or another client did first.
    private func ask(_ answered: Signal, _ key: String, _ run: @escaping () async throws -> JSONValue) -> Reply {
        let out = Future<[Cbor.Value]>()
        let task = Task { [weak self] in
            do {
                let r = try await run()
                out.complete(self?.result(r) ?? [])
            } catch {
                out.complete(self?.error(RpcError.failed, "\(error)") ?? [])
            }
            if let s = self { s.lock.locked { _ = s.pending.removeValue(forKey: key) } }
        }
        // another client answered first: our reply is not needed, but the stream must go on
        answered.onFire {
            out.complete(self.error(RpcError.failed, "answered elsewhere"))
            task.cancel()
        }
        return .later(out)
    }

    private func result(_ r: JSONValue) -> [Cbor.Value] { [cborFromJSON(["jsonrpc": "2.0", "result": r])] }

    private func error(_ code: Int, _ message: String) -> [Cbor.Value] {
        [cborFromJSON(["jsonrpc": "2.0", "error": ["code": .int(Int64(code)), "message": .string(message)]])]
    }

    /// A fresh message id for `prompt` and `newSession`.
    public static func newMid() -> String { String(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(16)) }
}
