import Foundation
@preconcurrency import P2PACT

// Tool 2 `p2pact.fleet` (fleet spec): the computer and its agent sessions. JSON-RPC over `2.1 rpc`.

/// The computer as the fleet describes it (`Node`).
public struct FleetNode {
    public let id: String
    public let name: String
    public let os: String?
    /// online, lid, battery, temperature, working… as the computer reports.
    public let status: JSONValue
    public let agents: [AgentInfo]
    public let capabilities: JSONValue
    public let raw: JSONValue

    public init(_ m: JSONValue) {
        let caps = m.obj("capabilities") ?? .object([:])
        id = m.str("id") ?? ""
        name = m.str("name") ?? ""
        os = m.str("os")
        status = m.obj("status") ?? .object([:])
        agents = caps.objs("agents").map(AgentInfo.init)
        capabilities = caps
        raw = m
    }
}

public struct FleetHello {
    public let protocolVersion: String?
    public let node: FleetNode
    public let raw: JSONValue
}

/// An agent session of the fleet (`Session`): the same id as the chat's.
public struct FleetSession {
    public let id: String
    public let agent: String?
    public let model: String?
    public let dir: String?
    public let keep: Bool?
    public let perms: String?
    /// starting, working, waiting, idle… as the computer says.
    public let phase: String?
    public let title: String?
    /// RFC 3339.
    public let updated: String?
    /// The `ask` of the status, if the agent waits for the person.
    public let ask: JSONValue?
    public let raw: JSONValue

    public init(_ m: JSONValue) {
        let spec = m.obj("spec") ?? .object([:])
        let st = m.obj("status") ?? .object([:])
        id = m.str("id") ?? ""
        agent = spec.str("agent")
        model = spec.str("model")
        dir = spec.str("dir")
        keep = spec.bool("keep")
        perms = spec.str("perms")
        phase = st.str("phase")
        title = st.str("title")
        updated = st.str("updated")
        ask = st["ask"]
        raw = m
    }
}

/// What `session/create` starts. `extra` is added as it is, for fields this SDK does not know.
public struct SessionSpec {
    public var agent: String?
    public var dir: String?
    public var model: String?
    public var keep: Bool?
    public var perms: String?
    public var extra: [String: JSONValue]

    public init(agent: String? = nil, dir: String? = nil, model: String? = nil, keep: Bool? = nil, perms: String? = nil, extra: [String: JSONValue] = [:]) {
        self.agent = agent; self.dir = dir; self.model = model; self.keep = keep; self.perms = perms; self.extra = extra
    }

    public var json: JSONValue {
        var m: [String: JSONValue] = [:]
        if let a = agent { m["agent"] = .string(a) }
        if let d = dir { m["dir"] = .string(d) }
        if let x = model { m["model"] = .string(x) }
        if let k = keep { m["keep"] = .bool(k) }
        if let p = perms { m["perms"] = .string(p) }
        for (k, v) in extra { m[k] = v }
        return .object(m)
    }
}

public struct FleetMessage: Equatable {
    public let seq: Int64
    public let role: String
    public let text: String
    public let time: String?
    public let raw: JSONValue

    public init(_ m: JSONValue) {
        seq = m.long("seq") ?? 0
        role = m.str("role") ?? ""
        text = m.str("text") ?? ""
        time = m.str("time")
        raw = m
    }
}

/// `session/messages`: the replies after a number; `older` — there are earlier ones.
public struct FleetMessages {
    public let messages: [FleetMessage]
    public let last: Int64?
    public let older: Bool
    public let raw: JSONValue
}

public struct CloseResult {
    public let ok: Bool
    /// Done, but not smoothly.
    public let warning: String?
    public let raw: JSONValue
}

/// An event of a watch (fleet spec §4).
public enum FleetEvent {
    /// The whole list, at every change.
    case sessionsChanged([FleetSession])
    /// New replies of a session.
    case sessionMessages(id: String, messages: [FleetMessage])
    /// Replies of the session were lost: read `messages(id, after)` again.
    case resync(id: String)
    /// The agent's text while it is written (only if the watch asked for `partial`).
    case partial(id: String, message: JSONValue)
    /// What the computer would show as a notification.
    case notify(text: String)
    case other(method: String, params: JSONValue)
}

/// An active watch: `stop` unsubscribes.
public final class FleetWatch {
    /// The sessions at the start.
    public let sessions: [FleetSession]
    private let onStop: () async -> Void
    init(sessions: [FleetSession], onStop: @escaping () async -> Void) { self.sessions = sessions; self.onStop = onStop }
    public func stop() async { await onStop() }
}

public final class FleetClient {
    private let computer: Computer
    /// The events of the watch (`watch`); also after the computer restarted (the watch is repeated).
    public let events = Events<FleetEvent>()
    private let lock = NSLock()
    private var watching: Bool? // partial, or nil — not watching

    init(computer: Computer) { self.computer = computer }

    private func call(_ method: String, _ params: JSONValue? = nil, timeoutMs: Int64? = nil) async throws -> JSONValue {
        try await computer.rpc(Tools.fleetNumber, method, params, stream: streamOf(params?.str("id")), timeoutMs: timeoutMs)
    }

    // --- read ---

    public func hello() async throws -> FleetHello {
        let r = try await call("fleet/hello")
        return FleetHello(protocolVersion: r.str("protocol"), node: FleetNode(r.obj("node") ?? .object([:])), raw: r)
    }

    public func node() async throws -> FleetNode { FleetNode(try await call("node/get")) }

    public func sessions() async throws -> [FleetSession] { try await call("session/list").objs("sessions").map(FleetSession.init) }

    /// session is `session/get`; no such session — `RpcError` `-32004`.
    public func session(_ id: String) async throws -> FleetSession { FleetSession(try await call("session/get", ["id": .string(id)])) }

    /// messages is `session/messages`: the replies after number `after` (without it, the last `limit`).
    public func messages(_ id: String, after: Int64? = nil, limit: Int? = nil) async throws -> FleetMessages {
        var p: [String: JSONValue] = ["id": .string(id)]
        if let a = after { p["after"] = .int(a) }
        if let l = limit { p["limit"] = .int(Int64(l)) }
        let r = try await call("session/messages", .object(p))
        return FleetMessages(messages: r.objs("messages").map(FleetMessage.init), last: r.long("last"), older: r.bool("older") ?? false, raw: r)
    }

    /// watch subscribes to the fleet: `events` get the changes. Stop the result to unsubscribe. With
    /// `partial` the agent's text comes while it is written.
    public func watch(partial: Bool = false) async throws -> FleetWatch {
        lock.locked { watching = partial }
        let r = try await call("fleet/watch", ["partial": .bool(partial)])
        return FleetWatch(sessions: r.objs("sessions").map(FleetSession.init)) { [weak self] in
            if let s = self { s.lock.locked { s.watching = nil } }
            _ = try? await self?.call("fleet/unwatch")
        }
    }

    // --- write ---

    public func create(_ spec: SessionSpec, text: String? = nil) async throws -> FleetSession {
        var p: [String: JSONValue] = ["spec": spec.json]
        if let t = text { p["text"] = .string(t) }
        return FleetSession(try await call("session/create", .object(p), timeoutMs: 0))
    }

    /// send puts a message into the session.
    public func send(_ id: String, text: String) async throws {
        _ = try await call("session/send", ["id": .string(id), "text": .string(text)], timeoutMs: 0)
    }

    /// answer answers an agent's question (`answers`: question → label) or permission (`allow`).
    public func answer(_ id: String, waitId: String? = nil, answers: [String: String]? = nil, allow: Bool? = nil) async throws {
        var p: [String: JSONValue] = ["id": .string(id)]
        if let w = waitId { p["waitId"] = .string(w) }
        if let a = answers { p["answers"] = .object(a.mapValues { .string($0) }) }
        if let a = allow { p["allow"] = .bool(a) }
        _ = try await call("session/answer", .object(p), timeoutMs: 0)
    }

    public func interrupt(_ id: String) async throws { _ = try await call("session/interrupt", ["id": .string(id)], timeoutMs: 0) }

    public func close(_ id: String) async throws -> CloseResult {
        let r = try await call("session/close", ["id": .string(id)], timeoutMs: 0)
        return CloseResult(ok: r.bool("ok") ?? true, warning: r.str("warning"), raw: r)
    }

    /// setKeep keeps the agent running (on) or lets it stop.
    public func setKeep(_ id: String, on: Bool) async throws { _ = try await call("session/setKeep", ["id": .string(id), "on": .bool(on)], timeoutMs: 0) }

    /// The engine's state: version, mode, link, clients, peers (write: it names the device's data directory).
    public func status() async throws -> JSONValue { try await call("engine/status") }

    public func settings() async throws -> JSONValue { try await call("settings/get") }

    /// setSettings changes settings and gives them as they are after; invalid `patch` — `RpcError` `-32602`.
    public func setSettings(_ patch: JSONValue) async throws -> JSONValue { try await call("settings/set", ["patch": patch]) }

    /// Any other method of the fleet.
    public func request(_ method: String, params: JSONValue? = nil) async throws -> JSONValue { try await call(method, params) }

    // --- events ---

    func reconnected() {
        // the device forgot the subscription with its restart (fleet spec §4)
        let partial = lock.locked { watching }
        guard let partial = partial else { return }
        Task { _ = try? await call("fleet/watch", ["partial": .bool(partial)]) }
    }

    func notified(_ args: [Cbor.Value]) {
        guard let first = args.first else { return }
        let msg = jsonFromCbor(first)
        guard let method = msg.str("method") else { return }
        let p = msg.obj("params") ?? .object([:])
        switch method {
        case "session/changed": events.emit(.sessionsChanged(p.objs("sessions").map(FleetSession.init)))
        case "session/messages": events.emit(.sessionMessages(id: p.str("id") ?? "", messages: p.objs("messages").map(FleetMessage.init)))
        case "session/resync": events.emit(.resync(id: p.str("id") ?? ""))
        case "session/partial": events.emit(.partial(id: p.str("id") ?? "", message: p.obj("message") ?? .object([:])))
        case "notify": events.emit(.notify(text: p.str("text") ?? ""))
        default: events.emit(.other(method: method, params: p))
        }
    }
}
