import Foundation
@preconcurrency import P2PACT

// Tool 4 `p2pact.plugins` (plugins spec): the plugins a computer hosts. JSON-RPC over `4.1 rpc`.
// Install and remove stay on the computer.

public enum PluginStatus: String {
    case running, starting, restarting
    /// Switched off.
    case stopped
    /// Disabled after repeated exits.
    case failed
    /// Not for this system.
    case unsupported
    /// Unreadable manifest.
    case broken
    case unknown

    init(wire: String?) { self = wire.flatMap { PluginStatus(rawValue: $0) } ?? .unknown }
}

public struct PluginInfo {
    public let name: String
    public let version: String?
    public let title: String?
    public let enabled: Bool
    public let status: PluginStatus
    public let error: String?
    public let restarts: Int
    public let pid: Int?
    /// The tool names the manifest allows.
    public let tools: [String]
    /// The tools the plugin has announced now, a subset of `tools`.
    public let announced: [String]
    /// `tool[:read|:write]` the plugin asked for.
    public let needs: [String]
    public let raw: JSONValue

    public init(_ m: JSONValue) {
        name = m.str("name") ?? ""
        version = m.str("version")
        title = m.str("title")
        enabled = m.bool("enabled") ?? false
        status = PluginStatus(wire: m.str("status"))
        error = m.str("error")
        restarts = m.int("restarts") ?? 0
        pid = m.int("pid")
        tools = m.strings("tools")
        announced = m.strings("announced")
        needs = m.strings("needs")
        raw = m
    }
}

/// What a plugin may use of the computer, and which methods of its own tools need only read.
public struct PluginGrants {
    public let name: String
    public let grants: [Grant]
    public let read: [String: [Int]]
    public let raw: JSONValue
}

/// An event of the plugins watch (plugins spec §2).
public enum PluginEvent {
    /// `plugin` as `plugins/list` gives it, now; `removed` means it is gone (the last entry).
    case changed(PluginInfo, removed: Bool)
    case other(method: String, params: JSONValue)
}

/// An active plugins watch: `stop` unsubscribes.
public final class PluginsWatch {
    /// The plugins at the start.
    public let plugins: [PluginInfo]
    private let onStop: () async -> Void
    init(plugins: [PluginInfo], onStop: @escaping () async -> Void) { self.plugins = plugins; self.onStop = onStop }
    public func stop() async { await onStop() }
}

/// The engine sends the level as "read"/"write"; an integer (1, 2) is accepted too.
func levelOf(_ v: JSONValue?) -> Int? {
    switch v {
    case .int(let i)?: return Int(i)
    case .double(let d)?: return Int(d)
    case .string("read")?: return LEVEL_READ
    case .string("write")?: return LEVEL_WRITE
    default: return nil
    }
}

public final class PluginsClient {
    private let computer: Computer
    /// The events of the watch (`watch`); also after the computer restarted (the watch is repeated).
    public let events = Events<PluginEvent>()
    private let lock = NSLock()
    private var watching = false

    init(computer: Computer) { self.computer = computer }

    private func call(_ method: String, _ params: JSONValue? = nil) async throws -> JSONValue {
        try await computer.rpc(Tools.pluginsNumber, method, params)
    }

    /// watch is `plugins/watch`: `events` get `plugins/changed`. Stop the result to unsubscribe.
    public func watch() async throws -> PluginsWatch {
        lock.locked { watching = true }
        let r = try await call("plugins/watch")
        return PluginsWatch(plugins: r.objs("plugins").map(PluginInfo.init)) { [weak self] in try? await self?.unwatch() }
    }

    /// unwatch is `plugins/unwatch`.
    public func unwatch() async throws {
        lock.locked { watching = false }
        _ = try await call("plugins/unwatch")
    }

    func reconnected() {
        // the device forgot the subscription with its restart (plugins spec §2)
        let w = lock.locked { watching }
        if w { Task { _ = try? await call("plugins/watch") } }
    }

    func notified(_ args: [Cbor.Value]) {
        guard let first = args.first else { return }
        let msg = jsonFromCbor(first)
        guard let method = msg.str("method") else { return }
        let p = msg.obj("params") ?? .object([:])
        switch method {
        case "plugins/changed": events.emit(.changed(PluginInfo(p), removed: p.bool("removed") ?? false))
        default: events.emit(.other(method: method, params: p))
        }
    }

    /// list is `plugins/list`.
    public func list() async throws -> [PluginInfo] { try await call("plugins/list").objs("plugins").map(PluginInfo.init) }

    /// log is `plugins/log`: the last `lines` lines of the plugin's log.
    public func log(_ name: String, lines: Int? = nil) async throws -> String {
        var p: [String: JSONValue] = ["name": .string(name)]
        if let l = lines { p["lines"] = .int(Int64(l)) }
        return try await call("plugins/log", .object(p)).str("log") ?? ""
    }

    /// grants is `plugins/grants`.
    public func grants(_ name: String) async throws -> PluginGrants {
        let r = try await call("plugins/grants", ["name": .string(name)])
        let grants = (r["grants"]?.arrayValue ?? []).compactMap { g -> Grant? in
            guard let t = g.str("tool"), let l = levelOf(g["level"]) else { return nil }
            return Grant(t, l)
        }
        var read: [String: [Int]] = [:]
        for (k, v) in r["read"]?.objectValue ?? [:] { read[k] = v.arrayValue?.compactMap { $0.intValue } ?? [] }
        return PluginGrants(name: r.str("name") ?? name, grants: grants, read: read, raw: r)
    }

    /// enable starts a plugin (and keeps it on across the computer's restarts). Needs write.
    public func enable(_ name: String) async throws { _ = try await call("plugins/enable", ["name": .string(name)]) }

    public func disable(_ name: String) async throws { _ = try await call("plugins/disable", ["name": .string(name)]) }

    /// callTool calls a method of a tool a plugin of the computer serves (core spec §8.2) by the tool's
    /// name; the number is the computer's own. See `Computer.callTool`.
    public func callTool(_ name: String, method: Int, args: [JSONValue] = []) async throws -> [JSONValue] {
        try await computer.callTool(name, method: method, args: args)
    }
}
