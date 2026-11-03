import Foundation
@preconcurrency import P2PACT

/// The names of the public tools (core spec §8).
public enum Tools {
    public static let chat = "p2pact.chat"
    public static let fleet = "p2pact.fleet"
    public static let plugins = "p2pact.plugins"

    static let chatNumber = 1
    static let fleetNumber = 2
    static let pluginsNumber = 4
}

/// What the SDK itself uses, to ask for when pairing: chat and fleet in full, the plugins' view.
/// The person of the computer may narrow it (`Computer.grants` tells what was granted).
public let defaultWants: [Grant] = [
    Grant(Tools.chat, LEVEL_WRITE),
    Grant(Tools.fleet, LEVEL_WRITE),
    Grant(Tools.plugins, LEVEL_READ)
]

/// ClientConfig is how a client reaches computers. `udp` and `tcp` are the addresses it listens on
/// ("" for tcp — only dials; nil — no such road); `relay` is a relay to use when a computer's invite names none.
public struct ClientConfig {
    public var udp: String?
    public var tcp: String?
    public var relay: RelayHint?
    /// How long a call waits for its answer, seconds; 0 — for ever. Prompts never time out.
    public var callTimeout: TimeInterval
    public var pairTimeout: TimeInterval

    public init(udp: String? = "0.0.0.0:0", tcp: String? = "", relay: RelayHint? = nil, callTimeout: TimeInterval = 60, pairTimeout: TimeInterval = 30) {
        self.udp = udp; self.tcp = tcp; self.relay = relay; self.callTimeout = callTimeout; self.pairTimeout = pairTimeout
    }
}

public enum ConnectionState {
    /// No live road to the computer.
    case offline
    /// A session with the computer runs and it has told its tools.
    case online
}

/// A change of a computer the application may show.
public enum ComputerEvent {
    /// Pairing finished (on our side).
    case paired(Computer)
    /// The computer's hello came: a session runs, its tools are known. After a restart it comes again.
    case online(Computer)
    /// The computer told what we may use of its tools (event 0.6).
    case grantsChanged(Computer, [Grant])
    case forgotten(Computer)

    public var computer: Computer {
        switch self {
        case .paired(let c), .online(let c), .grantsChanged(let c, _), .forgotten(let c): return c
        }
    }
}

/// An event of a tool the SDK has no typed layer for (a plugin's tool): the numbers are the computer's.
public struct ToolEvent {
    public let computer: Computer
    public let tool: String?
    public let toolNumber: Int
    public let event: Int
    public let args: [JSONValue]
    /// The arguments as they came (byte strings stay bytes).
    public let rawArgs: [Cbor.Value]
}

/// P2pactClient is an application's side of P2PACT: it pairs with computers (devices running the
/// P2PACT engine) by their invite, keeps them, and gives the typed clients of their public tools.
/// The state (keys, paired computers) lives in `dir`; keeping that safe is the application's job.
///
///     let client = try P2pactClient(dir: dataDir, name: "My app")
///     let computer = try await client.pair("p2pact1.…")
///     let chats = try await computer.chat.listSessions()
///
/// Calls are `async` and throw `P2pactCallError` (the P2PACT error codes) or `RpcError` (the tool's own errors).
public final class P2pactClient {
    /// The protocol node: for what this SDK does not wrap. Do not set its callbacks (unless you wrapped it: see `hello`).
    public let node: Node
    public let config: ClientConfig
    private let owned: Bool
    private let lock = NSLock()
    private var computersByID: [String: Computer] = [:]

    /// Pairing, hellos and grants of computers.
    public let computerEvents = Events<ComputerEvent>()
    /// Events of tools without a typed layer (a plugin's tool).
    public let toolEvents = Events<ToolEvent>()

    /// Starts a client that keeps its state in `dir`, makes the node and runs it.
    public convenience init(dir: String, name: String, config: ClientConfig = ClientConfig()) throws {
        self.init(node: try Node(dir: dir, name: name), config: config, owned: true)
    }

    /// Wrapping initializer: the typed clients over a node the application already runs (it owns the
    /// keys, the roads, the pairing and the node's callbacks). The SDK only serves the chat tool's
    /// calls from the computers (`handle`, so wrap before `node.start()`); `config`'s roads are not
    /// used. The application keeps `onHello`, `onEvent`, `onGranted` and `onPaired` of the node and
    /// passes them on: `hello`, `event`, `granted`, `paired`. `close` leaves the node open.
    public convenience init(node: Node, config: ClientConfig = ClientConfig()) {
        self.init(node: node, config: config, owned: false)
    }

    private init(node: Node, config: ClientConfig, owned: Bool) {
        self.node = node
        self.config = config
        self.owned = owned
        if owned {
            node.kind = Kind.client
            if let u = config.udp { try? node.listenUdp(u) }
            if let t = config.tcp { try? node.listenTcp(t) }
            if let r = config.relay { node.setRelay(r) }
            node.onPaired = { [weak self] p in self?.paired(p) }
            node.onHello = { [weak self] a in self?.hello(a) }
            node.onGranted = { [weak self] a, g in self?.granted(a, g) }
            node.onEvent = { [weak self] a, t, e, args in self?.event(a, t, e, args) }
        }
        // the computer's calls into the chat tool: permissions and questions of agents (chat spec §6, §9.1)
        node.handle(Tools.chatNumber, 1) { [weak self] addr, args in
            guard let c = self?.computerOrNil(addr) else { throw P2pactError(Errors.forbidden, "unknown computer") }
            return c.chat.incoming(args)
        }
        if owned { node.start() }
    }

    /// The computer's hello came (the node's `onHello`): for a wrapped node, pass it on first thing.
    public func hello(_ addr: String) { computerOrNil(addr)?.helloArrived() }

    /// An event of a tool from a computer (the node's `onEvent`): for a wrapped node, in the order the node gave it.
    public func event(_ addr: String, _ tool: Int, _ ev: Int, _ args: [Cbor.Value]) { dispatch(addr, tool, ev, args) }

    /// The computer told what we may use (the node's `onGranted`).
    public func granted(_ addr: String, _ grants: [Grant]) {
        if let c = computerOrNil(addr) { computerEvents.emit(.grantsChanged(c, grants)) }
    }

    /// Pairing finished (the node's `onPaired`).
    public func paired(_ p: Peer) {
        if usable(p) { computerEvents.emit(.paired(computerOf(p.addr))) }
    }

    private func usable(_ p: Peer) -> Bool { p.kind != Kind.plugin && p.kind != Kind.client }

    /// pair pairs with a computer by its invite (`p2pact1.…`, from `nomad invite` or the like) as a
    /// client application, asking for `wants`. It returns when the pairing is done; the person at the
    /// computer may narrow the grants later still: `ComputerEvent.grantsChanged`.
    public func pair(_ invite: String, wants: [Grant] = defaultWants, timeout: TimeInterval? = nil) async throws -> Computer {
        let inv: Invite
        do { inv = try Invite.parse(invite) } catch { throw typed(error) }
        let peer = try await node.joinAsync(inv, timeoutMs: Int64((timeout ?? config.pairTimeout) * 1000), wants: wants).value()
        return computerOf(peer.addr)
    }

    /// computers lists the paired computers.
    public func computers() -> [Computer] { node.knownPeers().filter(usable).map { computerOf($0.addr) } }

    /// computer finds a paired computer by its address (`Computer.id`) or nil.
    public func computer(id: String) -> Computer? { computerOrNil(id) }

    /// forget unpairs a computer: its keys and conversation state go.
    public func forget(_ computer: Computer) {
        node.forget(computer.id)
        lock.locked { computersByID.removeValue(forKey: computer.id) }
        computerEvents.emit(.forgotten(computer))
    }

    /// close stops the node (a wrapped node stays open).
    public func close() {
        if owned { node.close() }
    }

    // --- internals ---

    func computerOrNil(_ addr: String) -> Computer? {
        lock.lock()
        if let c = computersByID[addr] { lock.unlock(); return c }
        lock.unlock()
        guard let p = node.peer(addr), usable(p) else { return nil }
        return computerOf(addr)
    }

    private func computerOf(_ addr: String) -> Computer {
        lock.lock(); defer { lock.unlock() }
        if let c = computersByID[addr] { return c }
        let c = Computer(owner: self, id: addr)
        computersByID[addr] = c
        return c
    }

    private func dispatch(_ addr: String, _ tool: Int, _ ev: Int, _ args: [Cbor.Value]) {
        guard let c = computerOrNil(addr) else { return }
        switch (tool, ev) {
        case (Tools.chatNumber, 1): c.chat.notified(args)
        case (Tools.fleetNumber, 1): c.fleet.notified(args)
        case (Tools.pluginsNumber, 1): c.plugins.notified(args)
        case (Tools.pluginsNumber, _): break
        default:
            toolEvents.emit(ToolEvent(computer: c, tool: node.peerToolName(addr, tool), toolNumber: tool, event: ev, args: args.map(jsonFromCbor), rawArgs: args))
        }
    }
}

/// Computer is a paired computer: the device that runs agents. The typed clients of its tools hang
/// off it: `chat`, `fleet`, `plugins`.
public final class Computer {
    let owner: P2pactClient
    public let id: String
    private var node: Node { owner.node }
    private let ready = Future<Void>()
    private let lock = NSLock()
    private var hasHello = false
    private var chatClient: ChatClient?
    private var fleetClient: FleetClient?
    private var pluginsClient: PluginsClient?

    init(owner: P2pactClient, id: String) { self.owner = owner; self.id = id }

    public var name: String { node.peer(id)?.name ?? "" }
    public var os: String? { node.peer(id)?.os }

    /// Whether a session with the computer runs and it has told its tools.
    public var state: ConnectionState {
        let h = lock.locked { hasHello }
        return h && !node.paths(id).isEmpty ? .online : .offline
    }

    /// The roads in use: `udp`, `tcp`, `relay:<address>`…
    public var paths: [String] { node.paths(id) }

    /// What the computer lets us use of its tools, as it told us (event 0.6). Paired with wants (the
    /// SDK always asks): nothing until the first 0.6 arrives.
    public var grants: [Grant] { node.grantedBy(id) ?? defaultGrants() }

    /// The level we have on a tool of the computer: 0 none, 1 `LEVEL_READ`, 2 `LEVEL_WRITE`.
    public func level(_ tool: String) -> Int { grantLevel(grants, tool) }
    public func canRead(_ tool: String) -> Bool { level(tool) >= LEVEL_READ }
    public func canWrite(_ tool: String) -> Bool { level(tool) >= LEVEL_WRITE }

    public var chat: ChatClient {
        lock.lock(); defer { lock.unlock() }
        if let c = chatClient { return c }
        let c = ChatClient(computer: self); chatClient = c; return c
    }

    public var fleet: FleetClient {
        lock.lock(); defer { lock.unlock() }
        if let c = fleetClient { return c }
        let c = FleetClient(computer: self); fleetClient = c; return c
    }

    public var plugins: PluginsClient {
        lock.lock(); defer { lock.unlock() }
        if let c = pluginsClient { return c }
        let c = PluginsClient(computer: self); pluginsClient = c; return c
    }

    /// whenOnline returns when the computer's hello has come (at once, if it has).
    public func whenOnline() async throws { try await ready.value() }

    func helloArrived() {
        lock.locked { hasHello = true }
        chat.reconnected()
        fleet.reconnected()
        plugins.reconnected()
        ready.complete(())
        owner.computerEvents.emit(.online(self))
    }

    var callTimeoutMs: Int64 { Int64(owner.config.callTimeout * 1000) }

    /// rpc is a JSON-RPC call over the tool's `rpc` method (chat spec §2): the result object, or the tool's error.
    func rpc(_ tool: Int, _ method: String, _ params: JSONValue? = nil, stream: Int64 = 0, timeoutMs: Int64? = nil) async throws -> JSONValue {
        var req: [String: JSONValue] = ["jsonrpc": "2.0", "method": .string(method)]
        if let p = params { req["params"] = p }
        let r = try await node.callOn(id, stream: stream, tool, 1, [cborFromJSON(.object(req))], timeoutMs: timeoutMs ?? callTimeoutMs).value()
        guard let first = r.first else { throw P2pactCallError.failed("empty response") }
        let msg = jsonFromCbor(first)
        guard msg.objectValue != nil else { throw P2pactCallError.failed("empty response") }
        if let err = msg.obj("error") {
            throw RpcError(code: err.int("code") ?? RpcError.failed, message: err.str("message") ?? "", data: err["data"])
        }
        return msg.obj("result") ?? .object([:])
    }

    /// notify sends a JSON-RPC notification as the tool's `notify` event.
    func notify(_ tool: Int, _ method: String, _ params: JSONValue, stream: Int64) throws {
        let msg: JSONValue = ["jsonrpc": "2.0", "method": .string(method), "params": params]
        try node.eventOn(id, stream: stream, tool, 1, [cborFromJSON(msg)])
    }

    /// toolNumber is the number the computer gave a tool of its own (a plugin's) in its hello; nil until it is known.
    public func toolNumber(_ name: String) -> Int? { node.toolNumber(id, name) }

    /// callTool calls a method of a tool by name; the number is the computer's own (hosted tools,
    /// core spec §8.2). It waits for the computer's hello if it has not come. Arguments are JSON trees;
    /// the result values are the same, byte strings as base64 text (see `callToolRaw` for the CBOR).
    public func callTool(_ name: String, method: Int, args: [JSONValue] = [], timeout: TimeInterval? = nil) async throws -> [JSONValue] {
        try await callToolRaw(name, method: method, args: args.map(cborFromJSON), timeout: timeout).map(jsonFromCbor)
    }

    /// callToolRaw is callTool with CBOR values both ways.
    public func callToolRaw(_ name: String, method: Int, args: [Cbor.Value] = [], timeout: TimeInterval? = nil) async throws -> [Cbor.Value] {
        let ms = timeout.map { Int64($0 * 1000) } ?? callTimeoutMs
        let h = lock.locked { hasHello }
        if toolNumber(name) == nil && !h {
            // the hello may still be on its way after pairing
            let limit = ms > 0 ? Double(ms) / 1000 : 10
            let gate = Future<Void>()
            ready.whenComplete { _ in gate.complete(()) }
            DispatchQueue.global().asyncAfter(deadline: .now() + limit) { gate.complete(()) }
            try await gate.value()
        }
        guard toolNumber(name) != nil else { throw P2pactCallError.noMethod("the computer has no tool \(name)") }
        return try await node.callToolOn(id, name, method, args, timeoutMs: ms).value()
    }
}
