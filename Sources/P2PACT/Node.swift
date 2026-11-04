import Foundation

private let TS_SKEW = 120 * SEC // an older handshake start is a replay: drop it
private let INIT_EVERY = SEC // handshake retry while unanswered
private let AUTO_CONNECT = 30 * SEC // how often to try known devices without a session
private let ALIVE_FOR = 60 * SEC // a road is alive if something arrived on it within this time
private let SESSION_IDLE = 180 * SEC

/// keepaliveGap: how long a live road may stay quiet before a keepalive goes on it; tests shorten it.
var keepaliveGap = 25 * SEC

/// probeEvery: how often the direct roads are tried while a session runs over a relay or an application road.
var probeEvery = 30 * SEC

/// observeEvery: how often we ask our relay which address our UDP packets come from (NAT hole punching).
var observeEvery = 25 * SEC

/// reflexiveStale: a reflexive address the relay has not confirmed for this long leaves our hints (3 missed answers
/// and some); tests shorten it.
var reflexiveStale = 80 * SEC

/// A punch burst sends a keepalive to every UDP address of the device every punchEvery, for punchFor.
var punchEvery = 200 * MS
var punchFor = 3 * SEC

/// Held messages (spec §5): ask again after holdAsk, drop after holdDrop; tests shorten them.
var holdAsk = 15 * SEC
var holdDrop = 120 * SEC

/// Error codes (spec §6).
public enum Errors {
    public static let noMethod = 1
    public static let badArgs = 2
    public static let notFound = 3
    public static let forbidden = 4
    public static let failed = 5
    public static let notDelivered = 6
}

/// P2pactError is a call error (spec §6): a code and a text.
public struct P2pactError: Error, CustomStringConvertible {
    public let code: Int
    public let text: String
    public init(_ code: Int, _ text: String) { self.code = code; self.text = text }
    public var description: String { text }
}

/// Reply is what a handler returns: the result values, or a reply given later (spec §6): the
/// handler's turn on its stream ends at once, so the stream's next calls and events run, and the
/// result or error goes when the future completes.
public enum Reply {
    case values([Cbor.Value])
    case later(Future<[Cbor.Value]>)
}

/// Handler is a tool method: decoded CBOR arguments → a reply (or a thrown P2pactError).
public typealias Handler = (_ peer: String, _ args: [Cbor.Value]) throws -> Reply
/// LevelHandler is a tool method that checks the caller's level itself: the node only requires read.
public typealias LevelHandler = (_ peer: String, _ level: Int, _ args: [Cbor.Value]) throws -> Reply
/// ToolHandler is one handler for every method of a tool: it gets the method and the caller's level.
public typealias ToolHandler = (_ peer: String, _ level: Int, _ method: Int, _ args: [Cbor.Value]) throws -> Reply

/// DictState tells what compresses messages to a device (see Node.dictState).
public struct DictState {
    public let own: Bytes?
    public let using: Bytes?
    public let training: Bool
}

private final class Session {
    let peer: String
    let local: Int64
    let remote: Int64
    let send: CipherState
    let recv: CipherState
    var lastRecv: Int64
    var sendN: Int64 = 0
    var win = Window()
    init(peer: String, local: Int64, remote: Int64, send: CipherState, recv: CipherState, lastRecv: Int64) {
        self.peer = peer; self.local = local; self.remote = remote; self.send = send; self.recv = recv; self.lastRecv = lastRecv
    }
}

private final class PendingHs {
    let pair: Bool
    let hs: Handshake
    let at: Int64
    let peer: String // known device: to whom
    let invite: Invite? // pairing: their invite (we join) or ours (they join)
    let done: Future<Peer>?
    let remoteIdx: Int64 // pairing, we respond: the joiner's index
    let wants: [Grant]? // pairing, we join: what we ask to use on the inviting device (spec §2)
    // data that overtook the handshake reply (reordering): run once the session is up
    var early: [(Bytes, Endpoint)] = []
    init(pair: Bool, hs: Handshake, at: Int64, peer: String = "", invite: Invite? = nil, done: Future<Peer>? = nil, remoteIdx: Int64 = 0, wants: [Grant]? = nil) {
        self.pair = pair; self.hs = hs; self.at = at; self.peer = peer; self.invite = invite; self.done = done
        self.remoteIdx = remoteIdx; self.wants = wants
    }
}

private final class EpState {
    let ep: Endpoint
    var lastRecv: Int64 = 0
    var lastSend: Int64 = 0
    var session: Int64 = 0 // our index of the session its last packet belonged to
    init(_ ep: Endpoint) { self.ep = ep }
}

private struct Inbound { let msg: Bytes; let zip: Bool; let stream: Int64 }

private final class Inbox {
    var q = Deque<() -> Void>()
    var running = false
}

private final class PeerState {
    let addr: String
    let st = Delivery()
    var eps: [String: EpState] = [:]
    var lastTS: Int64 = 0 // timestamp of the last accepted handshake start
    var boot: Int64 = 0 // the other device's boot id (from the handshake)
    var heard = false // it knows our boot id: sent us session data or answered our handshake
    var lastInit: Int64 = 0
    var lastProbe: Int64 = 0
    var burstUntil: Int64 = 0 // a punch burst runs until then (0 — none)
    var burstNext: Int64 = 0
    var calls: [Int64: Future<[Cbor.Value]>] = [:]
    var callID: Int64 = 0
    var dicts: [Bytes] = [] // its dictionaries (ids), by slot — from its hello and 0.5
    var lacks: [Bytes] = [] // it asked us for these, so it lacks them until it announces again
    var waiting: [Inbound] = [] // waiting for a dictionary (spec §5): run in order once it arrives
    var waitSince: Int64 = 0
    var askingInfo = false
    var askedInfo: Int64 = 0
    var fetching = false
    var named: [String: ToolRef] = [:] // its named tools, from its hello (spec §8)
    var tried: [Bytes] = [] // dictionaries of its list we asked it for and did not get
    var sysCalls = Set<Int64>() // our calls of tool 0: their results are not conversation
    var inbox: [Int64: Inbox] = [:] // calls and events waiting for their turn, per stream
    init(_ addr: String) { self.addr = addr }

    /// initGap: retry a handshake after three measured round trips (250 ms – 2 s), else 1 s.
    func initGap() -> Int64 { st.srtt == 0 ? INIT_EVERY : min(max(3 * st.srtt, 250 * MS), 2 * SEC) }
}

private struct MKey: Hashable { let tool: Int; let method: Int }

/// goos is the operating system as p2pact-go names it (android and ios are phones).
func goos() -> String {
    #if os(macOS)
    return "darwin"
    #elseif os(iOS)
    return "ios"
    #elseif os(Linux)
    return "linux"
    #else
    return "unknown"
    #endif
}

private let nodeKey = DispatchSpecificKey<Void>()

/// Node is a device in a P2PACT network (spec §1–§8): pairing, sessions over any road, delivery,
/// messages and compression. All protocol state lives on one serial queue (the node's loop); roads
/// receive on their own threads and hand packets to it. Calls and events run on a concurrent worker
/// queue: those of one device on one stream one at a time, in the order sent, other streams in
/// parallel (spec §6); service calls (tool 0) at once.
public final class Node {
    private let dir: String
    public let name: String
    public let id: Identity
    let trust: Trust

    /// onEvent receives tool events (except tool 0) from known devices.
    public var onEvent: ((_ peer: String, _ tool: Int, _ event: Int, _ args: [Cbor.Value]) -> Void)?
    /// onPaired is called after pairing (on either side).
    public var onPaired: ((Peer) -> Void)?
    /// onWants is called on the inviting device when a newcomer has paired (spec §2), with what it asks to use: the
    /// application returns what the newcomer is granted, or nil to refuse. It runs on a worker and may wait for the person.
    public var onWants: ((_ p: Peer, _ wants: [Grant]) -> [Grant]?)?
    /// onGranted is called when a known device tells what we may use of its tools (event 0.6).
    public var onGranted: ((_ peer: String, _ grants: [Grant]) -> Void)?
    /// onHello is called when a known device sends its hello.
    public var onHello: ((String) -> Void)?
    /// onHeld is called when messages from a device waited too long for a dictionary or its list, or were compressed
    /// with a dictionary the sender has dropped since, and were dropped.
    public var onHeld: ((_ peer: String, _ held: Int) -> Void)?
    /// allowDict decides whether a known device may fetch a dictionary (0.5); nil — all may.
    public var allowDict: ((_ peer: String, _ id: Bytes) -> Bool)?
    /// noCompression turns compression off for what we send.
    public var noCompression = false
    /// noLearning: do not train our own dictionaries (spec §5).
    public var noLearning = false
    /// kind is what this device is for (Kind), told in pairing and the hello (spec §1).
    public var kind = Kind.unknown

    private let loop = DispatchQueue(label: "p2pact-node")
    private let workers = DispatchQueue(label: "p2pact-handler", attributes: .concurrent)
    private let callbacks = DispatchQueue(label: "p2pact-callback")
    private let io = DispatchQueue(label: "p2pact-io")
    private let trainer = DispatchQueue(label: "p2pact-train", qos: .utility)
    private var timers: [DispatchSourceTimer] = []

    private let boot: Int64 = { let v = u32(randomBytes(4), 0); return v == 0 ? 1 : v }()
    private var udp: UdpRoad?
    private var tcp: TcpRoad?
    private var ownRelay: RelayHint?
    private var ownWS: [String] = [] // WebSocket URLs of our relay, for the hints (setRelayWS)
    private var relays: [String: RelayRoad] = [:] // by server address
    private var apps: [AttachedRoad] = [] // roads the application provides
    private var advertise: Hints?
    private var hintsSent: Bytes? // our addresses as last announced (reannounce)
    private var hintsAt: Int64 = 0
    private var reflexive: String? // our address as the relay sees it (observe), part of our UDP hints
    private var observeAt: Int64 = 0 // when the last observe went out (0 — none yet)
    private var observeForce = false // a forced request waits for its second (observeNow)
    private var observeGot: Int64 = 0 // the relay last answered
    private var observeNonces: [Bytes] = [] // outstanding requests to the relay, newest last

    private var sessions: [Int64: Session] = [:] // by our index
    private var current: [String: Session] = [:] // the best session with a device
    private var hs: [Int64: PendingHs] = [:]
    private var invites: [String: Invite] = [:] // our invites by id (hex)
    private var inviteGrants: [String: [Grant]] = [:]
    private var loc: StreamRoad? // the local socket road
    private var localPathValue: String? // the socket we listen on, or dial
    private var peers: [String: PeerState] = [:]
    private var handlers: [MKey: Handler] = [:]
    private var levelHandlers: [MKey: LevelHandler] = [:]
    private var readMethods = Set<MKey>()
    private var toolHandlers: [Int: ToolHandler] = [:]
    private var names: [String: Int] = [:]
    private var numbers: [Int: String] = [:]
    private var versions: [Int: Int] = [:]
    private var resetAt: [String: Int64] = [:]
    private let dicts: DictStore
    private var learnerStore: Learner?
    private let timing: LearnTiming
    private var woken = false
    private var paused = false
    private var closed = false
    private var lastTs: Int64 = 0
    private var handshakeCount = 0

    public init(dir: String, name: String, timing: LearnTiming = LearnTiming()) throws {
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        self.dir = dir
        self.name = name
        self.timing = timing
        id = try Identity.load(dir: dir)
        trust = Trust(dir: dir)
        dicts = DictStore(dir: dir, io: io)
        dicts.listedBy = { [unowned self] d in // on the node's queue, as every change of the store
            guard let ps = self.peers[d.peer] else { return false }
            return hasId(ps.dicts, d.id)
        }
        loop.setSpecific(key: nodeKey, value: ())
        try? dicts.add(Dict(CommonDict.raw)) // the common dictionary, newest unless a later one was added
        handle(0, 1) { _, _ in .values([]) } // ping
        handle(0, 2) { [unowned self] peer, _ in .values(self.onLoop { self.info(peer) }) }
        handle(0, 5) { [unowned self] peer, args in .values(try self.dictHandler(peer, args)) }
        handle(0, 6) { [unowned self] peer, _ in .values([grantsWire(self.grants(peer) ?? [])]) }
    }

    private var learner: Learner {
        if let l = learnerStore { return l }
        let l = Learner(dir: dir, dicts: dicts, timing: timing, io: io, trainer: trainer, post: { [unowned self] f in self.post(f) },
                        addDict: { [unowned self] d in self.addDictLocal(d) })
        learnerStore = l
        return l
    }

    // --- the loop ---

    private func post(_ f: @escaping () -> Void) {
        loop.async { [weak self] in
            guard let self = self, !self.closed else { return }
            f()
        }
    }

    /// onLoop runs f on the node's queue and waits for it.
    private func onLoop<T>(_ f: () -> T) -> T {
        if DispatchQueue.getSpecific(key: nodeKey) != nil { return f() }
        return loop.sync(execute: f)
    }

    private func onLoopThrowing<T>(_ f: () throws -> T) throws -> T {
        if DispatchQueue.getSpecific(key: nodeKey) != nil { return try f() }
        return try loop.sync(execute: f)
    }

    private func receiveFromRoad(_ pkt: Bytes, _ from: Endpoint) { post { [unowned self] in self.receive(pkt, from) } }

    /// listenUdp opens the main road on an address ("0.0.0.0:48730", "127.0.0.1:0").
    public func listenUdp(_ addr: String) throws {
        let u = try UdpRoad(bind: addr) { [weak self] p, e in self?.receiveFromRoad(p, e) }
        onLoop {
            udp = u
            observeNow(Clock.nanos(), force: true) // a new socket has its own mapping
        }
    }

    /// listenTcp opens the fallback road; "" — dial only.
    public func listenTcp(_ addr: String) throws {
        let t = try TcpRoad(bind: addr) { [weak self] p, e in self?.receiveFromRoad(p, e) }
        onLoop { tcp = t }
    }

    public var udpAddr: String { onLoop { udp?.localAddr ?? "" } }
    public var tcpAddr: String { onLoop { tcp?.localAddr ?? "" } }

    /// listenLocal opens the local socket at path (spec §3): a Unix domain socket for our OS user only.
    public func listenLocal(_ path: String) throws {
        if path.isEmpty { throw P2pactError(Errors.badArgs, "no socket path") }
        try onLoopThrowing {
            if loc != nil { throw P2pactError(Errors.failed, "the local socket is already in use") }
            loc = try LocalRoad.listen(path) { [weak self] p, e in self?.receiveFromRoad(p, e) }
            localPathValue = path
        }
    }

    /// useLocal makes the node reach a device on this computer over its local socket at path.
    public func useLocal(_ path: String) throws {
        if path.isEmpty { throw P2pactError(Errors.badArgs, "no socket path") }
        try onLoopThrowing {
            if loc != nil { throw P2pactError(Errors.failed, "the local socket is already in use") }
            loc = LocalRoad.dialer { [weak self] p, e in self?.receiveFromRoad(p, e) }
            localPathValue = path
        }
    }

    public func localPath() -> String? { onLoop { localPathValue } }

    private func isLocal(_ from: Endpoint) -> Bool { loc != nil && from.road === loc }

    /// pluginInvite makes the invite for a program the device starts (spec §2): single use, no hints, and the
    /// program is granted exactly grants — the install gave them, nobody is asked.
    public func pluginInvite(ttlMs: Int64, grants: [Grant]) -> Invite {
        onLoop {
            let inv = Invite(key: id.key.publicKey, name: name, secret: randomBytes(32), exp: wallMillis() + ttlMs, hints: Hints())
            invites[inv.id.hex()] = inv
            inviteGrants[inv.id.hex()] = cleanGrants(grants)
            return inv
        }
    }

    /// pluginEnv is pluginInvite and the environment to start the program with, "NAME=value".
    public func pluginEnv(ttlMs: Int64, grants: [Grant]) throws -> [String] {
        guard let path = localPath() else { throw P2pactError(Errors.failed, "the node does not listen on a local socket") }
        return ["\(ENV_SOCKET)=\(path)", "\(ENV_INVITE)=\(pluginInvite(ttlMs: ttlMs, grants: grants).string)"]
    }

    /// setRelay sets our relay: used for pairing and pair channels.
    public func setRelay(_ h: RelayHint?) {
        onLoop {
            if ownRelay?.addr != h?.addr { // another relay sees another address
                reflexive = nil
                observeNonces = []
            }
            ownRelay = h
            observeNow(Clock.nanos(), force: true)
        }
    }

    /// setRelayWS tells the WebSocket URLs of our relay (the one given to setRelay, as browsers dial it): they go into
    /// our invites and hellos. This library does not dial them.
    public func setRelayWS(_ urls: [String]) { onLoop { ownWS = urls } }

    /// setAdvertise announces these hints instead of our own addresses; nil — our own again.
    public func setAdvertise(_ h: Hints?) { onLoop { advertise = h } }

    /// start runs the service loop: delivery, retransmission, keepalives, connecting to known devices.
    public func start() {
        func timer(_ ms: Int64, _ f: @escaping () -> Void) {
            let t = DispatchSource.makeTimerSource(queue: loop)
            t.schedule(deadline: .now() + .milliseconds(Int(ms)), repeating: .milliseconds(Int(ms)))
            t.setEventHandler { [weak self] in
                guard let self = self, !self.closed else { return }
                f()
            }
            t.resume()
            timers.append(t)
        }
        timer(20) { [unowned self] in self.pump(Clock.nanos()) }
        timer(1000) { [unowned self] in self.maintain(Clock.nanos()) }
        timer(timing.tickMs) { [unowned self] in self.learner.tick() }
    }

    public func close() {
        if onLoop({ closed }) { return }
        onLoop {
            closed = true
            learnerStore?.closed = true
            for t in timers { t.cancel() }
            timers = []
            udp?.close()
            tcp?.close()
            for r in relays.values { r.close() }
            for a in apps { a.detach() }
            loc?.close()
            for ps in peers.values { for c in ps.calls.values { c.fail(P2pactError(Errors.failed, "node closed")) } }
            for h in hs.values { h.done?.fail(P2pactError(Errors.failed, "node closed")) }
        }
        io.sync {}
        trust.flush()
    }

    /// setPaused pauses the node (true) or resumes it: nothing is sent and nothing is taken in meanwhile.
    public func setPaused(_ on: Bool) {
        onLoop { if !closed { pause(on) } }
    }

    private func pause(_ on: Bool) {
        if paused == on { return }
        paused = on
        tcp?.pause(on)
        if on {
            for r in relays.values { r.close() }
            for a in apps { a.drop() }
            for ps in peers.values { ps.burstUntil = 0 } // no bursts while paused
            observeNonces = []
            return
        }
        let now = Clock.nanos()
        observeNow(now, force: true) // the mapping may have changed in the sleep
        if let h = ownRelay { for k in invites.keys { relay(h).join(k, "a") } }
        for p in trust.list() {
            joinPair(p)
            peerState(p.addr)?.lastInit = 0
        }
        for (peer, ps) in peers { if let s = current[peer] { sendData(now, peer, ps, s, keepalive(), true) } }
        pump(now)
        maintain(now)
    }

    /// handle registers method tool.method. Calls of one device on one stream run one at a time, in the order
    /// sent, together with its events there (spec §6); other streams do not wait.
    public func handle(_ tool: Int, _ method: Int, _ h: @escaping Handler) { onLoop { handlers[MKey(tool: tool, method: method)] = h } }

    // --- grants (spec §8.1) ---

    public func handleLevel(_ tool: Int, _ method: Int, _ h: @escaping LevelHandler) { onLoop { levelHandlers[MKey(tool: tool, method: method)] = h } }

    /// markRead declares methods of a tool as read: a device with read on the tool may call them.
    public func markRead(_ tool: Int, _ methods: Int...) { onLoop { for m in methods { readMethods.insert(MKey(tool: tool, method: m)) } } }

    private func requiredLevel(_ tool: Int, _ method: Int) -> Int {
        let k = MKey(tool: tool, method: method)
        if levelHandlers[k] != nil || readMethods.contains(k) || (toolHandlers[tool] != nil && handlers[k] == nil) { return LEVEL_READ }
        return LEVEL_WRITE
    }

    /// grants is what we let a device use of ours (nil — an unknown device).
    public func grants(_ peer: String) -> [Grant]? { trust.get(peer)?.allowed() }

    /// grantedBy is what a device lets us use of its tools, as it told us (event 0.6).
    public func grantedBy(_ peer: String) -> [Grant]? { trust.get(peer)?.offered() }

    public func level(_ peer: String, _ tool: String) -> Int { trust.get(peer).map { grantLevel($0.grants, tool) } ?? 0 }

    /// setGrants replaces what a trusted device may use, keeps it with the trust and tells the device with event 0.6.
    public func setGrants(_ peer: String, _ grants: [Grant]) throws {
        let clean = cleanGrants(grants)
        if !trust.setGrants(peer, clean) { throw P2pactError(Errors.notFound, "unknown device") }
        try event(peer, 0, 6, [grantsWire(clean)])
    }

    /// grant changes one entry; level 0 removes the entry.
    public func grant(_ peer: String, _ tool: String, _ level: Int) throws {
        guard let p = trust.get(peer) else { throw P2pactError(Errors.notFound, "unknown device") }
        try setGrants(peer, p.allowed().filter { $0.tool != tool } + (level > 0 ? [Grant(tool, level)] : []))
    }

    // --- named tools (spec §8) ---

    /// registerTool gives a tool of ours a name and picks its number: the first one from 64 up that no other
    /// tool of ours uses. The number is announced in the hello's named map.
    @discardableResult
    public func registerTool(_ name: String, _ version: Int = 1) throws -> Int {
        if !validToolName(name) { throw P2pactError(Errors.badArgs, "bad tool name: \(name)") }
        return onLoop {
            if let known = names[name] {
                if versions[known] != version {
                    versions[known] = version
                    reannounceTools()
                }
                return known
            }
            var num = FIRST_NAMED_TOOL
            while numbers[num] != nil || handlers.keys.contains(where: { $0.tool == num }) { num += 1 }
            names[name] = num
            numbers[num] = name
            versions[num] = version
            reannounceTools()
            return num
        }
    }

    private func reannounceTools() { for peer in Array(current.keys) { sendInfo(peer) } }

    /// handleTool registers method of the named tool (registered at version 1 if it is not yet).
    public func handleTool(_ name: String, _ method: Int, _ h: @escaping Handler) throws {
        let num = try FIXED_TOOLS[name] ?? registerTool(name, 1)
        handle(num, method, h)
    }

    /// handleToolAll serves every method of the named tool with h.
    public func handleToolAll(_ name: String, _ h: @escaping ToolHandler) throws {
        let num = try registerTool(name, 1)
        onLoop { toolHandlers[num] = h }
    }

    /// peerTools lists the named tools a device announced in its hello, sorted by name.
    public func peerTools(_ peer: String) -> [String] { onLoop { (peers[peer]?.named.keys.sorted()) ?? [] } }

    private func toolNameOf(_ tool: Int) -> String? { FIXED_TOOLS.first { $0.value == tool }?.key ?? numbers[tool] }

    /// toolNumber resolves a tool name to the number the device announced for it in its hello (spec §8).
    public func toolNumber(_ peer: String, _ name: String) -> Int? {
        if let n = FIXED_TOOLS[name] { return n }
        return onLoop { peers[peer]?.named[name]?.number }
    }

    /// peerToolName is the name of a tool of a device by the number it announced (nil — unnamed).
    public func peerToolName(_ peer: String, _ tool: Int) -> String? {
        if let e = FIXED_TOOLS.first(where: { $0.value == tool }) { return e.key }
        return onLoop { peers[peer]?.named.first { $0.value.number == tool }?.key }
    }

    /// callTool is call by tool name: the number is the device's own.
    public func callToolOn(_ peer: String, stream: Int64 = 0, _ name: String, _ method: Int, _ args: [Cbor.Value] = [], timeoutMs: Int64 = 0) -> Future<[Cbor.Value]> {
        guard let num = toolNumber(peer, name) else {
            let f = Future<[Cbor.Value]>()
            f.fail(P2pactError(Errors.noMethod, "the device has no tool \(name)"))
            return f
        }
        return callOn(peer, stream: stream, num, method, args, timeoutMs: timeoutMs)
    }

    private func namedTools() -> Cbor.Value {
        .map(names.sorted { $0.key < $1.key }.map { Cbor.MapEntry(.text($0.key), .array([.int(Int64($0.value)), .int(Int64(versions[$0.value] ?? 1))])) })
    }

    // --- pairing ---

    /// invite creates an invite valid for ttlMs; pairing is accepted on all our roads.
    public func invite(ttlMs: Int64) -> Invite {
        onLoop {
            let inv = Invite(key: id.key.publicKey, name: name, secret: randomBytes(32), exp: wallMillis() + ttlMs, hints: hints())
            invites[inv.id.hex()] = inv
            if !paused, let r = ownRelay { relay(r).join(inv.id.hex(), "a") }
            return inv
        }
    }

    private final class Box<T> { var v: T; init(_ v: T) { self.v = v } }

    /// joinAsync pairs using an invite, trying all its hints until one answers.
    public func joinAsync(_ inv: Invite, timeoutMs: Int64 = 30_000, wants: [Grant]? = nil) -> Future<Peer> {
        let done = Future<Peer>()
        post { [unowned self] in
            var eps: [Endpoint] = []
            if let u = self.udp { for a in inv.hints.udp { eps.append(Endpoint(road: u, addr: a)) } }
            if let t = self.tcp { for a in inv.hints.tcp { eps.append(Endpoint(road: t, addr: a)) } }
            var rr: RelayRoad?
            if let h = inv.hints.relay {
                rr = self.relay(h)
                eps.append(Endpoint(road: rr!, addr: inv.id.hex()))
            }
            // a device on this computer, over its socket
            if let lr = self.loc, let lp = self.localPathValue { eps.append(Endpoint(road: lr, addr: lp)) }
            // a link the application opened to a device it has not named
            let owner = Crypto.address(inv.key)
            for a in self.apps where a.peer == nil || a.peer == owner { eps.append(a.endpoint) }
            if eps.isEmpty {
                done.fail(P2pactError(Errors.failed, "the invite has no road we can use"))
                return
            }
            let deadline = Clock.nanos() + timeoutMs * MS
            let local = Box<Int64>(0)
            func attempt() {
                self.hs.removeValue(forKey: local.v)
                if done.isDone { return }
                if Clock.nanos() > deadline {
                    done.fail(P2pactError(Errors.failed, "pairing timed out"))
                    return
                }
                guard let h = try? Handshake(.xxpsk2, initiator: true, prologue: Bytes(PROLOGUE.utf8), s: self.id.key, psk: inv.secret),
                      let msg1 = try? h.writeMessage() else { return }
                local.v = self.newIndex()
                self.hs[local.v] = PendingHs(pair: true, hs: h, at: Clock.nanos(), invite: inv, done: done, wants: wants)
                let pkt = cat([UInt8(P_PAIR1)], inv.id, be32(local.v), msg1)
                if !self.paused { // paused: try again on the next round
                    rr?.join(inv.id.hex(), "b") // again after a pause closed it
                    for e in eps { _ = e.road.send(e.addr, pkt) }
                }
                self.loop.asyncAfter(deadline: .now() + .milliseconds(Int(INIT_EVERY / MS))) { [weak self] in self?.post { attempt() } }
            }
            done.whenComplete { _ in self.post { self.hs.removeValue(forKey: local.v); rr?.leave(inv.id.hex()) } }
            attempt()
        }
        return done
    }

    /// join pairs using an invite and waits for it.
    @discardableResult
    public func join(_ inv: Invite, timeoutMs: Int64 = 30_000, wants: [Grant]? = nil) throws -> Peer {
        try joinAsync(inv, timeoutMs: timeoutMs, wants: wants).get()
    }

    /// PairInfo is the pairing handshake payload [name, boot, hints, signing key, os, kind, wants].
    struct PairInfo {
        let name: String
        let boot: Int64
        let hints: Hints
        let signKey: Bytes?
        let os: String?
        let kind: Int
        let wants: [Grant]? // what the newcomer asks to use (spec §2); nil — it did not say, which is everything
    }

    func parsePair(_ payload: Bytes) -> PairInfo {
        let a = (try? Cbor.decode(payload))?.asList ?? []
        return PairInfo(name: a.at(0).asString ?? "", boot: a.at(1).asInt64 ?? 0, hints: Hints.fromWire(a.at(2)), signKey: a.at(3).asBytes,
                        os: a.at(4).asString, kind: a.at(5).asInt ?? Kind.unknown, wants: a.count > 6 ? parseGrants(a[6]) : nil)
    }

    /// pairPayload is our payload; wants are what we ask to use (nil — not asking, the field is left out).
    func pairPayload(_ wants: [Grant]? = nil) -> Bytes {
        var a: [Cbor.Value] = [.text(name), .int(boot), hints().toWire(), .bytes(id.sign.publicKey), .text(goos())]
        if kind != Kind.unknown || wants != nil { a.append(.int(Int64(kind))) }
        if let w = wants { a.append(grantsWire(cleanGrants(w))) }
        return Cbor.encode(.array(a))
    }

    /// forget drops a known device: we stop answering it. Our conversation's dictionaries and history go too.
    public func forget(_ addr: String) {
        onLoop {
            dicts.forget(addr)
            learner.forget(addr)
            if let ps = peers.removeValue(forKey: addr) { for c in ps.calls.values { c.fail(P2pactError(Errors.failed, "device forgotten")) } }
            if let s = current.removeValue(forKey: addr) { sessions.removeValue(forKey: s.local) }
            _ = trust.remove(addr)
        }
    }

    public func peer(_ addr: String) -> Peer? { trust.get(addr) }

    // --- calls and events ---

    /// callOn invokes tool.method on a known device on a stream (0 — the ordered default) and completes with the
    /// result elements. timeoutMs 0 — no timeout.
    public func callOn(_ peer: String, stream: Int64 = 0, _ tool: Int, _ method: Int, _ args: [Cbor.Value] = [], timeoutMs: Int64 = 0) -> Future<[Cbor.Value]> {
        let f = Future<[Cbor.Value]>()
        post { [unowned self] in
            guard let ps = self.peerState(peer) else {
                f.fail(P2pactError(Errors.notFound, "unknown device"))
                return
            }
            ps.callID += 1
            let cid = ps.callID
            ps.calls[cid] = f
            if tool == 0 { ps.sysCalls.insert(cid) }
            f.whenComplete { _ in self.post { ps.calls.removeValue(forKey: cid); ps.sysCalls.remove(cid) } }
            if timeoutMs > 0 {
                self.loop.asyncAfter(deadline: .now() + .milliseconds(Int(timeoutMs))) { f.fail(P2pactError(Errors.failed, "call timed out")) }
            }
            self.push(ps, Cbor.encode(.array([0, .int(cid), .int(Int64(tool)), .int(Int64(method))] + args)), stream, tool != 0)
        }
        if onLoop({ closed }) { f.fail(P2pactError(Errors.failed, "node closed")) }
        return f
    }

    public func call(_ peer: String, _ tool: Int, _ method: Int, _ args: [Cbor.Value] = [], timeoutMs: Int64 = 0) -> Future<[Cbor.Value]> {
        callOn(peer, stream: 0, tool, method, args, timeoutMs: timeoutMs)
    }

    /// event sends event tool.event to a known device on stream 0 (in order, like calls).
    public func event(_ peer: String, _ tool: Int, _ event: Int, _ args: [Cbor.Value] = []) throws { try eventOn(peer, stream: 0, tool, event, args) }

    public func eventOn(_ peer: String, stream: Int64, _ tool: Int, _ event: Int, _ args: [Cbor.Value] = []) throws {
        let msg = Cbor.encode(.array([3, .int(Int64(tool)), .int(Int64(event))] + args))
        try onLoopThrowing {
            guard let ps = peerState(peer) else { throw P2pactError(Errors.notFound, "unknown device") }
            // a tool's events go only to devices with at least read on it (spec §8.1)
            if tool != 0 && grantLevel(trust.get(peer)?.grants, toolNameOf(tool) ?? "") < LEVEL_READ { return }
            push(ps, msg, stream, tool != 0)
        }
    }

    /// afterEvents completes when everything already received from the device on the stream (its
    /// events and calls) has run through onEvent and the handlers. A call's result completes as it
    /// arrives, ahead of the events queued before it: a client that must have all of them (a chat's
    /// history before the answer to `session/load`) waits for this after the result. Do not wait
    /// for it inside onEvent of the same stream: it would wait for itself.
    public func afterEvents(_ peer: String, stream: Int64 = 0) -> Future<Void> {
        let f = Future<Void>()
        post { [unowned self] in
            if let ps = self.peerState(peer) { self.enqueue(ps, stream) { f.complete(()) } } else { f.complete(()) }
        }
        if onLoop({ closed }) { f.complete(()) }
        return f
    }

    /// knownPeers lists the paired devices.
    public func knownPeers() -> [Peer] { trust.list() }

    /// paths lists live roads to a known device: udp, tcp, relay:<address>.
    public func paths(_ peer: String) -> [String] {
        onLoop {
            guard let ps = peers[peer] else { return [] }
            let now = Clock.nanos()
            var out: [String] = []
            for e in ps.eps.values where now - e.lastRecv <= ALIVE_FOR && !out.contains(e.ep.road.name) { out.append(e.ep.road.name) }
            return out
        }
    }

    /// info is the hello (spec §6, 0.2): [name, os, implementation, {tool: version}, [dictionaries], hints, kind, {name: [tool, version]}].
    private func info(_ peer: String) -> [Cbor.Value] {
        var tools: [Int] = []
        // tools whose handlers check the caller's level are tools too
        for k in handlers.keys where k.tool != 0 && numbers[k.tool] == nil && !tools.contains(k.tool) { tools.append(k.tool) }
        for k in levelHandlers.keys where k.tool != 0 && numbers[k.tool] == nil && !tools.contains(k.tool) { tools.append(k.tool) }
        for t in toolHandlers.keys where t != 0 && numbers[t] == nil && !tools.contains(t) { tools.append(t) }
        tools.sort()
        return [.text(name), .text(goos()), "p2pact-swift", .map(tools.map { Cbor.MapEntry(.int(Int64($0)), .int(1)) }),
                .array(dicts.ids(peer).map { .bytes($0) }), hints().toWire(), .int(Int64(kind)), namedTools()]
    }

    private func hints() -> Hints {
        var h = baseHints()
        // the address the relay saw us from (a NAT's outside address); local addresses stay
        if let r = reflexive, ownRelay != nil, !h.udp.contains(r) { h.udp.append(r) }
        return h
    }

    private func baseHints() -> Hints {
        if var a = advertise {
            if a.relay == nil, let r = ownRelay { a.relay = r }
            if a.ws.isEmpty { a.ws = ownWS }
            return a
        }
        return Hints(udp: udp?.localAddrs() ?? [], tcp: tcp?.localAddrs() ?? [], relay: ownRelay, ws: ownWS)
    }

    // --- NAT hole punching ---

    /// observeNow asks the relay which address our UDP packets come from: every observeEvery, or at once (force:
    /// relay set, socket changed, resumed) — but not more than once a second; a forced request that comes too soon
    /// waits for maintain. A reflexive address the relay has not confirmed for reflexiveStale is dropped (another
    /// network, an old relay). An old relay never answers: harmless.
    private func observeNow(_ now: Int64, force: Bool = false) {
        if force { observeForce = true }
        guard !paused, !closed, let u = udp, let h = ownRelay else { return }
        let gap = now - observeAt
        if observeAt != 0 && (gap < min(SEC, observeEvery) || (!observeForce && gap < observeEvery)) { return }
        if reflexive != nil && now - observeGot > reflexiveStale { setReflexive(now, nil) }
        observeForce = false
        observeAt = now
        let nonce = randomBytes(16)
        observeNonces.append(nonce)
        if observeNonces.count > 4 { observeNonces.removeFirst() }
        _ = u.send(h.addr, encodeObserve(nonce: nonce))
    }

    /// onObserve takes the relay's reply: it must come from the relay's address, over our UDP road, with the nonce
    /// of a request of ours.
    private func onObserve(_ now: Int64, _ pkt: Bytes, _ from: Endpoint) {
        guard let u = udp, from.road === u, let h = ownRelay, let r = decodeObserve(pkt),
              let i = observeNonces.firstIndex(of: r.nonce), u.resolvedText(h.addr) == from.addr else { return }
        observeNonces.remove(at: i) // answered once
        observeGot = now
        setReflexive(now, r.addr)
    }

    /// setReflexive records our address as the relay sees it (nil — forget it): announced at once; a new one starts
    /// bursts to the devices not on a direct road.
    private func setReflexive(_ now: Int64, _ addr: String?) {
        if reflexive == addr { return }
        reflexive = addr // replaces the old one
        hintsAt = 0
        reannounce(now) // the hello carries it
        if addr == nil { return }
        for (peer, ps) in peers where !onDirect(peer, ps, now) { startBurst(now, ps) }
    }

    /// onDirect: the session with the device runs over a live UDP or TCP road.
    private func onDirect(_ peer: String, _ ps: PeerState, _ now: Int64) -> Bool {
        guard current[peer] != nil else { return false }
        let c = candidates(peer, ps, now, false)
        return c.count == 1 && now - c[0].lastRecv <= ALIVE_FOR && roadRank(c[0].ep.road) < 2
    }

    private func startBurst(_ now: Int64, _ ps: PeerState) {
        if paused || closed { return }
        ps.burstUntil = now + punchFor
        ps.burstNext = 0
    }

    /// punchTick sends the keepalives of the bursts that run: a packet from each side to the other's outside address
    /// makes both NATs let the answer in.
    private func punchTick(_ now: Int64) {
        for (peer, ps) in peers where ps.burstUntil != 0 {
            if now >= ps.burstUntil || onDirect(peer, ps, now) { ps.burstUntil = 0; continue }
            if now < ps.burstNext { continue }
            ps.burstNext = now + punchEvery
            guard let s = current[peer], let u = udp, let p = trust.get(peer), p.kind != Kind.plugin else { continue }
            for a in p.hints.udp { sealTo(s, epState(ps, Endpoint(road: u, addr: a)), now, keepalive()) }
        }
    }

    private func epState(_ ps: PeerState, _ ep: Endpoint) -> EpState {
        if let x = ps.eps[ep.key] { return x }
        let e = EpState(ep)
        ps.eps[ep.key] = e
        return e
    }

    /// sessionUp: a session started over a relay or an application road — punch at once.
    private func sessionUp(_ now: Int64, _ ps: PeerState, _ from: Endpoint) {
        if roadRank(from.road) >= 2 { startBurst(now, ps) }
    }

    /// helloHints stores the hints of a hello; changed UDP addresses of a device not on a direct road start a burst.
    private func helloHints(_ now: Int64, _ peer: String, _ ps: PeerState, name: String, os: String, _ h: Hints) {
        let before = trust.get(peer)?.hints.udp
        trust.setHints(peer, name: name, os: os, h)
        if let after = trust.get(peer)?.hints.udp, after != before, !onDirect(peer, ps, now) { startBurst(now, ps) }
    }

    // --- receiving ---

    private func receive(_ pkt: Bytes, _ from: Endpoint) {
        // paused: what came is dropped unanswered, its sender sends it again after we resume
        if pkt.count < 5 || closed || paused { return }
        let now = Clock.nanos()
        switch Int(pkt[0]) {
        case P_DATA: onData(now, pkt, from)
        case P_INIT: onInit(now, pkt, from)
        case P_RESP: onResp(now, pkt, from)
        case P_PAIR1: onPair1(now, pkt, from)
        case P_PAIR2: onPair2(now, pkt, from)
        case P_PAIR3: onPair3(now, pkt, from)
        case P_OBSERVE: onObserve(now, pkt, from)
        case P_RESET:
            let idx = u32(pkt, 1)
            for s in Array(sessions.values) where s.remote == idx {
                sessions.removeValue(forKey: s.local)
                if current[s.peer] === s { current.removeValue(forKey: s.peer) }
            }
        default: break
        }
    }

    private func onData(_ now: Int64, _ pkt: Bytes, _ from: Endpoint) {
        if pkt.count < DATA_HEADER + 16 { return }
        let idx = u32(pkt, 1)
        guard let s = sessions[idx] else {
            // our handshake is still waiting for its reply, and data from the new session
            // overtook it: hold the data instead of resetting the session
            if let h = hs[idx], !h.pair, h.early.count < 16 {
                h.early.append((pkt, from))
                return
            }
            let k = from.key
            if now - (resetAt[k] ?? 0) >= 5 * SEC {
                resetAt[k] = now
                _ = from.road.send(from.addr, cat([UInt8(P_RESET)], be32(idx)))
            }
            return
        }
        let cnt = u32(pkt, 5)
        guard let plain = s.recv.decryptAt(cnt, Bytes(pkt[0..<DATA_HEADER]), pkt, DATA_HEADER) else { return }
        if !s.win.accept(cnt) { return }
        s.lastRecv = now
        if current[s.peer] == nil { current[s.peer] = s }
        guard let ps = peerState(s.peer) else { return }
        ps.heard = true
        // a packet on a better road than the one in use (a probe, spec §7) is answered on it: the
        // other side hears the road too, and both move to it
        let c = candidates(s.peer, ps, now, false)
        let better = c.count == 1 && roadRank(from.road) < roadRank(c[0].ep.road)
        seen(ps, from, now, s.local)
        if better, let e = ps.eps[from.key] { sealTo(s, e, now, keepalive()) }
        let peer = s.peer
        _ = ps.st.receive(now, plain) { m, z, st in self.inbound(peer, m, z, st) }
        if ps.st.ackDue != 0 && now >= ps.st.ackDue { wake() } // an ack is due now
    }

    /// onInit: a known device starts a session (Noise_IK) with data in the first packet (spec §4.2).
    private func onInit(_ now: Int64, _ pkt: Bytes, _ from: Endpoint) {
        guard let h = try? Handshake(.ik, initiator: false, prologue: Bytes(PROLOGUE.utf8), s: id.key),
              let payload = try? h.readMessage(Bytes(pkt[5...])), payload.count >= 12, let rs = h.rs else { return }
        let peer = Crypto.address(rs)
        guard let known = trust.get(peer) else { return } // silence to strangers
        if known.kind == Kind.plugin && !isLocal(from) { return } // a plugin is reachable over the local socket only (spec §2)
        guard let ps = peerState(peer) else { return }
        let ts = u64(payload, 0)
        let age = wallMillis() * MS - ts
        if ts <= ps.lastTS || age > TS_SKEW || age < -TS_SKEW { return } // a replay of an old start
        ps.lastTS = ts
        let local = newIndex()
        guard let resp = try? h.writeMessage(be32(boot)), let (c1, c2) = h.ciphers else { return }
        let s = Session(peer: peer, local: local, remote: u32(pkt, 1), send: c2, recv: c1, lastRecv: now)
        sessions[local] = s
        current[peer] = s
        handshakeCount += 1
        seen(ps, from, now, s.local)
        bootOf(ps, u32(payload, 8))
        sessionUp(now, ps, from)
        _ = from.road.send(from.addr, cat([UInt8(P_RESP)], be32(s.remote), be32(local), resp))
        // data in the first packet; from a device that has not heard our boot id it may be
        // numbered for our previous boot, to be renumbered once it gets our reply: drop it
        // unacknowledged, it comes again in the session (spec §4.2)
        if payload.count > 12 && ps.heard {
            _ = ps.st.receive(now, Bytes(payload[12...])) { m, z, st in self.inbound(peer, m, z, st) }
        }
        sendInfo(peer)
    }

    private func onResp(_ now: Int64, _ pkt: Bytes, _ from: Endpoint) {
        if pkt.count < 9 { return }
        let local = u32(pkt, 1)
        guard let h = hs[local], !h.pair else { return }
        guard let payload = try? h.hs.readMessage(Bytes(pkt[9...])), let (c1, c2) = h.hs.ciphers, payload.count >= 4 else { return }
        hs.removeValue(forKey: local)
        let s = Session(peer: h.peer, local: local, remote: u32(pkt, 5), send: c1, recv: c2, lastRecv: now)
        sessions[local] = s
        current[h.peer] = s
        handshakeCount += 1
        guard let ps = peerState(h.peer) else { return }
        ps.heard = true
        seen(ps, from, now, s.local)
        bootOf(ps, u32(payload, 0))
        sessionUp(now, ps, from)
        sendInfo(h.peer)
        for (p, f) in h.early { onData(now, p, f) }
    }

    /// onPair1: someone joins with our invite (Noise_XXpsk2, we respond).
    private func onPair1(_ now: Int64, _ pkt: Bytes, _ from: Endpoint) {
        if pkt.count < 21 { return }
        guard let inv = invites[Bytes(pkt[1..<17]).hex()] else { return }
        if wallMillis() > inv.exp { return }
        guard let h = try? Handshake(.xxpsk2, initiator: false, prologue: Bytes(PROLOGUE.utf8), s: id.key, psk: inv.secret),
              (try? h.readMessage(Bytes(pkt[21...]))) != nil,
              let msg2 = try? h.writeMessage(pairPayload()) else { return }
        let local = newIndex()
        let remoteIdx = u32(pkt, 17)
        hs[local] = PendingHs(pair: true, hs: h, at: now, invite: inv, remoteIdx: remoteIdx)
        _ = from.road.send(from.addr, cat([UInt8(P_PAIR2)], be32(remoteIdx), be32(local), msg2))
    }

    /// onPair2: we are joining; the invite owner answered.
    private func onPair2(_ now: Int64, _ pkt: Bytes, _ from: Endpoint) {
        if pkt.count < 9 { return }
        let local = u32(pkt, 1)
        guard let h = hs[local], h.pair, let done = h.done else { return }
        guard let payload = try? h.hs.readMessage(Bytes(pkt[9...])) else { return } // wrong secret or a stranger
        let inv = h.invite!
        guard let rs = h.hs.rs, same(rs, inv.key) else {
            hs.removeValue(forKey: local)
            done.fail(P2pactError(Errors.failed, "device key does not match the invite"))
            return
        }
        let pp = parsePair(payload)
        guard let msg3 = try? h.hs.writeMessage(pairPayload(h.wants)), let (c1, c2) = h.hs.ciphers else { return }
        hs.removeValue(forKey: local)
        let peer = Crypto.address(inv.key)
        let wh = pp.hints
        let hints = Hints(udp: wh.udp.isEmpty ? inv.hints.udp : wh.udp, tcp: wh.tcp.isEmpty ? inv.hints.tcp : wh.tcp, relay: wh.relay ?? inv.hints.relay, ws: wh.ws.isEmpty ? inv.hints.ws : wh.ws)
        let p = Peer(addr: peer, key: inv.key, name: pp.name, pairSecret: inv.secret, hints: hints, signKey: pp.signKey, os: pp.os,
                     kind: pp.kind, granted: h.wants != nil ? [] : nil, local: isLocal(from)) // asked: nothing until the first 0.6 (spec §2)
        trust.put(p)
        let s = Session(peer: peer, local: local, remote: u32(pkt, 5), send: c1, recv: c2, lastRecv: now)
        sessions[local] = s
        current[peer] = s
        guard let ps = peerState(peer) else { return }
        seen(ps, from, now, s.local)
        bootOf(ps, pp.boot)
        sessionUp(now, ps, from)
        _ = from.road.send(from.addr, cat([UInt8(P_PAIR3)], be32(s.remote), msg3))
        paired(trust.get(peer) ?? p)
        done.complete(trust.get(peer) ?? p)
    }

    /// onPair3: the joiner confirmed; pairing is complete.
    private func onPair3(_ now: Int64, _ pkt: Bytes, _ from: Endpoint) {
        let local = u32(pkt, 1)
        guard let h = hs[local], h.pair, h.done == nil else { return }
        guard let payload = try? h.hs.readMessage(Bytes(pkt[5...])), let (c1, c2) = h.hs.ciphers else { return }
        let inv = h.invite!
        let pp = parsePair(payload)
        let preset = inviteGrants[inv.id.hex()]
        let forProgram = preset != nil
        // a plugin pairs over the local socket only, with an invite made for programs (spec §2)
        if (pp.kind == Kind.plugin || forProgram) && (pp.kind != Kind.plugin || !isLocal(from)) { return }
        hs.removeValue(forKey: local)
        invites.removeValue(forKey: inv.id.hex()) // single use
        if let r = ownRelay { relay(r).leave(inv.id.hex()) }
        guard let rs = h.hs.rs else { return }
        let key = rs
        let peer = Crypto.address(key)
        var p = Peer(addr: peer, key: key, name: pp.name, pairSecret: inv.secret, hints: pp.hints, signKey: pp.signKey, os: pp.os, via: inv.id.hex(), kind: pp.kind)
        // what the newcomer may use (spec §2): without wants it asks for everything and keeps the
        // default; with them, and no onWants to narrow them, it gets what it asked. With onWants
        // the application decides: until it does the newcomer may use nothing.
        if let w = pp.wants { p.grants = cleanGrants(w) }
        var decide = onWants
        if decide != nil { p.grants = [] }
        if let pre = preset { // the install gave the grants: nobody is asked
            decide = nil
            p.grants = cleanGrants(pre)
        }
        if pp.kind == Kind.plugin { p.hints = Hints() } // reachable over the local socket only
        inviteGrants.removeValue(forKey: inv.id.hex())
        trust.put(p)
        // the joiner was the initiator; we are the responder
        let s = Session(peer: peer, local: local, remote: h.remoteIdx, send: c2, recv: c1, lastRecv: now)
        sessions[local] = s
        current[peer] = s
        guard let ps = peerState(peer) else { return }
        seen(ps, from, now, s.local)
        bootOf(ps, pp.boot)
        sessionUp(now, ps, from)
        if let ask = decide {
            let wants = cleanGrants(pp.wants ?? defaultGrants())
            let newcomer = trust.get(peer) ?? p
            sendInfo(peer)
            execute { [unowned self] in
                let grants = ask(newcomer, wants)
                if let grants = grants {
                    do { try self.setGrants(peer, grants) } catch { return }
                    if let cb = self.onPaired, let now2 = self.trust.get(peer) { self.callbacks.async { cb(now2) } }
                } else { // refused: the newcomer is forgotten
                    self.forget(peer)
                }
            }
            return
        }
        paired(trust.get(peer) ?? p)
    }

    private func paired(_ p: Peer) {
        sendInfo(p.addr)
        if let cb = onPaired { callbacks.async { cb(p) } }
    }

    /// bootOf records the other device's boot id; a change means its receiving restarted.
    private func bootOf(_ ps: PeerState, _ boot: Int64) {
        if ps.boot != 0 && ps.boot != boot { ps.st.reset() }
        ps.boot = boot
    }

    /// sendInfo sends our hello: name, where to find us and our dictionaries (event 0.2).
    private func sendInfo(_ peer: String) {
        guard let ps = peerState(peer) else { return }
        hintsSent = Cbor.encode(hints().toWire()) // what the devices know of us (reannounce)
        push(ps, Cbor.encode(.array([3, 0, 2] + info(peer))), 0, false)
        grantsEvent(peer, ps)
    }

    /// grantsEvent tells the device what it may use, unless we never set it (the default it assumes).
    private func grantsEvent(_ peer: String, _ ps: PeerState) {
        guard let g = trust.get(peer)?.grants else { return }
        push(ps, Cbor.encode(.array([3, 0, 6, grantsWire(g)])), 0, false)
    }

    /// message handles a reassembled message (spec §6).
    private func message(_ peer: String, _ msg: Bytes, _ stream: Int64) {
        guard let a = (try? Cbor.decode(msg))?.asList, a.count >= 2, let ps = peerState(peer) else { return }
        switch a[0].asInt64 {
        case 0: // call
            if a.count < 4 { return }
            guard let cid = a[1].asInt64, let tool = a[2].asInt, let method = a[3].asInt else { return }
            if tool != 0 { hear(peer, msg) }
            var h = handlers[MKey(tool: tool, method: method)]
            var level = 0
            var forbidden = false
            if tool != 0 { // grants (spec §8.1): tool 0 is always allowed
                level = grantLevel(trust.get(peer)?.grants, toolNameOf(tool) ?? "")
                forbidden = level < requiredLevel(tool, method)
            }
            let lh = levelHandlers[MKey(tool: tool, method: method)]
            let th = toolHandlers[tool]
            if let lh = lh, !forbidden {
                let lv = level
                h = { p, args in try lh(p, lv, args) }
            }
            if h == nil, let th = th, !forbidden {
                let lv = level
                h = { p, args in try th(p, lv, method, args) }
            }
            let args = Array(a[4...])
            let boot = ps.boot
            let handler = h
            func reply(_ res: [Cbor.Value]?, _ err: Error?) {
                let out: Cbor.Value
                if let e = err {
                    if let pe = e as? P2pactError {
                        out = [2, .int(cid), .int(Int64(pe.code)), .text(pe.text)]
                    } else {
                        out = [2, .int(cid), .int(Int64(Errors.failed)), .text("\(e)")]
                    }
                } else {
                    out = .array([1, .int(cid)] + (res ?? []))
                }
                let b = Cbor.encode(out)
                post { [unowned self] in
                    // the result goes back on the call's stream, unless the caller restarted meanwhile
                    guard let p = self.peerState(peer), boot == 0 || p.boot == boot else { return }
                    // a hello, like the event: never compressed (spec §5)
                    if tool == 0 && method == 2 {
                        p.st.push(b, zip: false, stream: stream, reply: true)
                        self.wake()
                    } else {
                        self.push(p, b, stream, tool != 0, reply: true)
                    }
                }
            }
            let run: () -> Void = {
                if forbidden {
                    reply(nil, P2pactError(Errors.forbidden, "forbidden"))
                } else if let handler = handler {
                    let res: Reply
                    do { res = try handler(peer, args) } catch {
                        reply(nil, error)
                        return
                    }
                    // a reply given later: the turn ends here, the reply goes when it is ready
                    switch res {
                    case .values(let v): reply(v, nil)
                    case .later(let f):
                        f.whenComplete { r in
                            switch r {
                            case .success(let v): reply(v, nil)
                            case .failure(let e): reply(nil, e)
                            }
                        }
                    }
                } else {
                    reply(nil, P2pactError(Errors.noMethod, "no such method"))
                }
            }
            // service calls (a dictionary, a ping) never wait behind a slow handler
            if tool == 0 { execute(run) } else { enqueue(ps, stream, run) }
        case 1, 2: // result, error
            guard let cid = a[1].asInt64, let f = ps.calls[cid] else { return }
            if !ps.sysCalls.contains(cid) { hear(peer, msg) }
            ps.calls.removeValue(forKey: cid)
            if a[0] == .int(1) {
                f.complete(Array(a[2...]))
            } else {
                f.fail(P2pactError(a.at(2).asInt ?? Errors.failed, a.at(3).asString ?? ""))
            }
        case 3: // event
            if a.count < 3 { return }
            guard let tool = a[1].asInt, let ev = a[2].asInt else { return }
            if tool == 0 && ev == 2 && a.count >= 9 { // hello: name, hints, dictionaries
                helloHints(Clock.nanos(), peer, ps, name: a[3].asString ?? "", os: a[4].asString ?? "", Hints.fromWire(a[8]))
                if a.count >= 10, let k = a[9].asInt { trust.setKind(peer, k) }
                ps.named = a.count >= 11 ? parseNamed(a[10]) : [:]
                ps.dicts = idsOf(a[7])
                ps.lacks = []
                ps.tried = []
                fetchNew(peer, ps)
                drain(peer, ps)
                if let cb = onHello { callbacks.async { cb(peer) } }
                return
            }
            if tool == 0 && ev == 6 && a.count >= 4 { // what we may use of its tools
                if let g = parseGrants(a[3]) {
                    trust.setGranted(peer, g)
                    if let cb = onGranted { callbacks.async { cb(peer, g) } }
                }
                return
            }
            if tool == 0 && ev == 5 && a.count >= 4 { // the dictionary list changed
                ps.dicts = idsOf(a[3])
                ps.lacks = []
                ps.tried = []
                fetchNew(peer, ps)
                drain(peer, ps)
                return
            }
            if tool != 0 { hear(peer, msg) }
            guard let cb = onEvent else { return }
            let args = Array(a[3...])
            enqueue(ps, stream) { cb(peer, tool, ev, args) }
        default: break
        }
    }

    /// parseNamed reads the hello's {name: [tool, version]}; a malformed entry is skipped.
    private func parseNamed(_ v: Cbor.Value) -> [String: ToolRef] {
        guard let m = v.asMap else { return [:] }
        var out: [String: ToolRef] = [:]
        for e in m {
            guard let l = e.value.asList, let name = e.key.asString, let n = l.at(0).asInt, let ver = l.at(1).asInt else { continue }
            out[name] = ToolRef(number: n, version: ver)
        }
        return out
    }

    private func execute(_ f: @escaping () -> Void) {
        if closed { return }
        workers.async(execute: f)
    }

    /// enqueue runs f behind the stream's earlier calls and events. Each stream has its own turn on the
    /// worker queue while it has work: a slow handler holds up its stream only.
    private func enqueue(_ ps: PeerState, _ stream: Int64, _ f: @escaping () -> Void) {
        let ib: Inbox
        if let e = ps.inbox[stream] { ib = e } else { ib = Inbox(); ps.inbox[stream] = ib }
        ib.q.append(f)
        if ib.running { return }
        ib.running = true
        runNext(ps, stream, ib)
    }

    private func runNext(_ ps: PeerState, _ stream: Int64, _ ib: Inbox) {
        if ib.q.isEmpty || closed {
            ib.running = false
            if ps.inbox[stream] === ib { ps.inbox.removeValue(forKey: stream) }
            return
        }
        let f = ib.q.removeFirst()
        execute { [weak self] in
            f() // a failing callback does not stop its stream
            self?.post { self?.runNext(ps, stream, ib) }
        }
    }

    // --- sending ---

    private func peerState(_ peer: String) -> PeerState? {
        if let p = peers[peer] { return p }
        if trust.get(peer) == nil { return nil }
        let p = PeerState(peer)
        peers[peer] = p
        return p
    }

    private func seen(_ ps: PeerState, _ from: Endpoint, _ now: Int64, _ session: Int64) {
        let e: EpState
        if let x = ps.eps[from.key] { e = x } else { e = EpState(from); ps.eps[from.key] = e }
        e.lastRecv = now
        e.session = session
    }

    /// candidates picks where to send: the best live road; with none alive or on retransmission, all hints too.
    private func candidates(_ peer: String, _ ps: PeerState, _ now: Int64, _ all: Bool) -> [EpState] {
        var alive = ps.eps.values.filter { now - $0.lastRecv <= ALIVE_FOR }
        // prefer roads the current session was heard on: earlier sessions may have used roads that are gone now
        if let cur = current[peer], !all {
            let mine = alive.filter { $0.session == cur.local }
            if !mine.isEmpty { alive = mine }
        }
        if !alive.isEmpty && !all {
            // the road heard from last; a better kind only if heard within half a second of it (spec §7)
            var best = alive[0]
            for e in alive where e.lastRecv > best.lastRecv { best = e }
            for e in alive where roadRank(e.ep.road) < roadRank(best.ep.road) && best.lastRecv - e.lastRecv < 500 * MS { best = e }
            return [best]
        }
        var out = alive
        guard let p = trust.get(peer) else { return out }
        func add(_ ep: Endpoint) {
            let e: EpState
            if let x = ps.eps[ep.key] { e = x } else { e = EpState(ep); ps.eps[ep.key] = e }
            if !out.contains(where: { $0 === e }) { out.append(e) }
        }
        if p.local, let lr = loc, let lp = localPathValue { add(Endpoint(road: lr, addr: lp)) } // the device we dial on this computer
        if p.kind == Kind.plugin { return out } // reachable over the local socket only, on the connection it opened
        if let u = udp { for a in p.hints.udp { add(Endpoint(road: u, addr: a)) } }
        if let t = tcp { for a in p.hints.tcp { add(Endpoint(road: t, addr: a)) } }
        if let r = pairRelay(p) { add(Endpoint(road: r, addr: p.relayChannel)) }
        for a in apps where a.peer == peer { add(a.endpoint) } // a road the application opened to this device
        return out
    }

    /// roadRank orders kinds of roads (spec §7): UDP, TCP, a relay, then a road the application provides.
    private func roadRank(_ r: Road) -> Int {
        if r is AttachedRoad { return 3 }
        switch r.name {
        case "udp": return 0
        case "tcp", "local": return 1
        default: return 2
        }
    }

    /// sealTo sends packet content on one endpoint only (a keepalive, a probe).
    private func sealTo(_ s: Session, _ e: EpState, _ now: Int64, _ plain: Bytes) {
        if paused { return }
        if e.ep.road.send(e.ep.addr, seal(s, plain)) { e.lastSend = now }
    }

    /// probe tries the direct roads to a device while the session runs over a relay or a road the application
    /// provides (spec §7): a keepalive to every UDP and TCP address known for it, every probeEvery.
    private func probe(_ now: Int64, _ peer: String, _ ps: PeerState, _ s: Session) {
        if now - ps.lastProbe < probeEvery { return }
        let c = candidates(peer, ps, now, false)
        if c.count != 1 || roadRank(c[0].ep.road) < 2 { return }
        ps.lastProbe = now
        for e in candidates(peer, ps, now, true) where roadRank(e.ep.road) < 2 { sealTo(s, e, now, keepalive()) }
    }

    // --- application roads ---

    /// attachRoad attaches a road the application provides (spec §3): Bluetooth LE GATT, a serial line, a pipe.
    /// peer is the device it reaches, when the application knows it.
    @discardableResult
    public func attachRoad(peer: String?, road: AppRoad, config: AppRoadConfig) throws -> AttachedRoad {
        if config.mtu < 1 { throw P2pactError(Errors.badArgs, "an application road needs an MTU") }
        if !config.stream && config.mtu < MAX_ROAD_PACKET {
            throw P2pactError(Errors.badArgs, "a datagram road must carry \(MAX_ROAD_PACKET) bytes; a smaller link that keeps order is a stream road")
        }
        if let p = peer, trust.get(p) == nil { throw P2pactError(Errors.notFound, "unknown device") }
        let a = AttachedRoad(app: road, config: config, peer: peer, deliver: { [weak self] p, e in self?.receiveFromRoad(p, e) },
                             onDetach: { [weak self] r in self?.post { self?.detached(r) } })
        onLoop {
            apps.append(a)
            if peer != nil { appAttached(Clock.nanos(), a) }
        }
        return a
    }

    /// appAttached starts using a road the application attached for a device: a keepalive over it when there is a
    /// session (so the other side binds it too), a handshake when not.
    private func appAttached(_ now: Int64, _ a: AttachedRoad) {
        if paused { return }
        guard let peer = a.peer, let ps = peerState(peer) else { return }
        let e: EpState
        if let x = ps.eps[a.endpoint.key] { e = x } else { e = EpState(a.endpoint); ps.eps[a.endpoint.key] = e }
        if let s = current[peer] {
            sealTo(s, e, now, keepalive())
            return
        }
        ps.lastInit = 0
        startInit(now, peer, ps, ps.st.idle() ? nil : ps.st.nextPacket(now, false)?.plain)
    }

    private func detached(_ a: AttachedRoad) {
        apps.removeAll { $0 === a }
        for ps in peers.values { for (k, v) in ps.eps where v.ep.road === a { ps.eps.removeValue(forKey: k) } }
    }

    /// pairRelay picks the pair's relay: the one of the lower address, else the other's.
    private func pairRelay(_ p: Peer) -> RelayRoad? {
        let mine = ownRelay
        let theirs = p.hints.relay
        let (first, second) = p.addr < id.addr ? (theirs, mine) : (mine, theirs)
        guard let h = first ?? second else { return nil }
        return relay(h)
    }

    private func relay(_ h: RelayHint) -> RelayRoad {
        if let r = relays[h.addr] { return r }
        let r = RelayRoad(hint: h) { [weak self] p, e in self?.receiveFromRoad(p, e) }
        relays[h.addr] = r
        return r
    }

    private func sendData(_ now: Int64, _ peer: String, _ ps: PeerState, _ s: Session, _ plain: Bytes, _ all: Bool) {
        if paused { return }
        let pkt = seal(s, plain)
        for e in candidates(peer, ps, now, all) where e.ep.road.send(e.ep.addr, pkt) { e.lastSend = now }
    }

    private func seal(_ s: Session, _ plain: Bytes) -> Bytes {
        let hdr = cat([UInt8(P_DATA)], be32(s.remote), be32(s.sendN))
        let pkt = cat(hdr, s.send.encryptAt(s.sendN, hdr, plain))
        s.sendN += 1
        return pkt
    }

    /// startInit starts a session with a known device (Noise_IK); first is first-packet data.
    private func startInit(_ now: Int64, _ peer: String, _ ps: PeerState, _ first: Bytes?) {
        guard let p = trust.get(peer) else { return }
        if paused || now - ps.lastInit < ps.initGap() { return }
        ps.lastInit = now
        // keep the last few unanswered starts: a reply to any of them opens the session
        var pending = hs.filter { !$0.value.pair && $0.value.peer == peer }.sorted { $0.value.at < $1.value.at }.map { $0.key }
        while pending.count >= 3 { hs.removeValue(forKey: pending.removeFirst()) }
        guard let h = try? Handshake(.ik, initiator: true, prologue: Bytes(PROLOGUE.utf8), s: id.key, rs: p.key) else { return }
        lastTs = max(lastTs + 1, wallMillis() * MS) // strictly newer than the last start
        guard let msg1 = try? h.writeMessage(cat(be64(lastTs), be32(boot), first ?? [])) else { return }
        let local = newIndex()
        hs[local] = PendingHs(pair: false, hs: h, at: now, peer: peer)
        let pkt = cat([UInt8(P_INIT)], be32(local), msg1)
        for e in candidates(peer, ps, now, true) where e.ep.road.send(e.ep.addr, pkt) { e.lastSend = now }
    }

    private func wake() {
        if woken || closed { return }
        woken = true
        post { [unowned self] in
            self.woken = false
            self.pump(Clock.nanos())
        }
    }

    /// pump sends what is queued and what is due for retransmission.
    private func pump(_ now: Int64) {
        if paused { return } // nothing goes, and no timer counts a try: delivery resumes where it stopped
        punchTick(now)
        for (peer, ps) in peers {
            guard let s = current[peer] else {
                // take a part for the first packet only when a handshake really goes out (a
                // restarted device drops it unacknowledged until it has heard us: spec §4.2)
                if !ps.st.idle() && now - ps.lastInit >= ps.initGap() && trust.get(peer) != nil {
                    startInit(now, peer, ps, ps.st.nextPacket(now, false)?.plain)
                }
                continue
            }
            // nothing for 10 s while retransmitting: the session looks dead, start a new one
            if !ps.st.idle() && now - s.lastRecv > 10 * SEC && ps.st.stuck() {
                current.removeValue(forKey: peer)
                continue
            }
            let c = candidates(peer, ps, now, false)
            if c.count == 1 {
                let r = c[0].ep.road
                if let ar = r as? AttachedRoad {
                    ps.st.reliable = ar.config.stream
                    ps.st.link = ar.rate
                } else {
                    ps.st.reliable = r.name != "udp"
                    ps.st.link = 0
                }
            }
            var i = 0
            while true {
                if i == 256 { // a burst at a time; the rest on the next wake
                    wake()
                    break
                }
                i += 1
                guard let next = ps.st.nextPacket(now, false) else { break }
                sendData(now, peer, ps, s, next.plain, next.retry)
            }
            for e in ps.eps.values { // keepalive on every quiet road
                if now - e.lastRecv <= ALIVE_FOR && now - e.lastSend >= keepaliveGap {
                    if e.ep.road.send(e.ep.addr, seal(s, keepalive())) { e.lastSend = now }
                }
            }
        }
    }

    /// maintain runs every second: connect to known devices, keep relay channels, clean up.
    private func maintain(_ now: Int64) {
        if paused { return }
        observeNow(now)
        for p in trust.list() {
            guard let ps = peerState(p.addr) else { continue }
            joinPair(p)
            let s = current[p.addr]
            if s == nil && now - ps.lastInit >= AUTO_CONNECT { startInit(now, p.addr, ps, nil) }
            if let s = s { probe(now, p.addr, ps, s) }
        }
        unhold(now)
        reannounce(now)
        for (k, s) in sessions where current[s.peer] !== s && now - s.lastRecv > SESSION_IDLE { sessions.removeValue(forKey: k) }
        for (k, h) in hs where now - h.at > 60 * SEC { hs.removeValue(forKey: k) }
        let wall = wallMillis()
        for (k, inv) in invites where wall > inv.exp {
            invites.removeValue(forKey: k)
            inviteGrants.removeValue(forKey: k)
            if let r = ownRelay { relay(r).leave(k) }
        }
    }

    /// joinPair keeps the pair's relay channel open.
    private func joinPair(_ p: Peer) {
        pairRelay(p)?.join(p.relayChannel, p.addr < id.addr ? "b" : "a")
    }

    private func newIndex() -> Int64 {
        while true {
            let i = u32(randomBytes(4), 0)
            if i != 0 && sessions[i] == nil && hs[i] == nil { return i }
        }
    }

    // --- compression (spec §5) ---

    /// push queues a message, compressed when worth it: with our dictionary for this device, else the newest one
    /// it also has. talk: the message is conversation (not tool 0), so it goes to the history.
    private func push(_ ps: PeerState, _ msg: Bytes, _ stream: Int64, _ talk: Bool, reply: Bool = false) {
        if noCompression || bootstrap(msg) {
            ps.st.push(msg, zip: false, stream: stream, reply: reply)
        } else {
            let (d, slot) = dicts.pick(ps.addr, ps.dicts, ps.lacks)
            let z = compress(msg, d, slot)
            if talk && !noLearning { learner.talk(ps.addr, msg, d, z) }
            if let z = z { ps.st.push(z, zip: true, stream: stream, reply: reply) } else { ps.st.push(msg, zip: false, stream: stream, reply: reply) }
        }
        wake()
    }

    /// hear queues a conversation message we got from the device for the history.
    private func hear(_ peer: String, _ msg: Bytes) {
        if !noCompression && !noLearning { learner.hear(peer, msg) }
    }

    /// inbound decompresses a reassembled message and runs it in order. A missing dictionary is not an error: we
    /// hold the message and everything after it and ask the sender for it. While waiting, only results of our
    /// calls, hellos and dictionary lists run out of order.
    private func inbound(_ peer: String, _ msg: Bytes, _ zip: Bool, _ stream: Int64) {
        guard let ps = peerState(peer) else { return }
        if !ps.waiting.isEmpty {
            if case .plain(let m) = unzip(ps, msg, zip), outOfOrder(m) {
                message(peer, m, stream)
                drain(peer, ps)
                return
            }
        }
        if ps.waiting.isEmpty { ps.waitSince = Clock.nanos() }
        ps.waiting.append(Inbound(msg: msg, zip: zip, stream: stream))
        drain(peer, ps)
    }

    /// unhold: held messages do not wait forever (spec §5) — after holdAsk we ask again; after holdDrop they are
    /// dropped and the lists are learnt anew.
    private func unhold(_ now: Int64) {
        for (peer, ps) in peers {
            if ps.waiting.isEmpty { continue }
            let held = now - ps.waitSince
            if held >= holdDrop {
                let k = ps.waiting.count
                ps.waiting = []
                ps.fetching = false; ps.askingInfo = false
                ps.dicts = []; ps.lacks = []; ps.tried = []
                sendInfo(peer)
                if let cb = onHeld { io.async { cb(peer, k) } }
            } else if held >= holdAsk {
                if ps.dicts.isEmpty { askInfo(peer, ps) } else { ps.tried = []; drain(peer, ps) }
            }
        }
    }

    /// reannounce: our addresses changed — tell the devices in session at once with our hello.
    private func reannounce(_ now: Int64) {
        if now - hintsAt < 5 * SEC { return }
        hintsAt = now
        guard let sent = hintsSent else { return }
        if Cbor.encode(hints().toWire()) == sent { return }
        for peer in Array(current.keys) { sendInfo(peer) }
    }

    /// askInfo asks the device for its hello (0.2 info) when we hold its messages without its list.
    private func askInfo(_ peer: String, _ ps: PeerState) {
        let now = Clock.nanos()
        if ps.askingInfo || now - ps.askedInfo < 10 * SEC { return }
        ps.askingInfo = true
        ps.askedInfo = now
        call(peer, 0, 2, timeoutMs: 30_000).whenComplete { [weak self] r in
            self?.post {
                guard let self = self else { return }
                ps.askingInfo = false
                guard case .success(let res) = r, res.count >= 5, ps.dicts.isEmpty, self.peers[peer] === ps else { return }
                ps.dicts = idsOf(res[4])
                self.fetchNew(peer, ps)
                self.drain(peer, ps)
            }
        }
    }

    /// drain runs waiting messages in order until one cannot be decoded yet.
    private func drain(_ peer: String, _ ps: PeerState) {
        while let w = ps.waiting.first {
            switch unzip(ps, w.msg, w.zip) {
            case .missing:
                let did = ps.dicts[Int(w.msg[0]) - 1]
                if !did.isEmpty {
                    if !hasId(ps.tried, did) { fetchDict(peer, ps, did) } // one we could not get: unhold asks again, then drops
                    return
                }
                ps.waiting.removeFirst() // a free slot: the sender dropped that dictionary, the message cannot be read
                if let cb = onHeld { io.async { cb(peer, 1) } }
            case .noList:
                askInfo(peer, ps)
                return // wait for a hello or 0.5, and ask for it
            case .bad: ps.waiting.removeFirst()
            case .plain(let m):
                ps.waiting.removeFirst()
                message(peer, m, w.stream)
            }
        }
    }

    private enum Unzip {
        case plain(Bytes)
        case missing // we lack the dictionary in that slot
        case noList // the slot is beyond the list we know
        case bad
    }

    private func unzip(_ ps: PeerState, _ msg: Bytes, _ zip: Bool) -> Unzip {
        if !zip { return .plain(msg) }
        if msg.isEmpty { return .bad }
        var d: Dict?
        let slot = Int(msg[0])
        if slot > 0 {
            if slot > ps.dicts.count { return .noList }
            guard let x = dicts.get(ps.dicts[slot - 1], ps.addr) else { return .missing }
            d = x
        }
        guard let out = try? decompress(msg, d) else { return .bad }
        return .plain(out)
    }

    /// fetchNew asks the device for the newest dictionary in its list that we lack: so it can compress with it.
    private func fetchNew(_ peer: String, _ ps: PeerState) {
        guard let did = ps.dicts.first(where: { !$0.isEmpty && dicts.get($0, peer) == nil && !hasId(ps.tried, $0) }) else { return }
        fetchDict(peer, ps, did)
    }

    /// fetchDict asks the device for dictionary id (0.5 dict): one it compressed a waiting message with, or a new
    /// one in its list. What we get belongs to the pair with it.
    private func fetchDict(_ peer: String, _ ps: PeerState, _ did: Bytes) {
        if ps.fetching { return }
        ps.fetching = true
        func attempt(_ tryN: Int) {
            call(peer, 0, 5, [.bytes(did)], timeoutMs: 30_000).whenComplete { [weak self] r in
                self?.post {
                    guard let self = self else { return }
                    var raw: Bytes?
                    if case .success(let res) = r { raw = res.at(0).asBytes }
                    var d: Dict?
                    if let raw = raw, same(dictId(raw), did) { d = try? Dict(raw, peer: peer, own: false) }
                    if d == nil && tryN < 2 && !self.closed && self.peers[peer] === ps {
                        attempt(tryN + 1)
                        return
                    }
                    ps.fetching = false
                    if self.closed || self.peers[peer] !== ps { return } // forgotten meanwhile
                    if let x = d, !self.addDictLocal(x) { d = nil } // could not store it: do not ask again and again
                    // not dropped at once even if a message waits for it: it stays held, unhold asks again
                    // after holdAsk and drops it after holdDrop, telling the application (onHeld)
                    if d == nil { ps.tried.append(did) }
                    self.drain(peer, ps)
                    self.fetchNew(peer, ps)
                }
            }
        }
        attempt(0)
    }

    /// dictHandler serves 0.5 dict [id] → dictionary bytes, only one the asker may see. A device that asks lacks
    /// it, so we stop compressing with it for that device until it announces again.
    private func dictHandler(_ peer: String, _ args: [Cbor.Value]) throws -> [Cbor.Value] {
        guard let did = args.at(0).asBytes else { throw P2pactError(Errors.badArgs, "dictionary id required") }
        if let allow = allowDict, !allow(peer, did) { throw P2pactError(Errors.forbidden, "dictionary is for the family only") }
        let d: Dict? = onLoop {
            peers[peer]?.lacks.append(did)
            return dicts.get(did, peer)
        }
        guard let dd = d else { throw P2pactError(Errors.notFound, "no such dictionary") }
        return [.bytes(dd.raw)]
    }

    /// addDict stores a new (newest) common dictionary and announces it (event 0.5).
    public func addDict(_ raw: Bytes) throws {
        let d = try Dict(raw)
        if !onLoop({ addDictLocal(d) }) { throw P2pactIOError("could not store the dictionary") }
    }

    /// addDictLocal stores a dictionary and announces the new list to the devices that see it: all for a common
    /// one, the pair's device for its own. Only over a live session: a new one starts with our hello.
    private func addDictLocal(_ d: Dict) -> Bool {
        do { try dicts.add(d) } catch { return false }
        for p in trust.list() {
            if !d.visible(p.addr) || current[p.addr] == nil { continue }
            peerState(p.addr)?.st.push(Cbor.encode(.array([3, 0, 5, .array(dicts.ids(p.addr).map { .bytes($0) })])), zip: false, stream: 0)
        }
        wake()
        return true
    }

    /// addDictForTest stores a dictionary as the node would (a pair's one too) and announces it (tests).
    func addDictForTest(_ d: Dict) { _ = onLoop { addDictLocal(d) } }

    /// dictHandlerForTest serves 0.5 dict as the node does (tests wrap it to count requests).
    func dictHandlerForTest(_ peer: String, _ args: [Cbor.Value]) throws -> [Cbor.Value] { try dictHandler(peer, args) }

    /// heldForTest is how many messages from peer wait for a dictionary or its list (tests).
    func heldForTest(_ peer: String) -> Int { onLoop { peers[peer]?.waiting.count ?? 0 } }

    /// dictIdsForTest lists the dictionary ids peer sees, by slot (tests).
    func dictIdsForTest(_ peer: String) -> [Bytes] { onLoop { dicts.ids(peer) } }

    /// loseDictsForTest forgets every dictionary we have (tests).
    func loseDictsForTest() { onLoop { dicts.clearForTest() } }

    // --- for tests: NAT hole punching ---
    func hintsForTest() -> Hints { onLoop { hints() } }
    func reflexiveForTest() -> String? { onLoop { reflexive } }
    func burstActiveForTest(_ peer: String) -> Bool { onLoop { (peers[peer]?.burstUntil ?? 0) != 0 } }
    func burstClearForTest(_ peer: String) { onLoop { peers[peer]?.burstUntil = 0 } }
    /// leaveDirectForTest forgets the live roads of a device: its session counts as not on a direct road.
    func leaveDirectForTest(_ peer: String) { onLoop { peers[peer]?.eps.removeAll() } }
    /// helloHintsForTest is a hello of the device with these hints.
    func helloHintsForTest(_ peer: String, _ h: Hints) { onLoop { if let ps = peers[peer] { helloHints(Clock.nanos(), peer, ps, name: "", os: "", h) } } }
    /// sessionUpForTest is a session of the device that started on this road.
    func sessionUpForTest(_ peer: String, _ from: Endpoint) { onLoop { if let ps = peers[peer] { sessionUp(Clock.nanos(), ps, from) } } }

    /// dictState tells what compresses messages to peer.
    public func dictState(_ peer: String) -> DictState {
        onLoop {
            let ps = peers[peer]
            return DictState(own: dicts.own(peer)?.id, using: ps.flatMap { dicts.pick(peer, $0.dicts, $0.lacks).0?.id },
                             training: learner.training(peer))
        }
    }
}

private func idsOf(_ v: Cbor.Value) -> [Bytes] { v.asList?.compactMap { $0.asBytes } ?? [] }

/// bootstrap: a hello or a dictionary list ([3, 0, 2|5, …]) carries what the receiver needs to decompress, so it
/// always goes uncompressed — a device that restarted must be able to read it.
func bootstrap(_ m: Bytes) -> Bool {
    m.count > 3 && m[1] == 3 && m[2] == 0 && (m[3] == 2 || m[3] == 5)
}

/// outOfOrder: results and errors of our calls, hellos and dictionary lists may skip the queue.
private func outOfOrder(_ m: Bytes) -> Bool {
    if m.count < 2 { return false }
    return m[1] == 1 || m[1] == 2 || (m.count > 3 && m[1] == 3 && m[2] == 0 && (m[3] == 2 || m[3] == 5))
}
