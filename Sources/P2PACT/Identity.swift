import Foundation

/// PROLOGUE is the protocol version bound into every handshake (spec §10).
let PROLOGUE = "p2pact/1"

// --- Grants (spec §8.1) ---

/// Levels of a grant.
public let LEVEL_READ = 1 // the methods a tool marks as read, and the tool's events
public let LEVEL_WRITE = 2 // everything

/// ALL_TOOLS is the tool name that stands for every tool, present and future.
public let ALL_TOOLS = "*"

/// Grant lets a device use a tool at a level: one element of [[tool name, level]…].
public struct Grant: Equatable {
    public let tool: String
    public let level: Int
    public init(_ tool: String, _ level: Int) { self.tool = tool; self.level = level }
}

/// defaultGrants is what a person's own device gets: everything, ["*", 2].
public func defaultGrants() -> [Grant] { [Grant(ALL_TOOLS, LEVEL_WRITE)] }

/// grantLevel is the level a list of grants gives for a tool name: the highest of the entries that
/// name it or "*"; 0 — none. A nil list is the default (everything).
public func grantLevel(_ grants: [Grant]?, _ tool: String) -> Int {
    guard let grants = grants else { return LEVEL_WRITE }
    var level = 0
    for g in grants where (g.tool == tool || g.tool == ALL_TOOLS) && g.level > level { level = g.level }
    return level
}

func grantsWire(_ g: [Grant]) -> Cbor.Value { .array(g.map { .array([.text($0.tool), .int(Int64($0.level))]) }) }

/// parseGrants reads [[tool name, level]…]; a malformed entry is skipped. nil — not a list.
func parseGrants(_ v: Cbor.Value) -> [Grant]? {
    guard let list = v.asList else { return nil }
    var out = [Grant]()
    for e in list {
        guard let pair = e.asList, let tool = pair.at(0).asString, let level = pair.at(1).asInt else { continue }
        if level < 1 { continue }
        out.append(Grant(tool, min(level, LEVEL_WRITE)))
    }
    return out
}

/// cleanGrants drops entries without a level and merges repeats, keeping the highest.
func cleanGrants(_ input: [Grant]) -> [Grant] {
    var out = [Grant]()
    for g0 in input {
        if g0.tool.isEmpty || g0.level < 1 { continue }
        let g = Grant(g0.tool, min(g0.level, LEVEL_WRITE))
        if let i = out.firstIndex(where: { $0.tool == g.tool }) {
            out[i] = Grant(g.tool, max(out[i].level, g.level))
        } else {
            out.append(g)
        }
    }
    return out
}

func grantsToJson(_ g: [Grant]) -> [Any] { g.map { ["tool": $0.tool, "level": $0.level] as [String: Any] } }

func grantsFromJson(_ v: Any?) -> [Grant]? {
    guard let l = v as? [Any] else { return nil }
    return l.compactMap { e in
        guard let m = e as? [String: Any], let t = m["tool"] as? String, let lv = (m["level"] as? NSNumber)?.intValue else { return nil }
        return Grant(t, lv)
    }
}

// --- Tools (spec §8) ---

/// Tools given by the spec: the same number on every device. Their names are what grants are written in.
let FIXED_TOOLS: [String: Int] = [
    "p2pact.service": 0, "p2pact.chat": 1, "p2pact.fleet": 2, "p2pact.family": 3, "p2pact.plugins": 4
]

/// FIRST_NAMED_TOOL is the first number a device may choose for a named tool (spec §8).
public let FIRST_NAMED_TOOL = 64

/// validToolName reports a tool name of spec §8: lowercase, dot-separated, the reverse of a domain.
public func validToolName(_ name: String) -> Bool {
    let parts = name.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    if parts.count < 2 || parts[0] == "p2pact" { return false }
    return parts.allSatisfy { p in
        !p.isEmpty && p.first != "-" && p.last != "-" && p.unicodeScalars.allSatisfy { ($0 >= "a" && $0 <= "z") || ($0 >= "0" && $0 <= "9") || $0 == "-" }
    }
}

/// ToolRef is a named tool on a device: its number there and its version.
struct ToolRef { let number: Int; let version: Int }

/// Environment variables a device gives a program it starts (spec §2, local programs).
public let ENV_SOCKET = "P2PACT_SOCKET"
public let ENV_INVITE = "P2PACT_INVITE"

// --- Kinds ---

/// Kinds of device (spec §1): what a device is for, told in the pairing payload and the hello.
public enum Kind {
    public static let unknown = 0 // not said (an older device): guess as before, e.g. by OS
    public static let computer = 1 // runs agents, serves tools
    public static let client = 2 // an app a person holds: a phone, a desktop or web app
    public static let plugin = 3 // a program on the same computer that adds tools to it
}

// --- Identity ---

/// Identity holds a device's permanent keys (spec §1): X25519 for sessions, Ed25519 for signatures.
public final class Identity {
    public let key: KeyPair
    public let sign: KeyPair
    public let addr: String

    init(key: KeyPair, sign: KeyPair) {
        self.key = key
        self.sign = sign
        addr = Crypto.address(key.publicKey)
    }

    /// shared derives a pair secret with pub without pairing (devices known from the family book).
    func shared(_ pub: Bytes, _ label: String) -> Bytes { Crypto.mac(Crypto.x25519(key.privateKey, pub) ?? [], label) }

    /// load reads the keys from dir/net-key.json, creating them (owner-only) when missing.
    public static func load(dir: String) throws -> Identity {
        let path = dir + "/net-key.json"
        var f: [String: Any] = [:]
        if let d = FileManager.default.contents(atPath: path) {
            guard let m = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
                  let priv = unb64(m["private"] as? String), let pub = unb64(m["public"] as? String),
                  priv.count == 32, pub.count == 32 else { throw P2pactIOError("net-key.json is corrupt") }
            f = m
        }
        var changed = false
        if f["private"] == nil {
            let k = Crypto.x25519Keypair()
            f["private"] = b64(k.privateKey)
            f["public"] = b64(k.publicKey)
            changed = true
        }
        if unb64(f["sign"] as? String)?.count != 32 {
            f["sign"] = b64(randomBytes(32))
            changed = true
        }
        if changed {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try writeAtomic(path, Bytes(try JSONSerialization.data(withJSONObject: f, options: [.sortedKeys])))
        }
        let key = Crypto.x25519Keypair(unb64(f["private"] as? String))
        return Identity(key: key, sign: Crypto.ed25519Keypair(unb64(f["sign"] as? String)!))
    }
}

/// Hints tell where to find a device (spec §7).
public struct Hints: Equatable {
    public var udp: [String]
    public var tcp: [String]
    public var relay: RelayHint?
    /// ws: WebSocket URLs of the relay, for browsers (the fourth element; we only carry them).
    public var ws: [String]
    public init(udp: [String] = [], tcp: [String] = [], relay: RelayHint? = nil, ws: [String] = []) { self.udp = udp; self.tcp = tcp; self.relay = relay; self.ws = ws }

    /// toWire is [UDP addresses, [relay address, fingerprint], TCP addresses].
    func toWire() -> Cbor.Value {
        var a: [Cbor.Value] = [
            udp.isEmpty ? .null : .array(udp.map { .text($0) }),
            relay.map { .array([.text($0.addr), .text($0.fp)]) } ?? .null,
            tcp.isEmpty ? .null : .array(tcp.map { .text($0) })
        ]
        if !ws.isEmpty { a.append(.array(ws.map { .text($0) })) } // without it the old three
        return .array(a)
    }

    func toJson() -> [String: Any] {
        var m: [String: Any] = [:]
        if !udp.isEmpty { m["udp"] = udp }
        if !tcp.isEmpty { m["tcp"] = tcp }
        if let r = relay { m["relay"] = ["addr": r.addr, "fp": r.fp] }
        if !ws.isEmpty { m["ws"] = ws }
        return m
    }

    static func fromWire(_ v: Cbor.Value) -> Hints {
        let a = v.asList ?? []
        func strs(_ x: Cbor.Value) -> [String] { x.asList?.compactMap { $0.asString } ?? [] }
        let r = strs(a.at(1))
        return Hints(udp: strs(a.at(0)), tcp: strs(a.at(2)), relay: r.count == 2 && !r[0].isEmpty ? RelayHint(addr: r[0], fp: r[1]) : nil, ws: strs(a.at(3)))
    }

    static func fromJson(_ v: Any?) -> Hints {
        guard let m = v as? [String: Any] else { return Hints() }
        func strs(_ x: Any?) -> [String] { (x as? [Any])?.compactMap { $0 as? String } ?? [] }
        var relay: RelayHint?
        if let r = m["relay"] as? [String: Any], let a = r["addr"] as? String { relay = RelayHint(addr: a, fp: r["fp"] as? String ?? "") }
        return Hints(udp: strs(m["udp"]), tcp: strs(m["tcp"]), relay: relay, ws: strs(m["ws"]))
    }
}

/// Peer is a known device (spec §2): [address, key, name, pair_secret, hints, added].
public struct Peer {
    public var addr: String
    public var key: Bytes
    public var name: String
    public var pairSecret: Bytes
    public var hints: Hints
    public var added: Int64 = 0
    public var signKey: Bytes?
    public var os: String?
    public var via: String? // joined through our invite with this id (hex)
    public var kind: Int = Kind.unknown
    /// What we let this device use of ours (spec §8.1); nil — never set, which is ["*", 2].
    public var grants: [Grant]?
    /// What the device lets us use of its tools (its event 0.6); nil — not told, which is ["*", 2] as well.
    public var granted: [Grant]?
    /// We reach the device over our local socket (a plugin's host, spec §3).
    public var local = false
    /// The devices we forward to for this one (spec §3, Node.allowForward); the consent is for the pair, so each of the
    /// two lists the other.
    public var forward: [String] = []

    init(addr: String, key: Bytes, name: String, pairSecret: Bytes, hints: Hints, added: Int64 = 0, signKey: Bytes? = nil,
         os: String? = nil, via: String? = nil, kind: Int = Kind.unknown, grants: [Grant]? = nil, granted: [Grant]? = nil, local: Bool = false,
         forward: [String] = []) {
        self.addr = addr; self.key = key; self.name = name; self.pairSecret = pairSecret; self.hints = hints; self.added = added
        self.signKey = signKey; self.os = os; self.via = via; self.kind = kind; self.grants = grants; self.granted = granted
        self.local = local; self.forward = forward
    }

    /// relayChannel is the pair's relay channel: only these two devices know it (spec §3).
    var relayChannel: String { Bytes(Crypto.mac(pairSecret, "relay")[0..<16]).hex() }

    /// allowed is what we let the device use of ours; the default if never set.
    public func allowed() -> [Grant] { grants ?? defaultGrants() }
    /// offered is what the device lets us use of its tools, as it told us; the default if it never did.
    public func offered() -> [Grant] { granted ?? defaultGrants() }
}

/// Trust is the set of known devices in dir/net-peers.json (the same format as p2pact-go). The file is
/// written on a queue of its own, in order: callers never wait for the disk.
final class Trust {
    private let path: String
    private var peers: [String: Peer] = [:]
    private let lock = NSLock()
    private let writer = DispatchQueue(label: "p2pact-trust")

    init(dir: String) {
        path = dir + "/net-peers.json"
        guard let d = FileManager.default.contents(atPath: path),
              let list = (try? JSONSerialization.jsonObject(with: d)) as? [Any] else { return }
        for j in list {
            guard let m = j as? [String: Any], let addr = m["addr"] as? String, let key = unb64(m["key"] as? String) else { continue }
            let p = Peer(addr: addr, key: key, name: m["name"] as? String ?? "", pairSecret: unb64(m["pair_secret"] as? String) ?? [],
                         hints: Hints.fromJson(m["hints"]), added: (m["added"] as? NSNumber)?.int64Value ?? 0,
                         signKey: unb64(m["sign_key"] as? String), os: m["os"] as? String, via: m["via"] as? String,
                         kind: (m["kind"] as? NSNumber)?.intValue ?? 0, grants: grantsFromJson(m["grants"]),
                         granted: grantsFromJson(m["granted"]), local: (m["local"] as? Bool) ?? false,
                         forward: (m["forward"] as? [Any])?.compactMap { $0 as? String } ?? [])
            if p.key.count == 32 && Crypto.address(p.key) == p.addr { peers[p.addr] = p }
        }
    }

    func get(_ addr: String) -> Peer? { lock.lock(); defer { lock.unlock() }; return peers[addr] }

    func list() -> [Peer] { lock.lock(); defer { lock.unlock() }; return peers.values.sorted { $0.addr < $1.addr } }

    /// put adds or updates a known device.
    func put(_ p0: Peer) {
        lock.lock(); defer { lock.unlock() }
        var p = p0
        if p.added == 0 { p.added = wallMillis() }
        peers[p.addr] = p
        save()
    }

    /// setGrants stores what we let a known device use; false — no such device.
    func setGrants(_ addr: String, _ g: [Grant]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard var p = peers[addr] else { return false }
        p.grants = g
        peers[addr] = p
        save()
        return true
    }

    /// setGranted stores what a known device told us we may use of its tools.
    func setGranted(_ addr: String, _ g: [Grant]) {
        lock.lock(); defer { lock.unlock() }
        guard var p = peers[addr] else { return }
        p.granted = g
        peers[addr] = p
        save()
    }

    /// setKind stores the kind a device told in its hello.
    func setKind(_ addr: String, _ kind: Int) {
        lock.lock(); defer { lock.unlock() }
        guard var p = peers[addr], p.kind != kind else { return }
        p.kind = kind
        peers[addr] = p
        save()
    }

    /// setHints stores fresh hints of a known device (from its hello).
    func setHints(_ addr: String, name: String, os: String, _ h: Hints) {
        lock.lock(); defer { lock.unlock() }
        guard var p = peers[addr] else { return }
        if !name.isEmpty { p.name = name }
        if !os.isEmpty { p.os = os }
        p.hints = Hints(udp: h.udp.isEmpty ? p.hints.udp : h.udp, tcp: h.tcp.isEmpty ? p.hints.tcp : h.tcp, relay: h.relay ?? p.hints.relay, ws: h.ws.isEmpty ? p.hints.ws : h.ws)
        peers[addr] = p
        save()
    }

    func remove(_ addr: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if peers.removeValue(forKey: addr) == nil { return false }
        for (k, p) in peers where p.forward.contains(addr) { // forgetting a device withdraws forwarding to it
            var q = p
            q.forward.removeAll { $0 == addr }
            peers[k] = q
        }
        save()
        return true
    }

    /// setForward stores the devices we forward to for a known device.
    func setForward(_ addr: String, _ list: [String]) {
        lock.lock(); defer { lock.unlock() }
        guard var p = peers[addr] else { return }
        p.forward = list
        peers[addr] = p
        save()
    }

    private func save() {
        let list: [[String: Any]] = peers.values.sorted { $0.addr < $1.addr }.map { p in
            var m: [String: Any] = ["addr": p.addr, "key": b64(p.key), "name": p.name, "pair_secret": b64(p.pairSecret),
                                    "hints": p.hints.toJson(), "added": p.added]
            if let s = p.signKey { m["sign_key"] = b64(s) }
            if let o = p.os { m["os"] = o }
            if let v = p.via { m["via"] = v }
            if p.kind != Kind.unknown { m["kind"] = p.kind }
            m["grants"] = p.grants.map { grantsToJson($0) } ?? NSNull()
            if let g = p.granted { m["granted"] = grantsToJson(g) }
            if p.local { m["local"] = true }
            if !p.forward.isEmpty { m["forward"] = p.forward }
            return m
        }
        guard let b = try? JSONSerialization.data(withJSONObject: list, options: [.prettyPrinted, .sortedKeys]) else { return }
        let path = self.path
        writer.async {
            try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try? writeAtomic(path, Bytes(b))
        }
    }

    /// flush waits until every change is on disk.
    func flush() { writer.sync {} }
}

/// Invite is an invitation to pair (spec §2): `p2pact1.<base64url(CBOR)>`.
public struct Invite {
    public let key: Bytes
    public let name: String
    public let secret: Bytes
    public let exp: Int64 // Unix ms
    public let hints: Hints

    init(key: Bytes, name: String, secret: Bytes, exp: Int64, hints: Hints) {
        self.key = key; self.name = name; self.secret = secret; self.exp = exp; self.hints = hints
    }

    /// id is the invite id in pairing packets and its relay channel.
    var id: Bytes { Bytes(Crypto.mac(secret, "invite")[0..<16]) }

    public var string: String {
        let b = Cbor.encode([1, .bytes(key), .text(name), .bytes(secret), .int(exp / 1000), hints.toWire()])
        return Invite.prefix + b64url(b)
    }

    static let prefix = "p2pact1."

    /// parse parses an invite string; an expired invite is an error.
    public static func parse(_ str: String) throws -> Invite {
        let s = str.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.hasPrefix(prefix) else { throw P2pactError(Errors.badArgs, "not an invite") }
        let raw = String(s.dropFirst(prefix.count)).trimmingCharacters(in: CharacterSet(charactersIn: "="))
        guard let bytes = unb64url(raw), let v = (try? Cbor.decode(bytes))?.asList,
              v.at(0) == .int(1), let key = v.at(1).asBytes, let secret = v.at(3).asBytes, key.count == 32, secret.count == 32 else {
            throw P2pactError(Errors.badArgs, "invite is corrupt")
        }
        let inv = Invite(key: key, name: v.at(2).asString ?? "", secret: secret, exp: (v.at(4).asInt64 ?? 0) * 1000, hints: Hints.fromWire(v.at(5)))
        if wallMillis() > inv.exp { throw P2pactError(Errors.badArgs, "invite expired") }
        return inv
    }
}
