import Foundation

/// AppRoad is a road the application provides (spec §3): Bluetooth LE GATT, a serial line, a pipe
/// to another program — anything the node cannot open by itself. The node calls send from one
/// thread of its own, one call at a time, never on the node's thread: it may block until the link
/// has taken the bytes. What arrives the application hands to AttachedRoad.receive.
public protocol AppRoad: AnyObject {
    /// send carries one unit of at most AppRoadConfig.mtu bytes: a packet on a datagram road, a
    /// piece of the byte stream on a stream road. A throw on a stream road detaches it: the
    /// stream is broken mid-packet, so the application attaches the link again once it is back.
    func send(_ b: Bytes) throws
}

/// AppRoadConfig describes an application road.
///
/// - name — the kind of road, shown as "app:<name>" ("ble");
/// - stream — the link keeps order and loses nothing while it is up: packets are framed as on TCP
///   (a 2-byte length, then the packet) and the frames are cut into pieces of at most mtu bytes.
///   Otherwise the road carries datagrams, one packet each, and must take any packet whole:
///   mtu at least MAX_ROAD_PACKET;
/// - mtu — the largest unit AppRoad.send takes;
/// - rate — bytes per second the link carries, if known; 0 — DEFAULT_APP_RATE until measured.
public struct AppRoadConfig {
    public var name: String
    public var stream: Bool
    public var mtu: Int
    public var rate: Int
    public init(name: String = "app", stream: Bool, mtu: Int, rate: Int = 0) {
        self.name = name; self.stream = stream; self.mtu = mtu; self.rate = rate
    }
}

/// MAX_ROAD_PACKET is the largest packet a road must carry (the TCP road's frame takes the same).
public let MAX_ROAD_PACKET = MAX_PACKET + 64

/// DEFAULT_APP_RATE is the rate assumed for an application road that declares none.
public let DEFAULT_APP_RATE = 16 << 10

private let APP_QUEUE = 256
private let appRoadSeq = Counter()

private final class Counter {
    private let l = NSLock()
    private var n = 0
    func next() -> Int { l.lock(); defer { l.unlock() }; n += 1; return n }
}

/// AttachedRoad is an application road attached to a node.
public final class AttachedRoad: Road {
    public let name: String
    private let app: AppRoad
    public let config: AppRoadConfig
    /// the device it reaches, as the application told the node (nil — learnt from packets)
    public let peer: String?
    private let deliver: (Bytes, Endpoint) -> Void
    private let onDetach: (AttachedRoad) -> Void
    let id: String
    private(set) var endpoint: Endpoint!
    private let out = FrameQueue(limit: APP_QUEUE)
    private let stopped = AtomicFlag()
    private let rl = NSRecursiveLock()
    private var buf = Bytes() // the stream being reassembled
    private var have = 0

    init(app: AppRoad, config: AppRoadConfig, peer: String?, deliver: @escaping (Bytes, Endpoint) -> Void, onDetach: @escaping (AttachedRoad) -> Void) {
        self.name = "app:" + config.name
        self.app = app
        self.config = config
        self.peer = peer
        self.deliver = deliver
        self.onDetach = onDetach
        self.id = "#\(appRoadSeq.next())"
        self.endpoint = Endpoint(road: self, addr: id)
        spawn("p2pact-app-road") { [self] in write() }
    }

    /// rate is the link rate to plan with before one is measured, bytes/s.
    var rate: Double { config.rate > 0 ? Double(config.rate) : Double(DEFAULT_APP_RATE) }

    /// send queues a packet for the application's send (addr is the attachment's own).
    public func send(_ addr: String, _ pkt: Bytes) -> Bool {
        if pkt.count > MAX_ROAD_PACKET || stopped.value { return false }
        var b: Bytes
        if config.stream {
            b = [UInt8(pkt.count >> 8 & 0xff), UInt8(pkt.count & 0xff)]
            b.append(contentsOf: pkt)
        } else {
            b = pkt
        }
        return out.offer(b)
    }

    /// write hands queued packets to the application, a stream road's in pieces of at most the MTU.
    private func write() {
        while !stopped.value {
            guard let b = out.poll(timeout: 1, cancel: { self.stopped.value }) else { continue }
            if stopped.value { return }
            if !config.stream {
                try? app.send(b)
                continue
            }
            var at = 0
            while at < b.count {
                let k = min(b.count - at, max(config.mtu, 1))
                do {
                    try app.send(Bytes(b[at..<at + k]))
                } catch {
                    detach() // the stream is broken mid-packet
                    return
                }
                at += k
            }
        }
    }

    /// receive hands the node what arrived on the road: a datagram, or the next piece of the byte
    /// stream (pieces may be of any size). Call it from one thread at a time, in the order the
    /// bytes came.
    public func receive(_ b: Bytes) {
        if stopped.value { return }
        if !config.stream {
            if b.count <= MAX_ROAD_PACKET { deliver(b, endpoint) }
            return
        }
        rl.lock(); defer { rl.unlock() }
        if buf.count < have + b.count { buf += Bytes(repeating: 0, count: max(have + b.count, 2 * buf.count, 4096) - buf.count) }
        buf.replaceSubrange(have..<have + b.count, with: b)
        have += b.count
        var at = 0
        while have - at >= 2 {
            let k = Int(buf[at]) << 8 | Int(buf[at + 1])
            if k > MAX_ROAD_PACKET { // not a frame: the stream is damaged, nothing tells where the next one starts
                have = 0
                return
            }
            if have - at < 2 + k { break }
            deliver(Bytes(buf[at + 2..<at + 2 + k]), endpoint)
            at += 2 + k
        }
        if at > 0 {
            buf.replaceSubrange(0..<have - at, with: buf[at..<have])
            have -= at
        }
    }

    /// drop discards what waits for the application's send (the node pauses).
    func drop() { out.clear() }

    /// detach stops using the road: the link is gone. The session goes on over the other roads.
    public func detach() {
        if !stopped.setIfUnset() { return }
        out.clear()
        out.nudge()
        onDetach(self)
    }

    public var isDetached: Bool { stopped.value }
}
