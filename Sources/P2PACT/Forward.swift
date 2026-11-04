import Foundation

// Via a third device (spec §3): a device both trust carries a pair's packets inside its own
// sessions with each of them — event 0.7 forward [to, packet] to it, event 0.8 forwarded
// [from, packet] from it. The packets stay end-to-end encrypted: the forwarder sees what a relay
// sees. It forwards only for pairs its person opted it in for (Node.allowForward), one hop only,
// within a rate limit, and never ahead of its own traffic. The node's side is in Node.swift.

let EV_FORWARD = 7 // event 0.7 forward [to, packet]: to a forwarder
let EV_FORWARDED = 8 // event 0.8 forwarded [from, packet]: from a forwarder

/// DEFAULT_FORWARD_RATE: bytes a second a forwarder carries in one direction of a pair, unless Node.forwardRate says otherwise.
public let DEFAULT_FORWARD_RATE = 256 << 10

let FORWARD_BURST = 64 << 10 // bytes a direction may send at once above its rate, and may wait

/// FORWARD_QUEUE: past this many parts waiting to go to a device, packets to forward to it (and our own packets for a
/// forwarder) are dropped — our own traffic goes first.
let FORWARD_QUEUE = 128

private let b32: [Character] = Array("abcdefghijklmnopqrstuvwxyz234567")

/// addrBytes is an address as it goes on the wire: 16 bytes; nil — not an address.
func addrBytes(_ addr: String) -> Bytes? {
    if addr.count != 26 { return nil }
    var out = Bytes()
    var v = 0
    var bits = 0
    for c in addr.lowercased() {
        guard let d = b32.firstIndex(of: c) else { return nil }
        v = (v << 5) | d
        bits += 5
        if bits >= 8 {
            out.append(UInt8((v >> (bits - 8)) & 0xff))
            bits -= 8
            v &= (1 << bits) - 1
        }
    }
    return out.count == 16 ? out : nil
}

/// addrText is an address from the wire.
func addrText(_ b: Bytes) -> String {
    var out = ""
    var bits = 0
    var v = 0
    for x in b {
        v = (v << 8) | Int(x)
        bits += 8
        while bits >= 5 {
            out.append(b32[(v >> (bits - 5)) & 31])
            bits -= 5
        }
        v &= (1 << bits) - 1
    }
    if bits > 0 { out.append(b32[(v << (5 - bits)) & 31]) }
    return out
}

/// forwardStream is the stream forward events about a device go on: its address's first 8 bytes, so a loss towards one
/// device holds up nothing else.
func forwardStream(_ addr: Bytes) -> Int64 {
    var s: UInt64 = 0
    for i in 0..<8 { s = (s << 8) | UInt64(addr[i]) }
    return s == 0 ? 1 : Int64(bitPattern: s)
}

/// forwardMsg: events 0.7 and 0.8 — never compressed, run out of order (spec §3).
func forwardMsg(_ m: Bytes) -> Bool {
    m.count > 3 && m[1] == 3 && m[2] == 0 && (Int(m[3]) == EV_FORWARD || Int(m[3]) == EV_FORWARDED)
}

/// ViaRoad is the road to other devices through forwarder x: send wraps a packet into event 0.7 to x; what x hands over
/// (0.8) arrives on it. Its address is the device at the other end. send runs on the node's queue, like every road's
/// send from the node.
final class ViaRoad: Road {
    let x: String
    let name: String
    private let carry: (_ to: String, _ pkt: Bytes) -> Bool
    init(x: String, carry: @escaping (_ to: String, _ pkt: Bytes) -> Bool) {
        self.x = x
        name = "via:" + x
        self.carry = carry
    }
    func send(_ addr: String, _ pkt: Bytes) -> Bool { carry(addr, pkt) }
}

struct FwdPending {
    let to: String
    let msg: Bytes
    let stream: Int64
    let size: Int // the forwarded packet's bytes
}

/// FwdBucket shapes one forwarded direction: a token bucket of the forward rate with bursts of FORWARD_BURST bytes. What
/// comes over the rate waits, up to a burst, and goes as the bucket refills — the queue it builds tells the pair's
/// congestion control to slow down; past that it is dropped.
final class FwdBucket {
    var tokens: Double
    var at: Int64
    var q = Deque<FwdPending>()
    var queued = 0 // bytes waiting in q
    init(tokens: Double, at: Int64) { self.tokens = tokens; self.at = at }

    func refill(_ now: Int64, _ rate: Double) {
        if now <= at { return }
        tokens = min(Double(FORWARD_BURST), tokens + rate * Double(now - at) / Double(SEC))
        at = now
    }
}
