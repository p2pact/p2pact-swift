import Foundation

// Delivery (spec §5). The decrypted content of a data packet:
//
//   flags (1) | [ack] | [varint part number | [varint stream | varint number in stream] | part]
//   ack = varint "all up to N" | varint count | count × (varint missing, varint received)
//
// A message is cut into packet-sized parts numbered consecutively. Messages on stream 0 are
// delivered in the order sent; a message on another stream is delivered as soon as it is
// complete and its stream's earlier messages are delivered. Anything unacknowledged is
// retransmitted while the session lives.

let F_ACK = 1 // carries an ack
let F_MSG = 2 // carries a message part
let F_MORE = 4 // more parts follow
let F_ZIP = 8 // compressed; set on every part of a compressed message
let F_ONCE = 16 // do not ack (keepalive)
let F_FIRST = 32 // the first part of a message on a stream: stream and its number follow
let F_CONT = 64 // a further part of a message on a stream

/// ACK_BUDGET is the room for an ack in a packet; ranges beyond it are left out.
let ACK_BUDGET = 60

/// MAX_PART: 1200 − 9 (header) − 16 (tag) − 1 (flags) − the ack − up to 5 (part number) − up to 20 (stream).
let MAX_PART = MAX_PACKET - DATA_HEADER - 16 - 1 - ACK_BUDGET - 5 - 20

let RTO_START = 500 * MS // before the first round-trip sample
let RTO_MIN = 50 * MS
let RTO_MAX = 4 * SEC
let ACK_DELAY = 40 * MS
let CWND_START = 32.0 // parts in flight at first
let CWND_MIN = 32.0
let CWND_MAX = 4096.0
let GOT_MAX = 8192 // parts held above the first gap
// MSG_MAX (longer messages abort reassembly) is defined with compression
let LINK_QUEUE = SEC

final class Part {
    var seq: Int64
    let data: Bytes
    let more: Bool
    let zip: Bool
    let stream: Int64 // 0 — the ordered default stream
    let reply: Bool // part of a result or error: it answers a call of this boot only
    var num: Int64 = 0 // message number in its stream (from 1), on the first part
    var first = false // first part of a message on a stream
    var copies: [Int64] = [] // when each copy was sent
    var timer = false // the last copy went because the timer ran out
    var sent: Int64 = 0
    var tries = 0
    var delivered: Int64 = 0 // bytes delivered when this part was sent: its ack gives a rate sample
    var busy = false // the link was busy when it was sent: other parts were in flight ahead of it

    init(seq: Int64, data: Bytes, more: Bool, zip: Bool, stream: Int64, reply: Bool) {
        self.seq = seq; self.data = data; self.more = more; self.zip = zip; self.stream = stream; self.reply = reply
    }
}

final class RPart {
    let data: Bytes
    let more: Bool
    let zip: Bool
    let first: Bool
    let streamed: Bool
    let stream: Int64
    let num: Int64
    var used = false
    init(data: Bytes, more: Bool, zip: Bool, first: Bool, streamed: Bool, stream: Int64, num: Int64) {
        self.data = data; self.more = more; self.zip = zip; self.first = first; self.streamed = streamed
        self.stream = stream; self.num = num
    }
}

/// A queue with O(1) pops from the front.
struct Deque<T> {
    private var items: [T?] = []
    private var head = 0
    var isEmpty: Bool { head >= items.count }
    var count: Int { items.count - head }
    mutating func append(_ x: T) { items.append(x) }
    mutating func removeFirst() -> T {
        let x = items[head]!
        items[head] = nil
        head += 1
        if head > 64 && head * 2 > items.count {
            items.removeFirst(head)
            head = 0
        }
        return x
    }
    var first: T? { isEmpty ? nil : items[head] }
    var all: [T] { items[head...].compactMap { $0 } }
    mutating func removeAll() { items = []; head = 0 }
}

/// Delivery is delivery to one device, both directions.
final class Delivery {
    var next: Int64 = 1 // number of our next part
    var inflight: [Int64: Part] = [:]
    var queue = Deque<Part>()

    // congestion control: the window grows while acks arrive and halves on a loss while a queue
    // builds; the retransmission timer follows the measured round trip (RFC 6298)
    var cwnd = CWND_START
    var ssthresh = CWND_MAX
    var srtt: Int64 = 0
    var rttvar: Int64 = 0
    var minRTT: Int64 = 0
    var lastCut: Int64 = 0

    // delivery rate, as in BBR: bytes acknowledged per second, the maximum of recent samples
    var delivered: Int64 = 0
    var inflightBytes: Int64 = 0
    var reliable = false // the current road is a reliable stream: nothing is lost on it
    var link = 0.0 // the current road is an application's slow link: its rate to plan with, bytes/s
    var bw = 0.0
    var bwAt: Int64 = 0

    var snext: [Int64: Int64] = [:] // last message number sent per stream

    var recvAck: Int64 = 1 // the first part not received yet
    var got: [Int64: RPart] = [:] // parts received from recvAck on, and earlier ones not yet used
    var next0: Int64 = 1 // the next part to take for stream 0
    private var asm0 = Bytes()
    private var zip0 = false
    private var streams: [Int64: RStream] = [:]
    var ackDue: Int64 = 0 // when to ack (0 — nothing to ack)
    var unacked = 0 // parts received since our last ack

    private final class RStream {
        var next: Int64 = 1
        var ready: [Int64: (Bytes, Bool)] = [:]
    }

    private func resetRecv() {
        snext = [:]
        recvAck = 1; next0 = 1; got = [:]; asm0 = Bytes(); zip0 = false
        streams = [:]
        ackDue = 0; unacked = 0
    }

    /// rto is the retransmission timeout for a part sent for the first time.
    func rto() -> Int64 { srtt == 0 ? RTO_START : min(max(srtt + 4 * rttvar, RTO_MIN), RTO_MAX) }

    /// rate takes a delivery-rate sample: the estimate is the maximum of the last ~2 seconds.
    private func rate(_ now: Int64, _ r: Double) {
        if r >= bw || now - bwAt > 2 * SEC {
            bw = r
            bwAt = now
        }
    }

    /// canSend tells whether one more part may go: the congestion window, capped by twice the
    /// bandwidth-delay product while a queue is building.
    func canSend() -> Bool {
        // an application road (Bluetooth): about a second of the link in flight
        if link > 0 && inflightBytes >= Int64(linkRate() * Double(LINK_QUEUE) / Double(SEC)) + Int64(MAX_PART) { return false }
        if reliable { return Double(inflight.count) < CWND_MAX } // the road controls congestion itself
        if inflight.count >= Int(cwnd) { return false }
        if queueing() && bw > 0 && minRTT > 0 {
            return inflightBytes < Int64(2 * bw * Double(minRTT) / Double(SEC)) + Int64(4 * MAX_PART)
        }
        return true
    }

    /// timeout is when a part is due for retransmission: the current estimate plus the time the
    /// link needs for the parts sent ahead of it, doubled on retries only on signs of congestion
    /// or after three tries in a row.
    func timeout(_ p: Part, _ ahead: Int64) -> Int64 {
        var t = rto()
        if link > 0 {
            t += ACK_DELAY + 2 * Int64(Double(ahead + 1) * Double(MAX_PART + 64) / linkRate() * Double(SEC))
        } else if bw > 0 {
            t += Int64(Double(ahead) * Double(MAX_PART) / bw * Double(SEC))
        }
        let backoff = queueing() ? p.tries - 1 : max(0, p.tries - 3)
        var i = 0
        while i < backoff && t < RTO_MAX {
            t *= 2
            i += 1
        }
        return min(t, RTO_MAX)
    }

    /// linkRate is the rate the link delivers at: as measured, else what an application road declares (0 — unknown).
    func linkRate() -> Double { bw > 0 ? bw : link }

    /// sample takes a round-trip measurement (Karn's rule); a grown round trip leaves slow start.
    private func sample(_ rtt: Int64) {
        if minRTT == 0 || rtt < minRTT { minRTT = rtt }
        if cwnd < ssthresh && rtt > minRTT + max(minRTT / 2, 4 * MS) { ssthresh = cwnd }
        if srtt == 0 {
            srtt = rtt
            rttvar = rtt / 2
            return
        }
        let d = abs(srtt - rtt)
        rttvar = (3 * rttvar + d) / 4
        srtt = (7 * srtt + rtt) / 8
    }

    /// acked grows the window for n newly acknowledged parts.
    private func acked(_ n: Int) {
        let q = queueing()
        for _ in 0..<n {
            if cwnd < ssthresh || !q { cwnd += 1 } else { cwnd += 1 / cwnd }
        }
        cwnd = min(cwnd, CWND_MAX)
    }

    /// queueing reports that the round trip has grown well above its minimum.
    func queueing() -> Bool { srtt > minRTT + max(minRTT / 2, 10 * MS) }

    /// lost halves the window, at most once per round trip, and only while a queue builds.
    private func lost(_ now: Int64) {
        if now - lastCut < max(srtt, RTO_MIN) || !queueing() { return }
        lastCut = now
        ssthresh = max(cwnd / 2, CWND_MIN)
        cwnd = ssthresh
    }

    /// reset handles a restart of the other device (spec §4.2): our unacknowledged parts are
    /// renumbered from 1; receiving restarts from 1 too. Replies are dropped: the calls they
    /// answer ended with the restart, and the new call ids start from 1 again.
    func reset() {
        var pending = inflight.values.sorted { $0.seq < $1.seq }
        pending.append(contentsOf: queue.all)
        next = 1; inflight = [:]; queue = Deque<Part>(); inflightBytes = 0
        resetRecv()
        cwnd = CWND_START; ssthresh = CWND_MAX; lastCut = 0
        srtt = 0; rttvar = 0; minRTT = 0; bw = 0; bwAt = 0
        for p in pending {
            if p.reply { continue }
            p.seq = next; next += 1
            p.copies = []; p.sent = 0; p.tries = 0; p.timer = false
            if p.first { // the other side expects each stream from message 1 again
                let n = (snext[p.stream] ?? 0) + 1
                snext[p.stream] = n
                p.num = n
            }
            queue.append(p)
        }
    }

    /// push queues a message in parts on a stream (0 — the ordered default); zip marks it
    /// compressed, reply — a result or error (dropped if the other device restarts).
    func push(_ msg: Bytes, zip: Bool, stream: Int64, reply: Bool = false) {
        var num: Int64 = 0
        if stream != 0 {
            num = (snext[stream] ?? 0) + 1
            snext[stream] = num
        }
        var at = 0
        var first = true
        while true {
            let n = min(msg.count - at, MAX_PART)
            let p = Part(seq: next, data: Bytes(msg[at..<at + n]), more: at + n < msg.count, zip: zip, stream: stream, reply: reply)
            next += 1
            if stream != 0 && first {
                p.first = true
                p.num = num
            }
            first = false
            queue.append(p)
            at += n
            if at >= msg.count { return }
        }
    }

    struct Next { let plain: Bytes; let retry: Bool }

    /// nextPacket builds the next packet content: an overdue retransmission, a new part, or just
    /// an ack; nil — nothing to send. forceAck asks for an ack now.
    func nextPacket(_ now: Int64, _ forceAck: Bool) -> Next? {
        var p: Part?
        var lowest: Int64 = 0
        for seq in inflight.keys where lowest == 0 || seq < lowest { lowest = seq }
        for x in inflight.values {
            if now - x.sent >= timeout(x, x.seq - lowest) && (p == nil || x.seq < p!.seq) { p = x }
        }
        var retry = false
        if let rp = p {
            retry = true
            rp.timer = rp.sent != 0 // not taken as lost by an ack: the timer ran out
            lost(now)
        } else if !queue.isEmpty && canSend() {
            let np = queue.removeFirst()
            p = np
            inflight[np.seq] = np
            inflightBytes += Int64(np.data.count)
        }
        let received = recvAck > 1 || !got.isEmpty
        let ack = received && (p != nil || forceAck || (ackDue != 0 && now >= ackDue))
        if p == nil && !ack { return nil }
        var flags = 0
        var b = ByteBuf(p != nil ? p!.data.count + 96 : 64)
        b.byte(0)
        if ack {
            flags |= F_ACK
            appendAck(&b)
            ackDue = 0
            unacked = 0
        }
        if let p = p {
            flags |= F_MSG
            if p.more { flags |= F_MORE }
            if p.zip { flags |= F_ZIP }
            b.uvarint(p.seq)
            if p.first {
                flags |= F_FIRST
                b.uvarint(p.stream)
                b.uvarint(p.num)
            } else if p.stream != 0 {
                flags |= F_CONT
            }
            b.bytes(p.data)
            p.copies.append(now)
            p.delivered = delivered
            p.busy = inflightBytes - Int64(p.data.count) >= Int64(2 * MAX_PART)
            p.sent = now
            p.tries += 1
        }
        b.buf[0] = UInt8(flags)
        return Next(plain: b.buf, retry: retry)
    }

    /// appendAck writes the ack: all up to recvAck−1, then the ranges received above the first
    /// gap as (missing, received) counts, as many as fit in ACK_BUDGET.
    private func appendAck(_ b: inout ByteBuf) {
        b.uvarint(recvAck - 1)
        let above = got.keys.filter { $0 > recvAck }.sorted()
        var ranges = ByteBuf(ACK_BUDGET)
        var count: Int64 = 0
        var cursor = recvAck
        var i = 0
        while i < above.count {
            var j = i
            while j + 1 < above.count && above[j + 1] == above[j] + 1 { j += 1 }
            let gap = above[i] - cursor
            let run = Int64(j - i + 1)
            if ranges.size + uvarintSize(gap) + uvarintSize(run) > ACK_BUDGET - 12 { break }
            ranges.uvarint(gap)
            ranges.uvarint(run)
            count += 1
            cursor = above[j] + 1
            i = j + 1
        }
        b.uvarint(count)
        b.bytes(ranges.buf)
    }

    typealias Deliver = (Bytes, Bool, Int64) -> Void

    /// receive handles packet content from the other device; deliver is called for every message
    /// as it becomes deliverable (zip — compressed; stream — the stream it came on). False — the
    /// content is malformed.
    func receive(_ now: Int64, _ b: Bytes, _ deliver: Deliver) -> Bool {
        if b.isEmpty { return false }
        let flags = Int(b[0])
        var r = VarReader(b, 1)
        if flags & F_ACK != 0 {
            let upto = r.uvarint()
            let count = r.uvarint()
            if !r.ok || count > 64 || count < 0 { return false }
            var done = 0
            var newest: Int64 = 0 // the latest send time among the parts this ack covers
            func ack(_ seq: Int64) {
                guard let p = inflight[seq] else { return }
                // an ack sooner than the minimum round trip after a timer's copy is for an earlier
                // copy: the timer fired on a queue, not a loss (RFC 8985 §6.2).
                var sent = p.sent
                if p.timer && now - p.sent < minRTT {
                    for (i, c) in p.copies.enumerated() where i == 0 || now - c >= minRTT { sent = c }
                    sample(now - sent)
                } else if p.tries > 1 && reliable && link > 0 {
                    sample(now - p.copies[0])
                }
                if sent > newest { newest = sent }
                delivered += Int64(p.data.count)
                if p.tries == 1 {
                    sample(now - p.sent)
                    let dt = now - p.sent
                    if dt > 0 && (link == 0 || p.busy) { rate(now, Double(delivered - p.delivered) / Double(dt) * Double(SEC)) }
                }
                inflight.removeValue(forKey: seq)
                inflightBytes -= Int64(p.data.count)
                done += 1
            }
            for seq in inflight.keys.filter({ $0 <= upto }) { ack(seq) }
            var beyond: Int64 = 0
            var cursor = upto + 1
            for _ in 0..<Int(count) {
                let gap = r.uvarint()
                let run = r.uvarint()
                if !r.ok || run > Int64(GOT_MAX) || run < 0 || gap > Int64(Int32.max) || gap < 0 { return false }
                let start = cursor + gap
                if !inflight.isEmpty && run > 0 { for seq in start..<(start + run) { ack(seq) } }
                beyond += run
                cursor = start + run
            }
            acked(done)
            // time-based loss detection (RACK, RFC 8985)
            if newest != 0 && !reliable {
                let reorder = max(srtt / 4, MS)
                var anyLost = false
                for p in inflight.values where p.sent != 0 && p.sent + reorder < newest {
                    p.sent = 0
                    anyLost = true
                }
                if anyLost { lost(now) }
            }
            // fast retransmit: three parts after the gap arrived, so the gap is lost
            if beyond > 0 && !reliable {
                if let p = inflight[upto + 1],
                   beyond >= 3 || now - p.sent >= max(srtt / 4, ACK_DELAY),
                   link == 0 || p.tries == 1 || now - p.sent >= srtt {
                    p.sent = 0
                }
            }
        }
        if flags & F_MSG == 0 { return true }
        let seq = r.uvarint()
        if !r.ok { return false }
        var first = false
        var streamed = false
        var st: Int64 = 0
        var num: Int64 = 0
        if flags & F_FIRST != 0 {
            st = r.uvarint()
            num = r.uvarint()
            if !r.ok { return false }
            first = true
            streamed = true
        } else if flags & F_CONT != 0 {
            streamed = true
        }
        if ackDue == 0 { ackDue = now + ACK_DELAY }
        // like TCP: ack at once every second part, and on anything out of order
        unacked += 1
        if unacked >= 2 || seq != recvAck { ackDue = now }
        if seq < recvAck || got[seq] != nil || got.count >= GOT_MAX { return true } // duplicate, or too far ahead
        got[seq] = RPart(data: Bytes(b[r.pos...]), more: flags & F_MORE != 0, zip: flags & F_ZIP != 0, first: first,
                         streamed: streamed, stream: st, num: num)
        while got[recvAck] != nil { recvAck += 1 }
        if streamed { assemble(seq, deliver) }
        take0(deliver)
        for (k, x) in got where x.used && k < recvAck && k < next0 { got.removeValue(forKey: k) } // forget parts that are used and acknowledged
        return true
    }

    /// assemble completes the stream message part seq belongs to, if all its parts are here.
    private func assemble(_ seq: Int64, _ deliver: Deliver) {
        var start = seq
        while true {
            guard let x = got[start] else { return }
            if x.used { return }
            if x.first { break }
            if !x.streamed || start == 0 { return }
            start -= 1
        }
        let head = got[start]!
        var msg = Bytes()
        var end = start
        while true {
            guard let x = got[end], x.streamed, !x.used, !(end != start && x.first) else { return } // a part is still missing
            if msg.count + x.data.count > MSG_MAX { return }
            msg.append(contentsOf: x.data)
            if !x.more { break }
            end += 1
        }
        for k in start...end { got[k]!.used = true }
        let rs: RStream
        if let e = streams[head.stream] { rs = e } else { rs = RStream(); streams[head.stream] = rs }
        if head.num < rs.next { return } // a duplicate of a delivered message
        rs.ready[head.num] = (msg, head.zip)
        while let m = rs.ready.removeValue(forKey: rs.next) {
            rs.next += 1
            deliver(m.0, m.1, head.stream)
        }
    }

    /// take0 delivers stream 0 messages in order; parts of stream messages are skipped.
    private func take0(_ deliver: Deliver) {
        while let x = got[next0] {
            next0 += 1
            if x.streamed { continue }
            x.used = true
            if asm0.isEmpty { zip0 = x.zip }
            if asm0.count + x.data.count > MSG_MAX {
                asm0 = Bytes()
                continue
            }
            asm0.append(contentsOf: x.data)
            if x.more { continue }
            let msg = asm0
            asm0 = Bytes()
            deliver(msg, zip0, 0)
        }
    }

    /// idle reports that nothing waits to be sent or acknowledged.
    func idle() -> Bool { inflight.isEmpty && queue.isEmpty }

    /// stuck: a part was tried four times (the session looks dead).
    func stuck() -> Bool { inflight.values.contains { $0.tries >= 4 } }
}

/// keepalive is a liveness packet content: flags only, not acknowledged.
func keepalive() -> Bytes { [UInt8(F_ONCE)] }
