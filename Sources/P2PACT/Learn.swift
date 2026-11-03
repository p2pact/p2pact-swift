import Foundation
import libzstd

// Our own dictionaries (spec §5): a device trains a dictionary for each device it talks to, on
// that conversation. It learns what it sent; while that is little, what it got fills the history
// up to 256 KB. The first dictionary comes at 32 KB of history; then a new one when the history
// has doubled (up to 1 MB), monthly, or when compression got 15 % worse than right after training.

let LEARN_FIRST = 32 << 10
let LEARN_MAX = 1 << 20
let LEARN_HEARD = 256 << 10
let LEARN_SAMPLE = 4 << 10
let LEARN_WINDOW = 32 << 10
let LEARN_WORSE = 1.15
let LEARN_MONTH: Int64 = 30 * 24 * 3600 * SEC
let LEARN_DICT_MAX = 64 << 10
let LEARN_QUEUE_MAX = 1 << 20
let LEARN_OWN_MIN = 8

/// LearnTiming: learning is deferred; tests shorten these.
public struct LearnTiming {
    public var tickMs: Int64
    public var lullMs: Int64
    public var waitMs: Int64
    public var checkMs: Int64
    public init(tickMs: Int64 = 1000, lullMs: Int64 = 1000, waitMs: Int64 = 60_000, checkMs: Int64 = 24 * 3600_000) {
        self.tickMs = tickMs; self.lullMs = lullMs; self.waitMs = waitMs; self.checkMs = checkMs
    }
}

/// History is one conversation, kept in dir/net-history/<hash of the device's address>.
final class History {
    let file: String
    var fileSize: Int64 = 0
    var buf = Bytes()
    var rewrite = false
    var flushing = false
    var gone = false
    var own: [Bytes] = []
    var heard: [Bytes] = []
    var ownSize = 0
    var heardSize = 0
    var trained = 0
    var at: Int64 = 0
    var plain: Int64 = 0
    var zips: Int64 = 0
    var base = 0.0
    var worse = false
    var checked: Int64 = 0
    var due = ""
    var dueAt: Int64 = 0
    var training = false

    init(_ file: String) { self.file = file }

    func size() -> Int { ownSize + min(heardSize, max(0, LEARN_HEARD - ownSize)) }

    func add(_ m0: Bytes, _ isHeard: Bool) {
        let m = m0.count > LEARN_SAMPLE ? Bytes(m0.prefix(LEARN_SAMPLE)) : m0
        if isHeard {
            heard.append(m)
            heardSize += m.count
            while heardSize > LEARN_HEARD { heardSize -= heard.removeFirst().count }
        } else {
            own.append(m)
            ownSize += m.count
            while ownSize > LEARN_MAX { ownSize -= own.removeFirst().count }
        }
    }
}

func historyFile(_ dir: String, _ peer: String) -> String {
    dir + "/net-history/" + Bytes(Crypto.blake2s(Bytes(peer.utf8)).prefix(8)).hex()
}

private func record(_ b: inout Bytes, _ m: Bytes, _ heard: Bool) {
    b.append(contentsOf: be32(Int64(m.count)))
    b.append(heard ? 1 : 0)
    b.append(contentsOf: m)
}

private struct Pending {
    let msg: Bytes
    let heard: Bool
    let plain: Int
    let zips: Int
}

private final class PeerLearn {
    var queue: [Pending] = []
    var queued = 0
    var lastTalk: Int64 = 0
    var hist: History?
}

/// Learner keeps the conversation histories and trains our dictionary for each device. Its
/// methods run on the node's queue; the disk is written on io and dictionaries are trained
/// on trainer, one at a time; their results come back through post.
final class Learner {
    private let dir: String
    private let dicts: DictStore
    private let timing: LearnTiming
    private let io: DispatchQueue
    private let trainer: DispatchQueue
    private let post: (@escaping () -> Void) -> Void
    private let addDict: (Dict) -> Bool
    private var peers: [String: PeerLearn] = [:]
    private let closedLock = NSLock()
    private var _closed = false
    var closed: Bool {
        get { closedLock.lock(); defer { closedLock.unlock() }; return _closed }
        set { closedLock.lock(); _closed = newValue; closedLock.unlock() }
    }

    init(dir: String, dicts: DictStore, timing: LearnTiming, io: DispatchQueue, trainer: DispatchQueue,
         post: @escaping (@escaping () -> Void) -> Void, addDict: @escaping (Dict) -> Bool) {
        self.dir = dir; self.dicts = dicts; self.timing = timing; self.io = io; self.trainer = trainer
        self.post = post; self.addDict = addDict
    }

    func hear(_ peer: String, _ msg: Bytes) { queue(peer, Pending(msg: msg, heard: true, plain: 0, zips: 0)) }

    func talk(_ peer: String, _ msg: Bytes, _ d: Dict?, _ z: Bytes?) {
        let own = d?.own == true
        queue(peer, Pending(msg: msg, heard: false, plain: own ? msg.count : 0, zips: own ? (z?.count ?? msg.count) : 0))
    }

    private func queue(_ peer: String, _ p: Pending) {
        if p.msg.count < ZIP_MIN { return }
        let pl = peers[peer] ?? { let n = PeerLearn(); peers[peer] = n; return n }()
        if pl.queued >= LEARN_QUEUE_MAX { return }
        pl.queue.append(p)
        pl.queued += min(p.msg.count, LEARN_SAMPLE)
        pl.lastTalk = wallMillis()
    }

    func tick(_ now: Int64 = wallMillis()) {
        for (peer, pl) in peers {
            if pl.queue.isEmpty && (pl.hist?.due.isEmpty ?? true) { continue }
            let q = pl.queue
            pl.queue = []
            pl.queued = 0
            let h = history(peer, pl)
            for p in q {
                let m = p.msg.count > LEARN_SAMPLE ? Bytes(p.msg.prefix(LEARN_SAMPLE)) : p.msg
                h.add(m, p.heard)
                save(h, m, p.heard)
                h.plain += Int64(p.plain)
                h.zips += Int64(p.zips)
            }
            consider(peer, pl, h, now)
        }
    }

    private func history(_ peer: String, _ pl: PeerLearn) -> History {
        if let h = pl.hist { return h }
        let h = History(historyFile(dir, peer))
        pl.hist = h
        let b = Bytes(FileManager.default.contents(atPath: h.file) ?? Data())
        h.fileSize = Int64(b.count)
        var at = 0
        while at + 5 <= b.count {
            let l = Int(u32(b, at))
            if l > LEARN_SAMPLE || at + 5 + l > b.count || b[at + 4] > 1 { break } // a torn record
            h.add(Bytes(b[(at + 5)..<(at + 5 + l)]), b[at + 4] == 1)
            at += 5 + l
        }
        if let d = dicts.own(peer) {
            h.trained = h.size()
            let p = dicts.dir + "/" + d.id.hex()
            if let date = (try? FileManager.default.attributesOfItem(atPath: p))?[.modificationDate] as? Date {
                h.at = Int64(date.timeIntervalSince1970 * 1000)
            }
        }
        return h
    }

    private func save(_ h: History, _ m: Bytes, _ heard: Bool) {
        record(&h.buf, m, heard)
        if h.fileSize + Int64(h.buf.count) > 2 * Int64(LEARN_MAX + LEARN_HEARD) { h.rewrite = true }
        if !h.flushing {
            h.flushing = true
            flush(h)
        }
    }

    private func flush(_ h: History) {
        let whole = h.rewrite
        var data: Bytes
        if whole {
            data = Bytes()
            for x in h.own { record(&data, x, false) }
            for x in h.heard { record(&data, x, true) }
        } else {
            data = h.buf
        }
        h.buf = Bytes()
        h.rewrite = false
        if data.isEmpty || h.gone || closed {
            h.flushing = false
            return
        }
        let bytes = data
        io.async { [post] in
            let fm = FileManager.default
            let parent = (h.file as NSString).deletingLastPathComponent
            do {
                try fm.createDirectory(atPath: parent, withIntermediateDirectories: true)
                if whole {
                    try writeAtomic(h.file, bytes)
                } else {
                    if !fm.fileExists(atPath: h.file) {
                        fm.createFile(atPath: h.file, contents: nil, attributes: [.posixPermissions: 0o600])
                    }
                    let fh = try FileHandle(forWritingTo: URL(fileURLWithPath: h.file))
                    defer { try? fh.close() }
                    try fh.seekToEnd()
                    try fh.write(contentsOf: Data(bytes))
                }
                if h.gone { try? fm.removeItem(atPath: h.file) }
            } catch {}
            post {
                h.fileSize = whole ? Int64(bytes.count) : h.fileSize + Int64(bytes.count)
                self.flush(h)
            }
        }
    }

    private func consider(_ peer: String, _ pl: PeerLearn, _ h: History, _ now: Int64) {
        if h.training { return }
        let own = dicts.own(peer)
        let size = h.size()
        if h.plain >= Int64(LEARN_WINDOW) {
            let ratio = Double(h.zips) / Double(h.plain)
            h.plain = 0
            h.zips = 0
            if h.base == 0 { h.base = ratio } else if ratio >= h.base * LEARN_WORSE { h.worse = true }
        }
        if h.due.isEmpty && h.own.count >= LEARN_OWN_MIN {
            if own == nil {
                if size >= max(LEARN_FIRST, 2 * h.trained) { h.due = "first" }
            } else if size < LEARN_FIRST {
                // too little to replace what we have
            } else if h.trained < LEARN_MAX && size >= 2 * h.trained {
                h.due = "doubled"
            } else if now - h.checked >= timing.checkMs {
                h.checked = now
                if (now - h.at) * MS > LEARN_MONTH || h.worse { h.due = "check" }
            }
            if !h.due.isEmpty { h.dueAt = now }
        }
        if h.due.isEmpty || (now - pl.lastTalk < timing.lullMs && now - h.dueAt < timing.waitMs) { return }
        h.due = ""
        h.worse = false
        h.training = true
        let ownMsgs = h.own
        let heardAll = h.heard
        let heard = Array(heardAll.suffix(countFrom(heardAll, max(0, LEARN_HEARD - h.ownSize))))
        let dictSize = min(LEARN_DICT_MAX, max(size / 4, 4 << 10))
        trainer.async { [post] in
            let raw: Bytes? = self.closed ? nil : (try? train(ownMsgs, heard, dictSize))
            post {
                h.training = false
                h.trained = size
                h.at = wallMillis()
                if self.closed || raw == nil || self.peers[peer] !== pl { return }
                guard let d = try? Dict(raw!, peer: peer, own: true) else { return }
                if self.addDict(d) {
                    h.plain = 0
                    h.zips = 0
                    h.base = 0
                }
            }
        }
    }

    func training(_ peer: String) -> Bool {
        guard let pl = peers[peer] else { return false }
        let h = pl.hist
        return !pl.queue.isEmpty || (h != nil && (h!.training || !h!.due.isEmpty))
    }

    func forget(_ peer: String) {
        peers.removeValue(forKey: peer)?.hist?.gone = true
        let f = historyFile(dir, peer)
        io.async { try? FileManager.default.removeItem(atPath: f) }
    }

    func historySize(_ peer: String) -> (Int, Int) {
        let pl = peers[peer] ?? { let n = PeerLearn(); peers[peer] = n; return n }()
        let h = history(peer, pl)
        return (h.ownSize, h.heardSize)
    }

    /// flushed tells whether everything learnt so far is on disk (tests).
    func flushed(_ peer: String) -> Bool {
        guard let h = peers[peer]?.hist else { return true }
        return !h.flushing && h.buf.isEmpty
    }
}

/// countFrom is how many of the newest messages fit in n bytes.
func countFrom(_ msgs: [Bytes], _ n0: Int) -> Int {
    var n = n0
    var c = 0
    var i = msgs.count - 1
    while i >= 0 && n >= msgs[i].count {
        n -= msgs[i].count
        c += 1
        i -= 1
    }
    return c
}

/// train trains a zstd dictionary of up to size bytes with zstd's own trainer (ZDICT). The
/// samples are ordered so the newest of ours come last. The result is in zstd's standard format
/// (magic, non-zero id, entropy tables, content), as spec §5 requires.
func train(_ own: [Bytes], _ heard: [Bytes], _ size: Int) throws -> Bytes {
    let samples = (heard + own).filter { !$0.isEmpty }
    if samples.count < 8 { throw CompressError("too few samples") }
    var flat = Bytes()
    var sizes: [Int] = []
    for s in samples { flat.append(contentsOf: s); sizes.append(s.count) }
    var buf = Bytes(repeating: 0, count: size)
    let n = buf.withUnsafeMutableBytes { o in
        flat.withUnsafeBytes { f in
            sizes.withUnsafeBufferPointer { s in
                ZDICT_trainFromBuffer(o.baseAddress, size, f.baseAddress, s.baseAddress, UInt32(sizes.count))
            }
        }
    }
    if ZDICT_isError(n) != 0 { throw CompressError("training failed") }
    var raw = Bytes(buf[0..<n])
    if raw.count < 16 || le32(raw, 0) != ZSTD_DICT_MAGIC { throw CompressError("training: not a dictionary") }
    if le32(raw, 4) == 0 { // a dictionary needs a non-zero id: derive one from the content
        let h = Crypto.blake2s(raw)
        var v = UInt32(h[0]) | UInt32(h[1]) << 8 | UInt32(h[2]) << 16 | UInt32(h[3]) << 24
        if v < 32768 { v |= 0x8000_0000 } // ids below 32768 are reserved
        if v == 0 { v = 0x8000_0001 }
        for i in 0..<4 { raw[4 + i] = UInt8(truncatingIfNeeded: v >> UInt32(8 * i)) }
    }
    return raw
}
