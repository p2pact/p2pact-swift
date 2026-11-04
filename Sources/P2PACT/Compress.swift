import Foundation
import libzstd

// Compression (spec §5): zstd with a dictionary. A compressed message is [dictionary slot 1]
// [zstd frame without its magic and dictionary id]: the receiver knows both from the slot in
// the sender's dictionary list. Slot 0 means no dictionary.

/// MSG_MAX: the longest message (decompressed) we accept.
let MSG_MAX = 16 << 20
/// ZIP_MIN: shorter messages are not compressed; the gain is below the overhead.
let ZIP_MIN = 64
/// ZIP_FAST_FROM: from this size on, a faster level.
let ZIP_FAST_FROM = 32 << 10
/// ZIP_DICT_FAST_FROM: with a dictionary libzstd's level 3 is far weaker than Go's (1.8x the bytes at 40 KB),
/// so level 7 is kept up to this size and the fast level starts here.
let ZIP_DICT_FAST_FROM = 1 << 20
/// ZIP_QUICK_BELOW: shorter messages with a dictionary at the fastest level.
let ZIP_QUICK_BELOW = 1 << 10
/// DICT_KEEP is how many dictionaries of one kind to keep.
let DICT_KEEP = 4
/// DICT_LISTED_MAX bounds the pair's dictionaries kept because the device still lists them: what a device may
/// list to another (its common ones, its own for it and the one it got from it). Everything we fetch from a
/// device is the pair's here, so its list can hold more than DICT_KEEP of that kind; evicting one it lists
/// would only make us fetch it again, and again (spec §5).
let DICT_LISTED_MAX = 3 * DICT_KEEP
/// SLOTS_MAX: past this many slots, a new dictionary takes the oldest empty one.
let SLOTS_MAX = 32

let ZSTD_DICT_MAGIC: Int64 = 0xEC30A437
private let ZSTD_MAGIC: Bytes = [0x28, 0xb5, 0x2f, 0xfd]

private let LEVEL_PLAIN: Int32 = 19
private let LEVEL_DICT: Int32 = 7
private let LEVEL_QUICK: Int32 = 1
private let LEVEL_FAST: Int32 = 3

struct CompressError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

/// dictId is a dictionary's id: the first 16 bytes of BLAKE2s of its bytes (spec §5).
func dictId(_ raw: Bytes) -> Bytes { Bytes(Crypto.blake2s(raw).prefix(16)) }

/// Dict is a compression dictionary in zstd's standard format (magic, a non-zero id, entropy
/// tables, content). peer: "" — a common one; otherwise it belongs to the pair with that device.
/// own: we trained it (for peer).
final class Dict {
    let raw: Bytes
    let peer: String
    let own: Bool
    let id: Bytes
    /// zid is the dictionary id inside zstd frames (from its header).
    let zid: Int64

    private let lock = NSLock()
    private var enc: OpaquePointer?
    private var quick: OpaquePointer?
    private var fast: OpaquePointer?
    private var dec: OpaquePointer?

    init(_ raw: Bytes, peer: String = "", own: Bool = false) throws {
        if raw.count < 16 || le32(raw, 0) != ZSTD_DICT_MAGIC { throw CompressError("not a zstd dictionary") }
        self.raw = raw
        self.peer = peer
        self.own = own
        self.id = dictId(raw)
        self.zid = le32(raw, 4)
        if zid == 0 { throw CompressError("a zstd dictionary needs an id") }
    }

    deinit {
        if let e = enc { ZSTD_freeCDict(e) }
        if let e = quick { ZSTD_freeCDict(e) }
        if let e = fast { ZSTD_freeCDict(e) }
        if let e = dec { ZSTD_freeDDict(e) }
    }

    private func make(_ level: Int32) -> OpaquePointer? {
        raw.withUnsafeBytes { ZSTD_createCDict($0.baseAddress, raw.count, level) }
    }

    func encoder(_ size: Int) -> OpaquePointer? {
        lock.lock(); defer { lock.unlock() }
        if size >= ZIP_DICT_FAST_FROM {
            if fast == nil { fast = make(LEVEL_FAST) }
            return fast
        } else if size < ZIP_QUICK_BELOW {
            if quick == nil { quick = make(LEVEL_QUICK) }
            return quick
        }
        if enc == nil { enc = make(LEVEL_DICT) }
        return enc
    }

    func decoder() -> OpaquePointer? {
        lock.lock(); defer { lock.unlock() }
        if dec == nil { dec = raw.withUnsafeBytes { ZSTD_createDDict($0.baseAddress, raw.count) } }
        return dec
    }

    /// visible reports whether the dictionary may be used with, listed to or given to peer.
    func visible(_ peer: String) -> Bool { self.peer.isEmpty || self.peer == peer }

    /// withOwner is the same bytes kept for a pair.
    func withOwner(_ peer: String, _ own: Bool) -> Dict { try! Dict(raw, peer: peer, own: own) }
}

/// One set of zstd contexts per thread: contexts are not thread-safe and costly to create.
private final class Codecs {
    let plain = ZSTD_createCCtx()
    let withDict = ZSTD_createCCtx()
    let dec = ZSTD_createDCtx()
    deinit {
        ZSTD_freeCCtx(plain); ZSTD_freeCCtx(withDict); ZSTD_freeDCtx(dec)
    }
}

private func codecs() -> Codecs {
    let key = "p2pact.zstd.codecs"
    let td = Thread.current.threadDictionary
    if let c = td[key] as? Codecs { return c }
    let c = Codecs()
    td[key] = c
    return c
}

/// compress returns [slot | frame] for a receiver that has d (nil — none), or nil when not worth it.
func compress(_ msg: Bytes, _ d: Dict?, _ slot: Int) -> Bytes? {
    if msg.count < ZIP_MIN { return nil }
    let c = codecs()
    let cap = ZSTD_compressBound(msg.count)
    var buf = Bytes(repeating: 0, count: cap)
    var n = 0
    if let d = d {
        guard let cd = d.encoder(msg.count), let ctx = c.withDict else { return nil }
        ZSTD_CCtx_reset(ctx, ZSTD_reset_session_and_parameters)
        ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 0)
        if ZSTD_isError(ZSTD_CCtx_refCDict(ctx, cd)) != 0 { return nil }
        n = buf.withUnsafeMutableBytes { o in msg.withUnsafeBytes { i in
            ZSTD_compress2(ctx, o.baseAddress, cap, i.baseAddress, msg.count) } }
    } else {
        guard let ctx = c.plain else { return nil }
        ZSTD_CCtx_reset(ctx, ZSTD_reset_session_and_parameters)
        ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, msg.count >= ZIP_FAST_FROM ? LEVEL_FAST : LEVEL_PLAIN)
        ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 0)
        n = buf.withUnsafeMutableBytes { o in msg.withUnsafeBytes { i in
            ZSTD_compress2(ctx, o.baseAddress, cap, i.baseAddress, msg.count) } }
    }
    if ZSTD_isError(n) != 0 { return nil }
    guard let frame = stripFrame(Bytes(buf[0..<n])) else { return nil }
    if 1 + frame.count >= msg.count { return nil }
    return [UInt8(truncatingIfNeeded: slot)] + frame
}

/// decompress reverses compress; d is the dictionary for the slot in the first byte (nil for 0).
func decompress(_ b: Bytes, _ d: Dict?) throws -> Bytes {
    if b.count < 2 { throw CompressError("short") }
    guard let frame = restoreFrame(b, 1, d?.zid ?? 0) else { throw CompressError("bad frame") }
    guard let ctx = codecs().dec else { throw CompressError("no context") }
    var dd: OpaquePointer?
    if let d = d {
        dd = d.decoder()
        if dd == nil { throw CompressError("bad dictionary") }
    }
    func run(_ out: UnsafeMutableRawPointer?, _ cap: Int) -> Int {
        frame.withUnsafeBytes { i in
            if let dd = dd { return ZSTD_decompress_usingDDict(ctx, out, cap, i.baseAddress, frame.count, dd) }
            return ZSTD_decompressDCtx(ctx, out, cap, i.baseAddress, frame.count)
        }
    }
    let size = frame.withUnsafeBytes { ZSTD_getFrameContentSize($0.baseAddress, frame.count) }
    if size != ZSTD_CONTENTSIZE_UNKNOWN && size != ZSTD_CONTENTSIZE_ERROR {
        if size > UInt64(MSG_MAX) { throw CompressError("message too long") }
        var out = Bytes(repeating: 0, count: Int(size))
        let n = out.withUnsafeMutableBytes { run($0.baseAddress, Int(size)) }
        if ZSTD_isError(n) != 0 || n != Int(size) { throw CompressError("bad frame") }
        return out
    }
    if size == ZSTD_CONTENTSIZE_ERROR { throw CompressError("bad frame") }
    var cap = max(frame.count * 8, 4096) // unknown size: grow up to MSG_MAX
    while true {
        var out = Bytes(repeating: 0, count: cap)
        let n = out.withUnsafeMutableBytes { run($0.baseAddress, cap) }
        if ZSTD_isError(n) == 0 { return Bytes(out[0..<n]) }
        if cap >= MSG_MAX { throw CompressError("message too long") }
        cap = min(cap * 4, MSG_MAX)
    }
}

/// stripFrame drops the zstd magic (4 bytes) and the dictionary id (up to 4) from a frame.
func stripFrame(_ f: Bytes) -> Bytes? {
    if f.count < 6 || Array(f[0..<4]) != ZSTD_MAGIC { return nil }
    let fhd = Int(f[4])
    let didLen = [0, 1, 2, 4][fhd & 3]
    var at = 5
    if fhd & 0x20 == 0 { at += 1 } // not single-segment: a window descriptor follows
    if f.count < at + didLen { return nil }
    var out = Bytes(repeating: 0, count: f.count - 4 - didLen)
    out[0] = UInt8(fhd & ~3 & 0xff)
    for i in 0..<(at - 5) { out[1 + i] = f[5 + i] }
    for i in 0..<(f.count - at - didLen) { out[at - 4 + i] = f[at + didLen + i] }
    return out
}

/// restoreFrame puts back the magic and dictionary id zid (0 — no dictionary); the frame starts at off.
func restoreFrame(_ b: Bytes, _ off: Int, _ zid: Int64) -> Bytes? {
    let len = b.count - off
    if len < 2 { return nil }
    let fhd = Int(b[off])
    if fhd & 3 != 0 { return nil }
    var at = 1
    if fhd & 0x20 == 0 { at += 1 }
    if len < at { return nil }
    if zid == 0 { return cat(ZSTD_MAGIC, Bytes(b[off...])) }
    var out = Bytes(repeating: 0, count: 4 + len + 4)
    for i in 0..<4 { out[i] = ZSTD_MAGIC[i] }
    out[4] = UInt8((fhd | 3) & 0xff)
    for i in 0..<(at - 1) { out[5 + i] = b[off + 1 + i] }
    for i in 0..<4 { out[4 + at + i] = UInt8(truncatingIfNeeded: zid >> Int64(8 * i)) }
    for i in 0..<(len - at) { out[8 + at + i] = b[off + at + i] }
    return out
}

func hasId(_ list: [Bytes], _ id: Bytes) -> Bool { list.contains { same($0, id) } }

/// COMMON_DICT is the common dictionary (spec §5, dict/common-1.zdict of the spec repository).
enum CommonDict {
    static let raw: Bytes = {
        guard let u = Bundle.module.url(forResource: "common-1", withExtension: "zdict"),
              let d = try? Data(contentsOf: u) else { fatalError("common-1.zdict missing") }
        return Bytes(d)
    }()
}
