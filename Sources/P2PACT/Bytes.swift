import Foundation

// Byte helpers shared by the whole library. Byte strings are [UInt8] everywhere.

public typealias Bytes = [UInt8]

/// Nanosecond constants, as Int64 (the node's clock is monotonic nanoseconds).
let MS: Int64 = 1_000_000
let SEC: Int64 = 1_000_000_000

/// Clock is monotonic nanoseconds. It starts an hour in, so 0 means "never" and is older than anything.
enum Clock {
    private static let start = DispatchTime.now().uptimeNanoseconds
    static func nanos() -> Int64 {
        Int64(DispatchTime.now().uptimeNanoseconds - start) + 3_600_000_000_000
    }
}

func wallMillis() -> Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) }

public func randomBytes(_ n: Int) -> Bytes {
    var b = Bytes(repeating: 0, count: n)
    if n > 0 { b.withUnsafeMutableBytes { _ = SecRandomCopyBytesShim($0) } }
    return b
}

private func SecRandomCopyBytesShim(_ p: UnsafeMutableRawBufferPointer) -> Int32 {
    var g = SystemRandomNumberGenerator()
    var i = 0
    while i < p.count {
        let v = g.next()
        withUnsafeBytes(of: v) { vb in
            for k in 0..<8 where i + k < p.count { p[i + k] = vb[k] }
        }
        i += 8
    }
    return 0
}

private let hexDigits = Array("0123456789abcdef".utf8)

extension Array where Element == UInt8 {
    public func hex() -> String {
        var out = [UInt8]()
        out.reserveCapacity(count * 2)
        for b in self {
            out.append(hexDigits[Int(b >> 4)])
            out.append(hexDigits[Int(b & 15)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}

public func unhex(_ s: String) -> Bytes? {
    let u = Array(s.utf8)
    if u.count % 2 != 0 { return nil }
    func d(_ c: UInt8) -> UInt8? {
        switch c {
        case 48...57: return c - 48
        case 97...102: return c - 87
        case 65...70: return c - 55
        default: return nil
        }
    }
    var out = Bytes()
    out.reserveCapacity(u.count / 2)
    var i = 0
    while i < u.count {
        guard let h = d(u[i]), let l = d(u[i + 1]) else { return nil }
        out.append(h << 4 | l)
        i += 2
    }
    return out
}

/// Constant-time comparison of byte strings.
func same(_ a: Bytes, _ b: Bytes) -> Bool {
    if a.count != b.count { return false }
    var r: UInt8 = 0
    for i in 0..<a.count { r |= a[i] ^ b[i] }
    return r == 0
}

func cat(_ parts: Bytes...) -> Bytes {
    var out = Bytes()
    out.reserveCapacity(parts.reduce(0) { $0 + $1.count })
    for p in parts { out.append(contentsOf: p) }
    return out
}

func b64(_ b: Bytes) -> String { Data(b).base64EncodedString() }

func unb64(_ s: String?) -> Bytes? {
    guard let s = s, let d = Data(base64Encoded: s) else { return nil }
    return Bytes(d)
}

func b64url(_ b: Bytes) -> String {
    Data(b).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func unb64url(_ s: String) -> Bytes? {
    var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    return unb64(t)
}

func u32(_ b: Bytes, _ at: Int) -> Int64 {
    Int64(b[at]) << 24 | Int64(b[at + 1]) << 16 | Int64(b[at + 2]) << 8 | Int64(b[at + 3])
}

func be32(_ v: Int64) -> Bytes {
    [UInt8(truncatingIfNeeded: v >> 24), UInt8(truncatingIfNeeded: v >> 16), UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)]
}

func be64(_ v: Int64) -> Bytes { (0..<8).map { UInt8(truncatingIfNeeded: v >> Int64(56 - 8 * $0)) } }

func u64(_ b: Bytes, _ at: Int) -> Int64 {
    var n: Int64 = 0
    for i in 0..<8 { n = (n << 8) | Int64(b[at + i]) }
    return n
}

func le32(_ b: Bytes, _ at: Int) -> Int64 {
    Int64(b[at]) | Int64(b[at + 1]) << 8 | Int64(b[at + 2]) << 16 | Int64(b[at + 3]) << 24
}

/// ByteBuf is a growing byte buffer with varints (LEB128, as Go's binary.Uvarint).
struct ByteBuf {
    var buf = Bytes()
    var size: Int { buf.count }
    init(_ capacity: Int = 64) { buf.reserveCapacity(capacity) }
    mutating func byte(_ b: Int) { buf.append(UInt8(truncatingIfNeeded: b)) }
    mutating func uvarint(_ v: Int64) {
        var x = UInt64(bitPattern: v)
        while x & ~0x7f != 0 {
            buf.append(UInt8((x & 0x7f) | 0x80))
            x >>= 7
        }
        buf.append(UInt8(x))
    }
    mutating func bytes(_ b: Bytes) { buf.append(contentsOf: b) }
    mutating func bytes(_ b: ArraySlice<UInt8>) { buf.append(contentsOf: b) }
}

func uvarintSize(_ v: Int64) -> Int {
    var n = 1
    var x = UInt64(bitPattern: v)
    while x & ~0x7f != 0 { x >>= 7; n += 1 }
    return n
}

/// A reader of varints over a byte array; `ok` turns false on a short or overlong one.
struct VarReader {
    let b: Bytes
    var pos: Int
    var ok = true
    init(_ b: Bytes, _ pos: Int) { self.b = b; self.pos = pos }
    mutating func uvarint() -> Int64 {
        var x: UInt64 = 0
        var s: UInt64 = 0
        while true {
            if pos >= b.count || s > 63 { ok = false; return 0 }
            let c = UInt64(b[pos]); pos += 1
            if c < 0x80 { return Int64(bitPattern: x | (c << s)) }
            x |= (c & 0x7f) << s
            s += 7
        }
    }
}

/// writeAtomic replaces a file in one step, owner-only: a reader never sees it half-written.
func writeAtomic(_ path: String, _ b: Bytes) throws {
    let tmp = path + ".tmp"
    let fm = FileManager.default
    fm.createFile(atPath: tmp, contents: Data(b), attributes: [.posixPermissions: 0o600])
    if rename(tmp, path) != 0 { throw P2pactIOError("cannot write \(path)") }
}

public struct P2pactIOError: Error, CustomStringConvertible {
    public let description: String
    public init(_ d: String) { description = d }
}
