import Foundation

/// CBOR (RFC 8949), the subset messages use (spec §6): integers, byte and text strings, arrays,
/// maps, booleans, null and floats. Tags are skipped on decoding.
public enum Cbor {
    public indirect enum Value: Equatable {
        case int(Int64)
        case bytes(Bytes)
        case text(String)
        case array([Value])
        case map([MapEntry])
        case bool(Bool)
        case double(Double)
        case null
    }

    public struct MapEntry: Equatable {
        public let key: Value
        public let value: Value
        public init(_ k: Value, _ v: Value) { key = k; value = v }
    }

    public struct CborError: Error, CustomStringConvertible {
        public let description: String
        init(_ d: String) { description = d }
    }

    public static func encode(_ v: Value) -> Bytes {
        var out = Bytes()
        write(&out, v)
        return out
    }

    private static func head(_ out: inout Bytes, _ major: UInt8, _ n: UInt64) {
        let m = major << 5
        switch n {
        case 0...23: out.append(m | UInt8(n))
        case 24...0xff: out.append(m | 24); out.append(UInt8(n))
        case 0x100...0xffff: out.append(m | 25); out.append(UInt8(n >> 8)); out.append(UInt8(n & 0xff))
        case 0x10000...0xffff_ffff:
            out.append(m | 26)
            for s in stride(from: 24, through: 0, by: -8) { out.append(UInt8((n >> UInt64(s)) & 0xff)) }
        default:
            out.append(m | 27)
            for s in stride(from: 56, through: 0, by: -8) { out.append(UInt8((n >> UInt64(s)) & 0xff)) }
        }
    }

    private static func write(_ out: inout Bytes, _ v: Value) {
        switch v {
        case .null: out.append(0xf6)
        case .bool(let b): out.append(b ? 0xf5 : 0xf4)
        case .int(let n):
            if n >= 0 { head(&out, 0, UInt64(n)) } else { head(&out, 1, UInt64(-1 - n)) }
        case .double(let d):
            out.append(0xfb)
            let bits = d.bitPattern
            for s in stride(from: 56, through: 0, by: -8) { out.append(UInt8((bits >> UInt64(s)) & 0xff)) }
        case .bytes(let b): head(&out, 2, UInt64(b.count)); out.append(contentsOf: b)
        case .text(let s):
            let b = Bytes(s.utf8)
            head(&out, 3, UInt64(b.count))
            out.append(contentsOf: b)
        case .array(let a):
            head(&out, 4, UInt64(a.count))
            for x in a { write(&out, x) }
        case .map(let m):
            head(&out, 5, UInt64(m.count))
            for e in m { write(&out, e.key); write(&out, e.value) }
        }
    }

    /// decode reads one value; trailing bytes are an error.
    public static func decode(_ b: Bytes) throws -> Value {
        var r = Reader(b)
        let v = try r.value(0)
        if r.pos != b.count { throw CborError("cbor: trailing bytes") }
        return v
    }

    private struct Reader {
        let b: Bytes
        var pos = 0
        init(_ b: Bytes) { self.b = b }

        mutating func byte() throws -> Int {
            if pos >= b.count { throw CborError("cbor: short") }
            defer { pos += 1 }
            return Int(b[pos])
        }

        mutating func arg(_ info: Int) throws -> UInt64 {
            switch info {
            case 0..<24: return UInt64(info)
            case 24: return UInt64(try byte())
            case 25: let a = try byte(); let c = try byte(); return UInt64(a << 8 | c)
            case 26:
                var n: UInt64 = 0
                for _ in 0..<4 { n = (n << 8) | UInt64(try byte()) }
                return n
            case 27:
                var n: UInt64 = 0
                for _ in 0..<8 { n = (n << 8) | UInt64(try byte()) }
                return n
            default: throw CborError("cbor: bad length")
            }
        }

        mutating func bytes(_ n: UInt64) throws -> Bytes {
            if n > UInt64(b.count - pos) { throw CborError("cbor: short") }
            let out = Bytes(b[pos..<pos + Int(n)])
            pos += Int(n)
            return out
        }

        func count(_ n: UInt64) throws -> Int {
            if n > UInt64(b.count - pos) { throw CborError("cbor: too long") } // every item takes a byte
            return Int(n)
        }

        mutating func value(_ depth: Int) throws -> Value {
            if depth > 64 { throw CborError("cbor: too deep") }
            let ib = try byte()
            let major = ib >> 5
            let info = ib & 31
            if info == 31 && (2...5).contains(major) { return try indefinite(major, depth) }
            switch major {
            case 0:
                let n = try arg(info)
                return .int(Int64(bitPattern: n))
            case 1:
                let n = try arg(info)
                return .int(-1 - Int64(bitPattern: n))
            case 2: return .bytes(try bytes(try arg(info)))
            case 3: return .text(String(decoding: try bytes(try arg(info)), as: UTF8.self))
            case 4:
                let n = try count(try arg(info))
                var a = [Value]()
                for _ in 0..<n { a.append(try value(depth + 1)) }
                return .array(a)
            case 5:
                let n = try count(try arg(info))
                var m = [MapEntry]()
                for _ in 0..<n {
                    let k = try value(depth + 1)
                    m.append(MapEntry(k, try value(depth + 1)))
                }
                return .map(m)
            case 6:
                _ = try arg(info)
                return try value(depth + 1)
            default:
                switch info {
                case 20: return .bool(false)
                case 21: return .bool(true)
                case 22, 23: return .null
                case 25: return .double(half(Int(try arg(25))))
                case 26: return .double(Double(Float(bitPattern: UInt32(try arg(26)))))
                case 27: return .double(Double(bitPattern: try arg(27)))
                default:
                    if info >= 24 { _ = try arg(info) }
                    return .null
                }
            }
        }

        mutating func indefinite(_ major: Int, _ depth: Int) throws -> Value {
            var items = [Value]()
            while true {
                if pos < b.count && b[pos] == 0xff { pos += 1; break }
                items.append(try value(depth + 1))
            }
            switch major {
            case 2:
                var out = Bytes()
                for x in items {
                    guard case .bytes(let c) = x else { throw CborError("cbor: bad chunk") }
                    out += c
                }
                return .bytes(out)
            case 3:
                var out = ""
                for x in items {
                    guard case .text(let c) = x else { throw CborError("cbor: bad chunk") }
                    out += c
                }
                return .text(out)
            case 4: return .array(items)
            default:
                if items.count % 2 != 0 { throw CborError("cbor: odd map") }
                var m = [MapEntry]()
                var i = 0
                while i < items.count { m.append(MapEntry(items[i], items[i + 1])); i += 2 }
                return .map(m)
            }
        }

        func half(_ h: Int) -> Double {
            let exp = (h >> 10) & 0x1f
            let mant = h & 0x3ff
            let v: Double
            switch exp {
            case 0: v = Double(mant) * pow(2.0, -24.0)
            case 31: v = mant == 0 ? Double.infinity : Double.nan
            default: v = Double(mant + 1024) * pow(2.0, Double(exp) - 25.0)
            }
            return h & 0x8000 != 0 ? -v : v
        }
    }
}

// Typed reads of decoded CBOR values: nil when the value has another type.
extension Cbor.Value {
    public var asInt64: Int64? { if case .int(let n) = self { return n }; return nil }
    public var asInt: Int? { if case .int(let n) = self, n >= Int64(Int32.min), n <= Int64(Int32.max) { return Int(n) }; return nil }
    public var asBytes: Bytes? { if case .bytes(let b) = self { return b }; return nil }
    public var asString: String? { if case .text(let s) = self { return s }; return nil }
    public var asList: [Cbor.Value]? { if case .array(let a) = self { return a }; return nil }
    public var asMap: [Cbor.MapEntry]? { if case .map(let m) = self { return m }; return nil }
    public var isNull: Bool { if case .null = self { return true }; return false }
}

extension Array where Element == Cbor.Value {
    /// at is the element at i, or null when there is none.
    public func at(_ i: Int) -> Cbor.Value { i >= 0 && i < count ? self[i] : .null }
}

// Literals: `let v: Cbor.Value = [0, 1, "x", nil]`.
extension Cbor.Value: ExpressibleByIntegerLiteral {
    public init(integerLiteral v: Int64) { self = .int(v) }
}
extension Cbor.Value: ExpressibleByStringLiteral {
    public init(stringLiteral v: String) { self = .text(v) }
}
extension Cbor.Value: ExpressibleByBooleanLiteral {
    public init(booleanLiteral v: Bool) { self = .bool(v) }
}
extension Cbor.Value: ExpressibleByNilLiteral {
    public init(nilLiteral: ()) { self = .null }
}
extension Cbor.Value: ExpressibleByArrayLiteral {
    public init(arrayLiteral e: Cbor.Value...) { self = .array(e) }
}
