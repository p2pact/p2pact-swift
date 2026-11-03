import Foundation
@preconcurrency import P2PACT

/// JSONValue is a JSON tree: what the tools' messages are made of. Every model of the client keeps
/// the JSON it was read from (`raw`), so a field this SDK has no name for is still reachable.
public enum JSONValue: Equatable, Hashable, Codable, CustomStringConvertible {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null } else if let b = try? c.decode(Bool.self) { self = .bool(b) } else if let i = try? c.decode(Int64.self) { self = .int(i) } else if let d = try? c.decode(Double.self) { self = .double(d) } else if let s = try? c.decode(String.self) { self = .string(s) } else if let a = try? c.decode([JSONValue].self) { self = .array(a) } else { self = .object(try c.decode([String: JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .int(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    /// parse reads JSON text.
    public static func parse(_ text: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8))
    }

    public var description: String {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (try? e.encode(self)).flatMap { String(data: $0, encoding: .utf8) } ?? "null"
    }

    // --- reading ---

    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var int64Value: Int64? {
        switch self {
        case .int(let i): return i
        case .double(let d): return d == d.rounded() && abs(d) < 1e15 ? Int64(d) : nil
        default: return nil
        }
    }
    public var intValue: Int? { int64Value.map { Int($0) } }
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
    public var objectValue: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }
    public var isNull: Bool { if case .null = self { return true }; return false }

    /// The member of an object (nil for anything else, or a missing key).
    public subscript(key: String) -> JSONValue? { objectValue?[key] }

    public func str(_ k: String) -> String? { self[k]?.stringValue }
    public func int(_ k: String) -> Int? { self[k]?.intValue }
    public func long(_ k: String) -> Int64? { self[k]?.int64Value }
    public func bool(_ k: String) -> Bool? { self[k]?.boolValue }
    public func obj(_ k: String) -> JSONValue? { self[k]?.objectValue == nil ? nil : self[k] }
    /// The objects of the array at k (others are skipped).
    public func objs(_ k: String) -> [JSONValue] { self[k]?.arrayValue?.filter { $0.objectValue != nil } ?? [] }
    public func strings(_ k: String) -> [String] { self[k]?.arrayValue?.compactMap { $0.stringValue } ?? [] }

    /// The object at `_meta.p2pact` of an ACP object (chat spec §8); an empty object if there is none.
    public var p2pactMeta: JSONValue { self["_meta"]?["p2pact"] ?? .object([:]) }
}

extension JSONValue: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral, ExpressibleByBooleanLiteral,
    ExpressibleByDictionaryLiteral, ExpressibleByArrayLiteral, ExpressibleByNilLiteral, ExpressibleByFloatLiteral {
    public init(stringLiteral v: String) { self = .string(v) }
    public init(integerLiteral v: Int64) { self = .int(v) }
    public init(booleanLiteral v: Bool) { self = .bool(v) }
    public init(floatLiteral v: Double) { self = .double(v) }
    public init(nilLiteral: ()) { self = .null }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { $1 }))
    }
}

// --- CBOR <-> JSON ---

/// jsonFromCbor makes a decoded CBOR value into a JSON tree: byte strings become base64 text, map keys strings.
public func jsonFromCbor(_ v: Cbor.Value) -> JSONValue {
    switch v {
    case .int(let i): return .int(i)
    case .bytes(let b): return .string(Data(b).base64EncodedString())
    case .text(let s): return .string(s)
    case .array(let a): return .array(a.map(jsonFromCbor))
    case .map(let m):
        var o: [String: JSONValue] = [:]
        for e in m {
            let k: String
            switch e.key {
            case .text(let s): k = s
            case .int(let i): k = String(i)
            default: k = "\(e.key)"
            }
            o[k] = jsonFromCbor(e.value)
        }
        return .object(o)
    case .bool(let b): return .bool(b)
    case .double(let d): return .double(d)
    case .null: return .null
    }
}

/// cborFromJSON makes a JSON tree ready for the wire: whole doubles become integers, object keys are sorted.
public func cborFromJSON(_ v: JSONValue) -> Cbor.Value {
    switch v {
    case .null: return .null
    case .bool(let b): return .bool(b)
    case .int(let i): return .int(i)
    case .double(let d):
        if d == d.rounded() && !d.isInfinite && abs(d) < 1e15 { return .int(Int64(d)) }
        return .double(d)
    case .string(let s): return .text(s)
    case .array(let a): return .array(a.map(cborFromJSON))
    case .object(let o): return .map(o.keys.sorted().map { Cbor.MapEntry(.text($0), cborFromJSON(o[$0]!)) })
    }
}

/// streamOf is the stream of a session or resource: the first 8 bytes of BLAKE2s(id) as a number, 0
/// replaced by 1 (chat spec §2); no id — 0.
public func streamOf(_ id: String?) -> Int64 {
    guard let id = id, !id.isEmpty else { return 0 }
    let h = Crypto.blake2s(Bytes(id.utf8))
    var n: UInt64 = 0
    for i in 0..<8 { n = n << 8 | UInt64(h[i]) }
    return n == 0 ? 1 : Int64(bitPattern: n)
}
