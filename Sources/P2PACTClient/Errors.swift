import Foundation
@preconcurrency import P2PACT

/// A P2PACT error (core spec §6): the call never reached the tool. The cases name the ones an
/// application handles; `code` is the number of spec §6.
public enum P2pactCallError: Error, CustomStringConvertible, Equatable {
    /// Error 1: the device has no such tool or method.
    case noMethod(String)
    /// Error 2: the arguments are wrong.
    case badArgs(String)
    /// Error 3: no such thing.
    case notFound(String)
    /// Error 4: the grants of the device do not allow the call (spec §8.1).
    case forbidden(String)
    /// Error 5: the call failed on the device (or timed out here).
    case failed(String)
    /// Error 6: not delivered, e.g. a hosted tool whose plugin is gone (spec §8.2).
    case notDelivered(String)
    case other(code: Int, message: String)

    public var code: Int {
        switch self {
        case .noMethod: return Errors.noMethod
        case .badArgs: return Errors.badArgs
        case .notFound: return Errors.notFound
        case .forbidden: return Errors.forbidden
        case .failed: return Errors.failed
        case .notDelivered: return Errors.notDelivered
        case .other(let c, _): return c
        }
    }

    public var message: String {
        switch self {
        case .noMethod(let m), .badArgs(let m), .notFound(let m), .forbidden(let m), .failed(let m), .notDelivered(let m): return m
        case .other(_, let m): return m
        }
    }

    public var description: String { "p2pact error \(code): \(message)" }

    public init(code: Int, message: String) {
        switch code {
        case Errors.noMethod: self = .noMethod(message)
        case Errors.badArgs: self = .badArgs(message)
        case Errors.notFound: self = .notFound(message)
        case Errors.forbidden: self = .forbidden(message)
        case Errors.failed: self = .failed(message)
        case Errors.notDelivered: self = .notDelivered(message)
        default: self = .other(code: code, message: message)
        }
    }

    public var isForbidden: Bool { if case .forbidden = self { return true }; return false }
}

/// A JSON-RPC error of the tool itself (the call was delivered): `code` is JSON-RPC's (`-32601` no
/// such method, `-32602` params, `-32004` no such resource, `-32000` failed), `data` the optional extra.
public struct RpcError: Error, CustomStringConvertible, Equatable {
    public static let methodNotFound = -32601
    public static let invalidParams = -32602
    public static let noSuchResource = -32004
    public static let failed = -32000

    public let code: Int
    public let message: String
    public let data: JSONValue?

    public init(code: Int, message: String, data: JSONValue? = nil) {
        self.code = code; self.message = message; self.data = data
    }

    public var isMethodNotFound: Bool { code == RpcError.methodNotFound }
    public var isNoSuchResource: Bool { code == RpcError.noSuchResource }
    public var description: String { "rpc error \(code): \(message)" }
}

/// typed turns the core's P2pactError into the error of its code; others stay as they are.
func typed(_ e: Error) -> Error {
    if let p = e as? P2pactError { return P2pactCallError(code: p.code, message: p.text) }
    return e
}

// --- Future <-> async ---

extension Future {
    /// value waits for the future without blocking a thread; its failure is typed ([P2pactCallError]).
    func value() async throws -> T {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<T, Error>) in
            whenComplete { r in
                switch r {
                case .success(let v): c.resume(returning: v)
                case .failure(let e): c.resume(throwing: typed(e))
                }
            }
        }
    }
}
