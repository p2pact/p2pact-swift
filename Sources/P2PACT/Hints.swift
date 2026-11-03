import Foundation

/// RelayHint is a relay: its address and the SHA-256 of its certificate (hex).
public struct RelayHint: Equatable {
    public let addr: String
    public let fp: String
    public init(addr: String, fp: String) { self.addr = addr; self.fp = fp }
}
