import Foundation

// The Noise Protocol Framework, just what P2PACT uses: Noise_IK and Noise_XXpsk2 with 25519,
// ChaChaPoly and BLAKE2s (spec §2, §4.2).

struct NoiseError: Error { let msg: String; init(_ m: String) { msg = m } }

final class CipherState {
    let k: Bytes?
    var n: Int64 = 0
    init(_ k: Bytes? = nil) { self.k = k }

    func encrypt(_ ad: Bytes, _ pt: Bytes) -> Bytes {
        guard let key = k else { return pt }
        defer { n += 1 }
        return Crypto.seal(key, n, ad, pt)
    }

    func decrypt(_ ad: Bytes, _ ct: Bytes) throws -> Bytes {
        guard let key = k else { return ct }
        guard let pt = Crypto.open(key, n, ad, ct) else { throw NoiseError("noise: decryption failed") }
        n += 1
        return pt
    }

    /// encryptAt and decryptAt take an explicit nonce: transport packets carry their number.
    func encryptAt(_ n: Int64, _ ad: Bytes, _ pt: Bytes) -> Bytes { Crypto.seal(k!, n, ad, pt) }
    func decryptAt(_ n: Int64, _ ad: Bytes, _ ct: Bytes, _ off: Int) -> Bytes? { Crypto.open(k!, n, ad, ct, off) }
}

private func hkdf(_ ck: Bytes, _ ikm: Bytes, _ n: Int) -> [Bytes] {
    let t = Crypto.hmac(ck, ikm)
    let o1 = Crypto.hmac(t, [1])
    let o2 = Crypto.hmac(t, o1, [2])
    if n == 2 { return [o1, o2] }
    return [o1, o2, Crypto.hmac(t, o2, [3])]
}

private final class SymmetricState {
    var h: Bytes
    var ck: Bytes
    var cs = CipherState()

    init(_ name: String) {
        let b = Bytes(name.utf8)
        h = b.count <= 32 ? b + Bytes(repeating: 0, count: 32 - b.count) : Crypto.blake2s(b)
        ck = h
    }

    func mixKey(_ ikm: Bytes) {
        let o = hkdf(ck, ikm, 2)
        ck = o[0]
        cs = CipherState(o[1])
    }

    func mixHash(_ data: Bytes) { h = Crypto.blake2s(h, data) }

    func mixKeyAndHash(_ ikm: Bytes) {
        let o = hkdf(ck, ikm, 3)
        ck = o[0]
        mixHash(o[1])
        cs = CipherState(o[2])
    }

    func encryptAndHash(_ pt: Bytes) -> Bytes {
        let c = cs.encrypt(h, pt)
        mixHash(c)
        return c
    }

    func decryptAndHash(_ ct: Bytes) throws -> Bytes {
        let p = try cs.decrypt(h, ct)
        mixHash(ct)
        return p
    }

    func split() -> (CipherState, CipherState) {
        let o = hkdf(ck, [], 2)
        return (CipherState(o[0]), CipherState(o[1]))
    }
}

enum Pattern {
    case ik, xxpsk2

    var noiseName: String { self == .ik ? "IK" : "XXpsk2" }
    var preResponderStatic: Bool { self == .ik }
    var msgs: [[String]] {
        switch self {
        case .ik: return [["e", "es", "s", "ss"], ["e", "ee", "se"]]
        case .xxpsk2: return [["e"], ["e", "ee", "s", "es", "psk"], ["s", "se"]]
        }
    }
}

/// Handshake runs one Noise handshake. After the last message, `ciphers` holds (c1, c2).
final class Handshake {
    private let pattern: Pattern
    private let initiator: Bool
    private let s: KeyPair
    private let psk: Bytes?
    private let ss: SymmetricState
    private var e: KeyPair?
    private(set) var re: Bytes?
    private(set) var rs: Bytes?
    private var i = 0
    private(set) var ciphers: (CipherState, CipherState)?

    init(_ pattern: Pattern, initiator: Bool, prologue: Bytes, s: KeyPair, rs: Bytes? = nil, psk: Bytes? = nil) {
        self.pattern = pattern
        self.initiator = initiator
        self.s = s
        self.rs = rs
        self.psk = psk
        ss = SymmetricState("Noise_\(pattern.noiseName)_25519_ChaChaPoly_BLAKE2s")
        ss.mixHash(prologue)
        if pattern.preResponderStatic { ss.mixHash(initiator ? rs! : s.publicKey) }
    }

    private var usesPsk: Bool { psk != nil }

    private func dh(_ a: KeyPair, _ b: Bytes) throws {
        guard let z = Crypto.x25519(a.privateKey, b) else { throw NoiseError("noise: bad key") }
        ss.mixKey(z)
    }

    func writeMessage(_ payload: Bytes = []) throws -> Bytes {
        var out = Bytes()
        for t in pattern.msgs[i] {
            switch t {
            case "e":
                let k = Crypto.x25519Keypair()
                e = k
                out += k.publicKey
                ss.mixHash(k.publicKey)
                if usesPsk { ss.mixKey(k.publicKey) }
            case "s": out += ss.encryptAndHash(s.publicKey)
            default: try token(t)
            }
        }
        out += ss.encryptAndHash(payload)
        finish()
        return out
    }

    func readMessage(_ msg: Bytes) throws -> Bytes {
        var pos = 0
        for t in pattern.msgs[i] {
            switch t {
            case "e":
                if msg.count < pos + 32 { throw NoiseError("noise: short message") }
                let r = Bytes(msg[pos..<pos + 32])
                pos += 32
                re = r
                ss.mixHash(r)
                if usesPsk { ss.mixKey(r) }
            case "s":
                let n = 32 + (ss.cs.k != nil ? 16 : 0)
                if msg.count < pos + n { throw NoiseError("noise: short message") }
                rs = try ss.decryptAndHash(Bytes(msg[pos..<pos + n]))
                pos += n
            default: try token(t)
            }
        }
        let payload = try ss.decryptAndHash(Bytes(msg[pos...]))
        finish()
        return payload
    }

    private func token(_ t: String) throws {
        switch t {
        case "ee": try dh(e!, re!)
        case "es": if initiator { try dh(e!, rs!) } else { try dh(s, re!) }
        case "se": if initiator { try dh(s, re!) } else { try dh(e!, rs!) }
        case "ss": try dh(s, rs!)
        case "psk": ss.mixKeyAndHash(psk!)
        default: break
        }
    }

    private func finish() {
        i += 1
        if i == pattern.msgs.count { ciphers = ss.split() }
    }
}
