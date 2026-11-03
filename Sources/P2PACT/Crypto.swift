import CryptoKit
import Foundation

// Primitives: X25519, Ed25519 and ChaCha20-Poly1305 from CryptoKit; BLAKE2s (RFC 7693) here, since
// CryptoKit has none. No home-made cryptography beyond that one hash (spec §1).

public struct KeyPair {
    public let privateKey: Bytes
    public let publicKey: Bytes
    public init(privateKey: Bytes, publicKey: Bytes) { self.privateKey = privateKey; self.publicKey = publicKey }
}

/// Blake2s is BLAKE2s-256 without a key (RFC 7693).
struct Blake2s {
    private static let iv: [UInt32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ]
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
    ]

    private var h: [UInt32]
    private var t: UInt64 = 0
    private var buf = Bytes()

    init() {
        h = Blake2s.iv
        h[0] ^= 0x0101_0000 ^ 32 // digest length 32, no key, fanout 1, depth 1
    }

    mutating func update(_ data: Bytes) {
        buf.append(contentsOf: data)
        // keep the last block (it may be the final one) unprocessed
        while buf.count > 64 {
            t += 64
            compress(Array(buf[0..<64]), last: false)
            buf.removeFirst(64)
        }
    }

    mutating func finish() -> Bytes {
        t += UInt64(buf.count)
        var block = buf
        block.append(contentsOf: Bytes(repeating: 0, count: 64 - block.count))
        compress(block, last: true)
        var out = Bytes()
        for w in h { for i in 0..<4 { out.append(UInt8(truncatingIfNeeded: w >> UInt32(8 * i))) } }
        return out
    }

    private mutating func compress(_ block: Bytes, last: Bool) {
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            m[i] = UInt32(block[4 * i]) | UInt32(block[4 * i + 1]) << 8 | UInt32(block[4 * i + 2]) << 16 | UInt32(block[4 * i + 3]) << 24
        }
        var v = [UInt32](repeating: 0, count: 16)
        for i in 0..<8 { v[i] = h[i]; v[i + 8] = Blake2s.iv[i] }
        v[12] ^= UInt32(truncatingIfNeeded: t)
        v[13] ^= UInt32(truncatingIfNeeded: t >> 32)
        if last { v[14] = ~v[14] }
        @inline(__always) func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }
        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = rotr(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 12)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = rotr(v[d] ^ v[a], 8)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 7)
        }
        for r in 0..<10 {
            let s = Blake2s.sigma[r]
            g(0, 4, 8, 12, m[s[0]], m[s[1]])
            g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]])
            g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]])
            g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]])
            g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }
}

public enum Crypto {
    /// x25519Keypair creates a key pair, or derives the public key of a given private key.
    public static func x25519Keypair(_ priv: Bytes? = nil) -> KeyPair {
        let k: Curve25519.KeyAgreement.PrivateKey
        if let p = priv, let kk = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: p) {
            k = kk
        } else {
            k = Curve25519.KeyAgreement.PrivateKey()
        }
        return KeyPair(privateKey: Bytes(k.rawRepresentation), publicKey: Bytes(k.publicKey.rawRepresentation))
    }

    /// x25519 is the Diffie-Hellman shared secret; nil for an invalid or low-order public key.
    public static func x25519(_ priv: Bytes, _ pub: Bytes) -> Bytes? {
        guard let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv),
              let p = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub),
              let s = try? k.sharedSecretFromKeyAgreement(with: p) else { return nil }
        return s.withUnsafeBytes { Bytes($0) }
    }

    /// ed25519Keypair derives a signing key pair from a 32-byte seed.
    public static func ed25519Keypair(_ seed: Bytes) -> KeyPair {
        let k = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return KeyPair(privateKey: seed, publicKey: Bytes(k.publicKey.rawRepresentation))
    }

    public static func ed25519Sign(_ seed: Bytes, _ msg: Bytes) -> Bytes {
        let k = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return Bytes(try! k.signature(for: msg))
    }

    public static func ed25519Verify(_ pub: Bytes, _ msg: Bytes, _ sig: Bytes) -> Bool {
        guard sig.count == 64, pub.count == 32, let k = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
        return k.isValidSignature(sig, for: msg)
    }

    public static func blake2s(_ parts: Bytes...) -> Bytes { blake2sList(parts) }

    static func blake2sList(_ parts: [Bytes]) -> Bytes {
        var h = Blake2s()
        for p in parts { h.update(p) }
        return h.finish()
    }

    /// hmac is HMAC-BLAKE2s (RFC 2104, block size 64).
    public static func hmac(_ key: Bytes, _ parts: Bytes...) -> Bytes { hmacList(key, parts) }

    static func hmacList(_ key: Bytes, _ parts: [Bytes]) -> Bytes {
        var k = key.count > 64 ? blake2s(key) : key
        k.append(contentsOf: Bytes(repeating: 0, count: 64 - k.count))
        let inner = blake2sList([k.map { $0 ^ 0x36 }] + parts)
        return blake2sList([k.map { $0 ^ 0x5c }, inner])
    }

    /// mac is HMAC-BLAKE2s(key, label): relay channels and invite ids come from secrets.
    public static func mac(_ key: Bytes, _ label: String) -> Bytes { hmac(key, Bytes(label.utf8)) }

    private static func nonce(_ n: Int64) -> ChaChaPoly.Nonce {
        var b = Bytes(repeating: 0, count: 12)
        for i in 0..<8 { b[4 + i] = UInt8(truncatingIfNeeded: n >> Int64(8 * i)) }
        return try! ChaChaPoly.Nonce(data: b)
    }

    /// seal is ChaCha20-Poly1305 with the Noise nonce layout (4 zero bytes, 64-bit LE counter).
    public static func seal(_ key: Bytes, _ n: Int64, _ ad: Bytes, _ pt: Bytes) -> Bytes {
        let box = try! ChaChaPoly.seal(pt, using: SymmetricKey(data: key), nonce: nonce(n), authenticating: ad)
        return Bytes(box.ciphertext) + Bytes(box.tag)
    }

    /// open reverses seal; nil if the tag does not match. The ciphertext is ct[off...].
    public static func open(_ key: Bytes, _ n: Int64, _ ad: Bytes, _ ct: Bytes, _ off: Int = 0) -> Bytes? {
        if ct.count - off < 16 { return nil }
        let end = ct.count - 16
        guard let box = try? ChaChaPoly.SealedBox(nonce: nonce(n), ciphertext: ct[off..<end], tag: ct[end...]),
              let pt = try? ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: ad) else { return nil }
        return Bytes(pt)
    }

    private static let b32 = Array("abcdefghijklmnopqrstuvwxyz234567")

    /// address of a device: the first 16 bytes of BLAKE2s of its public key, lowercase base32 (spec §1).
    public static func address(_ pub: Bytes) -> String {
        let h = Bytes(blake2s(pub)[0..<16])
        var out = ""
        var bits = 0
        var v = 0
        for b in h {
            v = (v << 8) | Int(b)
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
}
