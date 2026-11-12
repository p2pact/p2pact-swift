import CommonCrypto
import CryptoKit
import Foundation

/// The relay has no code slots (an older relay): look on the local network only.
public struct CodeUnsupportedError: Error, CustomStringConvertible {
    public var description: String { "relay has no code slots" }
}

/// Nobody shows this code now (wrong, expired or already used).
public struct CodeNotFoundError: Error, CustomStringConvertible {
    public var description: String { "code not found" }
}

/// Short code (spec §2): an invite a person can type. The inviting device seals a fresh invite
/// under an 8-symbol code and puts it on its relay (code slots, spec §3) and in its `_p2pact._udp`
/// record (spec §7); given the code, `fetchInvite` gets it from a relay and `inviteFromTxt` from a
/// discovery record (browsing is the platform's: NWBrowser on Apple systems). The code is
/// low-entropy: it only finds the invite; the inviting device asks its person before granting
/// anything. Publishing a code is not here: a joiner only looks one up.
public enum Code {
    public static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    public static let length = 8

    /// service is the DNS-SD service type of local discovery (spec §7).
    public static let service = "_p2pact._udp"

    private static let salt = Bytes("p2pact-code".utf8)
    private static let rounds: UInt32 = 100_000

    /// normalize returns a typed code in canonical form (upper case, no dashes, O→0, I/L→1, U→V); nil — not a code.
    public static func normalize(_ s: String) -> String? {
        var out = [Character]()
        for ch in s.uppercased() {
            let r: Character
            switch ch {
            case " ", "-", "\t", "\n", "·": continue
            case "O": r = "0"
            case "I", "L": r = "1"
            case "U": r = "V"
            default: r = ch
            }
            if !alphabet.contains(r) { return nil }
            out.append(r)
        }
        return out.count == length ? String(out) : nil
    }

    /// format shows a code to a person: "K7Q2-M9PX".
    public static func format(_ code: String) -> String {
        code.count == length ? code.prefix(4) + "-" + code.dropFirst(4) : code
    }

    /// slot returns the slot of a code (32 hex) and its sealing key; nil — not a code.
    public static func slot(_ code: String) -> (slot: String, key: Bytes)? {
        guard let c = normalize(code) else { return nil }
        var k = Bytes(repeating: 0, count: 48)
        let pw = Bytes(c.utf8)
        let st = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw.map { Int8(bitPattern: $0) }, pw.count,
                                      salt, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds, &k, k.count)
        if st != Int32(kCCSuccess) { return nil }
        return (Bytes(k[0..<16]).hex(), Bytes(k[16..<48]))
    }

    /// openBox opens a box (base64url of nonce || ciphertext || tag) with the code's slot and key;
    /// nil — it does not open, or the invite inside is corrupt or expired.
    static func openBox(slot: String, key: Bytes, box: String) -> String? {
        guard let raw = unb64url(box.trimmingCharacters(in: CharacterSet(charactersIn: "="))), raw.count >= 12 + 16,
              let ad = unhex(slot),
              let nonce = try? ChaChaPoly.Nonce(data: raw[0..<12]),
              let sealed = try? ChaChaPoly.SealedBox(nonce: nonce, ciphertext: raw[12..<(raw.count - 16)], tag: raw[(raw.count - 16)...]),
              let pt = try? ChaChaPoly.open(sealed, using: SymmetricKey(data: key), authenticating: ad),
              let s = String(data: pt, encoding: .utf8), (try? Invite.parse(s)) != nil else { return nil }
        return s
    }

    /// seal returns the slot and box of an invite string under a code (what the inviting device publishes).
    static func seal(_ code: String, invite: String) -> (slot: String, box: String)? {
        guard let (slot, key) = slot(code), let ad = unhex(slot),
              let sealed = try? ChaChaPoly.seal(Data(invite.utf8), using: SymmetricKey(data: key), authenticating: ad) else { return nil }
        return (slot, b64url(Bytes(sealed.nonce) + Bytes(sealed.ciphertext) + Bytes(sealed.tag)))
    }

    /// open opens a box with the code; nil — it does not open, or the invite is corrupt or expired.
    public static func open(_ code: String, box: String) -> String? {
        guard let (slot, key) = slot(code) else { return nil }
        return openBox(slot: slot, key: key, box: box)
    }

    /// inviteFromTxt returns the invite string of a `_p2pact._udp` record (TXT as key → value) that shows `code`; nil — it does not.
    public static func inviteFromTxt(_ code: String, txt: [String: String]) -> String? {
        guard let (slot, key) = slot(code), txt["t"] == slot else { return nil }
        let pieces = txt.keys.compactMap { k -> Int? in
            guard k.hasPrefix("b"), let n = Int(k.dropFirst()), n >= 0 else { return nil }
            return n
        }.sorted()
        var box = ""
        for (i, n) in pieces.enumerated() {
            if n != i { return nil } // a piece is missing
            box += txt["b\(n)"] ?? ""
        }
        return openBox(slot: slot, key: key, box: box)
    }

    /// fetch gets the invite string shown under `code` from a relay (spec §3, code slots).
    /// Throws `CodeNotFoundError` — nobody shows it; `CodeUnsupportedError` — an older relay;
    /// `P2pactError` (badArgs) — not a code; `P2pactError` (failed) — the relay is unreachable or answers badly.
    public static func fetch(code: String, relay: RelayHint, timeout: TimeInterval = 15) async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                cont.resume(with: Result { try fetchBlocking(code: code, relay: relay, timeout: timeout) })
            }
        }
    }

    /// fetchInvite is `fetch` parsed into an `Invite`.
    public static func fetchInvite(code: String, relay: RelayHint, timeout: TimeInterval = 15) async throws -> Invite {
        try Invite.parse(try await fetch(code: code, relay: relay, timeout: timeout))
    }

    static func fetchBlocking(code: String, relay: RelayHint, timeout: TimeInterval) throws -> String {
        guard let (slot, key) = slot(code) else { throw P2pactError(Errors.badArgs, "not a code") }
        let ans = try slotCall(relay, ["relay": 1, "op": "get", "slot": slot], timeout: timeout)
        guard let box = ans["box"] as? String else { throw P2pactError(Errors.failed, "relay: no box") }
        guard let inv = openBox(slot: slot, key: key, box: box) else { throw P2pactError(Errors.failed, "code box does not open") }
        return inv
    }

    /// slotCall sends one request line to a relay over TLS (pinned by fingerprint when the hint has one) and reads the answer.
    static func slotCall(_ relay: RelayHint, _ req: [String: Any], timeout: TimeInterval) throws -> [String: Any] {
        guard let (host, port) = hostPort(relay.addr), let s = TLSStream(host: host, port: port, fp: relay.fp) else {
            throw P2pactError(Errors.badArgs, "bad relay address")
        }
        defer { s.cancel() }
        if !s.connect(timeout: timeout) { throw P2pactError(Errors.failed, "relay unreachable") }
        let data = try JSONSerialization.data(withJSONObject: req)
        if !s.send(Bytes(data) + [10], timeout: timeout) { throw P2pactError(Errors.failed, "relay: write failed") }
        guard let line = LineReader(s).readLine(timeout: timeout) else { throw P2pactError(Errors.failed, "relay closed") }
        guard let m = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any] else {
            throw P2pactError(Errors.failed, "relay: bad answer")
        }
        switch m["error"] as? String {
        case nil: return m
        case "not found": throw CodeNotFoundError()
        case "bad hello": throw CodeUnsupportedError()
        case let e?: throw P2pactError(Errors.failed, "relay: \(e)")
        }
    }
}
