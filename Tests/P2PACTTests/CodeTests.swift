import CryptoKit
import XCTest
import Foundation
@testable import P2PACT

final class CodeTests: XCTestCase {
    private func invite() throws -> String {
        let n = try Node(dir: NSTemporaryDirectory() + "p2pact-code-\(UUID().uuidString)", name: "laptop")
        return n.invite(ttlMs: 300_000).string
    }

    func testNormalize() {
        XCTAssertEqual(Code.normalize("k7q2-m9px"), "K7Q2M9PX")
        XCTAssertEqual(Code.normalize("oilu 0000"), "011V0000")
        XCTAssertNil(Code.normalize("K7Q2M9P"))
        XCTAssertNil(Code.normalize("K7Q2-M9P!"))
        XCTAssertEqual(Code.format("K7Q2M9PX"), "K7Q2-M9PX")
    }

    /// The vector of p2pact-go (TestCodeSlotVector) and p2pact-kotlin.
    func testSlotVector() throws {
        let (slot, key) = try XCTUnwrap(Code.slot("k7q2-m9px"))
        XCTAssertEqual(slot, "ae1aa553fe39be90efcf1eded8ddf3e6")
        XCTAssertEqual(key.hex(), "01c23c62071cac48fe6a5cdc7fbf99940219a11f632e3e6565addfbe895c60ca")
        // box of "p2pact1.vector" with nonce 00 01 … 0b: decrypts (the invite inside is not a real one)
        let raw = try XCTUnwrap(unb64url("AAECAwQFBgcICQoLKQMqysat2QOxFoZEfLdtACgMmw_hEYgh-uCshFLh"))
        let sealed = try ChaChaPoly.SealedBox(combined: raw)
        let pt = try ChaChaPoly.open(sealed, using: SymmetricKey(data: key), authenticating: unhex(slot)!)
        XCTAssertEqual(String(decoding: pt, as: UTF8.self), "p2pact1.vector")
        // not a real invite: the box does not open as one
        XCTAssertNil(Code.open("k7q2-m9px", box: "AAECAwQFBgcICQoLKQMqysat2QOxFoZEfLdtACgMmw_hEYgh-uCshFLh"))
    }

    func testSealOpenAndTxt() throws {
        let inv = try invite()
        let (slot, box) = try XCTUnwrap(Code.seal("K7Q2-M9PX", invite: inv))
        XCTAssertEqual(slot, Code.slot("k7q2m9px")?.slot)
        XCTAssertEqual(Code.open("k7q2 m9px", box: box), inv)
        XCTAssertNil(Code.open("K7Q2-M9PY", box: box))
        XCTAssertNotEqual(box, Code.seal("K7Q2-M9PX", invite: inv)?.box)
        // a record as p2pact-go's CodeTXT writes it
        var txt = ["v": "1", "t": slot]
        var i = 0
        var rest = Substring(box)
        while !rest.isEmpty { txt["b\(i)"] = String(rest.prefix(200)); rest = rest.dropFirst(200); i += 1 }
        XCTAssertEqual(Code.inviteFromTxt("K7Q2M9PX", txt: txt), inv)
        XCTAssertNil(Code.inviteFromTxt("K7Q2M9PY", txt: txt))
        txt.removeValue(forKey: "b0")
        XCTAssertNil(Code.inviteFromTxt("K7Q2M9PX", txt: txt))
    }

    func testBadCodeThrows() async {
        do {
            _ = try await Code.fetchInvite(code: "nope", relay: RelayHint(addr: "127.0.0.1:1", fp: ""))
            XCTFail("fetched")
        } catch let e as P2pactError {
            XCTAssertEqual(e.code, Errors.badArgs)
        } catch { XCTFail("\(error)") }
    }

    /// Against a relay with code slots (RelayProc: p2pact-go's cmd/p2pact-relay, P2PACT_RELAY=<binary>).
    func testFetchFromRelay() async throws {
        let r = try RelayProc()
        let code = String((0..<8).map { _ in Code.alphabet[Int(randomBytes(1)[0] & 31)] })
        do { _ = try await Code.fetchInvite(code: code, relay: r.hint); XCTFail("found before put") } catch is CodeNotFoundError {}
        let inv = try invite()
        let (slot, box) = try XCTUnwrap(Code.seal(code, invite: inv))
        _ = try Code.slotCall(r.hint, ["relay": 1, "op": "put", "slot": slot, "box": box, "ttl": 60, "tok": randomBytes(16).hex()], timeout: 10)
        let got = try await Code.fetchInvite(code: Code.format(code.lowercased()), relay: r.hint)
        XCTAssertEqual(got.string, try Invite.parse(inv).string)
        // a wrong fingerprint does not connect
        do {
            _ = try await Code.fetch(code: code, relay: RelayHint(addr: r.hint.addr, fp: String(repeating: "0", count: 64)), timeout: 5)
            XCTFail("fetched through a wrong fingerprint")
        } catch is CodeNotFoundError { XCTFail("reached the relay") } catch {}
    }
}
