import XCTest
import Foundation
@testable import P2PACT

final class CryptoTests: XCTestCase {
    func testBlake2sVectors() {
        XCTAssertEqual(Crypto.blake2s(Bytes("abc".utf8)).hex(), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        XCTAssertEqual(Crypto.blake2s([]).hex(), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        // several blocks, fed in pieces
        let big = Bytes((0..<768).map { UInt8($0 & 0xff) })
        XCTAssertEqual(Crypto.blake2s(big).hex(), "b928a17862e211e99759ba8819280803a914cd3dee7c5d711a3b5185aa96a7b3")
        XCTAssertEqual(Crypto.blake2s(Bytes(big[0..<64]), Bytes(big[64..<65]), Bytes(big[65...])).hex(), Crypto.blake2s(big).hex())
    }

    func testHmacBlake2s() {
        XCTAssertEqual(Crypto.hmac(Bytes("key".utf8), Bytes("The quick brown fox".utf8)).hex(),
                       "8717096fc5e7ac53d11d990acd4380c9ddd7bd8da5d8b5bc29855e6c98a866a4")
        XCTAssertEqual(Crypto.hmac(Bytes((0..<100).map { UInt8($0) }), Bytes(repeating: 120, count: 200)).hex(),
                       "834cd67f8ca0de35dfcdfff1510ae170f5850f5455aba1c085196c441d7ca7d9")
    }

    func testX25519RFC7748() {
        let a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")!
        let b = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")!
        XCTAssertEqual(Crypto.x25519Keypair(a).publicKey.hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        XCTAssertEqual(Crypto.x25519(a, Crypto.x25519Keypair(b).publicKey)?.hex(), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    }

    func testSealOpen() {
        let key = randomBytes(32)
        let ad = Bytes("header".utf8)
        let ct = Crypto.seal(key, 7, ad, Bytes("hello".utf8))
        XCTAssertEqual(ct.count, 5 + 16)
        XCTAssertEqual(Crypto.open(key, 7, ad, ct), Bytes("hello".utf8))
        XCTAssertNil(Crypto.open(key, 8, ad, ct))
        XCTAssertNil(Crypto.open(key, 7, Bytes("other".utf8), ct))
        var bad = ct
        bad[0] ^= 1
        XCTAssertNil(Crypto.open(key, 7, ad, bad))
        XCTAssertEqual(Crypto.open(key, 7, ad, [1, 2, 3] + ct, 3), Bytes("hello".utf8))
    }

    func testEd25519() {
        let k = Crypto.ed25519Keypair(randomBytes(32))
        let sig = Crypto.ed25519Sign(k.privateKey, Bytes("msg".utf8))
        XCTAssertTrue(Crypto.ed25519Verify(k.publicKey, Bytes("msg".utf8), sig))
        XCTAssertFalse(Crypto.ed25519Verify(k.publicKey, Bytes("other".utf8), sig))
    }

    func testAddress() {
        let a = Crypto.address(Crypto.x25519Keypair().publicKey)
        XCTAssertEqual(a.count, 26)
        XCTAssertTrue(a.allSatisfy { ("a"..."z").contains($0) || ("2"..."7").contains($0) })
        // the address of a fixed key never changes
        XCTAssertEqual(Crypto.address(Bytes(repeating: 7, count: 32)), Crypto.address(Bytes(repeating: 7, count: 32)))
    }

    func testNoiseIKAndXXpsk2() throws {
        let i = Crypto.x25519Keypair(), r = Crypto.x25519Keypair()
        let pro = Bytes("p2pact/1".utf8)
        let hi = Handshake(.ik, initiator: true, prologue: pro, s: i, rs: r.publicKey)
        let hr = Handshake(.ik, initiator: false, prologue: pro, s: r)
        let m1 = try hi.writeMessage(Bytes("first".utf8))
        XCTAssertEqual(try hr.readMessage(m1), Bytes("first".utf8))
        XCTAssertEqual(hr.rs, i.publicKey)
        let m2 = try hr.writeMessage(Bytes("second".utf8))
        XCTAssertEqual(try hi.readMessage(m2), Bytes("second".utf8))
        let c = Bytes("transport".utf8)
        XCTAssertEqual(hr.ciphers!.0.decryptAt(0, [], hi.ciphers!.0.encryptAt(0, [], c), 0), c)

        let psk = randomBytes(32)
        let xi = Handshake(.xxpsk2, initiator: true, prologue: pro, s: i, psk: psk)
        let xr = Handshake(.xxpsk2, initiator: false, prologue: pro, s: r, psk: psk)
        _ = try xr.readMessage(try xi.writeMessage())
        _ = try xi.readMessage(try xr.writeMessage(Bytes("a".utf8)))
        XCTAssertEqual(try xr.readMessage(try xi.writeMessage(Bytes("b".utf8))), Bytes("b".utf8))
        XCTAssertEqual(xi.rs, r.publicKey)
        XCTAssertEqual(xr.rs, i.publicKey)
        // a wrong secret fails
        let wi = Handshake(.xxpsk2, initiator: true, prologue: pro, s: i, psk: randomBytes(32))
        let wr = Handshake(.xxpsk2, initiator: false, prologue: pro, s: r, psk: psk)
        _ = try wr.readMessage(try wi.writeMessage())
        let reply = try wr.writeMessage()
        XCTAssertThrowsError(try wi.readMessage(reply))
    }
}

final class CborTests: XCTestCase {
    func enc(_ v: Cbor.Value) -> String { Cbor.encode(v).hex() }

    func testRFC8949Vectors() throws {
        XCTAssertEqual(enc(0), "00")
        XCTAssertEqual(enc(23), "17")
        XCTAssertEqual(enc(24), "1818")
        XCTAssertEqual(enc(1000), "1903e8")
        XCTAssertEqual(enc(1_000_000), "1a000f4240")
        XCTAssertEqual(enc(.int(1_000_000_000_000)), "1b000000e8d4a51000")
        XCTAssertEqual(enc(.int(-1)), "20")
        XCTAssertEqual(enc(.int(-1000)), "3903e7")
        XCTAssertEqual(enc("IETF"), "6449455446")
        XCTAssertEqual(enc(.bytes([1, 2, 3, 4])), "4401020304")
        XCTAssertEqual(enc([1, [2, 3], [4, 5]]), "8301820203820405")
        XCTAssertEqual(enc(nil), "f6")
        XCTAssertEqual(enc(true), "f5")
        XCTAssertEqual(enc(.map([Cbor.MapEntry(1, 2), Cbor.MapEntry(3, 4)])), "a201020304")
        XCTAssertEqual(enc(.double(1.1)), "fb3ff199999999999a")
    }

    func testDecode() throws {
        XCTAssertEqual(try Cbor.decode(unhex("1903e8")!), 1000)
        XCTAssertEqual(try Cbor.decode(unhex("3903e7")!), .int(-1000))
        XCTAssertEqual(try Cbor.decode(unhex("8301820203820405")!), [1, [2, 3], [4, 5]])
        XCTAssertEqual(try Cbor.decode(unhex("f93c00")!), .double(1.0)) // half
        XCTAssertEqual(try Cbor.decode(unhex("fa47c35000")!), .double(100000.0)) // float
        XCTAssertEqual(try Cbor.decode(unhex("5f42010243030405ff")!), .bytes([1, 2, 3, 4, 5])) // indefinite
        XCTAssertEqual(try Cbor.decode(unhex("c11a514b67b0")!), .int(1363896240)) // a tag is skipped
        XCTAssertThrowsError(try Cbor.decode(unhex("0000")!)) // trailing
        XCTAssertThrowsError(try Cbor.decode(unhex("82")!)) // short
        XCTAssertThrowsError(try Cbor.decode(unhex("9bffffffffffffffff")!)) // absurd length
    }

    func testRoundTripMessage() throws {
        let v: Cbor.Value = [0, 5, 64, 1, .bytes(Bytes(repeating: 9, count: 300)), "текст", nil]
        XCTAssertEqual(try Cbor.decode(Cbor.encode(v)), v)
    }
}

final class PacketTests: XCTestCase {
    func testWindow() {
        var w = Window()
        XCTAssertTrue(w.accept(0))
        XCTAssertFalse(w.accept(0))
        XCTAssertTrue(w.accept(5))
        XCTAssertTrue(w.accept(3))
        XCTAssertFalse(w.accept(3))
        XCTAssertTrue(w.accept(5000))
        XCTAssertFalse(w.accept(5)) // too old
        XCTAssertTrue(w.accept(4999))
        XCTAssertFalse(w.accept(4999))
    }

    func testVarints() {
        var b = ByteBuf()
        for v: Int64 in [0, 1, 127, 128, 300, 1 << 20, 1 << 40] { b.uvarint(v) }
        var r = VarReader(b.buf, 0)
        for v: Int64 in [0, 1, 127, 128, 300, 1 << 20, 1 << 40] { XCTAssertEqual(r.uvarint(), v) }
        XCTAssertTrue(r.ok)
        _ = r.uvarint()
        XCTAssertFalse(r.ok)
        XCTAssertEqual(uvarintSize(300), 2)
    }

    func testInvite() throws {
        let k = Crypto.x25519Keypair()
        let inv = Invite(key: k.publicKey, name: "Work laptop", secret: randomBytes(32), exp: wallMillis() + 60_000,
                         hints: Hints(udp: ["127.0.0.1:48730"], tcp: ["127.0.0.1:48731"], relay: RelayHint(addr: "r.example:443", fp: "ab")))
        XCTAssertTrue(inv.string.hasPrefix("p2pact1."))
        let back = try Invite.parse(inv.string)
        XCTAssertEqual(back.key, inv.key)
        XCTAssertEqual(back.secret, inv.secret)
        XCTAssertEqual(back.name, "Work laptop")
        XCTAssertEqual(back.hints, inv.hints)
        XCTAssertEqual(back.id.count, 16)
        let old = Invite(key: k.publicKey, name: "x", secret: randomBytes(32), exp: wallMillis() - 1000, hints: Hints())
        XCTAssertThrowsError(try Invite.parse(old.string))
        XCTAssertThrowsError(try Invite.parse("nope"))
    }

    func testToolNames() {
        XCTAssertTrue(validToolName("com.example.jira"))
        XCTAssertFalse(validToolName("p2pact.chat"))
        XCTAssertFalse(validToolName("single"))
        XCTAssertFalse(validToolName("Com.Example"))
    }

    func testGrants() {
        XCTAssertEqual(grantLevel(nil, "x.y"), 2)
        XCTAssertEqual(grantLevel([], "x.y"), 0)
        XCTAssertEqual(grantLevel([Grant("x.y", 1), Grant("*", 2)], "x.y"), 2)
        XCTAssertEqual(cleanGrants([Grant("a.b", 1), Grant("a.b", 2), Grant("c.d", 0)]), [Grant("a.b", 2)])
        XCTAssertEqual(parseGrants(grantsWire([Grant("a.b", 5)])), [Grant("a.b", 2)])
    }
}

/// Two Deliveries joined by a lossy, reordering "network" in simulated time.
final class DeliveryTests: XCTestCase {
    struct Rng: RandomNumberGenerator {
        var s: UInt64
        mutating func next() -> UInt64 { s = s &* 6364136223846793005 &+ 1442695040888963407; return s >> 11 }
        mutating func pct() -> Int { Int(next() % 100) }
    }

    /// run exchanges packets until both are idle; returns messages received by b as (stream, bytes).
    func run(_ a: Delivery, _ b: Delivery, loss: Int, shuffle: Bool, seed: UInt64 = 1) -> [(Int64, Bytes)] {
        var rng = Rng(s: seed)
        var now: Int64 = 10 * SEC
        var toB: [Bytes] = [], toA: [Bytes] = []
        var got: [(Int64, Bytes)] = []
        for _ in 0..<20000 {
            now += 5 * MS
            while let n = a.nextPacket(now, false) { if rng.pct() >= loss { toB.append(n.plain) } }
            while let n = b.nextPacket(now, false) { if rng.pct() >= loss { toA.append(n.plain) } }
            if shuffle { toB.shuffle(using: &rng); toA.shuffle(using: &rng) }
            for p in toB { _ = b.receive(now, p) { m, _, st in got.append((st, m)) } }
            for p in toA { _ = a.receive(now, p) { _, _, _ in } }
            toB = []; toA = []
            if a.idle() && b.ackDue == 0 && toB.isEmpty && got.count >= 1 && a.inflight.isEmpty { break }
        }
        return got
    }

    func testLongMessageSplitAndOrder() {
        let a = Delivery(), b = Delivery()
        var msgs: [Bytes] = []
        for i in 0..<5 { msgs.append(Bytes((0..<(i == 2 ? 50_000 : 100)).map { UInt8(($0 + i) & 0xff) })) }
        for m in msgs { a.push(m, zip: false, stream: 0) }
        XCTAssertGreaterThan(a.queue.count, 40) // the long one is in parts, each at most MAX_PART
        let got = run(a, b, loss: 0, shuffle: false)
        XCTAssertEqual(got.map { $0.1 }, msgs)
    }

    func testLossAndReorderStillDeliversInOrder() {
        for seed in 1...5 as ClosedRange<UInt64> {
            let a = Delivery(), b = Delivery()
            var msgs: [Bytes] = []
            for i in 0..<30 { msgs.append(Bytes((0..<(i % 7 == 0 ? 8000 : 60)).map { UInt8(($0 * 3 + i) & 0xff) })) }
            for m in msgs { a.push(m, zip: false, stream: 0) }
            let got = run(a, b, loss: 20, shuffle: true, seed: seed)
            XCTAssertEqual(got.count, msgs.count, "seed \(seed)")
            XCTAssertEqual(got.map { $0.1 }, msgs, "seed \(seed)")
        }
    }

    func testStreamsDeliverEachInOrder() {
        let a = Delivery(), b = Delivery()
        var sent: [Int64: [Bytes]] = [:]
        for i in 0..<40 {
            let st = Int64(1 + i % 3)
            let m = Bytes((0..<(i % 5 == 0 ? 3000 : 40)).map { UInt8(($0 + i) & 0xff) })
            sent[st, default: []].append(m)
            a.push(m, zip: i % 2 == 0, stream: st)
        }
        let got = run(a, b, loss: 15, shuffle: true, seed: 9)
        for st in 1...3 as ClosedRange<Int64> {
            XCTAssertEqual(got.filter { $0.0 == st }.map { $0.1 }, sent[st])
        }
    }

    func testRestartRenumbers() {
        let a = Delivery()
        a.push(Bytes("one".utf8), zip: false, stream: 0)
        a.push(Bytes("two".utf8), zip: false, stream: 4)
        a.push(Bytes("reply".utf8), zip: false, stream: 0, reply: true)
        _ = a.nextPacket(SEC, false)
        a.reset()
        XCTAssertEqual(a.queue.count, 2) // the reply is dropped with the restart
        XCTAssertEqual(a.queue.first?.seq, 1)
    }

    func testMalformedContentIsRefused() {
        let b = Delivery()
        XCTAssertFalse(b.receive(SEC, []) { _, _, _ in })
        XCTAssertFalse(b.receive(SEC, [UInt8(F_ACK)]) { _, _, _ in })
        XCTAssertFalse(b.receive(SEC, [UInt8(F_MSG)]) { _, _, _ in })
        XCTAssertTrue(b.receive(SEC, keepalive()) { _, _, _ in })
    }
}
