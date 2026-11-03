import XCTest
import Foundation
@testable import P2PACT

final class CompressTests: XCTestCase {
    func msg(_ n: Int) -> Bytes {
        var b = Bytes()
        var i = 0
        while b.count < n {
            b.append(contentsOf: Bytes("{\"id\":\(i),\"name\":\"user-\(i * i % 97)\",\"text\":\"the quick brown fox jumps over the lazy dog\"},".utf8))
            i += 1
        }
        return Bytes(b[0..<n])
    }

    func tmpDir() -> String {
        let p = NSTemporaryDirectory() + "p2pact-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: p, withIntermediateDirectories: true)
        return p
    }

    func common() throws -> Dict { try Dict(CommonDict.raw) }

    // Go reference output: compress(msg(n), common or nil, slot 1 or 0)
    let goVectors: [(String, Int, String)] = [
        ("plain", 300, "0040002c003d030004057b226964223a302c226e616d65223a22757365722d30222c2274657874223a2274686520717569636b2062726f776e20666f78206a756d7073206f766572206c617a7920646f67227d2c31313234333908000153807c031203b20ca48b42b228e07c61a93d"),
        ("dict", 300, "0140002c000d030024047b226964223a302c226e616d65223a22757365722d30222c2274657874223a2269636b20627278206a756d7073746865206c617a7920646f67227d2c3131323433390a000153807c031203b20c4807928d02ae432c1bdb4963a320fb1dd813"),
        ("plain", 5000, "006088121d0b00820b2420506bda00d80c837543990920136426869a9999109d94f253d2a501c551550d300777d1763a7fffebf3783b773be8cddcfc94879954f7f2b613a23e5332e6a6b75eab6ee3f11071be3791f9302ff526e5dce3f7b453f1ee3cd8c052188686c4814994c2320e04c652601e4bc034165602600c02164b8251048a21a63c9462c71022518ec510538c44c30e424cb1308772a841710f5bfa05a04e08337403124010401078162923f8ff1302760fc7c14f69b883cccac69cb691061d5231bd51a5bab1a4b511c454aed19d46b53362514ece5739bfde09ea50e33b0a24c517214b5604992a24afc61cc98c1e12a7d89188a0bd1d7dda19bdd2a969549a234d2de7895a7114be89445202d641ba747275e81919a8fc4849247ece179121878ada272456500224a1fb71d951e191351c292ac13b52fa372e9c12674419df1713cda2cb3c54406ec2c21f5291a1958c3831a97833f808771a228870519efa2f00bf0f"),
        ("dict", 5000, "01608812e50900d20e2a20506b6300d8ec08518b482d1005223b6e22002836258917971e36e6074500aa0268589870f597c7ff77ab6dfde95e6be6265eef3d9f969db9eed221ae51d555e91b5d78af9ecdecbb59b59c968cab9a9e877edd9d71cd2fb34a96726dfd26a27f96ce3257e91eea5ea2f176ac5b9f55210f8860491c860604822361d1189cc73270180b4b23e01c08281a85a314302841cc4361108212404371342841ca02c140484a5042811c027ea86178bd8f7e01907303b301125010501090b608c1ff0ac1fe0151a2d1ab86c64c0d8d94ba1dd24f0ba2b1544123a002e58e814e8375fccc620b0c968e360d22045a8528233bce69f98aa5bd73d7b79e1ddf7c5a297c2c4a49c41beeb2a588917ad32003c2de51100d37fe4a93ba3991504619e3ff7f71b46891f3f595c6577dd218dbbb35a2591211c09f26c369f703"),
        ("plain", 40000, "0060409b2d3d0032ec5b1d4053080040a9414d2728ed44f56666acc8a79452e7fd03effcdcdd5d9d0d020ec9e354dbb66ddbb66ddbb66ddbb66ddbb66ddbb6d5b66ddbb66ddbb66ddbb66ddbb66dfbffffffffffffffffffffd7ffffffffffffffffffff5f2449922449922449922449922449b22c9224499224499224499224499224c942928517562a54b5524b3b6943db5e879636b3e9a8ebb66ddbb6d5b8711cc7711cb76ddbb66ddbc66d6565979595955d56b6b2b2562a54c75455554a289d54937a625a2aa950420899838e4145abd125aaa182eaa483ce39e6f4d4e7f0ec9453c91499638ca939b1664c31d709a142c72473f5a6b17c6de939f549e90d6d3eef982b75f26b784a1bb17c8a2915837a366bfb296e46aeb0a0fa640a9db329d1687c4bd593aae87c0ccd59eb727b6c240791020746860083038230e1888054441c120f0d140a8e8b8881c3c1221231e0582048a08070401026928064e20232913c9202100191a048021248838043f22801494142a21183dba802947dff3f00e20b4e1084e4283e1210107818c8e908fe7ffd0014e6a70ef3df8ef9ea637edb2fff25964f6a954fc2953fdaca3779e59354f95dc6f24ff8f24562be4b63feeb309f15cc67f9e5a77ff92d7df9a4603ec9b9fcd7bf7c152fdfc4985f4630ff0598ef32e6ab14f35f1ff359c17c9630bffd989f52cc6735e6b374f9adbb7c565f3e46c7fc76637e49c37c1284f92e8cf9ab62be5bea5b36238e61f515f31146fa834d7583099489c512d6c01c680f94c3f29ff615d1dc54b40e737c6b36e693f498ff26cc5f03f35771f9efbffc742f5f51989f3acc6f37e6a317f3dbc7fc96613e2b98cfd2989f3ae693fe984f9230bf1dcc2fe92f1fc5cb77e9cb3f15e6b3c27c16c6fcb431bfc5319f15e6b300f35b1df351c67c96637e99c1fc175cbecb97afd2cbffdc31dfb5cb77c9e5b77bf9ade7600bcc5717e6a773f96db4fc9059f9c553f9612a5fe92b3fb495ffcd2d9f3c975f0ee6b71cf355c47c97c6fc575d3eabcb67e1cb0f1bf34bf4cb67e1f25d72f9a78ef9a08ff92e8ff96f60fe0b98cf62cc4731e6bf32e6bbc07c16607edb317f8597eff2e5b3e0f23b05cc6735e68350cc3f8f31bf2598cf02f3b1a5ee5333622bab7f30df35d203da54333181c25bac0b1a184eed01e92cff6d5f95cd4d45eb20c7b666633e498ff96fc2fc35307f1597fffecb4ff7f21585f9a9c3fc76633e7a31bf7dcc6f19e6b382f92c8df9a9633ee98ff92409f3dbc1fc92fef251bc7c97befc53613e2bcc6761cc4f1bf35b1cf359613e0b30bfd5311f65cc6739e69719cc7fc1e5bb7cf92abdfccf1df35dbb7c975c7ebb2f3f64cc7731e6bb984edaf2a5fcf52027ff3d960f4255fef9953fc6953fa2f2cb59f95991e52bf5f2438df9e9613e7b317f5d98dfe2e5a3fef25172f9a7c57c1075f92ebffc355ffe08984f42315f8530ff55cc5735e6ab0cf3dbc5fc94613eeb988fd2989f1acc677df92877f9ed5e7e468ff9a8603e49c7fc5018e6bb88f92ac6fcb5d4476e461cc3ea0b6ba40fb4a936358182f9088bb5a381f1cb27ed817f9666fbb6666e97761dd32be5dc981fda61fe9b315f5dcc7ff7e5bfecf259b97c92637eea319fd598cf12cc6f87f92d8ff9a8623e4b637e6b984ffa309f24c7fc7431bfa4bf7c162edf25977fea988f1af35918f3dbc2fc16613eeb988f42cc6f75cc6709f359c2fcf6c2d57eda97cfe297dfeef2bb18cc7ff1e5af7bf96fa90fa7f3c9c0fc675d3bcc7f96a1c5fc57d5985b7e9c35798913aab3dc9a87046b51a6404aade5dd6836195b2300f93009ff6a25eae9d9f1c9e01a6be5eca3f7e28ba2f8627d64e23fe52b8ba5d860141d3ef5d2c3f087445e52297ced26fc3624f1c11fbb4f11fc50021fad2a077c3682c4df93cd62fd9e4c0cbdefc1e7fba5010f7b7fb1b757de23cc63c2fb8b357b0683c1de3d8ab108ec7e13adfbcf48f75ccb69e75e55d021f75efa785edc53cd882e2c79ab6fdede33d2c6ed5d9b2a6def9a4087ed1d8b65d4de3730b2993d40a67d0bed617303679f5b0746f198d692db6fbca76cc65cb04ce31c365962e1fc5f6ffde1f17aabe77e881a315daf7ae970fdda9bc4d6bf1cc9b53e4d739af555ed23ac4f738e5d7d8b69b4d5a7f745abbe7b52bdf760ea530a2a528fce4d525866a585962cd318d92d4b30327adb521a0fb3d9b28502d8b4c4f6f5b36899adc3aff4feb6f94a7a15cbffc152d695769d25bb8ab4ea4a76d367f595ac22cdea2bd93d959557b26a20abaf64b72c8a8f9e34cc92d112d8e76f249c8acab9e3c613a56e8a27ff1d8d0a25e70a14d591f88641f590e35640f2cdf863a93d1e0bd31bc81e33d369431518b6d79f0948e8d5706579850011d9355ea242b627bb3b248aa8bd43aaa6e7ac90b152daa2ab58070dd479db6e9094a12ddf160b0da8e8077da75fe91379d1d7f1897d984ffb261fd8e7f092feb06747df3fce369d2b934371f675df3ac29cf205be3184dd3672fe4de3e5bf6d94dc9bc6c67fcd3114411afd3cdf98099946ba03dc2191b094d358bc4c23f80b50eea7da693ffa92df35e4dc4db4c1767482a43b19cd017585f46b11d8fe02a7f9a0f1a47d60f3e7f9c2f9ea3cd95c65bdc0dcfabc49c76bc2bf4c57f49849d2027903d220db76826efb3392f9b8eae8c7d3707749259ff183c149979141c6db5c3c755bcc4726f3cc7e326f32937c91ccfdf1fc9ac7b048f3461a93c489fe9a7f"),
        ("dict", 40000, "0160409b153d0092eb581a50b704000022c44c5555e5ffff2f909fd24fbe7b675effff67131105120102546ddbb66ddbb66ddbb66ddbb66ddbb66ddb56dbb66ddbb66ddbb66ddbb66ddbb6edffffffffffffffffffff5fffffffffffffffffffff7f9124499224499224499224499224c9b24892244992244992244992244992240949124e58a74cd548ed8cce66b6bdceec6ce5d24dd76ddbb66dab71e3388ee3386edbb66ddbb68ddbc8c8262323239b8c6c6464ad53a6a85455d539e6d06939fdf0ec9053e618630a192aa666b5b93435434cd1214344854a35116944a84ea929544a69f9b0560a29d7c79832544eb97acf58be9694a8a673decc657a54aed3c96fe1e76c433215cf21c5942e6b3b152f2347484cfd2965882ea5d98c6fa74aa76a682a2cb4d6e526f011b0308100c0d1510071411191e100b031a10020a131616100f070d090510190c08011401080b1918011201040062c122e3202080212220a2402040841004243804783dca8f2937b1ffd02c20b0e1086e4283d01121010101090819c8ee0ffd70f14e6a310f3d388f928c47cd52fffcb962f02567e182a1fc4ca3749e53fa1f23168cb2ffff24d8cf9aac5fc29315fe531ffedcb57f9e5a370f947c77c13c5e5b771f928be7c9331ff8963be8a627e9a98afc298ef22e64f89f92a82f96b623e0b60be0bcc9feacb67e9e5bf7ff91822e6a388f94731e69be898bf3ee6ab04f3d5526f99190124ab7f98cf36d2006dea1d4de05c16eb0f0626377b701fcbf7db3741e666a875747732a4317f28c4fc55637efa319fddcb5ffff2afe4f2478ef96d60becb305fe598ff75cc6711f3d78bf92ac67cd563fe92c47c1018f3d380f920f8f25d72f95bbb7c1063fefb98ef62cc572de64f89f92a8ff96f63beca311f05ccbf3ae69b2830bf8dcb47f1e5bb7cf93f1cf355f4f2d3bc7c155ebe0b706715f3dfc4fc2dbafc172c3fdca87c9357bee9ca3fd2ca1761e56f6fcb27f9e58b8cf95783f92862fe7b30df4597affacbdff2f24d8ef963e5e5a3f0f251befc2763be08c7fcb5603e0a31df0598ff05cc4731e6bf8df92ec47c1462fe95988fd297dfeee5abfcf23102e64f11f34d02cc3f6b98aff298ef1af3bfa5de733322e556ff301f37d23bdad4394ce09d2cd69d0cccccf6603596efb56f82cdcd51ebc8ec6c6863fe5284f9afc6fcf6613e3b97bf9ecbfff2e59f1cf3d3c47c9563beca31ffeb988f22e6af07f3558cf9aec1fc2581f92070cc6f13f349f0e5abf4f2a77ef920c6fcf7315fc598af1acc9f12f35d06f3dfc27c95c77c9698ff75cc1751627e9a978fe2cb77f9f26f38e6abc8e5a779f92e70f92660fe9431df25f1a4fd3ce5ab133ef9ea63f924b0f2cbaf7c71adfcf12b7fc895ff315bfef8972f12cc5719f3bf00f35d86f96b5f3e4b2f9fd5cb3f5acc0791979fe6cb77e9e58bc4fc4101e6ab18f3db83f92c60beea31ffcb98ef72cc4f13f3558ef92ac7fcaf5f3e8a97bf9ecbd750319f0598bf84305fc48cf96d623e8b98af967ac9cc0848b0fa7919e9196cea9e26f0627e67b14c696070f9257b40134ba97d873637eebd0ef982d46ccc5f8e30dfcb98df7ecc47f3f2d57ff96bbffca7637e8a98bf1ecc5731e6bb06f3b7c07c95c7fcb731dfe5980f12317f08c67c14c6fc32be7c155f3e6a2e7f48cc7719cc7f0bf3551ef35962fed7315f45317f7dcc4731e6bb8ef95780abbdf55c3e8a97ff9ecbf756303fcd97bfe5e5774bbdb8c62787f98cba4630bf50860cf38b55038049e2d724f49c10f69eae1e9a5445f9d2945f8a67acd9de578d0cf9661236a395afa797e3d7e06a6e25d847d5e28b40f1677df489bf972ffb2cd906931f3ef5d2dbf081df404950f83367c29721890fbeed3e2cf8420afcb6aa20e0bb11e4fffe6d16f1fb313168df3309dfbb0df8dffbadbdad79ef328f0feff7d62ce518cc75f75863f1b17b8f52f73838dd732ca798fbaba06bb9a7dec7a3711f69464c6409b0fa797bd4485fb76f6d2a6b7bcb0476b6972c56a8bdc8c06c00ec0101ed9b684f999b9dbd6c1dd4d331bbaab7530c3e755d496c966d9c378b2516cef1f5d01f5e5ebff55c83aa9177bdd54b89ebb1bd395b0fe548a1f5dd34ffacd76a5fb1fe9a73f7eaaf98c6564fbd2f5ff51c82ea71a1a9d75210927aecdc148e652a2dcd64098d11e4b0242343182db1f1809c962c1408bb25a0af57464b601dae94ded1366fd26fb1dc862c675d697bb09c56915db472def47569e5b4486bf6ca694fd58c95d31aa8392ba72d4b8ad2d37758b65b02e4f30a09c7aff2d3710b809287929373470b74c97f052ac448be612c26a4319020e166fea8fc8047407a1fdb232e756988f6c0f60617014d101a5eaa2a7417915ce3c51a123d59e121a1888a4c48343d8587042b25125d450d6820c16edb49b50c6de16db127d18af8b4ef94e23ed171fb3a02eec3c8b06fb2ac3e8703f3a78b38ecfbf37cdafac6e3149fa8f6ade46c9473183686bf908d5c4ade7819651b2571beb191e828204bc8469f01376663a0911e863a24c15c861bcb39d808a660ca954a3b2dd13aa1d72fc6833861c53a0235669207a17056a1a93c2a39b790d3fec3d2fc8eeb86dd66e3686b2e681ed9e4f54ce364e73c63c2c9e34be82923333e08734a340ddba4733340ead055a023fea0866353959e9972684e9f19db324ee362135c8b684a1d29e786f90170d294cc780cda9c4d995b45ff7c26faffff6932f4f7fd01")
    ]

    func testCommonDictLoads() throws {
        let d = try common()
        XCTAssertEqual(d.id.count, 16)
        XCTAssertEqual(d.id, dictId(CommonDict.raw))
        XCTAssertNotEqual(d.zid, 0)
        XCTAssertTrue(d.visible("anyone"))
    }

    func testRoundTripPlainAndDict() throws {
        let d = try common()
        for n in [300, 1500, 5000, 40000, 200_000] {
            let m = msg(n)
            if let z = compress(m, nil, 0) {
                XCTAssertEqual(z[0], 0)
                XCTAssertLessThan(z.count, m.count)
                XCTAssertEqual(try decompress(z, nil), m)
            } else { XCTFail("plain \(n) not compressed") }
            if let z = compress(m, d, 3) {
                XCTAssertEqual(z[0], 3)
                XCTAssertEqual(try decompress(z, d), m)
            } else { XCTFail("dict \(n) not compressed") }
        }
    }

    func testShortAndIncompressible() throws {
        XCTAssertNil(compress(msg(ZIP_MIN - 1), nil, 0))
        XCTAssertNil(compress(randomBytes(500), nil, 0))
        XCTAssertThrowsError(try decompress([0], nil))
        XCTAssertThrowsError(try decompress([0, 1, 2, 3, 4, 5, 6], nil))
    }

    func testStripRestore() throws {
        let d = try common()
        let z = compress(msg(2000), d, 1)!
        let frame = restoreFrame(z, 1, d.zid)!
        XCTAssertEqual(Array(frame[0..<4]), [0x28, 0xb5, 0x2f, 0xfd])
        XCTAssertEqual(stripFrame(frame)!, Bytes(z[1...]))
        XCTAssertNil(stripFrame([1, 2, 3, 4, 5, 6]))
        XCTAssertNil(restoreFrame([0, 0x20], 0, 0).flatMap { $0.count > 100 ? $0 : nil })
        XCTAssertNil(restoreFrame([3, 0, 0], 0, 0)) // a dictionary id flag in a stripped frame is invalid
    }

    func testGoVectorsDecodeInSwift() throws {
        let d = try common()
        for (kind, n, h) in goVectors where !h.isEmpty {
            let b = unhex(h)!
            XCTAssertEqual(try decompress(b, kind == "dict" ? d : nil), msg(n), "\(kind) \(n)")
        }
    }

    // Swift output for the Go reference to decode (checked by a Go test; only with P2PACT_VEC_OUT set)
    func testWriteSwiftVectors() throws {
        guard let out = ProcessInfo.processInfo.environment["P2PACT_VEC_OUT"] else { return }
        let d = try common()
        var s = ""
        for n in [300, 5000, 40000] {
            if let z = compress(msg(n), nil, 0) { s += "plain \(n) \(z.hex())\n" }
            if let z = compress(msg(n), d, 1) { s += "dict \(n) \(z.hex())\n" }
        }
        try s.write(toFile: out, atomically: true, encoding: .utf8)
    }

    func testStoreAddSlotsPickForget() throws {
        let dir = tmpDir()
        let io = DispatchQueue(label: "io")
        let st = DictStore(dir: dir, io: io)
        let c = try common()
        try st.add(c)
        XCTAssertEqual(st.ids("a"), [c.id])
        XCTAssertEqual(st.slotOf("a", c), 1)
        XCTAssertNil(st.pick("a", [], []).0)
        let (pd, slot) = st.pick("a", [c.id], [])
        XCTAssertEqual(pd?.id, c.id)
        XCTAssertEqual(slot, 1)
        XCTAssertNil(st.pick("a", [c.id], [c.id]).0)
        let own = try Dict(trainDict(), peer: "a", own: true)
        try st.add(own)
        XCTAssertEqual(st.dicts.first?.id, own.id)
        XCTAssertEqual(st.ids("a").count, 2)
        XCTAssertEqual(st.ids("b"), [c.id])
        XCTAssertNil(st.get(own.id, "b"))
        XCTAssertNotNil(st.get(own.id, "a"))
        XCTAssertEqual(st.own("a")?.id, own.id)
        XCTAssertEqual(st.pick("a", [c.id, own.id], []).0?.id, own.id)
        XCTAssertEqual(st.slotOf("a", own), 2)
        io.sync {}
        let st2 = DictStore(dir: dir, io: io)
        XCTAssertEqual(st2.dicts.map { $0.id }, st.dicts.map { $0.id })
        XCTAssertEqual(st2.own("a")?.peer, "a")
        st.forget("a")
        XCTAssertNil(st.own("a"))
        XCTAssertEqual(st.ids("a"), [c.id])
        io.sync {}
        XCTAssertEqual(DictStore(dir: dir, io: io).dicts.count, 1)
    }

    func testStoreKeepsDictKeep() throws {
        let io = DispatchQueue(label: "io")
        let st = DictStore(dir: tmpDir(), io: io)
        var ids: [Bytes] = []
        for _ in 0..<(DICT_KEEP + 2) {
            let d = try Dict(trainDict(salt: ids.count), peer: "p", own: true)
            ids.append(d.id)
            try st.add(d)
        }
        XCTAssertEqual(st.dicts.count, DICT_KEEP)
        XCTAssertEqual(st.dicts.first?.id, ids.last)
    }

    func samples(_ salt: Int = 0) -> [Bytes] {
        (0..<400).map { i in
            Bytes("{\"seq\":\(i + salt * 1000),\"user\":\"u\(i % 13)\",\"body\":\"hello, this is chat message number \(i * 31 % 17) about topic \(i % 7) in room \(salt)\",\"ts\":\(1_700_000_000 + i)}".utf8)
        }
    }

    func trainDict(salt: Int = 0) throws -> Bytes { try train(samples(salt), [], 4 << 10) }

    func testTrainRoundTrip() throws {
        let d = try Dict(try trainDict(), peer: "x", own: true)
        XCTAssertNotEqual(d.zid, 0)
        let m = samples()[5] + samples()[6]
        let z = compress(m, d, 1)!
        XCTAssertEqual(try decompress(z, d), m)
        XCTAssertLessThan(z.count, compress(m, nil, 0)!.count)
        XCTAssertThrowsError(try train([[1, 2, 3]], [], 4096))
    }

    func testLearnerTrainsAfterHistory() throws {
        let dir = tmpDir()
        let io = DispatchQueue(label: "io")
        let trainer = DispatchQueue(label: "trainer")
        let node = DispatchQueue(label: "node")
        let st = DictStore(dir: dir, io: io)
        var got: Dict?
        let done = DispatchSemaphore(value: 0)
        let l = Learner(dir: dir, dicts: st, timing: LearnTiming(tickMs: 10, lullMs: 0, waitMs: 0, checkMs: 1000),
                        io: io, trainer: trainer,
                        post: { f in node.async(execute: f) },
                        addDict: { d in got = d; try? st.add(d); done.signal(); return true })
        node.sync {
            for s in samples() {
                var m = s
                while m.count < 200 { m += s }
                l.talk("peer", m, nil, nil)
            }
            l.tick()
            XCTAssertTrue(l.training("peer"))
            XCTAssertGreaterThan(l.historySize("peer").0, LEARN_FIRST)
        }
        XCTAssertEqual(done.wait(timeout: .now() + 30), .success)
        node.sync {
            XCTAssertEqual(got?.peer, "peer")
            XCTAssertEqual(got?.own, true)
            XCTAssertFalse(l.training("peer"))
            XCTAssertEqual(st.own("peer")?.id, got?.id)
            l.forget("peer")
        }
        l.closed = true
        XCTAssertTrue(l.closed)
    }
}
