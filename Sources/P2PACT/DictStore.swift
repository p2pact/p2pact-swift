import Foundation

/// DictStore keeps dictionaries in dir/net-dicts/<id hex>; the order (newest first) is in the
/// file "order", a line per dictionary: "<id hex>" for a common one, "<id hex> <device> own|their"
/// for a pair's (the same layout as p2pact-go). Not thread-safe: the node's queue only.
final class DictStore {
    let dir: String
    private let io: DispatchQueue
    private(set) var dicts: [Dict] = [] // newest first

    // slots: what we list to each device, by slot. A dictionary keeps its slot while listed;
    // a dropped one leaves an empty id, and a new one goes to the end.
    private var slots: [String: [Bytes]] = [:]
    private var gen = 0
    private var cache: [String: (Int, [Bytes])] = [:]

    init(dir: String, io: DispatchQueue) {
        self.dir = (dir as NSString).appendingPathComponent("net-dicts")
        self.io = io
        let order = (try? String(contentsOfFile: self.dir + "/order", encoding: .utf8)) ?? ""
        var out: [Dict] = []
        for line in order.components(separatedBy: "\n") {
            let f = line.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\r" }).map(String.init)
            if f.count != 1 && f.count != 3 { continue } // a damaged line
            guard let data = FileManager.default.contents(atPath: self.dir + "/" + f[0]) else { continue }
            let raw = Bytes(data)
            guard let d = f.count == 3 ? try? Dict(raw, peer: f[1], own: f[2] == "own") : try? Dict(raw) else { continue }
            if d.id.hex() == f[0] { out.append(d) }
        }
        dicts = out
    }

    /// get returns dictionary id if peer may see it.
    func get(_ id: Bytes, _ peer: String) -> Dict? { dicts.first { same($0.id, id) && $0.visible(peer) } }

    /// add puts a dictionary first (moving it up if known) and deletes the oldest extra ones of its
    /// kind. The files are written on io, in order.
    func add(_ d: Dict) throws {
        let dir = self.dir
        io.async {
            do {
                try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                let p = dir + "/" + d.id.hex()
                let sz = (try? FileManager.default.attributesOfItem(atPath: p)[.size] as? Int) ?? nil
                if sz != d.raw.count { try writeAtomic(p, d.raw) }
            } catch {}
        }
        var out = [d]
        var dropped: [Dict] = []
        var kinds: [String: Int] = [:]
        func key(_ x: Dict) -> String { x.peer + "\u{0}" + (x.own ? "1" : "0") }
        kinds[key(d)] = 1
        for x in dicts {
            if same(x.id, d.id) && x.peer == d.peer { continue }
            let n = (kinds[key(x)] ?? 0) + 1
            kinds[key(x)] = n
            if n > DICT_KEEP { dropped.append(x) } else { out.append(x) }
        }
        for x in dropped where !out.contains(where: { same($0.id, x.id) }) {
            let p = dir + "/" + x.id.hex()
            io.async { try? FileManager.default.removeItem(atPath: p) }
        }
        dicts = out
        gen += 1
        saveOrder()
    }

    private func saveOrder() {
        var lines = ""
        for x in dicts {
            lines += x.id.hex() + (x.peer.isEmpty ? "" : " \(x.peer) \(x.own ? "own" : "their")") + "\n"
        }
        let dir = self.dir
        let bytes = Bytes(lines.utf8)
        io.async {
            do {
                try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
                try writeAtomic(dir + "/order", bytes)
            } catch {}
        }
    }

    /// list is what peer sees of our dictionaries, newest first: the common ones and the pair's.
    func list(_ peer: String) -> [Dict] {
        var out: [Dict] = []
        for d in dicts where d.visible(peer) && !out.contains(where: { same($0.id, d.id) }) { out.append(d) }
        return out
    }

    /// ids is our list for peer, by slot (an empty id — a free slot).
    func ids(_ peer: String) -> [Bytes] { slotsFor(peer) }

    private func slotsFor(_ peer: String) -> [Bytes] {
        if let c = cache[peer], c.0 == gen { return c.1 }
        let list = self.list(peer)
        var s = slots[peer] ?? []
        for i in s.indices where !s[i].isEmpty && !list.contains(where: { same($0.id, s[i]) }) { s[i] = [] }
        for j in list.indices.reversed() { // the oldest first, so the newest gets the last slot
            let d = list[j]
            if hasId(s, d.id) { continue }
            let free = s.count >= SLOTS_MAX ? s.firstIndex(where: { $0.isEmpty }) : nil
            if let f = free { s[f] = d.id } else { s.append(d.id) }
        }
        slots[peer] = s
        cache[peer] = (gen, s)
        return s
    }

    /// slotOf is d's slot in our list for peer (from 1).
    func slotOf(_ peer: String, _ d: Dict) -> Int {
        (slotsFor(peer).firstIndex(where: { same($0, d.id) }) ?? -1) + 1
    }

    /// own returns our newest dictionary trained for peer.
    func own(_ peer: String) -> Dict? { dicts.first { $0.own && $0.peer == peer } }

    /// pick returns the dictionary to compress for peer and its slot in our list for peer.
    func pick(_ peer: String, _ theirs: [Bytes], _ lacks: [Bytes]) -> (Dict?, Int) {
        let list = self.list(peer)
        func ok(_ d: Dict) -> Bool { hasId(theirs, d.id) && !hasId(lacks, d.id) }
        guard let d = list.first(where: { $0.own && ok($0) }) ?? list.first(where: { ok($0) }) else { return (nil, 0) }
        return (d, slotOf(peer, d))
    }

    /// forget drops what belongs to the pair with peer.
    func forget(_ peer: String) {
        let drop = dicts.filter { $0.peer == peer }
        if drop.isEmpty { return }
        dicts = dicts.filter { $0.peer != peer }
        for d in drop where !dicts.contains(where: { same($0.id, d.id) }) {
            let p = dir + "/" + d.id.hex()
            io.async { try? FileManager.default.removeItem(atPath: p) }
        }
        slots[peer] = nil
        cache[peer] = nil
        gen += 1
        saveOrder()
    }
}
