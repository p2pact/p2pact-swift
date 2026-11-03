import CryptoKit
import Foundation
import Network
import Security

// RelayRoad is the relay road (spec §3): one channel per pair, a packet is a base64 line over
// TLS. The server is p2pact-go's relay package:
//
//   -> {"relay":1,"channel":"<32 hex>","role":"a"}   <- {"ok":true}
//   -> "p" keepalive, answered with "P"; any other line is forwarded to the other side.

/// TLSLine is a blocking wrapper over an NWConnection: connect, send, receive with timeouts.
private final class TLSStream {
    private let conn: NWConnection
    private let q = DispatchQueue(label: "p2pact-relay-nw")
    private let lock = NSLock()
    private var failed = false

    init?(host: String, port: Int, fp: String) {
        guard let p = NWEndpoint.Port(rawValue: UInt16(truncatingIfNeeded: port)), port > 0, port < 65536 else { return nil }
        let tls = NWProtocolTLS.Options()
        if !fp.isEmpty {
            let want = fp.lowercased()
            sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
                let ref = sec_trust_copy_ref(trust).takeRetainedValue()
                guard let chain = SecTrustCopyCertificateChain(ref) as? [SecCertificate], let leaf = chain.first else {
                    complete(false)
                    return
                }
                let der = SecCertificateCopyData(leaf) as Data
                let got = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
                // verified by fingerprint: the SHA-256 of the certificate
                complete(got == want)
            }, DispatchQueue(label: "p2pact-relay-verify"))
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let params = NWParameters(tls: tls, tcp: tcp)
        conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: params)
    }

    private var isFailed: Bool { lock.lock(); defer { lock.unlock() }; return failed }

    /// connect waits for the TLS handshake; false — it failed or timed out.
    func connect(timeout: TimeInterval) -> Bool {
        let sem = DispatchSemaphore(value: 0)
        var ok = false
        var done = false
        conn.stateUpdateHandler = { [weak self] st in
            self?.lock.lock()
            defer { self?.lock.unlock() }
            switch st {
            case .ready:
                if !done { done = true; ok = true; sem.signal() }
            case .failed, .cancelled:
                self?.failed = true
                if !done { done = true; sem.signal() }
            case .waiting:
                // no route yet: do not wait for the network to come back, the caller backs off
                self?.failed = true
                if !done { done = true; sem.signal() }
            default: break
            }
        }
        conn.start(queue: q)
        if sem.wait(timeout: .now() + timeout) == .timedOut {
            cancel()
            return false
        }
        lock.lock(); defer { lock.unlock() }
        return ok
    }

    func send(_ b: Bytes, timeout: TimeInterval = 15) -> Bool {
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox()
        conn.send(content: Data(b), completion: .contentProcessed { err in
            box.ok = err == nil
            sem.signal()
        })
        if sem.wait(timeout: .now() + timeout) == .timedOut { cancel(); return false }
        return box.ok
    }

    /// receive returns what arrived; nil — timeout, error or end of stream.
    func receive(timeout: TimeInterval) -> Bytes? {
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox()
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 << 10) { data, _, isComplete, err in
            if let d = data, !d.isEmpty { box.data = Bytes(d) }
            box.ok = err == nil && !(box.data == nil && isComplete)
            sem.signal()
        }
        if sem.wait(timeout: .now() + timeout) == .timedOut { cancel(); return nil }
        return box.ok ? box.data : nil
    }

    func cancel() { conn.cancel() }

    private final class ResultBox { var ok = false; var data: Bytes? }
}

/// LineReader cuts the byte stream of a TLSStream into lines.
private final class LineReader {
    private let s: TLSStream
    private var buf = Bytes()
    init(_ s: TLSStream) { self.s = s }

    func readLine(timeout: TimeInterval) -> String? {
        while true {
            if let i = buf.firstIndex(of: 10) {
                let line = String(decoding: buf[0..<i], as: UTF8.self)
                buf.removeSubrange(0...i)
                return line
            }
            if buf.count > 256 << 10 { return nil }
            guard let more = s.receive(timeout: timeout) else { return nil }
            buf.append(contentsOf: more)
        }
    }
}

public final class RelayRoad: Road {
    public let name: String
    public let hint: RelayHint
    private let recv: Receiver
    private let lock = NSLock()
    private var channels = [String: Chan]()

    private final class Chan {
        let channel: String
        let role: String
        let out = FrameQueue(limit: 256)
        let stopped = AtomicFlag()
        private let l = NSLock()
        private var stream: TLSStream?
        init(_ channel: String, _ role: String) { self.channel = channel; self.role = role }

        func set(_ s: TLSStream?) {
            l.lock(); stream = s; l.unlock()
            if stopped.value { s?.cancel() }
        }

        func stop() {
            stopped.set(true)
            l.lock(); let s = stream; l.unlock()
            s?.cancel()
            out.nudge()
        }
    }

    init(hint: RelayHint, recv: @escaping Receiver) {
        self.hint = hint
        self.recv = recv
        self.name = "relay:" + hint.addr
    }

    /// send puts a packet into a channel; a channel not joined is an error.
    public func send(_ addr: String, _ pkt: Bytes) -> Bool {
        lock.lock(); let c = channels[addr]; lock.unlock()
        guard let ch = c else { return false }
        return ch.out.offer(pkt)
    }

    /// join keeps a channel open, reconnecting until leave.
    func join(_ channel: String, _ role: String) {
        lock.lock()
        if channels[channel] != nil { lock.unlock(); return }
        let c = Chan(channel, role)
        channels[channel] = c
        lock.unlock()
        spawn("p2pact-relay") { [self] in keep(c) }
    }

    func leave(_ channel: String) {
        lock.lock(); let c = channels.removeValue(forKey: channel); lock.unlock()
        c?.stop()
    }

    func close() {
        lock.lock(); let keys = Array(channels.keys); lock.unlock()
        for k in keys { leave(k) }
    }

    /// open counts joined channels (tests).
    var open: Int { lock.lock(); defer { lock.unlock() }; return channels.count }

    private func keep(_ c: Chan) {
        var backoff = 0.5
        while !c.stopped.value {
            let ok = session(c)
            if c.stopped.value { return }
            Thread.sleep(forTimeInterval: backoff)
            backoff = ok ? 0.5 : min(backoff * 2, 30)
        }
    }

    /// session runs one connection; true — it was established.
    private func session(_ c: Chan) -> Bool {
        guard let (host, port) = hostPort(hint.addr), let s = TLSStream(host: host, port: port, fp: hint.fp) else { return false }
        c.set(s)
        defer { s.cancel() }
        if c.stopped.value || !s.connect(timeout: 10) { return false }
        let hello = "{\"relay\":1,\"channel\":\"\(c.channel)\",\"role\":\"\(c.role)\"}\n"
        if !s.send(Bytes(hello.utf8)) { return false }
        let rd = LineReader(s)
        guard let first = rd.readLine(timeout: 15), first.contains("\"ok\":true") else { return false }
        let alive = AtomicFlag()
        alive.set(true)
        spawn("p2pact-relay-w") {
            while !c.stopped.value && alive.value {
                let pkt = c.out.poll(timeout: 25, cancel: { c.stopped.value || !alive.value })
                if !alive.value || c.stopped.value { break }
                let line = pkt.map { b64($0) + "\n" } ?? "p\n"
                if !s.send(Bytes(line.utf8)) { break }
            }
            s.cancel()
        }
        let ep = Endpoint(road: self, addr: c.channel)
        while !c.stopped.value {
            guard let raw = rd.readLine(timeout: 90) else { break }
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line == "P" { continue }
            guard let pkt = unb64(line) else { continue }
            if pkt.count > MAX_PACKET + 64 { continue }
            recv(pkt, ep)
        }
        alive.set(false)
        c.out.nudge()
        return true
    }
}
