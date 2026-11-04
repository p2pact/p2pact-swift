import Foundation

// Packets (spec §4.1): type (1) | receiver's session index (4) | packet number (4) | ciphertext | tag (16).

let P_INIT = 1 // known-device handshake start: [1][sender index 4][Noise]
let P_RESP = 2 // reply: [2][receiver index 4][sender index 4][Noise]
let P_PAIR1 = 3 // pairing: [3][invite id 16][sender index 4][Noise]
let P_PAIR2 = 4 // [4][receiver index 4][sender index 4][Noise]
let P_PAIR3 = 5 // [5][receiver index 4][Noise]
let P_DATA = 6 // [6][receiver index 4][packet number 4][ciphertext + tag 16]
let P_RESET = 7 // [7][index we do not know 4]

/// DATA_HEADER is the cleartext part of a data packet; it is also the associated data the tag covers.
let DATA_HEADER = 9

/// MAX_PACKET is the largest packet: it crosses any network without fragmentation.
public let MAX_PACKET = 1200

/// Window remembers the last 2048 packet numbers: replays and too-old packets are dropped (spec §4.1).
struct Window {
    static let SIZE: Int64 = 2048
    private var top: Int64 = 0 // highest accepted number + 1 (0 — nothing yet)
    private var bits = [UInt64](repeating: 0, count: Int(SIZE) / 64)

    mutating func accept(_ n: Int64) -> Bool {
        if n + 1 > top {
            let shift = n + 1 - top
            if shift >= Window.SIZE {
                for i in 0..<bits.count { bits[i] = 0 }
            } else {
                for i in 0..<shift { clear((top + i) % Window.SIZE) }
            }
            top = n + 1
        } else if top - n > Window.SIZE {
            return false
        } else if has(n % Window.SIZE) {
            return false
        }
        set(n % Window.SIZE)
        return true
    }

    private func has(_ i: Int64) -> Bool { bits[Int(i / 64)] & (1 << UInt64(i % 64)) != 0 }
    private mutating func set(_ i: Int64) { bits[Int(i / 64)] |= (1 << UInt64(i % 64)) }
    private mutating func clear(_ i: Int64) { bits[Int(i / 64)] &= ~(1 << UInt64(i % 64)) }
}

// Observe (NAT hole punching): the relay tells a device the address its UDP packet came from.
//   request  device -> relay: [8][nonce 16][zero padding 19] = 36 bytes (as long as the reply never grows past it)
//   reply    relay -> device: [8][nonce 16][ip 16][port 2, big-endian] = 35 bytes; IPv4 as IPv4-mapped IPv6
// UDP only, never between devices.
let P_OBSERVE = 8
let OBSERVE_REQUEST_SIZE = 36
let OBSERVE_REPLY_SIZE = 35

func encodeObserve(nonce: Bytes) -> Bytes {
    var out = Bytes(repeating: 0, count: OBSERVE_REQUEST_SIZE)
    out[0] = UInt8(P_OBSERVE)
    for i in 0..<16 { out[1 + i] = nonce[i] }
    return out
}

/// decodeObserve reads a reply: its nonce and the observed address as "host:port"; nil — not a valid reply.
func decodeObserve(_ pkt: Bytes) -> (nonce: Bytes, addr: String)? {
    if pkt.count != OBSERVE_REPLY_SIZE || Int(pkt[0]) != P_OBSERVE { return nil }
    let ip = Bytes(pkt[17..<33])
    let port = Int(pkt[33]) << 8 | Int(pkt[34])
    if port == 0 || ip.allSatisfy({ $0 == 0 }) { return nil }
    let host: String
    if ip[0..<10].allSatisfy({ $0 == 0 }) && ip[10] == 0xff && ip[11] == 0xff {
        host = "\(ip[12]).\(ip[13]).\(ip[14]).\(ip[15])"
    } else {
        var buf = [CChar](repeating: 0, count: 64)
        let ok = ip.withUnsafeBytes { inet_ntop(AF_INET6, $0.baseAddress, &buf, 64) != nil }
        if !ok { return nil }
        host = String(cString: buf)
    }
    return (Bytes(pkt[1..<17]), joinHostPort(host, port))
}
