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
