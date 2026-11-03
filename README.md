# p2pact-swift

Swift implementation of [P2PACT](https://github.com/p2pact/p2pact) (macOS 13+, iOS 16+).

- `P2PACT` library: identity, invites, pairing and known-device handshakes, sessions, delivery,
  CBOR messages, tool 0, named tools, grants and wants, UDP / TCP / relay / local-socket /
  application roads, zstd compression with dictionaries (incl. training).
- `p2pact-interop`: the JSON-line peer of [p2pact-tests](https://github.com/p2pact/p2pact-tests)
  (`P2PACT_SWIFT=.build/release/p2pact-interop go test ./interop`).

Crypto: CryptoKit (X25519, Ed25519, ChaCha20-Poly1305) and a BLAKE2s (RFC 7693) in `Crypto.swift`;
zstd from `facebook/zstd`.
