# p2pact-swift

Swift implementation of [P2PACT](https://github.com/p2pact/p2pact) (macOS 13+, iOS 16+).

- `P2PACT` library: identity, invites, pairing and known-device handshakes, sessions, delivery,
  CBOR messages, tool 0, named tools, grants and wants, UDP / TCP / relay / local-socket /
  application roads, zstd compression with dictionaries (incl. training).
- `allowForward(a, b, on)` — opt this device in as a forwarder between two devices it trusts
  (spec §3, via a third device): they reach each other through it when nothing else works, end
  to end encrypted. Kept with the trusted list; `forwardRate` limits each direction (256 KB/s by
  default). The two devices need nothing: they learn it from the hello and use the road
  `via:<forwarder>` (`paths`), ranked with an application road. `forwards`, `forwarders` and
  `forwardStats` tell who forwards for whom and how much.
- Tool 5 `p2pact.term` (terminals, `spec/term.md`) is a tool of the spec: `fixedTool("p2pact.term")` is 5,
  and the application serves it with `handleToolAll("p2pact.term", handler)` (announced in the hello's
  `{tool: version}`; the node requires read, the handler checks the rest). A terminal a device served
  before under a name of its own (a named tool from 64 up) is a *former name* (spec §8.1):
  `aliasTool(former, "p2pact.term")` makes grants on either name count for both (`levelIn`, the highest wins),
  `callToolOn` / `resolveTool` call 5 when the device announces it and the former name otherwise
  (`peerHasTool` tells what the hello announced), and events under 5 are `p2pact.term`
  (`peerToolName`). `P2PACTClient` has `Tools.term` and `Computer.callTool(Tools.term, …)`; there is no
  typed terminal client.
- `p2pact-interop`: the JSON-line peer of [p2pact-tests](https://github.com/p2pact/p2pact-tests)
  (`P2PACT_SWIFT=.build/release/p2pact-interop go test ./interop`).

Crypto: CryptoKit (X25519, Ed25519, ChaCha20-Poly1305) and a BLAKE2s (RFC 7693) in `Crypto.swift`;
zstd from `facebook/zstd`.

## P2PACTClient

`P2PACTClient` is the typed client for the public tools of a P2PACT computer (an engine such as
Nomad Code): chat (`p2pact.chat`, ACP over `1.1 rpc` with the `_p2pact/*` extensions), fleet
(`p2pact.fleet`) and plugins (`p2pact.plugins`). Swift concurrency: calls are `async`, events are
`AsyncStream`s (`events.stream()`) or callbacks (`events.subscribe`). Models keep the JSON they were
read from (`raw`). It mirrors the Kotlin, Go, TypeScript and Python clients.

```swift
import P2PACTClient

let client = try P2pactClient(dir: dataDir, name: "My app")
let computer = try await client.pair("p2pact1.…")          // asks for defaultWants
try await computer.whenOnline()

let chat = computer.chat
chat.permissionHandler = { request in request.allow() }
for chatSession in try await chat.listAllSessions() { print(chatSession.title ?? chatSession.id) }
let loaded = try await chat.loadSession("s1")               // the whole history, in order
let result = try await chat.prompt("s1", text: "run the tests")

for await e in computer.fleet.events.stream() { … }          // after try await computer.fleet.watch()
```

- A joiner that paired with wants has no grants until the computer's first `0.6` event:
  `computer.grants` is empty until then (`ComputerEvent.grantsChanged`, `computer.level(_:)`).
- Errors: `P2pactCallError` (`.forbidden` is code 4, a call the grants refuse) and `RpcError` (the
  tool's own JSON-RPC errors).
- `P2pactClient(node:)` wraps a node the application runs itself (see the doc comment).
- Example: `swift run p2pact-client-cli pair <invite>` / `chats` / `send <id> <text>` / `watch`
  (`Examples/ClientCLI`).
- End to end against the real engine: `P2PACT_ENGINE_E2E=<nomad-code/agent> swift test --filter EngineE2ETests`
  (runs `go test -run TestAppE2E` there).
