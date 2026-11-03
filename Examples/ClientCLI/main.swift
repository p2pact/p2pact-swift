import Foundation
@preconcurrency import P2PACT
import P2PACTClient

// A small client of a P2PACT computer (an engine such as Nomad Code).
//
//   p2pact-client-cli pair <invite>            pair with a computer
//   p2pact-client-cli chats                    list the chats of the computer
//   p2pact-client-cli send <chat id> <text>    send a message and print the reply as it comes
//   p2pact-client-cli watch                    print what happens on the computer (fleet events)
//
// The state (keys, the paired computer) is in $P2PACT_CLI_DIR (default ~/.p2pact-client-cli).

setvbuf(stdout, nil, _IOLBF, 0)

let dir = ProcessInfo.processInfo.environment["P2PACT_CLI_DIR"] ?? NSHomeDirectory() + "/.p2pact-client-cli"
try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

func fail(_ s: String) -> Never {
    FileHandle.standardError.write(Data((s + "\n").utf8))
    exit(1)
}

func usage() -> Never {
    fail("usage: p2pact-client-cli pair <invite> | chats | send <chat id> <text> | watch")
}

let args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else { usage() }

func run() async throws {
    let client = try P2pactClient(dir: dir, name: "p2pact-client-cli")
    defer { client.close() }

    if cmd == "pair" {
        guard args.count == 2 else { usage() }
        let computer = try await client.pair(args[1])
        try await computer.whenOnline()
        print("paired with \(computer.name) (\(computer.id))")
        // the person at the computer decides what we may do; wait for it
        for await e in client.computerEvents.stream() {
            if case .grantsChanged(let c, let g) = e {
                print("grants: " + g.map { "\($0.tool)=\($0.level)" }.joined(separator: " "))
                _ = c
                break
            }
        }
        return
    }

    guard let computer = client.computers().first else { fail("no computer is paired: p2pact-client-cli pair <invite>") }
    try await computer.whenOnline()

    switch cmd {
    case "chats":
        for s in try await computer.chat.listAllSessions() {
            print("\(s.id)\t\(s.state.rawValue)\t\(s.agent ?? "-")\t\(s.title ?? s.cwd ?? "")")
        }
    case "send":
        guard args.count >= 3 else { usage() }
        let chat = computer.chat
        let id = args[1]
        let updates = chat.updates.stream()
        let printer = Task {
            for await u in updates where u.sessionId == id {
                switch u.kind {
                case .agentMessage: print(u.text, terminator: "")
                case .toolCall(let t): print("\n[\(t.title ?? t.kind ?? "tool")]")
                default: break
                }
            }
        }
        chat.permissionHandler = { r in
            print("\nallow \(r.toolCall.title ?? "?")? [y/N] ", terminator: "")
            return (readLine() ?? "").lowercased().hasPrefix("y") ? r.allow() : r.deny()
        }
        let r = try await chat.prompt(id, text: args[2...].joined(separator: " "))
        printer.cancel()
        print("\n(\(r.stopReason ?? "done"))")
    case "watch":
        let fleet = computer.fleet
        let watch = try await fleet.watch()
        print("watching \(watch.sessions.count) sessions")
        for await e in fleet.events.stream() {
            switch e {
            case .sessionsChanged(let l): print("sessions: " + l.map { "\($0.title ?? $0.id): \($0.phase ?? "?")" }.joined(separator: ", "))
            case .sessionMessages(let id, let m): for x in m { print("[\(id)] \(x.role): \(x.text)") }
            case .notify(let t): print("notify: \(t)")
            default: break
            }
        }
    default:
        usage()
    }
}

do {
    try await run()
} catch {
    fail("\(error)")
}
