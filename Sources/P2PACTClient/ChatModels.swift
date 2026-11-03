import Foundation

// Types of tool 1 `p2pact.chat` (chat spec): ACP with `_meta.p2pact`. Unknown fields are ignored;
// every type keeps the JSON it was read from in `raw`.

public struct AgentInfo: Equatable {
    public let id: String
    public let name: String
    public let version: String?
    public let raw: JSONValue

    public init(_ m: JSONValue) {
        id = m.str("id") ?? ""
        name = m.str("name") ?? m.str("id") ?? ""
        version = m.str("version")
        raw = m
    }
}

/// The answer to `initialize`: what the computer's chat offers.
public struct InitializeResult: Equatable {
    public let protocolVersion: Int
    public let agentName: String?
    public let agentTitle: String?
    public let agentVersion: String?
    /// `session/load` works.
    public let loadSession: Bool
    /// The agents the computer can start (`_meta.p2pact.agents`), the first is the default.
    public let agents: [AgentInfo]
    /// The computer speaks the `_p2pact/<name>` extensions.
    public let extensions: Bool
    public let raw: JSONValue

    public init(_ m: JSONValue) {
        let info = m.obj("agentInfo")
        let meta = m.p2pactMeta
        protocolVersion = m.int("protocolVersion") ?? 1
        agentName = info?.str("name")
        agentTitle = info?.str("title")
        agentVersion = info?.str("version")
        loadSession = m.obj("agentCapabilities")?.bool("loadSession") ?? false
        agents = meta.objs("agents").map(AgentInfo.init)
        extensions = (meta.int("ext") ?? 0) >= 1
        raw = m
    }
}

public enum SessionState: String {
    case working, waiting, idle, closed
    /// A state this SDK does not know.
    case unknown

    init(wire: String?) { self = wire.flatMap { SessionState(rawValue: $0) } ?? .unknown }
}

/// A chat of a computer: an entry of `session/list` or `_p2pact/session_changed`.
public struct ChatSession: Equatable {
    public let id: String
    public let cwd: String?
    public let title: String?
    public let agent: String?
    public let state: SessionState
    /// RFC 3339.
    public let updatedAt: String?
    public let raw: JSONValue

    public init(_ m: JSONValue) {
        let meta = m.p2pactMeta
        id = m.str("sessionId") ?? ""
        cwd = m.str("cwd")
        title = meta.str("title") ?? m.str("title")
        agent = meta.str("agent")
        state = SessionState(wire: meta.str("state"))
        updatedAt = meta.str("updatedAt") ?? m.str("updatedAt")
        raw = m
    }
}

public struct SessionList {
    public let sessions: [ChatSession]
    public let nextCursor: String?
    public let raw: JSONValue
}

/// An ACP content block: text, image, resource_link…
public struct ContentBlock: Equatable {
    public let type: String
    public let text: String?
    public let raw: JSONValue

    public init(_ m: JSONValue?) {
        type = m?.str("type") ?? ""
        text = m?.str("text")
        raw = m ?? .object([:])
    }

    public static func text(_ text: String) -> JSONValue { ["type": "text", "text": .string(text)] }
    public static func image(mimeType: String, base64: String) -> JSONValue {
        ["type": "image", "mimeType": .string(mimeType), "data": .string(base64)]
    }
}

/// A tool call of an agent (`tool_call`, `tool_call_update` and the `toolCall` of a permission request).
public struct ToolCallInfo: Equatable {
    public let toolCallId: String
    public let title: String?
    /// ACP's kind: execute, read, edit…
    public let kind: String?
    /// pending, in_progress, completed, failed.
    public let status: String?
    public let raw: JSONValue

    public init(_ m: JSONValue) {
        toolCallId = m.str("toolCallId") ?? ""
        title = m.str("title")
        kind = m.str("kind")
        status = m.str("status")
        raw = m
    }
}

public struct PlanEntry: Equatable {
    public let content: String
    public let priority: String?
    public let status: String?
    public let raw: JSONValue
}

/// ChatUpdate is a `session/update`: a live message of a chat or a replayed one (`session/load`).
/// `seq` numbers the messages of a session; a client that loads a session again skips what it has
/// shown (chat spec §8). The pieces of a streamed agent message carry no `seq` but the first.
public struct ChatUpdate: Equatable {
    public enum Kind: Equatable {
        case userMessage(ContentBlock)
        case agentMessage(ContentBlock)
        case agentThought(ContentBlock)
        case toolCall(ToolCallInfo)
        case toolCallUpdate(ToolCallInfo)
        case plan([PlanEntry])
        case modeChanged(String)
        /// An update this SDK has no type for: read `raw`.
        case other(String)
    }

    public let sessionId: String
    public let kind: Kind
    public let seq: Int64?
    /// RFC 3339.
    public let time: String?
    /// The `update` object.
    public let raw: JSONValue

    /// The text of a message or thought (empty for the rest).
    public var text: String {
        switch kind {
        case .userMessage(let c), .agentMessage(let c), .agentThought(let c): return c.text ?? ""
        default: return ""
        }
    }

    public init(sessionId: String, update u: JSONValue) {
        let meta = u.p2pactMeta
        self.sessionId = sessionId
        seq = meta.long("seq")
        time = meta.str("time")
        raw = u
        let type = u.str("sessionUpdate") ?? ""
        switch type {
        case "user_message_chunk": kind = .userMessage(ContentBlock(u.obj("content")))
        case "agent_message_chunk": kind = .agentMessage(ContentBlock(u.obj("content")))
        case "agent_thought_chunk": kind = .agentThought(ContentBlock(u.obj("content")))
        case "tool_call": kind = .toolCall(ToolCallInfo(u))
        case "tool_call_update": kind = .toolCallUpdate(ToolCallInfo(u))
        case "plan": kind = .plan(u.objs("entries").map { PlanEntry(content: $0.str("content") ?? "", priority: $0.str("priority"), status: $0.str("status"), raw: $0) })
        case "current_mode_update": kind = .modeChanged(u.str("currentModeId") ?? "")
        default: kind = .other(type)
        }
    }
}

public struct NewSession {
    public let sessionId: String
    public let raw: JSONValue
}

/// What `session/load` gave: the replayed `updates` (all of them have come when it returns).
public struct LoadedSession {
    public let sessionId: String
    public let updates: [ChatUpdate]
    /// The chat is long and came as its tail: `ChatClient.older` fetches the earlier part.
    public let older: Bool
    public let raw: JSONValue
}

public struct PromptResult {
    public let stopReason: String?
    /// The `mid` was already executed; nothing was sent again.
    public let duplicate: Bool
    public let raw: JSONValue
}

/// A message of a conversation, as `_p2pact/older` gives it.
public struct ChatMessage: Equatable {
    public let seq: Int64
    public let role: String
    public let text: String
    public let time: String?
    public let images: [String]
    public let raw: JSONValue
}

public struct OlderPage {
    public let sessionId: String
    public let messages: [ChatMessage]
    public let more: Bool
    public let raw: JSONValue
}

public struct DiffFile: Equatable {
    public let path: String
    public let added: Int
    public let removed: Int
    public let status: String?
}

public struct DiffResult {
    public let files: [DiffFile]
    public let patch: String
    public let truncated: Bool
    /// `not_found`, `not_git` or text.
    public let error: String?
    public let raw: JSONValue
}

public struct ImageResult {
    /// Base64.
    public let data: String?
    /// `not_found`, `no_file`, `too_big`, `bad_image`.
    public let error: String?
    public let raw: JSONValue
}

/// `_p2pact/request_answered`: another client answered; stop showing the request.
public struct RequestAnswered: Equatable {
    public let sessionId: String
    public let toolCallId: String
}

// --- the computer asks, the application answers ---

public struct PermissionOption: Equatable {
    public let optionId: String
    public let name: String
    /// allow_once, allow_always, reject_once, reject_always.
    public let kind: String?
    public let description: String?
    public let raw: JSONValue
}

/// The outcome of a permission request.
public enum PermissionOutcome: Equatable {
    case selected(optionId: String)
    case cancelled
}

/// PermissionRequest is `session/request_permission` (chat spec §6): the agent asks the person to
/// allow something. It is also how an agent asks a single question: `toolCall.title` is the question
/// and the options are the answers (§9.1).
public final class PermissionRequest {
    public let sessionId: String
    public let toolCall: ToolCallInfo
    public let options: [PermissionOption]
    public let raw: JSONValue
    /// Fires when another client answered first (`RequestAnswered`): stop showing the request.
    public let answered: Signal

    init(sessionId: String, toolCall: ToolCallInfo, options: [PermissionOption], raw: JSONValue, answered: Signal) {
        self.sessionId = sessionId; self.toolCall = toolCall; self.options = options; self.raw = raw; self.answered = answered
    }

    /// The first option that allows, once before always; cancelled if there is none.
    public func allow() -> PermissionOutcome { pick("allow_once", "allow_always") }
    /// The first option that rejects.
    public func deny() -> PermissionOutcome { pick("reject_once", "reject_always") }
    public func select(_ option: PermissionOption) -> PermissionOutcome { .selected(optionId: option.optionId) }

    private func pick(_ kinds: String...) -> PermissionOutcome {
        for k in kinds { if let o = options.first(where: { $0.kind == k }) { return select(o) } }
        return .cancelled
    }
}

public struct QuestionOption: Equatable {
    public let label: String
    public let description: String?
}

public struct Question: Equatable {
    public let question: String
    public let header: String?
    /// The answer may take several options.
    public let multi: Bool
    public let options: [QuestionOption]
}

/// QuestionRequest is `_p2pact/question`: several questions, or answers that may take several options (§9.1).
public final class QuestionRequest {
    public let sessionId: String
    public let toolCallId: String
    public let questions: [Question]
    public let raw: JSONValue
    public let answered: Signal

    init(sessionId: String, toolCallId: String, questions: [Question], raw: JSONValue, answered: Signal) {
        self.sessionId = sessionId; self.toolCallId = toolCallId; self.questions = questions; self.raw = raw; self.answered = answered
    }

    /// The answer to a `multi` question: the labels joined by ", ".
    public static func join(_ labels: [String]) -> String { labels.joined(separator: ", ") }
}

/// The application's answer to permission requests; returns when the person decided. A throw
/// answers the computer with an error (the request stays open there). The task is cancelled when
/// another client answered first.
public typealias PermissionHandler = (PermissionRequest) async throws -> PermissionOutcome

/// The application's answer to questions: {question text → label} (see `QuestionRequest.join`);
/// a throw answers with an error (the question stays open on the computer).
public typealias QuestionHandler = (QuestionRequest) async throws -> [String: String]
