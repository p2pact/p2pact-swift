import Foundation
@preconcurrency import P2PACT

/// Subscription ends a subscription to Events.
public final class Subscription {
    private let onCancel: () -> Void
    init(_ onCancel: @escaping () -> Void) { self.onCancel = onCancel }
    public func cancel() { onCancel() }
}

/// Events is a stream of values the application listens to. Callbacks run on the library's worker
/// threads, one at a time per stream of a computer, in the order sent; the application moves to its
/// own actor itself. `stream()` gives the same as an AsyncStream: values queue without limit, so a
/// slow reader never holds up the library.
public final class Events<T> {
    private let lock = NSLock()
    private var listeners: [Int: (T) -> Void] = [:]
    private var next = 0

    init() {}

    /// subscribe calls f for every value from now on.
    @discardableResult
    public func subscribe(_ f: @escaping (T) -> Void) -> Subscription {
        lock.lock()
        let id = next
        next += 1
        listeners[id] = f
        lock.unlock()
        return Subscription { [weak self] in
            guard let self = self else { return }
            self.lock.lock(); self.listeners.removeValue(forKey: id); self.lock.unlock()
        }
    }

    /// stream is the events as an AsyncStream; the delivery ends when the loop over it ends.
    public func stream() -> AsyncStream<T> {
        AsyncStream { continuation in
            let sub = subscribe { continuation.yield($0) }
            continuation.onTermination = { _ in sub.cancel() }
        }
    }

    func emit(_ v: T) {
        lock.lock()
        let fs = Array(listeners.values)
        lock.unlock()
        for f in fs { f(v) }
    }
}

/// Signal fires once; what waits for it goes on. For "another client answered".
public final class Signal {
    private let f = Future<Void>()
    init() {}
    public var isFired: Bool { f.isDone }
    func fire() { f.complete(()) }
    func onFire(_ g: @escaping () -> Void) { f.whenComplete { _ in g() } }
    /// wait returns when the signal has fired.
    public func wait() async { _ = try? await f.value() }
}

extension NSLock {
    /// locked runs f under the lock (usable from async code, unlike lock/unlock).
    @discardableResult
    func locked<T>(_ f: () -> T) -> T {
        lock()
        defer { unlock() }
        return f()
    }
}
