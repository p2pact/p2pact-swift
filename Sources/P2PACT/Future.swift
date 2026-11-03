import Foundation

/// Future is a value that arrives later: a call's result, a pairing. Thread-safe; `get` blocks.
public final class Future<T> {
    private let lock = NSLock()
    private var result: Result<T, Error>?
    private var waiters: [(Result<T, Error>) -> Void] = []

    public init() {}

    public var isDone: Bool { lock.lock(); defer { lock.unlock() }; return result != nil }

    /// complete sets the value; false — it was set already.
    @discardableResult
    public func complete(_ v: T) -> Bool { finish(.success(v)) }

    /// fail sets the error; false — it was set already.
    @discardableResult
    public func fail(_ e: Error) -> Bool { finish(.failure(e)) }

    private func finish(_ r: Result<T, Error>) -> Bool {
        lock.lock()
        if result != nil { lock.unlock(); return false }
        result = r
        let w = waiters
        waiters = []
        lock.unlock()
        for f in w { f(r) }
        return true
    }

    /// whenComplete runs f when the future is done (at once, if it is), on the completing thread.
    public func whenComplete(_ f: @escaping (Result<T, Error>) -> Void) {
        lock.lock()
        if let r = result { lock.unlock(); f(r); return }
        waiters.append(f)
        lock.unlock()
    }

    /// get waits for the value (nil timeout — forever) and returns it or throws its error.
    public func get(timeout: TimeInterval? = nil) throws -> T {
        let sem = DispatchSemaphore(value: 0)
        whenComplete { _ in sem.signal() }
        if let t = timeout {
            if sem.wait(timeout: .now() + t) == .timedOut { throw P2pactError(Errors.failed, "timed out") }
        } else {
            sem.wait()
        }
        lock.lock(); defer { lock.unlock() }
        return try result!.get()
    }
}
