import Dispatch
import NIO

// Shared helpers for test file paths and small utilities
public let TestsfilePath = #file.components(separatedBy: "TestSupport.swift")[0]

@inline(__always)
func tryBool(_ body: () throws -> Bool) -> Bool { (try? body()) ?? false }

// MARK: - Awaitable async shutdown helpers
// Use these in async test contexts where you can await completion.

func shutdownEventLoopGroupAsync(_ group: EventLoopGroup) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        group.shutdownGracefully(queue: .global()) { error in
            if let error = error {
                continuation.resume(throwing: error)
            } else {
                continuation.resume()
            }
        }
    }
}

func shutdownThreadPoolAsync(_ pool: NIOThreadPool) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        pool.shutdownGracefully(queue: .global()) { error in
            if let error = error {
                continuation.resume(throwing: error)
            } else {
                continuation.resume()
            }
        }
    }
}

// MARK: - Fire-and-forget background shutdown helpers
// Use these in synchronous test contexts where blocking would cause hangs.
// These initiate shutdown but return immediately without waiting for completion.

func shutdownEventLoopGroupInBackground(_ group: EventLoopGroup) {
    group.shutdownGracefully(queue: .global()) { error in
        if let error = error {
            assertionFailure("EventLoopGroup shutdown failed in background: \(error)")
        }
    }
}

func shutdownThreadPoolInBackground(_ pool: NIOThreadPool) {
    pool.shutdownGracefully(queue: .global()) { error in
        if let error = error {
            assertionFailure("NIOThreadPool shutdown failed in background: \(error)")
        }
    }
}
