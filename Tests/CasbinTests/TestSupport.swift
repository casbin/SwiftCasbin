import Dispatch
import NIO

// Shared helpers for test file paths and small utilities
public let TestsfilePath = #file.components(separatedBy: "TestSupport.swift")[0]

@inline(__always)
func tryBool(_ body: () throws -> Bool) -> Bool { (try? body()) ?? false }

// Non-blocking shutdown helpers so cooperative test executors don't hang.
func shutdownEventLoopGroupAsync(_ group: EventLoopGroup) {
    group.shutdownGracefully(queue: .global()) { _ in }
}

func shutdownThreadPoolAsync(_ pool: NIOThreadPool) {
    pool.shutdownGracefully(queue: .global()) { _ in }
}
