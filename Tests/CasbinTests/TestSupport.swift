import NIO

// Shared helpers for test file paths and small utilities
public let TestsfilePath = #file.components(separatedBy: "TestSupport.swift")[0]

@inline(__always)
func tryBool(_ body: () throws -> Bool) -> Bool { (try? body()) ?? false }

