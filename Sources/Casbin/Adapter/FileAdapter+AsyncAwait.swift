import NIO

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
extension FileAdapter {

    // Generic bridge from EventLoopFuture to async/await
    private func awaitFuture<T>(_ future: EventLoopFuture<T>) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            future.whenComplete { result in
                cont.resume(with: result)
            }
        }
    }

    // MARK: Load
    public func loadPolicy(m: Model) async throws {
        try await awaitFuture(self.loadPolicy(m: m))
    }

    public func loadFilteredPolicy(m: Model, f: Filter) async throws {
        try await awaitFuture(self.loadFilteredPolicy(m: m, f: f))
    }

    // MARK: Save / Clear
    public func savePolicy(m: Model) async throws {
        try await awaitFuture(self.savePolicy(m: m))
    }

    public func clearPolicy() async throws {
        try await awaitFuture(self.clearPolicy())
    }

    // MARK: No-op convenience (kept for API symmetry)
    public func addPolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        try await awaitFuture(self.addPolicy(sec: sec, ptype: ptype, rule: rule))
    }

    public func addPolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        try await awaitFuture(self.addPolicies(sec: sec, ptype: ptype, rules: rules))
    }

    public func removePolicy(sec: String, ptype: String, rule: [String]) async throws -> Bool {
        try await awaitFuture(self.removePolicy(sec: sec, ptype: ptype, rule: rule))
    }

    public func removePolicies(sec: String, ptype: String, rules: [[String]]) async throws -> Bool {
        try await awaitFuture(self.removePolicies(sec: sec, ptype: ptype, rules: rules))
    }

    public func removeFilteredPolicy(sec: String, ptype: String, fieldIndex: Int, fieldValues: [String]) async throws -> Bool {
        try await awaitFuture(self.removeFilteredPolicy(sec: sec, ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues))
    }
}

