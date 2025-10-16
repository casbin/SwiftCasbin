import NIO

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
extension Enforcer {

    // Generic bridge from EventLoopFuture to async/await
    private func awaitFuture<T>(_ future: EventLoopFuture<T>) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            future.whenComplete { result in
                cont.resume(with: result)
            }
        }
    }

    // MARK: Core lifecycle
    public func loadPolicy() async throws {
        let f: EventLoopFuture<Void> = self.loadPolicy()
        try await awaitFuture(f)
    }

    public func loadFilteredPolicy(_ f: Filter) async throws {
        let fut: EventLoopFuture<Void> = self.loadFilteredPolicy(f)
        try await awaitFuture(fut)
    }

    public func savePolicy() async throws {
        let f: EventLoopFuture<Void> = self.savePolicy()
        try await awaitFuture(f)
    }

    public func clearPolicy() async throws {
        let f: EventLoopFuture<Void> = self.clearPolicy()
        try await awaitFuture(f)
    }

    public func setModel(_ model: Model) async throws {
        let f: EventLoopFuture<Void> = self.setModel(model)
        try await awaitFuture(f)
    }

    public func setAdapter(_ adapter: Adapter) async throws {
        let f: EventLoopFuture<Void> = self.setAdapter(adapter)
        try await awaitFuture(f)
    }

    // MARK: Enforce
    public func enforce(_ rvals: Any...) async throws -> Bool {
        try enforce(rvals: rvals).get()
    }

    // MARK: Management (Policy)
    public func addPolicy(params: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addPolicy(params: params)
        return try await awaitFuture(f)
    }

    public func addPolicies(paramss: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addPolicies(paramss: paramss)
        return try await awaitFuture(f)
    }

    public func removePolicy(params: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removePolicy(params: params)
        return try await awaitFuture(f)
    }

    public func removePolicies(paramss: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removePolicies(paramss: paramss)
        return try await awaitFuture(f)
    }

    public func removeFilteredPolicy(fieldIndex: Int, fieldValues: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeFilteredPolicy(fieldIndex: fieldIndex, fieldValues: fieldValues)
        return try await awaitFuture(f)
    }

    // MARK: Management (Grouping)
    public func addGroupingPolicy(params: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addGroupingPolicy(params: params)
        return try await awaitFuture(f)
    }

    public func addGroupingPolicies(paramss: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addGroupingPolicies(paramss: paramss)
        return try await awaitFuture(f)
    }

    public func removeGroupingPolicy(params: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeGroupingPolicy(params: params)
        return try await awaitFuture(f)
    }

    public func removeGroupingPolicies(paramss: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeGroupingPolicies(paramss: paramss)
        return try await awaitFuture(f)
    }

    public func removeFilteredGroupingPolicy(fieldIndex: Int, fieldValues: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeFilteredGroupingPolicy(fieldIndex: fieldIndex, fieldValues: fieldValues)
        return try await awaitFuture(f)
    }
}

