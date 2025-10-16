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

    // MARK: Management (Named Policy)
    public func addNamedPolicy(ptype: String, params: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addNamedPolicy(ptype: ptype, params: params)
        return try await awaitFuture(f)
    }

    public func addNamedPolicies(ptype: String, paramss: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addNamedPolicies(ptype: ptype, paramss: paramss)
        return try await awaitFuture(f)
    }

    public func removeNamedPolicy(ptype: String, params: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeNamedPolicy(ptype: ptype, params: params)
        return try await awaitFuture(f)
    }

    public func removeNamedPolicies(ptype: String, paramss: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeNamedPolicies(ptype: ptype, paramss: paramss)
        return try await awaitFuture(f)
    }

    public func removeFilteredNamedPolicy(ptype: String, fieldIndex: Int, fieldValues: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeFilteredNamedPolicy(ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues)
        return try await awaitFuture(f)
    }

    // MARK: Management (Named Grouping)
    public func addNamedGroupingPolicy(ptype: String, params: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addNamedGroupingPolicy(ptype: ptype, params: params)
        return try await awaitFuture(f)
    }

    public func addNamedGroupingPolicies(ptype: String, paramss: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addNamedGroupingPolicies(ptype: ptype, paramss: paramss)
        return try await awaitFuture(f)
    }

    public func removeNamedGroupingPolicy(ptype: String, params: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeNamedGroupingPolicy(ptype: ptype, params: params)
        return try await awaitFuture(f)
    }

    public func removeNamedGroupingPolicies(ptype: String, paramss: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeNamedGroupingPolicies(ptype: ptype, paramss: paramss)
        return try await awaitFuture(f)
    }

    public func removeFilteredNamedGroupingPolicy(ptype: String, fieldIndex: Int, fieldValues: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.removeFilteredNamedGroupingPolicy(ptype: ptype, fieldIndex: fieldIndex, fieldValues: fieldValues)
        return try await awaitFuture(f)
    }

    // MARK: RBAC API
    public func addPermission(for user: String, permission: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addPermission(for: user, permission: permission)
        return try await awaitFuture(f)
    }

    public func addPermissions(for user: String, permissions: [[String]]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addPermissions(for: user, permissions: permissions)
        return try await awaitFuture(f)
    }

    public func addRole(for user: String, role: String, domain: String?) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addRole(for: user, role: role, domain: domain)
        return try await awaitFuture(f)
    }

    public func addRoles(for user: String, roles: [String], domain: String?) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.addRoles(for: user, roles: roles, domain: domain)
        return try await awaitFuture(f)
    }

    public func deleteRole(for user: String, role: String, domain: String?) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.deleteRole(for: user, role: role, domain: domain)
        return try await awaitFuture(f)
    }

    public func deleteRoles(for user: String, roles: [String], domain: String?) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.deleteRoles(for: user, roles: roles, domain: domain)
        return try await awaitFuture(f)
    }

    public func deleteUser(name: String) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.deleteUser(name: name)
        return try await awaitFuture(f)
    }

    public func deleteRole(name: String) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.deleteRole(name: name)
        return try await awaitFuture(f)
    }

    public func deletePermission(for user: String, permission: [String]) async throws -> Bool {
        let f: EventLoopFuture<Bool> = self.deletePermission(for: user, permission: permission)
        return try await awaitFuture(f)
    }
}

