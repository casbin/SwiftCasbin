import Testing
import Casbin
import NIO

@Suite("Enforcer RBAC Async/Await API Tests")
struct EnforcerRBACAsyncTests {

    private func withEnforcer<R>(_ body: (Enforcer) async throws -> R) async throws -> R {
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? elg.syncShutdownGracefully()
        }

        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
        _ = m.addDef(sec: "g", key: "g", value: "_, _")

        let adapter = MemoryAdapter(on: elg.next())
        let e = try Enforcer(m: m, adapter: adapter, .shared(elg))
        return try await body(e)
    }

    @Test("async addPermission and deletePermission")
    func testAsyncPermission() async throws {
        try await withEnforcer { e in
            // Add a permission
            let added = try await e.addPermission(for: "alice", permission: ["data1", "read"])
            #expect(added == true)

            // Verify it exists
            #expect(e.hasPermission(for: "alice", permission: ["data1", "read"]))

            // Delete it
            let deleted = try await e.deletePermission(for: "alice", permission: ["data1", "read"])
            #expect(deleted == true)

            // Verify it's gone
            #expect(!e.hasPermission(for: "alice", permission: ["data1", "read"]))
        }
    }

    @Test("async addPermissions")
    func testAsyncPermissions() async throws {
        try await withEnforcer { e in
            // Add multiple permissions
            let permissions = [
                ["data1", "read"],
                ["data2", "write"]
            ]
            let added = try await e.addPermissions(for: "alice", permissions: permissions)
            #expect(added == true)

            // Verify they exist
            #expect(e.hasPermission(for: "alice", permission: ["data1", "read"]))
            #expect(e.hasPermission(for: "alice", permission: ["data2", "write"]))
        }
    }

    @Test("async addRole and deleteRole")
    func testAsyncRole() async throws {
        try await withEnforcer { e in
            // Add a role
            let added = try await e.addRole(for: "alice", role: "admin", domain: nil)
            #expect(added == true)

            // Verify it exists
            #expect(e.hasRole(for: "alice", role: "admin", domain: nil))

            // Delete it
            let deleted = try await e.deleteRole(for: "alice", role: "admin", domain: nil)
            #expect(deleted == true)

            // Verify it's gone
            #expect(!e.hasRole(for: "alice", role: "admin", domain: nil))
        }
    }

    @Test("async addRoles")
    func testAsyncRoles() async throws {
        try await withEnforcer { e in
            // Add multiple roles
            let roles = ["admin", "user"]
            let added = try await e.addRoles(for: "alice", roles: roles, domain: nil)
            #expect(added == true)

            // Verify they exist
            #expect(e.hasRole(for: "alice", role: "admin", domain: nil))
            #expect(e.hasRole(for: "alice", role: "user", domain: nil))
        }
    }

    @Test("async deleteRoles")
    func testAsyncDeleteRoles() async throws {
        try await withEnforcer { e in
            // Add multiple roles
            _ = try await e.addRole(for: "alice", role: "admin", domain: nil)
            _ = try await e.addRole(for: "alice", role: "user", domain: nil)

            // Delete all roles for alice
            let deleted = try await e.deleteRoles(for: "alice", roles: [], domain: nil)
            #expect(deleted == true)

            // Verify they're gone by checking the policy directly
            #expect(!e.hasGroupingPolicy(params: ["alice", "admin"]))
            #expect(!e.hasGroupingPolicy(params: ["alice", "user"]))
        }
    }

    @Test("async deleteUser")
    func testAsyncDeleteUser() async throws {
        try await withEnforcer { e in
            // Add roles for a user
            _ = try await e.addRole(for: "alice", role: "admin", domain: nil)
            _ = try await e.addRole(for: "alice", role: "user", domain: nil)

            // Delete the user
            let deleted = try await e.deleteUser(name: "alice")
            #expect(deleted == true)

            // Verify all roles for the user are gone by checking the policy directly
            #expect(!e.hasGroupingPolicy(params: ["alice", "admin"]))
            #expect(!e.hasGroupingPolicy(params: ["alice", "user"]))
        }
    }

    @Test("async deleteRole by name")
    func testAsyncDeleteRoleByName() async throws {
        try await withEnforcer { e in
            // Add role for multiple users
            _ = try await e.addRole(for: "alice", role: "admin", domain: nil)
            _ = try await e.addRole(for: "bob", role: "admin", domain: nil)

            // Add permissions for the role
            _ = try await e.addPermission(for: "admin", permission: ["data1", "read"])

            // Delete the role by name
            let deleted = try await e.deleteRole(name: "admin")
            #expect(deleted == true)

            // Verify role is removed from all users by checking the policy directly
            #expect(!e.hasGroupingPolicy(params: ["alice", "admin"]))
            #expect(!e.hasGroupingPolicy(params: ["bob", "admin"]))
            // Verify permissions are gone
            #expect(!e.hasPermission(for: "admin", permission: ["data1", "read"]))
        }
    }
}
