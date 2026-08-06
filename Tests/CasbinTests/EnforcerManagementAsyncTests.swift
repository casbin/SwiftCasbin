import Testing
import Casbin
import NIO

@Suite("Enforcer Management Async/Await API Tests")
struct EnforcerManagementAsyncTests {

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

    @Test("async addNamedPolicy and removeNamedPolicy")
    func testAsyncNamedPolicy() async throws {
        try await withEnforcer { e in
            // Add a named policy
            let added = try await e.addNamedPolicy(ptype: "p", params: ["alice", "data1", "read"])
            #expect(added == true)

            // Verify it exists
            #expect(e.hasNamedPolicy(ptype: "p", params: ["alice", "data1", "read"]))

            // Remove it
            let removed = try await e.removeNamedPolicy(ptype: "p", params: ["alice", "data1", "read"])
            #expect(removed == true)

            // Verify it's gone
            #expect(!e.hasNamedPolicy(ptype: "p", params: ["alice", "data1", "read"]))
        }
    }

    @Test("async addNamedPolicies and removeNamedPolicies")
    func testAsyncNamedPolicies() async throws {
        try await withEnforcer { e in
            // Add multiple named policies
            let rules = [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"]
            ]
            let added = try await e.addNamedPolicies(ptype: "p", paramss: rules)
            #expect(added == true)

            // Verify they exist
            #expect(e.hasNamedPolicy(ptype: "p", params: ["alice", "data1", "read"]))
            #expect(e.hasNamedPolicy(ptype: "p", params: ["bob", "data2", "write"]))

            // Remove them
            let removed = try await e.removeNamedPolicies(ptype: "p", paramss: rules)
            #expect(removed == true)

            // Verify they're gone
            #expect(!e.hasNamedPolicy(ptype: "p", params: ["alice", "data1", "read"]))
            #expect(!e.hasNamedPolicy(ptype: "p", params: ["bob", "data2", "write"]))
        }
    }

    @Test("async removeFilteredNamedPolicy")
    func testAsyncRemoveFilteredNamedPolicy() async throws {
        try await withEnforcer { e in
            // Add multiple policies
            _ = try await e.addNamedPolicy(ptype: "p", params: ["alice", "data1", "read"])
            _ = try await e.addNamedPolicy(ptype: "p", params: ["alice", "data2", "write"])
            _ = try await e.addNamedPolicy(ptype: "p", params: ["bob", "data1", "read"])

            // Remove filtered - all alice policies
            let removed = try await e.removeFilteredNamedPolicy(
                ptype: "p",
                fieldIndex: 0,
                fieldValues: ["alice"]
            )
            #expect(removed == true)

            // Verify only bob's policy remains
            #expect(!e.hasNamedPolicy(ptype: "p", params: ["alice", "data1", "read"]))
            #expect(!e.hasNamedPolicy(ptype: "p", params: ["alice", "data2", "write"]))
            #expect(e.hasNamedPolicy(ptype: "p", params: ["bob", "data1", "read"]))
        }
    }

    @Test("async addNamedGroupingPolicy and removeNamedGroupingPolicy")
    func testAsyncNamedGroupingPolicy() async throws {
        try await withEnforcer { e in
            // Add a grouping policy
            let added = try await e.addNamedGroupingPolicy(ptype: "g", params: ["alice", "admin"])
            #expect(added == true)

            // Verify it exists
            #expect(e.hasGroupingNamedPolicy(ptype: "g", params: ["alice", "admin"]))

            // Remove it
            let removed = try await e.removeNamedGroupingPolicy(ptype: "g", params: ["alice", "admin"])
            #expect(removed == true)

            // Verify it's gone
            #expect(!e.hasGroupingNamedPolicy(ptype: "g", params: ["alice", "admin"]))
        }
    }

    @Test("async addNamedGroupingPolicies and removeNamedGroupingPolicies")
    func testAsyncNamedGroupingPolicies() async throws {
        try await withEnforcer { e in
            // Add multiple grouping policies
            let rules = [
                ["alice", "admin"],
                ["bob", "user"]
            ]
            let added = try await e.addNamedGroupingPolicies(ptype: "g", paramss: rules)
            #expect(added == true)

            // Verify they exist
            #expect(e.hasGroupingNamedPolicy(ptype: "g", params: ["alice", "admin"]))
            #expect(e.hasGroupingNamedPolicy(ptype: "g", params: ["bob", "user"]))

            // Remove them
            let removed = try await e.removeNamedGroupingPolicies(ptype: "g", paramss: rules)
            #expect(removed == true)

            // Verify they're gone
            #expect(!e.hasGroupingNamedPolicy(ptype: "g", params: ["alice", "admin"]))
            #expect(!e.hasGroupingNamedPolicy(ptype: "g", params: ["bob", "user"]))
        }
    }

    @Test("async removeFilteredNamedGroupingPolicy")
    func testAsyncRemoveFilteredNamedGroupingPolicy() async throws {
        try await withEnforcer { e in
            // Add multiple grouping policies
            _ = try await e.addNamedGroupingPolicy(ptype: "g", params: ["alice", "admin"])
            _ = try await e.addNamedGroupingPolicy(ptype: "g", params: ["alice", "user"])
            _ = try await e.addNamedGroupingPolicy(ptype: "g", params: ["bob", "user"])

            // Remove filtered - all alice grouping policies
            let removed = try await e.removeFilteredNamedGroupingPolicy(
                ptype: "g",
                fieldIndex: 0,
                fieldValues: ["alice"]
            )
            #expect(removed == true)

            // Verify only bob's grouping policy remains
            #expect(!e.hasGroupingNamedPolicy(ptype: "g", params: ["alice", "admin"]))
            #expect(!e.hasGroupingNamedPolicy(ptype: "g", params: ["alice", "user"]))
            #expect(e.hasGroupingNamedPolicy(ptype: "g", params: ["bob", "user"]))
        }
    }
}
