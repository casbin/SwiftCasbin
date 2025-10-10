import Testing
import Casbin

// Shared test file path - points to Tests/CasbinTests/ directory
let RBACAPITestsFilePath = #filePath.components(separatedBy: "RBACAPITests.swift")[0]

@Suite("RBAC API Tests")
struct RBACAPITests {

    func makeEnforcer(_ mfile:String,_ aFile:String? = nil) async throws -> Enforcer {
        let m = try await DefaultModel.from(file: RBACAPITestsFilePath + mfile)
        let adapter: Adapter
        if let aFile = aFile {
            adapter = FileAdapter(filePath: RBACAPITestsFilePath + aFile)
        } else {
            adapter = MemoryAdapter()
        }
        let e = try await Enforcer(m: m, adapter: adapter)
        return e
    }

    @Test("Role API")
    func testRoleAPI() async throws {
        let e = try await makeEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        do {
            let r1 = await e.getRoles(for: "alice", domain: nil)
            let r2 = await e.getRoles(for: "bob", domain: nil)
            let r3 = await e.getRoles(for: "data2_admin", domain: nil)
            let r4 = await e.getRoles(for: "non_exists", domain: nil)
            #expect(["data2_admin"] == r1)
            #expect([] == r2)
            #expect([] == r3)
            #expect([] == r4)
        }

        do {
            let h1 = await e.hasRole(for: "alice", role: "data1_admin", domain: nil)
            let h2 = await e.hasRole(for: "alice", role: "data2_admin", domain: nil)
            #expect(h1 == false)
            #expect(h2 == true)
        }
       _ = try await e.addRole(for: "alice", role: "data1_admin", domain: nil)
        do {
            let a = (await e.getRoles(for: "alice", domain: nil)).sorted()
            let b = (await e.getRoles(for: "bob", domain: nil)).sorted()
            let c = (await e.getRoles(for: "data2_admin", domain: nil)).sorted()
            let actions = (await e.getAllActions()).sorted()
            #expect(["data1_admin", "data2_admin"] == a)
            #expect([] == b)
            #expect([] == c)
            #expect(["read", "write"] == actions)
        }
        //XCTAssertEqual(["data1", "data2"], e.getAllObjects().sorted())
        //XCTAssertEqual(["alice", "bob", "data2_admin"], e.getAllSubjects().sorted())
        //XCTAssertEqual(["data1_admin", "data2_admin"], e.getAllRoles().sorted())
    }
    @Test("Core API for Role API with domain")
    func testCoreAPI_for_RoleAPI_with_domain() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        do {
            let actions = await e.getAllActions()
            #expect(["read", "write"] == actions.sorted())
        }
        //XCTAssertEqual(["data1", "data2"], e.getAllObjects())
        //XCTAssertEqual(["admin",], e.getAllSubjects())
        //XCTAssertEqual(["admin", ], e.getAllRoles())
    }
}
