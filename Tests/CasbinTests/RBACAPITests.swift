import XCTest
import Casbin

// Shared test file path - points to Tests/CasbinTests/ directory
let RBACAPITestsFilePath = #filePath.components(separatedBy: "RBACAPITests.swift")[0]

final class RBACAPITests: XCTestCase {

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

    func testRoleAPI() async throws {
        let e = try await makeEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        XCTAssertEqual(["data2_admin"], e.getRoles(for: "alice", domain: nil))
        XCTAssertEqual([], e.getRoles(for: "bob", domain: nil))
        XCTAssertEqual([], e.getRoles(for: "data2_admin", domain: nil))
        XCTAssertEqual([], e.getRoles(for: "non_exists", domain: nil))

        XCTAssertEqual(false, e.hasRole(for: "alice", role: "data1_admin", domain: nil))
        XCTAssertEqual(true, e.hasRole(for: "alice", role: "data2_admin", domain: nil))
       _ = try await e.addRole(for: "alice", role: "data1_admin", domain: nil)
        XCTAssertEqual(["data1_admin", "data2_admin"], e.getRoles(for: "alice", domain: nil).sorted())
        XCTAssertEqual([], e.getRoles(for: "bob", domain: nil).sorted())
        XCTAssertEqual([], e.getRoles(for: "data2_admin", domain: nil).sorted())
        XCTAssertEqual(["read", "write"], e.getAllActions().sorted())
        //XCTAssertEqual(["data1", "data2"], e.getAllObjects().sorted())
        //XCTAssertEqual(["alice", "bob", "data2_admin"], e.getAllSubjects().sorted())
        //XCTAssertEqual(["data1_admin", "data2_admin"], e.getAllRoles().sorted())
    }
    func testCoreAPI_for_RoleAPI_with_domain() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        XCTAssertEqual(["read", "write"], e.getAllActions().sorted())
        //XCTAssertEqual(["data1", "data2"], e.getAllObjects())
        //XCTAssertEqual(["admin",], e.getAllSubjects())
        //XCTAssertEqual(["admin", ], e.getAllRoles())
    }
}
