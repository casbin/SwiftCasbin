import XCTest
import Casbin

// Shared test file path - points to Tests/CasbinTests/ directory
let DefaultModelTestsFilePath = #filePath.components(separatedBy: "DefaultModelTests.swift")[0]

final class DefaultModelTests: XCTestCase {

    func makeEnforcer(_ mfile:String,_ aFile:String? = nil) async throws -> Enforcer {
        let m = try await DefaultModel.from(file: DefaultModelTestsFilePath + mfile)
        let adapter: Adapter
        if let aFile = aFile {
            adapter = FileAdapter(filePath: DefaultModelTestsFilePath + aFile)
        } else {
            adapter = MemoryAdapter()
        }
        let e = try await Enforcer(m: m, adapter: adapter)
        return e
    }


    func testBasicModel() async throws {
       let e = try await makeEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
        XCTAssertTrue(try e.enforce("alice","data1","read").get())
        XCTAssertTrue(try e.enforce("bob", "data2", "write").get())
        
        XCTAssertFalse(try e.enforce("alice","data1","write").get())
        XCTAssertFalse(try e.enforce("alice","data2", "read").get())
        XCTAssertFalse(try e.enforce("alice","data2", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "read").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "read").get())
    }
    
    func testBasicModelNoPolicy() async throws {
        let e = try await makeEnforcer("examples/basic_model.conf")
        
        XCTAssertFalse(try e.enforce("alice","data1","read").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "write").get())
        
        XCTAssertFalse(try e.enforce("alice","data1","write").get())
        XCTAssertFalse(try e.enforce("alice","data2", "read").get())
        XCTAssertFalse(try e.enforce("alice","data2", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "read").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "read").get())

    }
    func testBasicModelWithRoot() async throws {
        let e = try await makeEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv")
        XCTAssertTrue(try e.enforce("alice","data1","read").get())
        XCTAssertTrue(try e.enforce("bob", "data2", "write").get())
        XCTAssertTrue(try e.enforce("root","data1","read").get())
        XCTAssertTrue(try e.enforce("root","data1","write").get())
        XCTAssertTrue(try e.enforce("root","data2","read").get())
        XCTAssertTrue(try e.enforce("root","data2","write").get())
        
        XCTAssertFalse(try e.enforce("alice","data1","write").get())
        XCTAssertFalse(try e.enforce("alice","data2", "read").get())
        XCTAssertFalse(try e.enforce("alice","data2", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "read").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "read").get())
   
    }
    
    func testBasicModelWithRootNoPolicy() async throws {
        let e = try await makeEnforcer("examples/basic_with_root_model.conf")
        
        XCTAssertFalse(try e.enforce("alice","data1","read").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "write").get())
        XCTAssertTrue(try e.enforce("root","data1","read").get())
        XCTAssertTrue(try e.enforce("root","data1","write").get())
        XCTAssertTrue(try e.enforce("root","data2","read").get())
        XCTAssertTrue(try e.enforce("root","data2","write").get())
        
        XCTAssertFalse(try e.enforce("alice","data1","write").get())
        XCTAssertFalse(try e.enforce("alice","data2", "read").get())
        XCTAssertFalse(try e.enforce("alice","data2", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "read").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "read").get())
    }
    
    func testBasicModelWithoutUsers() async throws {
        let e = try await makeEnforcer("examples/basic_without_users_model.conf", "examples/basic_without_users_policy.csv")
        
        XCTAssertTrue(try e.enforce("data1","read").get())
        XCTAssertFalse(try e.enforce("data1","write").get())
        XCTAssertFalse(try e.enforce("data2","read").get())
        XCTAssertTrue(try e.enforce("data2","write").get())
        
    }
    func testBasicModelWithoutResources() async throws {
        let e = try await makeEnforcer("examples/basic_without_resources_model.conf", "examples/basic_without_resources_policy.csv")
        XCTAssertTrue(try e.enforce("alice","read").get())
        XCTAssertFalse(try e.enforce("alice","write").get())
        XCTAssertFalse(try e.enforce("bob","read").get())
        XCTAssertTrue(try e.enforce("bob","write").get())
    }
    
    func testRbacModel() async throws {
        let e = try await makeEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        
        XCTAssertEqual(true, try e.enforce("alice","data1","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testRbacModelWithResourceRoles() async throws {
        let e = try await makeEnforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv")
        XCTAssertEqual(true, try e.enforce("alice","data1","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())

    }
    
    func testRbacModelWithDomains() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        XCTAssertEqual(true, try e.enforce("alice","domain1","data1","read").get())
        XCTAssertEqual(true, try e.enforce("alice","domain1","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","write").get())
    }
    
    func testRbacModelWithDomainsRuntime() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf")
       _ = try await e.addPolicy(params: ["admin","domain1","data1","read"])
       _ = try await e.addPolicy(params: ["admin","domain1","data1","write"])
       _ = try await e.addPolicy(params: ["admin","domain2","data2","read"])
       _ = try await e.addPolicy(params: ["admin","domain2","data2","write"])
       _ = try await e.addGroupingPolicy(params: ["alice","admin","domain1"])
       _ = try await e.addGroupingPolicy(params: ["bob","admin","domain2"])
        
        XCTAssertEqual(true, try e.enforce("alice","domain1","data1","read").get())
        XCTAssertEqual(true, try e.enforce("alice","domain1","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","write").get())

        let removed1 = try await e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"])
        XCTAssertEqual(true, removed1)

        XCTAssertEqual(false, try e.enforce("alice","domain1","data1","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","write").get())

        let removed2 = try await e.removePolicy(params: ["admin", "domain2", "data2", "read"])
        XCTAssertEqual(true, removed2)

        XCTAssertEqual(false, try e.enforce("alice","domain1","data1","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","write").get())
    }
    
    func testRbacModelWithDomainsAtRuntimeMockAdapter() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
       _ = try await e.addPolicy(params: ["admin", "domain3", "data1", "read"])
       _ = try await e.addGroupingPolicy(params: ["alice", "admin", "domain3"])
        XCTAssertEqual(true, try e.enforce("alice", "domain3", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("alice", "domain1", "data1", "read").get())
        _ = try await e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"])
        XCTAssertEqual(false, try e.enforce("alice", "domain1", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("bob", "domain2", "data2", "read").get())
        _ = try await e.removePolicy(params: ["admin", "domain2", "data2", "read"])
        XCTAssertEqual(false, try e.enforce("bob", "domain2", "data2", "read").get())
    }
    
    func testRbacModelWithDeny() async throws {
        let e = try await makeEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testRbacModelWithNotDeny() async throws {
        let e = try await makeEnforcer("examples/rbac_with_not_deny_model.conf", "examples/rbac_with_deny_policy.csv")
        XCTAssertEqual(false, try e.enforce("alice", "data2", "write").get())
    }
    func testRbacModelWithCustomData() async throws {
        let e = try await makeEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        _ = try await e.addGroupingPolicy(params: ["bob", "data2_admin", "custom_data"])
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
        
        _ = try await e.removeGroupingPolicy(params: ["bob", "data2_admin", "custom_data"])
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testRbacModelUsinginOp() async throws {
        let e  = try await makeEnforcer("examples/rbac_model_matcher_using_in_op.conf", "examples/rbac_policy.csv")

        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
//        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
//        XCTAssertEqual(true, try e.enforce("bob", "data2", "write").get())
//        XCTAssertEqual(true, try e.enforce("alice", "data2", "write").get())
//        XCTAssertEqual(true, try e.enforce("alice", "data2", "read").get())
//        XCTAssertEqual(true, try e.enforce("guest", "data2", "read").get())
//        XCTAssertEqual(true, try e.enforce("alice", "data3", "read").get())
//        XCTAssertEqual(true, try e.enforce("bob", "data3", "read").get())
    }

    struct Book {
        var owner:String
    }
    func testAbac() async throws {
        
        let e = try await makeEnforcer("examples/abac_model.conf")
        XCTAssertEqual(false, try e.enforce("alice", Book.init(owner: "zhangsan"), "read").get())
        
        XCTAssertEqual(true, try e.enforce("alice", Book.init(owner: "alice"), "read").get())
    }
}
