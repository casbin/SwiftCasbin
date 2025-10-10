import Testing
import Casbin

// Shared test file path - points to Tests/CasbinTests/ directory
let DefaultModelTestsFilePath = #filePath.components(separatedBy: "DefaultModelTests.swift")[0]

@Suite("Default Model Tests")
struct DefaultModelTests {
    func expect(_ expected: Bool, _ e: Enforcer, _ rvals: any Sendable..., file: StaticString = #filePath, line: UInt = #line) async throws {
        let res = try await e.enforce(rvals: Array(rvals)).get()
        #expect(expected == res)
    }

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


    @Test("Basic model")
    func testBasicModel() async throws {
       let e = try await makeEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
        try await expect(true, e, "alice","data1","read")
        try await expect(true, e, "bob", "data2", "write")
        
        try await expect(false, e, "alice","data1","write")
        try await expect(false, e, "alice","data2", "read")
        try await expect(false, e, "alice","data2", "write")
        try await expect(false, e, "bob", "data1", "read")
        try await expect(false, e, "bob", "data1", "write")
        try await expect(false, e, "bob", "data2", "read")
    }
    
    @Test("Basic model no policy")
    func testBasicModelNoPolicy() async throws {
        let e = try await makeEnforcer("examples/basic_model.conf")
        
        try await expect(false, e, "alice","data1","read")
        try await expect(false, e, "bob", "data2", "write")
        
        try await expect(false, e, "alice","data1","write")
        try await expect(false, e, "alice","data2", "read")
        try await expect(false, e, "alice","data2", "write")
        try await expect(false, e, "bob", "data1", "read")
        try await expect(false, e, "bob", "data1", "write")
        try await expect(false, e, "bob", "data2", "read")

    }
    @Test("Basic model with root")
    func testBasicModelWithRoot() async throws {
        let e = try await makeEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv")
        try await expect(true, e, "alice","data1","read")
        try await expect(true, e, "bob", "data2", "write")
        try await expect(true, e, "root","data1","read")
        try await expect(true, e, "root","data1","write")
        try await expect(true, e, "root","data2","read")
        try await expect(true, e, "root","data2","write")
        
        try await expect(false, e, "alice","data1","write")
        try await expect(false, e, "alice","data2", "read")
        try await expect(false, e, "alice","data2", "write")
        try await expect(false, e, "bob", "data1", "read")
        try await expect(false, e, "bob", "data1", "write")
        try await expect(false, e, "bob", "data2", "read")
   
    }
    
    @Test("Basic model with root no policy")
    func testBasicModelWithRootNoPolicy() async throws {
        let e = try await makeEnforcer("examples/basic_with_root_model.conf")
        
        try await expect(false, e, "alice","data1","read")
        try await expect(false, e, "bob", "data2", "write")
        try await expect(true, e, "root","data1","read")
        try await expect(true, e, "root","data1","write")
        try await expect(true, e, "root","data2","read")
        try await expect(true, e, "root","data2","write")
        
        try await expect(false, e, "alice","data1","write")
        try await expect(false, e, "alice","data2", "read")
        try await expect(false, e, "alice","data2", "write")
        try await expect(false, e, "bob", "data1", "read")
        try await expect(false, e, "bob", "data1", "write")
        try await expect(false, e, "bob", "data2", "read")
    }
    
    @Test("Basic model without users")
    func testBasicModelWithoutUsers() async throws {
        let e = try await makeEnforcer("examples/basic_without_users_model.conf", "examples/basic_without_users_policy.csv")
        
        try await expect(true, e, "data1","read")
        try await expect(false, e, "data1","write")
        try await expect(false, e, "data2","read")
        try await expect(true, e, "data2","write")
        
    }
    @Test("Basic model without resources")
    func testBasicModelWithoutResources() async throws {
        let e = try await makeEnforcer("examples/basic_without_resources_model.conf", "examples/basic_without_resources_policy.csv")
        try await expect(true, e, "alice","read")
        try await expect(false, e, "alice","write")
        try await expect(false, e, "bob","read")
        try await expect(true, e, "bob","write")
    }
    
    @Test("RBAC model")
    func testRbacModel() async throws {
        let e = try await makeEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        
        try await expect(true, e, "alice","data1","read")
        try await expect(false, e, "alice","data1","write")
        try await expect(true, e, "alice","data2","read")
        try await expect(true, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(false, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")
    }
    
    @Test("RBAC with resource roles")
    func testRbacModelWithResourceRoles() async throws {
        let e = try await makeEnforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv")
        try await expect(true, e, "alice","data1","read")
        try await expect(true, e, "alice","data1","write")
        try await expect(false, e, "alice","data2","read")
        try await expect(true, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(false, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")

    }
    
    @Test("RBAC with domains")
    func testRbacModelWithDomains() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        try await expect(true, e, "alice","domain1","data1","read")
        try await expect(true, e, "alice","domain1","data1","write")
        try await expect(false, e, "alice","domain1","data2","read")
        try await expect(false, e, "alice","domain1","data2","write")
        try await expect(false, e, "bob","domain2","data1","read")
        try await expect(false, e, "bob","domain2","data1","write")
        try await expect(true, e, "bob","domain2","data2","read")
        try await expect(true, e, "bob","domain2","data2","write")
    }
    
    @Test("RBAC with domains runtime")
    func testRbacModelWithDomainsRuntime() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf")
       _ = try await e.addPolicy(params: ["admin","domain1","data1","read"])
       _ = try await e.addPolicy(params: ["admin","domain1","data1","write"])
       _ = try await e.addPolicy(params: ["admin","domain2","data2","read"])
       _ = try await e.addPolicy(params: ["admin","domain2","data2","write"])
       _ = try await e.addGroupingPolicy(params: ["alice","admin","domain1"])
       _ = try await e.addGroupingPolicy(params: ["bob","admin","domain2"])
        
        try await expect(true, e, "alice","domain1","data1","read")
        try await expect(true, e, "alice","domain1","data1","write")
        try await expect(false, e, "alice","domain1","data2","read")
        try await expect(false, e, "alice","domain1","data2","write")
        try await expect(false, e, "bob","domain2","data1","read")
        try await expect(false, e, "bob","domain2","data1","write")
        try await expect(true, e, "bob","domain2","data2","read")
        try await expect(true, e, "bob","domain2","data2","write")

        let removed1 = try await e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"])
        #expect(removed1)

        try await expect(false, e, "alice","domain1","data1","read")
        try await expect(false, e, "alice","domain1","data1","write")
        try await expect(false, e, "alice","domain1","data2","read")
        try await expect(false, e, "alice","domain1","data2","write")
        try await expect(false, e, "bob","domain2","data1","read")
        try await expect(false, e, "bob","domain2","data1","write")
        try await expect(true, e, "bob","domain2","data2","read")
        try await expect(true, e, "bob","domain2","data2","write")

        let removed2 = try await e.removePolicy(params: ["admin", "domain2", "data2", "read"])
        #expect(removed2)

        try await expect(false, e, "alice","domain1","data1","read")
        try await expect(false, e, "alice","domain1","data1","write")
        try await expect(false, e, "alice","domain1","data2","read")
        try await expect(false, e, "alice","domain1","data2","write")
        try await expect(false, e, "bob","domain2","data1","read")
        try await expect(false, e, "bob","domain2","data1","write")
        try await expect(false, e, "bob","domain2","data2","read")
        try await expect(true, e, "bob","domain2","data2","write")
    }
    
    @Test("RBAC with domains at runtime (mock adapter)")
    func testRbacModelWithDomainsAtRuntimeMockAdapter() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
       _ = try await e.addPolicy(params: ["admin", "domain3", "data1", "read"])
       _ = try await e.addGroupingPolicy(params: ["alice", "admin", "domain3"])
        try await expect(true, e, "alice", "domain3", "data1", "read")
        try await expect(true, e, "alice", "domain1", "data1", "read")
        _ = try await e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"])
        try await expect(false, e, "alice", "domain1", "data1", "read")
        try await expect(true, e, "bob", "domain2", "data2", "read")
        _ = try await e.removePolicy(params: ["admin", "domain2", "data2", "read"])
        try await expect(false, e, "bob", "domain2", "data2", "read")
    }
    
    @Test("RBAC with deny")
    func testRbacModelWithDeny() async throws {
        let e = try await makeEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")
        try await expect(true, e, "alice", "data1", "read")
        try await expect(false, e, "alice","data1","write")
        try await expect(true, e, "alice","data2","read")
        try await expect(false, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(false, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")
    }
    
    @Test("RBAC with not deny")
    func testRbacModelWithNotDeny() async throws {
        let e = try await makeEnforcer("examples/rbac_with_not_deny_model.conf", "examples/rbac_with_deny_policy.csv")
        try await expect(false, e, "alice", "data2", "write")
    }
    @Test("RBAC with custom data")
    func testRbacModelWithCustomData() async throws {
        let e = try await makeEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        _ = try await e.addGroupingPolicy(params: ["bob", "data2_admin", "custom_data"])
        try await expect(true, e, "alice", "data1", "read")
        try await expect(false, e, "alice","data1","write")
        try await expect(true, e, "alice","data2","read")
        try await expect(true, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(true, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")
        
        _ = try await e.removeGroupingPolicy(params: ["bob", "data2_admin", "custom_data"])
        try await expect(true, e, "alice", "data1", "read")
        try await expect(false, e, "alice","data1","write")
        try await expect(true, e, "alice","data2","read")
        try await expect(true, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(false, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")
    }
    
    @Test("RBAC using in-op")
    func testRbacModelUsinginOp() async throws {
        let e  = try await makeEnforcer("examples/rbac_model_matcher_using_in_op.conf", "examples/rbac_policy.csv")

        try await expect(true, e, "alice", "data1", "read")
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
    @Test("ABAC")
    func testAbac() async throws {
        
        let e = try await makeEnforcer("examples/abac_model.conf")
        try await expect(false, e, "alice", Book.init(owner: "zhangsan"), "read")
        
        try await expect(true, e, "alice", Book.init(owner: "alice"), "read")
    }
}
