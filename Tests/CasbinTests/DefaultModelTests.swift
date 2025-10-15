import Testing
import NIO
import Casbin

@Suite("Default Model", .timeLimit(.minutes(1)))
struct DefaultModelTests {
    private func tryBool(_ body: () throws -> Bool) -> Bool { (try? body()) ?? false }
    // Create an Enforcer that shares a test-scoped EventLoopGroup.
    // Ensures adapters' futures complete and no background ELG is left running.
    // Also silences logs to keep test runs fast.
    
    private func withEnforcer(_ mfile:String,_ aFile:String? = nil, body: (Enforcer) throws -> Void) throws {
        let pool = NIOThreadPool.singleton
        let elg = MultiThreadedEventLoopGroup.singleton
        let fileIo = NonBlockingFileIO(threadPool: pool)
        let m = try DefaultModel.from(file:TestsfilePath + mfile , fileIo: fileIo, on: elg.next()).wait()
        let adapter:Adapter = (aFile != nil)
            ? FileAdapter(filePath: TestsfilePath + (aFile ?? ""), fileIo: fileIo, eventloop: elg.next())
            : MemoryAdapter(on: elg.next())
        let e = try Enforcer(m: m, adapter: adapter, .shared(elg))
        e.enableLog = false
        e.logger.logLevel = .warning
        try body(e)
    }
   
    
    @Test("basic model")
    func testBasicModel() throws {
        try withEnforcer("examples/basic_model.conf", "examples/basic_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice","data1","read").get() })
            #expect(tryBool { try e.enforce("bob", "data2", "write").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","data2", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data2", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("bob", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "data2", "read").get() })
        }
    }
    
    @Test("basic model no policy")
    func testBasicModelNoPolicy() throws {
        try withEnforcer("examples/basic_model.conf") { e in
            #expect(!tryBool { try e.enforce("alice","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob", "data2", "write").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","data2", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data2", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("bob", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "data2", "read").get() })
        }
    }
    @Test("basic model with root")
    func testBasicModelWithRoot() throws {
        try withEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice","data1","read").get() })
            #expect(tryBool { try e.enforce("bob", "data2", "write").get() })
            #expect(tryBool { try e.enforce("root","data1","read").get() })
            #expect(tryBool { try e.enforce("root","data1","write").get() })
            #expect(tryBool { try e.enforce("root","data2","read").get() })
            #expect(tryBool { try e.enforce("root","data2","write").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","data2", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data2", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("bob", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "data2", "read").get() })
        }
    }
    
    @Test("root no policy")
    func testBasicModelWithRootNoPolicy() throws {
        try withEnforcer("examples/basic_with_root_model.conf") { e in
            #expect(!tryBool { try e.enforce("alice","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob", "data2", "write").get() })
            #expect(tryBool { try e.enforce("root","data1","read").get() })
            #expect(tryBool { try e.enforce("root","data1","write").get() })
            #expect(tryBool { try e.enforce("root","data2","read").get() })
            #expect(tryBool { try e.enforce("root","data2","write").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","data2", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data2", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("bob", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "data2", "read").get() })
        }
    }
    
    @Test("basic model without users")
    func testBasicModelWithoutUsers() throws {
        try withEnforcer("examples/basic_without_users_model.conf", "examples/basic_without_users_policy.csv") { e in
            #expect(tryBool { try e.enforce("data1","read").get() })
            #expect(!tryBool { try e.enforce("data1","write").get() })
            #expect(!tryBool { try e.enforce("data2","read").get() })
            #expect(tryBool { try e.enforce("data2","write").get() })
        }
    }
    @Test("basic model without resources")
    func testBasicModelWithoutResources() throws {
        try withEnforcer("examples/basic_without_resources_model.conf", "examples/basic_without_resources_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice","read").get() })
            #expect(!tryBool { try e.enforce("alice","write").get() })
            #expect(!tryBool { try e.enforce("bob","read").get() })
            #expect(tryBool { try e.enforce("bob","write").get() })
        }
    }
    
    @Test("rbac model basic")
    func testRbacModel() throws {
        try withEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice","data1","read").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(tryBool { try e.enforce("alice","data2","read").get() })
            #expect(tryBool { try e.enforce("alice","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","data1","write").get() })
            #expect(!tryBool { try e.enforce("bob","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","data2","write").get() })
        }
    }
    
    @Test("rbac with resource roles")
    func testRbacModelWithResourceRoles() throws {
        try withEnforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice","data1","read").get() })
            #expect(tryBool { try e.enforce("alice","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","data2","read").get() })
            #expect(tryBool { try e.enforce("alice","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","data1","write").get() })
            #expect(!tryBool { try e.enforce("bob","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","data2","write").get() })
        }
    }
    
    @Test("rbac with domains")
    func testRbacModelWithDomains() throws {
        try withEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice","domain1","data1","read").get() })
            #expect(tryBool { try e.enforce("alice","domain1","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data2","read").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data1","write").get() })
            #expect(tryBool { try e.enforce("bob","domain2","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","domain2","data2","write").get() })
        }
    }
    
    @Test("rbac with domains runtime policy")
    func testRbacModelWithDomainsRuntime() throws {
        try withEnforcer("examples/rbac_with_domains_model.conf") { e in
            _ = try e.addPolicy(params: ["admin","domain1","data1","read"]).wait()
            _ = try e.addPolicy(params: ["admin","domain1","data1","write"]).wait()
            _ = try e.addPolicy(params: ["admin","domain2","data2","read"]).wait()
            _ = try e.addPolicy(params: ["admin","domain2","data2","write"]).wait()
            _ = try e.addGroupingPolicy(params: ["alice","admin","domain1"]).wait()
            _ = try e.addGroupingPolicy(params: ["bob","admin","domain2"]).wait()
            #expect(tryBool { try e.enforce("alice","domain1","data1","read").get() })
            #expect(tryBool { try e.enforce("alice","domain1","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data2","read").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data1","write").get() })
            #expect(tryBool { try e.enforce("bob","domain2","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","domain2","data2","write").get() })
            #expect(tryBool { try e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"]).wait() })
            #expect(!tryBool { try e.enforce("alice","domain1","data1","read").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data2","read").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data1","write").get() })
            #expect(tryBool { try e.enforce("bob","domain2","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","domain2","data2","write").get() })
            #expect(tryBool { try e.removePolicy(params: ["admin", "domain2", "data2", "read"]).wait() })
            #expect(!tryBool { try e.enforce("alice","domain1","data1","read").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data2","read").get() })
            #expect(!tryBool { try e.enforce("alice","domain1","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data1","write").get() })
            #expect(!tryBool { try e.enforce("bob","domain2","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","domain2","data2","write").get() })
        }
    }
    
    @Test("rbac domains at runtime with adapter")
    func testRbacModelWithDomainsAtRuntimeMockAdapter() throws {
        try withEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv") { e in
            _ = try e.addPolicy(params: ["admin", "domain3", "data1", "read"]).wait()
            _ = try e.addGroupingPolicy(params: ["alice", "admin", "domain3"]).wait()
            #expect(tryBool { try e.enforce("alice", "domain3", "data1", "read").get() })
            #expect(tryBool { try e.enforce("alice", "domain1", "data1", "read").get() })
            _ = try e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"]).wait()
            #expect(!tryBool { try e.enforce("alice", "domain1", "data1", "read").get() })
            #expect(tryBool { try e.enforce("bob", "domain2", "data2", "read").get() })
            _ = try e.removePolicy(params: ["admin", "domain2", "data2", "read"]).wait()
            #expect(!tryBool { try e.enforce("bob", "domain2", "data2", "read").get() })
        }
    }
    
    @Test("rbac with deny")
    func testRbacModelWithDeny() throws {
        try withEnforcer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(tryBool { try e.enforce("alice","data2","read").get() })
            #expect(!tryBool { try e.enforce("alice","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","data1","write").get() })
            #expect(!tryBool { try e.enforce("bob","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","data2","write").get() })
        }
    }
    
    @Test("rbac not deny")
    func testRbacModelWithNotDeny() throws {
        try withEnforcer("examples/rbac_with_not_deny_model.conf", "examples/rbac_with_deny_policy.csv") { e in
            #expect(!tryBool { try e.enforce("alice", "data2", "write").get() })
        }
    }

    @Test("rbac with custom data")
    func testRbacModelWithCustomData() throws {
        try withEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv") { e in
            _ = try e.addGroupingPolicy(params: ["bob", "data2_admin", "custom_data"]).wait()
            #expect(tryBool { try e.enforce("alice", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(tryBool { try e.enforce("alice","data2","read").get() })
            #expect(tryBool { try e.enforce("alice","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","data1","write").get() })
            #expect(tryBool { try e.enforce("bob","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","data2","write").get() })
            _ = try e.removeGroupingPolicy(params: ["bob", "data2_admin", "custom_data"]).wait()
            #expect(tryBool { try e.enforce("alice", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(tryBool { try e.enforce("alice","data2","read").get() })
            #expect(tryBool { try e.enforce("alice","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","data1","write").get() })
            #expect(!tryBool { try e.enforce("bob","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","data2","write").get() })
        }
    }
    
    @Test("rbac using in op")
    func testRbacModelUsinginOp() throws {
        try withEnforcer("examples/rbac_model_matcher_using_in_op.conf", "examples/rbac_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice", "data1", "read").get() })
        }
    }

    struct Book {
        var owner:String
    }
    @Test("abac model")
    func testAbac() throws {
        try withEnforcer("examples/abac_model.conf") { e in
            #expect(!tryBool { try e.enforce("alice", Book.init(owner: "zhangsan"), "read").get() })
            #expect(tryBool { try e.enforce("alice", Book.init(owner: "alice"), "read").get() })
        }
    }
}
