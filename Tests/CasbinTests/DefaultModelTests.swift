import XCTest
import NIO
import Casbin


final class DefaultModelTests: XCTestCase {
    var elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var pool = NIOThreadPool(numberOfThreads: 1)
    deinit {
        do {
            try pool.syncShutdownGracefully()
            try elg.syncShutdownGracefully()
        } catch  {
            
        }
    }
    func makeEnforer(_ mfile:String,_ aFile:String? = nil) throws -> Enforcer {
        
        pool.start()
        let fileIo = NonBlockingFileIO(threadPool: pool)
        let m = try DefaultModel.from(file:TestsfilePath + mfile , fileIo: fileIo, on: elg.next()).wait()
        var adapter:Adapter
        if let aFile = aFile {
            adapter = FileAdapter.init(filePath: TestsfilePath + aFile, fileIo: fileIo, eventloop: elg.next())
        } else {
            adapter = MemoryAdapter.init(on: elg.next())
        }
        let e = try Enforcer.init(m: m, adapter: adapter)
        return e
    }
   
    
    func testBasicModel() throws {
       let e = try makeEnforer("examples/basic_model.conf", "examples/basic_policy.csv")
        XCTAssertTrue(try e.enforce("alice","data1","read").get())
        XCTAssertTrue(try e.enforce("bob", "data2", "write").get())
        
        XCTAssertFalse(try e.enforce("alice","data1","write").get())
        XCTAssertFalse(try e.enforce("alice","data2", "read").get())
        XCTAssertFalse(try e.enforce("alice","data2", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "read").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "read").get())
    }
    
    func testBasicModelNoPolicy() throws {
        let e = try makeEnforer("examples/basic_model.conf")
        
        XCTAssertFalse(try e.enforce("alice","data1","read").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "write").get())
        
        XCTAssertFalse(try e.enforce("alice","data1","write").get())
        XCTAssertFalse(try e.enforce("alice","data2", "read").get())
        XCTAssertFalse(try e.enforce("alice","data2", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "read").get())
        XCTAssertFalse(try e.enforce("bob", "data1", "write").get())
        XCTAssertFalse(try e.enforce("bob", "data2", "read").get())

    }
    func testBasicModelWithRoot() throws {
        let e = try makeEnforer("examples/basic_with_root_model.conf", "examples/basic_policy.csv")
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
    
    func testBasicModelWithRootNoPolicy() throws {
        let e = try makeEnforer("examples/basic_with_root_model.conf")
        
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
    
    func testBasicModelWithoutUsers() throws {
        let e = try makeEnforer("examples/basic_without_users_model.conf", "examples/basic_without_users_policy.csv")
        
        XCTAssertTrue(try e.enforce("data1","read").get())
        XCTAssertFalse(try e.enforce("data1","write").get())
        XCTAssertFalse(try e.enforce("data2","read").get())
        XCTAssertTrue(try e.enforce("data2","write").get())
        
    }
    func testBasicModelWithoutResources() throws {
        let e = try makeEnforer("examples/basic_without_resources_model.conf", "examples/basic_without_resources_policy.csv")
        XCTAssertTrue(try e.enforce("alice","read").get())
        XCTAssertFalse(try e.enforce("alice","write").get())
        XCTAssertFalse(try e.enforce("bob","read").get())
        XCTAssertTrue(try e.enforce("bob","write").get())
    }
    
    func testRbacModel() throws {
        let e = try makeEnforer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        
        XCTAssertEqual(true, try e.enforce("alice","data1","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testRbacModelWithResourceRoles() throws {
        let e = try makeEnforer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv")
        XCTAssertEqual(true, try e.enforce("alice","data1","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())

    }
    
    func testRbacModelWithDomains() throws {
        let e = try makeEnforer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        XCTAssertEqual(true, try e.enforce("alice","domain1","data1","read").get())
        XCTAssertEqual(true, try e.enforce("alice","domain1","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","write").get())
    }
    
    func testRbacModelWithDomainsRuntime() throws {
        let e = try makeEnforer("examples/rbac_with_domains_model.conf")
       _ = try e.addPolicy(params: ["admin","domain1","data1","read"]).wait()
       _ = try e.addPolicy(params: ["admin","domain1","data1","write"]).wait()
       _ = try e.addPolicy(params: ["admin","domain2","data2","read"]).wait()
       _ = try e.addPolicy(params: ["admin","domain2","data2","write"]).wait()
       _ = try e.addGroupingPolicy(params: ["alice","admin","domain1"]).wait()
       _ = try e.addGroupingPolicy(params: ["bob","admin","domain2"]).wait()
        
        XCTAssertEqual(true, try e.enforce("alice","domain1","data1","read").get())
        XCTAssertEqual(true, try e.enforce("alice","domain1","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","write").get())
        
        XCTAssertEqual(true, try e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"]).wait())
        
        XCTAssertEqual(false, try e.enforce("alice","domain1","data1","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","write").get())
        
        XCTAssertEqual(true, try e.removePolicy(params: ["admin", "domain2", "data2", "read"]).wait())
        
        XCTAssertEqual(false, try e.enforce("alice","domain1","data1","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","domain1","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","domain2","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","domain2","data2","write").get())
    }
    
    func testRbacModelWithDomainsAtRuntimeMockAdapter() throws {
        let e = try makeEnforer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
       _ = try e.addPolicy(params: ["admin", "domain3", "data1", "read"]).wait()
       _ = try e.addGroupingPolicy(params: ["alice", "admin", "domain3"]).wait()
        XCTAssertEqual(true, try e.enforce("alice", "domain3", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("alice", "domain1", "data1", "read").get())
        _ = try e.removeFilteredPolicy(fieldIndex: 1, fieldValues: ["domain1","data1"]).wait()
        XCTAssertEqual(false, try e.enforce("alice", "domain1", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("bob", "domain2", "data2", "read").get())
        _ = try e.removePolicy(params: ["admin", "domain2", "data2", "read"]).wait()
        XCTAssertEqual(false, try e.enforce("bob", "domain2", "data2", "read").get())
    }
    
    func testRbacModelWithDeny() throws {
        let e = try makeEnforer("examples/rbac_with_deny_model.conf", "examples/rbac_with_deny_policy.csv")
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testRbacModelWithNotDeny() throws {
        let e = try makeEnforer("examples/rbac_with_not_deny_model.conf", "examples/rbac_with_deny_policy.csv")
        dump(e.model)
        XCTAssertEqual(false, try e.enforce("alice", "data2", "write").get())
    }
    func testRbacModelWithCustomData() throws {
        let e = try makeEnforer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        _ = try e.addGroupingPolicy(params: ["bob", "data2_admin", "custom_data"]).wait()
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
        
        _ = try e.removeGroupingPolicy(params: ["bob", "data2_admin", "custom_data"]).wait()
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testRbacModelUsinginOp() throws {
        let e  = try makeEnforer("examples/rbac_model_matcher_using_in_op.conf", "examples/rbac_policy.csv")
        dump(e.model)
        
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("bob", "data2", "write").get())
        XCTAssertEqual(true, try e.enforce("alice", "data2", "write").get())
        XCTAssertEqual(true, try e.enforce("alice", "data2", "read").get())
        XCTAssertEqual(true, try e.enforce("guest", "data2", "read").get())
        XCTAssertEqual(true, try e.enforce("alice", "data3", "read").get())
        XCTAssertEqual(true, try e.enforce("bob", "data3", "read").get())
    }
    //TODO
//    func testAbac() throws {
//        let e = try makeEnforer("examples/abac_model.conf")
//        XCTAssertEqual(false, try e.enforce("alice", #"{"owner":"bob"}"#, "read").get())
//        XCTAssertEqual(false, try e.enforce("alice", "alice", "read").get())
//    }
}
