import XCTest
import NIO
import Casbin


final class RbacApiTests: XCTestCase {
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
    
    func testRoleApi() throws {
        let e = try makeEnforer("examples/rbac_model.conf", "examples/rbac_policy.csv")
        XCTAssertEqual(["data2_admin"], e.getRoles(for: "alice", domain: nil))
        XCTAssertEqual([], e.getRoles(for: "bob", domain: nil))
        XCTAssertEqual([], e.getRoles(for: "data2_admin", domain: nil))
        XCTAssertEqual([], e.getRoles(for: "non_exists", domain: nil))
        
        XCTAssertEqual(false, e.hasRole(for: "alice", role: "data1_admin", domain: nil))
        XCTAssertEqual(true, e.hasRole(for: "alice", role: "data2_admin", domain: nil))
       _ = try e.addRole(for: "alice", role: "data1_admin", domain: nil).wait()
        XCTAssertEqual(["data1_admin", "data2_admin"], e.getRoles(for: "alice", domain: nil).sorted())
        XCTAssertEqual([], e.getRoles(for: "bob", domain: nil).sorted())
        XCTAssertEqual([], e.getRoles(for: "data2_admin", domain: nil).sorted())
        XCTAssertEqual(["read", "write"], e.getAllActions().sorted())
        //XCTAssertEqual(["data1", "data2"], e.getAllObjects().sorted())
        //XCTAssertEqual(["alice", "bob", "data2_admin"], e.getAllSubjects().sorted())
        //XCTAssertEqual(["data1_admin", "data2_admin"], e.getAllRoles().sorted())
    }
    func testCoreApi_for_RoleApi_with_domain() throws {
        let e = try makeEnforer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        XCTAssertEqual(["read", "write"], e.getAllActions().sorted())
        //XCTAssertEqual(["data1", "data2"], e.getAllObjects())
        //XCTAssertEqual(["admin",], e.getAllSubjects())
        //XCTAssertEqual(["admin", ], e.getAllRoles())
    }
}
