
import XCTest
import Casbin
import NIO
public let TestsfilePath = #file.components(separatedBy: "EnforcerTests.swift")[0]

final class EnforcerTests: XCTestCase {
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
    
    func testKeyMatchModelInMemory() throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")
        pool.start()
        let fileIo = NonBlockingFileIO(threadPool: pool)
        let adapter = FileAdapter.init(filePath: TestsfilePath + "examples/keymatch_policy.csv", fileIo: fileIo, eventloop: elg.next())
        let e = try Enforcer.init(m: m, adapter: adapter, .shared(elg))
        
        XCTAssertEqual(true, try e.enforce("alice","/alice_data/resource1","GET").get())
        XCTAssert(try e.enforce("alice","/alice_data/resource1","POST").get())
        XCTAssert(try e.enforce("alice","/alice_data/resource2","GET").get())
        XCTAssertEqual(false,try e.enforce("alice","/alice_data/resource2","POST").get())
        XCTAssertEqual(false,try e.enforce("alice","/bob_data/resource1","GET").get())
        XCTAssertEqual(false,try e.enforce("alice","/bob_data/resource1","POST").get())
        XCTAssertEqual(false,try e.enforce("alice","/bob_data/resource2","POST").get())
        XCTAssertEqual(false,try e.enforce("alice","/bob_data/resource2","GET").get())
        XCTAssertEqual(false,try e.enforce("bob","/alice_data/resource1","GET").get())
        XCTAssertEqual(false,try e.enforce("bob","/alice_data/resource1","POST").get())
        XCTAssertEqual(true,try e.enforce("bob","/alice_data/resource2","GET").get())
        XCTAssertEqual(false,try e.enforce("bob","/alice_data/resource1","POST").get())
        
        XCTAssertEqual(false,try e.enforce("bob","/bob_data/resource1","GET").get())
        XCTAssertEqual(true,try e.enforce("bob","/bob_data/resource1","POST").get())
        XCTAssertEqual(true,try e.enforce("bob","/bob_data/resource2","POST").get())
        XCTAssertEqual(false,try e.enforce("bob","/bob_data/resource2","GET").get())
        
        XCTAssertEqual(true,try e.enforce("cathy","/cathy_data","GET").get())
        XCTAssertEqual(true,try e.enforce("cathy","/cathy_data","POST").get())
        XCTAssertEqual(false,try e.enforce("cathy","/cathy_data","DELETE").get())
    }
    
    func testKeyMatchModelInMemoryDeny() throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "!some(where (p.eft == deny))")
        _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")
        pool.start()
        let fileIo = NonBlockingFileIO(threadPool: pool)
        let adapter = FileAdapter.init(filePath: TestsfilePath + "examples/keymatch_policy.csv", fileIo: fileIo, eventloop: elg.next())
        let e = try Enforcer.init(m: m, adapter: adapter, .shared(elg))
        
        XCTAssertEqual(true,try e.enforce("alice","/alice_data/resource2","POST").get())
    }
    func testRbacModelInMemoryIndeterminate() throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "g", key: "g", value: "_,_")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter.init(on: elg.next())
        let e = try Enforcer.init(m: m, adapter: adapter,.shared(elg))
       _ = try e.addPermission(for: "alice", permission: ["data1", "invalid"]).wait()
        XCTAssertEqual(false, try e.enforce("alice", "data1", "read").get())
    }
    func testRbacModelInMemory() throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "g", key: "g", value: "_,_")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter.init(on: elg.next())
        let e = try Enforcer.init(m: m, adapter: adapter,.shared(elg))
        
        _ = try e.addPermission(for: "alice", permission: ["data1","read"]).wait()
        _ = try e.addPermission(for: "bob", permission: ["data2","write"]).wait()
        _ = try e.addPermission(for: "data2_admin", permission: ["data2","read"]).wait()
        _ = try e.addPermission(for: "data2_admin", permission: ["data2","write"]).wait()
        _ = try e.addRole(for: "alice", role: "data2_admin", domain: nil).wait()
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testNotUsedRbacModelInmemory() throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "g", key: "g", value: "_,_")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter.init(on: elg.next())
        let e = try Enforcer.init(m: m, adapter: adapter,.shared(elg))
        _ = try e.addPermission(for: "alice", permission: ["data1", "read"]).wait()
        _ = try e.addPermission(for: "bob", permission: ["data2", "write"]).wait()
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testIpMatchModel() throws {
        let e = try makeEnforer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv")
        XCTAssertEqual(true,try e.enforce("192.168.2.123", "data1", "read").get())
        XCTAssertEqual(true,try e.enforce("10.0.0.5", "data2", "write").get())
        XCTAssertEqual(false,try e.enforce("192.168.2.123", "data1", "write").get())
        XCTAssertEqual(false,try e.enforce("192.168.2.123", "data2", "read").get())
        XCTAssertEqual(false,try e.enforce("192.168.2.123", "data2", "write").get())
        XCTAssertEqual(false,try e.enforce("192.168.0.123", "data1", "read").get())
        
        XCTAssertEqual(false,try e.enforce("192.168.0.123", "data1", "write").get())
        XCTAssertEqual(false,try e.enforce("192.168.0.123", "data2", "read").get())
        XCTAssertEqual(false,try e.enforce("192.168.0.123", "data2", "write").get())
        XCTAssertEqual(false,try e.enforce("10.0.0.5", "data1", "read").get())
        
        XCTAssertEqual(false,try e.enforce("10.0.0.5", "data1", "write").get())
        XCTAssertEqual(false,try e.enforce("10.0.0.5", "data2", "read").get())
        
        XCTAssertEqual(false,try e.enforce("192.168.0.1", "data1", "read").get())
        XCTAssertEqual(false,try e.enforce("192.168.0.1", "data1", "write").get())
        XCTAssertEqual(false,try e.enforce("192.168.0.1", "data2", "read").get())
        XCTAssertEqual(false,try e.enforce("192.168.0.1", "data2", "write").get())
    }
    
    func testEnableAutoSave() throws {
        let e = try makeEnforer("examples/basic_model.conf", "examples/basic_policy.csv")
        e.enableAutoSave(auto: false)
       _ = try e.removePolicy(params: ["alice", "data1", "read"]).wait()
       _ = try e.loadPolicy().wait()
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
        
        e.enableAutoSave(auto: true)
        _ = try e.removePolicy(params: ["alice", "data1", "read"]).wait()
        _ = try e.loadPolicy().wait()
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testRoleLinks() throws {
        let e = try makeEnforer("examples/rbac_model.conf")
        e.enableAutoBuildRoleLinks(auto: false)
        _ = try e.buildRoleLinks().get()
        XCTAssertEqual(false, try e.enforce("user501", "data9", "read").get())
    }
    
    func testGetAndSetModel() throws {
        let e = try makeEnforer("examples/basic_model.conf", "examples/basic_policy.csv")
        XCTAssertEqual(false, try e.enforce("root", "data1", "read").get())
        let e2 = try makeEnforer("examples/basic_with_root_model.conf", "examples/basic_policy.csv")
        _ = try e.setModel(e2.model).wait()
        XCTAssertEqual(true, try e.enforce("root", "data1", "read").get())
    }
    
    func testGetAndSetAdapterInmem() throws {
        let e = try makeEnforer("examples/basic_model.conf", "examples/basic_policy.csv")
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice", "data1", "write").get())
        
        let e2 = try makeEnforer("examples/basic_model.conf", "examples/basic_inverse_policy.csv")
         _ = try e.setAdapter(e2.adapter).wait()
        XCTAssertEqual(false, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("alice", "data1", "write").get())
    }
    
    func testKeymatchCustomModel() throws {
        let e = try makeEnforer("examples/keymatch_custom_model.conf", "examples/keymatch_policy.csv")
        
        e.addFunction(fname: "keyMatchCustom", f: Util.toExpressionFunction(name: "keyMatchCustom", function: { s1, s2 in
            return Util.keyMatch(s1, s2)
        }))
        XCTAssertEqual(true, try e.enforce("alice", "/alice_data/123", "GET").get())
        XCTAssertEqual(true, try e.enforce("alice", "/alice_data/resource1", "POST").get())
        XCTAssertEqual(true, try e.enforce("bob", "/alice_data/resource2", "GET").get())
        XCTAssertEqual(true, try e.enforce("bob", "/bob_data/resource1", "POST").get())
        XCTAssertEqual(true, try e.enforce("cathy", "/cathy_data", "GET").get())
        XCTAssertEqual(true, try e.enforce("cathy", "/cathy_data", "POST").get())
    }
    func testFilteredFileAdater() throws {
        let e = try makeEnforer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        let filter = Filter.init(p: ["","domain1"], g: ["","","domain1"])
       _ = try e.loadFilterdPolicy(filter).wait()
        
        XCTAssertEqual(true, try e.enforce("alice", "domain1", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("alice", "domain1", "data1", "write").get())
        XCTAssertEqual(false, try e.enforce("alice", "domain1", "data2", "read").get())
        XCTAssertEqual(false, try e.enforce("alice", "domain1", "data2", "write").get())
        XCTAssertEqual(false, try e.enforce("bob", "domain2", "data2", "read").get())
        XCTAssertEqual(false, try e.enforce("bob", "domain2", "data2", "write").get())
    }
    func testSetRoleManager() throws {
        let e = try makeEnforer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        let newRm = DefaultRoleManager.init(maxHierarchyLevel: 10)
        try e.setRoleManager(rm: newRm).get()
        XCTAssertEqual(true, try e.enforce("alice", "domain1", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("alice", "domain1", "data1", "write").get())
        XCTAssertEqual(true, try e.enforce("bob", "domain2", "data2", "read").get())
        XCTAssertEqual(true, try e.enforce("bob", "domain2", "data2", "write").get())
    }
    struct Person {
       let name:String
        let age:Int
    }
    func testPolicyAbac1() throws  {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub_rule, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter.init(on: elg.next())
        let e = try Enforcer.init(m: m, adapter: adapter,.shared(elg))
        _ = try e.addPolicy(params: ["r.sub.age > 18", "/data1", "read"]).wait()
        
        XCTAssertEqual(false, try e.enforce(Person.init(name: "alice", age: 16),  "/data1", "read").get())
        XCTAssertEqual(true, try e.enforce(Person.init(name: "bob", age: 19),  "/data1", "read").get())
        
    }
    struct Post {
        let author:String
    }
    func testPolicyAbac2() throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "g", key: "g", value: "_,_")
        _ = m.addDef(sec: "m", key: "m", value: "(g(r.sub, p.sub) || eval(p.sub) == true) && r.act == p.act")
        let adapter = MemoryAdapter.init(on: elg.next())
        let e = try Enforcer.init(m: m, adapter: adapter,.shared(elg))
        _ = try e.addPolicy(params: ["admin", "post", "write"]).wait()
        _ = try e.addPolicy(params: ["r.sub == r.obj.author", "post", "write"]).wait()
        _ = try e.addGroupingPolicy(params: ["alice", "admin"]).wait()
        XCTAssertEqual(true, try e.enforce("alice",Post.init(author: "bob"),"write").get())
        XCTAssertEqual(true, try e.enforce("bob",Post.init(author: "bob"),"write").get())
        
    }
}
