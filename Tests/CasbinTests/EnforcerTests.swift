
import XCTest
import Casbin
public let TestsfilePath = #filePath.components(separatedBy: "EnforcerTests.swift")[0]

final class EnforcerTests: XCTestCase {

    func makeEnforcer(_ mfile:String,_ aFile:String? = nil) async throws -> Enforcer {
        let m = try await DefaultModel.from(file: TestsfilePath + mfile)
        let adapter: Adapter
        if let aFile = aFile {
            adapter = FileAdapter(filePath: TestsfilePath + aFile)
        } else {
            adapter = MemoryAdapter()
        }
        let e = try await Enforcer(m: m, adapter: adapter)
        return e
    }
    
    func testKeyMatchModelInMemory() async throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")
        let adapter = FileAdapter(filePath: TestsfilePath + "examples/keymatch_policy.csv")
        let e = try await Enforcer(m: m, adapter: adapter)

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
    
    func testKeyMatchModelInMemoryDeny() async throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "!some(where (p.eft == deny))")
        _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")
        let adapter = FileAdapter(filePath: TestsfilePath + "examples/keymatch_policy.csv")
        let e = try await Enforcer(m: m, adapter: adapter)

        XCTAssertEqual(true,try e.enforce("alice","/alice_data/resource2","POST").get())
    }
    func testRbacModelInMemoryIndeterminate() async throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "g", key: "g", value: "_,_")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter()
        let e = try await Enforcer(m: m, adapter: adapter)
       _ = try await e.addPermission(for: "alice", permission: ["data1", "invalid"])
        XCTAssertEqual(false, try e.enforce("alice", "data1", "read").get())
    }
    func testRbacModelInMemory() async throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "g", key: "g", value: "_,_")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter()
        let e = try await Enforcer(m: m, adapter: adapter)

        _ = try await e.addPermission(for: "alice", permission: ["data1","read"])
        _ = try await e.addPermission(for: "bob", permission: ["data2","write"])
        _ = try await e.addPermission(for: "data2_admin", permission: ["data2","read"])
        _ = try await e.addPermission(for: "data2_admin", permission: ["data2","write"])
        _ = try await e.addRole(for: "alice", role: "data2_admin", domain: nil)
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(true, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testNotUsedRbacModelInmemory() async throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "g", key: "g", value: "_,_")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter()
        let e = try await Enforcer(m: m, adapter: adapter)
        _ = try await e.addPermission(for: "alice", permission: ["data1", "read"])
        _ = try await e.addPermission(for: "bob", permission: ["data2", "write"])
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testIpMatchModel() async throws {
        let e = try await makeEnforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv")
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
    
    func testEnableAutoSave() async throws {
        let e = try await makeEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
        e.enableAutoSave(auto: false)
       _ = try await e.removePolicy(params: ["alice", "data1", "read"])
       _ = try await e.loadPolicy()
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
        
        e.enableAutoSave(auto: true)
        _ = try await e.removePolicy(params: ["alice", "data1", "read"])
        _ = try await e.loadPolicy()
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice","data1","write").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","read").get())
        XCTAssertEqual(false, try e.enforce("alice","data2","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","read").get())
        XCTAssertEqual(false, try e.enforce("bob","data1","write").get())
        XCTAssertEqual(false, try e.enforce("bob","data2","read").get())
        XCTAssertEqual(true, try e.enforce("bob","data2","write").get())
    }
    
    func testRoleLinks() async throws {
        let e = try await makeEnforcer("examples/rbac_model.conf")
        e.enableAutoBuildRoleLinks(auto: false)
        _ = try e.buildRoleLinks().get()
        XCTAssertEqual(false, try e.enforce("user501", "data9", "read").get())
    }
    
    func testGetAndSetModel() async throws {
        let e = try await makeEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
        XCTAssertEqual(false, try e.enforce("root", "data1", "read").get())
        let e2 = try await makeEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv")
        _ = try await e.setModel(e2.model)
        XCTAssertEqual(true, try e.enforce("root", "data1", "read").get())
    }
    
    func testGetAndSetAdapterInmem() async throws {
        let e = try await makeEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
        XCTAssertEqual(true, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(false, try e.enforce("alice", "data1", "write").get())
        
        let e2 = try await makeEnforcer("examples/basic_model.conf", "examples/basic_inverse_policy.csv")
         _ = try await e.setAdapter(e2.adapter)
        XCTAssertEqual(false, try e.enforce("alice", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("alice", "data1", "write").get())
    }
    
    func testKeymatchCustomModel() async throws {
        let e = try await makeEnforcer("examples/keymatch_custom_model.conf", "examples/keymatch_policy.csv")
        
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
    func testFilteredFileAdater() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        let filter = Filter.init(p: ["","domain1"], g: ["","","domain1"])
       _ = try await e.loadFilterdPolicy(filter)
        
        XCTAssertEqual(true, try e.enforce("alice", "domain1", "data1", "read").get())
        XCTAssertEqual(true, try e.enforce("alice", "domain1", "data1", "write").get())
        XCTAssertEqual(false, try e.enforce("alice", "domain1", "data2", "read").get())
        XCTAssertEqual(false, try e.enforce("alice", "domain1", "data2", "write").get())
        XCTAssertEqual(false, try e.enforce("bob", "domain2", "data2", "read").get())
        XCTAssertEqual(false, try e.enforce("bob", "domain2", "data2", "write").get())
    }
    func testSetRoleManager() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
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
    func testPolicyAbac1() async throws  {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub_rule, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter()
        let e = try await Enforcer(m: m, adapter: adapter)
        _ = try await e.addPolicy(params: ["r.sub.age > 18", "/data1", "read"])

        XCTAssertEqual(false, try e.enforce(Person(name: "alice", age: 16),  "/data1", "read").get())
        XCTAssertEqual(true, try e.enforce(Person(name: "bob", age: 19),  "/data1", "read").get())

    }
    struct Post {
        let author:String
    }
    func testPolicyAbac2() async throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "g", key: "g", value: "_,_")
        _ = m.addDef(sec: "m", key: "m", value: "(g(r.sub, p.sub) || eval(p.sub) == true) && r.act == p.act")
        let adapter = MemoryAdapter()
        let e = try await Enforcer(m: m, adapter: adapter)
        _ = try await e.addPolicy(params: ["admin", "post", "write"])
        _ = try await e.addPolicy(params: ["r.sub == r.obj.author", "post", "write"])
        _ = try await e.addGroupingPolicy(params: ["alice", "admin"])
        XCTAssertEqual(true, try e.enforce("alice",Post(author: "bob"),"write").get())
        XCTAssertEqual(true, try e.enforce("bob",Post(author: "bob"),"write").get())

    }
    
}
