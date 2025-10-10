
import Testing
import Casbin
public let TestsfilePath = #filePath.components(separatedBy: "EnforcerTests.swift")[0]

@Suite("Enforcer Tests")
struct EnforcerTests {

    // Helper to assert enforce with actor Enforcer
    func expect(_ expected: Bool, _ e: Enforcer, _ rvals: any Sendable..., file: StaticString = #filePath, line: UInt = #line) async throws {
        let arr: [any Sendable] = Array(rvals)
        let res = try await e.enforce(rvals: arr).get()
        #expect(expected == res)
    }

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
    
    @Test("KeyMatch model in memory")
    func testKeyMatchModelInMemory() async throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")
        let adapter = FileAdapter(filePath: TestsfilePath + "examples/keymatch_policy.csv")
        let e = try await Enforcer(m: m, adapter: adapter)

        try await expect(true, e, "alice","/alice_data/resource1","GET")
        try await expect(true, e, "alice","/alice_data/resource1","POST")
        try await expect(true, e, "alice","/alice_data/resource2","GET")
        try await expect(false, e, "alice","/alice_data/resource2","POST")
        try await expect(false, e, "alice","/bob_data/resource1","GET")
        try await expect(false, e, "alice","/bob_data/resource1","POST")
        try await expect(false, e, "alice","/bob_data/resource2","POST")
        try await expect(false, e, "alice","/bob_data/resource2","GET")
        try await expect(false, e, "bob","/alice_data/resource1","GET")
        try await expect(false, e, "bob","/alice_data/resource1","POST")
        try await expect(true, e, "bob","/alice_data/resource2","GET")
        try await expect(false, e, "bob","/alice_data/resource1","POST")

        try await expect(false, e, "bob","/bob_data/resource1","GET")
        try await expect(true, e, "bob","/bob_data/resource1","POST")
        try await expect(true, e, "bob","/bob_data/resource2","POST")
        try await expect(false, e, "bob","/bob_data/resource2","GET")

        try await expect(true, e, "cathy","/cathy_data","GET")
        try await expect(true, e, "cathy","/cathy_data","POST")
        try await expect(false, e, "cathy","/cathy_data","DELETE")
    }
    
    @Test("KeyMatch deny in memory")
    func testKeyMatchModelInMemoryDeny() async throws {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "!some(where (p.eft == deny))")
        _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")
        let adapter = FileAdapter(filePath: TestsfilePath + "examples/keymatch_policy.csv")
        let e = try await Enforcer(m: m, adapter: adapter)

        try await expect(true, e, "alice","/alice_data/resource2","POST")
    }
    @Test("RBAC indeterminate in memory")
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
        try await expect(false, e, "alice", "data1", "read")
    }
    @Test("RBAC in memory")
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
        try await expect(true, e, "alice", "data1", "read")
        try await expect(false, e, "alice","data1","write")
        try await expect(true, e, "alice","data2","read")
        try await expect(true, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(false, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")
    }
    
    @Test("RBAC not-used model in memory")
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
        try await expect(true, e, "alice", "data1", "read")
        try await expect(false, e, "alice","data1","write")
        try await expect(false, e, "alice","data2","read")
        try await expect(false, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(false, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")
    }
    
    @Test("IP match model")
    func testIpMatchModel() async throws {
        let e = try await makeEnforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv")
        try await expect(true, e, "192.168.2.123", "data1", "read")
        try await expect(true, e, "10.0.0.5", "data2", "write")
        try await expect(false, e, "192.168.2.123", "data1", "write")
        try await expect(false, e, "192.168.2.123", "data2", "read")
        try await expect(false, e, "192.168.2.123", "data2", "write")
        try await expect(false, e, "192.168.0.123", "data1", "read")
        try await expect(false, e, "192.168.0.123", "data1", "write")
        try await expect(false, e, "192.168.0.123", "data2", "read")
        try await expect(false, e, "192.168.0.123", "data2", "write")
        try await expect(false, e, "10.0.0.5", "data1", "read")
        try await expect(false, e, "10.0.0.5", "data1", "write")
        try await expect(false, e, "10.0.0.5", "data2", "read")
        try await expect(false, e, "192.168.0.1", "data1", "read")
        try await expect(false, e, "192.168.0.1", "data1", "write")
        try await expect(false, e, "192.168.0.1", "data2", "read")
        try await expect(false, e, "192.168.0.1", "data2", "write")
    }
    
    @Test("Enable auto save")
    func testEnableAutoSave() async throws {
        let e = try await makeEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
        await e.enableAutoSave(auto: false)
       _ = try await e.removePolicy(params: ["alice", "data1", "read"])
       _ = try await e.loadPolicy()
        try await expect(true, e, "alice", "data1", "read")
        try await expect(false, e, "alice","data1","write")
        try await expect(false, e, "alice","data2","read")
        try await expect(false, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(false, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")
        
        await e.enableAutoSave(auto: true)
        _ = try await e.removePolicy(params: ["alice", "data1", "read"])
        _ = try await e.loadPolicy()
        try await expect(true, e, "alice", "data1", "read")
        try await expect(false, e, "alice","data1","write")
        try await expect(false, e, "alice","data2","read")
        try await expect(false, e, "alice","data2","write")
        try await expect(false, e, "bob","data1","read")
        try await expect(false, e, "bob","data1","write")
        try await expect(false, e, "bob","data2","read")
        try await expect(true, e, "bob","data2","write")
    }
    
    @Test("Role links")
    func testRoleLinks() async throws {
        let e = try await makeEnforcer("examples/rbac_model.conf")
        await e.enableAutoBuildRoleLinks(auto: false)
        _ = try await e.buildRoleLinks().get()
        try await expect(false, e, "user501", "data9", "read")
    }
    
    @Test("Get and set model")
    func testGetAndSetModel() async throws {
        let e = try await makeEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
        try await expect(false, e, "root", "data1", "read")
        let e2 = try await makeEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv")
        _ = try await e.setModel(e2.model)
        try await expect(true, e, "root", "data1", "read")
    }
    
    @Test("Get and set adapter in-memory")
    func testGetAndSetAdapterInmem() async throws {
        let e = try await makeEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
        try await expect(true, e, "alice", "data1", "read")
        try await expect(false, e, "alice", "data1", "write")
        
        let e2 = try await makeEnforcer("examples/basic_model.conf", "examples/basic_inverse_policy.csv")
        _ = try await e.setAdapter(e2.adapter)
        try await expect(false, e, "alice", "data1", "read")
        try await expect(true, e, "alice", "data1", "write")
    }
    
    @Test("KeyMatch custom model")
    func testKeymatchCustomModel() async throws {
        let e = try await makeEnforcer("examples/keymatch_custom_model.conf", "examples/keymatch_policy.csv")
        
        await e.addFunction(fname: "keyMatchCustom", f: Util.toExpressionFunction(name: "keyMatchCustom", function: { s1, s2 in
            return Util.keyMatch(s1, s2)
        }))
        try await expect(true, e, "alice", "/alice_data/123", "GET")
        try await expect(true, e, "alice", "/alice_data/resource1", "POST")
        try await expect(true, e, "bob", "/alice_data/resource2", "GET")
        try await expect(true, e, "bob", "/bob_data/resource1", "POST")
        try await expect(true, e, "cathy", "/cathy_data", "GET")
        try await expect(true, e, "cathy", "/cathy_data", "POST")
    }
    @Test("Filtered file adapter")
    func testFilteredFileAdater() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        let filter = Filter.init(p: ["","domain1"], g: ["","","domain1"])
       _ = try await e.loadFilterdPolicy(filter)
        
        try await expect(true, e, "alice", "domain1", "data1", "read")
        try await expect(true, e, "alice", "domain1", "data1", "write")
        try await expect(false, e, "alice", "domain1", "data2", "read")
        try await expect(false, e, "alice", "domain1", "data2", "write")
        try await expect(false, e, "bob", "domain2", "data2", "read")
        try await expect(false, e, "bob", "domain2", "data2", "write")
    }
    @Test("Set role manager")
    func testSetRoleManager() async throws {
        let e = try await makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        let newRm = DefaultRoleManager.init(maxHierarchyLevel: 10)
        try await e.setRoleManager(rm: newRm).get()
        try await expect(true, e, "alice", "domain1", "data1", "read")
        try await expect(true, e, "alice", "domain1", "data1", "write")
        try await expect(true, e, "bob", "domain2", "data2", "read")
        try await expect(true, e, "bob", "domain2", "data2", "write")
    }
    struct Person {
       let name:String
        let age:Int
    }
    @Test("Policy ABAC 1")
    func testPolicyAbac1() async throws  {
        let m = DefaultModel()
        _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
        _ = m.addDef(sec: "p", key: "p", value: "sub_rule, obj, act")
        _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
        _ = m.addDef(sec: "m", key: "m", value: "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act")
        let adapter = MemoryAdapter()
        let e = try await Enforcer(m: m, adapter: adapter)
        _ = try await e.addPolicy(params: ["r.sub.age > 18", "/data1", "read"])

        try await expect(false, e, Person(name: "alice", age: 16),  "/data1", "read")
        try await expect(true, e, Person(name: "bob", age: 19),  "/data1", "read")

    }
    struct Post {
        let author:String
    }
    @Test("Policy ABAC 2")
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
        try await expect(true, e, "alice",Post(author: "bob"),"write")
        try await expect(true, e, "bob",Post(author: "bob"),"write")

    }
    
}
