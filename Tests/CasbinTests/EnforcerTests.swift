import Testing
import Casbin
import NIO

@Suite("Enforcer", .timeLimit(.minutes(1)))
struct EnforcerTests {
    @inline(__always)
    private func tryBool(_ body: () throws -> Bool) -> Bool { (try? body()) ?? false }

    private func withELGAndPool<R>(_ body: (NIOThreadPool, EventLoopGroup) throws -> R) rethrows -> R {
        let pool = NIOThreadPool(numberOfThreads: 1)
        pool.start()
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? elg.syncShutdownGracefully()
            try? pool.syncShutdownGracefully()
        }
        return try body(pool, elg)
    }

    private func withEnforcer(_ mfile: String, _ aFile: String? = nil, body: (Enforcer) throws -> Void) throws {
        try withELGAndPool { pool, elg in
            let fileIo = NonBlockingFileIO(threadPool: pool)
            let m = try DefaultModel.from(file: TestsfilePath + mfile, fileIo: fileIo, on: elg.next()).wait()
            let adapter: Adapter = (aFile != nil)
                ? FileAdapter(filePath: TestsfilePath + (aFile ?? ""), fileIo: fileIo, eventloop: elg.next())
                : MemoryAdapter(on: elg.next())
            let e = try Enforcer(m: m, adapter: adapter, .shared(elg))
            e.enableLog = false
            e.logger.logLevel = .warning
            try body(e)
        }
    }

    @Test("keyMatch model in memory")
    func keyMatchModelInMemory() throws {
        try withELGAndPool { pool, elg in
            let m = DefaultModel()
            _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
            _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
            _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
            _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")
            let fileIo = NonBlockingFileIO(threadPool: pool)
            let adapter = FileAdapter(filePath: TestsfilePath + "examples/keymatch_policy.csv", fileIo: fileIo, eventloop: elg.next())
            let e = try Enforcer(m: m, adapter: adapter, .shared(elg))
            e.enableLog = false
            e.logger.logLevel = .warning
            #expect(tryBool { try e.enforce("alice","/alice_data/resource1","GET").get() })
            #expect(tryBool { try e.enforce("alice","/alice_data/resource1","POST").get() })
            #expect(tryBool { try e.enforce("alice","/alice_data/resource2","GET").get() })
            #expect(!tryBool { try e.enforce("alice","/alice_data/resource2","POST").get() })
            #expect(!tryBool { try e.enforce("alice","/bob_data/resource1","GET").get() })
            #expect(!tryBool { try e.enforce("alice","/bob_data/resource1","POST").get() })
            #expect(!tryBool { try e.enforce("alice","/bob_data/resource2","POST").get() })
            #expect(!tryBool { try e.enforce("alice","/bob_data/resource2","GET").get() })
            #expect(!tryBool { try e.enforce("bob","/alice_data/resource1","GET").get() })
            #expect(!tryBool { try e.enforce("bob","/alice_data/resource1","POST").get() })
            #expect(tryBool { try e.enforce("bob","/alice_data/resource2","GET").get() })
            #expect(!tryBool { try e.enforce("bob","/alice_data/resource1","POST").get() })
            #expect(!tryBool { try e.enforce("bob","/bob_data/resource1","GET").get() })
            #expect(tryBool { try e.enforce("bob","/bob_data/resource1","POST").get() })
            #expect(tryBool { try e.enforce("bob","/bob_data/resource2","POST").get() })
            #expect(!tryBool { try e.enforce("bob","/bob_data/resource2","GET").get() })
            #expect(tryBool { try e.enforce("cathy","/cathy_data","GET").get() })
            #expect(tryBool { try e.enforce("cathy","/cathy_data","POST").get() })
            #expect(!tryBool { try e.enforce("cathy","/cathy_data","DELETE").get() })
        }
    }

    @Test("keyMatch deny")
    func keyMatchModelInMemoryDeny() throws {
        try withELGAndPool { pool, elg in
            let m = DefaultModel()
            _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
            _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
            _ = m.addDef(sec: "e", key: "e", value: "!some(where (p.eft == deny))")
            _ = m.addDef(sec: "m", key: "m", value: "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")
            let fileIo = NonBlockingFileIO(threadPool: pool)
            let adapter = FileAdapter(filePath: TestsfilePath + "examples/keymatch_policy.csv", fileIo: fileIo, eventloop: elg.next())
            let e = try Enforcer(m: m, adapter: adapter, .shared(elg))
            #expect(tryBool { try e.enforce("alice","/alice_data/resource2","POST").get() })
        }
    }

    @Test("rbac indeterminate")
    func rbacModelInMemoryIndeterminate() throws {
        try withELGAndPool { _, elg in
            let m = DefaultModel()
            _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
            _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
            _ = m.addDef(sec: "g", key: "g", value: "_,_")
            _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
            _ = m.addDef(sec: "m", key: "m", value: "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")
            let adapter = MemoryAdapter(on: elg.next())
            let e = try Enforcer(m: m, adapter: adapter, .shared(elg))
            _ = try e.addPermission(for: "alice", permission: ["data1", "invalid"]).wait()
            #expect(!tryBool { try e.enforce("alice", "data1", "read").get() })
        }
    }

    @Test("rbac in memory")
    func rbacModelInMemory() throws {
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

    @Test("rbac multiline model")
    func rbacModelInMultiLine() throws {
        try withEnforcer("examples/rbac_model_in_multi_line.conf", "examples/rbac_policy.csv") { e in
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

    @Test("ip match model")
    func ipMatchModel() throws {
        try withEnforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv") { e in
            #expect(tryBool { try e.enforce("192.168.2.123", "data1", "read").get() })
            #expect(tryBool { try e.enforce("10.0.0.5", "data2", "write").get() })
            #expect(!tryBool { try e.enforce("192.168.2.123", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("192.168.2.123", "data2", "read").get() })
            #expect(!tryBool { try e.enforce("192.168.2.123", "data2", "write").get() })
            #expect(!tryBool { try e.enforce("192.168.0.123", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("192.168.0.123", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("192.168.0.123", "data2", "read").get() })
            #expect(!tryBool { try e.enforce("192.168.0.123", "data2", "write").get() })
            #expect(!tryBool { try e.enforce("10.0.0.5", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("10.0.0.5", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("10.0.0.5", "data2", "read").get() })
            #expect(!tryBool { try e.enforce("192.168.0.1", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("192.168.0.1", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("192.168.0.1", "data2", "read").get() })
            #expect(!tryBool { try e.enforce("192.168.0.1", "data2", "write").get() })
        }
    }

    @Test("enable auto save")
    func enableAutoSave() throws {
        try withEnforcer("examples/basic_model.conf", "examples/basic_policy.csv") { e in
            e.enableAutoSave(auto: false)
            _ = try e.removePolicy(params: ["alice", "data1", "read"]).wait()
            _ = try e.loadPolicy().wait()
            #expect(tryBool { try e.enforce("alice", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","data2","read").get() })
            #expect(!tryBool { try e.enforce("alice","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","data1","write").get() })
            #expect(!tryBool { try e.enforce("bob","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","data2","write").get() })
            e.enableAutoSave(auto: true)
            _ = try e.removePolicy(params: ["alice", "data1", "read"]).wait()
            _ = try e.loadPolicy().wait()
            #expect(tryBool { try e.enforce("alice", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("alice","data1","write").get() })
            #expect(!tryBool { try e.enforce("alice","data2","read").get() })
            #expect(!tryBool { try e.enforce("alice","data2","write").get() })
            #expect(!tryBool { try e.enforce("bob","data1","read").get() })
            #expect(!tryBool { try e.enforce("bob","data1","write").get() })
            #expect(!tryBool { try e.enforce("bob","data2","read").get() })
            #expect(tryBool { try e.enforce("bob","data2","write").get() })
        }
    }

    @Test("role links")
    func roleLinks() throws {
        try withEnforcer("examples/rbac_model.conf") { e in
            e.enableAutoBuildRoleLinks(auto: false)
            _ = try e.buildRoleLinks().get()
            #expect(!tryBool { try e.enforce("user501", "data9", "read").get() })
        }
    }

    @Test("get & set model")
    func getAndSetModel() throws {
        try withEnforcer("examples/basic_model.conf", "examples/basic_policy.csv") { e in
            #expect(!tryBool { try e.enforce("root", "data1", "read").get() })
            try withEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv") { e2 in
                _ = try e.setModel(e2.model).wait()
                #expect(tryBool { try e.enforce("root", "data1", "read").get() })
            }
        }
    }

    @Test("get & set adapter in-memory")
    func getAndSetAdapterInmem() throws {
        try withEnforcer("examples/basic_model.conf", "examples/basic_policy.csv") { e in
            #expect(tryBool { try e.enforce("alice", "data1", "read").get() })
            #expect(!tryBool { try e.enforce("alice", "data1", "write").get() })
            try withEnforcer("examples/basic_model.conf", "examples/basic_inverse_policy.csv") { e2 in
                _ = try e.setAdapter(e2.adapter).wait()
                #expect(!tryBool { try e.enforce("alice", "data1", "read").get() })
                #expect(tryBool { try e.enforce("alice", "data1", "write").get() })
            }
        }
    }

    @Test("keymatch custom function")
    func keymatchCustomModel() throws {
        try withEnforcer("examples/keymatch_custom_model.conf", "examples/keymatch_policy.csv") { e in
            e.addFunction(fname: "keyMatchCustom", f: Util.toExpressionFunction(name: "keyMatchCustom", function: { s1, s2 in
                return Util.keyMatch(s1, s2)
            }))
            #expect(tryBool { try e.enforce("alice", "/alice_data/123", "GET").get() })
            #expect(tryBool { try e.enforce("alice", "/alice_data/resource1", "POST").get() })
            #expect(tryBool { try e.enforce("bob", "/alice_data/resource2", "GET").get() })
            #expect(tryBool { try e.enforce("bob", "/bob_data/resource1", "POST").get() })
            #expect(tryBool { try e.enforce("cathy", "/cathy_data", "GET").get() })
            #expect(tryBool { try e.enforce("cathy", "/cathy_data", "POST").get() })
        }
    }

    @Test("filtered file adapter")
    func filteredFileAdater() throws {
        try withEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv") { e in
            let filter = Filter(p: ["","domain1"], g: ["","","domain1"])
            _ = try e.loadFilterdPolicy(filter).wait()
            #expect(tryBool { try e.enforce("alice", "domain1", "data1", "read").get() })
            #expect(tryBool { try e.enforce("alice", "domain1", "data1", "write").get() })
            #expect(!tryBool { try e.enforce("alice", "domain1", "data2", "read").get() })
            #expect(!tryBool { try e.enforce("alice", "domain1", "data2", "write").get() })
            #expect(!tryBool { try e.enforce("bob", "domain2", "data2", "read").get() })
            #expect(!tryBool { try e.enforce("bob", "domain2", "data2", "write").get() })
        }
    }

    @Test("set role manager")
    func setRoleManager() throws {
        try withEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv") { e in
            let newRm = DefaultRoleManager(maxHierarchyLevel: 10)
            _ = try e.setRoleManager(rm: newRm).get()
            #expect(tryBool { try e.enforce("alice", "domain1", "data1", "read").get() })
            #expect(tryBool { try e.enforce("alice", "domain1", "data1", "write").get() })
            #expect(tryBool { try e.enforce("bob", "domain2", "data2", "read").get() })
            #expect(tryBool { try e.enforce("bob", "domain2", "data2", "write").get() })
        }
    }

    struct Person { let name: String; let age: Int }

    @Test("policy ABAC 1")
    func policyAbac1() throws  {
        try withELGAndPool { _, elg in
            let m = DefaultModel()
            _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
            _ = m.addDef(sec: "p", key: "p", value: "sub_rule, obj, act")
            _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
            _ = m.addDef(sec: "m", key: "m", value: "eval(p.sub_rule) && r.obj == p.obj && r.act == p.act")
            let adapter = MemoryAdapter(on: elg.next())
            let e = try Enforcer(m: m, adapter: adapter, .shared(elg))
            _ = try e.addPolicy(params: ["r.sub.age > 18", "/data1", "read"]).wait()
            #expect(!tryBool { try e.enforce(Person(name: "alice", age: 16),  "/data1", "read").get() })
            #expect(tryBool { try e.enforce(Person(name: "bob", age: 19),  "/data1", "read").get() })
        }
    }

    struct Post { let author: String }

    @Test("policy ABAC 2")
    func policyAbac2() throws {
        try withELGAndPool { _, elg in
            let m = DefaultModel()
            _ = m.addDef(sec: "r", key: "r", value: "sub, obj, act")
            _ = m.addDef(sec: "p", key: "p", value: "sub, obj, act")
            _ = m.addDef(sec: "e", key: "e", value: "some(where (p.eft == allow))")
            _ = m.addDef(sec: "g", key: "g", value: "_,_")
            _ = m.addDef(sec: "m", key: "m", value: "(g(r.sub, p.sub) || eval(p.sub) == true) && r.act == p.act")
            let adapter = MemoryAdapter(on: elg.next())
            let e = try Enforcer(m: m, adapter: adapter, .shared(elg))
            _ = try e.addPolicy(params: ["admin", "post", "write"]).wait()
            _ = try e.addPolicy(params: ["r.sub == r.obj.author", "post", "write"]).wait()
            _ = try e.addGroupingPolicy(params: ["alice", "admin"]).wait()
            #expect(tryBool { try e.enforce("alice",Post(author: "bob"),"write").get() })
            #expect(tryBool { try e.enforce("bob",Post(author: "bob"),"write").get() })
        }
    }
}
