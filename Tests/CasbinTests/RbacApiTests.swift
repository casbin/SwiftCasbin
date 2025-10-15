import Testing
import NIO
import Casbin

@Suite("RBAC API", .timeLimit(.minutes(1)))
struct RbacApiTests {
    private func withEnforcer(_ mfile: String, _ aFile: String? = nil, body: (Enforcer) throws -> Void) throws {
        let pool = NIOThreadPool(numberOfThreads: 1)
        pool.start()
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? elg.syncShutdownGracefully()
            try? pool.syncShutdownGracefully()
        }
        let fileIo = NonBlockingFileIO(threadPool: pool)
        let m = try DefaultModel.from(file: TestsfilePath + mfile, fileIo: fileIo, on: elg.next()).wait()
        let adapter: Adapter
        if let aFile = aFile {
            adapter = FileAdapter(filePath: TestsfilePath + aFile, fileIo: fileIo, eventloop: elg.next())
        } else {
            adapter = MemoryAdapter(on: elg.next())
        }
        let e = try Enforcer(m: m, adapter: adapter)
        e.enableLog = false
        e.logger.logLevel = .warning
        try body(e)
    }

    @Test("basic role APIs")
    func roleApi() throws {
        try withEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv") { e in
            #expect(e.getRoles(for: "alice", domain: nil) == ["data2_admin"])
            #expect(e.getRoles(for: "bob", domain: nil).isEmpty)
            #expect(e.getRoles(for: "data2_admin", domain: nil).isEmpty)
            #expect(e.getRoles(for: "non_exists", domain: nil).isEmpty)

            #expect(!e.hasRole(for: "alice", role: "data1_admin", domain: nil))
            #expect(e.hasRole(for: "alice", role: "data2_admin", domain: nil))
            _ = try e.addRole(for: "alice", role: "data1_admin", domain: nil).wait()
            #expect(e.getRoles(for: "alice", domain: nil).sorted() == ["data1_admin", "data2_admin"])
            #expect(e.getRoles(for: "bob", domain: nil).sorted() == [])
            #expect(e.getRoles(for: "data2_admin", domain: nil).sorted() == [])
            #expect(e.getAllActions().sorted() == ["read", "write"])
        }
    }

    @Test("core API with domain")
    func coreApiWithDomain() throws {
        try withEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv") { e in
            #expect(e.getAllActions().sorted() == ["read", "write"])
        }
    }
}
