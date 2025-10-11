import Testing
import NIO
import Casbin

@Suite("RBAC API")
struct RbacApiTests {
    private func makeEnforcer(_ mfile: String, _ aFile: String? = nil) throws -> Enforcer {
        let pool = NIOThreadPool(numberOfThreads: 1)
        pool.start()
        defer { try? pool.syncShutdownGracefully() }
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { try? elg.syncShutdownGracefully() }
        let fileIo = NonBlockingFileIO(threadPool: pool)

        let m = try DefaultModel.from(file: TestsfilePath + mfile, fileIo: fileIo, on: elg.next()).wait()
        let adapter: Adapter = {
            if let aFile = aFile {
                return FileAdapter(filePath: TestsfilePath + aFile, fileIo: fileIo, eventloop: elg.next())
            } else {
                return MemoryAdapter(on: elg.next())
            }
        }()
        return try Enforcer(m: m, adapter: adapter)
    }

    @Test("basic role APIs")
    func roleApi() throws {
        let e = try makeEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
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

    @Test("core API with domain")
    func coreApiWithDomain() throws {
        let e = try makeEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
        #expect(e.getAllActions().sorted() == ["read", "write"])
    }
}
