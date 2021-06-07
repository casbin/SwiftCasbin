
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
    
    
}
