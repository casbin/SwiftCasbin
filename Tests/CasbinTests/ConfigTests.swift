
import XCTest
import Casbin
import NIO

final class ConfigTests: XCTestCase {
    var elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var pool = NIOThreadPool(numberOfThreads: 1)
    func testGet() throws {
        let filePath = #file.components(separatedBy: "ConfigTests.swift")[0] + "examples/testini.ini"
        pool.start()
        let fileIo = NonBlockingFileIO(threadPool: pool)
        var config = try Config.from(file: filePath, fileIo: fileIo, on: elg.next())
            .wait()
        
        XCTAssertEqual(true, config.getBool(key: "debug"))
        XCTAssertEqual(64, config.getInt(key: "math::math.i64"))
        XCTAssertEqual(64.1, config.getFloat(key: "math::math.f64"))
        XCTAssertEqual("10.0.0.1", config.get(key: "mysql::mysql.master.host"))
        config.set(key: "other::key1", value: "new test key")
        XCTAssertEqual("new test key", config.get(key: "other::key1"))
        config.set(key: "other::key1", value: "test key")
        XCTAssertEqual("test key", config.get(key: "other::key1"))
        XCTAssertEqual("r.sub==p.sub&&r.obj==p.obj", config.get(key: "multi1::name"))
        XCTAssertEqual("r.sub==p.sub&&r.obj==p.obj", config.get(key: "multi2::name"))
        XCTAssertEqual("r.sub==p.sub&&r.obj==p.obj", config.get(key: "multi3::name"))
        XCTAssertEqual("", config.get(key: "multi4::name"))
        XCTAssertEqual("r.sub==p.sub&&r.obj==p.obj", config.get(key: "multi5::name"))
        try pool.syncShutdownGracefully()
        try elg.syncShutdownGracefully()
    }
    
    func testFromText() throws {
        let text = #"""
            # test config
                            debug = true
                            url = act.wiki
                            ; redis config
                            [redis]
                            redis.key = push1,push2
                            ; mysql config
                            [mysql]
                            mysql.dev.host = 127.0.0.1
                            mysql.dev.user = root
                            mysql.dev.pass = 123456
                            mysql.dev.db = test
                            mysql.master.host = 10.0.0.1
                            mysql.master.user = root
                            mysql.master.pass = 89dds)2$#d
                            mysql.master.db = act
                            ; math config
                            [math]
                            math.i64 = 64
                            math.f64 = 64.1
        """#
        
        var config = try Config.from(text: text, on: elg.next()).wait()
        XCTAssertEqual(true, config.getBool(key: "debug"))
        XCTAssertEqual(64, config.getInt(key: "math::math.i64"))
        XCTAssertEqual(64.1, config.getFloat(key: "math::math.f64"))
        XCTAssertEqual("10.0.0.1", config.get(key: "mysql::mysql.master.host"))
        config.set(key: "other::key1", value: "new test key")
        XCTAssertEqual("new test key", config.get(key: "other::key1"))
        config.set(key: "other::key1", value: "test key")
        XCTAssertEqual("test key", config.get(key: "other::key1"))
        
        try pool.syncShutdownGracefully()
        try elg.syncShutdownGracefully()
    }
}
